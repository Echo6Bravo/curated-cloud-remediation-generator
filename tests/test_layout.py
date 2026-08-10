"""Tests for output-file layout.

The property that matters here is not tidiness: **no output file may span more
than one cloud or more than one credential scope, and no HCL file more than one
region when that cloud's Terraform provider is region-scoped.** Both formats
target a single credential scope -- the shell script through ambient credentials,
HCL through a scoped provider configuration -- so a file that mixes them either
fails or, worse, succeeds against the wrong resource.
"""

from __future__ import annotations

import pytest

from remgen.core.layout import (
    DEFAULT_MAX_PER_FILE,
    Format,
    describe_layout,
    plan_units,
)
from remgen.core.model import ApiCall, Finding, HclTarget, Recipe


def _recipe(**overrides) -> Recipe:
    kwargs = {
        "policy_id": "p1",
        "policy_title": "Title",
        "summary": "Summary",
        "api": ApiCall(service="s3", operation="Op", parameters=("Bucket",)),
        "cli_template": "aws s3api do-thing --bucket {resource_id} --region {region}",
        "hcl": HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'),),
            import_id_template="{resource_id}",
        ),
        "reverse_hint": "undo it",
    }
    kwargs.update(overrides)
    return Recipe(**kwargs)


def _pairs(specs):
    """Build ``(recipe, finding)`` pairs from ``(resource_id, region, account)``."""
    recipe = _recipe()
    return [
        (recipe, Finding(policy_id="p1", resource_id=rid, region=reg, account_id=acct))
        for rid, reg, acct in specs
    ]


def _plan(pairs, fmt, **kwargs):
    """Call :func:`plan_units` with the AWS-shaped provider facts.

    ``cloud`` has no default in the real signature -- a unit with no cloud has no
    directory and no filename prefix -- so the tests supply one here rather than
    repeating it at every call site.
    """
    kwargs.setdefault("cloud", "aws")
    return plan_units(pairs, fmt, **kwargs)


# ---------------------------------------------------------------------------
# Hard boundaries -- correctness, so they hold at any size
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", [Format.CLI, Format.HCL])
def test_no_unit_ever_spans_two_scopes(fmt):
    pairs = _pairs(
        [
            ("b1", "us-east-1", "111111111111"),
            ("b2", "us-east-1", "222222222222"),
            ("b3", "us-west-2", "111111111111"),
        ]
    )
    for unit in _plan(pairs, fmt):
        accounts = {f.account_id for _, f in unit.pairs}
        assert len(accounts) == 1
        assert accounts == {unit.scope_id}


@pytest.mark.parametrize("fmt", [Format.CLI, Format.HCL])
def test_scope_split_is_not_defeated_by_disabling_size_splitting(fmt):
    # max_per_file=0 turns off the *soft* cap only. If it also merged scopes, a
    # user could silently opt out of a correctness rule via a size flag.
    pairs = _pairs([("b1", "us-east-1", "111111111111"), ("b2", "us-east-1", "222222222222")])
    units = _plan(pairs, fmt, max_per_file=0)
    assert len(units) == 2
    assert {u.scope_id for u in units} == {"111111111111", "222222222222"}


def test_hcl_never_spans_two_regions_even_when_small():
    # Region is a hard boundary for HCL because the AWS provider is region-scoped,
    # so this split must happen at two findings, not only at scale.
    pairs = _pairs([("b1", "us-east-1", "111111111111"), ("b2", "eu-west-1", "111111111111")])
    units = _plan(pairs, Format.HCL)
    assert len(units) == 2
    assert {u.region for u in units} == {"us-east-1", "eu-west-1"}
    for unit in units:
        assert {f.region for _, f in unit.pairs} == {unit.region}


def test_hcl_region_split_survives_disabled_size_splitting():
    pairs = _pairs([("b1", "us-east-1", "111111111111"), ("b2", "eu-west-1", "111111111111")])
    assert len(_plan(pairs, Format.HCL, max_per_file=0)) == 2


def test_hcl_keeps_regions_together_when_the_provider_is_not_region_scoped():
    # The rule is a property of the *provider*, not of HCL. `azurerm` carries
    # `location` per resource, so splitting there would fragment output without
    # making any file more correct. A hard-coded AWS assumption here would silently
    # do that to every cloud added later.
    pairs = _pairs([("b1", "eastus", "sub-1"), ("b2", "westeurope", "sub-1")])
    units = _plan(
        pairs,
        Format.HCL,
        cloud="azure",
        provider_is_region_scoped=False,
        scope_noun="subscription",
    )
    assert len(units) == 1
    assert units[0].region is None


def test_cli_keeps_regions_together_when_small():
    # A CLI script carries --region per command, so splitting a small script by
    # region would produce more files without making anything more correct.
    pairs = _pairs([("b1", "us-east-1", "111111111111"), ("b2", "eu-west-1", "111111111111")])
    units = _plan(pairs, Format.CLI)
    assert len(units) == 1
    assert units[0].region is None
    assert "all-regions" in units[0].filename


def test_cli_splits_regions_once_large():
    specs = [
        (f"b{i}", "us-east-1" if i % 2 else "eu-west-1", "111111111111")
        for i in range(DEFAULT_MAX_PER_FILE + 10)
    ]
    units = _plan(_pairs(specs), Format.CLI)
    assert len(units) > 1
    assert all(u.region is not None for u in units)


# The volume-triggered region split, decorrelated from format and from cloud.
#
# `split_by_region` is one `or` over two independent causes -- the format/provider
# hard boundary, and the volume threshold -- and every test above holds both axes at
# once: HCL is always tested region-scoped (where the hard boundary fires first and
# masks the threshold entirely) and the volume case was only ever tested on the AWS
# CLI. So the untested cell is the one that matters: **HCL on a provider that is not
# region-scoped, above the threshold.** Azure is exactly that shape, and nothing
# reached it.
_REGION_SCOPING = [
    pytest.param(Format.CLI, True, "aws", "account", id="aws-cli"),
    pytest.param(Format.CLI, False, "azure", "subscription", id="azure-cli"),
    pytest.param(Format.HCL, True, "aws", "account", id="aws-hcl-region-scoped"),
    # The cell no other test covers.
    pytest.param(Format.HCL, False, "azure", "subscription", id="azure-hcl-not-region-scoped"),
]


@pytest.mark.parametrize("fmt,region_scoped,cloud,noun", _REGION_SCOPING)
@pytest.mark.parametrize(
    "count,expect_region_split",
    [
        # Exactly at the threshold is NOT over it: the condition is `>`, and an
        # off-by-one here would split every run that happens to land on the default.
        (DEFAULT_MAX_PER_FILE, False),
        (DEFAULT_MAX_PER_FILE + 1, True),
    ],
    ids=["at-threshold", "one-over-threshold"],
)
def test_volume_triggers_a_region_split_independently_of_format(
    fmt, region_scoped, cloud, noun, count, expect_region_split
):
    """Above the threshold, region splits for *any* format -- not just the CLI.

    The two regions are chosen so neither exceeds the threshold alone; only the
    combined scope does. That keeps this a test of the region decision rather than of
    the part-chunking that follows it.
    """
    specs = [(f"b{i}", "r-one" if i % 2 else "r-two", "scope-1") for i in range(count)]
    units = _plan(
        _pairs(specs),
        fmt,
        cloud=cloud,
        provider_is_region_scoped=region_scoped,
        scope_noun=noun,
    )
    # A hard boundary splits by region at any size, so it is region-split either way.
    hard = fmt.region_is_hard_boundary(provider_is_region_scoped=region_scoped)
    split = any(u.region is not None for u in units)
    assert split is (hard or expect_region_split), (
        f"{fmt.value}/region_scoped={region_scoped} at {count}: region split={split}"
    )
    if split:
        # Whatever the cause, the invariant holds: a file naming a region contains
        # only that region. A split that mislabels its contents is worse than none.
        for unit in units:
            if unit.region is not None:
                assert {f.region for _, f in unit.pairs} == {unit.region}


@pytest.mark.parametrize("fmt,region_scoped,cloud,noun", _REGION_SCOPING)
def test_the_stated_reason_for_a_region_split_matches_the_actual_cause(
    fmt, region_scoped, cloud, noun
):
    """A volume split must not be explained as a provider constraint.

    This is the defect that made the whole batch worth doing: `describe_layout`
    inferred the cause from `region is not None`, so a volume-triggered Azure HCL
    split was explained as "this cloud's Terraform provider is region-scoped" --
    false for `azurerm`, and stated to an operator with total confidence. An
    explanation a reader can check and find wrong teaches them the tool's stated
    reasons are decorative, which is worse than printing nothing.
    """
    count = DEFAULT_MAX_PER_FILE + 1
    specs = [(f"b{i}", "r-one" if i % 2 else "r-two", "scope-1") for i in range(count)]
    units = _plan(
        _pairs(specs), fmt, cloud=cloud, provider_is_region_scoped=region_scoped, scope_noun=noun
    )
    joined = " ".join(describe_layout(units, provider_is_region_scoped=region_scoped))

    if fmt.region_is_hard_boundary(provider_is_region_scoped=region_scoped):
        assert "region-scoped" in joined
        assert "--max-per-file" not in joined
    else:
        # The volume cause, named as reviewability and pointing at the knob that
        # controls it -- the correctness splits have no knob, so implying one would
        # be its own false claim.
        assert "region-scoped" not in joined, (
            "a volume-triggered split was explained as a provider constraint"
        )
        assert "more remediations than one file should hold" in joined
        assert "--max-per-file" in joined
        assert "reviewability rather than correctness" in joined


# ---------------------------------------------------------------------------
# Cloud, the outermost hard boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", [Format.CLI, Format.HCL])
def test_every_unit_carries_the_cloud_it_was_planned_for(fmt):
    units = _plan(_pairs([("b1", "us-east-1", "1")]), fmt, cloud="aws")
    assert all(u.cloud == "aws" for u in units)


@pytest.mark.parametrize("fmt", [Format.CLI, Format.HCL])
def test_output_path_is_under_a_per_cloud_directory(fmt):
    unit = _plan(_pairs([("b1", "us-east-1", "1")]), fmt)[0]
    assert unit.relative_path == f"aws/{unit.filename}"


def test_two_clouds_never_collide_even_with_identical_scope_and_region():
    # Two clouds can legitimately produce the same scope id and region name in a
    # test or a mocked estate. If the cloud were only a directory and not also in
    # the filename, copying both files into one place would silently overwrite one.
    pairs = _pairs([("b1", "us-east-1", "1")])
    aws = _plan(pairs, Format.CLI, cloud="aws")[0]
    other = _plan(pairs, Format.CLI, cloud="gcp")[0]
    assert aws.filename != other.filename
    assert aws.relative_path != other.relative_path


# ---------------------------------------------------------------------------
# Soft boundary -- size
# ---------------------------------------------------------------------------


def test_large_scope_is_split_into_numbered_parts():
    specs = [(f"b{i}", "us-east-1", "111111111111") for i in range(25)]
    units = _plan(_pairs(specs), Format.HCL, max_per_file=10)
    assert [u.part for u in units] == [1, 2, 3]
    assert all(u.total_parts == 3 for u in units)
    assert [len(u.pairs) for u in units] == [10, 10, 5]
    assert "part1of3" in units[0].filename


def test_splitting_loses_nothing_and_duplicates_nothing():
    specs = [(f"b{i}", "us-east-1", "111111111111") for i in range(25)]
    pairs = _pairs(specs)
    units = _plan(pairs, Format.HCL, max_per_file=7)
    recovered = [p for u in units for p in u.pairs]
    assert len(recovered) == len(pairs)
    assert {f.resource_id for _, f in recovered} == {f.resource_id for _, f in pairs}


def test_a_single_part_is_not_numbered():
    # "part1of1" in a filename implies there is a part 2 to look for.
    units = _plan(_pairs([("b1", "us-east-1", "1")]), Format.HCL)
    assert units[0].part is None
    assert "part" not in units[0].filename


def test_zero_max_per_file_disables_size_splitting():
    specs = [(f"b{i}", "us-east-1", "111111111111") for i in range(50)]
    units = _plan(_pairs(specs), Format.HCL, max_per_file=0)
    assert len(units) == 1
    assert len(units[0].pairs) == 50


# ---------------------------------------------------------------------------
# Filenames and determinism
# ---------------------------------------------------------------------------


def test_filenames_are_unique():
    specs = [
        (f"b{i}", region, account)
        for i in range(30)
        for region in ("us-east-1", "eu-west-1")
        for account in ("111111111111", "222222222222")
    ]
    for fmt in (Format.CLI, Format.HCL):
        units = _plan(_pairs(specs), fmt, max_per_file=7)
        names = [u.filename for u in units]
        assert len(names) == len(set(names))


def test_filename_names_the_cloud_the_account_and_region():
    # The operator has to pick a vendor CLI and credentials per file, so both
    # requirements belong in the name rather than only inside the file.
    units = _plan(_pairs([("b1", "eu-west-1", "111111111111")]), Format.HCL)
    assert units[0].filename == "remediate-aws-111111111111-eu-west-1.tf"


def test_shell_extension_comes_from_the_provider_but_hcl_is_always_tf():
    pairs = _pairs([("b1", "us-east-1", "1")])
    cli = _plan(pairs, Format.CLI, extension=".ps1")[0]
    hcl = _plan(pairs, Format.HCL, extension=".ps1")[0]
    assert cli.filename.endswith(".ps1")
    # .tf is the configuration language's extension, not the cloud's, so a provider
    # cannot override it.
    assert hcl.filename.endswith(".tf")


def test_scope_description_uses_the_clouds_own_noun():
    unit = _plan(
        _pairs([("b1", "eastus", "sub-1")]),
        Format.CLI,
        cloud="azure",
        scope_noun="subscription",
    )[0]
    assert "azure subscription sub-1" in unit.scope_description
    assert "account" not in unit.scope_description


def test_layout_is_independent_of_input_order():
    specs = [
        ("b1", "us-east-1", "111111111111"),
        ("b2", "eu-west-1", "222222222222"),
        ("b3", "us-east-1", "222222222222"),
    ]
    forward = _plan(_pairs(specs), Format.HCL)
    reverse = _plan(_pairs(list(reversed(specs))), Format.HCL)
    assert [u.filename for u in forward] == [u.filename for u in reverse]
    assert [[f.resource_id for _, f in u.pairs] for u in forward] == [
        [f.resource_id for _, f in u.pairs] for u in reverse
    ]


@pytest.mark.parametrize("fmt", [Format.CLI, Format.HCL])
def test_empty_input_produces_no_units(fmt):
    assert _plan([], fmt) == []
    assert describe_layout([], provider_is_region_scoped=True) == []


# ---------------------------------------------------------------------------
# The explanation
# ---------------------------------------------------------------------------


def _describe(pairs, fmt, *, region_scoped=True, **kwargs):
    """Plan and describe with one consistent view of the provider's region scoping.

    Both calls take it, and passing two different values would describe a layout that
    was never planned -- which is the class of defect these tests exist to catch.
    """
    kwargs.setdefault("provider_is_region_scoped", region_scoped)
    units = _plan(pairs, fmt, **kwargs)
    return " ".join(describe_layout(units, provider_is_region_scoped=region_scoped))


def test_describe_layout_states_the_credential_requirement():
    # A directory of 40 files with no explanation reads as a bug, and an operator
    # who does not know each needs its own credentials will run the first and stop.
    specs = [("b1", "us-east-1", "111111111111"), ("b2", "us-east-1", "222222222222")]
    joined = _describe(_pairs(specs), Format.CLI)
    assert "2 accounts" in joined
    assert "credentials for the account in its name" in joined


def test_describe_layout_names_the_cloud():
    assert "in aws" in _describe(_pairs([("b1", "us-east-1", "1")]), Format.CLI)


def test_describe_layout_explains_the_region_split_only_for_hcl():
    specs = [("b1", "us-east-1", "1"), ("b2", "eu-west-1", "1")]
    assert "region-scoped" in _describe(_pairs(specs), Format.HCL)
    assert "region-scoped" not in _describe(_pairs(specs), Format.CLI)


def test_describe_layout_uses_the_clouds_own_noun():
    specs = [("b1", "eastus", "sub-1"), ("b2", "eastus", "sub-2")]
    joined = _describe(_pairs(specs), Format.CLI, cloud="azure", scope_noun="subscription")
    assert "subscriptions" in joined
    assert "account" not in joined


def test_describe_layout_mentions_parts_when_it_split_for_size():
    specs = [(f"b{i}", "us-east-1", "1") for i in range(25)]
    assert "parts" in _describe(_pairs(specs), Format.HCL, max_per_file=10)


# ---------------------------------------------------------------------------
# The explanation names the cause that actually applied
# ---------------------------------------------------------------------------
#
# Every sentence used to be gated on `len(units) > 1`, which is a count and not a
# cause. Each test below is a layout with exactly ONE cause, asserting the other
# sentences stay absent -- the assertion the old implementation could not satisfy.


def test_one_scope_split_by_region_is_not_described_as_a_scope_split():
    # The plainest case, and it was wrong: a single AWS account whose HCL spans two
    # regions was told "Split by account", which an operator can immediately see is
    # false -- there is one account, and both files name it.
    specs = [("b1", "us-east-1", "111111111111"), ("b2", "eu-west-1", "111111111111")]
    joined = _describe(_pairs(specs), Format.HCL)
    assert "region-scoped" in joined
    assert "Split by account" not in joined
    assert "1 accounts" in joined
    # Two files, no parts. Asserted here rather than only in the size-only test below,
    # because that one is the *positive* case for parts: re-gating this sentence on the
    # file count would keep it passing while telling everyone with two files to "run the
    # parts of a scope in order", of a scope that has no parts.
    assert "numbered parts" not in joined


def test_a_size_only_split_claims_neither_a_scope_nor_a_region_split():
    # One account, one region, chunked into parts. Both other sentences were printed.
    specs = [(f"b{i}", "us-east-1", "111111111111") for i in range(25)]
    joined = _describe(_pairs(specs), Format.HCL, max_per_file=10)
    assert "numbered parts" in joined
    assert "Split by account" not in joined
    assert "Split by region" not in joined


def test_a_scope_split_alone_claims_no_region_split():
    # Two accounts, one region each. Two regions appear across the run, but no
    # scope's output was split by region -- so counting distinct regions globally
    # (rather than per scope) would report a split that did not happen.
    specs = [("b1", "us-east-1", "111111111111"), ("b2", "eu-west-1", "222222222222")]
    joined = _describe(_pairs(specs), Format.HCL)
    assert "Split by account" in joined
    assert "Split by region" not in joined
    assert "numbered parts" not in joined


def test_a_single_file_is_described_without_claiming_any_split():
    joined = _describe(_pairs([("b1", "us-east-1", "1")]), Format.CLI)
    assert "1 .sh file(s)" in joined
    assert "Split by" not in joined
    # The credential sentence is also a split consequence, so it goes too: telling
    # someone with one file that "each file needs its own credentials" is noise.
    assert "credentials for the" not in joined


def test_every_split_cause_can_be_reported_at_once():
    # The complement of the tests above: with all four causes genuinely present, all
    # four sentences must appear. Otherwise a fix that suppressed sentences too
    # eagerly would pass every single-cause test.
    specs = [
        (f"b{i}", region, account)
        for account in ("111111111111", "222222222222")
        for region in ("us-east-1", "eu-west-1")
        for i in range(6)
    ]
    units = _plan(_pairs(specs), Format.HCL, max_per_file=3)
    joined = " ".join(describe_layout(units, provider_is_region_scoped=True))
    assert "Split by account" in joined
    assert "region-scoped" in joined
    assert "numbered parts" in joined
    assert "credentials for the account" in joined


def test_describe_layout_requires_the_providers_region_scoping():
    # Not defaulted, deliberately: a default does not degrade the explanation, it
    # asserts something about the provider that may be false -- and the caller who
    # forgets is exactly the one who would get the wrong sentence silently.
    units = _plan(_pairs([("b1", "us-east-1", "1")]), Format.CLI)
    with pytest.raises(TypeError):
        describe_layout(units)
