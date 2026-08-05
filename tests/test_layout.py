"""Tests for output-file layout.

The property that matters here is not tidiness: **no output file may span more
than one AWS account, and no HCL file more than one region.** Both formats target
a single account -- the shell script through ambient credentials, HCL through a
region- and credential-scoped provider -- so a file that mixes them either fails
or, worse, succeeds against the wrong resource.
"""

from __future__ import annotations

import pytest

from remgen.layout import (
    DEFAULT_MAX_PER_FILE,
    Format,
    describe_layout,
    plan_units,
)
from remgen.model import ApiCall, Finding, HclTarget, Recipe


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


# ---------------------------------------------------------------------------
# Hard boundaries -- correctness, so they hold at any size
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", [Format.AWSCLI, Format.HCL])
def test_no_unit_ever_spans_two_accounts(fmt):
    pairs = _pairs(
        [
            ("b1", "us-east-1", "111111111111"),
            ("b2", "us-east-1", "222222222222"),
            ("b3", "us-west-2", "111111111111"),
        ]
    )
    for unit in plan_units(pairs, fmt):
        accounts = {f.account_id for _, f in unit.pairs}
        assert len(accounts) == 1
        assert accounts == {unit.account_id}


@pytest.mark.parametrize("fmt", [Format.AWSCLI, Format.HCL])
def test_account_split_is_not_defeated_by_disabling_size_splitting(fmt):
    # max_per_file=0 turns off the *soft* cap only. If it also merged accounts, a
    # user could silently opt out of a correctness rule via a size flag.
    pairs = _pairs(
        [("b1", "us-east-1", "111111111111"), ("b2", "us-east-1", "222222222222")]
    )
    units = plan_units(pairs, fmt, max_per_file=0)
    assert len(units) == 2
    assert {u.account_id for u in units} == {"111111111111", "222222222222"}


def test_hcl_never_spans_two_regions_even_when_small():
    # Region is a hard boundary for HCL because the provider is region-scoped, so
    # this split must happen at two findings, not only at scale.
    pairs = _pairs(
        [("b1", "us-east-1", "111111111111"), ("b2", "eu-west-1", "111111111111")]
    )
    units = plan_units(pairs, Format.HCL)
    assert len(units) == 2
    assert {u.region for u in units} == {"us-east-1", "eu-west-1"}
    for unit in units:
        assert {f.region for _, f in unit.pairs} == {unit.region}


def test_hcl_region_split_survives_disabled_size_splitting():
    pairs = _pairs(
        [("b1", "us-east-1", "111111111111"), ("b2", "eu-west-1", "111111111111")]
    )
    assert len(plan_units(pairs, Format.HCL, max_per_file=0)) == 2


def test_cli_keeps_regions_together_when_small():
    # A CLI script carries --region per command, so splitting a small script by
    # region would produce more files without making anything more correct.
    pairs = _pairs(
        [("b1", "us-east-1", "111111111111"), ("b2", "eu-west-1", "111111111111")]
    )
    units = plan_units(pairs, Format.AWSCLI)
    assert len(units) == 1
    assert units[0].region is None
    assert "all-regions" in units[0].filename


def test_cli_splits_regions_once_large():
    specs = [
        (f"b{i}", "us-east-1" if i % 2 else "eu-west-1", "111111111111")
        for i in range(DEFAULT_MAX_PER_FILE + 10)
    ]
    units = plan_units(_pairs(specs), Format.AWSCLI)
    assert len(units) > 1
    assert all(u.region is not None for u in units)


# ---------------------------------------------------------------------------
# Soft boundary -- size
# ---------------------------------------------------------------------------


def test_large_scope_is_split_into_numbered_parts():
    specs = [(f"b{i}", "us-east-1", "111111111111") for i in range(25)]
    units = plan_units(_pairs(specs), Format.HCL, max_per_file=10)
    assert [u.part for u in units] == [1, 2, 3]
    assert all(u.total_parts == 3 for u in units)
    assert [len(u.pairs) for u in units] == [10, 10, 5]
    assert "part1of3" in units[0].filename


def test_splitting_loses_nothing_and_duplicates_nothing():
    specs = [(f"b{i}", "us-east-1", "111111111111") for i in range(25)]
    pairs = _pairs(specs)
    units = plan_units(pairs, Format.HCL, max_per_file=7)
    recovered = [p for u in units for p in u.pairs]
    assert len(recovered) == len(pairs)
    assert {f.resource_id for _, f in recovered} == {f.resource_id for _, f in pairs}


def test_a_single_part_is_not_numbered():
    # "part1of1" in a filename implies there is a part 2 to look for.
    units = plan_units(_pairs([("b1", "us-east-1", "1")]), Format.HCL)
    assert units[0].part is None
    assert "part" not in units[0].filename


def test_zero_max_per_file_disables_size_splitting():
    specs = [(f"b{i}", "us-east-1", "111111111111") for i in range(50)]
    units = plan_units(_pairs(specs), Format.HCL, max_per_file=0)
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
    for fmt in (Format.AWSCLI, Format.HCL):
        units = plan_units(_pairs(specs), fmt, max_per_file=7)
        names = [u.filename for u in units]
        assert len(names) == len(set(names))


def test_filename_names_the_account_and_region():
    # The operator has to pick credentials per file, so the requirement belongs in
    # the name rather than only inside the file.
    units = plan_units(_pairs([("b1", "eu-west-1", "111111111111")]), Format.HCL)
    assert units[0].filename == "remediate-111111111111-eu-west-1.tf"


def test_layout_is_independent_of_input_order():
    specs = [
        ("b1", "us-east-1", "111111111111"),
        ("b2", "eu-west-1", "222222222222"),
        ("b3", "us-east-1", "222222222222"),
    ]
    forward = plan_units(_pairs(specs), Format.HCL)
    reverse = plan_units(_pairs(list(reversed(specs))), Format.HCL)
    assert [u.filename for u in forward] == [u.filename for u in reverse]
    assert [[f.resource_id for _, f in u.pairs] for u in forward] == [
        [f.resource_id for _, f in u.pairs] for u in reverse
    ]


@pytest.mark.parametrize("fmt", [Format.AWSCLI, Format.HCL])
def test_empty_input_produces_no_units(fmt):
    assert plan_units([], fmt) == []
    assert describe_layout([]) == []


# ---------------------------------------------------------------------------
# The explanation
# ---------------------------------------------------------------------------


def test_describe_layout_states_the_credential_requirement():
    # A directory of 40 files with no explanation reads as a bug, and an operator
    # who does not know each needs its own credentials will run the first and stop.
    specs = [("b1", "us-east-1", "111111111111"), ("b2", "us-east-1", "222222222222")]
    lines = describe_layout(plan_units(_pairs(specs), Format.AWSCLI))
    joined = " ".join(lines)
    assert "2 account(s)" in joined
    assert "credentials for the account in its name" in joined


def test_describe_layout_explains_the_region_split_only_for_hcl():
    specs = [("b1", "us-east-1", "1"), ("b2", "eu-west-1", "1")]
    hcl = " ".join(describe_layout(plan_units(_pairs(specs), Format.HCL)))
    assert "region-scoped" in hcl
    cli = " ".join(describe_layout(plan_units(_pairs(specs), Format.AWSCLI)))
    assert "region-scoped" not in cli


def test_describe_layout_mentions_parts_when_it_split_for_size():
    specs = [(f"b{i}", "us-east-1", "1") for i in range(25)]
    lines = describe_layout(plan_units(_pairs(specs), Format.HCL, max_per_file=10))
    assert any("parts" in line for line in lines)
