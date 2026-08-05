"""Tests for the output generators.

The central property under test: **no value from a finding can change the
structure of a generated artifact.** Everything else here is secondary.
"""

from __future__ import annotations

import pytest

from remgen.core.generators.common import TemplateError, comment_block, render_template
from remgen.core.generators.hcl import assign_labels, render_hcl
from remgen.core.generators.hcl import render_one as render_hcl_one
from remgen.core.layout import Format, plan_units
from remgen.core.model import (
    ApiCall,
    CostImpact,
    Effort,
    Finding,
    HclTarget,
    Recipe,
    UnsafeIdentifierError,
)
from remgen.providers.aws import AWS
from remgen.providers.aws.hcl import scope_block
from remgen.providers.aws.recipes import all_recipes
from remgen.providers.aws.shell import render_cli_script
from remgen.providers.aws.shell import render_one as render_cli_one

from .test_model import UNSAFE_VALUES

VERSION = "0.0.0-test"
STAMP = "2026-01-01T00:00:00Z"


def _finding(**overrides) -> Finding:
    kwargs = {
        "policy_id": "p1",
        "resource_id": "my-bucket",
        "region": "us-east-1",
        "account_id": "123456789012",
    }
    kwargs.update(overrides)
    return Finding(**kwargs)


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


# ---------------------------------------------------------------------------
# Template safety
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [v for v in UNSAFE_VALUES if v and len(v) <= 1024])
def test_unsafe_values_cannot_reach_a_template(value):
    # Findings reject these at construction. This asserts the *second* guard, in
    # case a Finding is ever built by a path that skips validation.
    finding = object.__new__(Finding)
    object.__setattr__(finding, "policy_id", "p1")
    object.__setattr__(finding, "resource_id", value)
    object.__setattr__(finding, "region", "us-east-1")
    object.__setattr__(finding, "account_id", "1")
    object.__setattr__(finding, "resource_name", "")
    with pytest.raises(UnsafeIdentifierError):
        render_template("aws thing --id {resource_id}", finding)


def test_template_rejects_unknown_field():
    with pytest.raises(TemplateError, match="not an allowed field"):
        render_template("{secret}", _finding())


@pytest.mark.parametrize("template", ["{}", "{0}", "{resource_id.__class__}", "{a[0]}"])
def test_template_rejects_positional_and_attribute_access(template):
    # "{resource_id.__class__}" would otherwise reach beyond the allowlist.
    with pytest.raises(TemplateError):
        render_template(template, _finding())


def test_template_rejects_missing_value():
    with pytest.raises(TemplateError, match="resource_name"):
        render_template("{resource_name}", _finding())


def test_template_reports_malformed_string():
    with pytest.raises(TemplateError, match="malformed"):
        render_template("{unclosed", _finding())


# ---------------------------------------------------------------------------
# comment_block
# ---------------------------------------------------------------------------


def test_comment_block_wraps_long_lines():
    long_line = "word " * 60
    out = comment_block([long_line], width=80)
    assert all(len(line) <= 80 for line in out.splitlines())


def test_comment_block_never_splits_urls():
    url = "https://docs.aws.amazon.com/" + "a" * 120
    out = comment_block([f"AWS docs: {url}"], width=80)
    assert url in out


def test_comment_block_renders_blank_lines_as_bare_hash():
    out = comment_block(["a", "", "b"])
    assert out.splitlines() == ["# a", "#", "# b"]


def test_comment_block_preserves_bullet_indentation():
    out = comment_block(["  - " + "word " * 40], width=60)
    lines = out.splitlines()
    assert lines[0].startswith("#   - ")
    assert lines[1].startswith("#     ")  # hanging indent past the marker


# ---------------------------------------------------------------------------
# aws CLI generator
# ---------------------------------------------------------------------------


def test_cli_script_has_failfast_header():
    out = render_cli_script([(_recipe(), _finding())], version=VERSION, generated_at=STAMP)
    assert "set -euo pipefail" in out
    assert out.startswith("#!/usr/bin/env bash")


def test_cli_script_is_valid_with_no_findings():
    out = render_cli_script([], version=VERSION, generated_at=STAMP)
    assert "set -euo pipefail" in out
    assert "No remediable findings" in out


def test_cli_command_is_rendered_with_finding_values():
    out = render_cli_one(_recipe(), _finding())
    assert "aws s3api do-thing --bucket my-bucket --region us-east-1" in out


def test_cli_output_carries_safety_notes():
    recipe = _recipe(reversible=False, reverse_hint="", cost_impact=CostImpact.USAGE_SCALED)
    out = render_cli_one(recipe, _finding())
    assert "NOT REVERSIBLE" in out
    assert "COST SCALES WITH USAGE" in out


def test_cli_script_orders_safest_before_riskier():
    safe = _recipe(policy_id="safe", policy_title="Safe")
    risky = _recipe(policy_id="risky", policy_title="Risky", data_path_impact=True)
    out = render_cli_script(
        [(risky, _finding()), (safe, _finding())], version=VERSION, generated_at=STAMP
    )
    assert out.index("SAFEST") < out.index("DISRUPTIVE")


# ---------------------------------------------------------------------------
# HCL generator
# ---------------------------------------------------------------------------


def test_hcl_always_pairs_import_with_resource():
    # Without an import block, a plan would try to CREATE a duplicate resource.
    out = render_hcl_one(_recipe(), _finding())
    assert "import {" in out
    assert 'resource "aws_thing"' in out
    assert out.count("import {") == out.count('resource "')


def test_hcl_import_id_uses_the_template():
    recipe = _recipe(
        hcl=HclTarget(
            resource_type="aws_cloudtrail",
            attributes=(("name", '"{resource_id}"'),),
            import_id_template="arn:aws:cloudtrail:{region}:{account_id}:trail/{resource_id}",
        )
    )
    out = render_hcl_one(recipe, _finding(resource_id="my-trail"))
    assert 'id = "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail"' in out


def test_hcl_labels_match_between_import_and_resource():
    finding = _finding(resource_id="arn:aws:s3:::weird.name/x")
    out = render_hcl_one(_recipe(), finding)
    label = "arn_aws_s3_weird_name_x"
    assert f"to = aws_thing.{label}" in out
    assert f'resource "aws_thing" "{label}"' in out


def test_hcl_renders_nested_blocks():
    recipe = _recipe(
        hcl=HclTarget(
            resource_type="aws_s3_bucket_versioning",
            attributes=(("bucket", '"{resource_id}"'),),
            import_id_template="{resource_id}",
            blocks=(("versioning_configuration", (("status", '"Enabled"', ""),)),),
        )
    )
    out = render_hcl_one(recipe, _finding())
    assert "versioning_configuration {" in out
    assert 'status = "Enabled"' in out


def test_hcl_marks_incomplete_blocks():
    recipe = _recipe(
        hcl=HclTarget(
            resource_type="aws_db_instance",
            attributes=(("identifier", '"{resource_id}"'),),
            import_id_template="{resource_id}",
            unresolvable_required_attributes=(
                ("engine", '"postgres"', "TODO: set the real engine"),
            ),
        )
    )
    out = render_hcl_one(recipe, _finding())
    # The three things a reader needs: that it is incomplete, which argument, and
    # that the placeholder is not the real value. Asserted as properties rather than
    # as exact prose, so rewording the warning does not fail the test but dropping
    # any part of it does.
    assert "INCOMPLETE" in out
    assert "engine" in out
    assert "TODO: set the real engine" in out
    assert "type checking only" in out


def test_hcl_skips_recipes_without_a_target():
    out = render_hcl([(_recipe(hcl=None), _finding())], version=VERSION, generated_at=STAMP)
    assert "No remediable findings" in out
    # No actual resource/import blocks -- the header prose mentions the words.
    assert 'resource "' not in out
    assert "import {" not in out


def test_hcl_raises_if_asked_to_render_a_recipe_without_a_target():
    with pytest.raises(ValueError, match="no HCL target"):
        render_hcl_one(_recipe(hcl=None), _finding())


# ---------------------------------------------------------------------------
# HCL label uniqueness
#
# HCL requires resource labels to be unique per type within a module, but AWS
# resource names are only unique per account+region. Two resources with the same
# name in dev and prod -- an ordinary pattern -- collapse to one label and produce
# a file that fails `validate` with "Duplicate resource configuration", while the
# CLI still reports success. These tests pin the label assignment.
# ---------------------------------------------------------------------------


def test_same_name_in_two_accounts_gets_distinct_labels():
    recipe = _recipe()
    pairs = [
        (recipe, _finding(region="us-east-1", account_id="111111111111")),
        (recipe, _finding(region="us-west-2", account_id="222222222222")),
    ]
    labels = assign_labels(pairs)
    assert len(set(labels.values())) == 2

    out = render_hcl(pairs, version=VERSION, generated_at=STAMP)
    declared = [
        line for line in out.splitlines() if line.startswith('resource "aws_thing"')
    ]
    assert len(declared) == 2
    assert len(set(declared)) == 2, "duplicate resource label would fail tofu validate"


def test_unique_resource_id_keeps_the_short_label():
    # Disambiguation is applied only where needed, so the common case stays legible.
    pairs = [(_recipe(), _finding(resource_id="only-one"))]
    assert assign_labels(pairs) == {0: "only-one"}


def test_same_name_across_different_resource_types_is_not_disambiguated():
    # Uniqueness is per resource type, so an S3 and a DynamoDB block may share a
    # label without conflict -- disambiguating them would be needless noise.
    a = _recipe(policy_id="a")
    b = _recipe(
        policy_id="b",
        hcl=HclTarget(
            resource_type="aws_other",
            attributes=(("bucket", '"{resource_id}"'),),
            import_id_template="{resource_id}",
        ),
    )
    labels = assign_labels([(a, _finding()), (b, _finding())])
    assert labels == {0: "my-bucket", 1: "my-bucket"}


def test_identical_findings_still_get_unique_labels():
    # The CLI dedupes these, so this is a generator-level backstop. An ordinal is
    # used rather than a content digest, which would be identical for identical
    # findings and so collide again.
    recipe = _recipe()
    pairs = [(recipe, _finding()), (recipe, _finding()), (recipe, _finding())]
    labels = assign_labels(pairs)
    assert len(set(labels.values())) == 3


def test_labels_are_stable_regardless_of_input_order():
    # Same set in a different order must give each finding the same label, so
    # regenerating produces a reviewable diff rather than a reshuffle.
    recipe = _recipe()
    f1 = _finding(region="us-east-1", account_id="111111111111")
    f2 = _finding(region="us-west-2", account_id="222222222222")
    forward = assign_labels([(recipe, f1), (recipe, f2)])
    reverse = assign_labels([(recipe, f2), (recipe, f1)])
    assert forward[0] == reverse[1]
    assert forward[1] == reverse[0]


def test_import_and_resource_labels_agree_after_disambiguation():
    # The import block must point at the resource block it pairs with; if only one
    # of the two were disambiguated, the plan would create instead of import.
    recipe = _recipe()
    pairs = [
        (recipe, _finding(region="us-east-1", account_id="111111111111")),
        (recipe, _finding(region="us-west-2", account_id="222222222222")),
    ]
    out = render_hcl(pairs, version=VERSION, generated_at=STAMP)
    targets = {
        line.split("aws_thing.")[1].strip()
        for line in out.splitlines()
        if "to = aws_thing." in line
    }
    declared = {
        line.split('"')[3] for line in out.splitlines() if line.startswith('resource "')
    }
    assert targets == declared
    assert len(targets) == 2


# ---------------------------------------------------------------------------
# Properties that must hold for the real curated recipe set
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("recipe", all_recipes(), ids=lambda r: r.policy_id)
def test_every_curated_recipe_renders_both_formats(recipe):
    finding = _finding(policy_id=recipe.policy_id, resource_id="test-resource-1")
    cli = render_cli_one(recipe, finding)
    assert "test-resource-1" in cli
    if recipe.hcl is not None:
        hcl = render_hcl_one(recipe, finding)
        assert "import {" in hcl


@pytest.mark.parametrize("recipe", all_recipes(), ids=lambda r: r.policy_id)
def test_curated_recipes_declare_a_docs_url(recipe):
    assert recipe.docs_url.startswith("https://docs.aws.amazon.com/")


@pytest.mark.parametrize("recipe", all_recipes(), ids=lambda r: r.policy_id)
def test_curated_recipes_are_not_disruptive_in_v1(recipe):
    # v1 promises no availability-affecting remediations. This is the guard.
    from remgen.core.model import SafetyTier

    assert recipe.safety_tier is not SafetyTier.DISRUPTIVE
    assert recipe.effort is Effort.LOW
    assert not recipe.data_path_impact


# ---------------------------------------------------------------------------
# The AWS scope block -- the provider's contribution to a cloud-neutral renderer
# ---------------------------------------------------------------------------


def _aws_unit(fmt=Format.HCL, **kwargs):
    pairs = [(_recipe(), _finding(**kwargs))]
    return plan_units(
        pairs,
        fmt,
        cloud=AWS.cloud,
        scope_noun=AWS.credential_scope_noun,
        extension=AWS.shell_extension,
        provider_is_region_scoped=AWS.hcl_provider_is_region_scoped,
    )[0]


def test_scope_block_names_the_account_the_region_and_the_credential_guard():
    """``allowed_account_ids`` is the difference between two very different failures.

    Without it a provider pointed at the wrong account does not error -- it imports a
    same-named resource from the account it *can* see and reconfigures that one. So
    the guard, and the account and region it guards, must all be present.
    """
    block = scope_block(_aws_unit(region="eu-west-1", account_id="111111111111"))
    assert 'provider "aws"' in block
    assert 'allowed_account_ids = ["111111111111"]' in block
    assert 'region              = "eu-west-1"' in block
    assert "ONE account and ONE region" in block


def test_scope_block_is_commented_out_so_it_cannot_duplicate_a_workspaces_provider():
    # The header tells the reader to drop this file into an existing workspace, which
    # already declares a provider. An active block there is a "Duplicate provider
    # configuration" error, so every line of it must be a comment.
    block = scope_block(_aws_unit())
    for line in block.splitlines():
        assert not line.strip() or line.startswith("#"), f"uncommented line: {line!r}"


def test_scope_block_is_empty_rather_than_wrong_when_a_unit_spans_regions():
    # A CLI unit can span regions; an HCL one cannot for AWS. If such a unit ever
    # reached here, naming an arbitrary region would be worse than naming none.
    unit = _aws_unit(Format.CLI)
    assert unit.region is None
    assert scope_block(unit) == ""


def test_render_hcl_includes_the_providers_scope_block_when_given_one():
    unit = _aws_unit(account_id="111111111111", region="eu-west-1")
    out = render_hcl(
        list(unit.pairs),
        version=VERSION,
        generated_at=STAMP,
        unit=unit,
        command=AWS.command,
        docs_label=AWS.docs_label,
        scope_block=scope_block,
    )
    assert 'allowed_account_ids = ["111111111111"]' in out
    assert AWS.command in out
    assert "AWS docs" in out or not any(r.docs_url for r, _ in unit.pairs)


def test_render_hcl_without_a_scope_block_emits_no_scope_statement():
    # The default exists only for unit tests that render a single block. A file that
    # silently dropped the statement is the one that gets applied against the wrong
    # account, so the omission must be the caller's explicit choice.
    unit = _aws_unit()
    out = render_hcl(list(unit.pairs), version=VERSION, generated_at=STAMP, unit=unit)
    assert "SCOPE:" not in out


def test_hcl_header_is_cloud_neutral_until_a_provider_fills_it_in():
    # The shared renderer must not name AWS on its own; if it did, Azure output would
    # claim to be AWS output and the mistake would be invisible in review.
    out = render_hcl([(_recipe(), _finding())], version=VERSION, generated_at=STAMP)
    header = out.split("# ====")[0]
    assert "AWS" not in header
    assert "aws" not in header.replace("hashicorp/aws", "")
