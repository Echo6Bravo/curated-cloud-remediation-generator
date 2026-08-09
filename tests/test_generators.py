"""Tests for the output generators.

The central property under test: **no value from a finding can change the
structure of a generated artifact.** Everything else here is secondary.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from remgen.core.generators.common import TemplateError, comment_block, render_template
from remgen.core.generators.hcl import (
    AmbiguousImportError,
    HclMergeConflict,
    group_targets,
    render_hcl,
    version_constraint_block,
)
from remgen.core.generators.hcl import render_one as render_hcl_one
from remgen.core.layout import Format, plan_units
from remgen.core.model import (
    ApiCall,
    CostImpact,
    Effort,
    Finding,
    HclTarget,
    Recipe,
    SafetyTier,
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


def _labels(pairs) -> list[str]:
    return [t.label for t in group_targets(pairs)]


def test_same_name_in_two_regions_gets_distinct_labels():
    """Two labels for two resources whose names fold together.

    Uses two regions in *one* account rather than two accounts: two accounts sharing
    a resource name is a different and worse condition, and `group_targets` now
    refuses it outright -- see
    test_two_accounts_sharing_a_resource_name_refuse_to_render. The label rule under
    test here is the same either way.
    """
    recipe = _recipe()
    pairs = [
        (recipe, _finding(region="us-east-1", resource_id="a/b")),
        (recipe, _finding(region="us-west-2", resource_id="a_b")),
    ]
    assert len(set(_labels(pairs))) == 2

    out = render_hcl(pairs, version=VERSION, generated_at=STAMP)
    declared = [line for line in out.splitlines() if line.startswith('resource "aws_thing"')]
    assert len(declared) == 2
    assert len(set(declared)) == 2, "duplicate resource label would fail tofu validate"


def test_unique_resource_id_keeps_the_short_label():
    # Disambiguation is applied only where needed, so the common case stays legible.
    assert _labels([(_recipe(), _finding(resource_id="only-one"))]) == ["only-one"]


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
    assert _labels([(a, _finding()), (b, _finding())]) == ["my-bucket", "my-bucket"]


def test_two_ids_that_fold_to_one_label_still_get_unique_labels():
    """The ordinal backstop, reached without any duplicate input.

    ``to_hcl_label`` folds punctuation to underscores, so ``a/b`` and ``a_b`` are two
    genuinely different resources whose labels collide -- and after the
    account+region suffix is appended they *still* collide, because both resources
    are in the same account and region. An ordinal is used rather than a digest,
    which would be stable but unreadable, and merging is not an option: these are
    two different resources with two different import ids.
    """
    recipe = _recipe()
    pairs = [(recipe, _finding(resource_id="a/b")), (recipe, _finding(resource_id="a_b"))]
    labels = _labels(pairs)
    assert len(set(labels)) == 2, f"labels collided: {labels}"
    out = render_hcl(pairs, version=VERSION, generated_at=STAMP)
    assert out.count('resource "aws_thing"') == 2
    assert 'id = "a/b"' in out and 'id = "a_b"' in out


def test_labels_are_stable_regardless_of_input_order():
    # Same set in a different order must give each finding the same label, so
    # regenerating produces a reviewable diff rather than a reshuffle.
    recipe = _recipe()
    f1 = _finding(region="us-east-1", resource_id="a/b")
    f2 = _finding(region="us-west-2", resource_id="a_b")
    forward = {t.finding: t.label for t in group_targets([(recipe, f1), (recipe, f2)])}
    reverse = {t.finding: t.label for t in group_targets([(recipe, f2), (recipe, f1)])}
    assert forward == reverse
    assert len(forward) == 2


def test_import_and_resource_labels_agree_after_disambiguation():
    # The import block must point at the resource block it pairs with; if only one
    # of the two were disambiguated, the plan would create instead of import.
    recipe = _recipe()
    pairs = [
        (recipe, _finding(region="us-east-1", resource_id="a/b")),
        (recipe, _finding(region="us-west-2", resource_id="a_b")),
    ]
    out = render_hcl(pairs, version=VERSION, generated_at=STAMP)
    targets = {
        line.split("aws_thing.")[1].strip()
        for line in out.splitlines()
        if "to = aws_thing." in line
    }
    declared = {line.split('"')[3] for line in out.splitlines() if line.startswith('resource "')}
    assert targets == declared
    assert len(targets) == 2


# ---------------------------------------------------------------------------
# Merging: one live resource gets one block, however many policies it violates
#
# The defect these replace: two recipes on one resource emitted two `import`
# blocks carrying the same `id`. That file is *valid configuration* -- real
# `tofu validate` reports "Success!" on it, verified -- so no parser-level gate
# could catch it, and the conflict surfaced only at plan/apply against live
# infrastructure. Label disambiguation made the labels unique while leaving both
# imports pointed at one resource, which hid it rather than fixing it. So these
# assert on the import ids, never on the labels.
# ---------------------------------------------------------------------------


def _two_policies_on_one_bucket():
    """Two recipes for ``aws_thing``, agreeing on ``bucket`` and each adding one."""
    versioning = _recipe(
        policy_id="versioning",
        policy_title="Enable versioning",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'), ("versioning", "true")),
            import_id_template="{resource_id}",
        ),
    )
    encryption = _recipe(
        policy_id="encryption",
        policy_title="Enable encryption",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'), ("encrypted", "true")),
            import_id_template="{resource_id}",
        ),
    )
    return versioning, encryption


def test_two_policies_on_one_resource_produce_one_import_block():
    a, b = _two_policies_on_one_bucket()
    finding = _finding(resource_id="shared-bucket")
    out = render_hcl([(a, finding), (b, finding)], version=VERSION, generated_at=STAMP)

    assert out.count("import {") == 1, (
        "two import blocks for one resource: valid HCL that `tofu validate` accepts "
        "and that fails only at plan/apply"
    )
    assert out.count('resource "aws_thing"') == 1
    assert out.count('id = "shared-bucket"') == 1
    # Both remediations survived the merge -- one block, not one policy dropped.
    # Whitespace-normalized: `tofu fmt` alignment pads to the widest name in the
    # block, so an exact-spacing assertion would fail on an unrelated added
    # attribute rather than on a dropped remediation.
    body = " ".join(out.split())
    assert "versioning = true" in body
    assert "encrypted = true" in body


def test_the_merged_block_names_every_policy_it_applies():
    # A block that changes two things must say so where it is read. Otherwise a
    # reviewer approves one policy and applies another.
    a, b = _two_policies_on_one_bucket()
    finding = _finding(resource_id="shared-bucket")
    out = render_hcl([(a, finding), (b, finding)], version=VERSION, generated_at=STAMP)
    assert "versioning" in out and "encryption" in out
    assert "2 POLICIES on this one resource" in out
    assert "Enable versioning" in out and "Enable encryption" in out


def test_a_shared_attribute_is_emitted_once_not_twice():
    # Both recipes set `bucket`. Emitting it twice is a duplicate argument, which
    # HCL *does* reject -- so this is the half of the defect a parser would catch.
    a, b = _two_policies_on_one_bucket()
    finding = _finding(resource_id="shared-bucket")
    out = render_hcl([(a, finding), (b, finding)], version=VERSION, generated_at=STAMP)
    assert " ".join(out.split()).count('bucket = "shared-bucket"') == 1


def test_recipes_that_disagree_about_a_value_refuse_to_render():
    """Picking a winner would silently drop a remediation the user asked for."""
    a = _recipe(
        policy_id="wants-true",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("setting", "true"),),
            import_id_template="{resource_id}",
        ),
    )
    b = _recipe(
        policy_id="wants-false",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("setting", "false"),),
            import_id_template="{resource_id}",
        ),
    )
    finding = _finding()
    with pytest.raises(HclMergeConflict) as exc:
        render_hcl([(a, finding), (b, finding)], version=VERSION, generated_at=STAMP)
    message = str(exc.value)
    # The message has to name both policies and both values, or the reader cannot
    # tell which recipe to change.
    assert "wants-true" in message and "wants-false" in message
    assert "setting" in message
    assert "'true'" in message and "'false'" in message


def test_a_real_value_supersedes_another_recipes_TODO_placeholder():
    """The concrete win of merging, not just a tidier file.

    One recipe cannot derive an attribute and stubs it; another sets it for real.
    Merged, the block needs less human completion than either recipe alone -- and
    the TODO must be gone, because a leftover placeholder next to a real value is
    the case that reconfigures a resource with ``"TODO"``.
    """
    stubbed = _recipe(
        policy_id="stubs-it",
        policy_title="Stubs it",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'),),
            import_id_template="{resource_id}",
            unresolvable_required_attributes=(("engine", '"TODO"', "TODO: set the real engine"),),
        ),
    )
    knows = _recipe(
        policy_id="knows-it",
        policy_title="Knows it",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'), ("engine", '"postgres"')),
            import_id_template="{resource_id}",
        ),
    )
    finding = _finding()
    targets = group_targets([(stubbed, finding), (knows, finding)])
    assert len(targets) == 1
    assert targets[0].is_complete, "the stub was filled in, so nothing is left to complete"
    assert targets[0].unresolvable_names == ()

    out = render_hcl([(stubbed, finding), (knows, finding)], version=VERSION, generated_at=STAMP)
    assert '"postgres"' in out
    assert "TODO" not in out, "a leftover TODO beside a real value is what applies `TODO`"


def test_merging_is_keyed_on_the_rendered_import_id_not_the_template():
    """``import_id_template`` is a template, so two resources share one template.

    ``aws_cloudtrail`` renders
    ``arn:aws:cloudtrail:{region}:{account_id}:trail/{resource_id}``. Keying the
    merge on the template would collapse every trail in the file into one block --
    a far worse defect than the one merging fixes, and one that would look like it
    worked.
    """
    recipe = _recipe(
        hcl=HclTarget(
            resource_type="aws_cloudtrail",
            attributes=(("name", '"{resource_id}"'),),
            import_id_template="arn:aws:cloudtrail:{region}:{account_id}:trail/{resource_id}",
        )
    )
    pairs = [(recipe, _finding(resource_id="trail-a")), (recipe, _finding(resource_id="trail-b"))]
    out = render_hcl(pairs, version=VERSION, generated_at=STAMP)
    assert out.count("import {") == 2
    assert "trail/trail-a" in out and "trail/trail-b" in out


def test_two_accounts_sharing_a_resource_name_refuse_to_render():
    """The worst outcome this tool could produce, now refused rather than emitted.

    `{resource_id}`-style import ids carry no account, so `GameScores` in two
    accounts renders two `import` blocks with the *same* id. Whichever account the
    provider authenticates to, one of them adopts and reconfigures the same-named
    resource in the wrong account. `tofu validate` accepts the file.

    A correct caller never reaches this, because `plan_units` splits by account
    first -- which is why this went unnoticed. But that split is the only thing
    preventing it, and the generator cannot verify that another module was careful,
    so it asserts the property itself.
    """
    recipe = _recipe()
    pairs = [
        (recipe, _finding(account_id="111111111111")),
        (recipe, _finding(account_id="222222222222")),
    ]
    with pytest.raises(AmbiguousImportError) as exc:
        render_hcl(pairs, version=VERSION, generated_at=STAMP)
    message = str(exc.value)
    assert "111111111111" in message and "222222222222" in message
    # Both scopes named, and the consequence stated. The *noun* is asserted
    # separately below, per cloud: this call passes no unit, so it gets the neutral
    # default, and asserting "account" here would have pinned the message to one
    # cloud's vocabulary in a test about the refusal.
    assert "would be imported twice" in message
    assert "wrong credential scope" in message


@pytest.mark.parametrize(
    ("scope_noun", "wrong_noun"),
    [("account", "subscription"), ("subscription", "account")],
)
def test_the_clash_message_uses_the_cloud_s_own_word_for_the_scope(scope_noun, wrong_noun):
    """The exit-6 message an operator reads must name a thing in their estate.

    This message tells someone what to do about a refusal, and it hardcoded
    "account": an Azure user was told that "one provider configuration covers one
    account" and to "split the findings by account". Neither names anything they
    have, so the one instruction the tool gives them is unfollowable.

    Both directions are asserted -- the right noun present *and* the other cloud's
    noun absent -- because a message that appended the correct word while leaving the
    wrong one in place would satisfy a presence-only check.
    """
    recipe = _recipe()
    pairs = [
        (recipe, _finding(account_id="111111111111")),
        (recipe, _finding(account_id="222222222222")),
    ]
    with pytest.raises(AmbiguousImportError) as exc:
        group_targets(pairs, scope_noun=scope_noun)
    message = str(exc.value)
    assert f"wrong {scope_noun}" in message
    assert wrong_noun not in message, (
        f"the message still names {wrong_noun!r} while claiming to describe a {scope_noun}"
    )


def test_two_regions_sharing_a_resource_name_also_refuse_to_render():
    # Same defect, one account. Reachable only for a provider that is not
    # region-scoped, where `plan_units` does not split by region.
    recipe = _recipe()
    pairs = [
        (recipe, _finding(region="us-east-1")),
        (recipe, _finding(region="us-west-2")),
    ]
    with pytest.raises(AmbiguousImportError, match="us-east-1"):
        render_hcl(pairs, version=VERSION, generated_at=STAMP)


def test_the_layout_split_keeps_a_real_run_clear_of_that_refusal():
    """The refusal must not be reachable through the normal path.

    An assertion that fires on ordinary input is a broken tool rather than a guard,
    so this renders the same cross-account findings the way the CLI does -- planned
    into units first -- and requires every unit to render.
    """
    recipe = _recipe()
    pairs = [
        (recipe, _finding(account_id="111111111111")),
        (recipe, _finding(account_id="222222222222")),
        (recipe, _finding(account_id="111111111111", region="us-west-2")),
    ]
    units = plan_units(pairs, Format.HCL, cloud="aws")
    assert len(units) == 3, "the split is what makes each file unambiguous"
    for unit in units:
        out = render_hcl(list(unit.pairs), version=VERSION, generated_at=STAMP, unit=unit)
        assert out.count("import {") == 1


def test_duplicate_pairs_collapse_to_one_block():
    # The CLI dedupes findings, so this is a generator-level backstop. Previously
    # these got three distinct labels and three import blocks with one id.
    recipe = _recipe()
    finding = _finding()
    targets = group_targets([(recipe, finding)] * 3)
    assert len(targets) == 1
    assert targets[0].recipes == (recipe,) * 3


def test_a_merged_block_is_filed_under_the_riskiest_tier_it_carries():
    """The banner is a gate, so it must describe the whole block.

    A merged block is applied as a unit. Filing it under SAFEST because one of its
    two policies is safe would put an irreversible change under the banner that
    says reversible -- and `--safety-level` is what a user reads to decide.
    """
    safe, _ = _two_policies_on_one_bucket()
    risky = _recipe(
        policy_id="risky",
        policy_title="Risky one",
        reversible=False,
        reverse_hint="",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'), ("risky", "true")),
            import_id_template="{resource_id}",
        ),
    )
    finding = _finding()
    targets = group_targets([(safe, finding), (risky, finding)])
    assert len(targets) == 1
    assert targets[0].safety_tier is SafetyTier.CAUTION

    out = render_hcl([(safe, finding), (risky, finding)], version=VERSION, generated_at=STAMP)
    assert "Safety tier: CAUTION" in out
    assert "Safety tier: SAFEST" not in out, (
        "the merged block appeared under SAFEST, which is the banner a user trusts"
    )
    # And the irreversibility warning travels with it.
    assert "NOT REVERSIBLE" in out


def test_each_note_on_a_merged_block_says_which_policy_it_came_from():
    """Two reversal commands in one block are ambiguous unless each is attributed.

    A merged block emits the union of its contributors' safety notes, so two recipes
    produce two `Reversible: <command>` lines with *different* commands. Unattributed,
    a reader undoing the block takes either one as "the" reversal and leaves the other
    policy's change in place -- believing they had reverted it. The policy title on
    each line is what makes the pair readable as two things to undo.
    """
    a, b = _two_policies_on_one_bucket()
    a = replace(a, reverse_hint="turn versioning off")
    b = replace(b, reverse_hint="turn encryption off")
    finding = _finding(resource_id="shared-bucket")
    out = render_hcl([(a, finding), (b, finding)], version=VERSION, generated_at=STAMP)

    body = " ".join(out.split())
    for recipe, hint in ((a, "turn versioning off"), (b, "turn encryption off")):
        assert f"[{recipe.policy_title}] Reversible: {hint}" in body, (
            f"the reversal for {recipe.policy_title!r} is not attributed to it; a "
            f"reader cannot tell which of the two commands undoes which change:\n{out}"
        )


def test_a_merged_block_requires_the_highest_provider_version_of_its_parts():
    # Understating the requirement produces a file that fails `init` against the
    # version the header told the reader to use.
    # 5.9 and 5.12 specifically: 5.12 is the higher version, but "5.12" sorts
    # *below* "5.9" as a string, so a lexicographic comparison picks 5.9 and
    # understates the requirement. A 5.0/5.12 pair would not catch that, because
    # string and numeric order agree there.
    low = _recipe(
        policy_id="low",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("a", "true"),),
            import_id_template="{resource_id}",
            min_provider_version="5.9",
        ),
    )
    high = _recipe(
        policy_id="high",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("b", "true"),),
            import_id_template="{resource_id}",
            min_provider_version="5.12",
        ),
    )
    finding = _finding()
    # Both input orders, even though group_targets sorts internally: the assertion
    # is about the comparison, and a future change to that sort must not quietly
    # turn this into a one-order test.
    for pairs in ([(low, finding), (high, finding)], [(high, finding), (low, finding)]):
        assert group_targets(pairs)[0].min_provider_version == "5.12"


def test_merged_nested_blocks_are_combined_rather_than_repeated():
    a = _recipe(
        policy_id="a",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'),),
            import_id_template="{resource_id}",
            blocks=(("config", (("first", '"1"', ""),)),),
        ),
    )
    b = _recipe(
        policy_id="b",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'),),
            import_id_template="{resource_id}",
            blocks=(("config", (("second", '"2"', ""),)),),
        ),
    )
    finding = _finding()
    out = render_hcl([(a, finding), (b, finding)], version=VERSION, generated_at=STAMP)
    assert out.count("config {") == 1, "a repeated block is a different resource shape"
    assert '"1"' in out and '"2"' in out


def test_nested_blocks_that_disagree_also_refuse_to_render():
    a = _recipe(
        policy_id="a",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'),),
            import_id_template="{resource_id}",
            blocks=(("config", (("status", '"Enabled"', ""),)),),
        ),
    )
    b = _recipe(
        policy_id="b",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'),),
            import_id_template="{resource_id}",
            blocks=(("config", (("status", '"Suspended"', ""),)),),
        ),
    )
    finding = _finding()
    with pytest.raises(HclMergeConflict, match="config.status"):
        render_hcl([(a, finding), (b, finding)], version=VERSION, generated_at=STAMP)


def test_merged_output_is_independent_of_input_order():
    a, b = _two_policies_on_one_bucket()
    finding = _finding()
    forward = render_hcl([(a, finding), (b, finding)], version=VERSION, generated_at=STAMP)
    reverse = render_hcl([(b, finding), (a, finding)], version=VERSION, generated_at=STAMP)
    assert forward == reverse, "regenerating would produce a reshuffle instead of a diff"


def test_no_import_id_is_ever_claimed_twice_in_any_generated_file():
    """The invariant, asserted end-to-end over a run that mixes every case at once.

    Two accounts, two resources each, two policies merging on one resource type plus
    a third on another -- planned into units exactly as the CLI does, then every unit
    checked. Stated as a property over the emitted ``import`` ids rather than as a
    block count, because that is what was actually wrong: an id appearing twice for
    one resource type is the defect, whatever the labels look like.
    """
    a, b = _two_policies_on_one_bucket()
    other = _recipe(
        policy_id="other",
        policy_title="Other thing",
        hcl=HclTarget(
            resource_type="aws_other",
            attributes=(("name", '"{resource_id}"'),),
            import_id_template="{resource_id}",
        ),
    )
    pairs = []
    for account in ("111111111111", "222222222222"):
        for resource in ("one", "two"):
            finding = _finding(resource_id=resource, account_id=account)
            pairs.extend([(a, finding), (b, finding), (other, finding)])

    units = plan_units(pairs, Format.HCL, cloud="aws")
    seen: set[tuple[str, str, str]] = set()
    for unit in units:
        out = render_hcl(list(unit.pairs), version=VERSION, generated_at=STAMP, unit=unit)
        rtype = None
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("to = "):
                rtype = stripped.removeprefix("to = ").split(".")[0]
            elif stripped.startswith("id = ") and rtype is not None:
                # Scoped by file: the same id in two files is correct, because each
                # file is applied with its own account's credentials.
                key = (unit.relative_path, rtype, stripped)
                assert key not in seen, f"{key} is claimed by two import blocks"
                seen.add(key)
                rtype = None
    # 2 accounts x 2 resources x (one merged aws_thing + one aws_other).
    assert len(seen) == 8


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
    assert recipe.safety_tier is not SafetyTier.DISRUPTIVE
    assert recipe.effort is Effort.LOW
    assert not recipe.data_path_impact


# ---------------------------------------------------------------------------
# The provider version constraint
#
# The property under test throughout: **a floor with no ceiling is worse than no
# constraint at all.** Unbounded, a generated file resolves to whatever major is
# newest on the day the *user* runs `init`, so a break lands in their terminal
# against a major nobody verified and reads as a defect in the file. So the tests
# below are mostly about the upper bound existing, being exclusive, and never being
# asserted from a value nobody measured.
# ---------------------------------------------------------------------------


def test_the_constraint_bounds_the_next_major_exclusively():
    # The ceiling is `< 7.0`, not `<= 6`: every minor and patch inside the verified
    # major must be allowed, or a routine 6.58 release stops resolving.
    out = version_constraint_block(
        provider_source="hashicorp/aws", verified_major=6, min_version="5.0"
    )
    assert 'version = ">= 5.0, < 7.0"' in out
    assert 'source  = "hashicorp/aws"' in out
    assert "required_providers" in out


def test_the_constraint_is_commented_out_so_it_cannot_duplicate_a_workspaces_own():
    # A module may hold exactly one `required_providers` configuration, and the header
    # tells the reader to drop this file into a workspace that already has one. Active,
    # this block is a "Duplicate required providers configuration" error at `init` --
    # the same reason the provider block is commented, which is why it is asserted the
    # same way rather than trusted to the comment explaining it.
    out = version_constraint_block(
        provider_source="hashicorp/aws", verified_major=6, min_version="5.0"
    )
    for line in out.splitlines():
        assert not line.strip() or line.startswith("#"), f"uncommented line: {line!r}"


def test_the_local_provider_name_comes_from_the_source_not_the_cloud():
    """``azure`` declares ``azurerm``, which is the case a cloud-derived name gets wrong.

    ``required_providers`` keys on the local name, and every reference in the file
    resolves through it. Deriving it from the cloud id would emit ``azure = { source =
    "hashicorp/azurerm" }``, which ``init`` accepts -- it is a legal rename -- and which
    then fails to match the ``provider "azurerm"`` block in the same file.
    """
    out = version_constraint_block(
        provider_source="hashicorp/azurerm", verified_major=5, min_version="5.0"
    )
    assert "azurerm = {" in out
    assert "azure = {" not in out
    assert 'version = ">= 5.0, < 6.0"' in out


@pytest.mark.parametrize(
    ("source", "major"),
    [
        ("", 6),  # a bound with no provider to name
        ("hashicorp/aws", 0),  # a provider with no verified ceiling
        ("", 0),  # neither
        ("hashicorp/aws", -1),  # a ceiling that cannot be rendered as one
    ],
)
def test_an_unjustifiable_constraint_is_omitted_rather_than_guessed(source, major):
    # Both halves read as a checked claim, so a constraint naming the wrong provider or
    # bounding at a major nobody verified is worse than none. The descriptor guards in
    # test_structure.py stop a real cloud reaching here; this is the render-time floor.
    assert (
        version_constraint_block(provider_source=source, verified_major=major, min_version="5.0")
        == ""
    )


def test_a_floor_above_the_verified_ceiling_is_refused_rather_than_emitted():
    """The one case where the two halves contradict each other.

    A recipe requiring 7.x under a ceiling of ``< 7.0`` emits a constraint no version
    satisfies. ``tofu init`` reports that as "no available releases match", which is
    true and says nothing about the cause: a recipe was written against a major nobody
    re-verified, so the *ceiling* is what is stale. Raising here names that.
    """
    with pytest.raises(ValueError, match="unsatisfiable"):
        version_constraint_block(
            provider_source="hashicorp/aws", verified_major=6, min_version="7.1"
        )


def test_the_files_constraint_takes_the_highest_floor_among_its_blocks():
    """One file gets one constraint, so it must satisfy every block in it.

    The versions are 5.9 and 5.12 for the reason
    ``test_a_merged_block_requires_the_highest_provider_version_of_its_parts`` uses
    them: "5.12" sorts *below* "5.9" as a string, so a lexicographic max understates
    the requirement and the file fails `init` against a version its own per-policy
    notes said was enough. These two recipes target *different* resources, so this is
    the file-wide aggregate rather than the per-merge one that test covers.
    """
    low = _recipe(
        policy_id="low",
        hcl=HclTarget(
            resource_type="aws_thing",
            attributes=(("a", "true"),),
            import_id_template="{resource_id}",
            min_provider_version="5.9",
        ),
    )
    high = _recipe(
        policy_id="high",
        hcl=HclTarget(
            resource_type="aws_other",
            attributes=(("b", "true"),),
            import_id_template="{resource_id}",
            min_provider_version="5.12",
        ),
    )
    finding = _finding()
    for pairs in ([(low, finding), (high, finding)], [(high, finding), (low, finding)]):
        out = render_hcl(
            pairs,
            version=VERSION,
            generated_at=STAMP,
            provider_source="hashicorp/aws",
            verified_major=6,
        )
        assert 'version = ">= 5.12, < 7.0"' in out, "the file understated its own floor"


def test_render_hcl_emits_no_constraint_when_the_caller_supplies_no_verified_major():
    # The defaults keep a caller that has neither -- every unit test here, and any
    # future cloud without HCL -- rendering as before, rather than emitting a bound it
    # cannot justify. Asserted so the defaults cannot quietly grow a made-up ceiling.
    out = render_hcl([(_recipe(), _finding())], version=VERSION, generated_at=STAMP)
    assert "required_providers" not in out
    assert "PROVIDER VERSION" not in out


def test_a_file_with_no_remediable_findings_claims_no_provider_version():
    # A no-results file configures nothing, so a version constraint on it would bound
    # a provider it never uses -- and would be the only content in the file besides
    # the header saying nothing was generated.
    out = render_hcl(
        [(_recipe(hcl=None), _finding())],
        version=VERSION,
        generated_at=STAMP,
        provider_source="hashicorp/aws",
        verified_major=6,
    )
    assert "No remediable findings" in out
    assert "required_providers" not in out


def test_the_constraint_precedes_the_scope_block_and_every_resource():
    """Order is a readability claim, and the one place it could silently invert.

    The constraint is *computed* after ``group_targets`` -- it needs the file-wide
    minimum, which is only known once every target is merged -- but it must be
    *rendered* before the scope statement, because a reader scanning from the top has
    to reach the version requirement before the first block that depends on it.
    """
    unit = _aws_unit(account_id="111111111111", region="eu-west-1")
    out = render_hcl(
        list(unit.pairs),
        version=VERSION,
        generated_at=STAMP,
        unit=unit,
        command=AWS.command,
        scope_block=scope_block,
        provider_source=AWS.tf_provider_source,
        verified_major=AWS.tf_provider_verified_major,
    )
    assert out.index("PROVIDER VERSION") < out.index("SCOPE:") < out.index("import {")


def test_the_constraint_says_which_half_of_the_range_was_actually_verified():
    """The floor and the ceiling are different kinds of claim, and it must say so.

    The ceiling is "we verified this major". The floor is the recipes' own
    ``min_provider_version`` -- the release at which the arguments first existed --
    which for AWS is 5.0 while verification happened on 6.x. So the emitted
    ``>= 5.0, < 7.0`` is *not* a verified range, and a block headed "Verified against
    hashicorp/aws 6.x" immediately above it invites reading it as one.
    """
    out = version_constraint_block(
        provider_source="hashicorp/aws", verified_major=6, min_version="5.0"
    )
    assert "not a verified range" in out


def test_a_range_wholly_inside_the_verified_major_does_not_warn_about_itself():
    """The Azure case, and the reason the caveat is conditional rather than always on.

    ``azurerm`` is verified at 5.x and its recipes floor at 5.0, so ``>= 5.0, < 6.0``
    admits nothing outside the tested major. Printing the AWS caveat here would tell the
    reader their constraint allows untested versions when it does not, and the fix it
    offers -- pin to 5.x -- is what the constraint already says.
    """
    out = version_constraint_block(
        provider_source="hashicorp/azurerm", verified_major=5, min_version="5.0"
    )
    assert 'version = ">= 5.0, < 6.0"' in out
    assert "not a verified range" not in out


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
        scope_block=scope_block,
    )
    assert 'allowed_account_ids = ["111111111111"]' in out
    assert AWS.command in out


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
