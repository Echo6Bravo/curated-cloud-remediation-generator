"""Tests for the per-run companion files, README.md and manifest.json.

Shared prose was moved out of the per-finding blocks to stop a run over a large
estate spending most of its output on the same paragraphs repeated hundreds of
times. That is only a safe change if **nothing was lost, only relocated** -- so the
tests here assert that every recipe's summary, prerequisites, caveats and docs URL
are still reachable, and that the safety notes stayed inline where a reviewer of the
commands will see them.
"""

from __future__ import annotations

import json
import re

import pytest

from remgen.artifacts import render_manifest, render_readme
from remgen.generators.awscli import render_cli_script
from remgen.generators.hcl import render_hcl
from remgen.layout import Format, plan_units
from remgen.model import ApiCall, CostImpact, Finding, HclTarget, Recipe
from remgen.recipes import all_recipes

VERSION = "0.0.0-test"
STAMP = "2026-01-01T00:00:00Z"


def _recipe(**overrides) -> Recipe:
    kwargs = {
        "policy_id": "p1",
        "policy_title": "Enable the thing",
        "summary": "Turns on the thing so the finding clears.",
        "api": ApiCall(service="s3", operation="PutThing", parameters=("Bucket",)),
        "cli_template": "aws s3api put-thing --bucket {resource_id} --region {region}",
        "hcl": HclTarget(
            resource_type="aws_thing",
            attributes=(("bucket", '"{resource_id}"'),),
            import_id_template="{resource_id}",
        ),
        "reverse_hint": "aws s3api delete-thing",
        "prerequisites": ("A log group must exist first.",),
        "caveats": ("Applies only to new objects.",),
        "docs_url": "https://docs.aws.amazon.com/thing.html",
    }
    kwargs.update(overrides)
    return Recipe(**kwargs)


def _pairs(recipe=None, specs=(("b1", "us-east-1", "111111111111"),)):
    recipe = recipe or _recipe()
    return [
        (
            recipe,
            Finding(
                policy_id=recipe.policy_id,
                resource_id=rid,
                region=reg,
                account_id=acct,
            ),
        )
        for rid, reg, acct in specs
    ]


def _units(pairs):
    return plan_units(pairs, Format.AWSCLI) + plan_units(pairs, Format.HCL)


def _uncommented(text: str) -> str:
    """Strip comment markers and line wrapping so prose can be matched literally.

    ``comment_block`` wraps to a column, so a long note is not a substring of the
    rendered output even when it is fully present. Matching against the unwrapped
    text tests whether the *note* survived, not how it happened to be wrapped.
    """
    stripped = re.sub(r"(?m)^\s*#\s?", "", text)
    return re.sub(r"\s+", " ", stripped)


def _readme(pairs):
    units = _units(pairs)
    return render_readme(
        units, version=VERSION, generated_at=STAMP, count=len(pairs)
    )


# ---------------------------------------------------------------------------
# Nothing was lost, only relocated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("recipe", all_recipes(), ids=lambda r: r.policy_id)
def test_every_recipes_reference_detail_survives_in_the_readme(recipe):
    """The relocation must not drop anything a reviewer needs.

    Summary, prerequisites, caveats and the docs link left the per-finding comment
    blocks. If they are not in the README, the run simply no longer tells the user
    what the fix does -- which is a loss of information disguised as an optimization.
    """
    text = _readme(_pairs(recipe))
    assert recipe.policy_title in text
    assert recipe.policy_id in text
    assert recipe.summary in text
    for item in recipe.prerequisites + recipe.caveats:
        assert item in text, f"{item!r} is not reachable anywhere"
    if recipe.docs_url:
        assert recipe.docs_url in text


@pytest.mark.parametrize("recipe", all_recipes(), ids=lambda r: r.policy_id)
def test_safety_notes_stay_in_the_artifacts_not_only_the_readme(recipe):
    """Safety notes are the one thing that must not move.

    Reversibility, cost and traffic impact are what a reviewer needs while looking at
    the command itself. A note that lives only in a sibling file is a note that gets
    applied without being read.
    """
    pairs = _pairs(recipe)
    script = _uncommented(render_cli_script(pairs, version=VERSION, generated_at=STAMP))
    for note in recipe.safety_notes:
        assert note in script, f"safety note missing from the script: {note!r}"
    if recipe.hcl is not None:
        hcl = _uncommented(render_hcl(pairs, version=VERSION, generated_at=STAMP))
        for note in recipe.safety_notes:
            assert note in hcl, f"safety note missing from the HCL: {note!r}"


def test_cost_warning_reaches_the_artifact():
    # The single most consequential note, because it is the one that surprises
    # someone applying a fix across a large estate.
    recipe = _recipe(cost_impact=CostImpact.USAGE_SCALED)
    script = render_cli_script(_pairs(recipe), version=VERSION, generated_at=STAMP)
    assert "COST SCALES WITH USAGE" in script


def test_artifacts_point_at_the_readme():
    # The pointer is what makes relocating the detail legitimate rather than a
    # silent omission.
    pairs = _pairs()
    units = plan_units(pairs, Format.AWSCLI)
    script = render_cli_script(
        pairs, version=VERSION, generated_at=STAMP, unit=units[0]
    )
    assert "README.md" in script
    hcl = render_hcl(pairs, version=VERSION, generated_at=STAMP)
    assert "README.md" in hcl


# ---------------------------------------------------------------------------
# Deduplication actually happened
# ---------------------------------------------------------------------------


def test_shared_prose_is_stated_once_per_policy_not_once_per_resource():
    specs = [(f"b{i}", "us-east-1", "111111111111") for i in range(20)]
    pairs = _pairs(specs=specs)
    script = render_cli_script(pairs, version=VERSION, generated_at=STAMP)
    assert script.count("POLICY: Enable the thing") == 1
    # Every resource is still individually present and removable.
    for i in range(20):
        assert f"--bucket b{i} " in script


def test_output_grows_sublinearly_with_resource_count():
    # The property the size work was for: adding a resource to an existing policy
    # group should cost roughly a command, not a full comment block. Checked as a
    # ratio so it holds regardless of the exact prose.
    one = render_cli_script(_pairs(), version=VERSION, generated_at=STAMP)
    many_specs = [(f"b{i}", "us-east-1", "111111111111") for i in range(50)]
    many = render_cli_script(
        _pairs(specs=many_specs), version=VERSION, generated_at=STAMP
    )
    marginal = (len(many) - len(one)) / 49
    assert marginal < 200, f"{marginal:.0f} B per extra resource is too much"


# ---------------------------------------------------------------------------
# README content
# ---------------------------------------------------------------------------


def test_readme_states_that_nothing_was_applied():
    text = _readme(_pairs())
    assert "modify AWS resources" in text
    assert "Nothing has been applied" in text


def test_readme_explains_why_output_is_split_and_the_credential_requirement():
    specs = [("b1", "us-east-1", "111111111111"), ("b2", "us-east-1", "222222222222")]
    text = _readme(_pairs(specs=specs))
    assert "2 AWS account(s)" in text
    assert "credentials for the account named in its filename" in text


def test_readme_states_the_partial_coverage_and_best_effort_position():
    text = _readme(_pairs())
    assert "intentionally partial" in text
    assert "Best effort" in text


def test_readme_records_the_review_checklist_and_both_toolchains():
    text = _readme(_pairs())
    assert "Review checklist" in text
    assert "AWS CLI v2" in text
    assert "OpenTofu >= 1.6" in text
    assert "0 to add" in text  # the plan assertion that catches a wrong import id


# ---------------------------------------------------------------------------
# manifest.json
# ---------------------------------------------------------------------------


def test_manifest_is_valid_json_and_indexes_every_file():
    specs = [("b1", "us-east-1", "111111111111"), ("b2", "eu-west-1", "222222222222")]
    units = _units(_pairs(specs=specs))
    data = json.loads(render_manifest(units, version=VERSION, generated_at=STAMP))
    assert [entry["file"] for entry in data["files"]] == [u.filename for u in units]
    assert data["applied"] is False
    assert data["accounts"] == ["111111111111", "222222222222"]


def test_manifest_records_scope_and_counts_per_file():
    specs = [("b1", "us-east-1", "111111111111"), ("b2", "us-east-1", "111111111111")]
    units = plan_units(_pairs(specs=specs), Format.HCL)
    data = json.loads(render_manifest(units, version=VERSION, generated_at=STAMP))
    entry = data["files"][0]
    assert entry["account_id"] == "111111111111"
    assert entry["region"] == "us-east-1"
    assert entry["remediations"] == 2
    assert entry["policy_counts"] == {"p1": 2}


def test_manifest_declares_policy_detail_once_and_references_it_by_id():
    # Normalized rather than inlined per file: with many accounts, repeating the
    # title and tier in every file entry was most of the manifest.
    specs = [(f"b{i}", "us-east-1", f"{111111111111 + i}") for i in range(10)]
    units = _units(_pairs(specs=specs))
    data = json.loads(render_manifest(units, version=VERSION, generated_at=STAMP))
    assert list(data["policies"]) == ["p1"]
    assert data["policies"]["p1"]["title"] == "Enable the thing"
    assert data["policies"]["p1"]["safety_tier"] == "safest"
    # Every id referenced by a file must resolve in the policy map, or the manifest
    # is a broken index rather than a compact one.
    for entry in data["files"]:
        for policy_id in entry["policy_counts"]:
            assert policy_id in data["policies"]


def test_manifest_region_is_null_when_a_file_spans_regions():
    # A CLI script legitimately spans regions. Recording "all-regions" as if it were
    # a region would mislead a pipeline reading this field.
    specs = [("b1", "us-east-1", "1"), ("b2", "eu-west-1", "1")]
    units = plan_units(_pairs(specs=specs), Format.AWSCLI)
    data = json.loads(render_manifest(units, version=VERSION, generated_at=STAMP))
    assert data["files"][0]["region"] is None


def test_manifest_counts_reconcile_with_the_units():
    specs = [(f"b{i}", "us-east-1", "111111111111") for i in range(25)]
    units = plan_units(_pairs(specs=specs), Format.HCL, max_per_file=10)
    data = json.loads(render_manifest(units, version=VERSION, generated_at=STAMP))
    assert sum(entry["remediations"] for entry in data["files"]) == 25
    assert [entry["part"] for entry in data["files"]] == [1, 2, 3]


# ---------------------------------------------------------------------------
# Size forecast
# ---------------------------------------------------------------------------


def test_size_forecast_does_not_under_predict_a_real_run():
    """The forecast exists to warn before a large run, so it must not under-predict.

    Over-predicting only warns early; under-predicting means the warning does not
    fire for the run that needed it. The constants are anchored on the smallest
    measured run for exactly this reason -- per-policy prose amortizes as a run
    grows, so real B/finding falls with scale while the estimate stays flat.
    """
    from remgen.cli import estimate_output_bytes

    specs = [
        (f"b{i}", ["us-east-1", "eu-west-1"][i % 2], f"{111111111111 + i % 4}")
        for i in range(40)
    ]
    pairs = _pairs(specs=specs)
    actual = 0
    for fmt, render in ((Format.AWSCLI, render_cli_script), (Format.HCL, render_hcl)):
        for unit in plan_units(pairs, fmt):
            actual += len(
                render(
                    list(unit.pairs),
                    version=VERSION,
                    generated_at=STAMP,
                    unit=unit,
                ).encode()
            )
    assert estimate_output_bytes(len(pairs)) >= actual, (
        f"forecast {estimate_output_bytes(len(pairs))} under-predicted actual {actual}"
    )
