"""Invariants of the recipe *set*, as opposed to of any single recipe.

Every other recipe test in this suite is parametrized per recipe, which means none
of them can see a property that only exists across two entries. A duplicate HCL
target, a policy id that appears twice, an API operation two recipes disagree about
-- each is invisible to a test that is handed one recipe at a time, and each is a way
the shipped output goes wrong.

The recipe set is also the file a contributor is most likely to edit, and the one
where a mistake is least likely to look like one: adding a well-formed entry that
collides with an existing one produces plausible-looking artifacts. So these are
written as set-level assertions that a new recipe must satisfy, and each states what
breaks if it does not.
"""

from __future__ import annotations

from collections import Counter, defaultdict

import pytest

from remgen.core.model import CostImpact, SafetyTier
from remgen.providers.aws.recipes import REGISTRY, all_recipes, get


def _recipes():
    return all_recipes()


# ---------------------------------------------------------------------------
# Identity: one entry per policy, reachable by its id
# ---------------------------------------------------------------------------


def test_the_set_is_not_empty():
    # The failure mode of every test below: a set-level assertion over zero items
    # passes while checking nothing. Asserted first so the rest cannot be vacuous.
    assert _recipes(), "the curated recipe set is empty; every invariant below is vacuous"


def test_policy_ids_are_unique():
    """A duplicate id silently shadows a recipe.

    ``REGISTRY`` is built as a dict comprehension, so a repeated ``policy_id`` does
    not raise -- the later entry wins and the earlier one becomes unreachable while
    still appearing in ``recipes`` output and in the README's count. The registry
    module raises on this at import, and this test states the same rule where a
    contributor reading the tests will find it.
    """
    ids = [r.policy_id for r in _recipes()]
    dupes = [pid for pid, n in Counter(ids).items() if n > 1]
    assert not dupes, f"duplicate policy_id(s): {dupes}"
    assert len(REGISTRY) == len(ids)


def test_every_recipe_is_reachable_through_get():
    # `get` is what pairs a finding with a recipe. An entry present in the set but not
    # resolvable by id would be reported as an unsupported policy -- a coverage gap
    # that looks like a deliberate omission.
    for recipe in _recipes():
        assert get(recipe.policy_id) is recipe, f"{recipe.policy_id} is not resolvable"


def test_policy_ids_look_like_uuids():
    """Policy ids come from the live Tenable catalog and are matched exactly.

    A truncated or reformatted id matches no finding, so the recipe never fires and
    the failure looks like "that policy has no coverage" rather than a typo.
    """
    for recipe in _recipes():
        parts = recipe.policy_id.split("-")
        assert [len(p) for p in parts] == [8, 4, 4, 4, 12], (
            f"{recipe.policy_id!r} is not a UUID; it will never match a finding"
        )
        assert recipe.policy_id.islower(), f"{recipe.policy_id} must be lowercase to match"


# ---------------------------------------------------------------------------
# HCL targets: the collision that real parsers do not catch
# ---------------------------------------------------------------------------


def test_no_two_recipes_target_the_same_hcl_resource_type():
    """Two policies on one resource type produce two import blocks for one resource.

    This is the invariant protecting the known open defect (ROADMAP: merge HCL blocks
    targeting one resource). When two recipes share a ``resource_type`` and both match
    the same resource, the generator emits two ``import`` blocks whose ``id`` is
    identical. Real ``tofu validate`` reports **"Success!"** on that file -- it is
    valid configuration -- and the conflict only surfaces at ``plan``/apply time
    against live infrastructure. So no existing gate catches it, and this test is what
    stands in until the merge is implemented.

    If you are adding a recipe that legitimately shares a resource type with an
    existing one, this test is the thing to fix, not to delete: implement the merge
    first and then replace this with an assertion about merged output.
    """
    by_type = defaultdict(list)
    for recipe in _recipes():
        if recipe.hcl is not None:
            by_type[recipe.hcl.resource_type].append(recipe.policy_id)
    collisions = {rtype: ids for rtype, ids in by_type.items() if len(ids) > 1}
    assert not collisions, (
        f"two or more recipes target the same HCL resource type: {collisions}. "
        f"Two import blocks would claim the same resource and `tofu validate` would "
        f"still pass. Implement block merging before shipping this."
    )


def test_hcl_import_templates_reference_only_finding_fields():
    """An import id built from an undefined field renders a literal placeholder.

    ``render_template`` raises on an unknown field, so this would surface as a run
    that fails -- but only for a finding that reaches that recipe. A recipe covering a
    policy absent from the test fixtures could ship broken.
    """
    allowed = {"resource_id", "region", "account_id", "policy_id"}
    for recipe in _recipes():
        if recipe.hcl is None:
            continue
        import re

        fields = set(re.findall(r"\{(\w+)\}", recipe.hcl.import_id_template))
        unknown = fields - allowed
        assert not unknown, f"{recipe.policy_id}: import template references {unknown}"


def test_unresolvable_attributes_are_not_also_declared_as_normal_attributes():
    """The same attribute in both lists emits it twice in one resource block.

    ``attributes`` renders a real value; ``unresolvable_required_attributes`` renders a
    TODO placeholder. An attribute in both produces a duplicate argument, which HCL
    rejects -- but only for the recipes a test happens to render.
    """
    for recipe in _recipes():
        if recipe.hcl is None:
            continue
        normal = {name for name, _value in recipe.hcl.attributes}
        stubs = {name for name, _value, _comment in recipe.hcl.unresolvable_required_attributes}
        overlap = normal & stubs
        assert not overlap, f"{recipe.policy_id}: {overlap} declared as both real and TODO"


# ---------------------------------------------------------------------------
# CLI and API: the two halves must describe the same call
# ---------------------------------------------------------------------------


#: AWS CLI command names that deliberately differ from the botocore service id.
#:
#: These are not typos and must not be "fixed": the S3 REST operations live in the
#: ``s3`` service model but are reached through ``aws s3api``, because ``aws s3`` is a
#: separate higher-level command. An explicit map rather than a looser assertion, so
#: that a genuine mismatch still fails and each exception has to be stated once.
CLI_COMMAND_ALIASES = {"s3": "s3api"}


def test_the_cli_template_invokes_the_service_the_api_call_names():
    """A recipe whose CLI and API disagree is verified against the wrong model.

    ``verify`` checks the ``ApiCall`` against the service model, but the artifact runs
    the ``cli_template``. If they name different services, a green ``verify`` says
    nothing about what the script will actually run -- the strongest form of a test
    that passes while the shipped thing is wrong.
    """
    for recipe in _recipes():
        tokens = recipe.cli_template.split()
        assert tokens[0] == "aws", f"{recipe.policy_id}: CLI template must invoke `aws`"
        expected = CLI_COMMAND_ALIASES.get(recipe.api.service, recipe.api.service)
        assert tokens[1] == expected, (
            f"{recipe.policy_id}: CLI calls `aws {tokens[1]}` but ApiCall names "
            f"{recipe.api.service!r} (expected `aws {expected}`); verify would check "
            f"the wrong service model. If this alias is legitimate, add it to "
            f"CLI_COMMAND_ALIASES with the reason."
        )


def test_every_cli_template_is_scoped_to_one_region_or_is_global():
    """A command with no region runs against the caller's default region.

    Output is split per region precisely so each command targets a known one. A
    template that omits ``--region`` silently inherits ``AWS_DEFAULT_REGION``, so the
    artifact's filename would name a region the command does not use. IAM and other
    global services are the legitimate exception and are listed explicitly rather than
    inferred, so a new global service has to be a deliberate addition.
    """
    global_services = {"iam", "s3api", "organizations", "cloudfront", "route53"}
    for recipe in _recipes():
        if recipe.api.service in global_services:
            continue
        assert "--region" in recipe.cli_template, (
            f"{recipe.policy_id}: `aws {recipe.api.service}` is regional but the "
            f"template has no --region; it would use the caller's default"
        )


def test_reversible_recipes_supply_a_reversal_and_irreversible_ones_say_why():
    """``reversible`` is a claim a reader acts on at 2am, so it must be backed.

    A recipe marked reversible with no reversal command tells the reader the change
    can be undone without telling them how. An irreversible one must say so in its
    *authored* ``caveats``, not merely in the derived ``safety_notes``: those are
    generated from ``reversible`` itself, so asserting them here would only re-derive
    the field and pass unconditionally. The caveat is where a human explains what
    specifically cannot be undone -- versioning suspends but never disables, a
    completed KMS rotation stays completed -- which no derivation can produce.
    """
    for recipe in _recipes():
        if recipe.reversible:
            assert recipe.reverse_hint.strip(), (
                f"{recipe.policy_id}: claims reversible but supplies no reversal"
            )
            continue
        joined = " ".join(recipe.caveats).lower()
        assert recipe.caveats, (
            f"{recipe.policy_id}: is irreversible and must explain in `caveats` what "
            f"cannot be undone; the derived safety note only repeats the flag"
        )
        assert any(word in joined for word in ("undo", "cannot", "never", "permanent")), (
            f"{recipe.policy_id}: is irreversible but no caveat says what is permanent"
        )


# ---------------------------------------------------------------------------
# Safety classification: the promise the default safety level makes
# ---------------------------------------------------------------------------


def test_safest_recipes_carry_no_ongoing_cost():
    """``safest`` is the default, so it is the tier that gets run unexamined.

    Scope is deliberate and narrow. ``safety_tier`` is a *derived* property computed
    from ``reversible``, ``data_path_impact``, ``effort`` and ``blocks_iac_destroy``,
    so asserting those four of a ``safest`` recipe re-implements the derivation and
    cannot fail -- an earlier version of this test did exactly that. The one thing the
    formula does **not** gate is ``CostImpact.LOW``: a recipe with a small recurring
    charge still derives to ``safest`` and is emitted by a default run.

    That is arguably correct -- a few dollars a month is not a safety problem -- but it
    is a judgement, not a consequence of the tier, so it is stated here where changing
    it requires changing an assertion. If a ``safest`` recipe should be allowed to cost
    money, add the reason to its caveats and list it below.
    """
    for recipe in _recipes():
        if recipe.safety_tier is not SafetyTier.SAFEST:
            continue
        assert recipe.cost_impact is CostImpact.NONE, (
            f"{recipe.policy_id}: is `safest` -- what a default run emits without review "
            f"-- but carries {recipe.cost_impact.value} ongoing cost. The tier formula "
            f"does not catch this; only this test does."
        )


def test_the_reversal_undoes_the_same_call_the_remediation_makes():
    """A reversal naming a different operation does not undo the change.

    ``reverse_hint`` is free prose that is printed to an operator as the way out, and
    nothing else checks it. A hint that drifted to another subcommand -- after a
    copy-paste between recipes, which is how this file grows -- reads as authoritative
    and silently does something else, or nothing. So the service and subcommand must
    match the remediation's own; only the flags may differ, since inverting the change
    is the point.
    """
    for recipe in _recipes():
        if not recipe.reverse_hint:
            continue
        forward = recipe.cli_template.split()
        reverse = recipe.reverse_hint.split()
        assert reverse[:1] == ["aws"], f"{recipe.policy_id}: reverse_hint must invoke `aws`"
        assert reverse[1:3] == forward[1:3], (
            f"{recipe.policy_id}: remediation runs `{' '.join(forward[1:3])}` but the "
            f"reversal runs `{' '.join(reverse[1:3])}`; it does not undo the same call"
        )


def test_at_least_one_recipe_is_safest():
    """The default safety level must produce something.

    If every recipe were `caution`, a default `generate` would emit no remediations
    and report a clean run -- indistinguishable from having no findings. The README
    states the split, and CI asserts the README matches; this asserts the property the
    number describes.
    """
    tiers = {r.safety_tier for r in _recipes()}
    assert SafetyTier.SAFEST in tiers, (
        "no recipe is `safest`, so a default run emits nothing and looks like success"
    )


def test_usage_scaled_cost_comes_with_a_way_to_bound_it():
    """The generic warning is derived; the way to *act* on it is not.

    ``safety_notes`` already emits "COST SCALES WITH USAGE" from ``cost_impact``, so
    asserting that string here would only re-derive the field. What is authored -- and
    therefore what can actually be missing -- is the caveat telling the reader how to
    put a ceiling on it. Unbounded cost is the one consequence in this tool that keeps
    accruing after the run ends, so a recipe that creates it owes the reader a bound.
    """
    for recipe in _recipes():
        if recipe.cost_impact is not CostImpact.USAGE_SCALED:
            continue
        joined = " ".join(recipe.caveats).lower()
        assert "cost" in joined, (
            f"{recipe.policy_id}: cost scales with usage but no authored caveat "
            f"discusses it; the derived note states the fact and nothing more"
        )
        assert any(word in joined for word in ("lifecycle", "expir", "estimate", "ceiling")), (
            f"{recipe.policy_id}: warns that cost grows without bound but names no way "
            f"to bound it (a lifecycle/expiration rule, or how to estimate first)"
        )


# ---------------------------------------------------------------------------
# Prose: the fields a reviewer reads
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field", ["policy_title", "summary", "cli_template", "docs_url", "reverse_hint"]
)
def test_no_recipe_ships_an_empty_prose_field(field):
    # An empty string is a legal value that renders as a blank line in the artifact,
    # which reads as "there is nothing to say here" rather than "this was not written".
    for recipe in _recipes():
        value = getattr(recipe, field)
        if field == "reverse_hint" and not recipe.reversible:
            continue
        assert value and value.strip(), f"{recipe.policy_id}: {field} is empty"


def test_titles_are_unique_so_the_readme_index_is_unambiguous():
    # `all_recipes` sorts by title for deterministic output, and the run README indexes
    # by it. Two identical titles make two different remediations indistinguishable in
    # the one document that explains them.
    titles = [r.policy_title for r in _recipes()]
    dupes = [t for t, n in Counter(titles).items() if n > 1]
    assert not dupes, f"duplicate policy titles: {dupes}"
