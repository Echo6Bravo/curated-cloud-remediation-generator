"""Invariants of the recipe *set*, as opposed to of any single recipe.

Every other recipe test in this suite is parametrized per recipe, which means none
of them can see a property that only exists across two entries. Two recipes
sharing an HCL target while disagreeing about what to set, a policy id that appears
twice, an API operation two recipes disagree about -- each is invisible to a test that
is handed one recipe at a time, and each is a way the shipped output goes wrong.

The recipe set is also the file a contributor is most likely to edit, and the one
where a mistake is least likely to look like one: adding a well-formed entry that
collides with an existing one produces plausible-looking artifacts. So these are
written as set-level assertions that a new recipe must satisfy, and each states what
breaks if it does not.

**Two invariants were considered for this file and deliberately left out.** Both are
recorded here because each looks like an obvious gap, and the reason it is not is the
kind of thing that gets rediscovered by writing the test and only later noticing it
proves nothing.

1. *That a merged block inherits the riskiest tier and the highest provider version of
   its contributors.* Already covered, against constructed overlaps, by
   ``test_a_merged_block_is_filed_under_the_riskiest_tier_it_carries`` and
   ``test_a_merged_block_requires_the_highest_provider_version_of_its_parts`` in
   ``tests/test_generators.py`` -- the latter with a ``5.9``/``5.12`` pair chosen because
   a lexicographic comparison passes a ``5.0``/``5.12`` one. A set-level restatement
   could not fail today for the reason
   ``test_the_whole_set_applied_to_one_resource_emits_one_block_per_resource`` explains:
   no two shipped recipes share a resource type, so every group has one contributor and
   there is nothing to inherit. It would be a test that passes because the input is
   trivial while appearing to check the merge -- worse than its absence, which at least
   sends a reader to the constructed-overlap tests that do check it.
2. *That each safety note names the resource it applies to.* ``safety_notes`` is a
   ``@property`` derived from the flags (:mod:`remgen.core.model`), so any assertion
   about its contents re-implements the derivation and passes unconditionally. Three of
   this file's original invariants did exactly that and had to be rewritten against
   authored fields; the rule that came out of it is above every test below that mentions
   a derived value. The authored counterpart -- ``caveats`` -- is already constrained by
   ``test_reversible_recipes_supply_a_reversal_and_irreversible_ones_say_why`` and
   ``test_usage_scaled_cost_comes_with_a_way_to_bound_it``.
"""

from __future__ import annotations

import importlib
import pathlib
import pkgutil
from collections import Counter

import pytest

from remgen.core.generators.hcl import group_targets
from remgen.core.model import CostImpact, Finding, SafetyTier
from remgen.providers.aws import recipes as recipes_pkg
from remgen.providers.aws.recipes import REGISTRY, all_recipes, get


def _recipes():
    return all_recipes()


def _service_modules() -> list[str]:
    return sorted(
        name for _f, name, ispkg in pkgutil.iter_modules(recipes_pkg.__path__) if not ispkg
    )


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
        # Compared against its own lowercasing rather than with `islower()`, which is
        # False for any string containing no cased characters at all -- so an id of
        # digits and dashes would fail this for having no letters rather than for being
        # uppercase, reporting a correct id as broken.
        assert recipe.policy_id == recipe.policy_id.lower(), (
            f"{recipe.policy_id} must be lowercase to match"
        )


# ---------------------------------------------------------------------------
# Layout: the per-service split has to stay true, and discovery has to see it all
# ---------------------------------------------------------------------------


def test_every_service_module_on_disk_is_actually_discovered():
    """The failure mode the discovery loop exists to prevent, asserted from outside it.

    Recipes are aggregated by importing every module in the package. If that ever
    regressed to a hand-written list -- or if a module's recipes stopped being reached
    for any other reason -- the result is silent: the file exists, imports cleanly and
    reads correctly, while ``all_recipes`` never returns its entries. The policy then
    reports as unsupported, every per-recipe test parametrizes over a set that excludes
    it, and nothing fails.

    So this walks the directory itself and requires each module's ``RECIPES`` to be
    present in the aggregate, comparing by ``policy_id`` because that is what ``get``
    resolves and therefore what "reached" has to mean.
    """
    modules = _service_modules()
    assert modules, "no service modules found; the recipe package would aggregate nothing"
    aggregated = {r.policy_id for r in _recipes()}
    for name in modules:
        module = importlib.import_module(f"{recipes_pkg.__name__}.{name}")
        missing = {r.policy_id for r in module.RECIPES} - aggregated
        assert not missing, (
            f"{name}.py declares {missing}, which `all_recipes()` does not return. Those "
            f"policies would report as unsupported while the recipe sits in the tree."
        )
    assert sum(
        len(importlib.import_module(f"{recipes_pkg.__name__}.{n}").RECIPES) for n in modules
    ) == len(aggregated), (
        "the aggregate and the per-module tuples disagree on how many recipes exist"
    )


@pytest.mark.parametrize("module_name", _service_modules())
def test_each_service_module_only_holds_recipes_for_that_service(module_name):
    """The module name is the botocore service id, and that is load-bearing.

    The split is only navigable if the filename predicts the contents: a reviewer
    seeing a diff to ``s3.py`` needs to know it cannot have changed the RDS
    remediation. Nothing enforces that mechanically except this, and the natural way
    to break it is convenience -- adding a second service's recipe to whichever file is
    already open. Asserted per module so a failure names the file rather than the set.
    """
    module = importlib.import_module(f"{recipes_pkg.__name__}.{module_name}")
    services = {r.api.service for r in module.RECIPES}
    assert services == {module_name}, (
        f"{module_name}.py holds recipes for {sorted(services)}. One module per AWS "
        f"service, named for the botocore service id -- move the others to their own file."
    )


def test_no_service_module_is_empty_or_missing_its_export():
    """An empty module is a file that looks like coverage and provides none.

    The discovery loop raises on this at import, so this test states the same rule
    where a contributor reading the tests finds it, and covers the case where the
    loop's own guard is weakened.
    """
    for name in _service_modules():
        module = importlib.import_module(f"{recipes_pkg.__name__}.{name}")
        found = getattr(module, "RECIPES", None)
        assert isinstance(found, tuple) and found, (
            f"{name}.py must export a non-empty RECIPES tuple; it is loaded as a recipe "
            f"source, so an empty one contributes nothing while appearing to"
        )


def test_the_package_holds_no_module_that_is_not_a_service():
    """Every module here is imported as a recipe source, so a helper cannot live here.

    Stated because the consequence is not obvious from the loop: dropping a utility
    module into this package makes it a discovery target, and it will raise at import
    for not exporting ``RECIPES``. That is the right failure, but it is better read
    here than debugged there.
    """
    directory = pathlib.Path(recipes_pkg.__file__).parent
    files = sorted(p.name for p in directory.glob("*.py") if p.name != "__init__.py")
    assert files == [f"{name}.py" for name in _service_modules()], (
        f"unexpected files in the recipe package: {files}. Only per-service recipe "
        f"modules belong here; helpers go one level up."
    )


# ---------------------------------------------------------------------------
# HCL targets: the collisions that real parsers do not catch
# ---------------------------------------------------------------------------


def test_the_whole_set_applied_to_one_resource_emits_one_block_per_resource():
    """Every recipe fired at a single resource must merge, not collide.

    Two ``import`` blocks carrying the same ``id`` are *valid configuration*: real
    ``tofu validate`` reports "Success!", because nothing at parse time knows the two
    ids name one resource. The conflict surfaces at ``plan``/``apply`` against live
    infrastructure. :func:`~remgen.core.generators.hcl.group_targets` prevents it by
    merging per resource, so what has to be checked at the set level is that the
    merge *succeeds* for this set: two recipes sharing a resource type and an import
    id must agree about every attribute they both set, or the merge refuses to render.

    That agreement is not something a per-recipe test can see, and it is knowable
    without any findings -- the recipes are hand-written and their overlap is fixed.
    Sharing a resource type is now allowed; disagreeing while sharing one is not.

    Be clear about what this currently proves: no two shipped recipes share a resource
    type yet, so today every group has one contributor and the merge is a no-op here.
    It is stated at the set level anyway because it is the assertion that starts doing
    work on the first recipe that overlaps an existing one -- which is exactly when the
    author will not be looking for this failure. The merge behaviour itself is exercised
    against constructed overlaps in ``tests/test_generators.py``.
    """
    shared = "shared-resource"
    pairs = [
        (
            recipe,
            Finding(
                policy_id=recipe.policy_id,
                resource_id=shared,
                region="us-east-1",
                account_id="111111111111",
            ),
        )
        for recipe in _recipes()
        if recipe.hcl is not None
    ]
    assert pairs, "no recipe carries an HCL target; the assertion below is vacuous"

    # Raises HclMergeConflict if two recipes on one resource disagree, and
    # AmbiguousImportError if two would claim one import id.
    targets = group_targets(pairs)

    ids = [(t.resource_type, t.import_id) for t in targets]
    assert len(ids) == len(set(ids)), f"an import id is claimed by two blocks: {ids}"
    assert sum(len(t.recipes) for t in targets) == len(pairs), (
        "a recipe was dropped by the merge; every pair must land in exactly one block"
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


def test_each_docs_url_points_at_the_operation_the_recipe_actually_calls():
    """The docs link must name the same operation the recipe runs.

    ``docs_url`` is authored, and the way it goes wrong is not a malformed URL -- it is
    a *working* link to the wrong page, because the fastest way to write a recipe is to
    copy the nearest one and edit it. Every existing entry ends in
    ``API_<Operation>.html``, so the operation name is recoverable from the link and can
    be compared against ``api.operation`` rather than merely eyeballed.

    Why this is worth a set-level assertion: the run README renders this link as
    "[Documentation]" (:mod:`remgen.core.artifacts`), so a reader following it to check
    what the remediation does lands on a page describing a *different* API call -- and
    reads a parameter list, a set of permissions and a set of consequences belonging to
    something the tool is not about to run. Nothing else in the suite compares the two:
    ``test_no_recipe_ships_an_empty_prose_field`` only checks the string is non-empty,
    and ``verify`` checks the operation against botocore without ever reading the link.

    Not asserted here: that the URL resolves. That would need a network call, and this
    suite makes none -- the whole tool's safety argument is that it does not.
    """
    for recipe in _recipes():
        assert recipe.docs_url.startswith("https://docs.aws.amazon.com/"), (
            f"{recipe.policy_id}: docs_url is not an AWS documentation URL "
            f"({recipe.docs_url!r}); it is rendered as the authoritative reference"
        )
        page = recipe.docs_url.rsplit("/", 1)[-1]
        assert page == f"API_{recipe.api.operation}.html", (
            f"{recipe.policy_id}: docs_url ends in {page!r}, but the recipe calls "
            f"{recipe.api.operation} and must link that operation's own page "
            f"(API_{recipe.api.operation}.html). A link to any other page sends a "
            f"reader to another call's parameters and consequences."
        )


def test_titles_are_unique_so_the_readme_index_is_unambiguous():
    # `all_recipes` sorts by title for deterministic output, and the run README indexes
    # by it. Two identical titles make two different remediations indistinguishable in
    # the one document that explains them.
    titles = [r.policy_title for r in _recipes()]
    dupes = [t for t, n in Counter(titles).items() if n > 1]
    assert not dupes, f"duplicate policy titles: {dupes}"
