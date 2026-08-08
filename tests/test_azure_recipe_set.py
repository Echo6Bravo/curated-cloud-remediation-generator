"""Invariants of the *Azure* recipe set, as opposed to of any single recipe.

The Azure counterpart of ``tests/test_recipe_set.py``, and deliberately a separate
file rather than a parametrization of it. Three of the rules below are Azure's alone
and would be wrong if applied to AWS -- ``--ids`` is required, ``--subscription`` is
required, and the docs host is ``learn.microsoft.com`` -- while two AWS rules are
wrong here: ``--region`` has no Azure equivalent on a command addressed by resource
id, and ``docs_url`` does not end in ``API_<Operation>.html``. A shared file would
have to branch on cloud in every test, which is how one cloud's assumption ends up
asserted about the other.

**The rules that are Azure-specific are each a measured constraint, not a style
choice**, and the recipes package docstring records where each came from:

* ``Recipe`` requires ``cli_template`` to name ``{resource_id}``, and an ARM
  resource id can only be handed to a command that accepts ``--ids``. A template
  that names the id any other way does not run.
* ``--subscription`` must be present because
  :class:`~remgen.providers.azure.shell.SubscriptionNotPinnedError` refuses to render
  a script without it. That guard is what keeps a generated script from inheriting
  whichever subscription the operator's login happened to have selected.
* The SDK package name is *not* always the ``az`` command group, so the module-name
  rule has to name its exceptions rather than assume the two agree.

Two invariants are deliberately **not** here, both because the AWS file already
explains why the same assertion proves nothing:

1. *That a merged block inherits the riskiest tier of its contributors.* Covered
   against constructed overlaps in ``tests/test_generators.py``. Unlike AWS, the Azure
   set genuinely does overlap -- three storage recipes share
   ``azurerm_storage_account`` -- so
   :func:`test_the_whole_set_applied_to_one_resource_emits_one_block_per_resource`
   below is doing real work here rather than waiting for a future recipe. What it
   cannot check is inheritance, because all three are ``safest``.
2. *Anything derived from the risk flags*, including ``safety_tier`` on its own and
   ``safety_notes``. Asserting a derived value re-implements its derivation and passes
   unconditionally; every test below that mentions one states which authored field it
   is really checking.
"""

from __future__ import annotations

import importlib
import pathlib
import pkgutil
import re
import sys
from collections import Counter

import pytest

from remgen.core.generators.hcl import group_targets
from remgen.core.model import CostImpact, Effort, Finding, SafetyTier
from remgen.providers.azure import recipes as recipes_pkg
from remgen.providers.azure.recipes import REGISTRY, all_recipes, get
from tests.conftest import WITHDRAWS_ACCESS

#: A subscription-shaped scope and an ARM-shaped resource id, used wherever a finding
#: is needed. AWS-shaped values would satisfy every assertion below while testing
#: nothing about Azure.
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"


def _recipes():
    return all_recipes()


def _service_modules() -> list[str]:
    return sorted(
        name for _f, name, ispkg in pkgutil.iter_modules(recipes_pkg.__path__) if not ispkg
    )


def _command_words(command: str) -> list[str]:
    """Return the ``az`` command name in ``command`` as its words.

    The leading run of words before the first flag or ``{placeholder}``. Azure command
    names vary in depth -- ``storage account update`` is three words, ``sql db tde set``
    is four -- so a fixed-arity split like the AWS tests' ``tokens[1]`` would read the
    latter as ``sql db``.

    Written here rather than imported from
    :func:`remgen.providers.azure.cli_surface._extract`, which does the same job for the
    verifier. Reusing it would make a bug in that parser invisible to these tests: they
    would agree with it about a mis-read command and both be wrong together.
    """
    tokens = command.split()
    words: list[str] = []
    for token in tokens[1:]:
        if token.startswith("-") or token.startswith("{"):
            break
        words.append(token)
    return words


# ---------------------------------------------------------------------------
# Identity: one entry per policy, reachable by its id
# ---------------------------------------------------------------------------


def test_the_set_is_not_empty():
    # The failure mode of every test below: a set-level assertion over zero items
    # passes while checking nothing. Asserted first so the rest cannot be vacuous --
    # and it is a live risk here rather than a formality, because this set was empty
    # by design until step 5 and `azremgen` is built to run with no recipes at all.
    assert _recipes(), "the Azure recipe set is empty; every invariant below is vacuous"


def test_policy_ids_are_unique():
    """A duplicate id silently shadows a recipe.

    ``REGISTRY`` is a dict comprehension, so a repeated ``policy_id`` does not raise
    on its own: the later entry wins, the earlier becomes unreachable through ``get``,
    and both are still counted. The package raises on it at import; this states the
    same rule where a contributor reading the tests will find it.

    More likely to happen in this set than in the AWS one, which is why the package's
    own check carries a comment saying so: two of the four Azure policies describe
    near-identical storage settings ("in transit is not enabled" and "insecure
    communication"), so a copy-pasted id between them reads as correct.
    """
    ids = [r.policy_id for r in _recipes()]
    dupes = [pid for pid, n in Counter(ids).items() if n > 1]
    assert not dupes, f"duplicate policy_id(s): {dupes}"
    assert len(REGISTRY) == len(ids)


def test_every_recipe_is_reachable_through_get():
    # `get` is what pairs a finding with a recipe. An entry in the set but not
    # resolvable by id is reported as an unsupported policy -- a coverage gap that
    # looks like a deliberate omission rather than a bug.
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
        # False for a string with no cased characters at all -- so an id made only of
        # digits and dashes would fail for having no letters rather than for being
        # uppercase, reporting a correct id as broken.
        assert recipe.policy_id == recipe.policy_id.lower(), (
            f"{recipe.policy_id} must be lowercase to match"
        )


# ---------------------------------------------------------------------------
# Layout: the per-service split has to stay true, and discovery has to see it all
# ---------------------------------------------------------------------------


def test_every_service_module_on_disk_is_actually_discovered():
    """The failure the discovery loop exists to prevent, asserted from outside it.

    Recipes are aggregated by importing every module in the package. If that regressed
    to a hand-written list -- or if a module's recipes stopped being reached for any
    other reason -- the result is silent: the file exists, imports cleanly and reads
    correctly, while ``all_recipes`` never returns its entries. The policy then reports
    as unsupported, every per-recipe test parametrizes over a set that excludes it, and
    nothing fails.

    So this walks the directory itself and requires each module's ``RECIPES`` to be in
    the aggregate, comparing by ``policy_id`` because that is what ``get`` resolves and
    therefore what "reached" has to mean.
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


#: ``az`` command groups whose SDK package name differs, keyed by SDK package.
#:
#: The module name is the ``azure.mgmt`` package name, because that is what
#: :mod:`remgen.providers.azure.drift` resolves -- and it is not always the ``az``
#: command group. ``az postgres`` and ``az mysql`` are both ``azure.mgmt.rdbms``, so a
#: recipe for either belongs in ``rdbms.py`` while its ``cli_template`` says something
#: else. Listed explicitly rather than inferred so that a real mismatch still fails and
#: each divergence has to be stated once, with the SDK package that owns it.
CLI_GROUP_ALIASES: dict[str, tuple[str, ...]] = {
    "rdbms": ("postgres", "mysql", "mariadb"),
}


@pytest.mark.parametrize("module_name", _service_modules())
def test_each_service_module_only_holds_recipes_for_that_service(module_name):
    """The module name is the ``azure.mgmt`` package name, and that is load-bearing.

    Two things depend on it. The split is only navigable if the filename predicts the
    contents -- a reviewer seeing a diff to ``storage.py`` needs to know it cannot have
    changed the SQL remediation -- and ``ApiCall.service`` is resolved as a directory
    name under the bundled SDK tree, so a recipe filed under the wrong module is
    verified against the wrong service's models or, more likely, reports
    ``SERVICE_MISSING`` for a service that exists.

    Asserted per module so a failure names the file rather than the set. Both module
    docstrings promise this test by name, so deleting it would leave two lies in the
    source tree.
    """
    module = importlib.import_module(f"{recipes_pkg.__name__}.{module_name}")
    services = {r.api.service for r in module.RECIPES}
    assert services == {module_name}, (
        f"{module_name}.py holds recipes for {sorted(services)}. One module per Azure "
        f"service, named for the azure.mgmt SDK package -- move the others to their own "
        f"file."
    )


def test_no_service_module_is_empty_or_missing_its_export():
    """An empty module is a file that looks like coverage and provides none.

    The discovery loop raises on this at import, so this states the same rule where a
    contributor reading the tests finds it, and covers the case where the loop's own
    guard is weakened. That the guard currently fires is checked directly, against a
    synthetic package, in :func:`test_a_module_without_recipes_fails_discovery_loudly`.
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
    module into this package makes it a discovery target, and it raises at import for
    not exporting ``RECIPES``. That is the right failure, but it is better read here
    than debugged there.
    """
    directory = pathlib.Path(recipes_pkg.__file__).parent
    files = sorted(p.name for p in directory.glob("*.py") if p.name != "__init__.py")
    assert files == [f"{name}.py" for name in _service_modules()], (
        f"unexpected files in the recipe package: {files}. Only per-service recipe "
        f"modules belong here; helpers go one level up."
    )


# ---------------------------------------------------------------------------
# Discovery's own failure modes, run against a synthetic package
# ---------------------------------------------------------------------------
#
# The four tests below execute the *real* `__init__.py` source over a package built in
# `tmp_path`, rather than asserting the rules a second time. The distinction matters:
# every check above says "the shipped modules satisfy the rule", which stays green if
# the guard that enforces it is deleted. These say "the guard fires", which is the part
# a future contributor is relying on when they add a module.
#
# Copying the source and importing it under another name is the only way to reach those
# branches: the guards run at import of the real package, which pytest has already
# imported by the time any test body runs, and re-importing it cannot fail because its
# modules are correct. Re-implementing the loop in the test would prove nothing at all.


def _synthetic_package(tmp_path: pathlib.Path, name: str, modules: dict[str, str]):
    """Build a package running the real discovery source over ``modules``, and import it.

    ``modules`` maps module name to file contents. The package's ``__init__.py`` is a
    byte-for-byte copy of the shipped one, so what runs is the code under test rather
    than a paraphrase of it.
    """
    package = tmp_path / name
    package.mkdir()
    real_init = pathlib.Path(recipes_pkg.__file__).read_text(encoding="utf-8")
    (package / "__init__.py").write_text(real_init, encoding="utf-8")
    for module_name, source in modules.items():
        (package / f"{module_name}.py").write_text(source, encoding="utf-8")
    sys.path.insert(0, str(tmp_path))
    try:
        return importlib.import_module(name)
    finally:
        sys.path.remove(str(tmp_path))
        for key in [k for k in sys.modules if k == name or k.startswith(f"{name}.")]:
            del sys.modules[key]


#: A minimal valid recipe module, as source. Written as text because it has to be
#: importable by the discovery loop from a file, which is the whole point of these tests.
_VALID_MODULE = """
from remgen.core.model import ApiCall, HclTarget, Recipe

RECIPES = (
    Recipe(
        policy_id="{policy_id}",
        policy_title="{title}",
        summary="A synthetic recipe used to exercise the discovery loop.",
        api=ApiCall(service="storage", operation="X.update", parameters=("p",)),
        cli_template="az storage account update --ids {{resource_id}}",
        hcl=None,
        reverse_hint="undo it",
        docs_url="https://learn.microsoft.com/en-us/rest/api/storagerp/x/update",
    ),
)
"""


def test_a_package_with_no_modules_fails_discovery_loudly(tmp_path):
    """Zero modules must raise, not aggregate to zero recipes.

    This is the branch that separates "Azure has no coverage yet", which was a real
    and supported state, from "the recipes stopped being found". Both produce an empty
    set and the tool reports the first honestly -- ``verify`` prints "nothing to check"
    and ``generate`` counts every finding as unsupported -- which is exactly why the
    second has to fail at import instead of borrowing that honest report.
    """
    with pytest.raises(ImportError, match="no recipe modules found"):
        _synthetic_package(tmp_path, "remgen_synthetic_empty", {})


def test_a_module_without_recipes_fails_discovery_loudly(tmp_path):
    # A helper dropped into the package, or a recipe module mid-edit. Either way it is
    # loaded as a recipe source, so it has to say so or say nothing at all.
    with pytest.raises(ImportError, match="non-empty RECIPES"):
        _synthetic_package(
            tmp_path,
            "remgen_synthetic_helper",
            {"helpers": "def shared_thing():\n    return 1\n"},
        )


def test_a_module_whose_recipes_are_not_recipes_fails_discovery_loudly(tmp_path):
    """A ``RECIPES`` tuple of the wrong type must not reach the pipeline.

    The realistic form is a tuple of dicts or of ``HclTarget`` objects, which would
    otherwise fail much later with an ``AttributeError`` inside a generator, naming a
    line in ``core`` for a mistake made in a provider.
    """
    with pytest.raises(ImportError, match="non-Recipe entry"):
        _synthetic_package(
            tmp_path,
            "remgen_synthetic_wrongtype",
            {"storage": 'RECIPES = ({"policy_id": "not-a-recipe"},)\n'},
        )


def test_two_modules_sharing_a_policy_id_fail_at_import(tmp_path):
    """The duplicate-id guard fires, rather than the dict silently keeping one.

    The failure this prevents is the quietest one in the package: the registry
    comprehension keeps the later entry, the earlier is unreachable through ``get``, and
    both are still counted -- so the README's recipe count, ``azremgen recipes`` and the
    per-recipe tests all agree on a number that is one larger than the coverage.

    Two modules rather than one, because that is the shape it takes in practice: the
    same id copied into a neighbouring service file, where no reviewer sees both lines
    at once.
    """
    with pytest.raises(RuntimeError, match="Duplicate policy_id"):
        _synthetic_package(
            tmp_path,
            "remgen_synthetic_dupe",
            {
                "storage": _VALID_MODULE.format(
                    policy_id="bed905d4-758c-4698-9ed8-4cdd4271eb4e", title="First"
                ),
                "sql": _VALID_MODULE.format(
                    policy_id="bed905d4-758c-4698-9ed8-4cdd4271eb4e", title="Second"
                ),
            },
        )


def test_the_synthetic_package_helper_can_actually_import_a_good_package(tmp_path):
    """The control for the four tests above, and not a formality.

    Each of them asserts that importing a broken package raises. If
    :func:`_synthetic_package` were broken -- a bad path, a missing ``sys.path`` entry,
    a stale ``sys.modules`` key -- every one of them would still pass, on an
    ``ImportError`` raised for the wrong reason and matched by a substring that happens
    to appear in it. So one test imports a *valid* package and requires the recipes to
    come back out.
    """
    module = _synthetic_package(
        tmp_path,
        "remgen_synthetic_ok",
        {
            "storage": _VALID_MODULE.format(
                policy_id="bed905d4-758c-4698-9ed8-4cdd4271eb4e", title="First"
            ),
            "sql": _VALID_MODULE.format(
                policy_id="f3c5d6e7-d8f0-48fd-97ab-16585ff981f3", title="Second"
            ),
        },
    )
    assert [r.policy_title for r in module.all_recipes()] == ["First", "Second"]
    assert module.get("bed905d4-758c-4698-9ed8-4cdd4271eb4e") is not None
    assert module.get("no-such-id") is None


# ---------------------------------------------------------------------------
# HCL targets: the collisions real parsers do not catch
# ---------------------------------------------------------------------------


def test_the_whole_set_applied_to_one_resource_emits_one_block_per_resource():
    """Every recipe fired at a single resource must merge, not collide.

    Two ``import`` blocks carrying the same ``id`` are *valid configuration*: real
    ``tofu validate`` reports "Success!", because nothing at parse time knows the two
    ids name one resource. The conflict surfaces at ``plan``/``apply`` against live
    infrastructure. :func:`~remgen.core.generators.hcl.group_targets` prevents it by
    merging per resource, so what has to hold at the set level is that the merge
    *succeeds*: recipes sharing a resource type and an import id must agree about every
    attribute they both set, or the merge refuses to render.

    **Unlike the AWS version of this test, this one is not waiting for a future
    recipe.** Three of the four shipped recipes target ``azurerm_storage_account`` with
    the same import id, so ``group_targets`` really does merge here -- which is only
    silent because all three declare the same five ``unresolvable_required_attributes``
    from one shared constant. Copying those five into a fourth storage recipe and
    changing one placeholder is a plausible edit, and it fails here rather than in a
    generated file nobody re-validated.
    """
    shared = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod"
        f"/providers/Microsoft.Storage/storageAccounts/prodlogs01"
    )
    pairs = [
        (
            recipe,
            Finding(
                policy_id=recipe.policy_id,
                resource_id=shared,
                region="eastus",
                account_id=SUBSCRIPTION,
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
    # The merge is doing real work rather than passing trivially: at least one block
    # carries more than one recipe. Without this, the test would keep passing if
    # `group_targets` stopped merging and started emitting one block per recipe --
    # which is the defect it exists to catch.
    assert max(len(t.recipes) for t in targets) > 1, (
        "no block merged more than one recipe, so this test is not exercising the merge"
    )


def test_hcl_import_templates_reference_only_finding_fields():
    """An import id built from an undefined field renders a literal placeholder.

    ``render_template`` raises on an unknown field, so this would surface as a run that
    fails -- but only for a finding that reaches that recipe. A recipe covering a policy
    absent from the test fixtures could ship broken.
    """
    allowed = {"resource_id", "region", "account_id", "policy_id"}
    for recipe in _recipes():
        if recipe.hcl is None:
            continue
        fields = set(re.findall(r"\{(\w+)\}", recipe.hcl.import_id_template))
        unknown = fields - allowed
        assert not unknown, f"{recipe.policy_id}: import template references {unknown}"


def test_every_hcl_import_id_is_a_full_arm_id():
    """The ``azurerm`` importers parse ids with typed parsers, not as opaque strings.

    Azure-specific and not a restatement of the test above. The provider's import ids
    come from its own ``commonids`` types, each a fixed ``/subscriptions/.../providers/...``
    path, and the importer *parses* it -- so an id assembled from a bare resource name,
    or from a region and a name, fails with "invalid URI for request" rather than with
    a not-found. A finding's ``resource_id`` for an Azure resource is already the full
    ARM path, so the correct template is the id unchanged; anything else is a sign the
    author was thinking in AWS's terms, where an import id genuinely is a bucket name.

    This is the same class of mistake as the ``server_id`` placeholder in ``sql.py``,
    which failed a real ``tofu validate`` for exactly this reason and is why that stub
    is a whole ARM path.
    """
    for recipe in _recipes():
        if recipe.hcl is None:
            continue
        assert recipe.hcl.import_id_template == "{resource_id}", (
            f"{recipe.policy_id}: import id is {recipe.hcl.import_id_template!r}. An "
            f"azurerm import id is a full ARM resource id, which is what a finding "
            f"already carries -- assembling one from parts produces a parse error at "
            f"plan time, not a not-found. If a resource type genuinely needs another "
            f"shape, name its commonids type here and say so."
        )


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


def test_every_placeholder_says_what_to_replace_it_with():
    """A type-valid placeholder is indistinguishable from a real value.

    This matters more for Azure than for AWS and the reason was measured: ``"TODO"``
    does not validate for three of ``azurerm_storage_account``'s five required
    arguments (a name pattern and two enums), so the placeholders are real-looking
    values -- ``"Standard"``, ``"LRS"``, a lowercase name. A reader skimming the
    generated block sees plausible configuration, and ``name`` and ``account_tier``
    are ForceNew, so applying it destroys the account rather than mis-tagging it.

    The comment is therefore the only thing distinguishing a stub from an answer, which
    makes an empty one a correctness problem rather than a documentation one. Requiring
    the word "TODO" in it as well: the generator's own INCOMPLETE banner lists the
    argument names, and this is what makes the inline annotation searchable in a diff.
    """
    for recipe in _recipes():
        if recipe.hcl is None:
            continue
        for name, value, comment in recipe.hcl.unresolvable_required_attributes:
            assert comment.strip(), (
                f"{recipe.policy_id}: the {name} placeholder ({value}) has no comment. It "
                f"is a type-valid value, so nothing else tells a reader it is a stub."
            )
            assert "TODO" in comment, (
                f"{recipe.policy_id}: the {name} placeholder's comment does not say TODO, "
                f"so it cannot be found by grepping a generated file"
            )


# ---------------------------------------------------------------------------
# CLI and API: the two halves must describe the same call
# ---------------------------------------------------------------------------


def test_the_cli_template_invokes_the_service_the_api_call_names():
    """A recipe whose CLI and API disagree is verified against the wrong model.

    ``verify`` checks the ``ApiCall`` against the bundled SDK, but the artifact runs the
    ``cli_template``. If they name different services, a green ``verify`` says nothing
    about what the script will actually run -- the strongest form of a test that passes
    while the shipped thing is wrong.

    Azure's twist is that "the same service" is not string equality: the SDK package and
    the ``az`` command group diverge for a handful of services, so the exceptions are
    listed in :data:`CLI_GROUP_ALIASES` and everything else must match exactly.
    """
    for recipe in _recipes():
        tokens = recipe.cli_template.split()
        assert tokens[0] == "az", f"{recipe.policy_id}: CLI template must invoke `az`"
        expected = CLI_GROUP_ALIASES.get(recipe.api.service, (recipe.api.service,))
        assert tokens[1] in expected, (
            f"{recipe.policy_id}: CLI calls `az {tokens[1]}` but ApiCall names "
            f"{recipe.api.service!r} (expected one of {expected}); verify would check "
            f"the wrong SDK package. If this divergence is legitimate, add it to "
            f"CLI_GROUP_ALIASES with the SDK package that owns it."
        )


def test_every_cli_template_addresses_its_resource_with_ids():
    """``--ids`` is not a style choice; it is what makes an Azure recipe possible.

    ``Recipe`` requires ``cli_template`` to contain ``{resource_id}``, and a finding's
    Azure ``resource_id`` is a full ARM path. The only ``az`` argument that accepts one
    is ``--ids``; passing it to a name-shaped argument such as ``--name`` fails, and
    ``az`` will happily accept the template as *written* while failing at run time on
    the operator's machine.

    That constraint is what removed a planned recipe rather than merely shaping one:
    ``az keyvault update`` does not accept ``--ids``, so the Key Vault RBAC remediation
    could not be templated at all and is absent. Asserted so the next author discovers
    that before writing the recipe rather than after -- and immediately after
    ``--ids``, because the id must be its *argument* rather than merely present
    somewhere in the line.
    """
    for recipe in _recipes():
        assert "--ids {resource_id}" in recipe.cli_template, (
            f"{recipe.policy_id}: the template must pass the finding's ARM id as "
            f"`--ids {{resource_id}}`. Check `az <command> --help` accepts --ids before "
            f"writing a recipe; not every command does, and one that does not cannot be "
            f"templated."
        )


def test_every_cli_template_pins_its_subscription():
    """A command with no ``--subscription`` runs against whichever one is selected.

    Azure's analogue of the AWS ``--region`` rule, and a harder requirement: an ``az``
    login spans subscriptions, so an unpinned command targets ``az account show``'s
    current default -- which the operator may have changed hours ago in another
    terminal. The script generator refuses to render an unpinned template at all
    (:class:`~remgen.providers.azure.shell.SubscriptionNotPinnedError`), so this test
    is what names the recipe rather than letting the failure surface as an exception
    from the renderer.

    Kept even though ``az`` *ignores* the flag when ``--ids`` is present -- it warns
    "option '--subscription' will be ignored due to use of '--ids'". The guarantee is
    unchanged, because the ARM id in ``--ids`` names the subscription itself, and the
    flag is what keeps that guarantee true for a future recipe that cannot use
    ``--ids``. Removing it because the warning looks untidy would silently drop the
    pinning contract for exactly that recipe.
    """
    for recipe in _recipes():
        assert "--subscription {account_id}" in recipe.cli_template, (
            f"{recipe.policy_id}: the template must pin `--subscription {{account_id}}`; "
            f"without it the command targets whichever subscription is currently "
            f"selected, and the script generator refuses to render it"
        )


def test_no_cli_template_names_a_location():
    """Azure commands addressed by resource id must not also carry a location.

    The inverse of the AWS ``--region`` rule, and it is a real hazard rather than a
    tidiness one: the ARM id already determines the resource group and location, so a
    ``--location`` on an update either duplicates what the id says or contradicts it.
    ``azurerm``'s own location argument is ForceNew, and ``az`` treats a location
    mismatch on some resource types as a move, so a stale value from a copied template
    is a destructive edit rather than a rejected one.
    """
    for recipe in _recipes():
        assert "--location" not in recipe.cli_template, (
            f"{recipe.policy_id}: the template names --location, which the ARM id in "
            f"--ids already determines. Remove it."
        )


def test_reversible_recipes_supply_a_reversal_and_irreversible_ones_say_why():
    """``reversible`` is a claim a reader acts on at 2am, so it must be backed.

    A recipe marked reversible with no reversal command tells the reader the change can
    be undone without telling them how. An irreversible one must say so in its
    *authored* ``caveats``, not merely in the derived ``safety_notes``: those are
    generated from ``reversible`` itself, so asserting them here would only re-derive
    the field and pass unconditionally.
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


def test_the_reversal_undoes_the_same_call_the_remediation_makes():
    """A reversal naming a different command does not undo the change.

    ``reverse_hint`` is free prose printed to an operator as the way out, and the
    CLI-surface axis only checks that its *flags* exist -- not that it is the same
    command. A hint that drifted to another subcommand after a copy-paste between
    recipes reads as authoritative and silently does something else, or nothing.

    Compared by whole command name rather than by a fixed number of tokens, because
    Azure command depth varies: ``sql db tde set`` is four words and ``storage account
    update`` is three, so the AWS test's ``[1:3]`` slice would compare ``sql db``
    against ``sql db`` and miss a reversal pointing at ``sql db audit-policy``.
    """
    for recipe in _recipes():
        if not recipe.reverse_hint:
            continue
        assert recipe.reverse_hint.split()[:1] == ["az"], (
            f"{recipe.policy_id}: reverse_hint must invoke `az`"
        )
        forward = _command_words(recipe.cli_template)
        reverse = _command_words(recipe.reverse_hint)
        assert forward, f"{recipe.policy_id}: no command name in the template"
        assert reverse == forward, (
            f"{recipe.policy_id}: remediation runs `az {' '.join(forward)}` but the "
            f"reversal runs `az {' '.join(reverse)}`; it does not undo the same call"
        )


def test_no_reversal_is_a_copy_of_the_remediation():
    """A reversal identical to the remediation re-applies it.

    Azure-specific because of how these templates are written: the forward and reverse
    commands differ by one flag *value* (``--https-only true`` / ``false``,
    ``--status Enabled`` / ``Disabled``), not by a different subcommand as several AWS
    reversals do. So the copy-paste that produces a wrong reversal here leaves something
    that runs cleanly, reports success, and changes nothing -- which is worse than a
    reversal that errors, and which the test above cannot see because the command names
    match by construction.

    Compared with the resource-id placeholder stripped, since a reverse hint is written
    for a human and says ``<resource-id>`` where the template says ``{resource_id}``.
    """
    for recipe in _recipes():
        if not recipe.reverse_hint:
            continue
        forward = recipe.cli_template.replace("{resource_id}", "ID")
        reverse = recipe.reverse_hint.replace("<resource-id>", "ID")
        forward_flags = {t for t in forward.split() if t.startswith("--")}
        # Only the flags both commands carry can be compared; the reverse hint omits
        # --subscription because a human runs it with their own context.
        shared = forward_flags & {t for t in reverse.split() if t.startswith("--")}
        assert shared, (
            f"{recipe.policy_id}: the reversal shares no flag with the remediation, so "
            f"it is not addressing the same setting"
        )
        differs = any(_flag_value(forward, flag) != _flag_value(reverse, flag) for flag in shared)
        assert differs, (
            f"{recipe.policy_id}: the reversal passes the same value as the remediation "
            f"for every flag they share, so running it re-applies the change instead of "
            f"undoing it"
        )


def _flag_value(command: str, flag: str) -> str | None:
    """Return the token following ``flag`` in ``command``, or ``None``."""
    tokens = command.split()
    for index, token in enumerate(tokens):
        if token == flag:
            following = tokens[index + 1 : index + 2]
            return following[0] if following else None
    return None


# ---------------------------------------------------------------------------
# Safety classification: the promise the default safety level makes
# ---------------------------------------------------------------------------


def test_safest_recipes_carry_no_ongoing_cost():
    """``safest`` is the default, so it is the tier that gets run unexamined.

    Scope is deliberately narrow. ``safety_tier`` is *derived* from ``reversible``,
    ``data_path_impact``, ``effort`` and ``blocks_iac_destroy``, so asserting those four
    of a ``safest`` recipe re-implements the derivation and cannot fail. The one thing
    the formula does **not** gate is ``CostImpact.LOW``: a recipe with a small recurring
    charge still derives to ``safest`` and is emitted by a default run.
    """
    for recipe in _recipes():
        if recipe.safety_tier is not SafetyTier.SAFEST:
            continue
        assert recipe.cost_impact is CostImpact.NONE, (
            f"{recipe.policy_id}: is `safest` -- what a default run emits without review "
            f"-- but carries {recipe.cost_impact.value} ongoing cost. The tier formula "
            f"does not catch this; only this test does."
        )


def test_a_recipe_that_withdraws_existing_access_says_so_inline():
    """The Azure half of the rule, sharing the AWS detector rather than restating it.

    Five of this set's eight recipes shut something off that works today: SFTP,
    local-user authentication, plain-HTTP clients, TLS 1.0/1.1 clients, and a
    cross-tenant replication policy. All five are honestly ``safest`` -- reversible,
    free, in-place -- so their banner says SAFEST, and ``safety_tier`` derives from four
    booleans none of which mean "withdraws existing access". Without a promoted caveat
    the warning that a data-transfer job stops working sits in the run README while the
    operator reads the command.

    ``WITHDRAWS_ACCESS`` comes from ``conftest`` deliberately: this rule is only worth
    having if both clouds are held to the same reading of it, and a per-file copy would
    diverge on the first cloud-specific reword. Its first draft, written from the S3
    recipe's phrasing, matched none of these five -- which is why the shared pattern
    describes the consequence rather than any recipe's words.
    """
    for recipe in _recipes():
        if recipe.safety_tier is not SafetyTier.SAFEST:
            continue
        if not WITHDRAWS_ACCESS.search(" ".join(recipe.caveats)):
            continue
        assert recipe.critical_caveats, (
            f"{recipe.policy_id}: is `safest` and a caveat says something working today "
            f"stops, but nothing is promoted to `critical_caveats`. The artifact would "
            f"show a SAFEST banner over the command with that warning in another file"
        )


def test_the_withdrawal_detector_actually_matches_this_set():
    """Anti-vacuity for the test above, and the reason it exists is a real near-miss.

    The rule is a text search, so it fails open: reword every caveat and it reports
    nothing wrong. That is exactly what the first draft of the pattern did against this
    set -- zero hits, silently implying Azure had no access-withdrawing recipes while
    five of them are. Asserting a floor here means a future narrowing of the pattern
    breaks this test instead of quietly disarming the one above.

    The floor is 5 rather than 1 because 1 would survive the same regression: the S3
    wording that the first draft did match is in the *AWS* set, so an AWS-shaped
    pattern scores 1 here on coincidence and 5 only if it genuinely reads consequences.
    """
    matched = [r for r in _recipes() if WITHDRAWS_ACCESS.search(" ".join(r.critical_caveats))]
    assert len(matched) >= 5, (
        f"the shared withdrawal pattern matches only {len(matched)} Azure recipe(s); it "
        f"matched 5 when written, so it has been narrowed and the rule above is now "
        f"weaker than it reads. Matched: {[r.policy_title for r in matched]}"
    )


def test_at_least_one_recipe_is_safest():
    """The default safety level must produce something.

    If every recipe were `caution`, a default `generate` would emit no remediations and
    report a clean run -- indistinguishable from having no findings.
    """
    tiers = {r.safety_tier for r in _recipes()}
    assert SafetyTier.SAFEST in tiers, (
        "no Azure recipe is `safest`, so a default run emits nothing and looks like success"
    )


@pytest.mark.parametrize("recipe", all_recipes(), ids=lambda r: r.policy_id)
def test_azure_recipes_are_not_disruptive_in_v1(recipe):
    """v1 promises no availability-affecting remediation, for both clouds.

    The Azure counterpart of ``test_curated_recipes_are_not_disruptive_in_v1`` in
    ``tests/test_generators.py``, which parametrizes over the AWS set and so cannot see
    this one. Stated as a separate test rather than by making that one multi-cloud,
    because the AWS file's other curated-set assertions are AWS-shaped -- its
    ``docs_url`` check requires an ``docs.aws.amazon.com`` host -- and a cloud-branching
    parametrization is how a rule ends up asserted about the wrong cloud.

    The guard is live rather than theoretical here: the Shared Key remediation
    (``392599b3``) passes all three verification axes and is excluded *only* because it
    is ``data_path_impact=True``. Adding it without also changing the v1 promise fails
    this test, which is the intent.
    """
    assert recipe.safety_tier is not SafetyTier.DISRUPTIVE
    assert recipe.effort is Effort.LOW
    assert not recipe.data_path_impact


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


#: Recipes whose ``docs_url`` cannot name its operation, and why.
#:
#: Empty, and kept as the escape hatch for the test below rather than as dead code: the
#: Azure REST reference is organized by operation group, but not uniformly -- a few
#: operations are documented on a page named for the resource rather than the verb. When
#: the first one lands, listing it here with the reason is the deliberate act; loosening
#: the assertion for everyone is not.
DOCS_PATH_EXCEPTIONS: dict[str, str] = {}


def test_each_docs_url_points_at_the_operation_the_recipe_actually_calls():
    """The docs link must name the same operation the recipe runs.

    ``docs_url`` is authored, and the way it goes wrong is not a malformed URL -- it is
    a *working* link to the wrong page, because the fastest way to write a recipe is to
    copy the nearest one and edit it. The run README renders it as "[Documentation]", so
    a reader following it to check what the remediation does lands on a page describing
    a different API call, and reads a parameter list and a set of consequences belonging
    to something the tool is not about to run.

    Checkable for Azure because the REST reference URL is a mechanical transform of the
    SDK operation: ``StorageAccountsOperations.update`` is documented at
    ``.../storage-accounts/update`` and
    ``TransparentDataEncryptionsOperations.begin_create_or_update`` at
    ``.../transparent-data-encryptions/create-or-update``. So both halves of
    ``ApiCall.operation`` are recovered from the link and compared, rather than only the
    host being checked. ``begin_`` is stripped first: it marks a long-running operation
    in the SDK and has no counterpart in the REST reference, which is a naming
    difference rather than a different call.

    Not asserted: that the URL resolves. That needs a network call, and this suite makes
    none -- the whole tool's safety argument is that it does not. Each of these was
    fetched once by hand when the recipe was written.
    """
    for recipe in _recipes():
        assert recipe.docs_url.startswith("https://learn.microsoft.com/"), (
            f"{recipe.policy_id}: docs_url is not a Microsoft Learn URL "
            f"({recipe.docs_url!r}); it is rendered as the authoritative reference"
        )
        if recipe.policy_id in DOCS_PATH_EXCEPTIONS:
            continue
        class_name, _, method = recipe.api.operation.partition(".")
        group = _kebab(class_name.removesuffix("Operations"))
        verb = method.removeprefix("begin_").replace("_", "-")
        assert recipe.docs_url.rstrip("/").endswith(f"/{group}/{verb}"), (
            f"{recipe.policy_id}: docs_url is {recipe.docs_url!r}, but the recipe calls "
            f"{recipe.api.operation} and must link that operation's own page, which ends "
            f"in /{group}/{verb}. A link to any other page sends a reader to another "
            f"call's parameters and consequences. If this operation is genuinely "
            f"documented elsewhere, add the policy id to DOCS_PATH_EXCEPTIONS with why."
        )


def _kebab(name: str) -> str:
    """``StorageAccounts`` -> ``storage-accounts``."""
    return re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()


def test_titles_are_unique_so_the_readme_index_is_unambiguous():
    # `all_recipes` sorts by title for deterministic output, and the run README indexes
    # by it. Two identical titles make two different remediations indistinguishable in
    # the one document that explains them.
    titles = [r.policy_title for r in _recipes()]
    dupes = [t for t, n in Counter(titles).items() if n > 1]
    assert not dupes, f"duplicate policy titles: {dupes}"
