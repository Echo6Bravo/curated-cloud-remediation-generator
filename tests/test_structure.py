"""Tests for the package's structural rules.

These assert properties of the *layout* rather than of any behaviour, because the
layout is what keeps a second cloud from changing the first one's output. Two
docstrings -- :mod:`remgen` and :mod:`remgen.core` -- promise a test enforces the
dependency direction. This is that test; without it the promise is a comment, and
a comment does not fail a build.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

import remgen
from remgen.core.provider import Provider
from remgen.providers.aws import AWS
from remgen.providers.azure import AZURE

SRC = pathlib.Path(remgen.__file__).parent
CORE = SRC / "core"


def _imported_modules(path: pathlib.Path) -> set[str]:
    """Return every module name ``path`` imports, from AST rather than by running it.

    Parsed statically on purpose: importing the module to inspect its imports would
    only see what ran, so a violation inside a function body or behind a conditional
    would pass unnoticed -- and a lazy import is exactly how this rule gets broken
    while looking like it holds.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def _core_modules() -> list[pathlib.Path]:
    return sorted(CORE.rglob("*.py"))


def test_there_are_core_modules_to_check():
    # A path typo would make every test below pass over an empty set, which is the
    # failure mode of a structural test: it reports green while checking nothing.
    assert len(_core_modules()) >= 5


@pytest.mark.parametrize("path", _core_modules(), ids=lambda p: p.name)
def test_core_never_imports_from_providers(path):
    """The one-way dependency rule, enforced rather than documented.

    ``core`` holds the shared pipeline. If it may reach into ``providers.aws``, then
    adding Azure means editing shared code, and the edit that makes Azure work is
    free to change what AWS emits. Whatever ``core`` needs from a cloud arrives
    through :class:`~remgen.core.provider.Provider`, so a failure here names the
    import that has to be inverted.
    """
    offenders = sorted(
        name
        for name in _imported_modules(path)
        if name == "remgen.providers" or name.startswith("remgen.providers.")
    )
    assert not offenders, (
        f"{path.relative_to(SRC)} imports {offenders} -- core must not depend on a "
        f"provider. Pass what it needs through remgen.core.provider.Provider."
    )


def _provider_names() -> list[str]:
    """Every provider package under ``remgen.providers``, discovered not listed.

    Discovered so that adding a cloud cannot silently opt it out of the structural
    rules below. A hardcoded list would have to be edited by the same commit that
    adds the provider, and the edit that is easiest to forget is the one that makes
    the new code exempt from the checks.
    """
    return sorted(
        p.name for p in (SRC / "providers").iterdir() if p.is_dir() and (p / "__init__.py").exists()
    )


def test_every_provider_is_discovered():
    # Guards the discovery itself: a wrong path would return [] and every
    # parametrized test below would vanish rather than fail.
    names = _provider_names()
    assert "aws" in names and "azure" in names, names


def _provider_modules() -> list[pathlib.Path]:
    return sorted((SRC / "providers").rglob("*.py"))


@pytest.mark.parametrize("path", _provider_modules(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_a_provider_never_imports_another_provider(path):
    """Two clouds sharing code directly is how one silently alters the other.

    Shared code belongs in ``core``, where the sharing is visible and both clouds'
    tests cover it. A cross-provider import puts it somewhere only one cloud's tests
    look.

    Now that there are two providers this can actually fail -- with one it was a rule
    without a counterexample. The tempting import is real: Azure needs a shell
    generator and AWS has one, so ``from remgen.providers.aws.shell import ...`` is
    the shortest path to a working ``azremgen`` and the one that makes an Azure change
    able to alter AWS output.
    """
    own_package = path.parent.name if path.parent.name != "providers" else None
    offenders = sorted(
        name
        for name in _imported_modules(path)
        if name.startswith("remgen.providers.")
        and (own_package is None or f".{own_package}" not in name)
    )
    assert not offenders, f"{path.relative_to(SRC)} imports another provider: {offenders}"


# ---------------------------------------------------------------------------
# The provider descriptor
# ---------------------------------------------------------------------------


def test_the_aws_descriptor_declares_the_two_correctness_claims():
    # Not labels. Region scoping decides whether HCL may span regions, and the scope
    # noun decides what every filename and guard message says.
    assert AWS.hcl_provider_is_region_scoped is True
    assert AWS.credential_scope_noun == "account"


def test_the_aws_descriptor_is_fully_populated():
    # An empty hint is a legal value that produces a message telling the user
    # nothing, which is indistinguishable from a message that was never written.
    assert AWS.catalog_export_hint
    assert AWS.models_unavailable_hint
    assert AWS.cli_requirement


def test_the_azure_descriptor_declares_the_claims_that_differ_from_aws():
    """The three values that make Azure Azure, asserted because they change output.

    ``hcl_provider_is_region_scoped`` is the consequential one: an ``azurerm``
    provider block carries no location, so ``.tf`` files may span locations. Setting
    it True would split Azure output per location, producing more files than the
    provider requires and implying a constraint that does not exist.
    """
    assert AZURE.credential_scope_noun == "subscription"
    assert AZURE.region_noun == "location"
    assert AZURE.hcl_provider_is_region_scoped is False
    # The pair that must differ from AWS, or the descriptor is not describing a
    # second cloud at all.
    assert AZURE.cloud != AWS.cloud
    assert AZURE.command != AWS.command


def test_the_azure_descriptor_is_fully_populated():
    # Same bar as AWS: an empty hint produces a message that tells the user nothing,
    # which is indistinguishable from one nobody wrote.
    assert AZURE.catalog_export_hint
    assert AZURE.models_unavailable_hint
    assert AZURE.cli_requirement
    assert AZURE.tf_provider_source == "hashicorp/azurerm"


def test_azure_ships_recipes_and_reaches_them_through_the_descriptor():
    """The provider's coverage, asserted so a change to it has to be deliberate.

    This test used to assert ``all_recipes() == ()`` and was named for it, on the rule
    that the first recipe to land must edit this test rather than quietly flipping the
    tool from "no coverage" to "some coverage" with no other signal. The recipes have
    landed, so it asserts the opposite fact with the same intent: the descriptor really
    reaches them, and every recipe is retrievable by the id a finding carries.

    ``get_recipe`` is exercised through the descriptor rather than through the recipes
    package directly, because those are two different facts. The package's own registry
    is tested in ``tests/test_azure_recipe_set.py``; what is checked here is the wiring,
    which is what silently returns ``None`` for everything if the descriptor still
    points at a module-level empty tuple.

    **One axis's verifier is asserted non-``None``, and the reason has changed once.**
    This originally required ``verify_cli_surface is None``, reasoning that ``None``
    prints "did not run" while a stub returning ``()`` reads as zero failures out of
    zero checks. That was about a stub. The verifier is real now, so a ``None`` here
    would stop a working axis from running at all.
    """
    recipes = AZURE.all_recipes()
    assert recipes, "the descriptor reaches no recipes; check the _RECIPES wiring"
    for recipe in recipes:
        assert AZURE.get_recipe(recipe.policy_id) is recipe
    assert AZURE.get_recipe("no-such-policy-id") is None
    assert AZURE.verify_cli_surface is not None, (
        "the CLI-surface axis is implemented; a None here would silently stop it running"
    )
    assert AZURE.describe_cli_surface_source is not None, (
        "an axis that runs without naming its source produces a report nobody can reproduce"
    )


def test_every_azure_provider_seam_is_implemented_and_none_still_raises():
    """No seam may still be a stub, because each stub had a *legal* quiet return.

    This replaces a parametrized test that asserted ``verify_recipes`` and
    ``hcl_scope_block`` raise ``NotImplementedError``. That test was the property which
    made shipping ``azremgen`` before its recipes safe: ``hcl_scope_block`` returning
    ``""`` is legal (the AWS implementation returns it for a region-spanning unit) and
    would have emitted HCL with no subscription guard, and ``verify_recipes`` returning
    ``()`` is indistinguishable from "every recipe passed" one frame up.

    Both are implemented now, so the assertion inverts rather than disappears. Deleting
    it would leave nothing checking that the descriptor points at the real
    implementations -- and a descriptor still pointing at a stub, with the working
    module sitting unreachable beside it, is exactly what happens when the wiring is
    forgotten. Each is called with a real argument and checked for the thing only the
    implementation produces.
    """
    from remgen.core.layout import Format, OutputUnit

    unit = OutputUnit(
        fmt=Format.HCL,
        cloud="azure",
        scope_id="00000000-0000-0000-0000-000000000000",
        region=None,
        part=None,
        total_parts=1,
        pairs=(),
        scope_noun="subscription",
    )
    block = AZURE.hcl_scope_block(unit)
    assert "00000000-0000-0000-0000-000000000000" in block
    assert 'provider "azurerm"' in block

    # An empty tuple, so this asserts the seam is wired rather than asserting anything
    # about Azure's current API. `()` in and `()` out is what a stub would also have
    # returned -- which is why the stub raised -- so the fact being pinned is only that
    # it no longer raises; the real verifier is covered in tests/test_azure_drift.py.
    assert AZURE.verify_recipes(()) == ()


def test_azure_render_shell_is_implemented_and_no_longer_raises():
    """The counterpart to the test above: an implemented piece must not still raise.

    Asserted separately rather than by deleting the parametrized case, because
    "removed from the raising list" and "actually works" are different facts. A
    `NotImplementedError` here would mean the descriptor still points at the stub
    while the generator exists beside it, unreachable -- which is exactly what
    happens if the wiring is forgotten.
    """
    from remgen.core.layout import Format, OutputUnit

    unit = OutputUnit(
        fmt=Format.CLI,
        cloud="azure",
        scope_id="00000000-0000-0000-0000-000000000000",
        region=None,
        part=None,
        total_parts=1,
        pairs=(),
        scope_noun="subscription",
    )
    # Empty pair list: the contract says that renders a valid script containing no
    # commands, which is enough to prove the real generator is wired in.
    out = AZURE.render_shell([], version="0.0.0", generated_at="T", unit=unit)
    assert out.startswith("#!/usr/bin/env bash")
    assert "azremgen" in out


@pytest.mark.parametrize("cloud", ["", "aws/prod", "../etc", "a b", "."])
def test_a_cloud_id_that_is_not_one_path_segment_is_rejected(cloud):
    """The cloud id becomes a directory name, so it is validated where it is set.

    A value containing a separator or a traversal component would write outside the
    output directory. Checked in ``__post_init__`` rather than at each join, because
    a join added later would not know to check.
    """
    with pytest.raises(ValueError, match="cloud must be"):
        Provider(
            cloud=cloud,
            display_name="X",
            command="xremgen",
            credential_scope_noun="account",
            region_noun="region",
            hcl_provider_is_region_scoped=True,
            all_recipes=lambda: (),
            get_recipe=lambda _pid: None,
            verify_recipes=lambda _r: (),
            describe_model_source=lambda: "none",
            render_shell=lambda *a, **k: "",
            hcl_scope_block=lambda _u: "",
        )


def test_a_provider_without_a_command_is_rejected():
    # The command name appears in generated artifacts as the way to regenerate them.
    # An empty one produces an artifact that cannot be traced back to anything.
    with pytest.raises(ValueError, match="command"):
        Provider(
            cloud="aws",
            display_name="AWS",
            command="",
            credential_scope_noun="account",
            region_noun="region",
            hcl_provider_is_region_scoped=True,
            all_recipes=lambda: (),
            get_recipe=lambda _pid: None,
            verify_recipes=lambda _r: (),
            describe_model_source=lambda: "none",
            render_shell=lambda *a, **k: "",
            hcl_scope_block=lambda _u: "",
        )
