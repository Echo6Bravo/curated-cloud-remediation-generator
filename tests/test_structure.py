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


@pytest.mark.parametrize(
    "path",
    sorted((SRC / "providers" / "aws").rglob("*.py")),
    ids=lambda p: p.name,
)
def test_a_provider_never_imports_another_provider(path):
    """Two clouds sharing code directly is how one silently alters the other.

    Shared code belongs in ``core``, where the sharing is visible and both clouds'
    tests cover it. A cross-provider import puts it somewhere only one cloud's tests
    look.
    """
    offenders = sorted(
        name
        for name in _imported_modules(path)
        if name.startswith("remgen.providers.") and ".aws" not in name
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
