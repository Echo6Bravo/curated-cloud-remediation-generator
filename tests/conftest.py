"""Shared test configuration.

Holds the OpenTofu provider setup, which is a property of the whole session rather
than of any one test.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

#: The provider constraint every generated-HCL check is validated against. Declared
#: once here so the warmed workspace and the per-test workspaces cannot disagree --
#: a mismatch would silently send each test back to a full `init`.
PROVIDER_TF = (
    "terraform {\n  required_providers {\n"
    '    aws = { source = "hashicorp/aws", version = "~> 5.0" }\n'
    "  }\n}\n"
    'provider "aws" {\n  region = "us-east-1"\n}\n'
)

#: The same, for Azure. A second constant rather than a parameterized builder,
#: because the two blocks are not the same shape and the difference is the point:
#: `azurerm` takes no `region`, so a provider block written by analogy to the AWS one
#: fails to load. `subscription_id` is required from azurerm 4.0 onward -- omitting it
#: is an error at plan time, not a default -- and `features {}` is here because every
#: published example has it, not because the schema demands it (measured: no
#: `min_items`, and a block without it validates on 5.0.1, 4.81.0 and 3.117.1).
AZURERM_PROVIDER_TF = (
    "terraform {\n  required_providers {\n"
    '    azurerm = { source = "hashicorp/azurerm", version = "~> 5.0" }\n'
    "  }\n}\n"
    'provider "azurerm" {\n  features {}\n'
    '  subscription_id = "00000000-0000-0000-0000-000000000000"\n}\n'
)

#: Where the provider plugins are cached between workspaces and between runs.
#:
#: Deliberately *outside* `tmp_path`: pytest deletes that between runs, which would
#: re-download on every invocation and defeat the point. Overridable so CI can point
#: it at a restored cache directory. Shared by both clouds -- one cache directory can
#: hold both providers, and splitting it would double the CI restore for no gain.
_DEFAULT_CACHE = Path.home() / ".cache" / "remgen-test-tofu-plugins"

TOFU = shutil.which("tofu") or shutil.which("terraform")


@pytest.fixture(scope="session", autouse=True)
def tofu_plugin_cache() -> Path | None:
    """Point OpenTofu at a shared plugin cache for the whole session.

    Autouse and session-scoped: the cache is only useful if every workspace in the
    run shares it, and requiring each test to opt in would mean a new test silently
    paying the full download again.

    Set in ``os.environ`` directly rather than via ``monkeypatch``, which is
    function-scoped and so cannot hold a session-wide value. Restored afterwards so a
    caller's own setting survives.

    Measured: the cache turns a per-workspace 663 MB download into a symlink tree
    (``.terraform`` drops to 0 B on disk). It does *not* make `init` cheap on its own
    -- see :func:`tofu_workspace_template` for the part that does.
    """
    if TOFU is None:
        yield None
        return

    cache = Path(os.environ.get("REMGEN_TEST_TOFU_CACHE") or _DEFAULT_CACHE)
    # OpenTofu creates a missing TF_PLUGIN_CACHE_DIR itself, but it is created here
    # too: if the path cannot be created, failing now names the cache as the cause
    # rather than surfacing later as an unexplained slow run.
    cache.mkdir(parents=True, exist_ok=True)

    previous = os.environ.get("TF_PLUGIN_CACHE_DIR")
    os.environ["TF_PLUGIN_CACHE_DIR"] = str(cache)
    try:
        yield cache
    finally:
        if previous is None:
            os.environ.pop("TF_PLUGIN_CACHE_DIR", None)
        else:
            os.environ["TF_PLUGIN_CACHE_DIR"] = previous


@pytest.fixture(scope="session")
def tofu_workspace_template(tmp_path_factory, tofu_plugin_cache) -> Path | None:
    """Return a directory holding an already-initialized ``.terraform`` tree.

    Tests copy this into their own workspace instead of running ``init`` there. The
    plugin cache alone does not make ``init`` cheap: even fully warm it re-verifies
    the 663 MB provider every time, measured at **16.7s per workspace**. Copying an
    initialized ``.terraform`` (a tree of symlinks into the cache, 0 B on disk) drops
    that to the cost of ``validate`` alone -- **2.0s**. Across five workspaces that is
    the difference between a suite people run and one they narrow.

    This is a speedup with no loss of rigor, which was verified rather than assumed:
    a workspace using the copied tree still rejects a missing required argument *and*
    an unsupported attribute, so full provider schema knowledge is intact. What is
    skipped is re-downloading and re-verifying a provider that has not changed within
    a single test session.

    ``None`` when no OpenTofu binary is present; the tests that need it skip on their
    own guard.
    """
    if TOFU is None:
        return None

    template = tmp_path_factory.mktemp("tofu-template")
    (template / "main.tf").write_text(PROVIDER_TF, encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        [TOFU, "init", "-no-color", "-backend=false"],
        cwd=template,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        # Returning None rather than failing here: a session fixture that raises
        # errors every test that requests it, which would report an infrastructure
        # problem as a wall of unrelated failures. The caller falls back to running
        # `init` itself and fails there with the real diagnostic.
        return None
    return template


@pytest.fixture(scope="session")
def real_provider_schema_path(tmp_path_factory, tofu_workspace_template) -> Path | None:
    """Return a path to a freshly generated ``tofu providers schema -json`` document.

    Session-scoped because generating it costs ~9.5s and the document cannot change
    within a run. Both the checker's own tests and the end-to-end ``verify`` test read
    it, and the latter needs a *path* rather than a parsed schema -- the CLI takes a
    path, and handing it a hand-built document would test the fixture instead of the
    command.

    ``None`` when there is no binary or the template could not be built.
    """
    if TOFU is None or tofu_workspace_template is None:
        return None

    path = tmp_path_factory.mktemp("tf-schema") / "schema.json"
    result = subprocess.run(  # noqa: S603
        [TOFU, "providers", "schema", "-json"],
        cwd=tofu_workspace_template,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    path.write_text(result.stdout, encoding="utf-8")
    return path


@pytest.fixture(scope="session")
def azurerm_workspace_template(tmp_path_factory, tofu_plugin_cache) -> Path | None:
    """The Azure counterpart of :func:`tofu_workspace_template`.

    A separate session fixture rather than a parameterization of the AWS one, and the
    cost is why: this is a second ``init`` (measured ~7.5s warm) and a second provider
    download, so folding both into one fixture would make every AWS-only run pay for
    Azure and vice versa. Session-scoped and lazily requested, so a run that touches
    no Azure HCL never builds it.

    Everything else about the mechanism is identical -- the copied ``.terraform`` tree
    of symlinks into the shared plugin cache -- and the sharing is deliberate: the
    saving is per workspace, and there is more than one Azure workspace to validate.

    ``None`` when no OpenTofu binary is present; requesting tests skip on their own
    guard, exactly as the AWS ones do.
    """
    if TOFU is None:
        return None

    template = tmp_path_factory.mktemp("azurerm-template")
    (template / "main.tf").write_text(AZURERM_PROVIDER_TF, encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        [TOFU, "init", "-no-color", "-backend=false"],
        cwd=template,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        # As above: a session fixture that raises attributes an infrastructure problem
        # to every test that requested it. The caller falls back to its own `init`.
        return None
    return template


@pytest.fixture(scope="session")
def real_azurerm_schema_path(tmp_path_factory, azurerm_workspace_template) -> Path | None:
    """A real ``tofu providers schema -json`` document for ``hashicorp/azurerm``.

    The Azure half of the schema axis, and it has to be generated the same way the AWS
    one is for the same reason: the checker in :mod:`remgen.core.hcl_schema` does not
    run ``tofu`` itself, so without this the end-to-end Azure ``verify`` test would
    depend on a schema document someone remembered to generate and would skip when they
    had not.

    ``None`` when there is no binary or the template could not be built.
    """
    if TOFU is None or azurerm_workspace_template is None:
        return None

    path = tmp_path_factory.mktemp("azurerm-schema") / "schema.json"
    result = subprocess.run(  # noqa: S603
        [TOFU, "providers", "schema", "-json"],
        cwd=azurerm_workspace_template,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    path.write_text(result.stdout, encoding="utf-8")
    return path


@pytest.fixture(scope="session")
def real_provider_schema(real_provider_schema_path):
    """Return the real ``hashicorp/aws`` schema, as :class:`ProviderSchema`.

    Produced here rather than required from the environment, because the checker in
    :mod:`remgen.core.hcl_schema` deliberately does not run ``tofu`` itself -- so
    without this fixture its tests against the *real* provider would depend on a
    19 MB artifact someone had remembered to generate, and would skip when they had
    not. A skip is exactly what must not happen to the tests that establish the
    module's central claim: that the schema's ``required`` flag is what the parser
    enforces.

    Generated from the already-initialized template, so it costs one
    ``providers schema -json`` per session (measured ~9.5s) and no extra download.
    Gated on the same ``TOFU is None`` condition as every other parser-backed test,
    which CI's "confirm the gated tests will actually run" step already covers.

    ``None`` when there is no binary or the template could not be built; requesting
    tests skip on their own guard.
    """
    if real_provider_schema_path is None:
        return None

    from remgen.core.hcl_schema import SchemaSourceError, load_provider_schema

    try:
        return load_provider_schema(real_provider_schema_path, source_prefix="hashicorp/aws")
    except SchemaSourceError:
        # The loader rejecting real `tofu` output is itself a bug, but reporting it
        # from a session fixture would attribute it to every requesting test. The
        # tests that assert the loader accepts real output fail on their own guard.
        return None
