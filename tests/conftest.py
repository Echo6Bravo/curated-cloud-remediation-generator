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

#: Where the AWS provider plugin is cached between workspaces and between runs.
#:
#: Deliberately *outside* `tmp_path`: pytest deletes that between runs, which would
#: re-download on every invocation and defeat the point. Overridable so CI can point
#: it at a restored cache directory.
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
