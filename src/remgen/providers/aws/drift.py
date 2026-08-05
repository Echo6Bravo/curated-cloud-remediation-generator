"""Verify recipes against the real AWS API definitions on every run.

AWS changes its API surface continuously. A recipe that was correct when written
can silently rot: an operation gets deprecated, a parameter gets renamed. Rather
than scraping AWS HTML documentation -- which is brittle and unverifiable -- this
module reads the *machine-readable service models* (``service-2.json``) that AWS
publishes and that botocore ships. Those models are the same source of truth used
to generate the AWS CLI and every AWS SDK, so checking against them is equivalent
to checking against the documented API.

Resolution order for the model directory:

1. ``REMGEN_BOTOCORE_DATA_DIR`` environment variable (explicit override).
2. An importable ``botocore`` package, if one happens to be installed.
3. The copy bundled inside an AWS CLI v2 installation, located by resolving the
   ``aws`` executable on ``PATH``.

If none are found, verification reports ``UNAVAILABLE`` rather than passing. A
check that cannot run must never look like a check that passed.

:class:`~remgen.core.drift.DriftResult` and its status enum are defined in
``core`` because the CLI's reporting and exit codes are shared across clouds.
Everything about *producing* the answer is here, because nothing about
``service-2.json`` generalizes to any other cloud.
"""

from __future__ import annotations

import glob
import gzip
import json
import os
import shutil
from functools import lru_cache
from pathlib import Path

from remgen.core.drift import DriftResult, DriftStatus
from remgen.core.model import Recipe


class ModelSourceNotFound(RuntimeError):
    """Raised when no botocore service-model directory can be located."""


@lru_cache(maxsize=1)
def find_model_dir() -> Path | None:
    """Locate a botocore ``data`` directory containing service models.

    Returns ``None`` when no source is available, so callers can degrade to
    ``UNAVAILABLE`` instead of crashing.
    """
    override = os.environ.get("REMGEN_BOTOCORE_DATA_DIR")
    if override:
        candidate = Path(override).expanduser()
        return candidate if candidate.is_dir() else None

    # An installed botocore, if the user happens to have one.
    try:
        import botocore  # noqa: PLC0415  (optional dependency, probed at runtime)

        data = Path(botocore.__file__).parent / "data"
        if data.is_dir():
            return data
    except ImportError:
        pass

    # AWS CLI v2 bundles its own vendored botocore.
    aws_bin = shutil.which("aws")
    if aws_bin:
        resolved = Path(aws_bin).resolve()
        # Walk up from .../libexec/bin/aws looking for the vendored data dir.
        for parent in list(resolved.parents)[:5]:
            matches = sorted(parent.glob("lib/python3*/site-packages/awscli/botocore/data"))
            if matches:
                return matches[-1]
    return None


@lru_cache(maxsize=256)
def _load_service_model(service: str) -> dict | None:
    """Load and cache the newest ``service-2.json`` for ``service``."""
    data_dir = find_model_dir()
    if data_dir is None:
        return None
    # Model layout: <data>/<service>/<api-version>/service-2.json[.gz]
    pattern = str(data_dir / glob.escape(service) / "*" / "service-2.json*")
    paths = sorted(glob.glob(pattern))
    if not paths:
        return None
    path = paths[-1]  # newest API version
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError, gzip.BadGzipFile):
        return None


def verify_recipe(recipe: Recipe) -> DriftResult:
    """Check one recipe's declared operation and parameters against AWS's model."""
    api = recipe.api
    base = {
        "policy_id": recipe.policy_id,
        "policy_title": recipe.policy_title,
        "service": api.service,
        "operation": api.operation,
    }

    if find_model_dir() is None:
        return DriftResult(
            **base,
            status=DriftStatus.UNAVAILABLE,
            detail=(
                "No botocore service models found. Install AWS CLI v2, or set "
                "REMGEN_BOTOCORE_DATA_DIR to a botocore data directory."
            ),
        )

    model = _load_service_model(api.service)
    if model is None:
        return DriftResult(
            **base,
            status=DriftStatus.SERVICE_MISSING,
            detail=f"No service model found for {api.service!r}.",
        )

    api_version = str(model.get("metadata", {}).get("apiVersion", ""))
    operations = model.get("operations", {})
    if api.operation not in operations:
        return DriftResult(
            **base,
            status=DriftStatus.OPERATION_MISSING,
            api_version=api_version,
            detail=(
                f"Operation {api.operation!r} is absent from the {api.service} model "
                f"({api_version}). The API may have been renamed or removed."
            ),
        )

    input_shape_name = operations[api.operation].get("input", {}).get("shape")
    shapes = model.get("shapes", {})
    members: set[str] = set()
    if input_shape_name:
        members = set(shapes.get(input_shape_name, {}).get("members", {}))

    missing = [p for p in api.parameters if p not in members]
    if missing:
        return DriftResult(
            **base,
            status=DriftStatus.PARAMETER_MISSING,
            api_version=api_version,
            detail=(
                f"Parameter(s) {', '.join(sorted(missing))} no longer accepted by "
                f"{api.service}.{api.operation} ({api_version})."
            ),
        )

    return DriftResult(**base, status=DriftStatus.OK, api_version=api_version)


def verify_all(recipes: tuple[Recipe, ...]) -> tuple[DriftResult, ...]:
    """Verify every recipe. Returns results in the order given."""
    return tuple(verify_recipe(r) for r in recipes)


def model_source_description() -> str:
    """Human-readable description of where models are being read from."""
    data_dir = find_model_dir()
    return str(data_dir) if data_dir else "unavailable"
