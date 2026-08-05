"""Tests for AWS service-model drift detection.

The property that matters most: a check that *cannot run* must never report OK.
Silent success on a missing model would mean the "verified every run" promise
quietly stops being true the moment the AWS CLI is absent.
"""

from __future__ import annotations

import json

import pytest

from remgen import drift
from remgen.drift import DriftStatus, verify_all, verify_recipe
from remgen.model import ApiCall, Recipe
from remgen.recipes import all_recipes


@pytest.fixture(autouse=True)
def _clear_caches():
    """Model lookups are lru_cached; clear between tests that change the source."""
    drift.find_model_dir.cache_clear()
    drift._load_service_model.cache_clear()
    yield
    drift.find_model_dir.cache_clear()
    drift._load_service_model.cache_clear()


def _recipe(service="s3", operation="PutBucketVersioning", parameters=("Bucket",)) -> Recipe:
    return Recipe(
        policy_id="p1",
        policy_title="Title",
        summary="Summary",
        api=ApiCall(service=service, operation=operation, parameters=parameters),
        cli_template="aws thing --id {resource_id}",
        hcl=None,
        reverse_hint="undo",
    )


def _write_model(root, service, *, operations, shapes, api_version="2006-03-01"):
    path = root / service / api_version
    path.mkdir(parents=True)
    (path / "service-2.json").write_text(
        json.dumps(
            {
                "metadata": {"apiVersion": api_version},
                "operations": operations,
                "shapes": shapes,
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture
def fake_models(tmp_path, monkeypatch):
    """A minimal botocore-shaped model directory under our control."""
    root = tmp_path / "data"
    _write_model(
        root,
        "s3",
        operations={"PutBucketVersioning": {"input": {"shape": "PutBucketVersioningRequest"}}},
        shapes={
            "PutBucketVersioningRequest": {
                "members": {"Bucket": {}, "VersioningConfiguration": {}}
            }
        },
    )
    monkeypatch.setenv("REMGEN_BOTOCORE_DATA_DIR", str(root))
    drift.find_model_dir.cache_clear()
    drift._load_service_model.cache_clear()
    return root


def test_matching_recipe_is_ok(fake_models):
    result = verify_recipe(_recipe())
    assert result.status is DriftStatus.OK
    assert result.ok
    assert result.api_version == "2006-03-01"


def test_missing_operation_is_detected(fake_models):
    result = verify_recipe(_recipe(operation="RemovedOperation"))
    assert result.status is DriftStatus.OPERATION_MISSING
    assert not result.ok
    assert "RemovedOperation" in result.detail


def test_missing_parameter_is_detected(fake_models):
    result = verify_recipe(_recipe(parameters=("Bucket", "RenamedParam")))
    assert result.status is DriftStatus.PARAMETER_MISSING
    assert not result.ok
    assert "RenamedParam" in result.detail


def test_missing_service_is_detected(fake_models):
    result = verify_recipe(_recipe(service="nonexistentservice"))
    assert result.status is DriftStatus.SERVICE_MISSING
    assert not result.ok


def test_unavailable_source_never_reports_ok(tmp_path, monkeypatch):
    # The whole point: no model source must not be mistaken for a passing check.
    monkeypatch.setenv("REMGEN_BOTOCORE_DATA_DIR", str(tmp_path / "does-not-exist"))
    drift.find_model_dir.cache_clear()
    drift._load_service_model.cache_clear()
    result = verify_recipe(_recipe())
    assert result.status is DriftStatus.UNAVAILABLE
    assert not result.ok
    assert "REMGEN_BOTOCORE_DATA_DIR" in result.detail


def test_gzipped_model_is_read(tmp_path, monkeypatch):
    import gzip

    root = tmp_path / "data"
    path = root / "s3" / "2006-03-01"
    path.mkdir(parents=True)
    payload = {
        "metadata": {"apiVersion": "2006-03-01"},
        "operations": {"PutBucketVersioning": {"input": {"shape": "Req"}}},
        "shapes": {"Req": {"members": {"Bucket": {}}}},
    }
    with gzip.open(path / "service-2.json.gz", "wb") as fh:
        fh.write(json.dumps(payload).encode("utf-8"))
    monkeypatch.setenv("REMGEN_BOTOCORE_DATA_DIR", str(root))
    drift.find_model_dir.cache_clear()
    drift._load_service_model.cache_clear()
    assert verify_recipe(_recipe()).status is DriftStatus.OK


def test_newest_api_version_is_used(tmp_path, monkeypatch):
    root = tmp_path / "data"
    _write_model(
        root,
        "s3",
        operations={},
        shapes={},
        api_version="2000-01-01",
    )
    _write_model(
        root,
        "s3",
        operations={"PutBucketVersioning": {"input": {"shape": "Req"}}},
        shapes={"Req": {"members": {"Bucket": {}}}},
        api_version="2020-01-01",
    )
    monkeypatch.setenv("REMGEN_BOTOCORE_DATA_DIR", str(root))
    drift.find_model_dir.cache_clear()
    drift._load_service_model.cache_clear()
    result = verify_recipe(_recipe())
    assert result.status is DriftStatus.OK
    assert result.api_version == "2020-01-01"


def test_corrupt_model_is_reported_not_crashed(tmp_path, monkeypatch):
    root = tmp_path / "data"
    path = root / "s3" / "2006-03-01"
    path.mkdir(parents=True)
    (path / "service-2.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("REMGEN_BOTOCORE_DATA_DIR", str(root))
    drift.find_model_dir.cache_clear()
    drift._load_service_model.cache_clear()
    assert verify_recipe(_recipe()).status is DriftStatus.SERVICE_MISSING


def test_verify_all_preserves_order(fake_models):
    recipes = (_recipe(), _recipe(operation="Gone"))
    results = verify_all(recipes)
    assert len(results) == 2
    assert results[0].status is DriftStatus.OK
    assert results[1].status is DriftStatus.OPERATION_MISSING


# ---------------------------------------------------------------------------
# The real curated set against the real, locally available AWS models
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    drift.find_model_dir() is None,
    reason="no botocore service models available in this environment",
)
def test_curated_recipes_match_real_aws_models():
    """Every shipped recipe must match the AWS API as actually published.

    This is the test that catches a recipe written from a stale memory of the API
    rather than from the service model.
    """
    failures = [
        f"{r.service}.{r.operation}: {r.detail}"
        for r in verify_all(all_recipes())
        if r.status not in (DriftStatus.OK, DriftStatus.UNAVAILABLE)
    ]
    assert not failures, "recipes no longer match AWS:\n" + "\n".join(failures)
