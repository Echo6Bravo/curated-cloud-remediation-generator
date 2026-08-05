"""Tests for catalog snapshotting/diffing and input parsing."""

from __future__ import annotations

import json

import pytest

from remgen.catalog import (
    SNAPSHOT_VERSION,
    BaselineState,
    CacheError,
    Snapshot,
    default_cache_dir,
    diff_catalog,
    load_snapshot,
    save_snapshot,
    snapshot_path,
)
from remgen.model import Policy
from remgen.sources import (
    JsonFileSource,
    SourceError,
    parse_findings,
    parse_policies,
)

# ---------------------------------------------------------------------------
# Catalog diff
# ---------------------------------------------------------------------------

A = Policy(policy_id="1", title="Alpha", category="IAM")
B = Policy(policy_id="2", title="Beta", category="Data")
C = Policy(policy_id="3", title="Gamma", category="Network")


def test_first_run_reports_no_changes():
    # A cold cache must not report the whole catalog as new: on a fresh CI runner
    # that would be hundreds of lines indistinguishable from a real change.
    diff = diff_catalog((A, B), None)
    assert diff.first_run
    assert not diff.changed
    assert diff.added == ()
    assert "first run" in " ".join(diff.summary_lines())


def test_detects_added_removed_and_renamed(tmp_path):
    save_snapshot(Snapshot(policies=(A, B)), tmp_path)
    renamed_b = Policy(policy_id="2", title="Beta v2", category="Data")
    diff = diff_catalog((A, renamed_b, C), *load_snapshot(tmp_path))
    assert diff.compared
    assert not diff.first_run
    assert [p.policy_id for p in diff.added] == ["3"]
    assert diff.removed == ()
    assert diff.renamed == (("2", "Beta", "Beta v2"),)
    assert diff.changed


def test_detects_removal(tmp_path):
    save_snapshot(Snapshot(policies=(A, B)), tmp_path)
    diff = diff_catalog((A,), *load_snapshot(tmp_path))
    assert [p.policy_id for p in diff.removed] == ["2"]


def test_unchanged_catalog_reports_unchanged(tmp_path):
    save_snapshot(Snapshot(policies=(A, B)), tmp_path)
    diff = diff_catalog((A, B), *load_snapshot(tmp_path))
    assert not diff.changed
    assert "unchanged" in " ".join(diff.summary_lines())


def test_new_policy_summary_states_it_is_not_remediated(tmp_path):
    save_snapshot(Snapshot(policies=(A,)), tmp_path)
    diff = diff_catalog((A, C), *load_snapshot(tmp_path))
    text = " ".join(diff.summary_lines())
    assert "not remediated" in text


# ---------------------------------------------------------------------------
# Snapshot persistence
# ---------------------------------------------------------------------------


def test_snapshot_roundtrip(tmp_path):
    original = Snapshot(policies=(A, B), captured_at="2026-01-01T00:00:00Z")
    save_snapshot(original, tmp_path)
    loaded, state = load_snapshot(tmp_path)
    assert state is BaselineState.PRESENT
    assert loaded is not None
    assert {p.policy_id for p in loaded.policies} == {"1", "2"}
    assert loaded.captured_at == "2026-01-01T00:00:00Z"


def test_missing_snapshot_reports_absent(tmp_path):
    loaded, state = load_snapshot(tmp_path / "nope")
    assert loaded is None
    assert state is BaselineState.ABSENT


@pytest.mark.parametrize(
    "text",
    [
        "{not json",
        "[]",
        json.dumps({"version": SNAPSHOT_VERSION + 99, "policies": []}),
        json.dumps({"version": SNAPSHOT_VERSION, "policies": "nope"}),
        json.dumps({"version": SNAPSHOT_VERSION, "policies": [{"title": "no id"}]}),
        json.dumps({"version": SNAPSHOT_VERSION, "policies": ["not-an-object"]}),
    ],
)
def test_corrupt_snapshot_degrades_to_no_baseline(text):
    # A broken cache must never break the run, and must never be half-read.
    assert Snapshot.from_json(text) is None


def test_corrupt_snapshot_is_unreadable_not_a_first_run(tmp_path):
    # The distinction that matters: a corrupt baseline must NOT be reported as a
    # first run. If it were, an operator on their hundredth run would be told
    # "baseline saved, no changes this time" -- and because the baseline is then
    # rebuilt from the current catalog, any policy added since their last good run
    # would never be reported, on this run or any later one. That is a silent false
    # negative in the one check this module exists to provide.
    snapshot_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    snapshot_path(tmp_path).write_text("garbage", encoding="utf-8")

    loaded, state = load_snapshot(tmp_path)
    assert loaded is None
    assert state is BaselineState.UNREADABLE

    diff = diff_catalog((A,), loaded, state)
    assert not diff.first_run
    assert not diff.compared
    text = " ".join(diff.summary_lines())
    assert "WARNING" in text
    assert "NOT detected" in text
    assert "first run" not in text


def test_unreadable_snapshot_file_is_unreadable_not_absent(tmp_path):
    # A permission error on an existing baseline is also not a first run.
    path = snapshot_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")
    path.chmod(0o000)
    try:
        loaded, state = load_snapshot(tmp_path)
    finally:
        path.chmod(0o600)
    assert loaded is None
    assert state is BaselineState.UNREADABLE


def test_diff_defaults_to_absent_without_a_state():
    assert diff_catalog((A,), None).baseline is BaselineState.ABSENT


def test_diff_rejects_present_state_without_a_snapshot():
    # Guards against a caller passing PRESENT with no snapshot, which would
    # otherwise silently produce a "first run" verdict.
    with pytest.raises(ValueError, match="requires a snapshot"):
        diff_catalog((A,), None, BaselineState.PRESENT)


def test_save_leaves_no_temp_file(tmp_path):
    save_snapshot(Snapshot(policies=(A,)), tmp_path)
    assert not list(tmp_path.glob("*.tmp"))


def test_unwritable_cache_raises_cache_error_not_oserror(tmp_path):
    # The CLI turns CacheError into a message; a bare OSError would reach the
    # operator as a traceback.
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        with pytest.raises(CacheError, match="cannot write snapshot"):
            save_snapshot(Snapshot(policies=(A,)), ro / "sub")
    finally:
        ro.chmod(0o700)


def test_failed_save_leaves_no_partial_temp_file(tmp_path):
    # A leftover .tmp must not be mistaken for a snapshot by a later run.
    snapshot_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    target = snapshot_path(tmp_path)
    # Make the *file* unwritable by making its directory read-only after creation.
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(CacheError):
            save_snapshot(Snapshot(policies=(A,)), tmp_path)
    finally:
        tmp_path.chmod(0o700)
    assert not list(tmp_path.glob("*.tmp"))
    assert not target.exists()


def test_cache_dir_honours_env(monkeypatch, tmp_path):
    monkeypatch.setenv("REMGEN_CACHE_DIR", str(tmp_path / "custom"))
    assert default_cache_dir() == tmp_path / "custom"


def test_cache_dir_falls_back_to_xdg(monkeypatch, tmp_path):
    monkeypatch.delenv("REMGEN_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert default_cache_dir() == tmp_path / "remgen"


# ---------------------------------------------------------------------------
# Finding parsing
# ---------------------------------------------------------------------------


def test_parses_common_key_spellings():
    records = [
        {"policy_id": "p", "resource_id": "r", "region": "us-east-1", "account_id": "1"},
        {"policyId": "p", "resourceId": "r2", "region": "us-east-1", "accountId": "1"},
        {"PolicyId": "p", "ResourceId": "r3", "Region": "us-east-1", "AccountId": "1"},
    ]
    findings, rejections = parse_findings(records)
    assert len(findings) == 3
    assert rejections == ()


def test_numeric_account_id_is_accepted():
    findings, rejections = parse_findings(
        [{"policyId": "p", "resourceId": "r", "region": "us-east-1", "accountId": 123456789012}]
    )
    assert findings[0].account_id == "123456789012"
    assert rejections == ()


def test_rejections_are_collected_not_dropped():
    records = [
        {"policyId": "p", "resourceId": "good", "region": "us-east-1", "accountId": "1"},
        {"policyId": "p", "region": "us-east-1", "accountId": "1"},  # no resource
        "not-an-object",
        {"policyId": "p", "resourceId": "bad; rm -rf /", "region": "us-east-1", "accountId": "1"},
    ]
    findings, rejections = parse_findings(records)
    # The counts must reconcile, or a dropped finding looks like a compliant one.
    assert len(findings) + len(rejections) == len(records)
    assert len(findings) == 1
    assert {r.index for r in rejections} == {1, 2, 3}
    assert all(r.reason for r in rejections)


def test_rejection_reason_is_truncated():
    findings, rejections = parse_findings([{"policyId": "p", "resourceId": "x" * 5000}])
    assert len(rejections) == 1
    assert len(rejections[0].raw) <= 130


# ---------------------------------------------------------------------------
# Policy parsing
# ---------------------------------------------------------------------------


def test_parse_policies_dedupes():
    policies, rejections = parse_policies(
        [{"id": "1", "title": "A"}, {"id": "1", "title": "A again"}]
    )
    assert len(policies) == 1
    assert len(rejections) == 1
    assert "duplicate" in rejections[0].reason


def test_parse_policies_requires_id():
    policies, rejections = parse_policies([{"title": "no id"}])
    assert policies == ()
    assert "missing policy id" in rejections[0].reason


# ---------------------------------------------------------------------------
# JsonFileSource
# ---------------------------------------------------------------------------


def test_reads_bare_array(tmp_path):
    path = tmp_path / "f.json"
    path.write_text(
        json.dumps([{"policyId": "p", "resourceId": "r", "region": "us-east-1", "accountId": "1"}]),
        encoding="utf-8",
    )
    result = JsonFileSource(findings_path=path).load()
    assert len(result.findings) == 1


@pytest.mark.parametrize("key", ["findings", "items", "data", "results"])
def test_reads_wrapped_object(tmp_path, key):
    path = tmp_path / "f.json"
    record = {"policyId": "p", "resourceId": "r", "region": "us-east-1", "accountId": "1"}
    path.write_text(json.dumps({key: [record]}), encoding="utf-8")
    assert len(JsonFileSource(findings_path=path).load().findings) == 1


def test_missing_file_raises_source_error(tmp_path):
    with pytest.raises(SourceError, match="cannot read"):
        JsonFileSource(findings_path=tmp_path / "nope.json").load()


def test_invalid_json_raises_source_error(tmp_path):
    path = tmp_path / "f.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(SourceError, match="not valid JSON"):
        JsonFileSource(findings_path=path).load()


def test_unexpected_shape_raises_source_error(tmp_path):
    path = tmp_path / "f.json"
    path.write_text(json.dumps({"unexpected": 1}), encoding="utf-8")
    with pytest.raises(SourceError, match="expected a JSON array"):
        JsonFileSource(findings_path=path).load()
