"""Track the Tenable Cloud Security policy catalog and diff it between runs.

New policies are published regularly, so a fixed recipe set silently falls behind.
This module snapshots the catalog to a local cache and reports what changed since
the previous run: policies added, policies removed, and policies renamed.

**A deliberate limitation, stated plainly:** detecting a new policy is not the
same as remediating it. This module cannot author a recipe. Writing one requires
verifying the AWS operation, the parameters, the IaC import identifier and the
safety characteristics -- judgement calls that a wrong answer makes actively
harmful. So a new policy is surfaced for a human to triage, and the "unsupported"
count is reported on every run rather than hidden. There is always a review queue;
that is the intended design, not a gap to be closed later.

**Cold-cache behaviour:** with no previous snapshot there is no baseline, so
nothing is reported as "new" -- the first run establishes the baseline and says
so. Reporting several hundred policies as newly added on a fresh machine would be
noise indistinguishable from a real change. This matters for CI, where a runner
with no persisted cache directory starts cold every time.

**"No baseline" and "baseline unreadable" are reported differently, on purpose.**
Both prevent a comparison, but they mean opposite things to the operator. A
genuine first run has nothing to compare and that is expected. A *corrupt or
unreadable* baseline on someone's hundredth run means the new-policy check they
rely on did not run -- and since the baseline is then rebuilt from the current
catalog, any policy added since their last run is permanently invisible. Calling
that a "first run" would be a silent false negative in the exact check this module
exists to provide, so it is reported as a warning with a distinct exit code.
"""

from __future__ import annotations

import contextlib
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from remgen.model import Policy

#: Schema version for the snapshot file. Bumped if the on-disk shape changes, so
#: an old snapshot is discarded rather than misread.
SNAPSHOT_VERSION = 1

_ENV_CACHE_DIR = "REMGEN_CACHE_DIR"


class BaselineState(str, Enum):
    """Why a baseline comparison did or did not happen.

    Distinguishes the two no-comparison cases, which look identical on disk but
    mean different things: ABSENT is an expected first run; UNREADABLE means a
    baseline existed and could not be used, so the change detection silently did
    not run.
    """

    #: A usable previous snapshot was found and compared against.
    PRESENT = "present"
    #: No snapshot file existed. Expected on a first run or a cold CI runner.
    ABSENT = "absent"
    #: A snapshot file existed but was corrupt, truncated, or a version this
    #: build cannot read. Comparison did not happen and the operator must know.
    UNREADABLE = "unreadable"


class CacheError(RuntimeError):
    """Raised when the snapshot cache cannot be written."""


def default_cache_dir() -> Path:
    """Return the cache directory, honouring ``REMGEN_CACHE_DIR`` then XDG."""
    override = os.environ.get(_ENV_CACHE_DIR)
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "remgen"


@dataclass(frozen=True)
class CatalogDiff:
    """What changed in the policy catalog since the previous snapshot."""

    #: Whether a baseline was compared against, and if not, why not.
    baseline: BaselineState
    added: tuple[Policy, ...] = ()
    removed: tuple[Policy, ...] = ()
    #: ``(policy_id, old_title, new_title)`` for policies whose title changed.
    renamed: tuple[tuple[str, str, str], ...] = ()
    #: Total policies in the current catalog.
    total: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed or self.renamed)

    @property
    def compared(self) -> bool:
        """True when a real comparison happened."""
        return self.baseline is BaselineState.PRESENT

    @property
    def first_run(self) -> bool:
        """True when no baseline existed at all (an expected first run)."""
        return self.baseline is BaselineState.ABSENT

    def summary_lines(self) -> list[str]:
        """Human-readable summary, suitable for terminal output."""
        if self.baseline is BaselineState.UNREADABLE:
            return [
                f"Policy catalog: {self.total} AWS policies.",
                "  WARNING: the cached baseline exists but could not be read "
                "(corrupt, truncated,",
                "  or written by a different version). No comparison was possible, so "
                "new or",
                "  changed policies were NOT detected on this run. The baseline is being "
                "rebuilt",
                "  from the current catalog, which means any policy added since the last "
                "good run",
                "  will not be reported later either. Review the catalog manually this "
                "once.",
            ]
        if self.baseline is BaselineState.ABSENT:
            return [
                f"Policy catalog: {self.total} AWS policies (first run -- baseline "
                f"saved, so no changes are reported this time).",
            ]
        if not self.changed:
            return [f"Policy catalog: {self.total} AWS policies, unchanged since last run."]

        lines = [f"Policy catalog: {self.total} AWS policies."]
        if self.added:
            lines.append(f"  {len(self.added)} new policy/policies since last run:")
            lines.extend(f"    + {p.title}  [{p.policy_id}]" for p in self.added)
            lines.append(
                "    New policies have no recipe and are not remediated. Review them "
                "and open an issue if one should be supported."
            )
        if self.removed:
            lines.append(f"  {len(self.removed)} policy/policies no longer in the catalog:")
            lines.extend(f"    - {p.title}  [{p.policy_id}]" for p in self.removed)
        if self.renamed:
            lines.append(f"  {len(self.renamed)} policy/policies renamed:")
            lines.extend(
                f"    ~ {old!r} -> {new!r}  [{pid}]" for pid, old, new in self.renamed
            )
        return lines


@dataclass
class Snapshot:
    """A point-in-time copy of the policy catalog."""

    policies: tuple[Policy, ...] = field(default_factory=tuple)
    #: ISO-8601 timestamp of when the snapshot was taken, or "" if unknown.
    captured_at: str = ""

    def to_json(self) -> str:
        payload = {
            "version": SNAPSHOT_VERSION,
            "captured_at": self.captured_at,
            "policies": [
                {"id": p.policy_id, "title": p.title, "category": p.category}
                for p in sorted(self.policies, key=lambda p: p.policy_id)
            ],
        }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Snapshot | None:
        """Parse a snapshot, returning ``None`` if it is unusable.

        A corrupt or future-versioned snapshot is treated as absent rather than
        raising: a broken cache file should degrade to "no baseline", never break
        the run.
        """
        try:
            payload = json.loads(text)
        except ValueError:
            return None
        if not isinstance(payload, dict) or payload.get("version") != SNAPSHOT_VERSION:
            return None
        raw = payload.get("policies")
        if not isinstance(raw, list):
            return None
        policies = []
        for item in raw:
            if not isinstance(item, dict):
                return None
            pid, title = item.get("id"), item.get("title")
            if not isinstance(pid, str) or not isinstance(title, str) or not pid:
                return None
            category = item.get("category")
            policies.append(
                Policy(
                    policy_id=pid,
                    title=title,
                    category=category if isinstance(category, str) else "",
                )
            )
        return cls(policies=tuple(policies), captured_at=str(payload.get("captured_at", "")))


def snapshot_path(cache_dir: Path | None = None) -> Path:
    """Return the path of the policy-catalog snapshot file."""
    return (cache_dir or default_cache_dir()) / "policy-catalog.json"


def load_snapshot(
    cache_dir: Path | None = None,
) -> tuple[Snapshot | None, BaselineState]:
    """Load the previous snapshot and report why it is unusable, if it is.

    Returns:
        ``(snapshot, state)``. The snapshot is ``None`` unless the state is
        :attr:`BaselineState.PRESENT`. The state distinguishes "no file" from
        "file present but unusable" so the caller can warn about the latter
        instead of mislabelling it a first run.
    """
    path = snapshot_path(cache_dir)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, BaselineState.ABSENT
    except OSError:
        # Present but unreadable -- a permission problem or an I/O error. The
        # baseline exists, so this is not a first run.
        return None, BaselineState.UNREADABLE

    snapshot = Snapshot.from_json(text)
    if snapshot is None:
        return None, BaselineState.UNREADABLE
    return snapshot, BaselineState.PRESENT


def save_snapshot(snapshot: Snapshot, cache_dir: Path | None = None) -> Path:
    """Write ``snapshot`` to the cache, creating the directory as needed.

    Written via a temporary file and atomic replace so an interrupted run cannot
    leave a truncated snapshot that looks like a catalog with fewer policies.

    Raises:
        CacheError: If the cache directory or file cannot be written. Raised as a
            typed error so the CLI can report it as a message rather than letting
            an ``OSError`` traceback reach the operator.
    """
    path = snapshot_path(cache_dir)
    tmp = path.with_suffix(".json.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(snapshot.to_json(), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        # Leave no partial temp file behind to be mistaken for a snapshot. If even
        # the cleanup fails there is nothing further to do -- the CacheError below
        # is the message that matters.
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise CacheError(f"cannot write snapshot to {path}: {exc}") from exc
    return path


def diff_catalog(
    current: tuple[Policy, ...],
    previous: Snapshot | None,
    state: BaselineState | None = None,
) -> CatalogDiff:
    """Compare the current catalog against the previous snapshot.

    Args:
        current: The catalog just loaded.
        previous: The baseline, or ``None`` if there is not a usable one.
        state: Why ``previous`` is absent, from :func:`load_snapshot`. Defaults to
            ``ABSENT`` when omitted, which keeps the two-argument call meaningful
            for callers that never had a file to begin with.
    """
    if previous is None:
        resolved = state if state is not None else BaselineState.ABSENT
        if resolved is BaselineState.PRESENT:
            raise ValueError("state=PRESENT requires a snapshot")
        return CatalogDiff(baseline=resolved, total=len(current))

    now = {p.policy_id: p for p in current}
    before = {p.policy_id: p for p in previous.policies}

    added = tuple(now[k] for k in sorted(now.keys() - before.keys()))
    removed = tuple(before[k] for k in sorted(before.keys() - now.keys()))
    renamed = tuple(
        (k, before[k].title, now[k].title)
        for k in sorted(now.keys() & before.keys())
        if before[k].title != now[k].title
    )
    return CatalogDiff(
        baseline=BaselineState.PRESENT,
        added=added,
        removed=removed,
        renamed=renamed,
        total=len(current),
    )


__all__ = [
    "SNAPSHOT_VERSION",
    "BaselineState",
    "CacheError",
    "CatalogDiff",
    "Snapshot",
    "default_cache_dir",
    "diff_catalog",
    "load_snapshot",
    "save_snapshot",
    "snapshot_path",
]
