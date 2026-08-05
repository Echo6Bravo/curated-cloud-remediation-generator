"""Input adapters: where policies and findings come from.

One interface, two implementations in v1:

* :class:`JsonFileSource` -- reads a JSON export. This is the offline path and
  the one the test suite exercises. It makes the whole tool runnable, reviewable
  and testable with no Tenable tenant and no AWS credentials.
* :class:`InMemorySource` -- used by tests and by callers that already hold data.

A live Tenable Cloud Security API adapter is deliberately not implemented here.
Doing it properly needs tenant credentials to verify against, and an adapter that
has never run against a real tenant would be untested code wearing the costume of
a feature. The interface below is what it would implement. See ROADMAP.md.

Input is treated as untrusted throughout: every record is validated, and a record
that fails validation is collected as a rejection rather than silently dropped, so
the count always reconciles.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from remgen.model import Finding, Policy, UnsafeIdentifierError

#: Keys accepted for each Finding field, in priority order. Real exports differ
#: in casing and naming between API versions and CSV/JSON paths, so a small
#: alias table is more useful than demanding one exact shape.
_FINDING_ALIASES: dict[str, tuple[str, ...]] = {
    "policy_id": ("policy_id", "policyId", "PolicyId", "policyID", "id"),
    "resource_id": (
        "resource_id",
        "resourceId",
        "ResourceId",
        "EntityProviderRawId",
        "provider_id",
        "arn",
    ),
    "region": ("region", "Region", "location"),
    "account_id": ("account_id", "accountId", "AccountId", "account", "subscription_id"),
    "resource_name": ("resource_name", "resourceName", "ResourceName", "name", "Name"),
}

_POLICY_ALIASES: dict[str, tuple[str, ...]] = {
    "policy_id": ("policy_id", "policyId", "PolicyId", "id", "Id"),
    "title": ("title", "Title", "name", "Name", "RiskPolicyTitle"),
    "category": ("category", "Category", "RiskPolicyCategory"),
}


class SourceError(RuntimeError):
    """Raised when an input source cannot be read at all."""


@dataclass(frozen=True)
class Rejection:
    """A record that could not be used, and why.

    Rejections are reported, never swallowed. A finding dropped in silence looks
    identical to a finding that was already compliant.
    """

    index: int
    reason: str
    raw: str = ""


@dataclass(frozen=True)
class LoadResult:
    """Everything an adapter produced, including what it could not use."""

    policies: tuple[Policy, ...] = ()
    findings: tuple[Finding, ...] = ()
    rejections: tuple[Rejection, ...] = ()


class Source(Protocol):
    """Where policies and findings come from."""

    def load(self) -> LoadResult:
        """Return policies, findings and any rejected records."""
        ...


def _pick(record: dict, aliases: tuple[str, ...]) -> str:
    """Return the first aliased key present and non-empty, else ``""``."""
    for key in aliases:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        # Account IDs are frequently numeric in JSON exports.
        if isinstance(value, int):
            return str(value)
    return ""


def _truncate(value: object, limit: int = 120) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def parse_findings(records: list) -> tuple[tuple[Finding, ...], tuple[Rejection, ...]]:
    """Convert raw records into validated findings, collecting rejections."""
    findings: list[Finding] = []
    rejections: list[Rejection] = []
    for i, record in enumerate(records):
        if not isinstance(record, dict):
            rejections.append(
                Rejection(index=i, reason="not a JSON object", raw=_truncate(record))
            )
            continue
        values = {f: _pick(record, a) for f, a in _FINDING_ALIASES.items()}
        missing = [
            f for f in ("policy_id", "resource_id", "region", "account_id") if not values[f]
        ]
        if missing:
            rejections.append(
                Rejection(
                    index=i,
                    reason=f"missing required field(s): {', '.join(missing)}",
                    raw=_truncate(record),
                )
            )
            continue
        try:
            findings.append(Finding(**values))
        except (UnsafeIdentifierError, ValueError) as exc:
            rejections.append(Rejection(index=i, reason=str(exc), raw=_truncate(record)))
    return tuple(findings), tuple(rejections)


def parse_policies(records: list) -> tuple[tuple[Policy, ...], tuple[Rejection, ...]]:
    """Convert raw records into policies, collecting rejections."""
    policies: list[Policy] = []
    rejections: list[Rejection] = []
    seen: set[str] = set()
    for i, record in enumerate(records):
        if not isinstance(record, dict):
            rejections.append(
                Rejection(index=i, reason="not a JSON object", raw=_truncate(record))
            )
            continue
        values = {f: _pick(record, a) for f, a in _POLICY_ALIASES.items()}
        if not values["policy_id"]:
            rejections.append(
                Rejection(index=i, reason="missing policy id", raw=_truncate(record))
            )
            continue
        if values["policy_id"] in seen:
            rejections.append(
                Rejection(
                    index=i,
                    reason=f"duplicate policy id {values['policy_id']}",
                    raw=_truncate(record),
                )
            )
            continue
        seen.add(values["policy_id"])
        policies.append(Policy(**values))
    return tuple(policies), tuple(rejections)


class JsonFileSource:
    """Load policies and/or findings from JSON files.

    Accepts either a bare JSON array, or an object with ``policies`` /
    ``findings`` keys. Both file arguments are optional so the tool is useful
    with only a policy catalog (to run ``policies``/``verify``) or only findings.
    """

    def __init__(
        self,
        *,
        findings_path: Path | None = None,
        policies_path: Path | None = None,
    ) -> None:
        self.findings_path = findings_path
        self.policies_path = policies_path

    @staticmethod
    def _read(path: Path, key: str) -> list:
        """Read a JSON file and return the relevant list of records."""
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise SourceError(f"cannot read {path}: {exc}") from exc
        except ValueError as exc:
            raise SourceError(f"{path} is not valid JSON: {exc}") from exc

        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for candidate in (key, "items", "data", "results"):
                if isinstance(payload.get(candidate), list):
                    return payload[candidate]
        raise SourceError(
            f"{path}: expected a JSON array, or an object with a {key!r} array"
        )

    def load(self) -> LoadResult:
        policies: tuple[Policy, ...] = ()
        findings: tuple[Finding, ...] = ()
        rejections: list[Rejection] = []

        if self.policies_path is not None:
            policies, rej = parse_policies(self._read(self.policies_path, "policies"))
            rejections.extend(rej)
        if self.findings_path is not None:
            findings, rej = parse_findings(self._read(self.findings_path, "findings"))
            rejections.extend(rej)
        return LoadResult(policies=policies, findings=findings, rejections=tuple(rejections))


@dataclass(frozen=True)
class InMemorySource:
    """A source backed by already-constructed objects. Used by tests."""

    policies: tuple[Policy, ...] = ()
    findings: tuple[Finding, ...] = ()

    def load(self) -> LoadResult:
        return LoadResult(policies=self.policies, findings=self.findings)


__all__ = [
    "InMemorySource",
    "JsonFileSource",
    "LoadResult",
    "Rejection",
    "Source",
    "SourceError",
    "parse_findings",
    "parse_policies",
]
