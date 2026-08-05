"""Decide how remediations are split across output files.

A single combined output file is wrong, not merely inconvenient. The reason is
that neither output format can target more than one AWS account at a time:

* **The ``aws`` CLI script inherits the caller's ambient credentials.** It carries
  ``--region`` per command but no ``--profile``, so a script spanning two accounts
  cannot be run: with ``set -euo pipefail`` it stops at the first resource that is
  not in the caller's account.
* **The AWS Terraform/OpenTofu provider is scoped to one account and one region.**
  An ``import`` block naming a resource in a different account either fails to find
  it or -- the dangerous case -- finds a *same-named* resource in the provider's
  account and adopts and reconfigures that one instead. Silently remediating the
  wrong resource is the worst outcome this tool could produce.

So the split is derived from what each format can address, and only then adjusted
for how much a human can review.

Boundary rules
--------------

**Hard boundaries. Never merged, regardless of size, because merging is wrong:**

===========  ==========================  ===================================
Format       Hard boundary               Why
===========  ==========================  ===================================
``aws`` CLI  account                     one credential set per script
HCL          account **and** region      provider is account+region scoped
===========  ==========================  ===================================

**Soft boundaries. Applied only when a file would be too large to review:**

* ``aws`` CLI: split by region next. ``--region`` travels on every command, so a
  single-account script spanning regions is correct -- this split is purely about
  file size, which is why it is conditional.
* Both formats: after the boundaries above, split into numbered parts.

The asymmetry is the point: region is a hard boundary for HCL and a soft one for
the CLI, because the two formats carry region differently. Encoding that as a
size heuristic for both would either emit unrunnable HCL or fragment CLI scripts
for no reason.

Everything here is pure: it decides file names and grouping and touches no
filesystem, so the layout is unit-testable without writing anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from remgen.model import Finding, Recipe

#: Default maximum remediations per output file. Chosen for reviewability rather
#: than any technical limit: at roughly 1 KB per remediation this keeps a file
#: near half a megabyte, which is greppable and diffable. Tunable via the CLI,
#: because what is reviewable depends on whether a human or a pipeline reads it.
DEFAULT_MAX_PER_FILE = 500

#: Below this, splitting a single-account CLI script by region creates more files
#: than it saves review effort, so region stays merged.
_CLI_REGION_SPLIT_THRESHOLD = DEFAULT_MAX_PER_FILE


class Format(str, Enum):
    """An output format, which determines the hard boundaries that apply."""

    #: ``aws`` CLI shell script. Account is a hard boundary; region is soft.
    AWSCLI = "awscli"
    #: OpenTofu/Terraform HCL. Account *and* region are hard boundaries.
    HCL = "hcl"

    @property
    def region_is_hard_boundary(self) -> bool:
        """True when a file may not span regions.

        HCL cannot, because the provider is region-scoped and the generated file
        declares no provider aliases. A CLI script can, because every command
        carries its own ``--region``.
        """
        return self is Format.HCL

    @property
    def extension(self) -> str:
        return ".sh" if self is Format.AWSCLI else ".tf"


@dataclass(frozen=True)
class OutputUnit:
    """One output file: its scope, its contents, and its name.

    Attributes:
        fmt: Which format this file is rendered in.
        account_id: The single account every finding in this file belongs to.
        region: The single region, or ``None`` when the file intentionally spans
            regions (only possible for the CLI format).
        part: 1-based part number when a scope was split for size, else ``None``.
        total_parts: How many parts the scope was split into, for the filename.
        pairs: The remediations to render into this file.
    """

    fmt: Format
    account_id: str
    region: str | None
    part: int | None
    total_parts: int
    pairs: tuple[tuple[Recipe, Finding], ...]

    @property
    def filename(self) -> str:
        """Return a filename encoding the scope, so it is obvious how to run it.

        The account and region are in the name deliberately: an operator running
        these needs to select credentials per file, and a name like
        ``remediate-111111111111-us-east-1.sh`` states the requirement where it
        will actually be read.
        """
        bits = ["remediate", self.account_id]
        if self.region is not None:
            bits.append(self.region)
        else:
            bits.append("all-regions")
        if self.part is not None:
            bits.append(f"part{self.part}of{self.total_parts}")
        return "-".join(bits) + self.fmt.extension

    @property
    def scope_description(self) -> str:
        """Human-readable scope, for the file header and the manifest."""
        region = self.region if self.region is not None else "all regions"
        part = (
            f", part {self.part} of {self.total_parts}" if self.part is not None else ""
        )
        return f"account {self.account_id}, {region}{part}"


def _sort_key(pair: tuple[Recipe, Finding]) -> tuple:
    """Order remediations deterministically within a file."""
    recipe, finding = pair
    return (recipe.policy_title, recipe.policy_id, finding.region, finding.resource_id)


def _chunk(
    pairs: list[tuple[Recipe, Finding]], max_per_file: int
) -> list[list[tuple[Recipe, Finding]]]:
    """Split ``pairs`` into runs of at most ``max_per_file``."""
    if max_per_file <= 0 or len(pairs) <= max_per_file:
        return [pairs]
    return [pairs[i : i + max_per_file] for i in range(0, len(pairs), max_per_file)]


def plan_units(
    pairs: list[tuple[Recipe, Finding]],
    fmt: Format,
    *,
    max_per_file: int = DEFAULT_MAX_PER_FILE,
) -> list[OutputUnit]:
    """Group remediations into the files they should be written to.

    Applies the hard boundaries for ``fmt`` first, then the soft ones only if a
    resulting group is still larger than ``max_per_file``.

    Args:
        pairs: The remediations to lay out.
        fmt: Output format, which decides whether region is a hard boundary.
        max_per_file: Soft cap per file. Set to ``0`` to disable size-based
            splitting entirely; the hard boundaries still apply, because those are
            correctness rules and not preferences.

    Returns:
        Output units in a deterministic order, each scoped to one account (and,
        for HCL, one region). Empty when ``pairs`` is empty.
    """
    if not pairs:
        return []

    # Hard boundary 1: account, for both formats.
    by_account: dict[str, list[tuple[Recipe, Finding]]] = {}
    for pair in pairs:
        by_account.setdefault(pair[1].account_id, []).append(pair)

    units: list[OutputUnit] = []
    for account_id in sorted(by_account):
        account_pairs = by_account[account_id]

        # Hard boundary 2: region, for HCL only. For the CLI this is a soft
        # boundary, applied below and only when the script is large.
        split_by_region = fmt.region_is_hard_boundary or (
            max_per_file > 0 and len(account_pairs) > _CLI_REGION_SPLIT_THRESHOLD
        )

        if split_by_region:
            by_region: dict[str, list[tuple[Recipe, Finding]]] = {}
            for pair in account_pairs:
                by_region.setdefault(pair[1].region, []).append(pair)
            groups = [(region, by_region[region]) for region in sorted(by_region)]
        else:
            groups = [(None, account_pairs)]

        for region, group in groups:
            ordered = sorted(group, key=_sort_key)
            chunks = _chunk(ordered, max_per_file)
            total = len(chunks)
            for index, chunk in enumerate(chunks, start=1):
                units.append(
                    OutputUnit(
                        fmt=fmt,
                        account_id=account_id,
                        region=region,
                        part=index if total > 1 else None,
                        total_parts=total,
                        pairs=tuple(chunk),
                    )
                )
    return units


def describe_layout(units: list[OutputUnit]) -> list[str]:
    """Explain the split, so the operator knows why they got several files.

    A directory that silently contains 40 files reads as a bug. Stating the rule
    that produced them, and the credential requirement they imply, is the
    difference between a split that helps and one that confuses.
    """
    if not units:
        return []
    accounts = {u.account_id for u in units}
    fmt = units[0].fmt
    lines = [
        f"  {len(units)} {fmt.extension} file(s) across {len(accounts)} account(s).",
    ]
    if len(units) > 1:
        lines.append(
            "  Split by account because neither format can target more than one "
            "account at a time."
        )
        if fmt.region_is_hard_boundary:
            lines.append(
                "  Split by region because the AWS provider is region-scoped."
            )
        if any(u.part is not None for u in units):
            lines.append(
                "  Large scopes were split into numbered parts for reviewability; "
                "run the parts of a scope in order."
            )
        lines.append(
            "  Each file must be run with credentials for the account in its name."
        )
    return lines


__all__ = [
    "DEFAULT_MAX_PER_FILE",
    "Format",
    "OutputUnit",
    "describe_layout",
    "plan_units",
]
