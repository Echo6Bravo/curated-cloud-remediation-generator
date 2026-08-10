"""Decide how remediations are split across output files.

A single combined output file is wrong, not merely inconvenient. The reason is
that no output format can target more than one credential scope at a time:

* **A CLI script inherits the caller's ambient credentials.** It carries a region
  per command but no profile, so a script spanning two accounts cannot be run:
  with ``set -euo pipefail`` it stops at the first resource that is not in the
  caller's account.
* **A Terraform/OpenTofu provider configuration is scoped to one credential set.**
  An ``import`` block naming a resource in a different account either fails to
  find it or -- the dangerous case -- finds a *same-named* resource in the
  provider's account and adopts and reconfigures that one instead. Silently
  remediating the wrong resource is the worst outcome this tool could produce.

So the split is derived from what each format can address, and only then adjusted
for how much a human can review.

Boundary rules
--------------

**Hard boundaries. Never merged, regardless of size, because merging is wrong:**

===========  ==================================  ===============================
Format       Hard boundary                       Why
===========  ==================================  ===============================
CLI script   cloud, credential scope             one credential set per script
HCL          cloud, credential scope, *region*   see below
===========  ==================================  ===============================

**Cloud is a hard boundary for both formats, and the outermost one.** A shell
script invokes one vendor CLI (``aws``, ``az``, ``gcloud``, ``oci``) and
authenticates to one vendor; a ``.tf`` file's provider block names one provider.
Beyond correctness, an operator applying remediations does so with one cloud's
credentials in one sitting, so the cloud is also the split they would make by
hand. Output is therefore written under ``<out>/<cloud>/`` and the cloud appears
in every filename.

**Whether region is hard depends on the provider, so it is data, not an
assumption.** ``hashicorp/aws`` binds a region to the provider configuration, so
a ``.tf`` file must not span regions. ``azurerm`` takes ``location`` per resource,
so the same rule would fragment Azure output into many files without making any
of them more correct. :class:`~remgen.core.provider.Provider` declares which
applies, and :class:`Format` is asked with that answer in hand rather than
hard-coding AWS's.

**Soft boundaries. Applied only when a file would be too large to review:**

* **Region, wherever it is not already a hard boundary.** That is the CLI on every
  cloud, and *also HCL on a cloud whose provider is not region-scoped* -- Azure
  reaches this path, because ``azurerm`` carries ``location`` per resource. The
  region travels with each remediation in both of those cases, so a single-scope
  file spanning regions is correct; the split is purely about file size, which is
  why it is conditional on :data:`_CLI_REGION_SPLIT_THRESHOLD`.
* Both formats: after the boundaries above, split into numbered parts.

The asymmetry is the point: region can be a hard boundary for HCL and a soft one
for the CLI, because the two formats carry region differently. Encoding that as a
size heuristic for both would either emit unrunnable HCL or fragment CLI scripts
for no reason.

**A consequence worth stating, because getting it wrong shipped a false claim:**
the same region split has two possible causes, and the units cannot tell them
apart -- an HCL file holding one region looks identical whether the provider
forced it or volume triggered it. Only the provider's scoping distinguishes them,
which is why :func:`describe_layout` *requires* that fact rather than defaulting
it. Before this was fixed, a volume-triggered Azure split was explained as
"this cloud's Terraform provider is region-scoped", which is false for
``azurerm``.

Everything here is pure: it decides file names and grouping and touches no
filesystem, so the layout is unit-testable without writing anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from remgen.core.model import Finding, Recipe

#: Default maximum remediations per output file. Chosen for reviewability rather
#: than any technical limit: at roughly 1 KB per remediation this keeps a file
#: near half a megabyte, which is greppable and diffable. Tunable via the CLI,
#: because what is reviewable depends on whether a human or a pipeline reads it.
DEFAULT_MAX_PER_FILE = 500

#: Below this, splitting a single-scope CLI script by region creates more files
#: than it saves review effort, so region stays merged.
_CLI_REGION_SPLIT_THRESHOLD = DEFAULT_MAX_PER_FILE


class Format(str, Enum):
    """An output format, which determines the hard boundaries that apply."""

    #: Vendor CLI shell script. Cloud and credential scope are hard boundaries;
    #: region is soft.
    CLI = "cli"
    #: OpenTofu/Terraform HCL. Cloud and credential scope are hard boundaries, and
    #: region is too when the cloud's provider is region-scoped.
    HCL = "hcl"

    def region_is_hard_boundary(self, *, provider_is_region_scoped: bool) -> bool:
        """True when a file of this format may not span regions.

        Takes the provider's scoping as an argument rather than assuming it. HCL
        cannot span regions when one provider configuration covers one region --
        true for ``hashicorp/aws``, false for ``azurerm``. A CLI script never has
        this constraint, because every command carries its own region.
        """
        return self is Format.HCL and provider_is_region_scoped


@dataclass(frozen=True)
class OutputUnit:
    """One output file: its scope, its contents, and its name.

    Attributes:
        fmt: Which format this file is rendered in.
        cloud: The cloud every finding in this file belongs to, e.g. ``"aws"``.
        scope_id: The single credential scope every finding belongs to -- an AWS
            account id, an Azure subscription id. Named for what it *is* rather
            than for one cloud's word for it, because the split rule is the same
            in every cloud: one credential set per file.
        region: The single region, or ``None`` when the file intentionally spans
            regions (only possible when region is a soft boundary).
        part: 1-based part number when a scope was split for size, else ``None``.
        total_parts: How many parts the scope was split into, for the filename.
        pairs: The remediations to render into this file.
        extension: Filename extension, supplied by the provider for CLI scripts.
        scope_noun: What ``scope_id`` is called in this cloud ("account",
            "subscription"). Used in the human-readable scope description, so a
            correct split is not described in the wrong cloud's vocabulary.
    """

    fmt: Format
    cloud: str
    scope_id: str
    region: str | None
    part: int | None
    total_parts: int
    pairs: tuple[tuple[Recipe, Finding], ...]
    extension: str = ".sh"
    scope_noun: str = "account"

    @property
    def filename(self) -> str:
        """Return a filename encoding the scope, so it is obvious how to run it.

        The cloud, the credential scope and the region are all in the name
        deliberately: whoever runs these has to select the right vendor CLI *and*
        the right credentials per file, and a name like
        ``remediate-aws-111111111111-us-east-1.sh`` states both requirements where
        they will actually be read. Files are also written under a per-cloud
        directory, but names have to survive being copied out of it.
        """
        bits = ["remediate", self.cloud, self.scope_id]
        if self.region is not None:
            bits.append(self.region)
        else:
            bits.append("all-regions")
        if self.part is not None:
            bits.append(f"part{self.part}of{self.total_parts}")
        ext = self.extension if self.fmt is Format.CLI else ".tf"
        return "-".join(bits) + ext

    @property
    def relative_path(self) -> str:
        """Return the path under the output directory, including the cloud segment.

        Cloud is a directory rather than only a filename prefix so that a run over
        several clouds produces a tree an operator can hand to the right team, and
        so that listing one cloud's directory is a complete inventory of what that
        cloud's credentials apply to.
        """
        return f"{self.cloud}/{self.filename}"

    @property
    def scope_description(self) -> str:
        """Human-readable scope, for the file header and the manifest."""
        region = self.region if self.region is not None else "all regions"
        part = f", part {self.part} of {self.total_parts}" if self.part is not None else ""
        return f"{self.cloud} {self.scope_noun} {self.scope_id}, {region}{part}"


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
    cloud: str,
    max_per_file: int = DEFAULT_MAX_PER_FILE,
    provider_is_region_scoped: bool = True,
    extension: str = ".sh",
    scope_noun: str = "account",
) -> list[OutputUnit]:
    """Group remediations into the files they should be written to.

    Applies the hard boundaries for ``fmt`` first, then the soft ones only if a
    resulting group is still larger than ``max_per_file``.

    Args:
        pairs: The remediations to lay out.
        fmt: Output format, which decides whether region can be a hard boundary.
        cloud: The cloud these remediations target. Every unit returned carries it,
            and it becomes the output subdirectory. Callers pass one cloud's pairs
            at a time -- cloud is a hard boundary, so mixing them in one call would
            be asking this function to undo the split it exists to make.
        max_per_file: Soft cap per file. Set to ``0`` to disable size-based
            splitting entirely; the hard boundaries still apply, because those are
            correctness rules and not preferences.
        provider_is_region_scoped: Whether this cloud's Terraform provider covers
            one region, making region a hard boundary for HCL.
        extension: Filename extension for CLI scripts.
        scope_noun: This cloud's word for the credential scope.

    Returns:
        Output units in a deterministic order, each scoped to one cloud and one
        credential scope (and, when the provider requires it, one region). Empty
        when ``pairs`` is empty.
    """
    if not pairs:
        return []

    # Hard boundary 1: credential scope, for every format. (Cloud is boundary 0 and
    # is enforced by the caller passing one cloud's pairs per call; it is carried
    # into every unit below.)
    by_scope: dict[str, list[tuple[Recipe, Finding]]] = {}
    for pair in pairs:
        by_scope.setdefault(pair[1].account_id, []).append(pair)

    units: list[OutputUnit] = []
    for scope_id in sorted(by_scope):
        scope_pairs = by_scope[scope_id]

        # Hard boundary 2: region, for HCL when the provider is region-scoped. For
        # the CLI this is a soft boundary, applied below and only when the script
        # is large.
        split_by_region = fmt.region_is_hard_boundary(
            provider_is_region_scoped=provider_is_region_scoped
        ) or (max_per_file > 0 and len(scope_pairs) > _CLI_REGION_SPLIT_THRESHOLD)

        if split_by_region:
            by_region: dict[str, list[tuple[Recipe, Finding]]] = {}
            for pair in scope_pairs:
                by_region.setdefault(pair[1].region, []).append(pair)
            groups = [(region, by_region[region]) for region in sorted(by_region)]
        else:
            groups = [(None, scope_pairs)]

        for region, group in groups:
            ordered = sorted(group, key=_sort_key)
            chunks = _chunk(ordered, max_per_file)
            total = len(chunks)
            for index, chunk in enumerate(chunks, start=1):
                units.append(
                    OutputUnit(
                        fmt=fmt,
                        cloud=cloud,
                        scope_id=scope_id,
                        region=region,
                        part=index if total > 1 else None,
                        total_parts=total,
                        pairs=tuple(chunk),
                        extension=extension,
                        scope_noun=scope_noun,
                    )
                )
    return units


def describe_layout(units: list[OutputUnit], *, provider_is_region_scoped: bool) -> list[str]:
    """Explain the split, so the operator knows why they got several files.

    A directory that silently contains 40 files reads as a bug. Stating the rule
    that produced them, and the credential requirement they imply, is the
    difference between a split that helps and one that confuses.

    **Each sentence is emitted only when that split actually happened**, and each is
    derived from the units rather than from the file count. An earlier version keyed
    every sentence off ``len(units) > 1``, which made all four claims wrong in
    ordinary cases: one account split across two regions was reported as "split by
    account", a single scope chunked into parts was reported as split by account
    *and* by region, and -- the one that matters most -- a volume-triggered region
    split on Azure was explained as "this cloud's Terraform provider is
    region-scoped", which is **false for azurerm**. An explanation a reader can
    check and find wrong is worse than none, because it teaches them the tool's
    stated reasons are decorative.

    Args:
        units: The planned output units. Whether a split happened is read off these:
            a cloud split shows up as more than one cloud, a scope split as more than
            one scope, a region split as more than one region *within a single scope*
            (two single-region scopes are a scope split, not a region split), and a
            size split as a non-``None`` ``part``.
        provider_is_region_scoped: Whether this cloud's Terraform provider covers one
            region. Needed because it is the one thing the units cannot reveal: a
            region split looks identical whether it was forced by the provider or
            triggered by volume, and those get different sentences because only the
            first is a correctness requirement. Passed to
            :meth:`Format.region_is_hard_boundary` rather than reasoned about here,
            so this function and the planner cannot disagree about the same rule.

            **Required, unlike the same parameter on** :func:`plan_units`, which
            defaults it to ``True``. The defaults would have to point in opposite
            directions to be safe, so there is no honest shared one. Planning
            defensively means assuming region-scoped: over-splitting produces more
            files than necessary, while under-splitting emits HCL that adopts a
            resource from the wrong region. Describing has no such fallback -- a
            default here does not degrade the explanation, it *asserts* something
            about the provider that may be false, and it is exactly the caller who
            forgets to pass it who gets the wrong sentence with no warning.
    """
    if not units:
        return []
    scopes = {u.scope_id for u in units}
    clouds = sorted({u.cloud for u in units})
    first = units[0]
    ext = first.extension if first.fmt is Format.CLI else ".tf"
    noun = first.scope_noun
    plural = noun if noun.endswith("s") else f"{noun}s"
    lines = [
        f"  {len(units)} {ext} file(s) across {len(scopes)} {plural} in {', '.join(clouds)}.",
    ]

    # Per (cloud, scope), because a region split means one credential scope's output
    # went to several files. Two scopes that each hold one region span two regions in
    # total while no region split occurred -- reporting that as one would explain a
    # split the operator can see did not happen.
    regions_per_scope: dict[tuple[str, str], set[str | None]] = {}
    for unit in units:
        regions_per_scope.setdefault((unit.cloud, unit.scope_id), set()).add(unit.region)
    split_by_region = any(len(regions) > 1 for regions in regions_per_scope.values())

    if len(clouds) > 1:
        lines.append("  Split by cloud because each file targets one vendor CLI or provider.")
    if len(scopes) > 1:
        lines.append(
            f"  Split by {noun} because no format can target more than one {noun} at a time."
        )
    if split_by_region:
        if first.fmt.region_is_hard_boundary(provider_is_region_scoped=provider_is_region_scoped):
            lines.append(
                "  Split by region because this cloud's Terraform provider is region-scoped."
            )
        else:
            # The volume-triggered split. Said out loud as a reviewability measure
            # rather than a correctness one, because it is: this format carries its
            # own region, so merging these files would still have been runnable.
            # That also tells the operator the knob exists -- the correctness splits
            # above have no knob, and conflating the two would imply they do.
            lines.append(
                f"  Split by region because this {noun} has more remediations than one "
                f"file should hold.\n  This format carries its own region, so the split "
                f"is for reviewability rather than correctness (see --max-per-file)."
            )
    if any(u.part is not None for u in units):
        lines.append(
            "  Large scopes were split into numbered parts for reviewability; "
            "run the parts of a scope in order."
        )
    if len(units) > 1:
        lines.append(f"  Each file must be run with credentials for the {noun} in its name.")
    return lines


__all__ = [
    "DEFAULT_MAX_PER_FILE",
    "Format",
    "OutputUnit",
    "describe_layout",
    "plan_units",
]
