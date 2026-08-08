"""Shared rendering helpers.

The important function here is :func:`render_template`. Every placeholder that
reaches a generator is filled from a :class:`~remgen.core.model.Finding`, whose fields
are allowlist-validated at construction. This module adds a second, independent
guard: it refuses to substitute a value that is not on the allowlist, even if a
caller managed to construct a Finding some other way.

Two checks for the same property is deliberate. Injection into generated
infrastructure code is the highest-consequence failure this tool could have, and
validation at the boundary plus validation at the point of use means a single
missed code path is not sufficient to produce a bad artifact.
"""

from __future__ import annotations

import string
import textwrap
from collections.abc import Sequence

from remgen.core.model import (
    Finding,
    Recipe,
    SafetyTier,
    UnsafeIdentifierError,
    validate_identifier,
)

#: Prefix marking a caveat that must be read before the command below it runs. Two
#: characters and no letters, so it survives being scanned rather than read, and so
#: `comment_block` can recognise it when hanging continuation lines.
CRITICAL_CAVEAT_MARKER = "!! "

#: Placeholders a template may reference, mapped to the Finding attribute used.
_ALLOWED_FIELDS = {
    "resource_id": "resource_id",
    "region": "region",
    "account_id": "account_id",
    "resource_name": "resource_name",
    "policy_id": "policy_id",
}


class TemplateError(ValueError):
    """Raised when a template references something it may not."""


def template_fields(template: str) -> tuple[str, ...]:
    """Return the placeholder names referenced by ``template``.

    Raises:
        TemplateError: If the template is not parseable as a format string, or
            uses positional/attribute/index access rather than plain names.
    """
    try:
        parsed = list(string.Formatter().parse(template))
    except ValueError as exc:
        raise TemplateError(f"malformed template {template!r}: {exc}") from exc

    names: list[str] = []
    for _literal, field_name, _spec, _conv in parsed:
        if field_name is None:
            continue
        if field_name == "" or not field_name.isidentifier():
            # Rejects "{}", "{0}", "{a.b}", "{a[0]}" -- none are legitimate here
            # and attribute access on a Finding could reach beyond the allowlist.
            raise TemplateError(
                f"template {template!r} uses unsupported placeholder {field_name!r}; "
                f"only plain named fields are allowed"
            )
        names.append(field_name)
    return tuple(names)


def render_template(template: str, finding: Finding) -> str:
    """Fill ``template`` from ``finding``, re-validating every value.

    Raises:
        TemplateError: If the template references a field that is not allowed,
            or a field the finding does not populate.
        UnsafeIdentifierError: If a value fails allowlist validation.
    """
    values: dict[str, str] = {}
    for name in template_fields(template):
        if name not in _ALLOWED_FIELDS:
            raise TemplateError(
                f"template references {name!r}, which is not an allowed field. "
                f"Allowed: {', '.join(sorted(_ALLOWED_FIELDS))}"
            )
        value = getattr(finding, _ALLOWED_FIELDS[name])
        if not value:
            raise TemplateError(
                f"finding for policy {finding.policy_id} has no {name!r}, but the "
                f"template requires it"
            )
        # Independent re-validation at the point of substitution.
        values[name] = validate_identifier(value, field_name=name)

    try:
        return template.format(**values)
    except (IndexError, KeyError) as exc:  # pragma: no cover - guarded above
        raise TemplateError(f"malformed template {template!r}: {exc}") from exc


def comment_block(lines: list[str], prefix: str = "# ", width: int = 88) -> str:
    """Render ``lines`` as comments, wrapped and with edge blanks trimmed.

    Wrapping matters: caveat text is written as prose in the recipes, and an
    unwrapped 300-character comment is one a reviewer scrolls past rather than
    reads. Leading indentation (used for bullet lists) is preserved on
    continuation lines so wrapped bullets stay visually attached.
    """
    lines = list(lines)
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()

    out: list[str] = []
    body = max(width - len(prefix), 20)
    for line in lines:
        if not line.strip():
            out.append("")
            continue
        stripped = line.lstrip()
        # Never wrap a line containing a URL: a split URL is not clickable and
        # not copyable, which defeats the point of including it. Overrunning the
        # target width is the lesser evil.
        if "://" in stripped:
            out.append(line)
            continue
        indent = line[: len(line) - len(stripped)]
        # Continuation lines of a marked line align past its marker, so a wrapped
        # bullet or critical caveat stays visually attached to the one it belongs to.
        # Without the hang, a five-line caveat's tail is indistinguishable from the
        # unmarked notes below it, which is precisely the line that must stand out.
        hang = indent
        for marker in ("- ", CRITICAL_CAVEAT_MARKER):
            if stripped.startswith(marker):
                hang = indent + " " * len(marker)
                break
        wrapped = textwrap.wrap(
            stripped,
            width=body,
            initial_indent=indent,
            subsequent_indent=hang,
            break_long_words=False,
            break_on_hyphens=False,
        )
        out.extend(wrapped or [indent])
    return "\n".join(f"{prefix}{line}".rstrip() for line in out)


def group_by_policy(
    pairs: list[tuple[Recipe, Finding]],
) -> list[tuple[Recipe, list[Finding]]]:
    """Group findings under their recipe, preserving first-seen order.

    Both generators emit a recipe's description, safety notes and caveats once per
    policy rather than once per resource -- repeating them per finding is what made
    comments roughly 85% of the output. Grouping is what lets that text be hoisted,
    so it lives here rather than in either generator.

    Order is first-seen rather than sorted, so the caller's tier and scope ordering
    is preserved and output stays deterministic.
    """
    grouped: dict[str, tuple[Recipe, list[Finding]]] = {}
    for recipe, finding in pairs:
        entry = grouped.get(recipe.policy_id)
        if entry is None:
            grouped[recipe.policy_id] = (recipe, [finding])
        else:
            entry[1].append(finding)
    return list(grouped.values())


def tier_banner(tier: SafetyTier) -> str:
    """Return a section banner for a safety tier.

    Shared rather than per-format because the wording *is* the safety
    classification, and two generators describing the same tier differently would
    make the tiers look like presentation rather than a rule.
    """
    label = {
        SafetyTier.SAFEST: ("SAFEST -- reversible, no data-path impact, no usage-scaled cost"),
        SafetyTier.CAUTION: ("CAUTION -- sound, but carries a commitment. Read each note."),
        SafetyTier.DISRUPTIVE: (
            "DISRUPTIVE -- can affect availability or requires replacement. "
            "Review individually; do not run unattended."
        ),
    }[tier]
    bar = "=" * 74
    return f"# {bar}\n# {label}\n# {bar}"


def critical_caveat_lines(caveats: Sequence[str]) -> list[str]:
    """Prefix each critical caveat so it is distinguishable from description.

    A marker rather than a heading: :func:`comment_block` wraps prose to the comment
    width, and a heading followed by wrapped paragraphs puts the marker several lines
    above the sentence that matters. Prefixing each caveat keeps the signal attached
    to its own text, and the leading indent means continuation lines stay visually
    under the marker instead of aligning with ordinary notes.

    Shared so the shell generators, the HCL generator and the merged-block path all
    mark them identically. Three formats inventing three markers is how a reader
    learns to ignore one of them.
    """
    out: list[str] = []
    for caveat in caveats:
        out.append(f"{CRITICAL_CAVEAT_MARKER}{caveat}")
    return out


def recipe_notes(recipe: Recipe, *, count: int | None = None) -> list[str]:
    """Return the comment lines that describe a recipe, independent of any finding.

    Emitted once per policy rather than once per resource: every line here is
    identical for all of that policy's findings. Cloud-neutral -- it reads only
    :class:`~remgen.core.model.Recipe` fields -- so both the HCL generator in
    ``core`` and each provider's shell generator render the same text from it. Two
    formats writing their own version of a safety warning is how the two come to
    disagree about what a change costs.

    Args:
        recipe: The recipe to describe.
        count: How many resources this group covers, when known.

    What is included here and what is not is decided by consequence, not by length.
    Safety notes state what a change costs, whether it can be undone, and whether it
    affects live traffic; someone reading a command must see those without leaving
    the file, so they stay inline. The reference material -- summary, prerequisites,
    caveats, documentation link -- answers "what is this policy and why". It is
    identical for every occurrence, so a run spanning many scopes would repeat it
    hundreds of times; it is written once in the run's README instead, and the
    pointer below is what makes that a relocation rather than an omission.

    ``critical_caveats`` is the exception, and it exists because that split has one
    blind spot. Safety notes are derived from four structured fields, so a warning
    the fields cannot express has no way to reach the artifact and lands in the
    README with the reference material -- under a banner that may well read SAFEST.
    S3 Block Public Access is exactly that: reversible, free, in-place, and it stops
    anonymous reads the instant it applies. Those lines are rendered here, prefixed
    so they read as a stop sign rather than as more description.
    """
    notes: list[str] = [f"POLICY: {recipe.policy_title}", f"Policy ID: {recipe.policy_id}"]
    if count is not None:
        notes.append(f"Resources: {count}")
    if recipe.critical_caveats:
        notes.append("")
        notes.extend(critical_caveat_lines(recipe.critical_caveats))
    if recipe.safety_notes:
        notes.append("")
        notes.extend(recipe.safety_notes)
    notes.append("Summary, caveats and docs: see README.md")
    return notes


__all__ = [
    "CRITICAL_CAVEAT_MARKER",
    "TemplateError",
    "UnsafeIdentifierError",
    "comment_block",
    "critical_caveat_lines",
    "group_by_policy",
    "recipe_notes",
    "render_template",
    "template_fields",
    "tier_banner",
]
