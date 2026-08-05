"""Shared rendering helpers.

The important function here is :func:`render_template`. Every placeholder that
reaches a generator is filled from a :class:`~remgen.model.Finding`, whose fields
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

from remgen.model import Finding, Recipe, UnsafeIdentifierError, validate_identifier

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
        # Continuation lines of a bullet align past the "- " marker.
        hang = indent + ("  " if stripped.startswith("- ") else "")
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


__all__ = [
    "TemplateError",
    "UnsafeIdentifierError",
    "comment_block",
    "group_by_policy",
    "render_template",
    "template_fields",
]
