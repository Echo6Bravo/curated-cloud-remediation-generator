"""Verify a recipe's ``aws`` command against the AWS CLI's own flag surface.

The third drift signal, and the one whose absence was the widest gap. ``drift.py``
checks that the *API* operation and its members exist in ``service-2.json``, but a
generated artifact does not call the API -- it runs ``aws``, whose flag names are a
transformation of the API members that the CLI performs, and which the CLI is free
to change independently. ``dynamodb.UpdateTable`` keeping its
``DeletionProtectionEnabled`` member says nothing about whether
``--deletion-protection-enabled`` is still spelled that way, or still exists on that
subcommand. Nothing checked the string a user actually pastes into a terminal.

Deriving the flag from the member name is the obvious approach and is wrong. It
looks like kebab-casing, and is not: ``DBInstanceIdentifier`` becomes
``--db-instance-identifier``, not ``--d-b-instance-identifier``, and the rule that
produces it lives in ``botocore.xform_name``. Worse, a derived flag would be checked
against a *derivation* rather than against the CLI, so a CLI-side rename -- exactly
the drift this exists to catch -- would be invisible.

So this reads the authoritative source. AWS CLI v2 ships
``awscli/data/ac.index``, the SQLite index behind shell autocompletion. It is the
CLI's own record of every command, subcommand and parameter it accepts, generated at
build time from the same models the parser uses. Its ``param_table`` is queried
read-only:

* Subcommand flags live under ``parent='aws.<service>'``, ``command='<subcommand>'``.
  The service here is the *CLI's* name for it, which is not always the API's:
  ``s3api`` is a CLI-only command group over the S3 API. Recipes name the CLI
  command because that is what they render, so no mapping is needed.
* Global flags such as ``--region`` live under ``parent=''``, ``command='aws'``.
* Booleans carry both polarities as separate rows -- ``deletion-protection-enabled``
  and ``no-deletion-protection-enabled`` -- which is what makes a recipe's
  ``reverse_hint`` checkable too, and that matters: the reverse command is the one a
  user runs in a hurry, having just broken something.

The index is opened ``mode=ro`` through a URI. It is a file inside an installed
package, not user input, but a verification command should not be able to write to
the tool it is verifying, and read-only is one parameter.

As everywhere in verification: no index means ``UNAVAILABLE``, never a pass.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import sqlite3
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path

from remgen.core.model import Recipe

#: Overrides index discovery, for tests and for a CI job that has one at a known path.
INDEX_ENV_VAR = "REMGEN_AWSCLI_AC_INDEX"

#: Flags the CLI accepts everywhere, whatever the subcommand. Read from the index
#: under ``parent=''``; this is only the fallback used when that query returns
#: nothing, so a future index layout change degrades to "known globals are fine"
#: rather than to a flood of false failures on every recipe at once.
_FALLBACK_GLOBALS = frozenset(
    {"region", "profile", "output", "endpoint-url", "no-cli-pager", "cli-input-json"}
)


class FlagStatus(str, Enum):
    """Outcome of checking one recipe's rendered commands."""

    OK = "ok"
    #: The subcommand exists but does not accept a flag the recipe passes. The
    #: generated command fails with "Unknown options".
    FLAG_MISSING = "flag_missing"
    #: The service or subcommand itself is not in the index. Every command the
    #: recipe renders is unrunnable.
    COMMAND_MISSING = "command_missing"
    #: No index available; the check could not run.
    UNAVAILABLE = "unavailable"

    @property
    def is_failure(self) -> bool:
        return self in (FlagStatus.FLAG_MISSING, FlagStatus.COMMAND_MISSING)


@dataclass(frozen=True)
class FlagResult:
    """Result of checking one recipe's CLI commands."""

    policy_id: str
    policy_title: str
    status: FlagStatus
    #: What was checked, e.g. ``"aws dynamodb update-table"``.
    command: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is FlagStatus.OK

    @property
    def checked(self) -> bool:
        return self.status is not FlagStatus.UNAVAILABLE


def find_ac_index() -> Path | None:
    """Locate the AWS CLI v2 autocomplete index, or ``None``.

    Mirrors :func:`remgen.providers.aws.drift.find_model_dir`: an env override first,
    then the installed CLI. Kept separate rather than generalized because the two
    look for different artifacts in differently-shaped locations, and one function
    with a filename parameter would be harder to read than two.
    """
    override = os.environ.get(INDEX_ENV_VAR)
    if override:
        candidate = Path(override).expanduser()
        return candidate if candidate.is_file() else None

    aws_bin = shutil.which("aws")
    if not aws_bin:
        return None
    resolved = Path(aws_bin).resolve()
    for parent in list(resolved.parents)[:5]:
        for pattern in _INDEX_PATTERNS:
            matches = sorted(parent.glob(pattern))
            if matches:
                return matches[-1]
    return None


#: Where ``ac.index`` sits relative to an ancestor of the ``aws`` binary. AWS CLI v2
#: ships in two shapes and both are in normal use, so both are searched:
#: the package install used by Homebrew and pip
#: (``lib/python3.x/site-packages/awscli/data``) and the self-contained PyInstaller
#: bundle from the official installer, which GitHub's runner images use
#: (``dist/awscli/data``). Supporting only the first is how this check would report
#: ``UNAVAILABLE`` on exactly the machine the drift canary runs on -- and
#: ``UNAVAILABLE`` is exit-code-neutral, so the canary would have gone quietly blind.
_INDEX_PATTERNS = (
    "lib/python3*/site-packages/awscli/data/ac.index",
    "dist/awscli/data/ac.index",
    "awscli/data/ac.index",
)


@lru_cache(maxsize=1)
def _load_surface() -> tuple[dict[tuple[str, str], frozenset[str]], frozenset[str], str] | None:
    """Read the whole flag surface once.

    Returns ``({(service, subcommand): flags}, globals, source)``, or ``None`` when
    there is no index. Read in one pass rather than queried per recipe: the file is
    21 MB and reopening it for each of a few dozen recipes is slower than the single
    scan, and it keeps sqlite handling in exactly one place.
    """
    path = find_ac_index()
    if path is None:
        return None
    try:
        # Read-only URI: verification must not be able to write to the CLI it checks.
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        by_command: dict[tuple[str, str], set[str]] = {}
        globals_: set[str] = set()
        for argname, command, parent in conn.execute(
            "SELECT argname, command, parent FROM param_table"
        ):
            if not argname:
                continue
            if parent == "" and command == "aws":
                globals_.add(argname)
            elif isinstance(parent, str) and parent.startswith("aws."):
                # parent is "aws.<service>"; nested groups exist ("aws.s3api") but
                # always carry the service in the last segment.
                service = parent.split(".", 1)[1]
                by_command.setdefault((service, command), set()).add(argname)
    except sqlite3.Error:
        # A malformed or unexpected index is "could not check", not "checked and
        # passed". Returning None routes it to UNAVAILABLE.
        return None
    finally:
        conn.close()

    if not by_command:
        return None
    return (
        {k: frozenset(v) for k, v in by_command.items()},
        frozenset(globals_) or _FALLBACK_GLOBALS,
        str(path),
    )


def index_source_description() -> str:
    """Where the flag surface was read from, for ``verify`` output."""
    surface = _load_surface()
    return surface[2] if surface else "unavailable"


#: A rendered command's leading words: ``aws <service> <subcommand>``. Placeholders
#: like ``{resource_id}`` never appear this early in a template, and a template that
#: put one there would be caught as a missing command rather than silently skipped.
_COMMAND_RE = re.compile(r"^\s*aws\s+([a-z0-9-]+)\s+([a-z0-9-]+)")


def _extract(command: str) -> tuple[str, str, list[str]] | None:
    """Split a rendered command into ``(service, subcommand, flag names)``.

    Returns ``None`` when the string does not start with ``aws <service> <sub>``.
    Flags are returned without their leading dashes and without ``--flag=value``
    values. Parsed with :mod:`shlex` so a quoted argument containing a space is one
    token; a template too malformed to lex is reported as unparseable rather than
    guessed at.
    """
    match = _COMMAND_RE.match(command)
    if not match:
        return None
    service, subcommand = match.group(1), match.group(2)
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    flags = [t.lstrip("-").split("=", 1)[0] for t in tokens if t.startswith("--") and t != "--"]
    return service, subcommand, flags


def verify_recipe_cli(recipe: Recipe) -> FlagResult:
    """Check a recipe's ``cli_template`` and ``reverse_hint`` against the CLI surface.

    Both are checked, because both are rendered into the shell artifact -- the
    reverse command as the documented way to undo the change. A reverse command with
    a stale flag fails at the moment it is most needed.
    """
    surface = _load_surface()
    base = {"policy_id": recipe.policy_id, "policy_title": recipe.policy_title}
    if surface is None:
        return FlagResult(
            **base,
            status=FlagStatus.UNAVAILABLE,
            command=recipe.cli_template.split("{", 1)[0].strip(),
            detail=(
                "No AWS CLI autocomplete index found. Install AWS CLI v2, or set "
                f"{INDEX_ENV_VAR} to an ac.index path."
            ),
        )
    by_command, globals_, _source = surface

    # The reverse hint is prose-with-a-command by contract, so it is checked only
    # when it actually looks like one. Skipping a non-command hint is correct; the
    # model already requires the hint to be non-empty for a reversible recipe, and
    # this check is not the place to also police its prose.
    candidates = [recipe.cli_template]
    if recipe.reverse_hint.strip().startswith("aws "):
        candidates.append(recipe.reverse_hint)

    primary_label = ""
    for command in candidates:
        parts = _extract(command)
        if parts is None:
            return FlagResult(
                **base,
                status=FlagStatus.COMMAND_MISSING,
                command=command.split("{", 1)[0].strip(),
                detail=(
                    f"Could not read an `aws <service> <subcommand>` command out of {command!r}."
                ),
            )
        service, subcommand, flags = parts
        known = by_command.get((service, subcommand))
        label = f"aws {service} {subcommand}"
        primary_label = primary_label or label
        if known is None:
            return FlagResult(
                **base,
                status=FlagStatus.COMMAND_MISSING,
                command=label,
                detail=(
                    f"`{label}` is not in the AWS CLI index. The service or subcommand "
                    f"was renamed or removed; this command cannot run as written."
                ),
            )
        unknown = [f for f in flags if f not in known and f not in globals_]
        if unknown:
            return FlagResult(
                **base,
                status=FlagStatus.FLAG_MISSING,
                command=label,
                detail=(
                    f"`{label}` does not accept "
                    + ", ".join(f"--{f}" for f in unknown)
                    + '. The generated command fails with "Unknown options".'
                ),
            )

    return FlagResult(**base, status=FlagStatus.OK, command=primary_label)


def verify_all_cli(recipes: tuple[Recipe, ...]) -> tuple[FlagResult, ...]:
    """Check every recipe's rendered commands, in the order given."""
    return tuple(verify_recipe_cli(r) for r in recipes)


__all__ = [
    "INDEX_ENV_VAR",
    "FlagResult",
    "FlagStatus",
    "find_ac_index",
    "index_source_description",
    "verify_all_cli",
    "verify_recipe_cli",
]
