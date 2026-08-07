"""Verify a recipe's ``az`` command against the CLI's own record of what it accepts.

The Azure counterpart of :mod:`remgen.providers.aws.cli_surface`, and it reads a
different source for a measured reason. AWS CLI v2 ships ``ac.index``, a SQLite table
of every command and parameter, so the AWS check is a read-only query. Azure ships
nothing equivalent, and the three candidates were each measured against ``az`` 2.89.0
before this was written:

* **``aaz`` command trees.** The plan of record, and wrong for *this* axis. Only 34 of
  65 command modules have an ``aaz`` tree, and -- what actually decides it -- the
  commands a recipe would name are mostly not in them. ``storage account update``, the
  likeliest first Azure recipe, has an ``aaz/latest/storage/account/`` directory with
  **no** ``_update.py``; ``sql/aaz`` holds only managed-instance commands, and
  ``postgresql/aaz`` only ``network vnet``. A check that could not see most recipes
  would report ``UNAVAILABLE`` for them, and ``UNAVAILABLE`` is exit-code-neutral --
  the axis would be quietly blind for the commands most likely to drift. ``aaz`` does
  declare ``url``, method and ``api-version`` inline, so it remains the right source
  for the *API* axis; that is a different question from what flags ``az`` accepts.
* **``commandIndex.latest.json``**, which does ship with the package, is only
  group-to-module (102 entries, no flags).
* **Importing ``azure.cli.core`` and asking the loader.** Not importable from our
  interpreter -- it lives in ``az``'s own virtualenv -- and putting that
  ``site-packages`` on ``sys.path`` would shadow our dependencies with ``az``'s pinned
  ones. It is also **not ground truth**: its ``arguments`` dict lists flags ``az``
  then rejects (``--account-name``, ``--cmd``, ``--immutability-policy-state`` all
  produce "unrecognized arguments") while omitting ``--subscription``, which ``az``
  accepts. A source that disagrees with the CLI in both directions produces false
  failures and false passes at once.

So this asks ``az`` itself: ``az <command> --help``, parsed by section. That is the
CLI's own statement of its surface, it covers ``aaz`` and non-``aaz`` commands alike,
and it was validated against real acceptance -- of 24 probed flags, ``az`` recognized
24, and the parsed set correctly excludes the flags the loader over-reported.

**Why the union of every section except Examples**, rather than trusting the "Global
Arguments" heading: section placement is not consistent between commands.
``--subscription`` appears under *Resource Id Arguments* for ``storage account
update`` and under *Global Arguments* for ``keyvault update``. Since every generated
Azure command pins ``--subscription`` -- ``azure.shell`` refuses to render one that
does not -- a check that read only the Global sections would fail every recipe.
``Examples`` is excluded because it contains whole sample command lines, whose flags
would be absorbed as if they were this command's own.

**Nothing here runs a remediation.** ``--help`` is the whole point: ``az`` does parse
arguments before authenticating, so a bogus flag is observable by running the real
command with no credentials, but that means naming a mutating operation to a process
that might have credentials after all. Asking for help text cannot mutate anything.
Verified to work with all network access denied and an empty config directory.

As everywhere in verification: no ``az`` on PATH means ``UNAVAILABLE``, never a pass.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil

# The first subprocess call in shipped code, so bandit's B404 and ruff's S603 fire here
# for the first time. Suppressed at each call site rather than project-wide, with the
# argument written out there: a blanket ignore in pyproject.toml would also silence the
# next subprocess call, which might deserve the finding. This module only ever builds
# argv lists and never uses a shell -- see the two call sites for the rest.
#
# Each suppression comment below carries the bare test id and nothing else. bandit
# parses every word following its suppression marker as a test id, so prose written
# alongside one is not a comment -- it becomes a screenful of "Test in comment: ...
# ignoring" warnings on every run, which is how a real bandit warning goes unnoticed.
# (Including that marker in this paragraph is what produced the screenful the first
# time, so it is described rather than spelled.) The reasoning therefore lives on its
# own lines, above the call.
import subprocess  # nosec B404
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache

from remgen.core.model import Recipe

#: Overrides the ``az`` executable, for tests and for a CI job with one at a known
#: path. Named for the binary rather than for an index, because unlike AWS there is no
#: index file to point at -- the CLI itself is the source.
AZ_ENV_VAR = "REMGEN_AZ_CLI"

#: Help sections whose flags are not this command's own. Only ``Examples``: every
#: other section, including the differently-named "Global" ones, lists flags the
#: command accepts. Sample command lines in ``Examples`` would otherwise contribute
#: flags belonging to *other* commands, which is how a check comes to accept a flag
#: that does not exist.
_NON_FLAG_SECTIONS = frozenset({"Examples"})

#: How long to wait for ``az --help``. Measured at 0.8-2.3s depending on how many
#: command modules the group pulls in; the ceiling is generous because a slow machine
#: timing out would report ``UNAVAILABLE`` on an axis that could have run, and this
#: runs once per recipe rather than in a loop.
_TIMEOUT_SECONDS = 60

#: A section header in ``az`` help output: a line at column zero, title-cased words.
#: Checked against the whole line so an indented flag description cannot match.
_SECTION_RE = re.compile(r"^([A-Z][A-Za-z ]*)$")

#: A flag line: indented, one or more space-separated option strings, an optional
#: ``[Required]``-style annotation, then ``:`` and the description. Aliases share a
#: line (``--name -n``), and only the ``--`` forms are collected -- a recipe template
#: spells flags in full, because a generated script is read by someone who did not
#: write it.
#:
#: The optional annotation is not a detail. Without it this pattern dropped every
#: required flag, since ``az`` writes them as ``--status    [Required] : ...`` -- so
#: the flags it silently failed to see were precisely a command's mandatory ones, the
#: ones a recipe is certain to pass. Caught by checking a real command
#: (``az sql db tde set --status Enabled``) against the parser and getting
#: ``flag_missing`` for a flag that exists and is required.
_FLAG_RE = re.compile(
    r"^\s{2,}(--[a-z0-9][a-z0-9-]*(?:\s+-{1,2}[a-zA-Z0-9-]+)*)\s*(?:\[[^\]]*\])?\s*(?::|$)"
)

#: A rendered command's leading words: ``az`` then the command group path. Azure
#: command names are multi-word and of varying depth (``storage account update`` is
#: three, ``sql db tde set`` is four), so the words are taken up to the first flag or
#: placeholder rather than by a fixed count -- the AWS pattern of exactly
#: ``<service> <subcommand>`` does not describe Azure.
_AZ_PREFIX_RE = re.compile(r"^\s*az\s+(.+)$")


class FlagStatus(str, Enum):
    """Outcome of checking one recipe's rendered commands."""

    OK = "ok"
    #: The command exists but does not accept a flag the recipe passes. The generated
    #: command fails with "unrecognized arguments".
    FLAG_MISSING = "flag_missing"
    #: The command group or subcommand itself is not recognized. Every command the
    #: recipe renders is unrunnable.
    COMMAND_MISSING = "command_missing"
    #: No ``az`` available, or it could not be asked; the check could not run.
    UNAVAILABLE = "unavailable"

    @property
    def is_failure(self) -> bool:
        return self in (FlagStatus.FLAG_MISSING, FlagStatus.COMMAND_MISSING)


@dataclass(frozen=True)
class FlagResult:
    """Result of checking one recipe's ``az`` commands.

    Shaped like the AWS :class:`~remgen.providers.aws.cli_surface.FlagResult` because
    the shared ``verify`` reads the same four values off both, but deliberately a
    separate class rather than a shared one: the two clouds disagree about what a
    command even *is*, and a dataclass extracted from one CLI's shape would be a guess
    about the next cloud's.
    """

    policy_id: str
    policy_title: str
    status: FlagStatus
    #: What was checked, e.g. ``"az storage account update"``.
    command: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is FlagStatus.OK

    @property
    def checked(self) -> bool:
        return self.status is not FlagStatus.UNAVAILABLE


def find_az() -> str | None:
    """Locate the ``az`` executable, or ``None``.

    An env override first, then ``PATH``. The override is checked for being an actual
    file so a stale variable degrades to ``UNAVAILABLE`` rather than to a confusing
    ``FileNotFoundError`` from deep inside :mod:`subprocess`.
    """
    override = os.environ.get(AZ_ENV_VAR)
    if override:
        return override if os.path.isfile(override) else None
    return shutil.which("az")


def cli_source_description() -> str:
    """Where the flag surface was read from, for ``verify`` output."""
    az = find_az()
    if not az:
        return "unavailable"
    version = _az_version(az)
    return f"{az} ({version})" if version else az


@lru_cache(maxsize=1)
def _az_version(az: str) -> str:
    """Return ``az``'s reported version, or ``""``.

    Recorded in the source line so a drift report says which CLI disagreed. Failure to
    read it is not a failure of the axis -- the flag check does not depend on it -- so
    this degrades to an empty string rather than making the whole axis unavailable.
    """
    try:
        # A fixed argv list with no shell. The only variable is `az`, which is this
        # process's own PATH or REMGEN_AZ_CLI -- a user choosing which of their own
        # executables to run is not a privilege boundary.
        done = subprocess.run(  # noqa: S603  # nosec B603
            [az, "version", "--output", "tsv", "--query", '"azure-cli"'],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    line = done.stdout.strip().splitlines()
    return f"az {line[0].strip()}" if done.returncode == 0 and line else ""


@lru_cache(maxsize=256)
def _accepted_flags(command: str) -> frozenset[str] | None:
    """Return every flag ``az <command>`` accepts, or ``None`` if it is not a command.

    Cached per command: several recipes may target the same command, and each call is
    a subprocess costing about a second.

    Returns ``None`` for an unrecognized command *and* for an ``az`` that could not be
    run at all; the caller distinguishes those by asking :func:`find_az` first, so that
    "this command is gone" and "there is no CLI" do not collapse into one status.
    """
    az = find_az()
    if not az:
        return None
    try:
        # An argv list with no shell, so nothing in `command` can be interpreted as a
        # shell metacharacter -- the worst a hostile string achieves is asking `az`
        # about a command that does not exist, which returns None. `command` is not
        # user input in any case: it is derived from a recipe's `cli_template`, which
        # is in-repo source reviewed before it ships. And the invocation always ends in
        # --help, so it prints rather than acts; a test asserts that property by
        # recording every argv this module spawns.
        done = subprocess.run(  # noqa: S603  # nosec B603
            [az, *command.split(), "--help"],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            # Help text is generated from the loaded command table; it needs no
            # credentials and no network.
            check=False,
        )  # nosec B603
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    flags = _parse_help(done.stdout)
    # An empty set from a successful --help means the output shape changed, not that
    # the command takes no flags. Returning it would pass every recipe that names this
    # command, so it is reported as could-not-parse instead.
    return flags or None


def _parse_help(text: str) -> frozenset[str]:
    """Extract accepted flags from ``az --help`` output.

    Every section contributes except ``Examples``. See the module docstring for why
    the "Global Arguments" heading cannot be used to separate global flags from a
    command's own: the placement is inconsistent between commands, and the check only
    needs to know whether ``az`` accepts a flag, not which section documents it.
    """
    section: str | None = None
    flags: set[str] = set()
    for line in text.splitlines():
        if line and not line[0].isspace():
            header = _SECTION_RE.match(line.rstrip())
            if header:
                section = header.group(1)
                continue
        if section in _NON_FLAG_SECTIONS:
            continue
        match = _FLAG_RE.match(line)
        if match:
            flags.update(tok for tok in match.group(1).split() if tok.startswith("--"))
    return frozenset(flags)


def _extract(command: str) -> tuple[str, list[str]] | None:
    """Split a rendered command into ``(az command name, flag names)``.

    Returns ``None`` when the string does not begin with ``az``. The command name is
    the run of leading words before the first flag or ``{placeholder}``, because Azure
    command names vary in depth -- a fixed two-word rule like the AWS one would read
    ``sql db tde set`` as ``sql db``.

    Parsed with :mod:`shlex` so a quoted argument containing a space stays one token;
    a template too malformed to lex is reported as unparseable rather than guessed at.
    """
    prefix = _AZ_PREFIX_RE.match(command)
    if not prefix:
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    words: list[str] = []
    for token in tokens[1:]:
        if token.startswith("-") or token.startswith("{"):
            break
        words.append(token)
    if not words:
        return None
    flags = [t.split("=", 1)[0] for t in tokens if t.startswith("--") and t != "--"]
    return " ".join(words), flags


def verify_recipe_cli(recipe: Recipe) -> FlagResult:
    """Check a recipe's ``cli_template`` and ``reverse_hint`` against ``az``.

    Both are checked, because both are rendered into the shell artifact -- the reverse
    command as the documented way to undo the change. A reverse command with a stale
    flag fails at the moment it is most needed, which is right after someone has
    broken something.
    """
    base = {"policy_id": recipe.policy_id, "policy_title": recipe.policy_title}
    if not find_az():
        return FlagResult(
            **base,
            status=FlagStatus.UNAVAILABLE,
            command=recipe.cli_template.split("{", 1)[0].strip(),
            detail=(f"No 'az' CLI found. Install the Azure CLI, or set {AZ_ENV_VAR} to its path."),
        )

    # The reverse hint is prose-with-a-command by contract, so it is checked only when
    # it actually looks like one. Skipping a prose hint is correct: the model already
    # requires a reversible recipe to have a non-empty hint, and policing its wording
    # is not this axis's job.
    candidates = [recipe.cli_template]
    if recipe.reverse_hint.strip().startswith("az "):
        candidates.append(recipe.reverse_hint)

    primary_label = ""
    for command in candidates:
        parts = _extract(command)
        if parts is None:
            return FlagResult(
                **base,
                status=FlagStatus.COMMAND_MISSING,
                command=command.split("{", 1)[0].strip(),
                detail=f"Could not read an `az <command>` invocation out of {command!r}.",
            )
        name, flags = parts
        label = f"az {name}"
        primary_label = primary_label or label
        known = _accepted_flags(name)
        if known is None:
            return FlagResult(
                **base,
                status=FlagStatus.COMMAND_MISSING,
                command=label,
                detail=(
                    f"`{label} --help` did not report a usable flag list. The command "
                    f"group or subcommand was renamed or removed, or the help output "
                    f"changed shape; either way this command cannot be confirmed to run "
                    f"as written."
                ),
            )
        unknown = [f for f in flags if f not in known]
        if unknown:
            return FlagResult(
                **base,
                status=FlagStatus.FLAG_MISSING,
                command=label,
                detail=(
                    f"`{label}` does not accept "
                    + ", ".join(unknown)
                    + '. The generated command fails with "unrecognized arguments".'
                ),
            )

    return FlagResult(**base, status=FlagStatus.OK, command=primary_label)


def verify_all_cli(recipes: tuple[Recipe, ...]) -> tuple[FlagResult, ...]:
    """Check every recipe's rendered commands, in the order given."""
    return tuple(verify_recipe_cli(r) for r in recipes)


__all__ = [
    "AZ_ENV_VAR",
    "FlagResult",
    "FlagStatus",
    "cli_source_description",
    "find_az",
    "verify_all_cli",
    "verify_recipe_cli",
]
