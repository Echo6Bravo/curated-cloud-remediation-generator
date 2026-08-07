"""Tests for the Azure CLI-surface axis.

Split deliberately into two kinds, because they fail for different reasons and one
kind must not be allowed to hide behind the other:

* **Parser tests** feed captured ``az --help`` text to :func:`_parse_help`. They are
  hermetic and assert the extraction rules -- sections, aliases, and the
  ``[Required]`` annotation that the first version of the pattern silently dropped.
* **Integration tests** run the real ``az`` and are skipped when it is absent. They
  are what tells us the parser agrees with the CLI; a parser test can only tell us the
  parser agrees with a fixture, and a fixture is a copy of what we already believed.

Nothing in this file invokes a mutating command. ``--help`` is the only subcommand the
verifier ever passes, which is a property of the module rather than of these tests, so
one test asserts it directly.
"""

from __future__ import annotations

import shutil

import pytest

from remgen.core.model import ApiCall, Recipe
from remgen.providers.azure.cli_surface import (
    AZ_ENV_VAR,
    FlagStatus,
    _accepted_flags,
    _extract,
    _parse_help,
    cli_source_description,
    find_az,
    verify_all_cli,
    verify_recipe_cli,
)

HAS_AZ = shutil.which("az") is not None
needs_az = pytest.mark.skipif(not HAS_AZ, reason="the real az CLI is not installed")

#: Captured from ``az sql db tde set --help`` (az 2.89.0), trimmed. Kept verbatim
#: rather than tidied: the exact column alignment and the ``[Required]`` marker are
#: what the parser has to cope with, so reformatting it would remove the test.
HELP_WITH_REQUIRED = """
Command
    az sql db tde set : Sets a database's transparent data encryption configuration.

Arguments
    --status    [Required] : Status of the transparent data encryption.  Allowed values: Disabled,
                             Enabled.

Global Policy Arguments
    --acquire-policy-token : Acquiring an Azure Policy token automatically for this resource
                             operation.

Resource Id Arguments
    --database -d          : Name of the Azure SQL Database.
    --ids                  : One or more resource IDs (space-delimited).
    --subscription         : Name or ID of subscription.

Global Arguments
    --debug                : Increase logging verbosity to show all debug logs.
    --help -h              : Show this help message and exit.

Examples
    Set a database's transparent data encryption
        az sql db tde set --status Enabled --database mydb
        --invented-example-flag
"""


def _recipe(*, template: str, reverse: str = "", policy_id: str = "p-1") -> Recipe:
    return Recipe(
        policy_id=policy_id,
        policy_title="Probe recipe",
        summary="A recipe used to exercise the CLI-surface axis.",
        api=ApiCall(
            service="storage",
            operation="storage account update",
            parameters=("allow-blob-public-access",),
        ),
        cli_template=template,
        hcl=None,
        reverse_hint=reverse or "Re-run with the previous value.",
        docs_url="https://learn.microsoft.com/cli/azure",
    )


# ---------------------------------------------------------------------------
# Parsing az --help
# ---------------------------------------------------------------------------


def test_required_flags_are_not_dropped():
    """Regression for a real false-failure bug, and the reason this file exists.

    ``az`` writes required flags as ``--status    [Required] : ...``. The first version
    of the flag pattern required the option strings to be followed directly by ``:``,
    so it skipped every required flag -- meaning the flags it could not see were
    exactly a command's *mandatory* ones, which a recipe is certain to pass. The axis
    would then have reported ``flag_missing`` for a correct recipe, and a reader would
    have believed the CLI had changed.

    Found by checking a real command rather than a fixture: ``az sql db tde set``
    accepts ``--status``, and the axis said it did not.
    """
    flags = _parse_help(HELP_WITH_REQUIRED)
    assert "--status" in flags, "a [Required] flag was dropped by the parser"


def test_aliases_and_every_non_example_section_contribute():
    flags = _parse_help(HELP_WITH_REQUIRED)
    # Long forms from four differently-named sections.
    assert {"--status", "--acquire-policy-token", "--database", "--debug"} <= flags
    # Short aliases are not collected: templates spell flags in full, so `-d` in the
    # accepted set would only make a typo'd template pass.
    assert "-d" not in flags and "-h" not in flags


def test_subscription_is_accepted_whatever_section_documents_it():
    """The check must not depend on where ``az`` files ``--subscription``.

    Placement is genuinely inconsistent: it is under *Resource Id Arguments* for
    ``storage account update`` and under *Global Arguments* for ``keyvault update``.
    Every generated Azure command pins ``--subscription`` -- ``azure.shell`` refuses to
    render one that does not -- so a rule that trusted the "Global" heading would fail
    every recipe at once.
    """
    assert "--subscription" in _parse_help(HELP_WITH_REQUIRED)


def test_flags_inside_examples_are_not_treated_as_accepted():
    """``Examples`` lists sample command lines, including other commands' flags.

    Absorbing one is how a check comes to accept a flag that does not exist, which is
    worse than not checking at all: it reports a pass on a command that will fail.

    **Scope of what this proves, stated because it is less than it looks.** On ``az``
    2.89.0 the ``Examples`` exclusion is defensive rather than load-bearing: measured
    across 15 real commands, dropping it changed the parsed flag set for none of them,
    because ``_FLAG_RE`` requires ``:`` or end-of-line after the option strings and
    example lines are ``--flag value``. So this fixture uses the one shape that *does*
    leak -- a bare flag alone on a wrapped line -- to pin the rule in place against a
    future help-format change. The first version of this test used a realistic example
    line and therefore asserted nothing: mutation-testing (deleting
    ``_NON_FLAG_SECTIONS``) left the suite green, which is how the vacuity was found.
    """
    flags = _parse_help(HELP_WITH_REQUIRED)
    assert "--invented-example-flag" not in flags


def test_help_output_that_lists_no_flags_parses_to_nothing():
    """The parser's half of the empty-output case: no flag lines means no flags."""
    assert _parse_help("Command\n    az thing : does a thing.\n") == frozenset()


def test_help_that_parses_to_no_flags_is_could_not_check_not_an_empty_accept_set(monkeypatch):
    """A successful ``--help`` that yields no flags is a shape change, not a fact.

    This is the branch that decides which *wrong* answer a help-format change produces.
    ``_accepted_flags`` must return ``None`` -- could-not-check -- rather than an empty
    set. An empty set would be read as "this command accepts no flags", so every recipe
    naming it would be reported as ``flag_missing``: a wall of confident drift failures
    caused by our own parser, pointing the reader at Azure.

    Driven through ``_accepted_flags`` rather than ``_parse_help`` because the
    distinction lives in the former; a parser-level test leaves this branch uncovered,
    which mutation-testing confirmed by deleting ``or None`` and staying green.
    """
    from remgen.providers.azure import cli_surface

    class _Done:
        returncode = 0
        stdout = "Command\n    az thing : does a thing.\n"

    monkeypatch.setattr(cli_surface, "find_az", lambda: "/usr/bin/az")
    monkeypatch.setattr(cli_surface.subprocess, "run", lambda *a, **k: _Done())
    _accepted_flags.cache_clear()
    assert _accepted_flags("thing") is None, (
        "help output with no parseable flags was reported as a command that accepts none"
    )
    _accepted_flags.cache_clear()


# ---------------------------------------------------------------------------
# Reading a command out of a template
# ---------------------------------------------------------------------------


def test_command_names_of_different_depths_are_read_whole():
    """Azure command names vary in depth, so a fixed word count is wrong.

    AWS is always ``aws <service> <subcommand>``. Azure has three-word
    (``storage account update``) and four-word (``sql db tde set``) names, and
    truncating the second to ``sql db`` would look up a command group that exists,
    getting a plausible flag set for the wrong command.
    """
    assert _extract("az storage account update --ids {resource_id}")[0] == (
        "storage account update"
    )
    assert _extract("az sql db tde set --status Enabled")[0] == "sql db tde set"


def test_the_command_stops_at_the_first_flag_or_placeholder():
    name, flags = _extract("az storage account update --ids {resource_id} --https-only true")
    assert name == "storage account update"
    assert flags == ["--ids", "--https-only"]


def test_flag_values_and_equals_forms_are_not_mistaken_for_flags():
    _name, flags = _extract("az storage account update --https-only=true --ids X")
    assert flags == ["--https-only", "--ids"]


def test_a_non_az_command_is_not_silently_skipped():
    # Returning None here routes to COMMAND_MISSING. Skipping it would let an AWS
    # template sit in the Azure recipe set and be reported as verified.
    assert _extract("aws s3api put-bucket-versioning --bucket b") is None


def test_an_unlexable_template_is_reported_rather_than_guessed_at():
    assert _extract('az storage account update --tags "unclosed') is None


# ---------------------------------------------------------------------------
# No az available: unavailable, never a pass
# ---------------------------------------------------------------------------


def test_a_missing_az_is_unavailable_and_not_ok(monkeypatch):
    # A stale env override, which is the realistic way this happens: the variable
    # points at an az that has been upgraded out from under it.
    monkeypatch.setenv(AZ_ENV_VAR, "/nonexistent/az")
    _accepted_flags.cache_clear()
    assert find_az() is None
    result = verify_recipe_cli(_recipe(template="az storage account update --ids {resource_id}"))
    assert result.status is FlagStatus.UNAVAILABLE
    assert not result.ok
    assert not result.checked, "an unavailable check must not count as checked"
    assert AZ_ENV_VAR in result.detail, "the detail does not say how to fix it"
    assert cli_source_description() == "unavailable"


def test_unavailable_is_distinct_from_command_missing(monkeypatch):
    """ "There is no CLI" and "the command is gone" must not collapse into one status.

    They have different fixes and different exit codes -- 4 for could-not-check, a
    failure for real drift -- so a single status would report an uninstalled CLI as
    though Azure had removed a command.
    """
    monkeypatch.setenv(AZ_ENV_VAR, "/nonexistent/az")
    _accepted_flags.cache_clear()
    assert (
        verify_recipe_cli(_recipe(template="az storage account update --ids {resource_id}")).status
        is FlagStatus.UNAVAILABLE
    )


# ---------------------------------------------------------------------------
# Against the real az
# ---------------------------------------------------------------------------


@needs_az
def test_a_real_pinned_command_passes():
    result = verify_recipe_cli(
        _recipe(
            template=(
                "az storage account update --ids {resource_id} "
                "--allow-blob-public-access false --subscription {account_id}"
            )
        )
    )
    assert result.status is FlagStatus.OK, result.detail
    assert result.command == "az storage account update"


@needs_az
def test_a_real_non_aaz_command_is_checkable():
    """The measurement that decided the source: recipes will name non-aaz commands.

    ``storage account update`` has an ``aaz/latest/storage/account/`` directory but no
    ``_update.py``, so an aaz-based check would have reported it as could-not-check --
    and could-not-check is exit-code-neutral, so the axis would have been quietly blind
    for the command most likely to be the first Azure recipe.
    """
    assert _accepted_flags("storage account update"), "a non-aaz command must be checkable"


@needs_az
def test_a_real_aaz_command_is_checkable_too():
    # Both kinds, through one code path: whether a command is aaz-generated is not
    # something this axis needs to know.
    assert _accepted_flags("network nsg rule update")


@needs_az
def test_a_bogus_flag_on_a_real_command_fails_with_a_usable_message():
    result = verify_recipe_cli(
        _recipe(
            template=(
                "az storage account update --ids {resource_id} "
                "--frobnicate-flag true --subscription {account_id}"
            )
        )
    )
    assert result.status is FlagStatus.FLAG_MISSING
    assert "--frobnicate-flag" in result.detail
    assert "unrecognized arguments" in result.detail


@needs_az
def test_a_bogus_command_is_command_missing():
    result = verify_recipe_cli(_recipe(template="az storage frobnicate update --ids {resource_id}"))
    assert result.status is FlagStatus.COMMAND_MISSING


@needs_az
def test_the_loader_over_reported_flags_are_correctly_rejected():
    """The other half of the source decision, asserted rather than described.

    Reading ``az``'s own command loader in-process was the obvious alternative. It
    lists flags ``az`` then refuses -- ``--account-name`` on ``storage account update``
    produces "unrecognized arguments" -- so a loader-based check would report a pass on
    a command that cannot run. This asserts the chosen source does not make that
    mistake, which is the claim the module docstring makes.
    """
    result = verify_recipe_cli(
        _recipe(
            template=(
                "az storage account update --ids {resource_id} "
                "--account-name sa1 --subscription {account_id}"
            )
        )
    )
    assert result.status is FlagStatus.FLAG_MISSING
    assert "--account-name" in result.detail


@needs_az
def test_a_stale_reverse_hint_is_caught():
    """The reverse command is checked too, because it is rendered into the artifact.

    It is also the command a user runs in a hurry, having just broken something, so a
    stale flag there fails at the worst possible moment.
    """
    result = verify_recipe_cli(
        _recipe(
            template=(
                "az storage account update --ids {resource_id} "
                "--allow-blob-public-access false --subscription {account_id}"
            ),
            reverse="az storage account update --ids X --frobnicate-reverse true --subscription S",
        )
    )
    assert result.status is FlagStatus.FLAG_MISSING
    assert "--frobnicate-reverse" in result.detail


@needs_az
def test_a_prose_reverse_hint_is_not_checked_as_a_command():
    result = verify_recipe_cli(
        _recipe(
            template=(
                "az storage account update --ids {resource_id} "
                "--allow-blob-public-access false --subscription {account_id}"
            ),
            reverse="Set the value back to true in the portal.",
        )
    )
    assert result.status is FlagStatus.OK, result.detail


@needs_az
def test_the_source_description_names_the_az_that_was_used():
    # A drift report has to say which CLI disagreed, or the reader cannot reproduce it.
    source = cli_source_description()
    assert source != "unavailable"
    assert "az" in source


@needs_az
def test_the_axis_never_invokes_anything_but_help(monkeypatch):
    """A property of the verifier, asserted by recording every subprocess it spawns.

    ``az`` parses arguments before authenticating, so flag validity is *observable* by
    running the real command with no credentials -- and doing that would mean a
    verification command naming a mutating operation to a process that might have
    credentials after all. This is the test that stops that shortcut being taken later.
    """
    import subprocess as sp

    from remgen.providers.azure import cli_surface

    calls: list[list[str]] = []
    real_run = sp.run

    def recording_run(args, *a, **kw):
        calls.append(list(args))
        return real_run(args, *a, **kw)

    monkeypatch.setattr(cli_surface.subprocess, "run", recording_run)
    _accepted_flags.cache_clear()
    cli_surface._az_version.cache_clear()
    verify_all_cli(
        (
            _recipe(
                template=(
                    "az storage account update --ids {resource_id} "
                    "--allow-blob-public-access false --subscription {account_id}"
                )
            ),
        )
    )
    assert calls, "nothing was invoked, so this test proved nothing"
    for argv in calls:
        # `update` necessarily appears in the argv, because the command being *asked
        # about* is `storage account update` -- so "contains no mutating verb" is the
        # wrong property, and asserting it failed here on correct code. The property
        # that matters is that the invocation is terminated by --help, which makes az
        # print rather than act. Checked as the final argument for that reason: --help
        # somewhere in the middle would not stop the command running.
        assert argv[-1] == "--help" or "version" in argv, (
            f"az was invoked in a form that is not a help or version query: {argv}"
        )


@needs_az
def test_results_come_back_one_per_recipe_in_order():
    recipes = (
        _recipe(
            policy_id="p-a",
            template="az storage account update --ids {resource_id} --subscription S",
        ),
        _recipe(
            policy_id="p-b",
            template="az keyvault update --ids {resource_id} --subscription S",
        ),
    )
    results = verify_all_cli(recipes)
    assert [r.policy_id for r in results] == ["p-a", "p-b"]
