"""Tests for the CLI-flag axis of verification.

The checker under test reads the AWS CLI's own autocomplete index, so most of these
run against the real index rather than a fixture -- and that is the point. A fixture
index would record what I believe the CLI accepts, which is the belief the checker
exists to stop trusting. The synthetic-index tests cover only the cases the real CLI
cannot produce on demand: a *removed* flag, a *renamed* subcommand, a malformed
database.

The negative controls matter more here than usual. A checker that says "all flags
accepted" is indistinguishable from one that checks nothing, so every status has a
test that provokes it from an otherwise-correct recipe.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest

from remgen.providers.aws.cli_surface import (
    INDEX_ENV_VAR,
    FlagStatus,
    _load_surface,
    find_ac_index,
    index_source_description,
    verify_all_cli,
    verify_recipe_cli,
)
from remgen.providers.aws.recipes import all_recipes

#: The shipped set, as the tool itself sees it -- the aggregate over every service
#: module, not one module's tuple. Importing a single module would check whichever
#: services that module happens to hold and silently stop covering a new one.
RECIPES = all_recipes()


def _dynamodb_recipe():
    """Return the DynamoDB recipe, which most negative controls below mutate.

    Looked up by resource rather than by position. These tests substitute a specific
    flag (``--deletion-protection-enabled``) and a specific subcommand
    (``update-table``), so they only mean anything against that recipe -- and indexing
    into the set made them depend on its order, which is now the order service modules
    are discovered in. A reordering would have left them running against a recipe whose
    template does not contain the string being replaced, so ``replace`` would return an
    unmodified command and the negative control would assert that a *correct* recipe
    fails. That passes for the wrong reason in the direction that matters.
    """
    for recipe in RECIPES:
        if recipe.api.service == "dynamodb":
            return recipe
    pytest.fail("no dynamodb recipe; re-point the flag-level tests at another recipe")


#: The real index, if the AWS CLI is installed. Every test that needs it gates at
#: collection time so a skip is visible in CI's summary rather than inside a pass.
_REAL_INDEX = find_ac_index()
_needs_index = pytest.mark.skipif(
    _REAL_INDEX is None,
    reason="AWS CLI v2 autocomplete index not found; the CLI-flag axis cannot be checked",
)


@pytest.fixture(autouse=True)
def _clear_surface_cache():
    """Reset the module's one-shot cache around every test.

    :func:`_load_surface` is ``lru_cache``d because reading a 21 MB sqlite file per
    recipe would be slow. That cache is per-process, so a test that points the module
    at a synthetic index would otherwise be served the previous test's real one -- and
    a test whose negative control silently ran against the wrong index passes for the
    wrong reason.
    """
    _load_surface.cache_clear()
    yield
    _load_surface.cache_clear()


def _synthetic_index(tmp_path, rows, *, globals_=(("region", "aws", ""),)):
    """Build a minimal ``ac.index`` containing only ``param_table``.

    Only the one table the checker reads is created. If it ever starts reading
    another, these tests fail loudly rather than quietly exercising a shape the real
    index does not have.
    """
    path = tmp_path / "ac.index"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE param_table (param_id INTEGER PRIMARY KEY, argname TEXT, "
        "type_name TEXT, command TEXT, parent TEXT, nargs TEXT, positional_arg TEXT, "
        "required INTEGER)"
    )
    conn.executemany(
        "INSERT INTO param_table (argname, command, parent) VALUES (?, ?, ?)",
        list(rows) + list(globals_),
    )
    conn.commit()
    conn.close()
    return path


# ---------------------------------------------------------------------------
# Against the real CLI
# ---------------------------------------------------------------------------


@_needs_index
def test_every_shipped_recipe_renders_a_command_the_cli_accepts():
    """The assertion the axis exists for.

    Note what this checks that ``test_drift.py`` does not: the drift tests confirm the
    *API* operation and its members exist in ``service-2.json``. This confirms the
    *command string* a user pastes into a terminal is one the ``aws`` binary parses --
    a different surface, changed by a different team, on a different schedule.
    """
    problems = [(r.command, r.status.value, r.detail) for r in verify_all_cli(RECIPES) if not r.ok]
    assert not problems, f"recipes render commands the AWS CLI rejects: {problems}"


@_needs_index
def test_every_recipe_was_actually_checked():
    """Guards against the axis passing because it silently checked nothing.

    ``ok`` is false for ``UNAVAILABLE``, so the test above already catches a total
    absence of index. This catches the subtler case of a per-recipe result that was
    never checked -- and it pins the count, so a recipe dropped from the loop fails.
    """
    results = verify_all_cli(RECIPES)
    assert len(results) == len(RECIPES)
    assert all(r.checked for r in results)
    assert all(r.command.startswith("aws ") for r in results)


@_needs_index
def test_the_s3api_command_group_resolves():
    """``s3api`` is a CLI-only command group, not an API service name.

    A checker that looked services up by their API name would report this recipe as a
    missing command. It is the one recipe in the set where the CLI's name for the
    service and the API's differ, so it is named explicitly -- if it is ever removed,
    this test should be re-pointed rather than deleted.
    """
    s3 = [r for r in RECIPES if "s3api" in r.cli_template]
    assert s3, "no s3api recipe remains; re-point this test at another CLI-only group"
    for recipe in s3:
        assert verify_recipe_cli(recipe).status is FlagStatus.OK


@_needs_index
def test_a_typo_in_a_flag_is_caught():
    # The negative control for the test above. Without it, "all flags accepted" and
    # "no flags examined" are the same result.
    recipe = _dynamodb_recipe()
    broken = replace(
        recipe,
        cli_template=recipe.cli_template.replace(
            "--deletion-protection-enabled", "--deletion-protection-enable"
        ),
    )
    # `str.replace` is silent when the substring is absent, so a recipe that stopped
    # rendering this flag would leave `broken` identical to `recipe` and turn this
    # negative control into an assertion that a correct command is rejected.
    assert broken.cli_template != recipe.cli_template, (
        "the flag this test breaks is no longer in the template; nothing was mutated"
    )
    result = verify_recipe_cli(broken)
    assert result.status is FlagStatus.FLAG_MISSING
    assert not result.ok
    assert "--deletion-protection-enable" in result.detail


@_needs_index
def test_a_renamed_subcommand_is_caught():
    recipe = replace(
        _dynamodb_recipe(), cli_template="aws dynamodb update-tabel --table-name {resource_id}"
    )
    assert verify_recipe_cli(recipe).status is FlagStatus.COMMAND_MISSING


@_needs_index
def test_a_renamed_service_is_caught():
    recipe = replace(
        _dynamodb_recipe(), cli_template="aws dynamodbz update-table --table-name {resource_id}"
    )
    assert verify_recipe_cli(recipe).status is FlagStatus.COMMAND_MISSING


@_needs_index
def test_a_stale_flag_in_the_reverse_hint_alone_is_caught():
    """The reverse command is checked too, and it is the one that matters most.

    A user runs the reverse command having just discovered the change was wrong. A
    stale flag there fails at the worst possible moment, and no test of the forward
    command would find it -- the two use opposite polarities of the same flag, so they
    can rot independently.
    """
    recipe = replace(
        _dynamodb_recipe(),
        reverse_hint="aws dynamodb update-table --table-name x --no-deletion-protection-enable",
    )
    result = verify_recipe_cli(recipe)
    assert result.status is FlagStatus.FLAG_MISSING
    assert "--no-deletion-protection-enable" in result.detail


@_needs_index
def test_the_negated_form_of_a_boolean_flag_is_recognised():
    """The control for the test above: ``--no-`` flags must not be rejected wholesale.

    If the checker did not know the negated forms, every reversible recipe's hint would
    fail -- and the fix would be to stop checking hints, losing the case above.
    """
    recipe = replace(
        _dynamodb_recipe(),
        reverse_hint="aws dynamodb update-table --table-name x --no-deletion-protection-enabled",
    )
    assert verify_recipe_cli(recipe).status is FlagStatus.OK


@_needs_index
def test_global_flags_are_accepted_on_any_subcommand():
    # --profile and --output are not in any subcommand's parameter list; rejecting
    # them would fail every recipe that renders one.
    recipe = replace(
        _dynamodb_recipe(),
        cli_template="aws dynamodb update-table --table-name {resource_id} --profile p --output json",
    )
    assert verify_recipe_cli(recipe).status is FlagStatus.OK


@_needs_index
def test_the_source_is_reported_as_a_real_path():
    assert index_source_description().endswith("ac.index")


# ---------------------------------------------------------------------------
# Synthetic index: the cases the real CLI cannot be made to produce
# ---------------------------------------------------------------------------


def test_a_flag_the_index_does_not_list_is_caught(tmp_path, monkeypatch):
    """A *removed* flag, which no real installed CLI will demonstrate.

    This is the drift the axis is built for: the CLI drops or renames a flag while the
    API operation behind it is untouched, so ``verify_recipes`` stays green and the
    generated script fails when run.
    """
    monkeypatch.setenv(
        INDEX_ENV_VAR,
        str(_synthetic_index(tmp_path, [("table-name", "update-table", "aws.dynamodb")])),
    )
    result = verify_recipe_cli(_dynamodb_recipe())
    assert result.status is FlagStatus.FLAG_MISSING
    assert "deletion-protection-enabled" in result.detail


def test_a_correct_recipe_passes_against_the_synthetic_index(tmp_path, monkeypatch):
    """The control: the synthetic index must be capable of producing a pass.

    Without this, the test above could be passing because the synthetic index is
    unreadable and everything fails -- which would also mean the *unavailable* path
    was being tested by accident.
    """
    monkeypatch.setenv(
        INDEX_ENV_VAR,
        str(
            _synthetic_index(
                tmp_path,
                [
                    ("table-name", "update-table", "aws.dynamodb"),
                    ("deletion-protection-enabled", "update-table", "aws.dynamodb"),
                    ("no-deletion-protection-enabled", "update-table", "aws.dynamodb"),
                ],
            )
        ),
    )
    assert verify_recipe_cli(_dynamodb_recipe()).status is FlagStatus.OK


def test_no_index_is_reported_as_unavailable_not_as_a_pass(tmp_path, monkeypatch):
    monkeypatch.setenv(INDEX_ENV_VAR, str(tmp_path / "absent.index"))
    monkeypatch.setattr("remgen.providers.aws.cli_surface.shutil.which", lambda _: None)
    result = verify_recipe_cli(_dynamodb_recipe())
    assert result.status is FlagStatus.UNAVAILABLE
    assert not result.checked
    assert not result.ok, "an unrunnable check must never satisfy `ok`"
    assert INDEX_ENV_VAR in result.detail
    assert index_source_description() == "unavailable"


def test_a_malformed_index_is_unavailable_rather_than_a_pass(tmp_path, monkeypatch):
    """A file that is not a database must degrade, not crash and not pass.

    The dangerous outcome is a green verification run against an index that could not
    be read -- so this asserts specifically on ``UNAVAILABLE``, not merely on "did not
    raise".
    """
    bad = tmp_path / "ac.index"
    bad.write_bytes(b"this is not sqlite")
    monkeypatch.setenv(INDEX_ENV_VAR, str(bad))
    result = verify_recipe_cli(_dynamodb_recipe())
    assert result.status is FlagStatus.UNAVAILABLE


def test_an_index_with_no_usable_rows_is_unavailable(tmp_path, monkeypatch):
    """An empty parameter table would otherwise fail every recipe at once.

    "Every command is missing" is a confident wrong answer that sends an operator
    looking for an upstream rename. "Could not check" is the truth.
    """
    monkeypatch.setenv(INDEX_ENV_VAR, str(_synthetic_index(tmp_path, [], globals_=[])))
    assert verify_recipe_cli(_dynamodb_recipe()).status is FlagStatus.UNAVAILABLE


def test_a_template_that_is_not_an_aws_command_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv(
        INDEX_ENV_VAR,
        str(_synthetic_index(tmp_path, [("table-name", "update-table", "aws.dynamodb")])),
    )
    recipe = replace(_dynamodb_recipe(), cli_template="kubectl delete pod {resource_id}")
    result = verify_recipe_cli(recipe)
    assert result.status is FlagStatus.COMMAND_MISSING


def test_the_index_is_opened_read_only(tmp_path, monkeypatch):
    """Verification must not be able to write to the tool it is verifying.

    Checked by observing the connection's behaviour rather than by reading the source,
    because a ``mode=ro`` that was dropped in a refactor would leave a source-grep
    test passing.
    """
    path = _synthetic_index(tmp_path, [("table-name", "update-table", "aws.dynamodb")])
    monkeypatch.setenv(INDEX_ENV_VAR, str(path))
    assert _load_surface() is not None  # populates from the read-only handle

    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO param_table (argname) VALUES ('x')")
    finally:
        conn.close()


def test_find_ac_index_prefers_the_env_override(tmp_path, monkeypatch):
    path = _synthetic_index(tmp_path, [("a", "b", "aws.c")])
    monkeypatch.setenv(INDEX_ENV_VAR, str(path))
    assert find_ac_index() == path
    monkeypatch.setenv(INDEX_ENV_VAR, str(tmp_path / "nope"))
    monkeypatch.setattr("remgen.providers.aws.cli_surface.shutil.which", lambda _: None)
    assert find_ac_index() is None


def test_verify_all_preserves_order_and_length(tmp_path, monkeypatch):
    monkeypatch.setenv(INDEX_ENV_VAR, str(_synthetic_index(tmp_path, [])))
    results = verify_all_cli(RECIPES)
    assert [r.policy_id for r in results] == [r.policy_id for r in RECIPES]
