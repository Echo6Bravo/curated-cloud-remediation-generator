"""Tests for the Azure ``az`` script generator.

Tested directly rather than through ``azremgen generate``, and now that Azure ships
recipes that is a choice rather than a necessity. It stays deliberate: the generator's
contract includes inputs the curated set does not contain and must never contain -- an
unpinned template, a template naming the wrong subscription, an empty recipe list --
and the end-to-end path can only exercise what a real recipe produces. So these build
recipe objects here, including the illegal ones, while the shipped-recipe path is
covered end to end in ``tests/test_azure_cli.py``.

The most important tests in this file assert that it **does not**. The AWS script
refuses to run when the active account differs from the target; this one proceeds,
because an Azure login legitimately spans subscriptions and every command names its
subscription explicitly. That difference is deliberate and load-bearing, so it is
asserted in both directions -- a future contributor "fixing the inconsistency" by
copying the AWS guard would break the pinning contract, and these tests are what
tells them so.
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from remgen.core.layout import Format, OutputUnit
from remgen.core.model import ApiCall, Finding, Recipe
from remgen.providers.azure.recipes import all_recipes as azure_recipes
from remgen.providers.azure.shell import (
    SubscriptionNotPinnedError,
    render_cli_script,
    render_one,
)

VERSION = "9.9.9"
STAMP = "2026-01-01T00:00:00+00:00"
SUB = "00000000-0000-0000-0000-000000000000"
OTHER_SUB = "11111111-1111-1111-1111-111111111111"

#: A pinned template. Every recipe in this file uses one, except where the point of
#: the test is that it does not.
PINNED = (
    "az storage account update --ids {resource_id} "
    "--allow-blob-public-access false --subscription {account_id}"
)


def _recipe(
    *,
    policy_id: str = "aaaaaaaa-1111-2222-3333-444444444444",
    title: str = "Storage account allows public blob access",
    template: str = PINNED,
    **kwargs,
) -> Recipe:
    """Build a recipe with the risk fields left at their safe defaults.

    ``safety_tier`` is derived from the risk fields rather than set, so a test that
    wants a riskier tier sets the *cause* (``reversible=False``,
    ``data_path_impact=True``) and lets the model classify it. Passing a tier
    directly would let a test assert a classification the model would not make.
    """
    fields = {
        "reverse_hint": "Re-run with --allow-blob-public-access true.",
        "docs_url": "https://learn.microsoft.com/cli/azure/storage/account",
    }
    # Caller wins: a test making a recipe irreversible must also be able to clear the
    # reverse hint, which the model requires it to do. Passing both as keywords would
    # be a TypeError rather than an override.
    fields.update(kwargs)
    return Recipe(
        policy_id=policy_id,
        policy_title=title,
        summary="Disable public blob access on the storage account.",
        api=ApiCall(
            service="storage",
            operation="storage account update",
            parameters=("allow-blob-public-access",),
        ),
        cli_template=template,
        hcl=None,
        **fields,
    )


def _finding(*, sub: str = SUB, name: str = "sa1", region: str = "eastus") -> Finding:
    return Finding(
        policy_id="aaaaaaaa-1111-2222-3333-444444444444",
        resource_id=(
            f"/subscriptions/{sub}/resourceGroups/rg-prod"
            f"/providers/Microsoft.Storage/storageAccounts/{name}"
        ),
        region=region,
        account_id=sub,
    )


def _unit(pairs, *, sub: str = SUB, region: str | None = None) -> OutputUnit:
    return OutputUnit(
        fmt=Format.CLI,
        cloud="azure",
        scope_id=sub,
        region=region,
        part=None,
        total_parts=1,
        pairs=tuple(pairs),
        scope_noun="subscription",
    )


def _script(pairs=None, *, unit=True) -> str:
    pairs = [(_recipe(), _finding())] if pairs is None else pairs
    return render_cli_script(
        pairs,
        version=VERSION,
        generated_at=STAMP,
        unit=_unit(pairs) if unit else None,
    )


# ---------------------------------------------------------------------------
# Structure and provenance
# ---------------------------------------------------------------------------


def test_the_script_fails_fast_and_names_the_az_cli():
    out = _script()
    assert out.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in out
    # The dependency check must precede any command, or a missing `az` surfaces as a
    # confusing failure partway through a run rather than as a clear one at the start.
    assert out.index("command -v az") < out.index("az storage account update")


def test_the_header_names_azremgen_not_awsremgen():
    """Provenance and the modifies-Azure warning, in Azure's own terms.

    Note what is *not* asserted: that "AWS" never appears. The subscription guard
    mentions the AWS script on purpose, to correct a reviewer who knows that artifact
    and would otherwise assume this one also refuses on an active-scope mismatch. A
    blanket ban on the word would forbid that warning, so the assertions below are
    about the things that would actually mislead -- the command name, and any `aws`
    command in the body.
    """
    out = _script()
    assert "Generated by azremgen" in out
    assert "awsremgen" not in out
    assert "MODIFIES AZURE RESOURCES" in out
    assert "MODIFIES AWS" not in out
    # No AWS *command* anywhere: the mentions of AWS are prose in comments, and a
    # runnable `aws` line would be a genuine defect. Checked on the non-comment lines
    # so the deliberate prose cannot mask it.
    code = [ln for ln in out.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    offenders = [ln for ln in code if "aws " in ln]
    assert not offenders, f"an aws command appears in an Azure script: {offenders}"


def test_the_cli_requirement_comes_from_the_provider_descriptor():
    """The version requirement must not be a second independent literal.

    The descriptor states it (for the run README) and the header states it (for
    someone opening one script alone). Two literals drift the first time the minimum
    version changes, and the reader of the stale one has no way to tell.
    """
    from remgen.providers.azure import AZURE

    out = render_cli_script(
        [(_recipe(), _finding())],
        version=VERSION,
        generated_at=STAMP,
        unit=_unit([(_recipe(), _finding())]),
        cli_requirement=AZURE.cli_requirement,
    )
    assert AZURE.cli_requirement in out
    # And the real seam, not just this direct call: what `core` invokes must agree.
    via_provider = AZURE.render_shell(
        [(_recipe(), _finding())],
        version=VERSION,
        generated_at=STAMP,
        unit=_unit([(_recipe(), _finding())]),
    )
    assert AZURE.cli_requirement in via_provider


def test_an_empty_pair_list_is_still_a_valid_script_that_does_nothing():
    out = _script([], unit=False)
    assert out.startswith("#!/usr/bin/env bash")
    assert "No remediable findings were supplied." in out
    assert "az storage account update" not in out
    # No guard either: there is nothing to guard, and a preflight in a script that
    # changes nothing would demand credentials for no reason.
    assert "expected_subscription" not in out


def test_safest_commands_precede_riskier_ones():
    safe = (_recipe(policy_id="p-safe", title="Safe thing"), _finding(name="sa1"))
    risky = (
        _recipe(
            policy_id="p-risky",
            title="Risky thing",
            reversible=False,
            reverse_hint="",
            data_path_impact=True,
        ),
        _finding(name="sa2"),
    )
    # Riskier first in the input, so passing cannot be an artifact of input order.
    out = _script([risky, safe])
    assert out.index("SAFEST") < out.index("Safe thing")
    assert out.index("Safe thing") < out.index("Risky thing")


def test_each_policy_is_described_once_however_many_resources_it_covers():
    pairs = [(_recipe(), _finding(name=f"sa{n}")) for n in range(4)]
    out = _script(pairs)
    assert out.count("Policy ID: aaaaaaaa-1111-2222-3333-444444444444") == 1
    assert out.count("Resources: 4") == 1
    assert out.count("az storage account update") == 4


def test_each_command_records_the_location_it_applies_to():
    # A script never spans subscriptions but may span locations, so the location has
    # to appear per resource -- it is not implied by the filename.
    pairs = [
        (_recipe(), _finding(name="sa1", region="eastus")),
        (_recipe(), _finding(name="sa2", region="westeurope")),
    ]
    out = _script(pairs)
    assert "(eastus)" in out and "(westeurope)" in out


# ---------------------------------------------------------------------------
# The subscription guard -- deliberately NOT the AWS account guard
# ---------------------------------------------------------------------------


def test_the_guard_checks_reachability_and_does_not_refuse_on_a_different_active_sub():
    """The deliberate inversion of the AWS behaviour, asserted so it is not "fixed".

    The AWS script exits non-zero when the active account differs from the target,
    and that is right for AWS: a credential set names exactly one account, so a
    mismatch means the commands would hit the wrong one. Azure is different in a way
    that matters -- one login spans subscriptions and ``--subscription`` is a global
    argument -- so the target is a property of each command rather than of ambient
    state.

    Refusing on a mismatch here would reject a user whose default is a different
    subscription they legitimately hold, *and* would imply the active subscription is
    what gets changed, which the explicit flags make false. So the guard asserts
    reachability instead, and merely reports a mismatch.
    """
    out = _script()
    assert "az account list" in out, "reachability is not checked"
    # The mismatch branch must be informational. Asserted by its own text and by the
    # absence of an exit in it, because "prints a note" and "prints a note then
    # exits" are indistinguishable from a substring check for the note alone.
    assert "Proceeding." in out
    active_branch = out[out.index('if [[ "$active_subscription"') :]
    branch_body = active_branch[: active_branch.index("\nfi")]
    assert "exit" not in branch_body, f"the mismatch branch exits:\n{branch_body}"


def test_the_guard_says_why_it_differs_from_the_aws_script():
    # A reviewer who knows the AWS artifact will assume this one refuses on mismatch.
    # The artifact has to correct that assumption itself; a docstring cannot reach
    # someone reading a generated file.
    out = _script()
    assert "AWS script" in out
    assert "does NOT require the subscription to be your active one" in out


def test_a_scoped_script_refuses_before_any_change_when_not_logged_in():
    out = _script()
    # Ordering is the property: the login check must precede the first mutating
    # command, not merely appear somewhere in the file.
    assert out.index("az account show") < out.index("az storage account update")
    assert "Run 'az login'" in out


def test_an_unscoped_script_has_no_guard_and_no_subscription_promise():
    """Without a unit there is no subscription to guard, so it must not claim one.

    This is the shape that would be easy to get wrong in the opposite direction:
    emitting the guard text with an empty ``expected_subscription`` would produce a
    script that compares against "" and refuses always, or worse, passes always.
    """
    out = _script(unit=False)
    assert "expected_subscription" not in out
    assert "az account list" not in out
    assert "Scope:" not in out


# ---------------------------------------------------------------------------
# The pinning contract the guard is relaxed on
# ---------------------------------------------------------------------------


def test_a_command_that_omits_the_subscription_is_refused():
    """The promise in the header is enforced, not asserted.

    The script tells the reader every command names its subscription, and the guard
    is deliberately relaxed *because* of that. If a recipe omitted the flag, the
    command would inherit whichever subscription the shell had selected and the
    relaxed guard would not catch it -- the two decisions are coupled, so the
    coupling is enforced at render time.

    This is the "comment that proves one component safe" failure mode: a reader who
    sees the promise stops checking the commands. So the promise is a check.
    """
    unpinned = _recipe(template="az storage account update --ids {resource_id} --https-only true")
    with pytest.raises(SubscriptionNotPinnedError) as exc:
        render_cli_script(
            [(unpinned, _finding())], version=VERSION, generated_at=STAMP, unit=_unit([])
        )
    msg = str(exc.value)
    assert "--subscription" in msg
    assert unpinned.policy_id in msg, "the error does not name the offending recipe"
    assert "cli_template" in msg, "the error does not say how to fix it"


def test_the_pinning_check_also_applies_to_a_standalone_single_command():
    # render_one is public and reachable independently, so the check cannot live only
    # in the whole-script path.
    with pytest.raises(SubscriptionNotPinnedError):
        render_one(_recipe(template="az storage account update --ids {resource_id}"), _finding())


def test_the_rendered_command_targets_the_finding_s_subscription():
    out = _script()
    assert f"--subscription {SUB}" in out
    assert OTHER_SUB not in out


# ---------------------------------------------------------------------------
# Critical caveats reach the Azure artifact too
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("recipe", azure_recipes(), ids=lambda r: r.policy_id)
def test_shipped_critical_caveats_render_inline_in_the_azure_script(recipe):
    """The shipped Azure set, not a constructed recipe.

    ``tests/test_artifacts.py`` proves the mechanism and parametrizes over the *AWS*
    registry, so it cannot see that five Azure recipes rely on it -- disabling SFTP,
    local-user authentication, plain HTTP, TLS 1.0/1.1, and cross-tenant replication all
    withdraw something that works today while deriving to ``safest``. Without this test
    an Azure-side regression in the shell generator would be caught only by AWS
    coverage, or not at all if the two shell modules ever diverge.

    Asserted against unwrapped text: ``comment_block`` wraps caveat prose to a column,
    so a present caveat is not a literal substring of the output.
    """
    if not recipe.critical_caveats:
        pytest.skip(f"{recipe.policy_id} declares no critical caveats")
    pairs = [(recipe, _finding())]
    flat = re.sub(r"\s+", " ", re.sub(r"(?m)^\s*#\s?", "", _script(pairs)))
    for caveat in recipe.critical_caveats:
        assert caveat in flat, f"critical caveat missing from the Azure script: {caveat!r}"


def test_at_least_one_shipped_azure_recipe_exercises_the_test_above():
    # The parametrized test skips per recipe, so a set that promoted nothing would
    # report all-skipped as success. This is the floor that makes it real.
    promoted = [r for r in azure_recipes() if r.critical_caveats]
    assert len(promoted) >= 5, (
        f"only {len(promoted)} Azure recipe(s) promote a critical caveat; 5 did when this "
        f"was written, so the test above is now largely skipped"
    )


# ---------------------------------------------------------------------------
# The artifact as bash, not as a string
# ---------------------------------------------------------------------------


def test_the_generated_script_is_syntactically_valid_bash(tmp_path):
    """Parsed by a real shell, because substring assertions accept broken scripts.

    Every other test here checks that text is present. None of them would notice an
    unbalanced quote in the guard, which is exactly the kind of defect that makes an
    artifact fail at the moment someone runs it.
    """
    bash = shutil.which("bash")
    assert bash, "bash is required to validate the generated artifact"
    path = tmp_path / "remediate.sh"
    path.write_text(_script(), encoding="utf-8")
    done = subprocess.run([bash, "-n", str(path)], capture_output=True, text=True)
    assert done.returncode == 0, f"generated script is not valid bash:\n{done.stderr}"


def test_a_resource_id_with_a_shell_metacharacter_never_reaches_the_script():
    # Defence in depth: `Finding` rejects these at construction, so this asserts the
    # boundary holds rather than testing the generator's escaping -- there is none,
    # deliberately, because the allowlist refuses instead of escaping.
    from remgen.core.model import UnsafeIdentifierError

    with pytest.raises(UnsafeIdentifierError):
        Finding(
            policy_id="aaaaaaaa-1111-2222-3333-444444444444",
            resource_id="/subscriptions/x; az group delete --name prod --yes",
            region="eastus",
            account_id=SUB,
        )
