"""End-to-end tests for ``azremgen``, the second cloud.

These exist for a reason beyond Azure. The shared pipeline was written against one
provider, and an abstraction validated against one instance is a guess -- so the
value of these tests is that they run the *same* `remgen.core.cli` down a different
provider's descriptor and check the output describes the cloud the user asked for.
Three real defects were found this way, all of them in `core` rather than in Azure:

* ``verify`` printed "All 0 recipe(s) match the current Azure API definitions" and
  exited 0 on a provider with no recipes -- a vacuous pass on a check that examined
  nothing, and the exact state a new provider starts in.
* The CLI-surface axis returned 0 while printing nothing at all, so ``verify``
  showed two sections where the command documents three.
* ``--help`` told an Azure user their HCL was split by "region", which is neither
  Azure's word nor true of ``azurerm``.

``azremgen`` now ships recipes, and the tests that used to pin the zero-coverage
behaviour still pin it -- against a **descriptor with its recipe set emptied**, via
:func:`_no_coverage`, rather than against the real provider. That substitution is the
point rather than a workaround. Every defect above is a property of *core* reached
through a provider with no recipes, which is the state every future cloud starts in;
asserting it against real Azure coverage would have been an accident of timing, and
deleting the tests when Azure gained recipes would have retired the regression cover
for the next cloud along with it.

The end-to-end tests below use the real recipe set, so what they assert is that the
same pipeline emits Azure remediations described in Azure's vocabulary.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess

import pytest

from remgen.core.cli import main as core_main
from remgen.providers.azure import AZURE
from remgen.providers.azure.cli import main

from .conftest import AZURERM_PROVIDER_TF, TOFU


def _no_coverage(*, argv: list[str]) -> int:
    """Run ``azremgen`` against an Azure descriptor whose recipe set is empty.

    Keeps the zero-coverage regressions alive now that Azure has recipes. Everything
    else about the descriptor is the real thing -- the same command name, nouns and
    verifiers -- because what is being tested is how ``core`` reports an axis that
    examined nothing, and a hand-built stub descriptor could differ from a real one in
    the field that matters.
    """
    empty = dataclasses.replace(AZURE, all_recipes=lambda: (), get_recipe=lambda _pid: None)
    return core_main(empty, argv)


#: Real Azure shapes. The resource ids are full ARM paths and the scope is a
#: subscription UUID -- both are what an Azure findings export actually contains, and
#: the leading '/' on a resource id is only accepted because `validate_identifier`
#: permits it. Using AWS-shaped values here would test nothing about Azure.
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"

#: Policy ids no recipe covers, which is what these are for: the zero-coverage
#: reporting tests need findings that reach the unsupported path, and they must keep
#: reaching it as Azure gains recipes. Deliberately not real ids -- pointing them at
#: a shipped policy would silently convert those tests into coverage tests.
FINDINGS = [
    {
        "policyId": "aaaaaaaa-1111-2222-3333-444444444444",
        "resourceId": (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod"
            f"/providers/Microsoft.Storage/storageAccounts/mystorageacct"
        ),
        "region": "eastus",
        "accountId": SUBSCRIPTION,
    },
    {
        "policyId": "bbbbbbbb-1111-2222-3333-444444444444",
        "resourceId": (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod"
            f"/providers/Microsoft.Sql/servers/mysqlsrv"
        ),
        "region": "westeurope",
        "accountId": SUBSCRIPTION,
    },
]

#: One finding per shipped recipe, for the tests that must produce real artifacts.
#:
#: Built from ``all_recipes()`` rather than written out, and the resource ids are keyed
#: on the recipe's own ``hcl.resource_type`` -- so a new recipe is exercised here the
#: day it lands rather than the day someone remembers to add a fixture. A hand-written
#: list is how Azure ended up with a suite that passed while ``generate`` had never
#: once emitted an Azure artifact.
#:
#: Most shipped recipes target one storage account *deliberately*: that is what makes
#: ``group_targets`` merge in the end-to-end path, so a merge that produced unparseable
#: HCL fails a real ``tofu validate`` here.
_ARM_IDS = {
    "azurerm_storage_account": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod"
        f"/providers/Microsoft.Storage/storageAccounts/prodlogs01"
    ),
    "azurerm_mssql_database": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod"
        f"/providers/Microsoft.Sql/servers/mysqlsrv/databases/appdb"
    ),
}

#: ARM ids for recipes that ship **without** an HCL target, keyed by ``api.service``.
#:
#: A CLI-only recipe still has to appear in these end-to-end tests -- it renders a real
#: command into the real script, and that is the axis it does have. But it carries no
#: ``hcl.resource_type`` to key a fixture on, so the service name is the key instead.
#: Separate from ``_ARM_IDS`` rather than merged: keying one dict by two different
#: things would make a missing entry look like a present one for the other kind.
_CLI_ONLY_ARM_IDS = {
    "storage": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod"
        f"/providers/Microsoft.Storage/storageAccounts/prodlogs01"
    ),
}


def _covered_findings() -> list[dict]:
    records = []
    for recipe in AZURE.all_recipes():
        if recipe.hcl is None:
            # A deliberate CLI-only recipe. The trusted-services bypass declines the
            # HCL axis because `network_rules.default_action` is Required and a finding
            # cannot supply it; see the rationale in recipes/storage.py. It must still
            # be exercised here, because its `az` command is generated like any other.
            resource_id = _CLI_ONLY_ARM_IDS.get(recipe.api.service)
            assert resource_id, (
                f"{recipe.policy_id} is CLI-only and no ARM id fixture exists for "
                f"service {recipe.api.service!r}. Add one to _CLI_ONLY_ARM_IDS, or the "
                f"end-to-end tests silently stop covering this recipe."
            )
            records.append(
                {
                    "policyId": recipe.policy_id,
                    "resourceId": resource_id,
                    "region": "eastus",
                    "accountId": SUBSCRIPTION,
                }
            )
            continue
        resource_id = _ARM_IDS.get(recipe.hcl.resource_type)
        assert resource_id, (
            f"no ARM id fixture for {recipe.hcl.resource_type}. A recipe was added for a "
            f"resource type this file cannot address, so the end-to-end tests would skip "
            f"it silently -- add an id of the right shape to _ARM_IDS."
        )
        records.append(
            {
                "policyId": recipe.policy_id,
                "resourceId": resource_id,
                "region": "eastus",
                "accountId": SUBSCRIPTION,
            }
        )
    return records


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("REMGEN_CACHE_DIR", str(tmp_path / "cache"))
    return tmp_path


def _findings(env) -> str:
    path = env / "azure-findings.json"
    path.write_text(json.dumps(FINDINGS), encoding="utf-8")
    return str(path)


def _covered(env) -> str:
    path = env / "azure-covered.json"
    path.write_text(json.dumps(_covered_findings()), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# verify -- the vacuous-pass fix
# ---------------------------------------------------------------------------


def test_verify_reports_nothing_to_check_rather_than_a_pass(env, capsys):
    """A provider with no recipes must not report that all of them passed.

    Regression for the defect this file's docstring lists first. Every axis iterates
    the recipe set, so an empty set passed all three and printed "All 0 recipe(s)
    match the current Azure API definitions" -- a sentence a reader cannot
    distinguish from a real pass, on a check that examined nothing. The drift canary
    would have reported green for Azure until the first recipe landed.

    Exit 0 is correct and deliberate: zero recipes is the expected state for a
    provider under construction, so failing would mean a cloud cannot be added
    incrementally. The requirement is on what it *says*, not on the code.

    Run against an emptied descriptor, because Azure has recipes now. See
    :func:`_no_coverage`: the defect is in ``core``'s reporting of an empty set, which
    is what the next cloud will start with.
    """
    assert _no_coverage(argv=["verify"]) == 0
    out = capsys.readouterr().out
    assert "nothing to check" in out
    assert "This is not a pass" in out
    # The specific sentence that used to appear. Asserted absent rather than just
    # asserting the new text present: adding an honest line while leaving the
    # misleading one in place would satisfy a presence-only check.
    assert "All 0 recipe(s)" not in out, f"still claims a vacuous pass:\n{out}"


def test_verify_says_so_on_every_one_of_the_four_axes(env, capsys):
    """All four axes must account for themselves, including the one with no verifier.

    ``verify`` documents four axes and a canary branches on which failed. The
    CLI-surface axis returned 0 while printing nothing, so the output showed two
    sections -- a reader counting them would conclude the third had passed, or would
    not know it existed. Asserted by looking for each axis's own label, because
    "three sections appeared" is what actually has to hold.

    This test used to also assert "did not run" appeared, for the CLI axis that had no
    verifier. It has one now, so that string would be a false statement about a check
    that really runs -- the axis reports "nothing to check" instead, which is the
    honest reason it examined nothing. The branch that prints "did not run" is still
    reachable for a provider with no CLI verifier and is covered in
    ``tests/test_cli.py`` against a descriptor with that field cleared, so removing the
    assertion here does not drop it.

    Also run against an emptied descriptor now -- see :func:`_no_coverage`. The
    four-sections requirement is asserted against the *real* recipe set too, in
    ``test_verify_reports_all_four_axes_against_the_real_recipe_set`` below; this one
    keeps the zero-coverage half, where a silent axis is easiest to miss.
    """
    assert _no_coverage(argv=["verify"]) == 0
    out = capsys.readouterr().out
    assert "service models" in out, "the API axis did not report"
    assert "HCL: " in out, "the HCL axis did not report"
    assert "CLI: " in out, "the CLI-surface axis did not report"
    assert "Policies: " in out, "the policy-catalog axis did not report"
    # The implemented axis must name the CLI it asked, or a drift report cannot be
    # reproduced -- and, having examined nothing, must still not read as a pass.
    cli_section = out.split("CLI: ", 1)[1]
    assert "Flag source:" in cli_section, "the CLI axis ran without saying what it asked"
    assert "nothing to check" in cli_section
    assert "This is not a pass" in cli_section
    assert "did not run" not in cli_section, (
        "the axis has a verifier now; 'did not run' would misreport a check that ran"
    )
    # The policy axis has no catalog here, so it must say it did not run -- and must not
    # borrow the API axis's "nothing to check", which would name the wrong reason.
    policy_section = out.split("Policies: ", 1)[1]
    assert "did NOT run" in policy_section
    assert "no --catalog given" in policy_section


def test_verify_reports_all_four_axes_against_the_real_recipe_set(env, capsys):
    """The other half of the test above: four axes must report for real recipes too.

    Not a duplicate. The test above proves an empty set cannot read as a pass; this one
    proves a non-empty set is actually examined, which is the failure the "nothing to
    check" path could otherwise mask -- a bug that skipped every recipe would print
    four well-formed sections and the zero-coverage assertions would not notice.

    Deliberately asserts the count and not the verdicts. Whether the recipes still
    match Azure is a question for the live axes (``tests/test_azure_drift.py``,
    ``tests/test_azure_cli_surface.py``) and for the drift canary; pinning "ok" here
    would make this end-to-end test fail when Azure changed something, which is
    information the canary is for and this test is not.
    """
    main(["verify"])
    out = capsys.readouterr().out
    count = len(AZURE.all_recipes())
    assert count, "this test is vacuous without recipes"
    # The HCL axis reports the number of recipes with an HCL target, which is fewer than
    # the recipe count once a CLI-only recipe ships. Derived, not offset by a constant.
    with_hcl = sum(1 for r in AZURE.all_recipes() if r.hcl is not None)
    assert with_hcl, "no recipe has an HCL target; the HCL section would be vacuous"
    assert f"Verifying {count} recipe(s)" in out
    assert f"HCL: checking {with_hcl} recipe(s)" in out
    assert f"CLI: checking {count} recipe(s)" in out
    assert f"Policies: checking {count} recipe(s)" in out
    assert "nothing to check" not in out, (
        "a real recipe set reported as examining nothing; the axis is skipping recipes"
    )


# ---------------------------------------------------------------------------
# generate -- no coverage, reported honestly, nothing written
# ---------------------------------------------------------------------------


def test_generate_writes_nothing_and_reports_every_finding_as_unsupported(env, capsys):
    """With no recipes, every finding must be counted as unsupported, not dropped.

    The run summary promises its counts reconcile: records read = usable + rejected,
    and usable = written + withheld + no-recipe. That promise is easiest to break at
    zero coverage, where "0 written" and "2 read" have to be connected by something
    the reader can see.
    """
    out_dir = env / "art"
    assert main(["generate", "--findings", _findings(env), "--out", str(out_dir), "-v"]) == 0
    captured = capsys.readouterr().out

    assert "Records read:         2" in captured
    assert "no recipe:          2" in captured
    assert "Coverage is intentionally partial" in captured
    # Both policy ids listed under -v, so a reader can act on them.
    for record in FINDINGS:
        assert record["policyId"] in captured

    # Nothing written: no artifacts, and no README or manifest either -- those are
    # written only when there is at least one output unit, so their absence is the
    # signal that this run produced nothing rather than produced empty files.
    assert not list(out_dir.rglob("*.sh"))
    assert not list(out_dir.rglob("*.tf"))


def test_generate_never_claims_to_have_changed_azure(env, capsys):
    # The closing line names the cloud. It read "This tool made no AWS changes"
    # regardless of provider until `display_name` was threaded through, which is a
    # correct statement about the wrong cloud.
    main(["generate", "--findings", _findings(env), "--out", str(env / "art")])
    captured = capsys.readouterr().out
    assert "made no Azure changes" in captured
    assert "AWS" not in captured, f"AWS is named in an Azure run:\n{captured}"


def test_azure_resource_ids_and_subscription_ids_are_accepted(env, capsys):
    """The step-1 validator changes, proved through the real command.

    A full ARM resource id begins with '/' and a subscription id is a UUID. Both had
    to be permitted without loosening the rule that guards filenames -- and this is
    the test that would fail if a future tightening of `validate_identifier` made
    Azure's primary identifier unrepresentable. Rejections are counted in the
    summary, so their absence is checkable.
    """
    main(["generate", "--findings", _findings(env), "--out", str(env / "art")])
    captured = capsys.readouterr().out
    assert "rejected" not in captured, f"a valid Azure finding was rejected:\n{captured}"
    assert "usable findings:    2" in captured


# ---------------------------------------------------------------------------
# generate -- real coverage, real artifacts, checked by the real toolchain
#
# The other half, and its absence was a genuine gap: every fixture above uses a
# policy id no recipe covers, so before this section `azremgen generate` had never
# once written an Azure artifact under test. The recipes were verified against the
# SDKs, the `azurerm` schema and `az --help`, and each generator was unit-tested --
# but nothing had run the whole path and looked at the file that came out.
# ---------------------------------------------------------------------------


def test_generate_writes_a_script_and_a_tf_for_every_shipped_recipe(env, capsys):
    """The path that had no coverage: real recipes, real files, on disk.

    Asserts the summary reconciles *and* that the files exist, because those fail
    separately. A run that counted four remediations and wrote nothing would satisfy
    the counts, and the layout writes README and manifest only when there is at least
    one output unit -- so their presence is the signal that a unit was really built.
    """
    out_dir = env / "art"
    findings = _covered(env)
    count = len(AZURE.all_recipes())
    assert count, "this test is vacuous without recipes"

    assert main(["generate", "--findings", findings, "--out", str(out_dir), "-v"]) == 0
    captured = capsys.readouterr().out

    assert f"Records read:         {count}" in captured
    assert f"Remediations written: {count}" in captured
    assert "no recipe" not in captured, (
        f"a shipped recipe did not match its own policy id:\n{captured}"
    )

    scripts = list(out_dir.rglob("*.sh"))
    tfs = list(out_dir.rglob("*.tf"))
    assert scripts, "no az script was written for a run that reported remediations"
    assert tfs, "no .tf was written for a run that reported remediations"
    assert (out_dir / "manifest.json").exists()
    assert (out_dir / "README.md").exists()
    # Filed under the cloud's own directory, which is what makes a multi-cloud
    # artifacts/ directory reviewable rather than a pile.
    assert all("azure" in part.parts for part in scripts + tfs)


def test_every_generated_command_carries_ids_and_a_subscription(env):
    """The pinning contract, asserted on the emitted script rather than the template.

    ``tests/test_azure_shell.py`` proves the generator refuses an unpinned template;
    this proves what the *shipped* recipes actually render. Both matter: a template
    could be pinned and still lose its subscription to a rendering bug, and that
    failure is invisible until someone runs the script against the wrong login.
    """
    out_dir = env / "art"
    main(["generate", "--findings", _covered(env), "--out", str(out_dir)])
    for script in out_dir.rglob("*.sh"):
        for line in script.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.startswith("az "):
                continue
            assert "--ids " in stripped, f"an az command with no --ids: {stripped}"
            assert f"--subscription {SUBSCRIPTION}" in stripped, (
                f"an az command that does not pin its subscription: {stripped}"
            )


def test_the_generated_script_is_syntactically_valid(env):
    # `bash -n` rather than a substring: a heredoc or quoting bug produces output that
    # reads correctly and does not run, which is the whole class of defect a review of
    # the text cannot catch.
    bash = shutil.which("bash")
    assert bash, "bash is required to check the generated artifact"
    out_dir = env / "art"
    main(["generate", "--findings", _covered(env), "--out", str(out_dir)])
    scripts = list(out_dir.rglob("*.sh"))
    assert scripts, "nothing was generated to check"
    for script in scripts:
        done = subprocess.run(  # noqa: S603
            [bash, "-n", str(script)], capture_output=True, text=True
        )
        assert done.returncode == 0, f"{script.name} is not valid bash:\n{done.stderr}"


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_the_generated_hcl_validates_against_the_real_azurerm_provider(
    env, azurerm_workspace_template
):
    """The oracle no substring assertion can replace, on the merged Azure block.

    Three shipped recipes target one storage account, so this file is a *merged*
    block -- the case where an attribute name that does not exist, a value of the wrong
    type, or a missing required argument surfaces. Two of those were found this way
    during step 5: ``https_traffic_only_enabled`` is the azurerm name (not the SDK's
    ``enable_https_traffic_only``), and ``azurerm_storage_account`` has five required
    arguments a finding cannot supply, which is why the block carries typed placeholders.

    ``fmt -check`` is asserted alongside ``validate`` because the committed sample is
    compared byte-for-byte: output that parses but is not canonically formatted turns
    the sample gate red for a reason that looks like a real diff.
    """
    if azurerm_workspace_template is None:
        pytest.fail("tofu is present but the azurerm workspace could not be built")

    out_dir = env / "art"
    main(["generate", "--findings", _covered(env), "--out", str(out_dir)])
    files = sorted(out_dir.rglob("*.tf"))
    assert files, "no HCL was generated"

    for index, tf_file in enumerate(files):
        work = env / "work" / f"tf{index}"
        work.mkdir(parents=True, exist_ok=True)
        shutil.copy(tf_file, work / "main.tf")
        (work / "provider.tf").write_text(AZURERM_PROVIDER_TF, encoding="utf-8")
        # symlinks=True: the tree points into the shared plugin cache, and
        # dereferencing would copy the whole provider per workspace.
        shutil.copytree(
            azurerm_workspace_template / ".terraform", work / ".terraform", symlinks=True
        )
        lock = azurerm_workspace_template / ".terraform.lock.hcl"
        if lock.exists():
            shutil.copy(lock, work / ".terraform.lock.hcl")

        fmt = subprocess.run(  # noqa: S603
            [TOFU, "fmt", "-check", "-no-color", "main.tf"],
            cwd=work,
            capture_output=True,
            text=True,
        )
        assert fmt.returncode == 0, f"generated HCL is not canonically formatted:\n{fmt.stdout}"

        validate = subprocess.run(  # noqa: S603
            [TOFU, "validate", "-no-color"], cwd=work, capture_output=True, text=True
        )
        assert validate.returncode == 0, (
            f"{tf_file.name} failed a real azurerm validate:\n{validate.stdout}"
        )


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_verify_passes_all_axes_against_the_real_azure_toolchain(
    env, capsys, real_azurerm_schema_path
):
    """All four Azure axes, green, against real inputs, through the real command.

    The Azure counterpart of ``test_cli.py``'s toolchain test, and the point is the
    same: each axis has its own unit tests, but CI and the drift canary branch on the
    *combined* exit code. An axis returning a code the combiner mishandles would leave
    every per-axis test green.

    Azure adds a reason of its own. Its four axes read four unrelated sources -- the
    SDKs bundled in ``az``, an ``azurerm`` schema document, ``az --help``, and a Tenable
    policy export -- so this is the only test that confirms one machine can satisfy all
    four at once.
    """
    if real_azurerm_schema_path is None:
        pytest.fail("tofu is present but no azurerm schema was produced; the HCL axis never ran")

    count = len(AZURE.all_recipes())
    # The HCL axis checks only the recipes that *have* an HCL target, so its count is
    # not the recipe count once a CLI-only recipe ships. Derived rather than adjusted by
    # a constant: hardcoding "count - 1" would pass today and silently stop checking the
    # real number the next time a CLI-only recipe lands.
    with_hcl = sum(1 for r in AZURE.all_recipes() if r.hcl is not None)
    assert with_hcl, "no recipe has an HCL target; the HCL axis would examine nothing"
    # A catalog is passed so the fourth axis actually runs. Derived from the recipe set
    # rather than typed: this file has no tenant to export from, and the axis's job here
    # is to prove the combiner handles four codes, not to re-confirm the ids upstream.
    catalog = env / "azure-catalog.json"
    catalog.write_text(
        json.dumps(
            [
                {"id": r.policy_id, "title": r.policy_title, "category": "Data"}
                for r in AZURE.all_recipes()
            ]
        ),
        encoding="utf-8",
    )
    code = main(
        [
            "verify",
            "--provider-schema",
            str(real_azurerm_schema_path),
            "--catalog",
            str(catalog),
        ]
    )
    captured = capsys.readouterr().out
    assert code == 0, captured
    assert f"Verifying {count} recipe(s) against Azure service models." in captured
    assert f"All {with_hcl} HCL target(s) match the current provider schema." in captured
    assert f"All {count} recipe(s) render commands the CLI accepts." in captured
    assert f"All {count} recipe(s) are keyed to a policy that still exists." in captured
    assert "nothing to check" not in captured, "an axis examined nothing and this still passed"


def test_the_aws_catalog_is_could_not_check_for_azure_too(env, capsys):
    """The wrong-cloud guard must be symmetric, not written around AWS.

    The guard lives in shared ``core`` code and is provoked from the AWS side in
    ``tests/test_cli.py``; this is the other direction. Worth both, because the message
    names the cloud from the descriptor -- ``provider.display_name`` -- and a hardcoded
    "AWS" there would tell an Azure user to confirm they had AWS's export, which is
    exactly the wrong instruction and would read as a tool defect.

    The catalog is real AWS ids, so this is the mistake a user actually makes: two
    exports in a downloads folder, and the wrong one on the command line.
    """
    from remgen.providers.aws import all_recipes as aws_recipes

    catalog = env / "aws-catalog.json"
    catalog.write_text(
        json.dumps(
            [
                {"id": r.policy_id, "title": r.policy_title, "category": "Data"}
                for r in aws_recipes()
            ]
        ),
        encoding="utf-8",
    )
    code = main(["verify", "--catalog", str(catalog)])
    captured = capsys.readouterr().out
    assert code == 4, f"a wrong-cloud export must be 'could not check', got {code}"
    assert "Confirm the export is Azure's" in captured, (
        "the message named the wrong cloud; it must come from the descriptor"
    )
    assert "AWS" not in captured.split("Policies: checking", 1)[1], (
        "the Azure policy axis must not mention AWS"
    )


# ---------------------------------------------------------------------------
# the cross-subscription escape
#
# Found by generating a mismatched finding, not by reading the code: `--ids` carries its
# own subscription and `az` resolves it in preference to `--subscription`, so a finding
# whose resource_id names subscription B and whose accountId is A produced a script
# headed "Scope: subscription A", with a preflight confirming A, that mutated a resource
# in B. Exit 0, artifacts written, nothing warned.
#
# Every test below asserts on the *artifact or the exit path*, never on
# `AZURE.scope_conflict` alone -- a correct predicate that nothing calls is the shape of
# the bug that was there before.
# ---------------------------------------------------------------------------

_OTHER_SUBSCRIPTION = "99999999-9999-9999-9999-999999999999"


def _mismatched_finding() -> dict:
    """A well-formed finding whose ARM id names a different subscription.

    Takes the first recipe that *has* an HCL target rather than simply the first recipe:
    ``all_recipes()`` is ordered by title, and a CLI-only recipe sorting first would make
    this fixture raise ``AttributeError`` on ``None`` -- turning every scope-conflict test
    into an error about a fixture rather than a statement about scope handling.
    """
    recipe = next(r for r in AZURE.all_recipes() if r.hcl is not None)
    resource_id = _ARM_IDS[recipe.hcl.resource_type].replace(SUBSCRIPTION, _OTHER_SUBSCRIPTION)
    assert _OTHER_SUBSCRIPTION in resource_id, "the fixture failed to substitute a subscription"
    return {
        "policyId": recipe.policy_id,
        "resourceId": resource_id,
        "region": "eastus",
        "accountId": SUBSCRIPTION,
    }


def test_a_finding_whose_arm_id_names_another_subscription_writes_no_artifact(env, capsys):
    """The escape itself: nothing may be emitted for a contradictory finding.

    Asserted as "no file mentions the other subscription" rather than "no files exist",
    because the failure being guarded against is not an empty run -- it is a run that
    writes a plausible script whose commands point somewhere the header disclaims.
    """
    path = env / "mismatch.json"
    path.write_text(json.dumps([_mismatched_finding()]), encoding="utf-8")
    out_dir = env / "art"
    code = main(["generate", "--findings", str(path), "--out", str(out_dir)])
    out = capsys.readouterr().out
    assert code == 0, out
    for artifact in list(out_dir.rglob("*.sh")) + list(out_dir.rglob("*.tf")):
        text = artifact.read_text(encoding="utf-8")
        assert _OTHER_SUBSCRIPTION not in text, (
            f"{artifact.name} targets {_OTHER_SUBSCRIPTION} while its scope guard "
            f"confirms {SUBSCRIPTION}"
        )
    assert "Remediations written: 0" in out


def test_the_conflict_is_reported_and_counted_not_silently_dropped(env, capsys):
    """A refused finding must be visible, and must name both subscriptions.

    The reconciliation the summary promises is the point: a finding that vanished
    between "records read" and "remediations written" reads as already-compliant.
    """
    path = env / "mismatch.json"
    path.write_text(json.dumps([_mismatched_finding()]), encoding="utf-8")
    main(["generate", "--findings", str(path), "--out", str(env / "art")])
    out = capsys.readouterr().out
    assert "scope conflicts:  1" in out, out
    assert "rejected:           1" in out, out
    # Both ids, so the reader can find the offending record in their export rather than
    # being told only that something was wrong.
    assert _OTHER_SUBSCRIPTION in out
    assert SUBSCRIPTION in out
    assert "Records read:         1" in out


def test_a_conflicting_finding_does_not_suppress_the_valid_ones(env, capsys):
    """One bad record must not cost the rest of the run.

    Rejecting per finding rather than failing the run is a deliberate choice, so it is
    tested: the alternative -- exit 2 on the whole file -- would make one malformed
    export row block every correct remediation in it.
    """
    records = _covered_findings() + [_mismatched_finding()]
    path = env / "mixed.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    out_dir = env / "art"
    code = main(["generate", "--findings", str(path), "--out", str(out_dir)])
    out = capsys.readouterr().out
    assert code == 0, out
    assert f"Remediations written: {len(_covered_findings())}" in out, out
    assert "scope conflicts:  1" in out, out
    for artifact in list(out_dir.rglob("*.sh")) + list(out_dir.rglob("*.tf")):
        assert _OTHER_SUBSCRIPTION not in artifact.read_text(encoding="utf-8")


def test_a_differently_cased_subscription_is_not_treated_as_a_conflict(env, capsys):
    """ARM's subscription segment is case-insensitive, so a case difference is not drift.

    A false positive here costs a real remediation for a resource that was never
    ambiguous, which is why the comparison is casefolded rather than exact.
    """
    recipe = AZURE.all_recipes()[0]
    lower = "11111111-1111-1111-1111-1111111111ab"
    resource_id = _ARM_IDS[recipe.hcl.resource_type].replace(SUBSCRIPTION, lower.upper())
    path = env / "cased.json"
    path.write_text(
        json.dumps(
            [
                {
                    "policyId": recipe.policy_id,
                    "resourceId": resource_id,
                    "region": "eastus",
                    "accountId": lower,
                }
            ]
        ),
        encoding="utf-8",
    )
    code = main(["generate", "--findings", str(path), "--out", str(env / "art")])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "scope conflict" not in out, out
    assert "Remediations written: 1" in out, out


def test_a_non_arm_resource_id_is_not_a_conflict(env, capsys):
    """An id that names no subscription cannot contradict one.

    A bare storage-account name is left to ``az`` to reject on its own terms. Rejecting
    it here would refuse input for a reason this check cannot actually establish.
    """
    recipe = AZURE.all_recipes()[0]
    path = env / "bare.json"
    path.write_text(
        json.dumps(
            [
                {
                    "policyId": recipe.policy_id,
                    "resourceId": "prodlogs01",
                    "region": "eastus",
                    "accountId": SUBSCRIPTION,
                }
            ]
        ),
        encoding="utf-8",
    )
    code = main(["generate", "--findings", str(path), "--out", str(env / "art")])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "scope conflict" not in out, out


def test_the_reported_record_number_is_the_input_position(env, capsys):
    """``[record N]`` must mean the same thing for both kinds of rejection.

    Scope conflicts are detected after loading, so the natural index is a position among
    *loaded findings* -- which differs from the input position whenever an earlier record
    failed to parse. Both print under one ``[record N]`` label, and two numbering schemes
    behind one label sends a reader to the wrong line of their export.

    The fixture puts a malformed record first precisely so the two numbers differ: the
    conflicting record is input index 2 but loaded-finding index 1. It also puts a
    *second* malformed record last, so file order and detection order genuinely disagree
    -- with the conflict at the end, appending and sorting produce the same list and the
    ordering half of this test would pass either way.
    """
    recipe = AZURE.all_recipes()[0]
    good = _ARM_IDS[recipe.hcl.resource_type]
    records = [
        # Rejected by the loader: no accountId. Input index 0.
        {"policyId": recipe.policy_id, "resourceId": good, "region": "eastus"},
        # Valid. Input index 1, loaded index 0.
        {
            "policyId": recipe.policy_id,
            "resourceId": good,
            "region": "eastus",
            "accountId": SUBSCRIPTION,
        },
        # The conflict. Input index 2, loaded index 1.
        _mismatched_finding(),
        # Rejected by the loader: no region. Input index 3, and the reason it is here --
        # it must be reported *after* the conflict above.
        {"policyId": recipe.policy_id, "resourceId": good, "accountId": SUBSCRIPTION},
    ]
    path = env / "ordered.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    main(["generate", "--findings", str(path), "--out", str(env / "art")])
    out = capsys.readouterr().out
    assert "[record 2] resource_id names subscription" in out, out
    assert "[record 1] resource_id names subscription" not in out, (
        "the conflict was numbered by its position among loaded findings, not by its "
        "position in the input file"
    )
    # In file order, so the list reads like the input rather than every parse failure
    # first and every scope conflict appended after them.
    positions = [out.index(f"[record {n}]") for n in (0, 2, 3)]
    assert positions == sorted(positions), f"rejections are not listed in input order: {out}"


def test_aws_has_no_scope_conflict_hook_and_that_is_correct(env):
    """The asymmetry is in the clouds, not in the coverage.

    Asserted rather than left implicit because the natural reading of "Azure has a check
    AWS lacks" is that AWS is behind. No AWS identifier this tool renders contains an
    account, so there is nothing for an account id to disagree with, and a shared check
    would pass vacuously on every AWS finding -- which is worse than none, since it would
    look like coverage.
    """
    from remgen.providers.aws import AWS

    assert AWS.scope_conflict is None
    assert AZURE.scope_conflict is not None
    for recipe in AWS.all_recipes():
        assert "{account_id}" not in recipe.cli_template, (
            f"{recipe.policy_id} now interpolates an account into its command; AWS may "
            f"need a scope_conflict hook after all"
        )


# ---------------------------------------------------------------------------
# vocabulary -- correct behaviour described in the wrong cloud's words is a defect
# ---------------------------------------------------------------------------


def test_help_uses_azures_own_nouns_and_not_awss(capsys):
    with pytest.raises(SystemExit):
        main(["generate", "--help"])
    out = capsys.readouterr().out
    assert "subscription" in out
    assert "account" not in out, f"AWS's scope noun leaked into azremgen --help:\n{out}"


def test_help_does_not_claim_hcl_is_split_by_location(capsys):
    """``azurerm`` carries location per resource, so Azure HCL is not split by it.

    The shared help text hardcoded "and HCL also by region" -- wrong noun and wrong
    fact for this provider. A user would look for that split in the filenames and not
    find it, which reads as a bug in the tool.
    """
    with pytest.raises(SystemExit):
        main(["generate", "--help"])
    out = capsys.readouterr().out
    assert "HCL also by" not in out


def test_no_help_text_says_a_azure(capsys):
    """ "a Azure" is wrong, and so was "a AWS" -- the article was hardcoded.

    Whitespace is collapsed before matching, because argparse wraps help text at the
    terminal width and the first instance of this defect survived a substring grep by
    wrapping between the article and the cloud name ("cli (a\\n  Azure CLI ..."). A
    check that reads the unwrapped text would have passed on the broken output, which
    makes this test's normalization the whole point of it rather than a detail.

    Fixed by rephrasing so no article is needed, not by an a/an rule: the choice
    depends on pronunciation rather than spelling, so a first-letter rule would emit
    "an GCP" for a cloud that has not been added yet.
    """
    import re

    # A word-boundary match, not " a Azure". The first version of this test looked for
    # a leading space and silently passed on the real defect, because the text reads
    # "cli (a Azure ..." -- the character before the article is '(', not a space. Found
    # by mutation: restoring the bug left the test green.
    bad = re.compile(r"\ba (AWS|Azure)\b")
    for argv in ([], ["generate"], ["policies"], ["verify"], ["recipes"]):
        with pytest.raises(SystemExit):
            main([*argv, "--help"])
        flat = re.sub(r"\s+", " ", capsys.readouterr().out)
        found = bad.findall(flat)
        assert not found, f"`azremgen {' '.join(argv)} --help` says 'a {found[0]}'"


def test_the_command_names_itself_not_awsremgen(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "azremgen" in out
    assert "awsremgen" not in out


def test_recipes_reports_zero_without_implying_more_exists(capsys):
    # Against an emptied descriptor, since Azure has recipes now: the property is that
    # a provider with none says "0" rather than printing an empty list under a heading
    # that implies coverage. That is the state the next cloud starts in.
    assert _no_coverage(argv=["recipes"]) == 0
    out = capsys.readouterr().out
    assert "0 curated recipe(s)" in out


def test_recipes_lists_every_real_azure_recipe_with_its_tier(capsys):
    """The counterpart: real coverage must be listed, counted, and tiered.

    Pins the count against ``all_recipes()`` rather than a literal, so adding a recipe
    does not fail this test -- but pins that *each* one is named, so a recipe that
    imports and verifies while never reaching the listing is caught. That is the exact
    failure mode the recipes package's discovery exists to prevent, and this is where
    it becomes visible from outside.
    """
    assert main(["recipes"]) == 0
    out = capsys.readouterr().out
    recipes = AZURE.all_recipes()
    assert f"{len(recipes)} curated recipe(s)" in out
    for recipe in recipes:
        assert recipe.policy_title in out
        assert recipe.policy_id in out


def test_policies_requires_a_catalog_and_the_hint_names_azure(capsys):
    # The hint is what a user acts on, and "export the AWS policy catalog" would send
    # an Azure user to the wrong export.
    with pytest.raises(SystemExit):
        main(["policies"])
    err = capsys.readouterr().err
    assert "--catalog" in err
