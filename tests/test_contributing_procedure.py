"""Tests that the contributor-facing procedure docs describe the real tool.

`CONTRIBUTING.md` is executable instructions in prose: it names test functions as the
enforcement for a rule, tells a contributor which flags to pass, and cites exit codes
as evidence a check ran. Every one of those is a claim about code, and none of them
were checked by anything -- the suite tests behaviour, so a doc could name a deleted
test or promise the wrong exit code and stay green forever.

That is not hypothetical. Three documents stated that `verify` without
`--provider-schema` exits `4`. It exits `0`, deliberately and with a comment in
`core/cli.py` explaining why, pinned by
`test_verify_without_a_schema_says_so_and_does_not_claim_a_pass`. So the docs told a
contributor that a green run proved the HCL axis had been checked, in the one case
where it proves the opposite -- undoing in prose the exact misreading the printed
output exists to prevent.

What these tests deliberately do *not* do is check that the prose is good advice.
They check that the things it points at exist and behave as described, which is the
part a machine can settle.
"""

from __future__ import annotations

import pathlib
import re

import pytest

import remgen

REPO = pathlib.Path(remgen.__file__).parent.parent.parent
CONTRIBUTING = REPO / "CONTRIBUTING.md"
README = REPO / "README.md"
ROADMAP = REPO / "ROADMAP.md"
TESTS = pathlib.Path(__file__).parent

DOCS = (CONTRIBUTING, README, ROADMAP)


def _test_functions_defined() -> set[str]:
    """Every test function name defined anywhere in the suite."""
    names: set[str] = set()
    for path in TESTS.rglob("test_*.py"):
        names.update(re.findall(r"^def (test_\w+)", path.read_text(encoding="utf-8"), re.MULTILINE))
    return names


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_test_function_cited_by_a_doc_exists(doc: pathlib.Path) -> None:
    """A doc that cites a test as its enforcement must cite one that exists.

    The failure mode is specific: these citations are how a reader checks that a
    stated rule is enforced rather than merely intended. A renamed test leaves the
    sentence pointing at nothing, and *the suite still passes* -- pytest does not care
    what a document calls a function. So the reader concludes a property is pinned
    when nothing pins it.

    Bare module names (``test_structure.py``) are the `docs-refs` job's business; this
    is about function names, which that job cannot see.
    """
    defined = _test_functions_defined()
    text = doc.read_text(encoding="utf-8")
    # Function names only: a citation ending in `.py` is a file, checked elsewhere.
    cited = {
        name for name in re.findall(r"`?(test_[a-z0-9_]{8,})`?", text) if not name.endswith("_py")
    }
    cited = {c for c in cited if f"{c}.py" not in text}
    missing = sorted(c for c in cited if c not in defined)
    assert not missing, (
        f"{doc.name} cites test function(s) that do not exist: {missing}. Either the "
        f"test was renamed and the doc now points at nothing -- in which case the rule "
        f"it claims to enforce is unenforced as far as any reader can tell -- or the "
        f"citation is a typo. Update the doc, not this test."
    )


def test_contributing_actually_cites_tests_as_enforcement() -> None:
    """The anti-vacuity guard for the check above, placed where citations belong.

    Asserted on `CONTRIBUTING.md` alone rather than per-document: README.md and
    ROADMAP.md legitimately cite none, so requiring every doc to name a test would
    fail them for a style they are entitled to. But if `CONTRIBUTING.md` stops naming
    any, the parametrized check above silently becomes a no-op -- it would iterate an
    empty set and pass -- and this repo's habit is that a check which cannot fail is
    worse than an absent one.
    """
    cited = set(re.findall(r"`(test_[a-z0-9_]{8,})`", CONTRIBUTING.read_text(encoding="utf-8")))
    functions = {c for c in cited if not c.endswith("_py")}
    assert len(functions) >= 3, (
        f"CONTRIBUTING.md cites only {sorted(functions)} as test-backed enforcement. "
        f"Citing tests by name is how a reader distinguishes an enforced rule from an "
        f"intended one; if these were removed on purpose, the check above no longer "
        f"protects anything and should be reconsidered rather than left passing."
    )


def test_contributing_does_not_claim_a_bare_verify_exits_nonzero() -> None:
    """The claim that regressed once, pinned so it cannot regress silently again.

    `verify` with no `--provider-schema` is exit-code-neutral by design: requiring a
    19 MB artifact would make the default invocation fail. The docs are therefore
    obliged to say the *output* carries the signal. A doc that ties exit 4 to a
    missing schema tells a contributor a green run proves the HCL axis was checked,
    which is precisely backwards.
    """
    for doc in DOCS:
        text = re.sub(r"\s+", " ", doc.read_text(encoding="utf-8"))
        for match in re.finditer(r"[^.]*exit(?:s|ed)? `4`[^.]*\.", text):
            sentence = match.group(0)
            # "asked for and could not run" is the true exit-4 case and may mention a
            # schema; what must not appear is exit 4 tied to *not passing the flag*.
            if re.search(
                r"[Ww]ithout (?:one|it|`--provider-schema`)|no provider schema|"
                r"default invocation",
                sentence,
            ):
                pytest.fail(
                    f"{doc.name} ties exit 4 to a missing --provider-schema: "
                    f"{sentence.strip()!r}. A bare `verify` exits 0 and prints "
                    f"'not checked'; exit 4 is for a check that was requested and "
                    f"could not run. Saying otherwise tells a contributor that a "
                    f"green exit code proves the HCL axis ran."
                )


def test_documented_verify_behaviour_without_a_schema_matches_the_docs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run the flagless command and assert what the docs now promise about it.

    Measured rather than asserted from reading: the previous wording was wrong for
    three releases because nobody ran it and compared.
    """
    from remgen.providers.aws.cli import main

    monkeypatch.delenv("REMGEN_TF_SCHEMA", raising=False)
    monkeypatch.setattr("sys.argv", ["awsremgen", "verify"])
    code = main()
    out = capsys.readouterr().out
    hcl = out.split("HCL: checking", 1)[1]

    assert code == 0, (
        "a bare `verify` is exit-code-neutral by design; if this now fails, the code "
        "changed and CONTRIBUTING.md/README.md/ROADMAP.md must be updated together"
    )
    assert "not checked" in hcl, "the unchecked axis must say so, since the exit code will not"
    assert "Schema source:" not in hcl, (
        "the docs tell a contributor to look for `Schema source:` as the evidence the "
        "HCL half ran; it must be absent when it did not"
    )


def test_contributing_points_recipe_authors_at_the_triage_register() -> None:
    """A recipe author must be told that moving the register row is part of the commit.

    The `claims` job compares the register's Shipped table against the recipes in both
    directions, so a contributor who follows CONTRIBUTING.md without touching
    `AWS_POLICY_TRIAGE.md` gets a red build. A procedure doc that leads to a failing
    gate it never mentions is a defect in the doc.
    """
    text = CONTRIBUTING.read_text(encoding="utf-8")
    assert "AWS_POLICY_TRIAGE.md" in text, (
        "CONTRIBUTING.md must name the triage register: it is where a recipe author "
        "gets the policy UUID and the prioritised list, and a CI gate requires the "
        "row to move in the same commit"
    )
    body = text.split("## Adding a recipe", 1)[1].split("\n## ", 1)[0]
    assert "AWS_POLICY_TRIAGE.md" in body, (
        "the register must be named in 'Adding a recipe' itself, not only elsewhere -- "
        "a contributor reads that section and stops"
    )
    assert re.search(r"move|moving|moves", body), (
        "'Adding a recipe' must say the register row moves when the recipe lands, or "
        "the contributor meets the gate as a surprise"
    )


@pytest.mark.parametrize(
    ("subcommand", "flag"),
    [
        ("generate", "--findings"),
        ("generate", "--out"),
        ("generate", "--safety-level"),
        ("verify", "--provider-schema"),
        ("policies", "--unsupported"),
    ],
)
def test_flags_the_docs_tell_contributors_to_run_exist(
    subcommand: str, flag: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Every flag the procedure docs put in a command block must be a real flag.

    Read off `--help` rather than grepped from the source, because the argument parser
    is what a contributor's shell will actually meet. A doc naming a renamed flag is a
    copy-pasteable command that fails, which is worse than no example.
    """
    from remgen.providers.aws.cli import main

    monkeypatch.setattr("sys.argv", ["awsremgen", subcommand, "--help"])
    with pytest.raises(SystemExit):
        main()
    assert flag in capsys.readouterr().out, (
        f"the docs tell contributors to run `awsremgen {subcommand} {flag}`, but that "
        f"flag is not in `awsremgen {subcommand} --help`"
    )
