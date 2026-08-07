"""Tests for the provider-schema axis of verification.

Two things are being tested and they are worth separating.

The first is the checker: given a schema document and a recipe, does it reach the
right verdict? Those tests build small synthetic schemas, because a synthetic schema
is the only way to exercise a *renamed* argument or a *removed* resource type -- the
real provider has neither, and a test that waits for HashiCorp to break something is
not a test.

The second is the claim that makes the checker worth having: that the schema's
``required`` flag is the same thing ``tofu validate`` enforces. That one cannot be
tested against a fixture at all, because the whole question is whether the fixture
would match reality. It is tested against the real binary and the real provider, and
skipped -- visibly, at collection -- when they are absent.
"""

from __future__ import annotations

import itertools
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from remgen.core.hcl_schema import (
    MAX_SCHEMA_BYTES,
    SCHEMA_ENV_VAR,
    ProviderSchema,
    SchemaSourceError,
    SchemaStatus,
    find_schema_path,
    load_provider_schema,
    verify_all_hcl,
    verify_recipe_hcl,
)
from remgen.core.model import ApiCall, HclTarget, Recipe
from remgen.providers.aws.recipes import all_recipes

from .conftest import PROVIDER_TF, TOFU

#: The shipped set, as the tool itself sees it. Taken from the aggregate rather than
#: from one service module, so a recipe added in a new module is covered here without
#: anyone remembering to add an import.
RECIPES = all_recipes()

# ---------------------------------------------------------------------------
# Fixtures: the smallest schema document shaped like a real one
# ---------------------------------------------------------------------------


def _doc(resources: dict, *, key: str = "registry.opentofu.org/hashicorp/aws") -> dict:
    return {"format_version": "1.0", "provider_schemas": {key: {"resource_schemas": resources}}}


def _attr(**flags) -> dict:
    base = {"required": False, "optional": True, "computed": False, "deprecated": False}
    base.update(flags)
    return base


def _thing(**overrides) -> dict:
    """A resource type with one required and one optional argument, and one block."""
    resource = {
        "block": {
            "attributes": {
                "name": _attr(required=True, optional=False),
                "enabled": _attr(),
                "legacy": _attr(deprecated=True),
            },
            "block_types": {
                "config": {
                    "nesting_mode": "list",
                    "block": {"attributes": {"status": _attr()}},
                },
                "mandatory": {
                    "nesting_mode": "list",
                    "min_items": 1,
                    "block": {"attributes": {"kind": _attr()}},
                },
            },
        }
    }
    resource["block"].update(overrides)
    return resource


def _schema(resources: dict | None = None) -> ProviderSchema:
    return load_provider_schema(
        _write(_doc(resources if resources is not None else {"aws_thing": _thing()})),
        source_prefix="hashicorp/aws",
    )


#: One directory for every synthetic schema this module writes. Held at module level,
#: not per test, because ``_schema`` and ``_write`` are plain helpers called from inside
#: assertions rather than fixtures, and threading ``tmp_path`` through all of them would
#: obscure what each test is actually asserting. Bound to a name so the directory is
#: removed when the interpreter exits rather than left behind.
_TMP_DIR = tempfile.TemporaryDirectory(prefix="remgen-schema-")
_TMP_COUNT = itertools.count()


def _write(document: dict) -> Path:
    """Write a synthetic schema document and return its path.

    A real file rather than a stub, because ``load_provider_schema`` checks the size on
    disk before parsing, and a path is what ``--provider-schema`` receives.
    """
    path = Path(_TMP_DIR.name) / f"schema-{next(_TMP_COUNT)}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _recipe(hcl: HclTarget | None, **overrides) -> Recipe:
    kwargs = {
        "policy_id": "p1",
        "policy_title": "Title",
        "summary": "Summary",
        "api": ApiCall(service="s3", operation="Op", parameters=("A",)),
        "cli_template": "aws s3api do-thing --bucket {resource_id}",
        "hcl": hcl,
        "reverse_hint": "undo it",
    }
    kwargs.update(overrides)
    return Recipe(**kwargs)


def _target(**overrides) -> HclTarget:
    kwargs = {
        "resource_type": "aws_thing",
        "attributes": (("name", '"{resource_id}"'), ("enabled", "true")),
        "import_id_template": "{resource_id}",
        # The fixture's `mandatory` block has min_items, so a target that omits it
        # would be REQUIRED_MISSING in every test rather than in the one testing it.
        "blocks": (("mandatory", (("kind", '"a"', ""),)),),
    }
    kwargs.update(overrides)
    return HclTarget(**kwargs)


# ---------------------------------------------------------------------------
# Loading: an unusable schema must never read as a pass
# ---------------------------------------------------------------------------


def test_a_matching_schema_loads():
    schema = _schema()
    assert schema.source == "registry.opentofu.org/hashicorp/aws"
    assert "aws_thing" in schema.resources


def test_the_registry_host_does_not_have_to_match():
    """Terraform and OpenTofu key the same provider under different hosts.

    An equality check on the provider address would report every recipe as
    unverifiable under whichever of the two tools was not hardcoded -- and it would do
    so as ``UNAVAILABLE``, which is exit-code-neutral, so nobody would notice the
    check had stopped running.
    """
    for host in ("registry.terraform.io", "registry.opentofu.org", ""):
        key = f"{host}/hashicorp/aws" if host else "hashicorp/aws"
        schema = load_provider_schema(
            _write(_doc({"aws_thing": _thing()}, key=key)), source_prefix="hashicorp/aws"
        )
        assert "aws_thing" in schema.resources, key


def test_a_schema_for_a_different_provider_is_an_error_not_a_pass():
    # The failure this prevents: pointing the check at an azurerm schema, getting
    # "no resource types matched", and reading that as "no problems found".
    with pytest.raises(SchemaSourceError, match="different provider"):
        load_provider_schema(
            _write(
                _doc({"azurerm_thing": _thing()}, key="registry.terraform.io/hashicorp/azurerm")
            ),
            source_prefix="hashicorp/aws",
        )


@pytest.mark.parametrize(
    ("document", "match"),
    [
        ({"format_version": "1.0"}, "no 'provider_schemas'"),
        ({"provider_schemas": {}}, "no 'provider_schemas'"),
        ([], "not an object"),
    ],
)
def test_a_document_that_is_not_a_schema_is_an_error(document, match):
    with pytest.raises(SchemaSourceError, match=match):
        load_provider_schema(_write(document), source_prefix="hashicorp/aws")


def test_an_empty_resource_set_is_an_error():
    """An entry with no resource types would report every recipe as missing.

    That is a wall of confident, wrong failures rather than "this document is not
    usable", and an operator would go looking for the renamed resource type.
    """
    with pytest.raises(SchemaSourceError, match="no resource schemas"):
        load_provider_schema(_write(_doc({})), source_prefix="hashicorp/aws")


def test_a_missing_file_names_how_to_produce_one(tmp_path):
    with pytest.raises(SchemaSourceError, match="tofu providers schema"):
        load_provider_schema(tmp_path / "absent.json", source_prefix="hashicorp/aws")


def test_an_oversized_schema_is_refused_before_parsing(tmp_path, monkeypatch):
    """The size limit must be checked against the file, not after reading it.

    Reading first and checking second is the same crash it exists to prevent.
    """
    monkeypatch.setattr("remgen.core.hcl_schema.MAX_SCHEMA_BYTES", 10)
    path = tmp_path / "big.json"
    path.write_text(json.dumps(_doc({"aws_thing": _thing()})))
    with pytest.raises(SchemaSourceError, match="over the"):
        load_provider_schema(path, source_prefix="hashicorp/aws")
    assert MAX_SCHEMA_BYTES > 19 * 1024 * 1024, (
        "the real hashicorp/aws schema is ~19 MB; a limit below it rejects every real document"
    )


def test_find_schema_path_prefers_the_explicit_argument(monkeypatch, tmp_path):
    monkeypatch.setenv(SCHEMA_ENV_VAR, str(tmp_path / "from-env.json"))
    assert find_schema_path(tmp_path / "explicit.json") == tmp_path / "explicit.json"
    assert find_schema_path(None) == tmp_path / "from-env.json"
    monkeypatch.delenv(SCHEMA_ENV_VAR)
    assert find_schema_path(None) is None


def test_a_path_that_is_set_but_absent_is_still_returned(monkeypatch, tmp_path):
    """Resolution must not silently swallow a path the operator asked for.

    Returning ``None`` for a configured-but-missing schema turns an explicit request
    into a skipped check, which is the failure mode the whole module is built to
    avoid.
    """
    missing = tmp_path / "nope.json"
    monkeypatch.setenv(SCHEMA_ENV_VAR, str(missing))
    assert find_schema_path(None) == missing


# ---------------------------------------------------------------------------
# The checker
# ---------------------------------------------------------------------------


def test_a_correct_target_passes():
    result = verify_recipe_hcl(_recipe(_target()), _schema())
    assert result.status is SchemaStatus.OK
    assert result.ok and result.checked
    assert not result.issues


def test_no_schema_is_reported_as_unavailable_not_as_a_pass():
    result = verify_recipe_hcl(_recipe(_target()), None)
    assert result.status is SchemaStatus.UNAVAILABLE
    assert not result.checked
    assert not result.ok, "an unrunnable check must never satisfy `ok`"
    assert SCHEMA_ENV_VAR in result.unavailable_detail


def test_a_recipe_with_no_hcl_target_is_not_counted_as_unchecked():
    # It will never be checkable, so counting it as unavailable would permanently
    # inflate the "could not check" number and train readers to ignore it.
    result = verify_recipe_hcl(_recipe(None), _schema())
    assert result.status is SchemaStatus.OK
    assert result.checked


def test_a_removed_resource_type_is_caught():
    result = verify_recipe_hcl(_recipe(_target(resource_type="aws_gone")), _schema())
    assert result.status is SchemaStatus.RESOURCE_TYPE_MISSING
    assert not result.ok


def test_a_renamed_argument_is_caught():
    result = verify_recipe_hcl(
        _recipe(_target(attributes=(("name", '"x"'), ("enabledd", "true")))), _schema()
    )
    assert result.status is SchemaStatus.ATTRIBUTE_MISSING
    assert [i.name for i in result.issues] == ["enabledd"]


def test_a_newly_required_argument_the_recipe_omits_is_caught():
    """The provider adding a required argument breaks every block for that type.

    Caught here rather than only by ``tofu validate`` in the HCL tests, because those
    exercise the resource types a fixture finding happens to reach; this covers every
    recipe in the set.
    """
    result = verify_recipe_hcl(
        _recipe(_target(attributes=(("enabled", "true"),))),  # drops the required `name`
        _schema(),
    )
    assert result.status is SchemaStatus.REQUIRED_MISSING
    assert [i.name for i in result.issues] == ["name"]


def test_a_required_block_the_recipe_omits_is_caught():
    result = verify_recipe_hcl(_recipe(_target(blocks=())), _schema())
    assert result.status is SchemaStatus.REQUIRED_MISSING
    assert [i.name for i in result.issues] == ["mandatory"]


def test_a_stub_is_accepted_as_covering_a_required_argument():
    """A ``"TODO"`` stub is how a recipe satisfies a genuinely required argument.

    Without this, every legitimate stub would be reported as REQUIRED_MISSING and the
    check would fail on the correct behaviour it is meant to protect.
    """
    result = verify_recipe_hcl(
        _recipe(
            _target(
                attributes=(("enabled", "true"),),
                unresolvable_required_attributes=(("name", '"TODO"', "TODO: set it"),),
            )
        ),
        _schema(),
    )
    assert result.status is SchemaStatus.OK


def test_claiming_an_optional_argument_is_required_is_a_failure():
    """The finding that motivated this module. See its docstring.

    ``enabled`` is optional in the fixture, so stubbing it as provider-required is a
    false claim -- and on the imported resource these blocks always accompany, the
    stub proposes a change to a value the user never asked to change.
    """
    result = verify_recipe_hcl(
        _recipe(_target(unresolvable_required_attributes=(("enabled", '"TODO"', "TODO"),))),
        _schema(),
    )
    assert result.status is SchemaStatus.NOT_REQUIRED
    assert not result.ok, "a false 'required' claim must fail, not warn"
    assert "optional" in result.issues[0].detail


def test_claiming_an_optional_block_is_required_is_a_failure():
    result = verify_recipe_hcl(
        _recipe(
            _target(
                blocks=(
                    ("mandatory", (("kind", '"a"', ""),)),
                    ("config", (("status", '"x"', ""),)),
                ),
                unresolvable_required_blocks=("config",),
            )
        ),
        _schema(),
    )
    assert result.status is SchemaStatus.NOT_REQUIRED
    assert [i.name for i in result.issues] == ["config"]


def test_a_deprecated_argument_warns_but_does_not_fail():
    """Deprecation is the notice before removal, which is what a canary wants to see.

    Failing on it would mean an upstream deprecation announcement breaks a release
    that is still entirely correct.
    """
    result = verify_recipe_hcl(
        _recipe(_target(attributes=(("name", '"x"'), ("legacy", "true")))), _schema()
    )
    assert result.status is SchemaStatus.DEPRECATED
    assert not result.status.is_failure
    assert result.ok, "a deprecated-but-valid recipe still passes"
    assert result.checked


def test_an_unknown_argument_inside_a_nested_block_is_caught():
    result = verify_recipe_hcl(
        _recipe(_target(blocks=(("mandatory", (("kindd", '"a"', ""),)),))), _schema()
    )
    assert result.status is SchemaStatus.ATTRIBUTE_MISSING
    assert [i.name for i in result.issues] == ["mandatory.kindd"]


def test_an_unknown_nested_block_is_caught():
    result = verify_recipe_hcl(
        _recipe(
            _target(
                blocks=(
                    ("mandatory", (("kind", '"a"', ""),)),
                    ("configg", (("status", '"x"', ""),)),
                )
            )
        ),
        _schema(),
    )
    assert result.status is SchemaStatus.ATTRIBUTE_MISSING
    assert "configg" in [i.name for i in result.issues]


def test_the_worst_finding_decides_the_verdict():
    """A recipe with several problems must report the most severe.

    If a lesser status won, a recipe with both a deprecation and a removed argument
    would be filed under "plan for the future" while being broken today.
    """
    result = verify_recipe_hcl(
        _recipe(_target(attributes=(("name", '"x"'), ("legacy", "true"), ("gone", "true")))),
        _schema(),
    )
    assert {i.status for i in result.issues} == {
        SchemaStatus.DEPRECATED,
        SchemaStatus.ATTRIBUTE_MISSING,
    }
    assert result.status is SchemaStatus.ATTRIBUTE_MISSING


def test_status_rank_is_a_strict_ordering():
    """``status`` picks the worst issue with ``max`` over ``rank``.

    Two statuses sharing a rank makes that choice arbitrary, and a flattened ordering
    lets a failure be reported under a warning heading.
    """
    ranks = [s.rank for s in SchemaStatus]
    assert len(set(ranks)) == len(list(SchemaStatus)), (
        f"two SchemaStatus members share a rank, so `max` between them is arbitrary: {ranks}"
    )
    assert SchemaStatus.OK.rank < SchemaStatus.DEPRECATED.rank < SchemaStatus.NOT_REQUIRED.rank
    assert SchemaStatus.NOT_REQUIRED.rank < SchemaStatus.RESOURCE_TYPE_MISSING.rank
    # Every member classified, so a new status cannot default into "not a failure".
    assert {s for s in SchemaStatus if s.is_failure} == {
        SchemaStatus.NOT_REQUIRED,
        SchemaStatus.REQUIRED_MISSING,
        SchemaStatus.ATTRIBUTE_MISSING,
        SchemaStatus.RESOURCE_TYPE_MISSING,
    }


def test_verify_all_preserves_order_and_length():
    recipes = tuple(_recipe(_target(), policy_id=f"p{n}") for n in range(3))
    results = verify_all_hcl(recipes, _schema())
    assert [r.policy_id for r in results] == ["p0", "p1", "p2"]


# ---------------------------------------------------------------------------
# The shipped recipe set
# ---------------------------------------------------------------------------


def test_no_shipped_recipe_stubs_an_argument_the_provider_does_not_require():
    """The regression guard for the finding this module was written to catch.

    Five stubs across two recipes claimed the provider required arguments it marks
    ``optional+computed``: ``aws_dynamodb_table.hash_key`` and its ``attribute``
    block, and ``aws_db_instance.engine``/``allocated_storage``/``username``. Because
    these blocks always accompany an ``import``, each stub proposed *changing* a live
    value -- and on ``hash_key`` or ``engine`` that forces replacement, destroying a
    table or a database.

    Asserted against the real schema when one is available, and structurally
    otherwise, so the guard has some force even in a bare checkout. The structural
    half is not merely a restatement: it pins the exact names that were wrong, so
    re-adding one fails here regardless of whether a schema is present.
    """
    known_bogus = {
        ("aws_dynamodb_table", "hash_key"),
        ("aws_dynamodb_table", "attribute"),
        ("aws_db_instance", "engine"),
        ("aws_db_instance", "allocated_storage"),
        ("aws_db_instance", "username"),
    }
    for recipe in RECIPES:
        if recipe.hcl is None:
            continue
        for name in recipe.hcl.unresolvable_names:
            assert (recipe.hcl.resource_type, name) not in known_bogus, (
                f"{recipe.hcl.resource_type}.{name} is stubbed as provider-required, but "
                f"the schema marks it optional+computed. On the imported resource this "
                f"block accompanies, the stub proposes changing a live value."
            )


def test_instance_class_keeps_its_stub():
    """The control for the test above: it must not have become "remove every stub".

    ``aws_db_instance.instance_class`` really is required -- ``tofu validate`` rejects
    the block without it -- so removing its stub would emit configuration that does
    not load. A test that only checked for absent stubs would pass on that too.
    """
    rds = [r for r in RECIPES if r.hcl and r.hcl.resource_type == "aws_db_instance"]
    assert rds, "no aws_db_instance recipe; this test no longer checks anything"
    assert rds[0].hcl.unresolvable_names == ("instance_class",)


# ---------------------------------------------------------------------------
# Against the real provider
# ---------------------------------------------------------------------------


#: Gate for the tests that need the genuine provider. The schema is produced by the
#: ``real_provider_schema`` session fixture from the same initialized workspace the
#: other parser-backed tests use, so these run wherever ``tofu`` is present -- which
#: CI already asserts. ``skipif`` on the binary rather than on the fixture value, so
#: the skip happens at collection where CI's "nothing was skipped" gate can see it.
_needs_tofu = pytest.mark.skipif(TOFU is None, reason="neither tofu nor terraform available")


@_needs_tofu
def test_the_loader_accepts_real_tofu_output(real_provider_schema):
    """Every fixture above is shaped like real output; this checks the shape is right.

    Without it, a change to the document format -- a renamed key, a moved
    ``resource_schemas`` -- would leave all the fixture-based tests passing while the
    checker rejected every real schema. And because an unusable schema degrades to
    "not checked", nobody would see it fail.
    """
    assert real_provider_schema is not None, (
        "`tofu` is present but no schema could be produced; the loader or the document "
        "format changed"
    )
    assert len(real_provider_schema.resources) > 1000, (
        f"the real provider has ~1700 resource types, got "
        f"{len(real_provider_schema.resources)}; this document is not what it should be"
    )
    assert "hashicorp/aws" in real_provider_schema.source


@_needs_tofu
def test_every_shipped_recipe_matches_the_real_provider_schema(real_provider_schema):
    problems = [
        (r.resource_type, i.status.value, i.name, i.detail)
        for r in verify_all_hcl(RECIPES, real_provider_schema)
        if r.status.is_failure
        for i in r.issues
    ]
    assert not problems, f"recipes disagree with the real provider schema: {problems}"


@_needs_tofu
def test_the_real_schema_still_marks_instance_class_required(real_provider_schema):
    """The stub that remains must remain justified, and the removed ones must stay so.

    Both directions matter. If the provider ever makes ``instance_class`` optional,
    keeping its stub becomes the same defect this module was written to remove. If it
    ever makes ``engine`` genuinely required, omitting it emits configuration that
    does not load, and the stub has to come back.
    """
    attrs = real_provider_schema.resource("aws_db_instance")["attributes"]
    assert attrs["instance_class"]["required"], (
        "instance_class is no longer required; its TODO stub now proposes resizing a "
        "live database and should be removed"
    )
    for name in ("engine", "allocated_storage", "username"):
        assert not attrs[name]["required"], (
            f"{name} is now genuinely required, so omitting it emits configuration that "
            f"does not load; it needs a stub again"
        )
    dynamo = real_provider_schema.resource("aws_dynamodb_table")
    assert not dynamo["attributes"]["hash_key"]["required"], (
        "hash_key is now genuinely required; a block without it no longer loads"
    )
    assert not dynamo["blocks"]["attribute"]["required"], (
        "the `attribute` block is now required; a table block without it no longer loads"
    )


@_needs_tofu
def test_the_schema_required_flag_is_what_the_parser_enforces(
    real_provider_schema, tmp_path, tofu_workspace_template
):
    """The claim the whole module rests on, checked against the real binary.

    Every verdict above trusts that the schema's ``required`` flag is the same thing
    ``tofu validate`` demands. That is an empirical claim about two independent
    programs, and no fixture can establish it -- a fixture would assert the very thing
    in question. So this renders the real recipes through the real generator and hands
    them to the real parser.

    Both directions are checked. Forward: the blocks the checker passes must validate.
    Backward: removing ``instance_class`` -- the one argument the schema still marks
    required -- must *fail* validation. Without the backward half this test would pass
    against a parser that accepted anything, which is precisely the scenario where the
    checker's approval would be worthless.
    """
    if tofu_workspace_template is None:
        raise AssertionError(
            "`tofu` is present but the template workspace could not be initialized, so "
            "the parser check never ran. This is a real failure, not a missing toolchain."
        )

    from remgen.core.generators.hcl import group_targets, render_target
    from remgen.core.model import Finding

    pairs = [
        (
            recipe,
            Finding(
                policy_id=recipe.policy_id,
                resource_id="test-resource",
                region="us-east-1",
                account_id="111111111111",
            ),
        )
        for recipe in RECIPES
        if recipe.hcl is not None
    ]
    # Confirm the checker approves of what is about to be validated, so a failure
    # below is a disagreement between the two rather than a recipe already known bad.
    assert all(r.ok for r in verify_all_hcl(RECIPES, real_provider_schema))
    body = "\n".join(render_target(target) for target in group_targets(pairs))

    def _validate(content: str):
        work = tmp_path / f"w{abs(hash(content)) % 10000}"
        work.mkdir(parents=True, exist_ok=True)
        (work / "main.tf").write_text(content, encoding="utf-8")
        (work / "provider.tf").write_text(PROVIDER_TF, encoding="utf-8")
        shutil.copytree(tofu_workspace_template / ".terraform", work / ".terraform", symlinks=True)
        lock = tofu_workspace_template / ".terraform.lock.hcl"
        if lock.exists():
            shutil.copy(lock, work / ".terraform.lock.hcl")
        return subprocess.run(  # noqa: S603
            [TOFU, "validate", "-no-color"],
            cwd=work,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

    forward = _validate(body)
    assert forward.returncode == 0, (
        f"the checker passed every recipe but `tofu validate` rejected the rendered "
        f"blocks, so the schema's `required` flag is not what the parser enforces:\n"
        f"{forward.stdout}\n{forward.stderr}"
    )

    # The control. Dropping the one still-required argument must be rejected; if it is
    # not, the forward pass proved nothing about this parser.
    assert 'instance_class      = "db.t3.micro"' in body or "instance_class" in body
    stripped = "\n".join(line for line in body.splitlines() if "instance_class" not in line)
    backward = _validate(stripped)
    assert backward.returncode != 0, (
        "`tofu validate` accepted an aws_db_instance block with no instance_class, so "
        "it is not enforcing required arguments and the forward check above is vacuous"
    )
    assert "instance_class" in backward.stdout + backward.stderr
