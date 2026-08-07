"""Tests for the Azure API-definition axis.

The property that matters most is the same one the AWS drift tests are built around:
**a check that cannot run must never report OK.** Everything else here is secondary to
that, because a silent pass is how the "verified every run" promise stops being true
without anyone noticing.

Azure adds a second property of equal weight, and it is the reason this file is not a
translation of ``tests/test_drift.py``. The bundled SDK fleet is **mid-migration between
two code generators**, and the reader has to handle both:

* new (``storage``, ``keyvault``): ``x: Optional[bool] = rest_field(name="...")``
* old (``sql``, ``redis``): ``_attribute_map = {"state": {"key": "properties.state"}}``

Handling one alone is not partial coverage, it is a confident wrong answer: every
property of every service on the other style reports ``PARAMETER_MISSING``, which reads
as "Azure renamed this" rather than as "this reader is broken". The shipped recipes span
both styles -- ``storage`` is new, ``sql`` is old -- so both are exercised here against
fixtures *and* against the real bundled SDKs.

**Split into three kinds, deliberately:**

* **Fixture tests** build a small ``azure/mgmt``-shaped tree in ``tmp_path`` and point
  the override at it. They assert the parsing and status rules, and they are the only
  way to reach the failure branches -- the real SDKs contain no missing operation.
* **Layout tests** build a fake ``az`` installation and assert :func:`find_sdk_dir`
  locates the packages inside it. These cover :data:`_SDK_GLOBS` and
  :func:`~remgen.providers.azure.drift._search_roots`, which are otherwise only ever
  exercised by whatever ``az`` the developer happens to have. That gap was not
  hypothetical: the layout GitHub's runners preinstall resolved to nothing while
  Homebrew, pip and the MSI all worked, so every Azure test skipped in CI. There is a
  test per layout now, including that one.
* **Integration tests** run against the real bundled SDKs and skip when there are none.
  They are what tells us the fixtures resemble Azure; a fixture test alone only tells us
  the parser agrees with a file we wrote from what we already believed.

Nothing here imports ``azure.mgmt`` or runs ``az``. The axis is pure :mod:`ast` over
files on disk, which is what makes it credential-free and offline, so a test that
reached for either would be testing something else.
"""

from __future__ import annotations

import pytest

from remgen.core.model import ApiCall, Recipe
from remgen.providers.azure import drift
from remgen.providers.azure.drift import (
    MODELS_ENV_VAR,
    DriftStatus,
    find_sdk_dir,
    model_source_description,
    verify_all,
    verify_recipe,
)
from remgen.providers.azure.recipes import all_recipes

HAS_SDK = find_sdk_dir() is not None
needs_sdk = pytest.mark.skipif(
    not HAS_SDK, reason="no bundled azure.mgmt SDK packages available in this environment"
)


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear **both** caches around every test.

    Two, not one, and that is the whole reason this fixture is autouse rather than
    per-test. :func:`find_sdk_dir` and :func:`~remgen.providers.azure.drift._load_service`
    are separately ``lru_cache``d, so clearing only the first serves the *previous*
    test's parsed models from a directory that no longer exists -- a failure that
    presents as one test contaminating another and is nearly impossible to read from the
    assertion that fails. ``drift``'s own docstring promises this fixture exists.
    """
    find_sdk_dir.cache_clear()
    drift._load_service.cache_clear()
    yield
    find_sdk_dir.cache_clear()
    drift._load_service.cache_clear()


def _recipe(
    *,
    service: str = "storage",
    operation: str = "StorageAccountsOperations.update",
    parameters: tuple[str, ...] = ("enable_https_traffic_only",),
) -> Recipe:
    return Recipe(
        policy_id="00000000-0000-0000-0000-000000000000",
        policy_title="Title",
        summary="Summary",
        api=ApiCall(service=service, operation=operation, parameters=parameters),
        cli_template="az storage account update --ids {resource_id}",
        hcl=None,
        reverse_hint="undo",
        docs_url="https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/update",
    )


#: A new-style generated model file: annotated assignments, usually ``rest_field``.
#:
#: Includes the three shapes the parser has to tell apart -- a ``rest_field`` property, a
#: plain annotated member the generator also emits, and a private ``_``-prefixed one that
#: is not a property. Written as realistic source rather than minimal source, because the
#: point of a fixture for an AST reader is the shapes it contains.
_NEW_STYLE_MODEL = '''
"""Generated file. Do not edit."""

class StorageAccountUpdateParameters(_Model):
    """Parameters for updating a storage account."""

    tags: Optional[Dict[str, str]] = rest_field(name="tags")
    properties: Optional["StorageAccountPropertiesUpdateParameters"] = rest_field(
        name="properties"
    )


class StorageAccountPropertiesUpdateParameters(_Model):
    """The nested body an ARM update actually carries."""

    enable_https_traffic_only: Optional[bool] = rest_field(name="supportsHttpsTrafficOnly")
    minimum_tls_version: Optional[str] = rest_field(name="minimumTlsVersion")
    plain_member: Optional[str] = None
    _private_thing: Optional[str] = rest_field(name="privateThing")
'''

#: An old-style generated model file: ``_attribute_map`` mapping Python names to wire
#: paths. The nested ``properties.state`` key is the realistic case, and the one the
#: shipped ``sql`` recipe depends on.
_OLD_STYLE_MODEL = '''
class LogicalDatabaseTransparentDataEncryption(ProxyResource):
    """A logical database transparent data encryption state."""

    _validation = {"id": {"readonly": True}}

    _attribute_map = {
        "id": {"key": "id", "type": "str"},
        "state": {"key": "properties.state", "type": "str"},
    }

    def __init__(self, *, state=None, **kwargs):
        super().__init__(**kwargs)
        self.state = state
'''

_OPERATIONS = '''
class StorageAccountsOperations:
    """Generated operations class."""

    @overload
    def update(self, resource_group_name, account_name, parameters, *, content_type="application/json"):
        ...

    def update(self, resource_group_name, account_name, parameters, **kwargs):
        return None

    async def begin_create(self, resource_group_name, account_name, parameters, **kwargs):
        return None
'''

_CONFIGURATION = """
class StorageManagementClientConfiguration:
    def __init__(self, credential, subscription_id, **kwargs):
        api_version: str = kwargs.pop("api_version", "2025-08-01")
        self.api_version = api_version
"""


def _write_service(
    root,
    service: str = "storage",
    *,
    operations: str | None = _OPERATIONS,
    models: dict[str, str] | None = None,
    configuration: str | None = _CONFIGURATION,
):
    """Build one ``azure/mgmt/<service>`` package under ``root``.

    Each part is optional so a test can build a tree missing exactly one thing. ``models``
    maps filename to source, because the fleet is inconsistent about it -- ``storage``
    puts everything in one ``_models.py`` while ``sql`` uses one file per model -- and the
    globbing that copes with both is a thing to test rather than assume.
    """
    service_dir = root / service
    if operations is not None:
        (service_dir / "operations").mkdir(parents=True)
        (service_dir / "operations" / "_operations.py").write_text(operations, encoding="utf-8")
    if models is not None:
        (service_dir / "models").mkdir(parents=True, exist_ok=True)
        for name, source in models.items():
            (service_dir / "models" / name).write_text(source, encoding="utf-8")
    if configuration is not None:
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "_configuration.py").write_text(configuration, encoding="utf-8")
    return service_dir


@pytest.fixture
def fake_sdk(tmp_path, monkeypatch):
    """A minimal ``azure/mgmt``-shaped tree under our control, both generator styles.

    ``storage`` is new-style and ``sql`` old-style, mirroring the real fleet and the two
    services the shipped recipes need, so a test that only ever ran against this fixture
    still covers both readers.
    """
    root = tmp_path / "mgmt"
    _write_service(root, "storage", models={"_models.py": _NEW_STYLE_MODEL})
    _write_service(
        root,
        "sql",
        operations=(
            "class TransparentDataEncryptionsOperations:\n"
            "    def begin_create_or_update(self, *args, **kwargs):\n"
            "        return None\n"
        ),
        models={"_transparent_data_encryption.py": _OLD_STYLE_MODEL},
        configuration=(
            "class SqlManagementClientConfiguration:\n"
            "    def __init__(self, credential, subscription_id, **kwargs):\n"
            '        api_version: str = kwargs.pop("api_version", "2024-11-01-preview")\n'
        ),
    )
    monkeypatch.setenv(MODELS_ENV_VAR, str(root))
    find_sdk_dir.cache_clear()
    drift._load_service.cache_clear()
    return root


# ---------------------------------------------------------------------------
# The statuses, against a tree we control
# ---------------------------------------------------------------------------


def test_matching_recipe_is_ok(fake_sdk):
    result = verify_recipe(_recipe())
    assert result.status is DriftStatus.OK
    assert result.ok
    assert result.api_version == "2025-08-01"


def test_a_new_style_property_is_found(fake_sdk):
    # `rest_field`-declared, on the nested properties class rather than on the top-level
    # update parameters -- which is the whole reason properties are looked up across
    # every model class. See test_a_property_on_a_nested_model_class_is_found.
    assert verify_recipe(_recipe(parameters=("minimum_tls_version",))).status is DriftStatus.OK


def test_an_old_style_property_is_found(fake_sdk):
    """The ``_attribute_map`` reader, exercised through the status it produces.

    This is the half that a reader written against ``storage`` alone would fail, and it
    would fail *silently* in the sense that matters: ``PARAMETER_MISSING`` for ``state``
    reads as "Azure renamed the TDE property", which is a believable thing to have
    happened and would send the next person to the Azure changelog rather than to this
    parser.
    """
    result = verify_recipe(
        _recipe(
            service="sql",
            operation="TransparentDataEncryptionsOperations.begin_create_or_update",
            parameters=("state",),
        )
    )
    assert result.status is DriftStatus.OK, result.detail
    assert result.api_version == "2024-11-01-preview"


def test_a_plain_annotated_member_counts_as_a_property(fake_sdk):
    # The generator emits `x: Optional[str] = None` alongside its rest_field members.
    # Matching on the rest_field call instead of on the annotation would miss those and
    # report a property Azure does declare as missing.
    assert verify_recipe(_recipe(parameters=("plain_member",))).status is DriftStatus.OK


def test_a_private_member_is_not_a_property(fake_sdk):
    # `_`-prefixed members are generator internals. Accepting them would let a recipe
    # declare `_private_thing` and pass, which is a check that cannot fail.
    result = verify_recipe(_recipe(parameters=("_private_thing",)))
    assert result.status is DriftStatus.PARAMETER_MISSING


def test_a_property_on_a_nested_model_class_is_found(fake_sdk):
    """Properties are searched across every model class, and that is deliberate.

    An ARM update body is nested: ``supportsHttpsTrafficOnly`` lives on
    ``StorageAccountPropertiesUpdateParameters``, which hangs off
    ``StorageAccountUpdateParameters.properties``. Requiring a recipe to name the exact
    leaf class would make it record SDK-internal structure that ``az`` hides, and would
    break on a generator reshuffle that renamed a container without changing the API.

    Asserted here because the looseness is a deliberate trade rather than an oversight:
    the axis confirms the property exists *somewhere* in the service's models, and a test
    that pinned it to one class would quietly convert that decision into a stricter one.
    """
    result = verify_recipe(_recipe(parameters=("enable_https_traffic_only", "tags")))
    assert result.status is DriftStatus.OK


def test_a_missing_operations_class_is_detected(fake_sdk):
    result = verify_recipe(_recipe(operation="GoneOperations.update"))
    assert result.status is DriftStatus.OPERATION_MISSING
    assert not result.ok
    assert "GoneOperations" in result.detail


def test_a_missing_method_is_detected_and_names_the_begin_convention(fake_sdk):
    """A renamed method must be reported with the hint that resolves it.

    The realistic form of this failure is not a deleted method, it is a method that
    became long-running: ``create_or_update`` -> ``begin_create_or_update``. That
    happened while writing the SQL recipe, before it shipped, and the detail says so
    because a reader seeing "has no method create_or_update" would otherwise go looking
    for a removed API.
    """
    result = verify_recipe(_recipe(operation="StorageAccountsOperations.create"))
    assert result.status is DriftStatus.OPERATION_MISSING
    assert "begin_" in result.detail


def test_an_async_method_is_still_a_method(fake_sdk):
    # The generator emits async operations classes too. Reading only `FunctionDef` would
    # report every async operation as missing.
    assert verify_recipe(_recipe(operation="StorageAccountsOperations.begin_create")).status is (
        DriftStatus.OK
    )


def test_a_missing_property_is_detected(fake_sdk):
    result = verify_recipe(_recipe(parameters=("enable_https_traffic_only", "renamedProperty")))
    assert result.status is DriftStatus.PARAMETER_MISSING
    assert not result.ok
    assert "renamedProperty" in result.detail


def test_the_detail_says_property_names_are_the_sdks_not_the_wires(fake_sdk):
    """The wire name is the wrong answer that looks right.

    ``supportsHttpsTrafficOnly`` is in the fixture -- as a ``rest_field`` name -- and it
    is what the REST documentation shows, so it is the name an author copying from the
    docs will write. The axis checks Python property names, so the wire name is reported
    missing, and the detail has to say which vocabulary it wanted or the report sends the
    reader to check a name that is genuinely correct in a different context.
    """
    result = verify_recipe(_recipe(parameters=("supportsHttpsTrafficOnly",)))
    assert result.status is DriftStatus.PARAMETER_MISSING
    assert "wire" in result.detail.lower()


def test_a_missing_service_is_detected(fake_sdk):
    result = verify_recipe(_recipe(service="nosuchservice"))
    assert result.status is DriftStatus.SERVICE_MISSING
    assert not result.ok


def test_the_missing_service_detail_names_the_sdk_package_convention(fake_sdk):
    """``az postgres`` is ``azure.mgmt.rdbms``, and that is the likely cause here.

    A recipe filed under the ``az`` command group instead of the SDK package name
    produces exactly this status, so the detail names the trap. Without it the report
    reads as "Azure does not ship a postgres SDK", which is false and unactionable.
    """
    result = verify_recipe(_recipe(service="postgres"))
    assert result.status is DriftStatus.SERVICE_MISSING
    assert "rdbms" in result.detail


def test_an_operation_that_is_not_a_dotted_pair_is_rejected(fake_sdk):
    """Azure operation identity is (class, method) and neither half is derivable.

    A recipe naming just ``update``, or the CLI command ``storage account update``, is a
    plausible mistake -- both read as an operation. Neither can be resolved, and the
    important part is that it is reported as drift rather than crashing a run partway
    through a verification of several recipes.
    """
    for operation in ("update", "storage account update", "A.B.C"):
        result = verify_recipe(_recipe(operation=operation))
        assert result.status is DriftStatus.OPERATION_MISSING, operation
        assert "<OperationsClass>.<method>" in result.detail


# ---------------------------------------------------------------------------
# The property the whole axis exists for: could-not-check is never a pass
# ---------------------------------------------------------------------------


def test_no_sdk_source_never_reports_ok(tmp_path, monkeypatch):
    monkeypatch.setenv(MODELS_ENV_VAR, str(tmp_path / "does-not-exist"))
    find_sdk_dir.cache_clear()
    drift._load_service.cache_clear()
    result = verify_recipe(_recipe())
    assert result.status is DriftStatus.UNAVAILABLE
    assert not result.ok
    # The report has to name the thing that would fix it, since this is the one status
    # a user can resolve themselves.
    assert MODELS_ENV_VAR in result.detail


def test_no_sdk_source_reports_unavailable_rather_than_service_missing(tmp_path, monkeypatch):
    """The two "could not check" statuses must not collapse into one.

    ``SERVICE_MISSING`` is a *finding* -- the SDK is there and this service is not, which
    means the recipe is wrong. ``UNAVAILABLE`` is an absence of evidence. They exit
    differently (3 versus 4) and the canary branches on which one it saw, so reporting
    the first when the second is true turns "install the CLI" into "a recipe is broken".
    """
    monkeypatch.setenv(MODELS_ENV_VAR, str(tmp_path / "nope"))
    find_sdk_dir.cache_clear()
    drift._load_service.cache_clear()
    assert verify_recipe(_recipe()).status is not DriftStatus.SERVICE_MISSING


def test_a_service_directory_that_yields_nothing_is_not_a_pass(tmp_path, monkeypatch):
    """An unreadable layout must not read as a service whose operations all vanished.

    A directory with no ``operations/`` and no ``models/`` is what a future SDK
    reorganization looks like from here. Reporting ``OPERATION_MISSING`` would blame
    Azure for renaming everything at once; reporting OK would be worse. ``_load_service``
    returns ``None``, which surfaces as ``SERVICE_MISSING`` -- honest, and the detail says
    the layout could not be read.
    """
    root = tmp_path / "mgmt"
    (root / "storage").mkdir(parents=True)
    monkeypatch.setenv(MODELS_ENV_VAR, str(root))
    find_sdk_dir.cache_clear()
    drift._load_service.cache_clear()
    result = verify_recipe(_recipe())
    assert result.status is DriftStatus.SERVICE_MISSING
    assert not result.ok
    assert "layout" in result.detail


def test_an_unparseable_model_file_is_skipped_not_crashed(tmp_path, monkeypatch):
    """A file this reader cannot parse is a could-not-check, not a traceback.

    An SDK newer than the reader is the realistic cause -- new syntax in a generated
    file. Raising would abort a verification run partway through and report a crash where
    the honest answer is that one property could not be confirmed.
    """
    root = tmp_path / "mgmt"
    _write_service(
        root,
        "storage",
        models={"_broken.py": "class X(:\n", "_models.py": _NEW_STYLE_MODEL},
    )
    monkeypatch.setenv(MODELS_ENV_VAR, str(root))
    find_sdk_dir.cache_clear()
    drift._load_service.cache_clear()
    # The good file is still read, so the recipe still verifies.
    assert verify_recipe(_recipe()).status is DriftStatus.OK


def test_an_unreadable_api_version_degrades_rather_than_failing(tmp_path, monkeypatch):
    """The api-version is context for a human; no check depends on it.

    So a missing or unparseable ``_configuration.py`` must not make the axis unavailable
    -- that would turn a cosmetic gap into a check that did not run. The detail strings
    say "unknown api-version" instead, which is why they are written with that fallback.
    """
    root = tmp_path / "mgmt"
    _write_service(root, "storage", models={"_models.py": _NEW_STYLE_MODEL}, configuration=None)
    monkeypatch.setenv(MODELS_ENV_VAR, str(root))
    find_sdk_dir.cache_clear()
    drift._load_service.cache_clear()
    result = verify_recipe(_recipe())
    assert result.status is DriftStatus.OK
    assert result.api_version == ""


def test_models_spread_across_one_file_each_are_all_read(tmp_path, monkeypatch):
    """The fleet is inconsistent about model layout, so globbing is load-bearing.

    ``storage`` puts every model in one ``_models.py``; ``sql`` uses one file per model,
    148 of them. Reading a fixed filename would work perfectly against one service and
    report every property of the other as missing.
    """
    root = tmp_path / "mgmt"
    _write_service(
        root,
        "storage",
        models={
            "_a.py": (
                "class A(_Model):\n"
                '    enable_https_traffic_only: Optional[bool] = rest_field(name="x")\n'
            ),
            "_b.py": (
                'class B(_Model):\n    minimum_tls_version: Optional[str] = rest_field(name="y")\n'
            ),
        },
    )
    monkeypatch.setenv(MODELS_ENV_VAR, str(root))
    find_sdk_dir.cache_clear()
    drift._load_service.cache_clear()
    result = verify_recipe(_recipe(parameters=("enable_https_traffic_only", "minimum_tls_version")))
    assert result.status is DriftStatus.OK, result.detail


def test_verify_all_preserves_order(fake_sdk):
    recipes = (_recipe(), _recipe(operation="GoneOperations.update"))
    results = verify_all(recipes)
    assert len(results) == 2
    assert results[0].status is DriftStatus.OK
    assert results[1].status is DriftStatus.OPERATION_MISSING


def test_model_source_description_says_unavailable_and_not_a_hopeful_sentence(
    tmp_path, monkeypatch
):
    """``"unavailable"`` is a contract, not a message.

    The shared ``verify`` compares this string against that literal to decide whether to
    print the models-unavailable hint. Anything else -- "not found", "" -- is rendered as
    if it were a path, so the report would name a location that does not exist.
    """
    monkeypatch.setenv(MODELS_ENV_VAR, str(tmp_path / "nope"))
    find_sdk_dir.cache_clear()
    assert model_source_description() == "unavailable"


def test_model_source_description_names_the_directory_when_there_is_one(fake_sdk):
    assert model_source_description() == str(fake_sdk)


# ---------------------------------------------------------------------------
# Finding the SDKs: the globs, against fake az installations
# ---------------------------------------------------------------------------
#
# These matter because `_SDK_GLOBS` is otherwise only ever exercised against whichever
# `az` the developer has installed -- so a glob that works on Homebrew and nowhere else
# passes every test on the machine where it was written and reports UNAVAILABLE for
# everyone on a pip or MSI install. The three layouts are built here explicitly.


@pytest.mark.parametrize(
    ("layout", "why"),
    [
        ("libexec/lib/python3.13/site-packages/azure/mgmt", "Homebrew: az is a bash wrapper"),
        ("lib/python3.13/site-packages/azure/mgmt", "pip install into a virtualenv"),
        ("lib/azure-cli/lib/python3.11/site-packages/azure/mgmt", "the MSI package layout"),
    ],
)
def test_the_sdk_directory_is_found_in_each_real_installation_layout(
    tmp_path, monkeypatch, layout, why
):
    """Each supported ``az`` layout, built and located.

    The Homebrew case is the one that forced more than a single glob and it is worth
    stating why: ``az`` there is a *bash wrapper*, so ``realpath`` stops at ``bin/az``
    rather than resolving into the Python tree, and the packages sit a further level down
    under ``libexec``. A single ``lib/`` pattern -- the shape the AWS side needs -- finds
    nothing on the most common macOS install.
    """
    root = tmp_path / "cellar"
    (root / layout).mkdir(parents=True)
    bin_dir = root / "bin"
    bin_dir.mkdir()
    az = bin_dir / "az"
    az.write_text('#!/bin/bash\nexec python -m azure.cli "$@"\n', encoding="utf-8")
    az.chmod(0o755)
    monkeypatch.delenv(MODELS_ENV_VAR, raising=False)
    monkeypatch.setenv("PATH", str(bin_dir))
    find_sdk_dir.cache_clear()
    assert find_sdk_dir() == root / layout, why


def test_the_sdks_are_found_when_they_are_not_under_the_launcher_at_all(tmp_path, monkeypatch):
    """The layout GitHub's runners ship, which no glob alone can reach.

    Reproduces the Debian package byte-for-byte in shape: ``/usr/bin/az`` is a *bash
    wrapper rather than a symlink*, so ``realpath`` stops there and the launcher's
    parents are ``usr/bin``, ``usr``, and the root. The packages are at
    ``opt/az/lib/python3*/site-packages/azure/mgmt`` -- below **none** of them.

    This is the regression test for a real CI failure: every Azure test was skipped on
    `ubuntu-latest` with "no bundled azure.mgmt SDK packages found", while the same
    recipes verified green locally on Homebrew and green in the canary, which
    ``pip install``s into ``site-packages`` and so happened to sit under the launcher.
    Three configurations agreed and the fourth -- the default install on the most
    common CI runner -- found nothing.

    Adding a fourth glob cannot fix it, and asserting that is the point of this test:
    the tree is not under the launcher, so no pattern rooted at the launcher matches.
    The wrapper is read for the interpreter it names instead.
    """
    root = tmp_path / "debian"
    sdk = root / "opt/az/lib/python3.14/site-packages/azure/mgmt"
    sdk.mkdir(parents=True)
    interpreter = root / "opt/az/bin/python3"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("", encoding="utf-8")
    bin_dir = root / "usr/bin"
    bin_dir.mkdir(parents=True)
    az = bin_dir / "az"
    # The real wrapper, verbatim from azure-cli_2.88.0-1~noble_amd64.deb. The quotes
    # sit *inside* the path, which is what defeated the first regex written for this.
    az.write_text(
        "#!/usr/bin/env bash\n"
        'bin_dir=`cd "$(dirname "$BASH_SOURCE[0]")"; pwd`\n'
        'AZ_INSTALLER=DEB "$bin_dir"/../../opt/az/bin/python3 -Im azure.cli "$@"\n',
        encoding="utf-8",
    )
    az.chmod(0o755)
    monkeypatch.delenv(MODELS_ENV_VAR, raising=False)
    monkeypatch.setenv("PATH", str(bin_dir))
    find_sdk_dir.cache_clear()

    assert find_sdk_dir() == sdk

    # The tree really is unreachable from the launcher, so this test cannot pass by
    # accident through the glob path it is meant to bypass.
    # `list(...)`, not the generator `parent.glob(pattern)` -- a generator is truthy
    # whether or not it will yield anything, so `any(parent.glob(p) for ...)` is
    # vacuously True and asserts nothing. Written the wrong way first; it failed here
    # rather than passing silently only because the expected answer is "no matches".
    assert not [
        match
        for parent in list(az.parents)[:6]
        for pattern in drift._SDK_GLOBS
        for match in parent.glob(pattern)
    ]


def test_a_launcher_that_names_no_interpreter_still_falls_back_to_the_globs(tmp_path, monkeypatch):
    """Reading the wrapper is additive, never a replacement.

    A launcher this code cannot parse -- a native binary, or a wrapper shape nobody has
    shipped yet -- must leave the glob search exactly as it was, or supporting a new
    layout would have cost the ones already working.
    """
    root = tmp_path / "opaque"
    layout = "lib/python3.13/site-packages/azure/mgmt"
    (root / layout).mkdir(parents=True)
    bin_dir = root / "bin"
    bin_dir.mkdir()
    az = bin_dir / "az"
    az.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
    az.chmod(0o755)
    monkeypatch.delenv(MODELS_ENV_VAR, raising=False)
    monkeypatch.setenv("PATH", str(bin_dir))
    find_sdk_dir.cache_clear()
    assert find_sdk_dir() == root / layout


def test_the_shebang_is_not_mistaken_for_the_interpreter(tmp_path, monkeypatch):
    """A shebang names the shell, or a path that does not exist here.

    ``/opt/az/bin/az`` inside the real package begins ``#!/mnt/repo/python_env/bin/
    python3`` -- a *build machine* path absent from every installed system. Trusting a
    shebang would search a directory tree that is not there and, worse, would do it in
    preference to the wrapper line that names the real interpreter.
    """
    root = tmp_path / "shebang"
    sdk = root / "opt/az/lib/python3.14/site-packages/azure/mgmt"
    sdk.mkdir(parents=True)
    bin_dir = root / "usr/bin"
    bin_dir.mkdir(parents=True)
    az = bin_dir / "az"
    az.write_text(
        "#!/mnt/repo/python_env/bin/python3\n"
        'AZ_INSTALLER=DEB "$bin_dir"/../../opt/az/bin/python3 -Im azure.cli "$@"\n',
        encoding="utf-8",
    )
    az.chmod(0o755)
    monkeypatch.delenv(MODELS_ENV_VAR, raising=False)
    monkeypatch.setenv("PATH", str(bin_dir))
    find_sdk_dir.cache_clear()
    assert find_sdk_dir() == sdk


def test_an_env_assignment_is_not_mistaken_for_the_interpreter(tmp_path, monkeypatch):
    """``VAR=/path/to/python3`` is a variable being set, not the interpreter.

    Both shipped wrappers put an assignment before the interpreter -- Homebrew's
    ``AZ_INSTALLER=HOMEBREW``, Debian's ``AZ_INSTALLER=DEB`` -- and neither *value*
    happens to look like a Python path. One that did would be returned in preference to
    the real interpreter, which would then never be searched.

    No shipped wrapper does this today, and it fails safe if it ever did: a path that
    resolves to nothing means the axis reports UNAVAILABLE rather than a false pass. It
    is tested because a latent wrong answer in resolution is what the bug this file
    documents already was once.
    """
    root = tmp_path / "assignment"
    sdk = root / "opt/az/lib/python3.14/site-packages/azure/mgmt"
    sdk.mkdir(parents=True)
    bin_dir = root / "usr/bin"
    bin_dir.mkdir(parents=True)
    az = bin_dir / "az"
    az.write_text(
        "#!/usr/bin/env bash\n"
        'PYTHONHOME=/nonexistent/decoy/python3 "$bin_dir"/../../opt/az/bin/python3'
        ' -Im azure.cli "$@"\n',
        encoding="utf-8",
    )
    az.chmod(0o755)
    monkeypatch.delenv(MODELS_ENV_VAR, raising=False)
    monkeypatch.setenv("PATH", str(bin_dir))
    find_sdk_dir.cache_clear()
    assert find_sdk_dir() == sdk


def test_no_az_on_path_and_no_override_is_not_found(tmp_path, monkeypatch):
    monkeypatch.delenv(MODELS_ENV_VAR, raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    find_sdk_dir.cache_clear()
    assert find_sdk_dir() is None


def test_the_override_wins_over_an_installed_az(tmp_path, monkeypatch):
    """The override is checked first, and that ordering is the point of it.

    It is what lets the drift canary verify against a pinned SDK tree on a runner that
    also has ``az`` installed. If the installed CLI won, the canary would silently be
    checking a different version from the one it reports.
    """
    override = tmp_path / "pinned" / "mgmt"
    override.mkdir(parents=True)
    monkeypatch.setenv(MODELS_ENV_VAR, str(override))
    find_sdk_dir.cache_clear()
    assert find_sdk_dir() == override


def test_an_override_pointing_at_a_file_is_rejected(tmp_path, monkeypatch):
    # A path typo, or a pointer at the archive rather than the unpacked tree. Returning
    # it would make every service report missing; None makes the axis report UNAVAILABLE,
    # which names the variable.
    bogus = tmp_path / "not-a-dir"
    bogus.write_text("", encoding="utf-8")
    monkeypatch.setenv(MODELS_ENV_VAR, str(bogus))
    find_sdk_dir.cache_clear()
    assert find_sdk_dir() is None


def test_an_override_set_to_empty_falls_back_rather_than_disabling_the_axis(tmp_path, monkeypatch):
    """``REMGEN_AZURE_SDK_DIR=""`` must behave as unset, not as "no models".

    An empty environment variable is what a shell script produces from an unset
    interpolation, and treating it as an override would report UNAVAILABLE on a machine
    with a perfectly good ``az`` -- while naming the variable the user did not knowingly
    set.
    """
    root = tmp_path / "cellar"
    layout = "lib/python3.13/site-packages/azure/mgmt"
    (root / layout).mkdir(parents=True)
    bin_dir = root / "bin"
    bin_dir.mkdir()
    (bin_dir / "az").write_text("#!/bin/bash\n", encoding="utf-8")
    (bin_dir / "az").chmod(0o755)
    monkeypatch.setenv(MODELS_ENV_VAR, "")
    monkeypatch.setenv("PATH", str(bin_dir))
    find_sdk_dir.cache_clear()
    assert find_sdk_dir() == root / layout


# ---------------------------------------------------------------------------
# The real curated set against the real bundled SDKs
# ---------------------------------------------------------------------------


@needs_sdk
def test_curated_azure_recipes_match_the_real_bundled_sdks():
    """Every shipped Azure recipe must match the SDK as actually bundled.

    The test that catches a recipe written from a stale memory of the API rather than
    from the definition -- and the one that already earned its place: it rejected
    ``TransparentDataEncryptions.create_or_update`` before the SQL recipe shipped,
    because the real method is ``begin_create_or_update``.

    ``UNAVAILABLE`` is tolerated for the same reason the AWS counterpart tolerates it:
    the skip guard checks whether *any* SDK tree was found, and a partial installation
    could still leave one service unreadable. Any other non-OK status is a real
    disagreement with Azure.
    """
    failures = [
        f"{r.service}.{r.operation}: {r.detail}"
        for r in verify_all(all_recipes())
        if r.status not in (DriftStatus.OK, DriftStatus.UNAVAILABLE)
    ]
    assert not failures, "Azure recipes no longer match the bundled SDKs:\n" + "\n".join(failures)


@needs_sdk
def test_the_real_sdks_contain_both_generator_styles():
    """The two-reader design, verified against Azure rather than against our fixture.

    Every parser test above runs on files written from what we already believed the two
    styles look like. If the real fleet had converged on one, those tests would keep
    passing while half the reader became dead code -- and, worse, if it had converged on
    the *other* one they would keep passing while the shipped recipes silently stopped
    being checked.

    So this asserts the split is real: ``storage`` is new-style (``rest_field``) and
    ``sql`` old-style (``_attribute_map``), read from the bundled source text. Both are
    services the shipped recipes depend on, so this is the measurement the drift module's
    docstring makes, re-taken every run.
    """
    sdk = find_sdk_dir()
    assert sdk is not None

    def _sources(service: str) -> str:
        files = sorted((sdk / service).glob("models/*.py"))
        assert files, f"no model files under {service}"
        return "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in files)

    assert "rest_field(" in _sources("storage"), (
        "azure.mgmt.storage is no longer new-style; the recipes' properties are being "
        "resolved by the other reader, or not at all"
    )
    assert "_attribute_map" in _sources("sql"), (
        "azure.mgmt.sql is no longer old-style; check the sql recipe still verifies"
    )


@needs_sdk
def test_the_real_sdks_report_a_pinned_api_version_for_every_recipe():
    """A drift report has to say which API version disagreed.

    ``api_version`` degrades to ``""`` by design when it cannot be read, which is correct
    -- no check depends on it -- and it means a silently broken ``_configuration.py``
    reader would leave every report unattributable while every other test stayed green.
    Asserted against the real SDKs because the parse target is generated code whose
    surrounding shape has already changed once between generator versions.
    """
    for result in verify_all(all_recipes()):
        if result.status is DriftStatus.UNAVAILABLE:
            continue
        assert result.api_version, (
            f"{result.service}.{result.operation}: no api-version was read, so a drift "
            f"report on this recipe could not say which version it disagreed with"
        )


@needs_sdk
def test_verifying_the_real_recipes_imports_no_azure_package():
    """The axis is AST-only, and that is a safety property rather than an optimization.

    Importing ``azure.mgmt`` would run generated code from an SDK whose version is
    whatever ``az`` happens to bundle, in this process; it is also how the CLI axis's
    dependency-shadowing problem started. Nothing in ``sys.modules`` should mention
    ``azure`` after a full verification run.

    Asserted after the real thing rather than after a fixture: the fixture tree contains
    no importable package, so it could not reveal an accidental import even if one were
    added.
    """
    import sys

    verify_all(all_recipes())
    leaked = sorted(name for name in sys.modules if name == "azure" or name.startswith("azure."))
    assert not leaked, f"the drift axis imported {leaked}; it must only parse source text"
