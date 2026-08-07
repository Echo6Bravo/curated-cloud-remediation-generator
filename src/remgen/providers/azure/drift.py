"""Verify a recipe's ARM operation and its properties against Azure's own definitions.

The Azure counterpart of :mod:`remgen.providers.aws.drift`, and the axis whose source
was an open question in the design rather than a detail. AWS ships ``service-2.json``:
one machine-readable model per service, the same source every AWS SDK and the CLI are
generated from. Azure ships **no** JSON API models -- ``find azure/mgmt -name '*.json'``
over ``az`` 2.89.0 returns nothing -- so the AWS approach has no direct analogue and the
options had to be measured.

**What this reads: the ``azure.mgmt.*`` SDK packages bundled inside ``az``.** There are
62 of them, code-generated from the same swagger specifications ARM itself is built
from, and they carry exactly the three things this axis needs:

* the **operation class and method** (``StorageAccountsOperations.update``), in
  ``<service>/operations/``,
* the **model class and its properties**, in ``<service>/models/`` (the JSON wire name
  of each is there too, and deliberately not what this checks -- see
  :attr:`_ServiceModel.models`),
* the **pinned ``api-version``**, in ``<service>/_configuration.py``.

Everything is recovered with :mod:`ast`. Nothing is imported and nothing executes, so
this is offline, credential-free, and immune to the dependency-shadowing problem that
ruled out importing ``azure.cli.core`` for the CLI axis -- see
:mod:`remgen.providers.azure.cli_surface` for that measurement.

**This supersedes the plan recorded in ``verify_recipes``' docstring**, which chose
``az``'s ``aaz`` command trees. The reason is the same one that redirected the CLI axis,
applied to a second set of commands: ``aaz`` does not contain the commands recipes name.
Of 18 candidate remediation commands, 5 have an ``aaz`` leaf; ``storage account update``
and ``keyvault update`` -- the two lowest-risk, highest-value Azure remediations -- are
both absent. Since ``UNAVAILABLE`` is exit-code-neutral, an ``aaz``-based axis would
have reported green while checking nothing for precisely the recipes that shipped first.
``aaz`` is no longer needed for either axis: the SDK operations carry the URL and HTTP
method too.

**Two model styles, and handling only one would fail silently.** The generator changed
mid-fleet, so of the 62 packages 14 are new-style and 43 old-style:

* new (``storage``, ``keyvault``):
  ``x: Optional[bool] = rest_field(name="supportsHttpsTrafficOnly")``
* old (``sql``, ``redis``): ``_attribute_map = {"state": {"key": "properties.state", ...}}``

The services needed for the first recipes span both, so this is load-bearing rather than
defensive -- a reader that knew one style would report ``PARAMETER_MISSING`` for every
property of every service using the other, and blame Azure for it.

As everywhere in verification: no ``az`` and no models means ``UNAVAILABLE``, never a
pass. A check that could not run is not a check that passed.
"""

from __future__ import annotations

import ast
import os
import re
import shutil
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from remgen.core.drift import DriftResult, DriftStatus
from remgen.core.model import Recipe

#: Overrides the location of the bundled SDK packages. Points at the directory that
#: *contains* the per-service packages (i.e. ``.../site-packages/azure/mgmt``), which is
#: the level the AWS override also names -- a directory of services, not one service.
MODELS_ENV_VAR = "REMGEN_AZURE_SDK_DIR"

#: Where the ``azure/mgmt`` tree sits relative to an ``az`` installation root. Globs
#: because the Python minor version is part of the path and moves with every CLI
#: upgrade. Ordered most-specific first. The ``libexec`` form is Homebrew's, the plain
#: ``lib/`` form is a pip or Debian install, and ``lib/azure-cli/lib`` is the MSI's.
_SDK_GLOBS = (
    "libexec/lib/python3*/site-packages/azure/mgmt",
    "lib/python3*/site-packages/azure/mgmt",
    "lib/azure-cli/lib/python3*/site-packages/azure/mgmt",
)

#: Matches a shell token that names a Python interpreter, e.g. ``bin/python3.14``.
#: Anchored on a path separator or the start of the token so a token that merely
#: *contains* the substring (``.../python_env/bin/az``) is not mistaken for one.
_PYTHON_TOKEN_RE = re.compile(r"(?:^|/)python[0-9.]*$")


@dataclass(frozen=True)
class _ServiceModel:
    """What one service's bundled SDK declares, as far as this axis cares.

    Deliberately not a mirror of the SDK's own structure: it holds the three questions
    a recipe asks -- does this operation exist, does this model property exist, and
    which ``api-version`` would the call use -- and nothing else, so a change in how
    the SDK is laid out is absorbed by the parser rather than by every caller.
    """

    #: ``{operation class name: frozenset of method names}``.
    operations: dict[str, frozenset[str]]
    #: ``{model class name: frozenset of property names}``. Python property names, not
    #: wire names: a recipe declares what it sets in the vocabulary a reader can find
    #: in the SDK and in ``az``'s own source, and the wire name is an implementation
    #: detail of serialization.
    models: dict[str, frozenset[str]]
    #: The ``api-version`` the bundled client pins, or ``""`` if it could not be read.
    api_version: str


@lru_cache(maxsize=1)
def find_sdk_dir() -> Path | None:
    """Locate the bundled ``azure/mgmt`` package directory, or ``None``.

    Resolution order mirrors :func:`remgen.providers.aws.drift.find_model_dir`: an
    explicit override, then the copy inside the installed CLI. There is no middle step
    equivalent to "an importable botocore", because importing Azure's SDK is exactly
    what this module avoids -- an importable ``azure.mgmt`` in *our* environment would
    be a different version from the one ``az`` uses, so it would answer a question
    nobody asked.

    Cached, like its AWS counterpart, because every recipe verified asks again and the
    answer involves globbing several directories. A test that changes
    :data:`MODELS_ENV_VAR` must therefore clear **both** this and
    :func:`_load_service`, or it is served the previous test's models -- there is a
    fixture in ``tests/test_azure_drift.py`` that does it.
    """
    override = os.environ.get(MODELS_ENV_VAR)
    if override:
        candidate = Path(override).expanduser()
        return candidate if candidate.is_dir() else None

    az_bin = shutil.which("az")
    if not az_bin:
        return None
    for root in _search_roots(Path(os.path.realpath(az_bin))):
        for pattern in _SDK_GLOBS:
            matches = sorted(root.glob(pattern))
            if matches:
                return matches[-1]
    return None


def _search_roots(launcher: Path) -> list[Path]:
    """Directories to glob for the SDK tree, given a resolved ``az`` launcher.

    The launcher's own parents, then -- if it is a shell wrapper -- the parents of the
    interpreter it names. That second source is not a refinement of the first; it
    reaches installations the first structurally cannot.

    **Why globbing upward from the launcher is not enough, measured on the layout
    GitHub's runners ship.** The Debian package installs ``/usr/bin/az`` as a *bash
    wrapper rather than a symlink*, so ``realpath`` stops there and the parents are
    ``/usr/bin``, ``/usr``, ``/``. The packages are at
    ``/opt/az/lib/python3*/site-packages/azure/mgmt``, which is not below any of them.
    No additional entry in :data:`_SDK_GLOBS` can reach it, because the tree is not
    under the launcher at all. Homebrew's wrapper is the same shape and *happened* to
    be reachable only because its interpreter sits inside the same Cellar prefix.

    Reading the wrapper is what both layouts have in common: each names its
    interpreter, and the SDKs are installed against that interpreter by construction.
    The file is *read*, never executed -- the "no network calls, no binaries invoked"
    property this whole module rests on is unchanged.

    Returns the launcher's roots first, so an installation the old resolution found is
    still found in the same place and by the same route.
    """
    roots = list(launcher.parents)[:6]
    try:
        first_kb = launcher.read_text(encoding="utf-8", errors="ignore")[:1024]
    except OSError:
        return roots
    # A native binary is not a wrapper; bail before regexing megabytes of ELF.
    if not first_kb.startswith("#!"):
        return roots
    interpreter = _interpreter_token(first_kb)
    if not interpreter:
        return roots
    # Debian's wrapper writes the path relative to the launcher, via a variable it set
    # earlier ("$bin_dir"/../../opt/az/bin/python3). Any unexpanded variable is
    # resolved against the launcher's own directory -- which is what `$bin_dir` is
    # assigned to -- rather than by running the shell to find out.
    if "$" in interpreter:
        interpreter = re.sub(r"\$\{?\w+\}?", ".", interpreter)
    candidate = Path(interpreter)
    if not candidate.is_absolute():
        candidate = launcher.parent / candidate
    resolved = Path(os.path.normpath(candidate))
    roots.extend(p for p in list(resolved.parents)[:6] if p not in roots)
    return roots


def _interpreter_token(script: str) -> str | None:
    """Return the interpreter path a wrapper script invokes, or ``None``.

    Scans tokens rather than matching a line pattern, because the quoting is not
    predictable: Homebrew writes a bare absolute path, and Debian writes
    ``"$bin_dir"/../../opt/az/bin/python3`` -- where the quotes sit *inside* the path,
    so a regex expecting a fully quoted token misses it. Quotes are stripped from
    anywhere in the token for that reason.

    The shebang line is skipped. It names the shell that runs the wrapper (or, for
    ``/opt/az/bin/az``, a *build-machine* path that does not exist on the installed
    system), never the interpreter the CLI actually runs under.

    Tokens containing ``=`` are skipped as environment assignments. Both shipped
    wrappers put one before the interpreter (``AZ_INSTALLER=HOMEBREW``, ``=DEB``), and
    neither *value* looks like a Python path -- but one that did would be returned in
    preference to the real interpreter, and the real one would then never be searched.
    """
    for line in script.splitlines():
        if line.startswith("#!") or not line.strip():
            continue
        for token in line.split():
            bare = token.replace('"', "").replace("'", "")
            if "=" in bare:
                continue
            if bare and _PYTHON_TOKEN_RE.search(bare):
                return bare
    return None


def model_source_description() -> str:
    """Where API definitions were read from, for ``verify`` output."""
    sdk = find_sdk_dir()
    return str(sdk) if sdk else "unavailable"


def _class_defs(path: Path) -> dict[str, ast.ClassDef]:
    """Return the top-level classes in one source file, by name.

    Returns ``{}`` rather than raising for an unreadable or unparseable file. A parse
    failure means the SDK is newer than this reader understands, which is a
    could-not-check; raising would turn a coverage gap into a crash in the middle of a
    verification run.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError, UnicodeDecodeError):
        return {}
    return {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}


def _properties(cls: ast.ClassDef) -> frozenset[str]:
    """Extract a model class's property names, from either generator style.

    Both styles are read because the SDK fleet is mid-migration and the services these
    recipes need span the split. Handling one alone is not a partial implementation, it
    is a silent wrong answer: every property of every service on the other style would
    be reported missing.
    """
    names: set[str] = set()
    for stmt in cls.body:
        # New style: annotated assignment, usually `= rest_field(...)`. The annotation
        # is what marks it as a declared property; matching on the rest_field call
        # instead would miss the plain `x: Optional[str] = None` members the generator
        # also emits.
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if not stmt.target.id.startswith("_"):
                names.add(stmt.target.id)
        # Old style: `_attribute_map = {"python_name": {"key": "wire.path", ...}}`.
        elif (
            isinstance(stmt, ast.Assign)
            and isinstance(stmt.value, ast.Dict)
            and any(isinstance(t, ast.Name) and t.id == "_attribute_map" for t in stmt.targets)
        ):
            for key in stmt.value.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    names.add(key.value)
    return frozenset(names)


def _api_version(service_dir: Path) -> str:
    """Read the ``api-version`` the bundled client pins, or ``""``.

    Recorded so a drift report says which API version disagreed. Read from the source
    text rather than by importing the client, and degraded to ``""`` on any failure:
    the version is context for a human, and no check depends on it, so failing to read
    it must not make the axis unavailable.
    """
    config = service_dir / "_configuration.py"
    try:
        module = ast.parse(config.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError, UnicodeDecodeError):
        return ""
    # `api_version: str = kwargs.pop("api_version", "2025-08-01")` -- the default is the
    # second argument, and it is the pinned version. Walked rather than indexed by
    # position in the file, because it sits inside a method whose surrounding shape has
    # changed between generator versions.
    for node in ast.walk(module):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "pop"
            and len(node.args) == 2
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "api_version"
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            return node.args[1].value
    return ""


@lru_cache(maxsize=64)
def _load_service(service: str) -> _ServiceModel | None:
    """Parse one bundled SDK package, or ``None`` if there is no such service.

    Cached because several recipes may target one service and the biggest file in the
    fleet (``sql``, 1 MB, 425 classes) costs about 50 ms to parse. Reads every module
    under ``operations/`` and ``models/``: the layout varies -- ``storage`` puts all 26
    operation classes in one ``_operations.py`` while ``sql`` spreads 148 across one
    file each -- so globbing is what makes one reader work for both.
    """
    sdk = find_sdk_dir()
    if sdk is None:
        return None
    service_dir = sdk / service
    if not service_dir.is_dir():
        return None

    operations: dict[str, frozenset[str]] = {}
    for path in sorted(service_dir.glob("operations/*.py")):
        for name, cls in _class_defs(path).items():
            methods = frozenset(
                node.name
                for node in cls.body
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            )
            # `|` rather than assignment: the generator emits @overload stubs alongside
            # the real definition, and for some services the same class name appears in
            # more than one module. Replacing would keep whichever file sorted last.
            operations[name] = operations.get(name, frozenset()) | methods

    models: dict[str, frozenset[str]] = {}
    for path in sorted(service_dir.glob("models/*.py")):
        for name, cls in _class_defs(path).items():
            models[name] = models.get(name, frozenset()) | _properties(cls)

    if not operations and not models:
        # A directory exists but yielded nothing. That is a layout this reader does not
        # understand, not a service with no operations, so it must not be reported as a
        # service whose every operation is missing.
        return None
    return _ServiceModel(
        operations=operations, models=models, api_version=_api_version(service_dir)
    )


def _split_operation(operation: str) -> tuple[str, str] | None:
    """Split ``"StorageAccountsOperations.update"`` into its class and method.

    The dotted form is required rather than inferred. Azure's operation identity is a
    (class, method) pair and neither half is derivable from the other or from the CLI
    command: ``sql db tde set`` is
    ``TransparentDataEncryptionsOperations.begin_create_or_update``, where the class
    name, the verb and the ``begin_`` long-running-operation prefix are all things a
    recipe author has to look up and be checked on.
    """
    if operation.count(".") != 1:
        return None
    cls, _, method = operation.partition(".")
    return (cls, method) if cls and method else None


def verify_recipe(recipe: Recipe) -> DriftResult:
    """Check one recipe's declared operation and properties against the bundled SDK.

    ``ApiCall.parameters`` is read as *model property names* here, where the AWS side
    reads them as input-shape member names. Both are "the names this recipe sets, in
    the vocabulary of the cloud's own API definition", which is what makes the shared
    :class:`~remgen.core.drift.DriftResult` honest for both clouds.
    """
    api = recipe.api
    base = {
        "policy_id": recipe.policy_id,
        "policy_title": recipe.policy_title,
        "service": api.service,
        "operation": api.operation,
    }

    if find_sdk_dir() is None:
        return DriftResult(
            **base,
            status=DriftStatus.UNAVAILABLE,
            detail=(
                f"No bundled Azure SDK models found. Install the Azure CLI, or set "
                f"{MODELS_ENV_VAR} to a directory of azure.mgmt.* packages."
            ),
        )

    parts = _split_operation(api.operation)
    if parts is None:
        return DriftResult(
            **base,
            status=DriftStatus.OPERATION_MISSING,
            detail=(
                f"{api.operation!r} is not a '<OperationsClass>.<method>' pair. Azure "
                f"operation identity is both halves; neither is derivable from the CLI "
                f"command."
            ),
        )
    class_name, method_name = parts

    model = _load_service(api.service)
    if model is None:
        return DriftResult(
            **base,
            status=DriftStatus.SERVICE_MISSING,
            detail=(
                f"No bundled azure.mgmt.{api.service} package, or its layout could not "
                f"be read. Note this is the SDK package name, which is not always the "
                f"`az` command group -- `az postgres` is azure.mgmt.rdbms."
            ),
        )

    if class_name not in model.operations:
        return DriftResult(
            **base,
            status=DriftStatus.OPERATION_MISSING,
            api_version=model.api_version,
            detail=(
                f"Operations class {class_name!r} is absent from azure.mgmt."
                f"{api.service} ({model.api_version or 'unknown api-version'})."
            ),
        )
    if method_name not in model.operations[class_name]:
        return DriftResult(
            **base,
            status=DriftStatus.OPERATION_MISSING,
            api_version=model.api_version,
            detail=(
                f"{class_name} has no method {method_name!r} in azure.mgmt."
                f"{api.service} ({model.api_version or 'unknown api-version'}). A "
                f"long-running operation is named 'begin_<verb>'."
            ),
        )

    # Properties are looked up across every model class rather than against the one
    # input model, because an ARM update body is nested: `supportsHttpsTrafficOnly`
    # lives on StorageAccountPropertiesUpdateParameters, which hangs off
    # StorageAccountUpdateParameters.properties. Requiring a recipe to name the exact
    # leaf class would make it record SDK-internal structure that `az` hides, and would
    # break on a generator reshuffle that renamed a container without touching the API.
    declared: set[str] = set()
    for props in model.models.values():
        declared |= props
    missing = [p for p in api.parameters if p not in declared]
    if missing:
        return DriftResult(
            **base,
            status=DriftStatus.PARAMETER_MISSING,
            api_version=model.api_version,
            detail=(
                f"Propert(ies) {', '.join(sorted(missing))} are not declared by any "
                f"azure.mgmt.{api.service} model "
                f"({model.api_version or 'unknown api-version'}). Names are the SDK's "
                f"Python property names, not the JSON wire names."
            ),
        )

    return DriftResult(**base, status=DriftStatus.OK, api_version=model.api_version)


def verify_all(recipes: tuple[Recipe, ...]) -> tuple[DriftResult, ...]:
    """Verify every recipe, in the order given."""
    return tuple(verify_recipe(r) for r in recipes)


__all__ = [
    "MODELS_ENV_VAR",
    "find_sdk_dir",
    "model_source_description",
    "verify_all",
    "verify_recipe",
]
