"""Verify a recipe's HCL target against the real Terraform/OpenTofu provider schema.

:mod:`remgen.providers.aws.drift` checks the *API* half of a recipe -- the operation
and parameters the shell script calls. Nothing checked the *HCL* half, and the two
rot independently: AWS can keep ``UpdateTable`` unchanged while the
``hashicorp/aws`` provider renames an argument, makes one required, or drops a
resource type. A recipe can therefore pass ``verify`` and still emit configuration
the provider rejects.

Unlike ``service-2.json``, this part **is** cloud-neutral, which is why it lives in
``core``. ``tofu providers schema -json`` has one format for every provider; only the
source address differs (``hashicorp/aws`` vs ``hashicorp/azurerm``), and that is a
field on :class:`~remgen.core.provider.Provider`. The AWS-specific reader in
``providers/aws/drift.py`` has no equivalent here.

**This module does not run ``tofu``.** It reads a schema document that something
else produced. Shelling out to a tool that downloads a 663 MB provider from a
registry is a network dependency and an execution surface that a generator handed
untrusted findings should not acquire, and it would make the common ``verify`` run
30 seconds slower for a check most users cannot perform offline anyway. So the
schema arrives as a file path -- ``--provider-schema``, or ``REMGEN_TF_SCHEMA`` --
and CI and the drift canary generate it in an explicit step. See CONTRIBUTING.md.

The rule inherited from :mod:`remgen.core.drift` holds here too, and matters more:
**a check that could not run is reported as ``UNAVAILABLE``, never as a pass.** No
schema on disk is the normal case for an ordinary user, so this one is
exit-code-neutral by default -- see :func:`~remgen.core.cli.cmd_verify`. What is
never neutral is a schema that *was* provided and *did* contradict a recipe.

Why ``NOT_REQUIRED`` is a finding rather than a nicety
------------------------------------------------------

:attr:`~remgen.core.model.HclTarget.unresolvable_required_attributes` exists to
satisfy arguments the provider *requires* but a finding cannot supply, by emitting a
type-valid ``"TODO"`` stub. If the schema says an argument is ``optional`` and
``computed``, that stub is not merely unnecessary -- it is actively harmful. These
blocks are always paired with ``import``, so the resource already exists:

* Omitted, an ``optional+computed`` argument means "keep whatever the live resource
  has". The plan shows no change for it.
* Stubbed as ``"TODO"``, it means "set this argument to the literal string TODO".
  On an attribute that forces replacement -- a DynamoDB ``hash_key``, an RDS
  ``engine`` -- the plan proposes destroying and recreating the resource.

A user who follows the instructions and replaces the placeholder is fine. A user who
misses one gets the worst outcome this tool can produce, from configuration that
``validate`` accepts. So a claim of "required" that the schema contradicts is
reported as drift, not as a warning.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from remgen.core.model import Recipe

#: Environment variable naming a ``tofu providers schema -json`` document.
SCHEMA_ENV_VAR = "REMGEN_TF_SCHEMA"

#: Cap on the schema document size, in bytes. The real ``hashicorp/aws`` schema is
#: about 19 MB; the limit is generous but bounded, because this file is parsed with
#: ``json.loads`` into memory and an unbounded read of an arbitrary path is a way to
#: turn a verification command into an out-of-memory crash.
MAX_SCHEMA_BYTES = 256 * 1024 * 1024


class SchemaStatus(str, Enum):
    """Outcome of checking one recipe's HCL target against a provider schema.

    Ordered by severity via :attr:`rank`, because a recipe can produce several
    findings at once and the run needs one verdict per recipe.
    """

    OK = "ok"
    #: An argument or block the recipe emits is marked ``deprecated``. Still
    #: accepted, so not a failure -- but it is the notice that precedes removal, and
    #: the whole point of a canary is to see that before the removal lands.
    DEPRECATED = "deprecated"
    #: The recipe claims an argument is provider-required, but the schema marks it
    #: optional. The ``"TODO"`` stub emitted for it can force replacement of an
    #: imported resource. See the module docstring.
    NOT_REQUIRED = "not_required"
    #: The schema marks an argument or block required, and the recipe neither sets
    #: it nor stubs it. ``tofu validate`` fails with "Missing required argument".
    REQUIRED_MISSING = "required_missing"
    #: An argument or block the recipe emits is absent from the schema. ``tofu
    #: validate`` fails with "Unsupported argument".
    ATTRIBUTE_MISSING = "attribute_missing"
    #: The resource type itself is absent. Every block for it is unusable.
    RESOURCE_TYPE_MISSING = "resource_type_missing"
    #: No schema document available; the check could not be performed. Distinct from
    #: every value above, all of which mean the check ran.
    UNAVAILABLE = "unavailable"

    @property
    def rank(self) -> int:
        """Severity order, least severe first.

        On the enum for the same reason :attr:`~remgen.core.model.SafetyTier.rank`
        is: more than one caller compares two of these -- a per-recipe verdict is
        the worst of its findings, and the CLI orders its report -- and two private
        copies that disagreed would file a ``REQUIRED_MISSING`` recipe under a
        ``DEPRECATED`` heading.
        """
        return _STATUS_RANK[self]

    @property
    def is_failure(self) -> bool:
        """True when this status means the recipe is wrong and must be fixed.

        ``DEPRECATED`` is excluded: it is a warning about the future, and failing on
        it would make an upstream deprecation announcement break a correct release.
        ``UNAVAILABLE`` is excluded because it is not a finding at all.
        """
        return self not in (SchemaStatus.OK, SchemaStatus.DEPRECATED, SchemaStatus.UNAVAILABLE)


_STATUS_RANK = {
    SchemaStatus.OK: 0,
    SchemaStatus.UNAVAILABLE: 1,
    SchemaStatus.DEPRECATED: 2,
    SchemaStatus.NOT_REQUIRED: 3,
    SchemaStatus.REQUIRED_MISSING: 4,
    SchemaStatus.ATTRIBUTE_MISSING: 5,
    SchemaStatus.RESOURCE_TYPE_MISSING: 6,
}


class SchemaSourceError(ValueError):
    """Raised when a schema document was named but cannot be used.

    Distinct from "no schema available": an operator who passed ``--provider-schema``
    asked for the check, so a path that does not parse is an error rather than a
    silent downgrade to unchecked. Conflating the two is how a canary goes blind
    while reporting green.
    """


@dataclass(frozen=True)
class SchemaIssue:
    """One disagreement between a recipe and the provider schema."""

    status: SchemaStatus
    #: The argument, block or resource type the finding is about.
    name: str
    detail: str


@dataclass(frozen=True)
class SchemaResult:
    """Result of checking one recipe's HCL target."""

    policy_id: str
    policy_title: str
    resource_type: str
    issues: tuple[SchemaIssue, ...] = field(default_factory=tuple)
    #: Empty when the check ran; set when it could not.
    unavailable_detail: str = ""
    provider_version: str = ""

    @property
    def status(self) -> SchemaStatus:
        """The worst finding, or ``OK`` / ``UNAVAILABLE`` when there are none."""
        if self.unavailable_detail:
            return SchemaStatus.UNAVAILABLE
        if not self.issues:
            return SchemaStatus.OK
        return max((i.status for i in self.issues), key=lambda s: s.rank)

    @property
    def ok(self) -> bool:
        """True when nothing needs fixing. Deprecation is reported, not failed."""
        return not self.status.is_failure and self.checked

    @property
    def checked(self) -> bool:
        """True when verification actually ran, whatever it concluded."""
        return self.status is not SchemaStatus.UNAVAILABLE


@dataclass(frozen=True)
class ProviderSchema:
    """The resource-type half of one provider's schema document.

    Holds only what verification reads. The full document is ~19 MB of which the
    other providers' entries and every attribute description are irrelevant here, so
    it is reduced on load rather than kept.
    """

    source: str
    version: str
    #: ``{resource_type: {"attributes": {...}, "blocks": {...}}}``, where each
    #: attribute maps to its schema dict and each block to ``(min_items, inner)``.
    resources: dict[str, dict]

    def resource(self, resource_type: str) -> dict | None:
        return self.resources.get(resource_type)


def find_schema_path(explicit: str | Path | None = None) -> Path | None:
    """Resolve where the provider schema document should be read from.

    Order: the explicit argument (a ``--provider-schema`` value), then
    :data:`SCHEMA_ENV_VAR`. Returns ``None`` when neither is set, which is the
    ordinary case and means the HCL check does not run.

    A path that is set but absent returns the path anyway, so the caller reports
    "you asked for this and it is not there" rather than silently skipping the check
    an operator explicitly requested.
    """
    if explicit:
        return Path(explicit).expanduser()
    from_env = os.environ.get(SCHEMA_ENV_VAR)
    if from_env:
        return Path(from_env).expanduser()
    return None


def load_provider_schema(path: Path, *, source_prefix: str) -> ProviderSchema:
    """Read a ``tofu providers schema -json`` document and reduce it.

    Args:
        path: The schema document.
        source_prefix: The provider's source address, e.g. ``"hashicorp/aws"``. The
            document keys providers by full registry address
            (``registry.opentofu.org/hashicorp/aws``,
            ``registry.terraform.io/hashicorp/aws``), which differ between OpenTofu
            and Terraform for the same provider -- so the match is a suffix rather
            than an equality, and an exact-match check here would report every
            recipe as unverifiable under one of the two tools.

    Raises:
        SchemaSourceError: If the file is missing, too large, not JSON, not a schema
            document, or contains no entry for ``source_prefix``. Every one of these
            is "you asked for this check and it cannot run", never a pass.
    """
    if not path.is_file():
        raise SchemaSourceError(
            f"no provider schema at {path}. Generate one with `tofu providers schema "
            f"-json > {path.name}` in a workspace that requires the provider."
        )
    size = path.stat().st_size
    if size > MAX_SCHEMA_BYTES:
        raise SchemaSourceError(
            f"{path} is {size} bytes, over the {MAX_SCHEMA_BYTES}-byte limit. Refusing "
            f"to parse it rather than risk exhausting memory during verification."
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SchemaSourceError(f"{path} could not be read as JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SchemaSourceError(f"{path} is JSON but not an object; this is not a schema document")

    schemas = document.get("provider_schemas")
    if not isinstance(schemas, dict) or not schemas:
        raise SchemaSourceError(
            f"{path} has no 'provider_schemas' object. Was it produced by something "
            f"other than `tofu providers schema -json`?"
        )

    matches = [k for k in schemas if k == source_prefix or k.endswith(f"/{source_prefix}")]
    if not matches:
        raise SchemaSourceError(
            f"{path} contains no schema for {source_prefix!r}; it has "
            f"{', '.join(sorted(schemas)[:4])}. This document is for a different "
            f"provider, so checking against it would verify nothing."
        )
    key = matches[0]
    entry = schemas[key] if isinstance(schemas[key], dict) else {}
    raw_resources = entry.get("resource_schemas")
    if not isinstance(raw_resources, dict) or not raw_resources:
        raise SchemaSourceError(
            f"{path} has an entry for {key} with no resource schemas. An empty "
            f"resource set would report every recipe's resource type as missing."
        )

    resources: dict[str, dict] = {}
    for rtype, rschema in raw_resources.items():
        block = rschema.get("block", {}) if isinstance(rschema, dict) else {}
        resources[rtype] = _reduce_block(block)

    return ProviderSchema(
        source=key,
        # The document records provider versions only when a lock file pinned them,
        # so this is best-effort and used for reporting, never for a decision.
        version=str(document.get("provider_versions", {}).get(key, "")),
        resources=resources,
    )


def _reduce_block(block: dict) -> dict:
    """Reduce one schema block to the attribute and nested-block facts checked here."""
    attributes = {}
    for name, attr in (block.get("attributes") or {}).items():
        if not isinstance(attr, dict):
            continue
        attributes[name] = {
            "required": bool(attr.get("required")),
            "optional": bool(attr.get("optional")),
            "computed": bool(attr.get("computed")),
            "deprecated": bool(attr.get("deprecated")),
        }
    blocks = {}
    for name, bt in (block.get("block_types") or {}).items():
        if not isinstance(bt, dict):
            continue
        blocks[name] = {
            # min_items is absent for most blocks; absent means not required.
            "required": bool(bt.get("min_items") or 0),
            "deprecated": bool(bt.get("block", {}).get("deprecated")),
            "inner": _reduce_block(bt.get("block") or {}),
        }
    return {"attributes": attributes, "blocks": blocks}


def verify_recipe_hcl(recipe: Recipe, schema: ProviderSchema | None) -> SchemaResult:
    """Check one recipe's HCL target against ``schema``.

    A recipe with no HCL target is reported ``OK`` with no findings: there is nothing
    to disagree with, and reporting it as unchecked would inflate the unavailable
    count with recipes that will never be checkable.
    """
    base = {
        "policy_id": recipe.policy_id,
        "policy_title": recipe.policy_title,
        "resource_type": recipe.hcl.resource_type if recipe.hcl else "",
    }
    if schema is None:
        return SchemaResult(
            **base,
            unavailable_detail=(
                "No provider schema available. Pass --provider-schema PATH or set "
                f"{SCHEMA_ENV_VAR}."
            ),
        )
    if recipe.hcl is None:
        return SchemaResult(**base, provider_version=schema.version)

    target = recipe.hcl
    resource = schema.resource(target.resource_type)
    if resource is None:
        return SchemaResult(
            **base,
            provider_version=schema.version,
            issues=(
                SchemaIssue(
                    status=SchemaStatus.RESOURCE_TYPE_MISSING,
                    name=target.resource_type,
                    detail=(
                        f"Resource type {target.resource_type!r} is not in the "
                        f"{schema.source} schema. It may have been renamed or removed; "
                        f"every block this recipe emits would fail to load."
                    ),
                ),
            ),
        )

    issues: list[SchemaIssue] = []
    attrs = resource["attributes"]
    blocks = resource["blocks"]

    set_names = {name for name, _ in target.attributes}
    stub_names = {name for name, _, _ in target.unresolvable_required_attributes}

    for name in sorted(set_names | stub_names):
        schema_attr = attrs.get(name)
        if schema_attr is None:
            issues.append(
                SchemaIssue(
                    status=SchemaStatus.ATTRIBUTE_MISSING,
                    name=name,
                    detail=(
                        f"{target.resource_type} has no argument {name!r}. `tofu "
                        f'validate` fails with "Unsupported argument".'
                    ),
                )
            )
            continue
        if schema_attr["deprecated"]:
            issues.append(
                SchemaIssue(
                    status=SchemaStatus.DEPRECATED,
                    name=name,
                    detail=(
                        f"{target.resource_type}.{name} is marked deprecated. Still "
                        f"accepted, but plan for its removal."
                    ),
                )
            )
        # The claim being checked: a stub exists only because the provider requires
        # the argument. See the module docstring for why a false claim is harmful
        # rather than merely redundant.
        if name in stub_names and not schema_attr["required"]:
            issues.append(
                SchemaIssue(
                    status=SchemaStatus.NOT_REQUIRED,
                    name=name,
                    detail=(
                        f"{target.resource_type}.{name} is declared as a "
                        f"provider-required argument this recipe must stub, but the "
                        f"schema marks it optional"
                        + (" and computed" if schema_attr["computed"] else "")
                        + f". Omit it: on an imported resource an optional argument "
                        f'left out keeps the live value, while `{name} = "TODO"` '
                        f"proposes changing it -- which on a replacement-forcing "
                        f"argument destroys and recreates the resource."
                    ),
                )
            )

    emitted_blocks = {name for name, _ in target.blocks}
    for name in sorted(emitted_blocks | set(target.unresolvable_required_blocks)):
        schema_block = blocks.get(name)
        if schema_block is None:
            issues.append(
                SchemaIssue(
                    status=SchemaStatus.ATTRIBUTE_MISSING,
                    name=name,
                    detail=(
                        f"{target.resource_type} has no nested block {name!r}. `tofu "
                        f'validate` fails with "Blocks of type {name!r} are not '
                        f'expected here".'
                    ),
                )
            )
            continue
        if schema_block["deprecated"]:
            issues.append(
                SchemaIssue(
                    status=SchemaStatus.DEPRECATED,
                    name=name,
                    detail=f"{target.resource_type} block {name!r} is marked deprecated.",
                )
            )
        if name in target.unresolvable_required_blocks and not schema_block["required"]:
            issues.append(
                SchemaIssue(
                    status=SchemaStatus.NOT_REQUIRED,
                    name=name,
                    detail=(
                        f"{target.resource_type} block {name!r} is declared as a "
                        f"provider-required block this recipe must stub, but the schema "
                        f"does not require it (no min_items). A stubbed block on an "
                        f"imported resource proposes replacing the real one."
                    ),
                )
            )
        # Inner attributes of a block the recipe does emit.
        inner = schema_block["inner"]["attributes"]
        for row_name, _value, _comment in dict(target.blocks).get(name, ()):
            if row_name not in inner:
                issues.append(
                    SchemaIssue(
                        status=SchemaStatus.ATTRIBUTE_MISSING,
                        name=f"{name}.{row_name}",
                        detail=(
                            f"{target.resource_type} block {name!r} has no argument "
                            f'{row_name!r}. `tofu validate` fails with "Unsupported '
                            f'argument".'
                        ),
                    )
                )

    # The other direction: something the provider requires that the recipe never
    # emits. `validate` fails on this, so it would be caught by the HCL tests -- but
    # only for a recipe a finding in the fixtures happens to exercise, and only if
    # someone runs the tofu-backed tests. Checking it here covers every recipe.
    covered = set_names | stub_names
    for name, schema_attr in sorted(attrs.items()):
        if schema_attr["required"] and name not in covered:
            issues.append(
                SchemaIssue(
                    status=SchemaStatus.REQUIRED_MISSING,
                    name=name,
                    detail=(
                        f"{target.resource_type} requires {name!r} and this recipe "
                        f"neither sets it nor stubs it. `tofu validate` fails with "
                        f'"Missing required argument".'
                    ),
                )
            )
    covered_blocks = emitted_blocks | set(target.unresolvable_required_blocks)
    for name, schema_block in sorted(blocks.items()):
        if schema_block["required"] and name not in covered_blocks:
            issues.append(
                SchemaIssue(
                    status=SchemaStatus.REQUIRED_MISSING,
                    name=name,
                    detail=(
                        f"{target.resource_type} requires at least one {name!r} block "
                        f"and this recipe emits none. `tofu validate` fails."
                    ),
                )
            )

    return SchemaResult(
        **base,
        provider_version=schema.version,
        issues=tuple(sorted(issues, key=lambda i: (-i.status.rank, i.name))),
    )


def verify_all_hcl(
    recipes: tuple[Recipe, ...], schema: ProviderSchema | None
) -> tuple[SchemaResult, ...]:
    """Check every recipe's HCL target. Returns results in the order given."""
    return tuple(verify_recipe_hcl(r, schema) for r in recipes)


__all__ = [
    "MAX_SCHEMA_BYTES",
    "SCHEMA_ENV_VAR",
    "ProviderSchema",
    "SchemaIssue",
    "SchemaResult",
    "SchemaSourceError",
    "SchemaStatus",
    "find_schema_path",
    "load_provider_schema",
    "verify_all_hcl",
    "verify_recipe_hcl",
]
