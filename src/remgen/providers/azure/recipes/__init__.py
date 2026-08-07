"""Curated Azure remediation recipes.

Every recipe here has been verified on three axes, all of which
``azremgen verify`` re-checks:

1. The ARM operation and its model properties, against the ``azure.mgmt.*`` SDK
   packages bundled inside the Azure CLI (see
   :mod:`remgen.providers.azure.drift`). Azure ships no botocore equivalent, so
   the SDKs -- code-generated from the same swagger specs ARM is built from --
   are the closest thing to a vendor-shipped machine-readable model.
2. The HCL resource type and every argument, against the ``azurerm`` provider's
   machine-readable schema (see :mod:`remgen.core.hcl_schema`) -- **not** against
   the provider documentation. Import identifier formats are read from the
   provider's own ``commonids`` id types, since the schema does not describe them.
3. The rendered ``az`` command's subcommand and flags, against ``az <command>
   --help`` (see :mod:`remgen.providers.azure.cli_surface`).

Coverage is intentionally partial, on the same rule as AWS: a wrong recipe is
worse than a missing one. Everything unsupported is reported by
``azremgen policies --unsupported`` so the gap is visible rather than silent.

**Three things the axes changed about what this package contains**, recorded here
because each is a constraint on what an Azure recipe *can* be rather than a note
about one recipe:

* **``{resource_id}`` requires ``--ids``.** ``Recipe`` demands that
  ``cli_template`` name ``{resource_id}``, and an ARM resource id can only be
  passed to a command that accepts ``--ids``. That is not universal: ``az
  keyvault update`` does not take it, so the planned Key Vault RBAC recipe cannot
  be written as a template at all and is absent rather than approximated. Check
  ``--ids`` before choosing a command, not after writing the recipe.
* **``--subscription`` is accepted but ignored alongside ``--ids``.** ``az``
  overwrites every argument carrying an ``id_part`` from the parsed id, and
  ``--subscription`` carries ``id_part='subscription'``, so it warns "option
  '--subscription' will be ignored due to use of '--ids'". The flag stays in every
  template regardless: :class:`~remgen.providers.azure.shell.SubscriptionNotPinnedError`
  requires it, the script header promises it, and the target subscription is
  still explicit because the ARM id contains it. What changes is only *which*
  token carries it.
* **A required argument the JSON schema does not mark required.** The planned SQL
  Server minimum-TLS recipe was dropped because ``azurerm_mssql_server`` enforces
  ``administrator_login`` and ``administrator_login_password`` through
  ``ExactlyOneOf``/``AtLeastOneOf`` rules that the machine-readable schema does
  not express -- the schema axis passes and ``tofu validate`` then fails. Writing
  it would have meant emitting a credential placeholder into generated
  configuration. ``azurerm_mssql_database`` was used instead, so TDE is still
  covered.

Policy IDs are the Tenable Cloud Security policy UUIDs from the live catalog.

**Layout: one module per Azure service**, named for the ``azure.mgmt`` SDK package
(``storage.py``, ``sql.py``), each exporting a ``RECIPES`` tuple -- the same
boundary the AWS package uses, and for the same reason: a recipe is reviewed
against one service's API, one command group and one set of provider resource
types. Note the SDK package name is *not* always the ``az`` command group
(``az postgres`` is ``azure.mgmt.rdbms``); the SDK name wins here, because that is
what :mod:`remgen.providers.azure.drift` resolves.

Modules are **discovered**, not listed, for the reason spelled out in
:mod:`remgen.providers.aws.recipes`: a forgotten entry in a hand-maintained list
is silent in the worst way -- the recipe imports, passes review, and never
appears in ``all_recipes``.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections import Counter

from remgen.core.model import Recipe


def _discover() -> tuple[Recipe, ...]:
    """Import every service module in this package and concatenate their recipes.

    Deliberately a separate implementation from the AWS one rather than a shared
    helper. ``test_structure.py`` asserts the two provider packages share nothing
    by import, and the duplication is four statements against a rule that exists
    because a cross-provider import is how one cloud's assumption reaches the
    other's output.
    """
    recipes: list[Recipe] = []
    modules = sorted(name for _finder, name, ispkg in pkgutil.iter_modules(__path__) if not ispkg)
    if not modules:
        raise ImportError(
            f"no recipe modules found in {__name__}; every policy would report as "
            f"unsupported and the tool would emit nothing while reporting success"
        )
    for name in modules:
        module = importlib.import_module(f"{__name__}.{name}")
        found = getattr(module, "RECIPES", None)
        if not isinstance(found, tuple) or not found:
            raise ImportError(
                f"{__name__}.{name} does not export a non-empty RECIPES tuple. Every "
                f"module in this package is loaded as a recipe source; if this file is "
                f"a helper rather than a recipe set, it belongs outside the package."
            )
        if not all(isinstance(r, Recipe) for r in found):
            raise ImportError(f"{__name__}.{name}: RECIPES holds a non-Recipe entry")
        recipes.extend(found)
    return tuple(recipes)


_ALL = _discover()

#: Mapping of Tenable policy UUID -> Recipe.
REGISTRY: dict[str, Recipe] = {r.policy_id: r for r in _ALL}

# A dict comprehension does not raise on a repeated policy_id: the later entry wins
# and the earlier becomes unreachable through `get` while still being counted. Two
# Azure policies here describe near-identical storage settings ("in transit" and
# "insecure communication"), which is exactly the situation where a copy-pasted id
# survives review.
if len(REGISTRY) != len(_ALL):
    _counts = Counter(r.policy_id for r in _ALL)
    _duplicates = sorted(pid for pid, n in _counts.items() if n > 1)
    raise RuntimeError(
        f"Duplicate policy_id in the recipe registry: {_duplicates}. One of the two "
        f"entries is unreachable through `get` while still being counted."
    )


def get(policy_id: str) -> Recipe | None:
    """Return the recipe for ``policy_id``, or ``None`` if unsupported."""
    return REGISTRY.get(policy_id)


def all_recipes() -> tuple[Recipe, ...]:
    """Return every recipe, ordered by policy title for stable output."""
    return tuple(sorted(REGISTRY.values(), key=lambda r: r.policy_title))


__all__ = ["REGISTRY", "all_recipes", "get"]
