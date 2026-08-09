"""Curated AWS remediation recipes.

Every recipe here has been verified on four axes, all of which
``awsremgen verify`` re-checks:

1. The AWS operation and its parameter names, against the botocore service model
   shipped with AWS CLI v2 (see :mod:`remgen.providers.aws.drift`).
2. The HCL resource type and every argument, against the provider's
   machine-readable schema (see :mod:`remgen.core.hcl_schema`) -- **not** against
   the provider documentation, which describes what *creating* a resource needs
   and disagrees with the schema in ways that cause data loss on an imported
   resource. Import identifier formats are read from the provider's own docs
   source, since the schema does not describe them.
3. The rendered ``aws`` command's subcommand and flags, against the CLI's own
   flag surface (see :mod:`remgen.providers.aws.cli_surface`).
4. The policy id, against the Tenable policy catalog. The one axis whose upstream
   is not AWS, and the one that catches a recipe going *quiet* rather than wrong:
   a retired policy id matches no finding, so the recipe never fires and produces
   an empty artifact set that reads as a clean estate. ``verify`` re-checks it only
   when given ``--catalog``, since there is no live adapter (see
   :mod:`remgen.core.sources`); every id here was confirmed live when written.

Coverage is intentionally partial. A wrong recipe is worse than a missing one,
so a policy appears here only once its remediation has been checked end to end.
Everything else is reported by ``awsremgen policies --unsupported`` so the gap is
visible rather than silent.

**Selection criterion: safe to remediate.** v1 contains only remediations that
are reversible, do not touch the data path, need no restart or replacement, and
carry no usage-scaled cost. That excludes plenty of *scriptable* policies -- for
example VPC flow logs is a single API call but bills on ingested volume with no
ceiling, so it is deliberately out of v1. See ROADMAP.md.

Policy IDs are the Tenable Cloud Security policy UUIDs from the live catalog.

**Layout: one module per AWS service**, named for the botocore service id
(``dynamodb.py``, ``rds.py``, ...), each exporting a ``RECIPES`` tuple. A recipe
is reviewed against one service's API, one CLI command and one set of provider
resource types, so the service is the boundary along which the reviewing splits.
It also gives the diff for a new recipe a shape a reviewer can trust: adding an
S3 policy touches ``s3.py``, so an unexpected change to another service's file is
visible rather than buried in a single long module.

Modules are **discovered**, not listed. A hand-maintained list is one more place
to forget, and forgetting there is silent in the worst way: the recipe exists,
imports cleanly and passes review, while ``all_recipes`` never returns it -- so
the policy reports as unsupported, every per-recipe test skips right past it, and
nothing anywhere fails. Discovery removes that failure mode and replaces it with
a loud one: a discovered module that does not export a well-formed ``RECIPES``
raises at import.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections import Counter

from remgen.core.model import Recipe


def _discover() -> tuple[Recipe, ...]:
    """Import every service module in this package and concatenate their recipes.

    Ordering is by module name so the aggregate is deterministic; ``all_recipes``
    re-sorts by title for output, but a stable order here keeps ``REGISTRY``
    iteration and any future ordinal-based test from depending on filesystem
    order.

    Every failure mode is raised rather than skipped. A module that does not
    export ``RECIPES``, or that exports something other than a tuple of recipes,
    is a mistake whose silent form is invisible coverage loss -- so it is an
    ``ImportError`` at startup instead, which no amount of green tests can hide.
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

# Built as a dict comprehension, so a repeated policy_id does not raise on its own:
# the later entry wins and the earlier one becomes unreachable while still being
# counted. Splitting the recipes across service modules makes that easier to do by
# accident -- a copy-pasted id in another file is no longer on the same screen -- so
# the check matters more now, not less.
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
