"""Curated AWS remediation recipes.

Every recipe here has been verified in two ways:

1. The AWS operation and parameter names were checked against the botocore
   service model shipped with AWS CLI v2 (see :mod:`remgen.providers.aws.drift`).
2. The HCL resource type and import identifier format were read from the AWS
   provider's own documentation source, not inferred.

Coverage is intentionally partial. A wrong recipe is worse than a missing one,
so a policy appears here only once its remediation has been checked end to end.
Everything else is reported by ``awsremgen policies --unsupported`` so the gap is
visible rather than silent.
"""

from __future__ import annotations

from remgen.core.model import Recipe

from .curated import RECIPES as _CURATED

#: Mapping of Tenable policy UUID -> Recipe.
REGISTRY: dict[str, Recipe] = {r.policy_id: r for r in _CURATED}

if len(REGISTRY) != len(_CURATED):
    raise RuntimeError("Duplicate policy_id in the recipe registry")


def get(policy_id: str) -> Recipe | None:
    """Return the recipe for ``policy_id``, or ``None`` if unsupported."""
    return REGISTRY.get(policy_id)


def all_recipes() -> tuple[Recipe, ...]:
    """Return every recipe, ordered by policy title for stable output."""
    return tuple(sorted(REGISTRY.values(), key=lambda r: r.policy_title))


__all__ = ["REGISTRY", "all_recipes", "get"]
