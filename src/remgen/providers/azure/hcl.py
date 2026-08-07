"""The Azure-specific part of HCL rendering: the scope statement.

Everything else about generating configuration -- import blocks, label uniqueness,
attribute alignment, TODO stubs -- is cloud-neutral and lives in
:mod:`remgen.core.generators.hcl`. What is here is the one block that names a real
provider type and its credential guard.

**The guard is weaker than AWS's, and pretending otherwise is the failure this module
is written around.** AWS's block sets ``allowed_account_ids``, which makes a credential
mismatch *fail the plan*. ``azurerm`` has no equivalent: of its 29 provider arguments
(schema 5.0.1) not one is an allow-list, so ``subscription_id`` **selects** a
subscription rather than asserting which one is acceptable. Every argument is checked
against the schema rather than recalled, because the whole point of this block is to be
the thing that is right when the rest of the file is being trusted.

The practical difference: an ``azurerm`` provider with the wrong ``subscription_id``
does not fail, it *targets the other subscription* -- and because these files are paired
with ``import`` blocks whose ids are fully-qualified ARM resource ids, the mismatch
surfaces as a confusing "resource not found" rather than as a wrong-scope error. There
is one thing working in Azure's favor and it is worth knowing: an ARM resource id
contains its own subscription id, so unlike an AWS bucket name there is no such thing as
a same-named resource in another subscription that could be silently adopted. The wrong
subscription produces a failed import, not a wrong one.

So the block states the subscription, and the comment says what the reader has to do
themselves, in place of the check that does not exist. A comment claiming a guard Azure
does not have would be worse than the honest sentence.
"""

from __future__ import annotations

from remgen.core.layout import OutputUnit

#: Scope statement plus a commented provider block. Commented rather than active for the
#: same reason as AWS's: the header instructs the user to place this file in an existing
#: workspace, which already declares a provider, and a second declaration is a
#: "Duplicate provider configuration" error.
#:
#: ``features {}`` is present because it is the conventional form every ``azurerm``
#: example shows, and this is code the reader is invited to uncomment -- a snippet that
#: does not look like the documentation it will be compared against costs more than the
#: line does.
#:
#: It is **not** included because it is required, which is what this comment first
#: claimed. Measured instead of recalled, and the claim was wrong: ``features`` is the
#: provider's only nested block but the schema sets no ``min_items``, and a provider
#: block without it passes ``tofu validate`` on azurerm 5.0.1, 4.81.0 and 3.117.1. The
#: "Insufficient features blocks" error is not something this file can trigger.
_SCOPE = """
# ---------------------------------------------------------------------------
# SCOPE: {scope}
#
# This file covers ONE subscription, because that is all an azurerm provider
# configuration covers. It may span locations: an azurerm provider block carries
# no location, so each resource names its own.
#
# CONFIRM the provider in this workspace targets subscription
# {subscription_id}. Unlike the AWS provider, azurerm has no
# `allowed_account_ids` equivalent -- `subscription_id` selects a subscription, it
# does not assert which one is acceptable, so a wrong value is not rejected. The
# import ids below are fully-qualified ARM ids that name this subscription, so a
# mismatch fails to find the resource rather than modifying the wrong one; expect
# "resource not found" if the provider is pointed elsewhere.
#
# Standalone use: uncomment this block.
#
# provider "azurerm" {{
#   subscription_id = "{subscription_id}"
#   features {{}}
# }}
# ---------------------------------------------------------------------------
"""


def scope_block(unit: OutputUnit) -> str:
    """Return the scope statement for ``unit``.

    Always returns a statement, where the AWS implementation returns ``""`` for a unit
    spanning regions. That is not an inconsistency to tidy up -- it is the same rule
    applied to a different provider. AWS omits the block when it cannot name a single
    region because the block *contains* a region and naming the wrong one would be worse
    than naming none. An ``azurerm`` provider block carries no location at all, so a unit
    spanning locations leaves nothing in this block undetermined and there is nothing to
    omit. Subscription is the only thing the block asserts, and it is a hard boundary in
    the layout, so it is always known.

    ``unit.region is None`` is therefore the *normal* Azure case rather than a guard
    case; see ``hcl_provider_is_region_scoped=False`` in
    :mod:`remgen.providers.azure`.
    """
    return _SCOPE.format(scope=unit.scope_description, subscription_id=unit.scope_id)


__all__ = ["scope_block"]
