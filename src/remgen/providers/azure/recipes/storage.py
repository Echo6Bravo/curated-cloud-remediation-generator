"""Storage recipes.

One module per Azure service. The module name is the ``azure.mgmt`` package name --
``azure.mgmt.storage`` -- which is what :mod:`remgen.providers.azure.drift` resolves
and which is asserted rather than assumed; see
``test_each_service_module_only_holds_recipes_for_that_service`` in
``tests/test_azure_recipe_set.py``.

**Every recipe here shares one HCL hazard, so it is stated once.**
``azurerm_storage_account`` has five required arguments -- ``name``,
``resource_group_name``, ``location``, ``account_tier``,
``account_replication_type`` -- and a finding supplies none of them. It carries an
ARM resource id, which the ``import`` block consumes; the paired ``resource`` block
still has to satisfy the provider. So every recipe declares all five as
``unresolvable_required_attributes``, and the generator marks the block INCOMPLETE.

Two things make those placeholders more dangerous here than in the AWS recipes, and
both were measured rather than assumed:

* **``"TODO"`` is not a usable placeholder.** ``tofu validate`` rejects it for three
  of the five: ``name`` must be 3-24 lowercase alphanumerics,
  ``account_tier`` must be ``Standard`` or ``Premium``, and
  ``account_replication_type`` must be one of LRS/ZRS/GRS/RAGRS/GZRS/RAGZRS. The
  placeholders below are type-valid values that validate, because a stub that fails
  validation gives the user a parse error instead of a reviewable plan.
* **A wrong placeholder can force replacement, and a storage account cannot be
  replaced without destroying its data.** Read from the provider source at v5.0.1:
  ``name`` and ``account_tier`` are ``Required + ForceNew``, and
  ``account_replication_type`` force-replaces via ``ForceNewIfChange`` when the value
  crosses the LRS/GRS/RAGRS family <-> ZRS/GZRS/RAGZRS boundary -- so ``"LRS"`` left
  in place on a ZRS account proposes a replacement, not a resize. This is the
  ``aws_dynamodb_table`` hazard again, except here the stubs cannot be dropped:
  unlike DynamoDB's ``hash_key``, these five are genuinely required and validate does
  reject the block without them. The INCOMPLETE warning and these comments are what
  the user has instead.

The ``az`` path has no equivalent problem: ``storage account update`` targets the
account by ``--ids`` and changes exactly the one setting named.
"""

from __future__ import annotations

from remgen.core.model import ApiCall, CostImpact, Effort, HclTarget, Recipe

#: The five arguments ``azurerm_storage_account`` requires and a finding cannot
#: supply. Shared by every recipe in this module because it is a property of the
#: resource type, not of any one remediation -- five copies would drift the first
#: time the provider changed one of them, and the drift would be silent because each
#: recipe is verified independently and would still pass.
#:
#: Values are type-valid, not descriptive: ``tofu validate`` enforces a pattern or an
#: enum on three of the five, so ``"TODO"`` fails to parse. The TODO goes in the
#: comment, which the generator renders on the same line.
_ACCOUNT_STUBS: tuple[tuple[str, str, str], ...] = (
    (
        "name",
        '"todoreplacethisname"',
        "TODO: the account's real name (3-24 lowercase alphanumerics). ForceNew: a "
        "wrong value destroys and recreates the account",
    ),
    ("resource_group_name", '"TODO-resource-group"', "TODO: the account's resource group"),
    ("location", '"TODO-location"', "TODO: e.g. eastus"),
    (
        "account_tier",
        '"Standard"',
        "TODO: the account's real tier (Standard or Premium). ForceNew: a wrong value "
        "destroys and recreates the account",
    ),
    (
        "account_replication_type",
        '"LRS"',
        "TODO: the account's real replication type. Crossing the LRS/GRS <-> ZRS/GZRS "
        "boundary forces replacement",
    ),
)

# The ARM id format the azurerm provider parses on import, taken from its own
# commonids.StorageAccountId: /subscriptions/{sub}/resourceGroups/{rg}/providers/
# Microsoft.Storage/storageAccounts/{name}. A finding's resource_id for a storage
# account is already exactly that, so the template is the id unchanged.
_IMPORT_ID = "{resource_id}"

# ---------------------------------------------------------------------------
# HTTPS-only traffic
#
# Safety: reversible, free, and it does not touch stored data. It *can* break a
# client still connecting over plain HTTP, which is why the caveat is explicit --
# but that client's traffic is unencrypted today, which is the finding.
# data_path_impact stays False: this rejects a protocol, it does not drop, reroute
# or transform requests that were already using it. See the caveat for the honest
# version of that distinction.
# ---------------------------------------------------------------------------
_HTTPS_ONLY = Recipe(
    policy_id="bed905d4-758c-4698-9ed8-4cdd4271eb4e",
    policy_title="Storage Account in transit is not enabled",
    summary="Require HTTPS for all storage endpoints so data in transit is encrypted.",
    api=ApiCall(
        service="storage",
        operation="StorageAccountsOperations.update",
        # The SDK's Python property name. The wire name is supportsHttpsTrafficOnly
        # and the azurerm argument is https_traffic_only_enabled -- three vocabularies
        # for one setting, which is why each axis is checked against its own source
        # rather than one name being assumed to work everywhere.
        parameters=("enable_https_traffic_only",),
    ),
    cli_template=(
        "az storage account update "
        "--ids {resource_id} "
        "--https-only true "
        "--subscription {account_id}"
    ),
    hcl=HclTarget(
        resource_type="azurerm_storage_account",
        attributes=(("https_traffic_only_enabled", "true"),),
        import_id_template=_IMPORT_ID,
        unresolvable_required_attributes=_ACCOUNT_STUBS,
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="az storage account update --ids <resource-id> --https-only false",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    caveats=(
        "Any client still connecting over plain HTTP will fail after this change. That "
        "traffic is unencrypted today, which is the finding -- but confirm no legacy "
        "client depends on it before applying fleet-wide.",
        "The azurerm default for this argument is already true, so a workspace that "
        "manages this account without naming the argument is not the source of the "
        "drift; the account was most likely created outside IaC.",
    ),
    docs_url="https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/update",
)

# ---------------------------------------------------------------------------
# Minimum TLS version
#
# Safety: reversible, free, no data-path impact. TLS1_2 rather than TLS1_3: the
# `az` help states "TLS1_3 is not yet supported" for storage, and azurerm 5.0.1
# accepts only TLS1_2 unless the deprecated data-plane feature flag is set (read
# from the provider source, where the wider enum is behind `!features.FivePointOh()`).
# ---------------------------------------------------------------------------
_MIN_TLS = Recipe(
    policy_id="0662810d-c71d-46a3-a937-e1c2b24792e4",
    policy_title="Storage Account insecure communication",
    summary="Require TLS 1.2 or later so clients cannot negotiate a deprecated cipher suite.",
    api=ApiCall(
        service="storage",
        operation="StorageAccountsOperations.update",
        # SDK property; the azurerm argument is min_tls_version and the wire name is
        # minimumTlsVersion. Same three-vocabulary problem as above.
        parameters=("minimum_tls_version",),
    ),
    cli_template=(
        "az storage account update "
        "--ids {resource_id} "
        "--min-tls-version TLS1_2 "
        "--subscription {account_id}"
    ),
    hcl=HclTarget(
        resource_type="azurerm_storage_account",
        attributes=(("min_tls_version", '"TLS1_2"'),),
        import_id_template=_IMPORT_ID,
        unresolvable_required_attributes=_ACCOUNT_STUBS,
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="az storage account update --ids <resource-id> --min-tls-version TLS1_0",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    caveats=(
        "A client whose TLS stack cannot negotiate 1.2 will fail. In practice that "
        "means very old SDK versions and .NET Framework applications with TLS 1.2 not "
        "explicitly enabled.",
        "The reverse command sets TLS1_0, which restores the weakest setting rather "
        "than whatever the account had before. If it was TLS1_1, pass that instead.",
        "Reversing via the HCL is not possible: `az` accepts TLS1_0 and TLS1_1, but "
        "azurerm 5.x validates min_tls_version against TLS1_2 alone, so reverting the "
        "generated attribute fails at plan time. Use the reverse command above.",
    ),
    docs_url="https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/update",
)

# ---------------------------------------------------------------------------
# Cross-tenant replication
#
# Safety: reversible, free, and it removes a capability rather than changing how
# existing requests are served. It is a no-op unless an object replication policy
# spanning tenants exists -- and if one does, this breaks it, which is the caveat.
# ---------------------------------------------------------------------------
_CROSS_TENANT_REPLICATION = Recipe(
    policy_id="29307516-af03-445b-a22c-5dfa62598b22",
    policy_title="Storage Account cross-tenant replication is enabled",
    summary="Disallow object replication to storage accounts in other Entra ID tenants.",
    api=ApiCall(
        service="storage",
        operation="StorageAccountsOperations.update",
        parameters=("allow_cross_tenant_replication",),
    ),
    cli_template=(
        "az storage account update "
        "--ids {resource_id} "
        "--allow-cross-tenant-replication false "
        "--subscription {account_id}"
    ),
    hcl=HclTarget(
        resource_type="azurerm_storage_account",
        # The azurerm argument is positive where the API property is too, but the
        # remediation is the false value: cross_tenant_replication_enabled = false
        # corresponds to --allow-cross-tenant-replication false.
        attributes=(("cross_tenant_replication_enabled", "false"),),
        import_id_template=_IMPORT_ID,
        unresolvable_required_attributes=_ACCOUNT_STUBS,
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint=(
        "az storage account update --ids <resource-id> --allow-cross-tenant-replication true"
    ),
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    caveats=(
        "An existing object replication policy whose source or destination is in "
        "another tenant stops replicating. Check for cross-tenant replication policies "
        "on this account before applying; there is no warning from the API.",
    ),
    docs_url="https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/update",
)

#: Every storage recipe. Aggregated by :mod:`remgen.providers.azure.recipes`.
#:
#: **``392599b3`` "Storage Account Shared Key access is enabled" is deliberately not
#: here**, though all three axes pass for it (``--allow-shared-key-access false``,
#: SDK ``allow_shared_key_access``, azurerm ``shared_access_key_enabled``). Disabling
#: Shared Key breaks every caller using an account key or a SAS -- which is most
#: tooling, including parts of ``az`` itself -- so it belongs to a tier this recipe
#: set does not ship: ``data_path_impact=True``, hence DISRUPTIVE, and v1 promises
#: none. It is a real remediation and a genuinely good one; it is a migration, not a
#: single call, and shipping it beside three settings that break nothing would
#: misrepresent it. See ROADMAP.md.
RECIPES: tuple[Recipe, ...] = (_HTTPS_ONLY, _MIN_TLS, _CROSS_TENANT_REPLICATION)

__all__ = ["RECIPES"]
