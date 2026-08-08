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

**One recipe here ships with ``hcl=None``, which no other recipe in this project
does.** ``_TRUSTED_SERVICES_BYPASS`` sets ``--bypass AzureServices``, and the
``azurerm`` equivalent is the ``bypass`` argument inside a ``network_rules`` block
whose ``default_action`` is ``Required`` -- read from the provider's own schema, not
its documentation. A finding carries no network rules, so every value we could put
there is invented, and both possible inventions are harmful in a way the existing
stub pattern is not:

* ``default_action = "Allow"`` generates configuration that *opens* the account.
* ``default_action = "Deny"`` generates configuration that cuts off every existing
  IP rule and VNet subnet, because ``ip_rules`` and ``virtual_network_subnet_ids``
  are ``Computed`` and their absence from the block empties them on apply.

The five ``_ACCOUNT_STUBS`` risk a replacement *warning* a reviewer can see in a
plan. This risks a silent network lockout or exposure from a value the tool made up.
So the HCL axis is declined rather than approximated -- the same rule that keeps the
Key Vault RBAC recipe out of this package entirely, applied to one axis instead of
all three. The ``az`` command is verified and safe: ``--bypass`` merges into the
existing rule set rather than replacing it.
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
    critical_caveats=(
        "Any client still connecting over plain HTTP will fail after this change. That "
        "traffic is unencrypted today, which is the finding -- but confirm no legacy "
        "client depends on it before applying fleet-wide.",
    ),
    caveats=(
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
    critical_caveats=(
        "A client whose TLS stack cannot negotiate 1.2 will fail. In practice that "
        "means very old SDK versions and .NET Framework applications with TLS 1.2 not "
        "explicitly enabled.",
    ),
    caveats=(
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
    critical_caveats=(
        "An existing object replication policy whose source or destination is in "
        "another tenant stops replicating. Check for cross-tenant replication policies "
        "on this account before applying; there is no warning from the API.",
    ),
    docs_url="https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/update",
)

# ---------------------------------------------------------------------------
# SFTP
#
# Safety: reversible, free. Disabling SFTP removes a protocol surface; it does not
# touch stored data, and blob/Data Lake access over HTTPS is unaffected.
#
# data_path_impact stays False on the same reading used for HTTPS-only above: this
# withdraws a protocol rather than dropping or rerouting requests inside one. An
# SFTP client *will* stop connecting, which is the first caveat -- and unlike the
# HTTPS case that traffic is not itself the finding, so the caveat is the stronger
# of the two.
# ---------------------------------------------------------------------------
_SFTP_DISABLED = Recipe(
    policy_id="a86dc2ab-4069-44b2-b55c-1e46b529eb2d",
    policy_title="Storage Account SFTP is enabled",
    summary="Disable the SFTP endpoint so the account is reachable only over HTTPS APIs.",
    api=ApiCall(
        service="storage",
        operation="StorageAccountsOperations.update",
        # SDK property is is_sftp_enabled; the az flag is --enable-sftp and the
        # azurerm argument is sftp_enabled. Three vocabularies again, each read from
        # its own source: `enable_sftp` is *not* an SDK property name and was checked
        # rather than assumed.
        parameters=("is_sftp_enabled",),
    ),
    cli_template=(
        "az storage account update "
        "--ids {resource_id} "
        "--enable-sftp false "
        "--subscription {account_id}"
    ),
    hcl=HclTarget(
        resource_type="azurerm_storage_account",
        attributes=(("sftp_enabled", "false"),),
        import_id_template=_IMPORT_ID,
        unresolvable_required_attributes=_ACCOUNT_STUBS,
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="az storage account update --ids <resource-id> --enable-sftp true",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    critical_caveats=(
        "Any SFTP client using this account stops working immediately. Unlike the "
        "HTTPS-only finding, that traffic is not insecure by itself -- SFTP is "
        "encrypted -- so confirm no data-transfer job depends on it before applying.",
    ),
    caveats=(
        "SFTP requires hierarchical namespace, so this recipe is a no-op on accounts "
        "that never had it enabled. Those accounts do not raise the finding.",
        "Local users are the identity mechanism SFTP uses. Disabling SFTP leaves any "
        "configured local users in place but unusable; see the local-user recipe to "
        "remove that surface as well.",
    ),
    docs_url="https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/update",
)

# ---------------------------------------------------------------------------
# Local (SFTP/NFS) user authentication
#
# Safety: reversible, free, no data-path impact. This is the identity surface SFTP
# authenticates against -- shared-key-like credentials local to the account rather
# than Entra ID principals.
# ---------------------------------------------------------------------------
_LOCAL_USER_DISABLED = Recipe(
    policy_id="e4da24ba-a2c6-4b9e-ae02-0764ed4718a0",
    policy_title="Storage Account local user authentication is enabled",
    summary="Disable local users so the account authenticates only through Entra ID.",
    api=ApiCall(
        service="storage",
        operation="StorageAccountsOperations.update",
        # SDK property is is_local_user_enabled, not enable_local_user.
        parameters=("is_local_user_enabled",),
    ),
    cli_template=(
        "az storage account update "
        "--ids {resource_id} "
        "--enable-local-user false "
        "--subscription {account_id}"
    ),
    hcl=HclTarget(
        resource_type="azurerm_storage_account",
        attributes=(("local_user_enabled", "false"),),
        import_id_template=_IMPORT_ID,
        unresolvable_required_attributes=_ACCOUNT_STUBS,
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="az storage account update --ids <resource-id> --enable-local-user true",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    critical_caveats=(
        "Every local user on this account loses the ability to authenticate. If SFTP "
        "is in use, this breaks it -- local users are how SFTP clients sign in.",
    ),
    caveats=(
        "Reversing restores the setting, and the local user definitions survive it. "
        "The users' keys and passwords are not deleted by either direction.",
    ),
    docs_url="https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/update",
)

# ---------------------------------------------------------------------------
# SAS expiration policy
#
# Safety: reversible, free, no data-path impact -- and specifically *not* the
# Shared Key remediation, which is excluded from this module. A SAS expiration
# policy with the Log action records violations; it does not reject the tokens.
# That distinction is the whole reason this one is shippable and Shared Key is not.
#
# The policy asks that an expiration be *set*, so a value has to be chosen. 90 days
# is the interval Microsoft's own guidance names as an upper bound for long-lived
# SAS, and it is stated in the caveats as a starting point rather than a
# recommendation, because the right value is a property of the workload.
# ---------------------------------------------------------------------------
_SAS_EXPIRATION_POLICY = Recipe(
    policy_id="052f0af6-7341-4da6-b49c-d524f462cd2f",
    policy_title="Storage Account SAS expiration policy is not set",
    summary="Set a SAS expiration policy so long-lived shared access signatures are flagged.",
    api=ApiCall(
        service="storage",
        operation="StorageAccountsOperations.update",
        # Both leaves of the SasPolicy model. drift.py matches property names across
        # every model class in the package, so a nested leaf verifies without the
        # recipe naming SasPolicy itself -- see the comment at drift.py:434.
        parameters=("sas_policy", "sas_expiration_period"),
    ),
    cli_template=(
        "az storage account update "
        "--ids {resource_id} "
        "--sas-exp 90.00:00:00 "
        "--sas-exp-action Log "
        "--subscription {account_id}"
    ),
    hcl=HclTarget(
        resource_type="azurerm_storage_account",
        attributes=(),
        # A nested block, because expiration_period is Required inside sas_policy.
        # Unlike network_rules, every argument here is suppliable: the period is the
        # value being set and expiration_action has a safe non-enforcing value, so
        # nothing is invented and the block is complete.
        blocks=(
            (
                "sas_policy",
                (
                    ("expiration_period", '"90.00:00:00"', "DD.HH:MM:SS"),
                    (
                        "expiration_action",
                        '"Log"',
                        "Log records violations; Block would reject non-conforming SAS",
                    ),
                ),
            ),
        ),
        import_id_template=_IMPORT_ID,
        unresolvable_required_attributes=_ACCOUNT_STUBS,
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="az storage account update --ids <resource-id> --sas-exp 00.00:00:00",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    caveats=(
        "This sets the `Log` action, which records SAS tokens exceeding the period "
        "without rejecting them. It satisfies the policy and breaks nothing. Changing "
        "the action to `Block` is the enforcing version and *will* reject "
        "non-conforming tokens -- that is a data-path change this recipe does not make.",
        "90 days is a starting point, not a recommendation. The right period is a "
        "property of the workload; shorten it once the log shows what actually issues "
        "long-lived SAS.",
        "The policy applies to SAS created after the change. Existing long-lived "
        "tokens keep working and are not revoked by setting a policy -- revoking them "
        "means rotating the account keys.",
    ),
    docs_url="https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/update",
)

# ---------------------------------------------------------------------------
# Azure trusted services access
#
# Safety: reversible, free, no data-path impact. This *grants* a bypass rather than
# withdrawing access, which is why it breaks nothing -- the finding is that trusted
# Azure services (Backup, Monitor, Data Factory and the rest) cannot reach an
# account whose default action is Deny, and the remediation restores that path.
#
# hcl=None. The reason is the module docstring's third section, and it is a
# deliberate one-axis decline rather than an omission.
# ---------------------------------------------------------------------------
_TRUSTED_SERVICES_BYPASS = Recipe(
    policy_id="bfa6917c-773b-43d8-acc3-9cb90de0fbde",
    policy_title="Storage Account Azure trusted services access is not enabled",
    summary="Allow trusted Azure services to reach the account through its network rules.",
    api=ApiCall(
        service="storage",
        operation="StorageAccountsOperations.update",
        # `bypass` lives on NetworkRuleSet rather than on the update-parameters model.
        # That verifies because drift.py matches across every model class in the
        # package; it is called out because the name is not on the model an author
        # would look at first.
        parameters=("bypass",),
    ),
    cli_template=(
        "az storage account update "
        "--ids {resource_id} "
        "--bypass AzureServices Logging Metrics "
        "--subscription {account_id}"
    ),
    hcl=None,
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="az storage account update --ids <resource-id> --bypass None",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    caveats=(
        "This widens access rather than restricting it: trusted Microsoft services "
        "gain a path that the account's Deny default action was blocking. That is the "
        "policy's intent -- those services authenticate with a managed identity and "
        "are scoped by RBAC -- but it is a grant, so review it as one.",
        "`--bypass` replaces the whole bypass set rather than adding to it. The value "
        "here is AzureServices plus Logging and Metrics, which is the `az` default set "
        "and a superset of what the policy asks for. An account deliberately bypassing "
        "only Logging ends up with more than it had.",
        "No IaC form is generated for this recipe. The azurerm equivalent needs a "
        "`network_rules` block whose required `default_action` a finding cannot "
        "supply, and both possible stub values are harmful -- one opens the account, "
        "the other drops its existing IP and subnet allowlist. Apply the command above "
        "and reconcile your configuration by hand.",
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
#: single call, and shipping it beside settings that break nothing would
#: misrepresent it. ``AZURE_POLICY_TRIAGE.md`` records it as a rejection for this
#: reason, so the register and this note now agree; an earlier version of the
#: register listed it as actionable because all three axes pass, which is true and
#: was not sufficient.
#:
#: **Three more storage policies are absent because they cannot be recipes at all**,
#: and they are named here because each one *looks* like it belongs in this module:
#: blob versioning (``77610610``), static website hosting (``44e127a4``) and soft
#: delete (``e11afc3b``) are blob *service* properties, set by ``az storage account
#: blob-service-properties update`` -- which takes ``--account-name`` as a required
#: argument and does not accept ``--ids`` at all. :class:`Recipe` requires
#: ``{resource_id}`` in ``cli_template``, so there is no template to write. They are
#: in ``R10-not-addressable-by-resource-id`` in the register.
RECIPES: tuple[Recipe, ...] = (
    _HTTPS_ONLY,
    _MIN_TLS,
    _CROSS_TENANT_REPLICATION,
    _SFTP_DISABLED,
    _LOCAL_USER_DISABLED,
    _SAS_EXPIRATION_POLICY,
    _TRUSTED_SERVICES_BYPASS,
)

__all__ = ["RECIPES"]
