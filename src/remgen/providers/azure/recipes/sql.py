"""SQL recipes.

One module per Azure service. The module name is the ``azure.mgmt`` package name --
``azure.mgmt.sql`` -- which is what :mod:`remgen.providers.azure.drift` resolves; see
``test_each_service_module_only_holds_recipes_for_that_service`` in
``tests/test_azure_recipe_set.py``.

**Two recipes here ship no HCL at all, and both reasons are measurements rather than
omissions.** Everything else in the tool emits a CLI command *and* an ``import``
block; these two emit only the command, which is a supported shape
(``Recipe.hcl`` is ``HclTarget | None``) but a rare one, so each records why.

*Minimum TLS version* (``17af7bf3``) cannot be written against
``azurerm_mssql_server``. The provider requires ``administrator_login`` and
``administrator_login_password`` through ``ExactlyOneOf``/``AtLeastOneOf`` rules that
the machine-readable schema does not express, so the HCL axis passes and ``tofu
validate`` then reports three "Missing required argument" errors. Satisfying it would
mean emitting a password placeholder into generated configuration -- a
credential-shaped stub in a file the user is told to commit. **This docstring
previously concluded the recipe was therefore absent, and that was one step further
than the measurement supports.** What the measurement rules out is the HCL half; ``az
sql server update --minimal-tls-version`` was always available and is what an
operator would run. So the recipe ships CLI-only, and the policy is supported rather
than reported as a gap.

*Microsoft Defender for SQL* (``675d3b4d``) has no usable HCL half for a different
reason: ``azurerm`` models this through
``azurerm_mssql_server_security_alert_policy``, which is the older
``securityAlertPolicies`` API rather than the ``advancedThreatProtectionSettings``
one the CLI calls, and its import id is the server id with
``/securityAlertPolicies/Default`` appended. Every Azure import id in this tool is
the finding's ``resource_id`` unchanged -- asserted by
``test_every_hcl_import_id_is_a_full_arm_id``, because the ``azurerm`` importers
*parse* ids with typed parsers -- and the generator substitutes whole finding fields
rather than appending to them. There is also no ``azurerm`` resource for the ATP
endpoint itself; ``azurerm_advanced_threat_protection`` is the Microsoft.Security
per-resource setting, addressed by ``target_resource_id``, and is not what this
policy measures.

That the min-TLS plan lost to a ``tofu validate`` run is the third time an Azure axis
overruled a plan, and the only one where the schema alone was not enough to see it.
Worth keeping: the schema axis cannot detect a cross-argument requirement, so a new
recipe still needs a real ``tofu validate`` run against the block it will emit.
``CONTRIBUTING.md`` says so as a rule; this is the finding it came from.
"""

from __future__ import annotations

from remgen.core.model import ApiCall, CostImpact, Effort, HclTarget, Recipe

# ---------------------------------------------------------------------------
# Transparent data encryption
#
# Safety: reversible, free, and it does not interrupt connections -- TDE encrypts
# at rest, transparently to clients, which is the "transparent" in the name.
# Encryption runs as a background scan over the data files; queries continue
# throughout. effort stays LOW because no restart, failover or replacement is
# involved, and the caveats carry the honest cost of the background scan.
# ---------------------------------------------------------------------------
_TDE = Recipe(
    policy_id="f3c5d6e7-d8f0-48fd-97ab-16585ff981f3",
    policy_title="SQL Database is not encrypted with transparent data encryption",
    summary="Enable transparent data encryption so the database files and backups are encrypted.",
    api=ApiCall(
        service="sql",
        # Both halves were checked and one was wrong on the first attempt: this is
        # begin_create_or_update, not create_or_update. The begin_ prefix marks a
        # long-running operation, and the API axis rejected the guess before this
        # recipe existed -- which is the clearest evidence that axis earns its keep.
        operation="TransparentDataEncryptionsOperations.begin_create_or_update",
        # `state` on LogicalDatabaseTransparentDataEncryption, whose wire path is
        # properties.state. azure.mgmt.sql is an old-style generated package, so this
        # name comes from _attribute_map rather than a rest_field annotation --
        # storage, in the neighbouring module, is the other style.
        parameters=("state",),
    ),
    # `az sql db tde set` takes --ids, so the finding's ARM database id addresses it
    # directly; --status is [Required] and takes Enabled/Disabled.
    cli_template=(
        "az sql db tde set --ids {resource_id} --status Enabled --subscription {account_id}"
    ),
    hcl=HclTarget(
        resource_type="azurerm_mssql_database",
        attributes=(("transparent_data_encryption_enabled", "true"),),
        # commonids.SqlDatabaseId: /subscriptions/{sub}/resourceGroups/{rg}/providers/
        # Microsoft.Sql/servers/{server}/databases/{database} -- read from the
        # provider's own id type, which is also what its importer validates against. A
        # finding's resource_id for a SQL database is already that form.
        import_id_template="{resource_id}",
        # Both of the resource type's required arguments, because a finding supplies
        # neither in the shape the provider wants: it has the database's full ARM id,
        # while the block needs the bare database name and the *server's* id. Both are
        # derivable from the import id by hand, which is what the TODOs say; they are
        # not derivable by the generator, whose templates substitute whole finding
        # fields and do not slice them.
        #
        # Both are ForceNew (provider source, v5.0.1), and an Azure SQL database
        # cannot be replaced without losing its data, so a stub left in place is
        # destructive rather than merely wrong. The generator's INCOMPLETE warning
        # covers it; these comments say what specifically goes wrong.
        unresolvable_required_attributes=(
            (
                "name",
                '"TODO-database-name"',
                "TODO: the last segment of the import id above. ForceNew: a wrong "
                "value destroys and recreates the database",
            ),
            # Spelled as a whole ARM path rather than "TODO-server-resource-id",
            # which is what this said first. The provider parses this argument with
            # commonids.ParseSqlServerID at *validate* time, so a placeholder that is
            # not a well-formed id fails with "invalid URI for request" -- the user
            # gets a parse error where they should be getting a reviewable plan. Same
            # class of problem as the storage account's name and tier stubs, found the
            # same way: by running tofu validate on the generated file rather than
            # trusting the schema, which types this as a plain string.
            (
                "server_id",
                '"/subscriptions/TODO-subscription-id/resourceGroups/TODO-resource-group'
                '/providers/Microsoft.Sql/servers/TODO-server-name"',
                "TODO: the import id above, truncated before /databases/. ForceNew",
            ),
        ),
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="az sql db tde set --ids <resource-id> --status Disabled",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    caveats=(
        "Encryption runs as a background scan over the database files. Queries continue "
        "during it, but expect additional I/O until it completes -- on a large database "
        "that is hours, and 'tde show' reports the progress.",
        "TDE cannot be disabled again on anything but a Data Warehouse SKU: the "
        "azurerm provider rejects the plan, and the reverse command is accepted only "
        "for DW databases. Treat this as effectively one-way for a normal database.",
        "This enables service-managed keys. A policy requiring a customer-managed key "
        "for TDE is a separate finding and is not remediated by this.",
    ),
    docs_url=(
        "https://learn.microsoft.com/en-us/rest/api/sql/transparent-data-encryptions/create-or-update"
    ),
)

# ---------------------------------------------------------------------------
# Server minimum TLS version
#
# CLI-only. See the module docstring for why the HCL half cannot be written without
# emitting a password placeholder into generated configuration.
#
# 1.2 rather than 1.3, and that is a deliberate floor rather than the strongest
# available value. The API accepts None/1.0/1.1/1.2/1.3 (read from the SDK's
# MinimalTlsVersion enum, and `az`'s own SqlServerMinimalTlsVersionType), so 1.3
# is writable -- but Azure SQL's TLS 1.3 support depends on the client driver, and
# older ODBC/JDBC drivers that negotiate 1.2 happily do not offer 1.3 at all. Setting
# 1.3 would strand them, which is a worse failure than the finding. 1.2 is what the
# policy asks for and what every currently supported driver negotiates.
#
# This withdraws access from clients that are working today, which is the case
# `critical_caveats` exists for: the change is reversible, free and in-place, so it
# derives to SAFEST and the artifact's banner says so, while a TLS 1.0 client stops
# connecting the moment it applies. Same reading as _HTTPS_ONLY and _MIN_TLS in the
# storage module, and as the S3 Block Public Access recipe on the AWS side --
# data_path_impact stays False because this rejects a connection by policy rather than
# altering an established request path, and setting it True would derive DISRUPTIVE,
# which v1 does not ship.
# ---------------------------------------------------------------------------
_MIN_TLS_VERSION = Recipe(
    policy_id="17af7bf3-0f70-4822-bc09-e41bfd97dbdf",
    policy_title="SQL Server TLS version does not meet minimum requirements",
    summary="Raise the server's minimum TLS version to 1.2 so older clients cannot negotiate down.",
    api=ApiCall(
        service="sql",
        # begin_update, not update: `az sql server update` drives a long-running
        # operation, and ServersOperations declares no plain `update`. The API axis
        # rejects the un-prefixed name, which is how the TDE recipe's operation name
        # was caught before it shipped.
        operation="ServersOperations.begin_update",
        # `minimal_tls_version` on Server and ServerUpdate; wire path
        # properties.minimalTlsVersion. Note the SDK/API spelling has one `l`
        # (minimal) while the azurerm argument is `minimum_tls_version` -- a genuine
        # difference between the two vocabularies, not a typo in either place.
        parameters=("minimal_tls_version",),
    ),
    cli_template=(
        "az sql server update --ids {resource_id} "
        "--minimal-tls-version 1.2 --subscription {account_id}"
    ),
    hcl=None,
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="az sql server update --ids <resource-id> --minimal-tls-version 1.0",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    critical_caveats=(
        "ANY CLIENT THAT CANNOT NEGOTIATE TLS 1.2 STOPS CONNECTING IMMEDIATELY, with a "
        "connection-level error rather than a login failure. Check for legacy ODBC and "
        "JDBC drivers, .NET Framework applications older than 4.7 that have not "
        "enabled TLS 1.2 explicitly, and embedded or appliance clients, before "
        "applying. The server does not warn and there is no grace period.",
    ),
    caveats=(
        "Existing connections are not dropped. The change applies to new connections, "
        "so an application with a warm pool can keep working for hours and then fail "
        "on its next reconnect -- which is well after the change looks successful.",
        "This is set on the server and applies to every database on it, including ones "
        "with no finding of their own.",
        "The reversal restores 1.0, which re-opens the finding. Azure also accepts "
        "'None' for no minimum, which this tool never writes.",
        "No HCL is generated for this recipe. The azurerm provider requires an "
        "administrator login and password on azurerm_mssql_server through rules the "
        "machine-readable schema does not express, so a generated block would either "
        "fail to validate or carry a credential-shaped placeholder. Set "
        "minimum_tls_version in whatever module already manages the server.",
    ),
    docs_url="https://learn.microsoft.com/en-us/rest/api/sql/servers/update",
)

# ---------------------------------------------------------------------------
# Microsoft Defender for SQL (Advanced Threat Protection)
#
# **The one recipe in either cloud that costs money and is still SAFEST, and that
# needed a deliberate decision rather than a derivation.** `safety_tier` is derived
# from `reversible`, `data_path_impact`, `effort` and `blocks_iac_destroy`, and
# CostImpact.LOW does not appear in the formula -- so a per-server charge derives to
# SAFEST, which is what a default run emits unreviewed.
#
# Three options were weighed. Declaring cost_impact=USAGE_SCALED would derive CAUTION
# and would be false: Defender for SQL is a flat per-server monthly charge, not a
# charge that scales with usage, and USAGE_SCALED is what the S3 versioning recipe
# means. Forcing CAUTION through another field would be misdeclaring that field.
# So the tier stays SAFEST with cost_impact=LOW, the charge is stated in
# `critical_caveats` where the operator reads it beside the command, and
# `test_safest_recipes_carry_no_ongoing_cost` allowlists this policy id with that
# reason -- which its own docstring sanctions, and which is the only place the
# combination is visible.
#
# The honest gap is the same one the S3 module records: the tier has no input meaning
# "free to run, not free to keep". Adding one is a safety-model change, not a recipe.
#
# `az sql server advanced-threat-protection-setting update` is the current command;
# the older `az sql server threat-policy update` addressed securityAlertPolicies and
# is what azurerm still models. Both --state and --ids are confirmed present in
# `--help`, and the accepted values Enabled/Disabled come from the API's
# AdvancedThreatProtectionState enum (whose third value, New, is a read-only initial
# state and is never written).
# ---------------------------------------------------------------------------
_DEFENDER = Recipe(
    policy_id="675d3b4d-8168-4bc8-bae2-ebad12102b53",
    policy_title="SQL Server Microsoft Defender is not enabled",
    summary=(
        "Enable Microsoft Defender for SQL so the server is monitored for anomalous "
        "activity and SQL injection."
    ),
    api=ApiCall(
        service="sql",
        # Verified against the bundled SDK: the operations class name really does carry
        # the `Settings` suffix while the model class does not. First attempt named the
        # model `ServerAdvancedThreatProtectionSetting`, which the API axis rejected.
        operation="ServerAdvancedThreatProtectionSettingsOperations.begin_create_or_update",
        # `state` on ServerAdvancedThreatProtection; wire path properties.state.
        parameters=("state",),
    ),
    cli_template=(
        "az sql server advanced-threat-protection-setting update --ids {resource_id} "
        "--state Enabled --subscription {account_id}"
    ),
    # No HCL. azurerm models this through the older securityAlertPolicies API, whose
    # import id appends /securityAlertPolicies/Default to the server id -- and every
    # Azure import id in this tool is the finding's resource_id unchanged, because the
    # provider's importers parse ids with typed parsers and the generator substitutes
    # whole fields rather than appending to them. See the module docstring.
    hcl=None,
    effort=Effort.LOW,
    reversible=True,
    reverse_hint=(
        "az sql server advanced-threat-protection-setting update --ids <resource-id> "
        "--state Disabled"
    ),
    data_path_impact=False,
    # LOW rather than NONE, and LOW rather than USAGE_SCALED. The charge is real and
    # recurring, so NONE would be false; it is flat per server rather than scaled by
    # usage, so USAGE_SCALED would be false too. This is the only recipe in either
    # cloud that is SAFEST with a non-NONE cost, and it is allowlisted by policy id in
    # test_safest_recipes_carry_no_ongoing_cost with this reason.
    cost_impact=CostImpact.LOW,
    blocks_iac_destroy=False,
    critical_caveats=(
        "THIS ADDS A RECURRING CHARGE. Microsoft Defender for SQL is billed per server "
        "per month at the subscription's Defender for Cloud rate, and enabling it at "
        "the server level is not free the way most remediations in this tool are. "
        "Confirm the spend is approved before running this across a fleet -- a default "
        "run emits it under a SAFEST banner, because the safety tier measures "
        "disruption rather than cost.",
    ),
    caveats=(
        "Nothing is interrupted and no connection is affected. Defender inspects "
        "telemetry out of band, so the only consequence at apply time is the charge "
        "and the alerts that follow.",
        "Alerts are delivered through Microsoft Defender for Cloud, and email "
        "recipients are configured separately. Enabling this without configuring "
        "notifications produces findings nobody is paged for.",
        "This enables Defender at the server level, which covers every database on the "
        "server. A vulnerability-assessment storage account is a separate setting and "
        "is not configured by this.",
        "No HCL is generated. The azurerm provider models this through the older "
        "securityAlertPolicies API rather than the advancedThreatProtectionSettings "
        "endpoint this command calls, and its import id is not the finding's resource "
        "id, so no import block can be generated from a finding alone.",
    ),
    docs_url=(
        "https://learn.microsoft.com/en-us/rest/api/sql/"
        "server-advanced-threat-protection-settings/create-or-update"
    ),
)

#: Every SQL recipe. Aggregated by :mod:`remgen.providers.azure.recipes`.
RECIPES: tuple[Recipe, ...] = (_TDE, _MIN_TLS_VERSION, _DEFENDER)

__all__ = ["RECIPES"]
