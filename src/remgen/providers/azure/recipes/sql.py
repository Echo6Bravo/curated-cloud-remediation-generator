"""SQL recipes.

One module per Azure service. The module name is the ``azure.mgmt`` package name --
``azure.mgmt.sql`` -- which is what :mod:`remgen.providers.azure.drift` resolves; see
``test_each_service_module_only_holds_recipes_for_that_service`` in
``tests/test_azure_recipe_set.py``.

**This module targets the database, not the server, and that was forced by a
measurement.** The planned recipe here was SQL Server minimum TLS version against
``azurerm_mssql_server``. It cannot be written: the provider requires
``administrator_login`` and ``administrator_login_password`` through
``ExactlyOneOf``/``AtLeastOneOf`` rules that the machine-readable schema does not
express, so the HCL axis passes and ``tofu validate`` then reports three "Missing
required argument" errors. Satisfying it would mean emitting a password placeholder
into generated configuration -- a credential-shaped stub in a file the user is told
to commit -- so the recipe is absent rather than approximated. The gap is real and
visible: ``17af7bf3`` "SQL Server TLS version does not meet minimum requirements"
reports as unsupported.

That is the third time an Azure axis overruled a plan, and the only one where the
schema alone was not enough to see it. Worth keeping: the schema axis cannot detect a
cross-argument requirement, so a new recipe still needs a real ``tofu validate`` run
against the block it will emit. ``CONTRIBUTING.md`` says so as a rule; this is the
finding it came from.
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

#: Every SQL recipe. Aggregated by :mod:`remgen.providers.azure.recipes`.
RECIPES: tuple[Recipe, ...] = (_TDE,)

__all__ = ["RECIPES"]
