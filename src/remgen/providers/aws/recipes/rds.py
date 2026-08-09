"""RDS recipes.

One module per AWS service. The module name is the botocore service id, which is
asserted rather than assumed -- see
``test_each_service_module_only_holds_recipes_for_that_service``.

**Two of the five recipes here ship no HCL, and this is the only AWS module where
that happens.** ``hcl`` is ``HclTarget | None`` and a CLI-only recipe is a supported
shape, but it is rare enough that each one records what ruled the HCL half out --
because "no import block" reads as an oversight otherwise.

*Public snapshot* cannot express the fix as configuration. Removing the ``all`` group
while preserving whichever explicit account ids exist requires knowing the current
list, and the generator substitutes whole finding fields rather than reading live
state, so any block it emitted would assert an account list it had guessed.

*Cluster automatic minor version upgrade* is the more interesting one, and its HCL
half was written before it was deleted. ``ModifyDBCluster`` sets the flag on the
cluster, but ``aws_rds_cluster`` declares no ``auto_minor_version_upgrade`` argument
-- read from the generated provider schema rather than the docs, where it is simply
absent from the attribute map, because Aurora applies the engine patch per instance
and the provider models it on ``aws_rds_cluster_instance``. Retargeting the HCL half
there fails for a reason no stub can cover: that resource imports by *instance*
identifier while the finding carries a *cluster* identifier, and
``import_id_template`` accepts no TODO, so the generated ``import`` block would carry
a well-formed cluster id naming nothing. The recipe's own comment records the two
schema errors the first draft made, since both came from reading the docs' argument
list instead of the schema.
"""

from __future__ import annotations

from remgen.core.model import ApiCall, CostImpact, Effort, HclTarget, Recipe

# ---------------------------------------------------------------------------
# Instance deletion protection
#
# Safety: free, reversible, metadata-only. --apply-immediately is safe here
# because the change does not require a reboot.
# ---------------------------------------------------------------------------
_DELETION_PROTECTION = Recipe(
    policy_id="4d6662cd-9f34-41eb-b152-f24c692d4fbf",
    policy_title="RDS Instance delete protection is not enabled",
    summary="Enable deletion protection so the database cannot be deleted by an API call alone.",
    api=ApiCall(
        service="rds",
        operation="ModifyDBInstance",
        parameters=("DBInstanceIdentifier", "DeletionProtection"),
    ),
    cli_template=(
        "aws rds modify-db-instance "
        "--db-instance-identifier {resource_id} "
        "--deletion-protection "
        "--apply-immediately "
        "--region {region}"
    ),
    hcl=HclTarget(
        resource_type="aws_db_instance",
        attributes=(
            ("identifier", '"{resource_id}"'),
            ("deletion_protection", "true"),
        ),
        # Verified: `terraform import aws_db_instance.default mydb-rds-instance`
        import_id_template="{resource_id}",
        # Only `instance_class` is genuinely required. The provider schema marks
        # `engine`, `allocated_storage` and `username` optional+computed, and
        # `tofu validate` accepts the block without them; they were declared here
        # from the docs, which describe what a *create* needs. On the imported
        # resource this block always accompanies, omitting them keeps the live
        # values, whereas `engine = "postgres"` on a MySQL instance proposes
        # replacing the database. `instance_class` has no such escape -- validate
        # does reject the block without it -- so it keeps its stub, and a wrong
        # instance class resizes rather than destroys.
        unresolvable_required_attributes=(
            ("instance_class", '"db.t3.micro"', "TODO: set to the instance's real class"),
        ),
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint=(
        "aws rds modify-db-instance --db-instance-identifier <id> "
        "--no-deletion-protection --apply-immediately"
    ),
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=True,
    caveats=(
        "This is a metadata-only change and does not restart the instance. "
        "--apply-immediately is included so it is not deferred to the maintenance window.",
    ),
    docs_url="https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html",
)

# ---------------------------------------------------------------------------
# Cluster deletion protection
#
# The cluster analogue of the recipe above, and deliberately near-identical: same
# safety profile (free, reversible, metadata-only), different resource. Aurora and
# Multi-AZ DB clusters are addressed by ModifyDBCluster rather than
# ModifyDBInstance, and a cluster's deletion protection is independent of its
# instances' -- so the shipped instance recipe does not cover a finding on a
# cluster, and the two policies are separate ids upstream for that reason.
#
# --apply-immediately is deliberately absent, unlike the instance recipe.
# ModifyDBCluster accepts it (confirmed in the botocore model), but for
# deletion protection there is nothing to defer: the parameter only governs
# whether *pending* modifications wait for the maintenance window, and this
# change has no pending state. The instance recipe includes it because the same
# call there can carry changes that do.
# ---------------------------------------------------------------------------
_CLUSTER_DELETION_PROTECTION = Recipe(
    policy_id="03242d06-4bec-44b5-89fa-0ebb4d926242",
    policy_title="RDS Cluster delete protection is not enabled",
    summary="Enable deletion protection so the cluster cannot be deleted by an API call alone.",
    api=ApiCall(
        service="rds",
        operation="ModifyDBCluster",
        parameters=("DBClusterIdentifier", "DeletionProtection"),
    ),
    cli_template=(
        "aws rds modify-db-cluster "
        "--db-cluster-identifier {resource_id} "
        "--deletion-protection "
        "--region {region}"
    ),
    hcl=HclTarget(
        resource_type="aws_rds_cluster",
        attributes=(
            ("cluster_identifier", '"{resource_id}"'),
            ("deletion_protection", "true"),
        ),
        # commonids-style bare identifier, same as the instance recipe:
        # `terraform import aws_rds_cluster.example my-cluster`.
        import_id_template="{resource_id}",
        # `engine` is the one argument the provider genuinely requires on this
        # resource -- schema-confirmed required, and `tofu validate` rejects the
        # block without it. It is left as a stub rather than guessed: unlike the
        # instance's `instance_class`, a wrong `engine` on an imported cluster
        # proposes *replacing* the cluster, which destroys the data. The generator's
        # INCOMPLETE banner covers it; this comment says what specifically breaks.
        unresolvable_required_attributes=(
            (
                "engine",
                '"aurora-postgresql"',
                "TODO: set to the cluster's real engine. A wrong value replaces the "
                "cluster and destroys its data",
            ),
        ),
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="aws rds modify-db-cluster --db-cluster-identifier <id> --no-deletion-protection",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=True,
    caveats=(
        "This is a metadata-only change and does not restart the cluster or its instances.",
        "Deletion protection on the cluster is independent of deletion protection on "
        "its instances. A finding for an instance is a separate policy and is not "
        "remediated by this.",
    ),
    docs_url="https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBCluster.html",
)

# ---------------------------------------------------------------------------
# Instance automatic minor version upgrade
#
# Safety: free and reversible, and it does not change anything at the moment it is
# applied -- it changes what happens at the *next* maintenance window. That is the
# whole safety story and it is why the caveats below are about a future event
# rather than an immediate one.
#
# effort stays LOW and data_path_impact stays False on the reading this project
# has used consistently: the field describes what *this command* does to requests
# in flight, and this command does nothing to them. The deferred restart is a real
# consequence and it is a caveat, not a tier input -- a minor-version patch applied
# in a maintenance window is the behaviour AWS defaults to for new instances.
# ---------------------------------------------------------------------------
_MINOR_VERSION_UPGRADE = Recipe(
    policy_id="ca0fddf1-a200-458c-a3cb-b78ad774c3d8",
    policy_title="RDS Instance automatic minor version upgrade is not enabled",
    summary=(
        "Enable automatic minor version upgrades so engine patches are applied in the "
        "maintenance window."
    ),
    api=ApiCall(
        service="rds",
        operation="ModifyDBInstance",
        parameters=("DBInstanceIdentifier", "AutoMinorVersionUpgrade"),
    ),
    # --apply-immediately is included, and it does NOT mean "patch now". It applies
    # the *flag* immediately rather than at the next maintenance window; without it
    # the setting itself sits pending. No engine upgrade is triggered by this call.
    cli_template=(
        "aws rds modify-db-instance "
        "--db-instance-identifier {resource_id} "
        "--auto-minor-version-upgrade "
        "--apply-immediately "
        "--region {region}"
    ),
    hcl=HclTarget(
        resource_type="aws_db_instance",
        attributes=(
            ("identifier", '"{resource_id}"'),
            ("auto_minor_version_upgrade", "true"),
        ),
        import_id_template="{resource_id}",
        # Same stub, same reason as the shipped deletion-protection recipe: only
        # `instance_class` is genuinely required, and a wrong value resizes rather
        # than destroys. See that recipe's comment for why the other three arguments
        # the docs call required are omitted.
        unresolvable_required_attributes=(
            ("instance_class", '"db.t3.micro"', "TODO: set to the instance's real class"),
        ),
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint=(
        "aws rds modify-db-instance --db-instance-identifier <id> "
        "--no-auto-minor-version-upgrade --apply-immediately"
    ),
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    caveats=(
        "This applies no upgrade now. It permits AWS to apply minor engine patches "
        "during the instance's maintenance window, which involves a restart and "
        "therefore a brief outage -- on a Single-AZ instance that is downtime, and on "
        "Multi-AZ it is a failover.",
        "Set a maintenance window you can tolerate before enabling this. An instance "
        "with no explicit window gets an AWS-assigned one, which may not be off-peak "
        "for you.",
        "Minor versions can deprecate behaviour. Read the engine's release notes if "
        "the application depends on version-specific behaviour.",
    ),
    docs_url="https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html",
)

# ---------------------------------------------------------------------------
# Public snapshot
#
# The one recipe in this module that withdraws access which real callers may be
# using, and the only one here with a critical caveat.
#
# It is `safest` by the derivation -- free, fully reversible, no data-path impact --
# and that reads wrong beside "stops other AWS accounts restoring this snapshot",
# which is exactly the gap `critical_caveats` exists to cover. Same argument as the
# S3 Block Public Access recipe: the tier cannot express "reversible, free, and may
# still cut off a legitimate consumer", and forcing a higher tier by declaring
# data_path_impact=True would return DISRUPTIVE, which v1 does not ship.
#
# `--values-to-remove all` is the whole fix. `all` is the special group meaning
# "every AWS account", so removing it leaves any explicitly-shared account ids in
# place -- which is why this is a public-access fix and not a sharing revocation.
# Verified against the model: ModifyDBSnapshotAttribute requires
# DBSnapshotIdentifier and AttributeName, and `restore` is the attribute that
# carries the account list.
# ---------------------------------------------------------------------------
_PUBLIC_SNAPSHOT = Recipe(
    policy_id="b03ad608-ad17-4165-95bd-3611db4f2185",
    policy_title="Public RDS Snapshot",
    summary="Remove public restore access so the snapshot cannot be copied by any AWS account.",
    api=ApiCall(
        service="rds",
        operation="ModifyDBSnapshotAttribute",
        parameters=("DBSnapshotIdentifier", "AttributeName", "ValuesToRemove"),
    ),
    cli_template=(
        "aws rds modify-db-snapshot-attribute "
        "--db-snapshot-identifier {resource_id} "
        "--attribute-name restore "
        "--values-to-remove all "
        "--region {region}"
    ),
    # No HCL half. The provider models snapshot sharing through
    # `aws_db_snapshot`'s `shared_accounts`, and expressing "remove the `all` group
    # while preserving whichever explicit account ids exist" would require the
    # generator to know the current list -- it substitutes whole finding fields and
    # cannot read live state, so any block it emitted would assert a complete
    # account list it had guessed. A CLI-only recipe removes exactly one entry and
    # leaves the rest untouched; `hcl=None` is the same choice the Azure
    # trusted-services recipe makes, for the same reason.
    hcl=None,
    effort=Effort.LOW,
    reversible=True,
    reverse_hint=(
        "aws rds modify-db-snapshot-attribute --db-snapshot-identifier <id> "
        "--attribute-name restore --values-to-add all"
    ),
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    critical_caveats=(
        "CONFIRM NOTHING LEGITIMATE RESTORES THIS SNAPSHOT FROM ANOTHER ACCOUNT "
        "BEFORE APPLYING. A cross-account restore pipeline, a partner's recovery "
        "process or a disaster-recovery account that relies on public visibility "
        "stops working immediately. This tool cannot tell intentional publication "
        "from accidental.",
    ),
    caveats=(
        "Only the `all` group is removed. Snapshots shared with specific account ids "
        "keep that sharing -- this closes public access, not delegated access. Use "
        "`describe-db-snapshot-attributes` to see the remaining list.",
        "A snapshot that was already copied while public stays copied. Revoking "
        "access does not reach copies that already exist in other accounts, so treat "
        "a previously-public snapshot of sensitive data as disclosed.",
        "An unencrypted public snapshot is the higher-severity case: it can be "
        "restored by anyone with no key required. Encryption of the source database "
        "is a separate policy and is not remediated by this.",
    ),
    docs_url=(
        "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/"
        "API_ModifyDBSnapshotAttribute.html"
    ),
)

# ---------------------------------------------------------------------------
# Cluster automatic minor version upgrade
#
# **CLI-only, and this is the recipe whose HCL half was written, measured, and then
# deleted.** ModifyDBCluster sets this on the cluster, but `aws_rds_cluster` declares
# no `auto_minor_version_upgrade` argument at all -- schema-confirmed absent, because
# Aurora applies an engine patch per instance, so the provider models the attribute on
# `aws_rds_cluster_instance` instead.
#
# Retargeting the HCL half at `aws_rds_cluster_instance` is what does not survive
# measurement, for a reason that is worse than any stub. That resource imports by
# *instance* identifier, while the finding carries a *cluster* identifier, and no
# template turns one into the other -- a cluster has many instances. The import id is
# the one thing `HclTarget` cannot mark unresolvable: `import_id_template` takes no
# TODO, so the generated `import` block would carry a cluster id that is
# well-formed, plausible, and names nothing. The INCOMPLETE banner would not cover it,
# because the banner lists *attributes*.
#
# The first draft did retarget it and stubbed `identifier`, and the schema axis
# rejected that too: `identifier` is optional+computed, so stubbing it proposes
# *renaming* the instance -- a replacement, which destroys it -- while `engine` is
# genuinely required and was missing. Both are recorded because they are the same
# mistake in two directions: reading the AWS docs' argument list instead of the
# generated schema.
#
# So this ships `hcl=None`, like `_PUBLIC_SNAPSHOT` above and the Azure
# trusted-services recipe. `az`-side reasoning is in the module docstring; the
# consequence for a Terraform-managed cluster is in the caveats, since a user whose
# cluster is in IaC still needs to know which resource to edit by hand.
# ---------------------------------------------------------------------------
_CLUSTER_MINOR_VERSION_UPGRADE = Recipe(
    policy_id="12ecb360-5e79-49ee-b771-7358670a185d",
    policy_title="RDS Cluster automatic minor version upgrade is not enabled",
    summary=(
        "Enable automatic minor version upgrades on the cluster so engine patches are "
        "applied in the maintenance window."
    ),
    api=ApiCall(
        service="rds",
        operation="ModifyDBCluster",
        parameters=("DBClusterIdentifier", "AutoMinorVersionUpgrade"),
    ),
    cli_template=(
        "aws rds modify-db-cluster "
        "--db-cluster-identifier {resource_id} "
        "--auto-minor-version-upgrade "
        "--region {region}"
    ),
    # See the block comment above: aws_rds_cluster has no such argument, and
    # aws_rds_cluster_instance cannot be imported from a cluster id.
    hcl=None,
    effort=Effort.LOW,
    reversible=True,
    reverse_hint=(
        "aws rds modify-db-cluster --db-cluster-identifier <id> --no-auto-minor-version-upgrade"
    ),
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    caveats=(
        "This applies no upgrade now. It permits AWS to apply minor engine patches "
        "during the cluster's maintenance window, which restarts instances and "
        "causes a failover on a multi-instance cluster.",
        "No HCL is generated. aws_rds_cluster has no auto_minor_version_upgrade "
        "argument -- Aurora patches per instance, so the attribute lives on "
        "aws_rds_cluster_instance, which imports by instance identifier while this "
        "finding carries a cluster identifier. If the cluster is managed in Terraform, "
        "set auto_minor_version_upgrade = true on each aws_rds_cluster_instance in it.",
        "Set a maintenance window you can tolerate before enabling this.",
    ),
    docs_url="https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBCluster.html",
)

#: Every RDS recipe. Aggregated by :mod:`remgen.providers.aws.recipes`.
RECIPES: tuple[Recipe, ...] = (
    _DELETION_PROTECTION,
    _CLUSTER_DELETION_PROTECTION,
    _MINOR_VERSION_UPGRADE,
    _PUBLIC_SNAPSHOT,
    _CLUSTER_MINOR_VERSION_UPGRADE,
)

__all__ = ["RECIPES"]
