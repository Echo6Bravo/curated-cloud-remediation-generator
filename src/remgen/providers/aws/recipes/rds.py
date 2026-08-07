"""RDS recipes.

One module per AWS service. The module name is the botocore service id, which is
asserted rather than assumed -- see
``test_each_service_module_only_holds_recipes_for_that_service``.
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

#: Every RDS recipe. Aggregated by :mod:`remgen.providers.aws.recipes`.
RECIPES: tuple[Recipe, ...] = (_DELETION_PROTECTION,)

__all__ = ["RECIPES"]
