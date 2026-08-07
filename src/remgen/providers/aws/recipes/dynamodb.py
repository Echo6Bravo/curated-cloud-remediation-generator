"""DynamoDB recipes.

One module per AWS service. The module name is the botocore service id, which is
asserted rather than assumed -- see
``test_each_service_module_only_holds_recipes_for_that_service``.
"""

from __future__ import annotations

from remgen.core.model import ApiCall, CostImpact, Effort, HclTarget, Recipe

# ---------------------------------------------------------------------------
# Table deletion protection
#
# Safety: free, reversible, metadata-only. Does not touch the data path.
# ---------------------------------------------------------------------------
_DELETION_PROTECTION = Recipe(
    policy_id="468d7976-445f-44c2-b9fb-45fb1005f373",
    policy_title="DynamoDB Table delete protection is not enabled",
    summary="Enable deletion protection so the table cannot be deleted by an API call alone.",
    api=ApiCall(
        service="dynamodb",
        operation="UpdateTable",
        parameters=("TableName", "DeletionProtectionEnabled"),
    ),
    cli_template=(
        "aws dynamodb update-table "
        "--table-name {resource_id} "
        "--deletion-protection-enabled "
        "--region {region}"
    ),
    hcl=HclTarget(
        resource_type="aws_dynamodb_table",
        attributes=(
            ("name", '"{resource_id}"'),
            ("deletion_protection_enabled", "true"),
        ),
        # Verified: `terraform import aws_dynamodb_table.basic-dynamodb-table GameScores`
        import_id_template="{resource_id}",
        # No unresolvable requirements. `hash_key` and the `attribute` block read as
        # required in the provider *docs*, and were declared here on that basis, but
        # the machine-readable schema marks both optional+computed and `tofu validate`
        # accepts this block without them (see tests/test_hcl_schema.py). Stubbing
        # them was worse than redundant: this block is always paired with `import`, so
        # omitting an optional+computed argument keeps the live value, while
        # `hash_key = "TODO"` proposes changing the table's key -- which forces
        # replacement, and a DynamoDB table cannot be replaced without losing its
        # data. Declaring nothing here is what keeps that plan from being generated.
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint=("aws dynamodb update-table --table-name <name> --no-deletion-protection-enabled"),
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=True,
    caveats=(
        "The CLI targets the table by name. If the finding supplies an ARN, extract the "
        "table name before running.",
    ),
    docs_url="https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html",
)

#: Every DynamoDB recipe. Aggregated by :mod:`remgen.providers.aws.recipes`.
RECIPES: tuple[Recipe, ...] = (_DELETION_PROTECTION,)

__all__ = ["RECIPES"]
