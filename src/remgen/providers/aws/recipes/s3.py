"""S3 recipes.

One module per AWS service. The module name is the botocore service id, which is
asserted rather than assumed -- see
``test_each_service_module_only_holds_recipes_for_that_service``. Note that the
service id is ``s3`` even though these remediations are run through ``aws s3api``:
the REST operations live in the ``s3`` model, and ``aws s3`` is a separate
higher-level command. ``tests/test_recipe_set.py`` states that exception once, in
``CLI_COMMAND_ALIASES``.
"""

from __future__ import annotations

from remgen.core.model import ApiCall, CostImpact, Effort, HclTarget, Recipe

# ---------------------------------------------------------------------------
# Bucket versioning
#
# Safety: no data-path impact -- reads and writes are unaffected. Classified
# CAUTION for two honest reasons: versioning can never be fully disabled (only
# suspended), and retained non-current versions grow storage cost indefinitely
# unless a lifecycle rule expires them.
# ---------------------------------------------------------------------------
_VERSIONING = Recipe(
    policy_id="284b1210-a31e-48ce-97af-f4d825ef132d",
    policy_title="S3 Bucket versioning is not enabled",
    summary="Enable versioning so overwritten and deleted objects remain recoverable.",
    api=ApiCall(
        service="s3",
        operation="PutBucketVersioning",
        parameters=("Bucket", "VersioningConfiguration"),
    ),
    cli_template=(
        "aws s3api put-bucket-versioning "
        "--bucket {resource_id} "
        "--versioning-configuration Status=Enabled "
        "--region {region}"
    ),
    hcl=HclTarget(
        resource_type="aws_s3_bucket_versioning",
        attributes=(("bucket", '"{resource_id}"'),),
        # versioning_configuration is a required *block*, not an attribute.
        blocks=(("versioning_configuration", (("status", '"Enabled"', ""),)),),
        # Verified: `terraform import aws_s3_bucket_versioning.example bucket-name`
        import_id_template="{resource_id}",
    ),
    effort=Effort.LOW,
    reversible=False,
    reverse_hint="",
    data_path_impact=False,
    cost_impact=CostImpact.USAGE_SCALED,
    blocks_iac_destroy=False,
    caveats=(
        "Versioning can never be fully disabled once enabled -- only suspended "
        "(Status=Suspended). Existing object versions remain.",
        "Storage cost grows because every overwrite retains the previous version. "
        "Pair this with a lifecycle rule expiring non-current versions, or cost will "
        "climb indefinitely on a write-heavy bucket.",
        "A bucket with MFA Delete enabled cannot have its versioning state changed "
        "with ordinary credentials.",
    ),
    docs_url="https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.html",
)

#: Every S3 recipe. Aggregated by :mod:`remgen.providers.aws.recipes`.
RECIPES: tuple[Recipe, ...] = (_VERSIONING,)

__all__ = ["RECIPES"]
