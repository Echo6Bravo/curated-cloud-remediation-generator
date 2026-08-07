"""CloudTrail recipes.

One module per AWS service. The module name is the botocore service id, which is
asserted rather than assumed -- see
``test_each_service_module_only_holds_recipes_for_that_service``.
"""

from __future__ import annotations

from remgen.core.model import ApiCall, CostImpact, Effort, HclTarget, Recipe

# ---------------------------------------------------------------------------
# Log file integrity validation
#
# Safety: free, reversible, and purely additive -- CloudTrail begins writing
# digest files alongside the log files. Nothing reads or blocks on it, so there
# is no data-path or availability risk.
# ---------------------------------------------------------------------------
_LOG_FILE_VALIDATION = Recipe(
    policy_id="8d1140ba-c917-44d7-b2ea-084f9dffe707",
    policy_title="CloudTrail S3 Bucket log file validation is not enabled",
    summary=(
        "Enable log file integrity validation so CloudTrail writes signed digest files, "
        "making log tampering detectable."
    ),
    api=ApiCall(
        service="cloudtrail",
        operation="UpdateTrail",
        parameters=("Name", "EnableLogFileValidation"),
    ),
    cli_template=(
        "aws cloudtrail update-trail "
        "--name {resource_id} "
        "--enable-log-file-validation "
        "--region {region}"
    ),
    hcl=HclTarget(
        resource_type="aws_cloudtrail",
        attributes=(
            ("name", '"{resource_id}"'),
            ("enable_log_file_validation", "true"),
        ),
        # Verified: imports by ARN, NOT by trail name. The provider documents
        #   terraform import aws_cloudtrail.sample \
        #     arn:aws:cloudtrail:us-east-1:123456789012:trail/my-sample-trail
        import_id_template="arn:aws:cloudtrail:{region}:{account_id}:trail/{resource_id}",
        # Verified required in provider docs; a finding carries no bucket name.
        unresolvable_required_attributes=(
            (
                "s3_bucket_name",
                '"TODO"',
                "TODO: set to the trail's existing log bucket",
            ),
        ),
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="aws cloudtrail update-trail --name <name> --no-enable-log-file-validation",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    caveats=(
        "Validation applies only to log files delivered after it is enabled; earlier "
        "files cannot be retroactively validated.",
        "Digest files are small but are stored in the same S3 bucket, so there is a "
        "negligible storage increase.",
        "The HCL import identifier is the trail ARN, not the trail name. This tool "
        "constructs it from the finding's account and region -- verify it matches for "
        "organization trails, whose ARN belongs to the management account.",
    ),
    docs_url="https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html",
)

#: Every CloudTrail recipe. Aggregated by :mod:`remgen.providers.aws.recipes`.
RECIPES: tuple[Recipe, ...] = (_LOG_FILE_VALIDATION,)

__all__ = ["RECIPES"]
