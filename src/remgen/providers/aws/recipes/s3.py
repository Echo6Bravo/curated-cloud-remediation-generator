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

# ---------------------------------------------------------------------------
# Block Public Access
#
# All four flags are set, because the policy asks whether Block Public Access is
# enabled and a bucket with two of four set is still reachable by the route the
# other two close. Setting a subset would emit a command that runs cleanly and
# leaves the finding open, which is worse than emitting nothing.
#
# The four are not equivalent, and AWS's own model documentation splits them:
#
#   * BlockPublicAcls and BlockPublicPolicy are *preventive*. They reject future
#     PUTs that would grant public access. Both state that enabling them "doesn't
#     affect existing policies or ACLs". Applying them to a bucket that is public
#     today changes nothing about who can read it today.
#   * IgnorePublicAcls and RestrictPublicBuckets are *retroactive*. They ignore
#     existing public ACLs and restrict existing public bucket policies. On a
#     bucket that intentionally serves public content -- a static website, a
#     published dataset -- these stop anonymous reads at once.
#
# So this recipe withdraws access that real callers may be using, and the caveats
# below are the loudest in the AWS set for that reason.
#
# **Why this is SAFEST rather than CAUTION**, since that reads wrong at first:
# `safety_tier` is derived, not declared, and the only fields that produce CAUTION
# are `reversible=False`, `cost_impact=USAGE_SCALED` and `blocks_iac_destroy=True`.
# None is true here -- `delete-public-access-block` fully reverses this, it costs
# nothing, and it does not block `destroy`. Setting `data_path_impact=True` to force
# a higher tier would return DISRUPTIVE, which v1 does not ship, and would be
# asserting something this project has consistently read the other way: it rejects
# and ignores requests by authorization rather than dropping, rerouting or
# transforming requests inside an established path. `_HTTPS_ONLY`, `_MIN_TLS` and
# `_SFTP_DISABLED` in the Azure storage module all withdraw access from real callers
# and all hold `data_path_impact=False` on that same reading.
#
# The honest gap this leaves is that the tier cannot express "reversible, free, and
# may still cut off your public website". Closing it needs a fifth tier input --
# something like `withdraws_existing_access` -- which would also move roughly five
# Azure recipes from `safest` to `caution` and rewrite the committed samples. That
# is a safety-model change, not a recipe, so it is not smuggled in here.
#
# Note also that this tool cannot know whether a bucket's public access is
# *intentional*. A Tenable Cloud Security exception does not survive a JSON export,
# and `Finding` carries no field for it -- see the Known limitations section of
# README.md. That is why the first caveat asks the reader to confirm intent rather
# than describing the change alone.
# ---------------------------------------------------------------------------
_BLOCK_PUBLIC_ACCESS = Recipe(
    policy_id="80b8e9b6-c285-4939-b115-452dfd65bbcc",
    policy_title="S3 Bucket block public access is not enabled",
    summary="Enable all four Block Public Access settings so the bucket cannot be made public.",
    api=ApiCall(
        service="s3",
        operation="PutPublicAccessBlock",
        # Both are `required` in the PutPublicAccessBlockRequest shape. The four
        # booleans live inside PublicAccessBlockConfiguration and are each optional
        # there, so naming the container is what the drift check can verify.
        parameters=("Bucket", "PublicAccessBlockConfiguration"),
    ),
    cli_template=(
        "aws s3api put-public-access-block "
        "--bucket {resource_id} "
        "--public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true "
        "--region {region}"
    ),
    hcl=HclTarget(
        resource_type="aws_s3_bucket_public_access_block",
        # Flat attributes, not a block: verified against the generated provider
        # schema, where all four are plain optional bools and the resource declares
        # no nested block types at all. Unlike `aws_s3_bucket_versioning` above,
        # there is no configuration block to satisfy.
        #
        # None of the four is `Computed`, which is what makes generating all four
        # safe here. Where a provider marks an attribute Computed and omits it from
        # generated configuration, apply reads that as "set to none" -- the reason
        # the Azure trusted-services recipe emits no HCL at all.
        attributes=(
            ("bucket", '"{resource_id}"'),
            ("block_public_acls", "true"),
            ("block_public_policy", "true"),
            ("ignore_public_acls", "true"),
            ("restrict_public_buckets", "true"),
        ),
        # Verified: `terraform import aws_s3_bucket_public_access_block.example bucket-name`
        import_id_template="{resource_id}",
    ),
    effort=Effort.LOW,
    reversible=True,
    reverse_hint="aws s3api delete-public-access-block --bucket <bucket> --region <region>",
    data_path_impact=False,
    cost_impact=CostImpact.NONE,
    blocks_iac_destroy=False,
    # Inline rather than in `caveats`, because this is the one consequence the four
    # tier fields cannot express: the change is reversible, free and in-place, so it
    # derives to SAFEST, and the banner above the command says so. Relocating this
    # sentence to the run README would leave a reader looking at `put-public-access-
    # block` under a SAFEST heading with nothing beside it about the website it turns
    # off. It is the only critical caveat in the set; see `Recipe.critical_caveats`
    # for why that bar is deliberately high.
    critical_caveats=(
        "CONFIRM THIS BUCKET IS NOT MEANT TO BE PUBLIC BEFORE APPLYING. If it serves "
        "a static website, a published dataset or any anonymously read content, that "
        "access stops immediately. This tool cannot tell intentional public access "
        "from accidental: a Tenable Cloud Security exception does not travel in a "
        "findings export, so scope your export rather than relying on the tool.",
    ),
    caveats=(
        "IgnorePublicAcls and RestrictPublicBuckets act on access that already "
        "exists -- existing public ACLs stop being honoured and existing public "
        "bucket policies are restricted to this account's principals. The other two "
        "flags only reject future attempts to grant public access.",
        "Account-level Block Public Access combines with this bucket-level setting, "
        "and S3 applies the more restrictive of the two. A bucket can therefore "
        "already be blocked in practice while still failing this policy, and this "
        "command is still the fix for the bucket-level gap.",
        "Cross-account access granted by bucket policy to specific external "
        "principals is also restricted by RestrictPublicBuckets, including "
        "non-public delegation. Check for partner or vendor access paths that are "
        "scoped by account rather than by a public wildcard.",
    ),
    docs_url="https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html",
)

#: Every S3 recipe. Aggregated by :mod:`remgen.providers.aws.recipes`.
RECIPES: tuple[Recipe, ...] = (_VERSIONING, _BLOCK_PUBLIC_ACCESS)

__all__ = ["RECIPES"]
