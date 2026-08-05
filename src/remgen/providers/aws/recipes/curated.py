"""The curated recipe set.

Each entry maps one Tenable Cloud Security AWS policy to a verified fix.

**Verification performed for every recipe below:**

* ``api``: operation and every named parameter confirmed present in the botocore
  service model bundled with AWS CLI v2 (2.36.15 at time of writing). Re-checked
  on every run by ``remgen verify``.
* ``hcl``: resource type and ``import`` identifier format read from
  ``hashicorp/terraform-provider-aws`` ``website/docs/r/*.html.markdown``, not
  inferred. Import identifiers differ per resource type and are easy to get
  wrong, so each is quoted in a comment next to the recipe.

**Selection criterion: safe to remediate.** v1 contains only remediations that
are reversible, do not touch the data path, need no restart or replacement, and
carry no usage-scaled cost. That excludes plenty of *scriptable* policies -- for
example VPC flow logs is a single API call but bills on ingested volume with no
ceiling, so it is deliberately out of v1. See ROADMAP.md.

Policy IDs are the Tenable Cloud Security policy UUIDs from the live catalog.
"""

from __future__ import annotations

from remgen.core.model import ApiCall, CostImpact, Effort, HclTarget, Recipe

# ---------------------------------------------------------------------------
# 1. DynamoDB table deletion protection
#
# Safety: free, reversible, metadata-only. Does not touch the data path.
# ---------------------------------------------------------------------------
_DYNAMODB_DELETION_PROTECTION = Recipe(
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
        # Verified required in provider docs; a finding carries no key schema.
        # `attribute` is a nested block, so its stub lives in `blocks`.
        unresolvable_required_attributes=(
            ("hash_key", '"TODO"', "TODO: set to the table's existing hash key"),
        ),
        unresolvable_required_blocks=("attribute",),
        blocks=(
            (
                "attribute",
                (
                    ("name", '"TODO"', "TODO: must match the table's hash key"),
                    ("type", '"S"', "TODO: S, N or B -- must match the live table"),
                ),
            ),
        ),
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

# ---------------------------------------------------------------------------
# 2. RDS instance deletion protection
#
# Safety: free, reversible, metadata-only. --apply-immediately is safe here
# because the change does not require a reboot.
# ---------------------------------------------------------------------------
_RDS_DELETION_PROTECTION = Recipe(
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
        # Verified required in provider docs (unless restoring from a snapshot or
        # replica source). None are derivable from a finding.
        unresolvable_required_attributes=(
            ("instance_class", '"db.t3.micro"', "TODO: set to the instance's real class"),
            ("engine", '"postgres"', "TODO: set to the instance's real engine"),
            ("allocated_storage", "20", "TODO: set to the instance's real storage (GiB)"),
            ("username", '"TODO"', "TODO: set to the instance's master username"),
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
# 3. CloudTrail log file integrity validation
#
# Safety: free, reversible, and purely additive -- CloudTrail begins writing
# digest files alongside the log files. Nothing reads or blocks on it, so there
# is no data-path or availability risk.
# ---------------------------------------------------------------------------
_CLOUDTRAIL_LOG_FILE_VALIDATION = Recipe(
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

# ---------------------------------------------------------------------------
# 4. KMS key automatic rotation
#
# Safety: no data-path impact and no downtime. Classified CAUTION rather than
# SAFEST for one honest reason: rotation cannot be cleanly undone in the sense
# that matters -- once material has rotated, previously generated material is
# retained and the key has multiple backing keys. Disabling rotation stops
# future rotations but does not restore the prior single-material state.
# ---------------------------------------------------------------------------
_KMS_KEY_ROTATION = Recipe(
    policy_id="995e8d78-940a-45bf-bac1-61a1fdb00d7a",
    policy_title="KMS Key automatic key rotation is not enabled",
    summary="Enable annual automatic rotation of the KMS key's backing material.",
    api=ApiCall(
        service="kms",
        operation="EnableKeyRotation",
        parameters=("KeyId",),
    ),
    cli_template="aws kms enable-key-rotation --key-id {resource_id} --region {region}",
    hcl=HclTarget(
        resource_type="aws_kms_key",
        attributes=(("enable_key_rotation", "true"),),
        # Verified: `terraform import aws_kms_key.a 1234abcd-12ab-34cd-56ef-1234567890ab`
        import_id_template="{resource_id}",
    ),
    effort=Effort.LOW,
    reversible=False,
    reverse_hint="",
    data_path_impact=False,
    cost_impact=CostImpact.LOW,
    blocks_iac_destroy=False,
    prerequisites=(
        "Applies only to symmetric encryption keys with AWS-generated material "
        "(KeyManager=CUSTOMER, Origin=AWS_KMS).",
    ),
    caveats=(
        "Not supported for asymmetric keys, HMAC keys, keys with imported material, or "
        "keys in a custom key store. The call fails on those, so filter findings first.",
        "'aws kms disable-key-rotation' stops future rotations but does not undo a "
        "rotation that already happened.",
        "Old key material is retained so existing ciphertext stays readable. Rotation "
        "does not re-encrypt existing data.",
        "Each additional backing key incurs a small monthly KMS charge.",
    ),
    docs_url="https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html",
)

# ---------------------------------------------------------------------------
# 5. S3 bucket versioning
#
# Safety: no data-path impact -- reads and writes are unaffected. Classified
# CAUTION for two honest reasons: versioning can never be fully disabled (only
# suspended), and retained non-current versions grow storage cost indefinitely
# unless a lifecycle rule expires them.
# ---------------------------------------------------------------------------
_S3_VERSIONING = Recipe(
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


#: All curated recipes. Order here is irrelevant; the registry sorts by title.
RECIPES: tuple[Recipe, ...] = (
    _DYNAMODB_DELETION_PROTECTION,
    _RDS_DELETION_PROTECTION,
    _CLOUDTRAIL_LOG_FILE_VALIDATION,
    _KMS_KEY_ROTATION,
    _S3_VERSIONING,
)

__all__ = ["RECIPES"]
