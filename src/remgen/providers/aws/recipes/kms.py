"""KMS recipes.

One module per AWS service. The module name is the botocore service id, which is
asserted rather than assumed -- see
``test_each_service_module_only_holds_recipes_for_that_service``.
"""

from __future__ import annotations

from remgen.core.model import ApiCall, CostImpact, Effort, HclTarget, Recipe

# ---------------------------------------------------------------------------
# Automatic key rotation
#
# Safety: no data-path impact and no downtime. Classified CAUTION rather than
# SAFEST for one honest reason: rotation cannot be cleanly undone in the sense
# that matters -- once material has rotated, previously generated material is
# retained and the key has multiple backing keys. Disabling rotation stops
# future rotations but does not restore the prior single-material state.
# ---------------------------------------------------------------------------
_KEY_ROTATION = Recipe(
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

#: Every KMS recipe. Aggregated by :mod:`remgen.providers.aws.recipes`.
RECIPES: tuple[Recipe, ...] = (_KEY_ROTATION,)

__all__ = ["RECIPES"]
