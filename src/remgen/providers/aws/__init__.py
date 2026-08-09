"""The AWS provider, and its description to the shared pipeline.

Assembled here rather than in the CLI so that everything AWS-specific is reachable
from one place: the recipe set, drift verification against botocore service models,
the ``aws`` CLI generator, and the ``provider "aws"`` scope statement.

Two values in the descriptor are correctness claims rather than labels, and both
are worth reading twice:

* ``credential_scope_noun="account"`` -- one AWS credential set addresses one
  account, which is why output is split per account and why each script refuses to
  run against a different one.
* ``hcl_provider_is_region_scoped=True`` -- a ``provider "aws"`` block carries a
  single ``region``, so a ``.tf`` file must not span regions. Setting this False
  would emit HCL whose import blocks cannot all resolve, and the failure mode is a
  success against the wrong resource rather than an error.
"""

from __future__ import annotations

from remgen.core.model import Recipe
from remgen.core.provider import Provider
from remgen.providers.aws.cli_surface import index_source_description, verify_all_cli
from remgen.providers.aws.drift import model_source_description, verify_all
from remgen.providers.aws.hcl import scope_block
from remgen.providers.aws.recipes import all_recipes, get
from remgen.providers.aws.shell import render_cli_script


def _verify_cli_surface(recipes: tuple[Recipe, ...]) -> tuple[tuple[bool, bool, str, str], ...]:
    """Adapt :func:`verify_all_cli` to the cloud-neutral tuple the pipeline reads.

    The adaptation lives here rather than in ``cli_surface`` so that module stays a
    straightforward AWS checker with its own richer result type, usable directly in
    tests and in the drift canary, while the shared CLI sees only the four facts it
    prints.
    """
    return tuple((r.ok, r.checked, r.command, r.detail) for r in verify_all_cli(recipes))


AWS = Provider(
    cloud="aws",
    display_name="AWS",
    command="awsremgen",
    credential_scope_noun="account",
    region_noun="region",
    hcl_provider_is_region_scoped=True,
    all_recipes=all_recipes,
    get_recipe=get,
    verify_recipes=verify_all,
    describe_model_source=model_source_description,
    render_shell=render_cli_script,
    hcl_scope_block=scope_block,
    shell_extension=".sh",
    catalog_export_hint=(
        "Export the AWS policy catalog from Tenable Cloud Security as JSON "
        "(an array of {id, title, category} objects)."
    ),
    models_unavailable_hint=(
        "Install AWS CLI v2, or set REMGEN_BOTOCORE_DATA_DIR to a botocore data dir."
    ),
    cli_requirement="AWS CLI v2 (v1 is not tested)",
    # Matched as a suffix of the schema document's provider key, which is
    # registry.opentofu.org/hashicorp/aws under OpenTofu and
    # registry.terraform.io/hashicorp/aws under Terraform.
    tf_provider_source="hashicorp/aws",
    # 6, because 6.x is what the recipes and the committed sample are validated
    # against -- `tofu init` in CI resolves 6.58.0 at the time of writing. Not a
    # guess at what is current: raising this asserts a re-verification happened, so
    # it is bumped by the commit that does one and not before. AWS and Azure differ
    # here (azurerm is still 5.x), which is why the field is per cloud.
    tf_provider_verified_major=6,
    verify_cli_surface=_verify_cli_surface,
    describe_cli_surface_source=index_source_description,
)

__all__ = ["AWS"]
