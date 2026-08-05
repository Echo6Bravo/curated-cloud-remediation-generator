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

from remgen.core.provider import Provider
from remgen.providers.aws.drift import model_source_description, verify_all
from remgen.providers.aws.hcl import scope_block
from remgen.providers.aws.recipes import all_recipes, get
from remgen.providers.aws.shell import render_cli_script

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
)

__all__ = ["AWS"]
