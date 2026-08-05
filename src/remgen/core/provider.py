"""What a cloud provider must supply for the shared pipeline to run.

The pipeline in :mod:`remgen.core.cli` is the same for every cloud: load findings
as untrusted input, dedupe, pair with recipes, gate by safety tier, split by
scope, render, write, then reconcile the counts. None of that is AWS-specific,
and reimplementing it per cloud is how the counts stop reconciling.

What *is* cloud-specific is narrower than it first appears, and this module is
the list of it. Each field below exists because a real difference was identified,
not because a difference seemed likely:

* **Naming.** The command, the credential-scope noun ("account" vs
  "subscription"), and the display name appear in generated artifacts and in
  error messages an operator reads at 2am. They are data, not string formatting
  applied to an id.
* **Recipes and drift.** Each cloud's recipe set and each cloud's way of
  verifying it against the live API are unrelated implementations. AWS reads
  botocore ``service-2.json``; nothing about that generalizes.
* **Shell rendering.** ``aws``, ``az``, ``gcloud`` and ``oci`` differ in flag
  syntax, in how identity is preflighted, and in which calls are idempotent. One
  generator per cloud, no shared skeleton -- see the note below.
* **Terraform scoping.** The AWS provider is scoped to one account *and* one
  region, so HCL must not span regions. That is a property of the provider, not
  of the cloud: ``azurerm`` carries ``location`` per resource instead, so the
  same rule would fragment Azure output for no reason.

Deliberately **not** abstracted yet, because there is one instance of each and a
generalization derived from one sample is a guess:

* There is no shared shell-script skeleton. :attr:`Provider.render_shell` is a
  whole generator, not a template filled from parameters. The second cloud is
  what should force the common parts out, against two real cases.
* There is no plugin discovery. ``awsremgen`` imports its provider directly. A
  registry with one entry is indirection without a decision behind it.
* The scope hierarchy is two levels deep (credential scope, then region) because
  that is what AWS has. Azure's subscription -> resource-group -> region and
  GCP's org -> folder -> project are deeper and one of them is path-shaped, so
  :class:`~remgen.core.layout.OutputUnit` will need a more general scope
  representation than two named fields. That change belongs in the commit that
  adds the second provider and can be checked against it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from remgen.core.drift import DriftResult
from remgen.core.model import Recipe


@dataclass(frozen=True)
class Provider:
    """Everything the shared pipeline needs from one cloud.

    Attributes:
        cloud: Short lowercase identifier, e.g. ``"aws"``. Used as the top output
            directory segment and recorded in the manifest, so a run over several
            clouds keeps its artifacts separable. Must be filesystem-safe.
        display_name: How the cloud is named in prose, e.g. ``"AWS"``.
        command: The console command that drives this provider, e.g.
            ``"awsremgen"``. Appears in ``--help`` and in generated artifacts, so
            a copied example is runnable as written.
        credential_scope_noun: What one credential set addresses -- ``"account"``
            for AWS, ``"subscription"`` for Azure. Appears in filenames, in the
            shell script's guard message, and in the README's explanation of why
            output is split. Getting this word wrong makes correct behavior read
            as a bug.
        region_noun: What the regional scope is called, e.g. ``"region"`` for AWS,
            ``"location"`` for Azure.
        hcl_provider_is_region_scoped: True when one Terraform/OpenTofu provider
            configuration covers exactly one region, so a ``.tf`` file must not
            span regions. True for ``hashicorp/aws``. False for ``azurerm``,
            which carries ``location`` per resource -- splitting there would
            fragment output without making it more correct.
        all_recipes: Returns every recipe, ordered for stable output.
        get_recipe: Returns the recipe for a policy id, or ``None``.
        verify_recipes: Checks recipes against this cloud's live API definitions.
        describe_model_source: Where those definitions were read from, for the
            ``verify`` output. Returns ``"unavailable"`` when there is no source.
        render_shell: Renders the CLI-script artifact for one output unit.
        hcl_scope_block: Renders the scope statement and commented provider block
            that heads a ``.tf`` file, or ``""`` for none.
        shell_extension: Filename extension for the shell artifact.
        catalog_export_hint: One line telling the user where to get the policy
            catalog, shown when ``--catalog`` is missing.
        models_unavailable_hint: How to obtain this cloud's API definitions, shown
            when verification could not run. Actionable per cloud -- installing the
            AWS CLI does nothing for Azure -- so the advice is data rather than a
            sentence in the shared code path.
        cli_requirement: What the shell artifacts need installed, e.g. ``"AWS CLI
            v2 (v1 is not tested)"``. Named in the run README because "install that
            cloud's CLI" is not something a reader can act on -- the version matters,
            and which versions are tested is a claim only the provider can make.
    """

    cloud: str
    display_name: str
    command: str
    credential_scope_noun: str
    region_noun: str
    hcl_provider_is_region_scoped: bool
    all_recipes: Callable[[], tuple[Recipe, ...]]
    get_recipe: Callable[[str], Recipe | None]
    verify_recipes: Callable[[tuple[Recipe, ...]], tuple[DriftResult, ...]]
    describe_model_source: Callable[[], str]
    render_shell: Callable[..., str]
    hcl_scope_block: Callable[..., str]
    shell_extension: str = ".sh"
    catalog_export_hint: str = ""
    models_unavailable_hint: str = ""
    cli_requirement: str = ""

    def __post_init__(self) -> None:
        # The cloud id becomes a path segment. A value containing a separator or
        # a traversal component would write outside the output directory, so it
        # is checked here rather than at every join.
        if not self.cloud or not self.cloud.replace("-", "").isalnum():
            raise ValueError(
                f"cloud must be a non-empty alphanumeric identifier, got {self.cloud!r}"
            )
        if not self.command:
            raise ValueError("Provider requires a command name")


__all__ = ["Provider"]
