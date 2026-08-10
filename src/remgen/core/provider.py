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
from remgen.core.model import Finding, Recipe


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
        verify_cli_surface: Checks that each recipe's rendered console command still
            names a real subcommand with real flags, against that CLI's own record of
            them. A third axis, distinct from ``verify_recipes``: the API model and
            the CLI's flag spelling for it change independently, and the artifact runs
            the latter. Returns ``(ok, checked, label, detail)`` per recipe -- a tuple
            rather than a shared result type because each cloud's CLI has a different
            notion of what a flag *is* (``az`` groups differ from ``aws``
            subcommands), and a common dataclass derived from one CLI would be a guess.
            ``None`` when the cloud has no such check yet, which is reported as not
            run.
        describe_cli_surface_source: Where that record was read from, or
            ``"unavailable"``.
        scope_conflict: Returns why a finding's ``resource_id`` contradicts its
            ``account_id``, or ``None`` when it does not. ``None`` for the whole hook
            means the cloud has no such conflict to detect, which is a fact about the
            cloud rather than a gap: AWS identifiers do not contain an account, so a
            bucket name cannot disagree with ``account_id``, and there is nothing to
            check. Azure's do -- an ARM id names its subscription, and ``az`` resolves
            ``--ids`` in preference to ``--subscription`` -- so a mismatch sends the
            mutation somewhere the script's own guard has just declared out of scope.
            Called during ``generate``, before anything is rendered, and a non-``None``
            return rejects that one finding rather than failing the run: the other
            findings are still correct, and a rejection is reported and counted where a
            dropped one would look compliant.
        tf_provider_source: The Terraform/OpenTofu provider's source address without
            a registry host, e.g. ``"hashicorp/aws"``. Used to find this cloud's
            entry in a ``tofu providers schema -json`` document, which keys providers
            by full registry address -- and the host differs between OpenTofu and
            Terraform for the same provider, so the match is on this suffix. Empty
            means the cloud has no HCL generation, and the schema check is skipped
            rather than reported as failing.
        tf_provider_verified_major: The highest provider *major* this cloud's recipes
            have actually been verified against, which becomes the upper bound of the
            version constraint in generated HCL. ``0`` emits no constraint.

            Per cloud rather than per recipe, because it records what was verified and
            the two clouds are verified against different majors: at the time of
            writing ``hashicorp/aws`` is 6.x while ``hashicorp/azurerm`` is 5.x, so one
            shared default would overstate the ceiling for whichever cloud trails.

            A floor with no ceiling is the shape that fails silently. Both providers
            ship a major roughly annually and both relocate arguments when they do --
            ``aws`` v3 to v4 moved 13 inline ``aws_s3_bucket`` parameters out to
            standalone resources, two of which these recipes write. Unbounded, a
            generated file resolves to
            whatever is newest on the day the *user* runs ``init``, so a break lands in
            their terminal against a major nobody verified, and reads as a defect in
            the file rather than as an untested combination.

            A major only, so a routine minor release inside a verified major needs no
            edit. Raising it is a deliberate claim that the recipes were re-verified,
            which is what ``verify``'s HCL axis and the drift canary measure.
        tf_provider_major_change_example: One real, verified argument relocation from
            *this* provider's own release history, quoted in the generated version
            constraint as the evidence for why the ceiling exists. Something like
            ``"azurerm 4 to 5 moved the azurerm_storage_account queue_properties block
            to a separate resource"``.

            Per cloud because the example is a factual claim about a specific provider,
            and the generator used to hardcode AWS's: an Azure ``.tf`` file explained
            its own ceiling by citing ``aws_s3_bucket``, a resource type that does not
            exist in the cloud the file targets. A reader who checks it learns the
            tool's stated reasons are decorative, which is worse than the ceiling being
            unexplained.

            **Empty is a supported state and emits no example**, rather than falling
            back to another cloud's. The surrounding sentence ("a provider major
            relocates arguments between resources") is true without one, so the cost of
            omitting it is a less concrete explanation -- against the cost of asserting
            something unverified about a provider, which is the failure this field
            exists to prevent. A new cloud therefore starts correct-but-general rather
            than inheriting a false specific.

            Whoever sets it is making a claim a reader can check, so it must come from
            the provider's own upgrade guide and name the major *in which the change
            landed*. The AWS value was wrong on exactly that point for as long as it was
            hardcoded: it said v5 to v6 moved the ``aws_s3_bucket`` sub-arguments, and
            that was v3 to v4 -- the v6 guide's only ``aws_s3_bucket`` entry is a
            ``region`` rename. Right resource, right kind of change, wrong major, in
            every generated file.
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
    tf_provider_source: str = ""
    tf_provider_verified_major: int = 0
    tf_provider_major_change_example: str = ""
    verify_cli_surface: (
        Callable[[tuple[Recipe, ...]], tuple[tuple[bool, bool, str, str], ...]] | None
    ) = None
    describe_cli_surface_source: Callable[[], str] | None = None
    scope_conflict: Callable[[Finding], str | None] | None = None

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
        # A verified major without a source address cannot be rendered -- the
        # constraint names the provider -- and a cloud with HCL generation but no
        # verified major emits an unbounded floor, which is the failure mode this
        # field exists to close. Both are caught here rather than at render time,
        # where the first is a KeyError on someone's run and the second is silent.
        if self.tf_provider_verified_major and not self.tf_provider_source:
            raise ValueError(
                f"{self.cloud}: tf_provider_verified_major="
                f"{self.tf_provider_verified_major} needs tf_provider_source to name "
                f"the provider it bounds"
            )
        if self.tf_provider_source and not self.tf_provider_verified_major:
            raise ValueError(
                f"{self.cloud}: tf_provider_source={self.tf_provider_source!r} generates "
                f"HCL, so it must declare tf_provider_verified_major; without it the "
                f"generated constraint has no upper bound and resolves to a major "
                f"nobody verified"
            )
        # The example is a claim about *this* provider, so it has to name it. Checked
        # mechanically because the defect it replaces was precisely a correct sentence
        # about the wrong provider -- text that reads fine and is false for the file it
        # is in, which no reviewer caught for as long as it was hardcoded. Matching the
        # local name (the last path segment) rather than the cloud id, since `azure`
        # generates `azurerm` and the example should speak the provider's language.
        if self.tf_provider_major_change_example:
            if not self.tf_provider_source:
                raise ValueError(
                    f"{self.cloud}: tf_provider_major_change_example describes a provider "
                    f"release, but tf_provider_source is empty, so this cloud emits no "
                    f"constraint for the example to appear in"
                )
            local_name = self.tf_provider_source.rsplit("/", 1)[-1]
            if local_name not in self.tf_provider_major_change_example:
                raise ValueError(
                    f"{self.cloud}: tf_provider_major_change_example does not mention "
                    f"{local_name!r}, so it is describing a different provider than the "
                    f"one it would be quoted in: "
                    f"{self.tf_provider_major_change_example!r}"
                )


__all__ = ["Provider"]
