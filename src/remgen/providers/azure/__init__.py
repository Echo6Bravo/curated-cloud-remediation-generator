"""The Azure provider, and its description to the shared pipeline.

**Coverage is partial and every piece is implemented.** The descriptor and the
command landed before any recipe existed, so the shared pipeline was exercised by a
second cloud first; the recipes in :mod:`remgen.providers.azure.recipes` came after,
each verified against the real Azure SDK models, the real ``azurerm`` schema and the
real ``az`` CLI surface. Nothing here raises a placeholder any more.

The shell generator is not a translation of the AWS script: an Azure login spans
subscriptions, so every command pins ``--subscription`` and the preflight checks
reachability rather than refusing on an active-subscription mismatch. That promise is
enforced at render time rather than asserted in a comment -- see
:class:`remgen.providers.azure.shell.SubscriptionNotPinnedError`.

One measured caveat on that promise, because it changes what the pinning *mechanism*
is without changing the guarantee. Every shipped recipe addresses its resource with
``--ids``, since :class:`~remgen.core.model.Recipe` requires ``cli_template`` to name
``{resource_id}`` and an ARM id can only be passed that way. ``az`` overwrites every
argument carrying an ``id_part`` from the parsed id, and ``--subscription`` carries
``id_part='subscription'`` -- so it emits "option '--subscription' will be ignored due
to use of '--ids'". The flag stays in every template regardless: the target
subscription remains explicit on the command line because the ARM id contains it, and
``SubscriptionNotPinnedError`` still checks for the flag, which keeps a future recipe
that does *not* use ``--ids`` from inheriting ambient state. Read from ``az``'s own
``azure/cli/core/commands/arm.py``, and recorded because the warning appears on every
line of a generated script and would otherwise look like a defect.

Three values here are correctness claims rather than labels, and each differs from
AWS for a reason that changes output:

* ``credential_scope_noun="subscription"`` -- one Azure credential context
  addresses one subscription, so output splits per subscription and each script
  must refuse to run against a different one. The word appears in filenames and in
  the guard message; AWS's "account" would describe correct behavior wrongly.
* ``region_noun="location"`` -- Azure's own word. ``az`` flags spell it
  ``--location``, so a script explaining itself in terms of "region" sends a reader
  looking for a flag that does not exist.
* ``hcl_provider_is_region_scoped=False`` -- **the one that changes the artifact
  set.** An ``azurerm`` provider block carries no location; every resource carries
  its own. So a ``.tf`` file may span locations, and splitting per location would
  fragment output without making it more correct. Subscription remains a hard
  boundary, because ``azurerm`` is configured with one ``subscription_id``.

Nothing here is shared with AWS by import -- ``test_structure.py`` enforces that in
both directions. What the two clouds have in common lives in ``remgen.core``, where
both clouds' tests cover it.
"""

from __future__ import annotations

from remgen.core.drift import DriftResult
from remgen.core.layout import OutputUnit
from remgen.core.model import Finding, Recipe
from remgen.core.provider import Provider
from remgen.providers.azure.cli_surface import cli_source_description, verify_all_cli
from remgen.providers.azure.drift import model_source_description
from remgen.providers.azure.drift import verify_all as verify_all_drift
from remgen.providers.azure.hcl import scope_block as azure_scope_block
from remgen.providers.azure.recipes import all_recipes as _all_azure_recipes
from remgen.providers.azure.recipes import get as _get_azure_recipe
from remgen.providers.azure.shell import render_cli_script

#: Stated once. Named in the descriptor (so the run README can print it) and passed
#: into the script header (so someone opening one script in isolation sees it). Two
#: independent literals would drift the first time the minimum version changed.
_CLI_REQUIREMENT = "Azure CLI (az) 2.50 or later"


def all_recipes() -> tuple[Recipe, ...]:
    """Return every Azure recipe, ordered by policy title for stable output.

    Delegates to :mod:`remgen.providers.azure.recipes`, which discovers its
    per-service modules rather than listing them. This used to be a module-level
    ``()`` with a comment promising recipes once each had passed all three axes; the
    promise is now kept in that package, where each recipe records the measurement
    beside itself.

    Coverage remains partial by design. Everything without a recipe is reported by
    ``azremgen policies --unsupported``, so a gap is visible rather than silent --
    and while this returned ``()``, ``verify`` printed "nothing to check" rather
    than "all passed" (see :func:`remgen.core.cli._no_recipes_to_verify`, which
    exists because the pre-fix code printed "All 0 recipe(s) match" and exited 0).
    """
    return _all_azure_recipes()


def get(policy_id: str) -> Recipe | None:
    """Return the recipe for ``policy_id``, or ``None`` if unsupported.

    A finding for an Azure policy with no recipe is reported as unsupported and
    counted in the run summary, which is the same path an AWS policy without a
    recipe takes -- so the reconciliation the summary promises does not depend on
    how complete the recipe set is.
    """
    return _get_azure_recipe(policy_id)


def verify_recipes(recipes: tuple[Recipe, ...]) -> tuple[DriftResult, ...]:
    """Verify recipes against Azure's API definitions. Implemented.

    **What this reads, and how that differs from the plan recorded here.** Azure has no
    botocore equivalent: ``az`` ships **zero** JSON API models
    (``find azure/mgmt -name '*.json'`` over ``az`` 2.89.0 returns nothing), so the AWS
    approach -- read the vendor's own shipped service model, offline, no network -- has
    no direct analogue. Four options were considered:

    1. Report the axis as "could not check" (exit ``4``) and rely on the other two.
       Honest, and permanently degrades a check the AWS side treats as primary.
    2. Read the REST declarations in ``az``'s ``aaz`` command trees, which state
       ``url``, HTTP method and ``api-version`` inline and are AST-readable.
    3. Vendor a pinned subset of ``azure-rest-api-specs``. Complete and exact, and a
       vendored copy that goes stale silently -- the failure mode the drift canary
       exists to prevent.
    4. Read the 62 ``azure.mgmt.*`` SDK packages ``az`` already bundles, which are
       code-generated from the same swagger specs ARM is built from.

    This docstring recorded the decision as **(2) with a per-recipe fallback to (1)**.
    That was superseded by **(4)**, and the reason is a measurement rather than a
    preference: of 18 candidate remediation commands, only 5 have an ``aaz`` leaf, and
    ``storage account update`` and ``keyvault update`` -- the first two recipes -- are
    both absent. Because could-not-check is exit-code-neutral, (2) would have shipped an
    axis reporting green while checking nothing for every recipe that existed. (4) covers
    every candidate, is still AST-only with no import and no network, and it caught a
    wrong operation name before the first recipe was written (``sql db tde set`` is
    ``begin_create_or_update``, not ``create_or_update``). The measurement is in
    :mod:`remgen.providers.azure.drift`.

    That is the **second** time a recorded plan lost to a measurement, both times for
    the same reason: ``aaz`` does not contain the commands recipes name. The first was
    the CLI-surface axis, which now asks ``az --help``
    (:mod:`remgen.providers.azure.cli_surface`). The plan is corrected here rather than
    quietly abandoned, because a stale plan left in the code is what the next person
    reads. ``aaz`` is now used by neither axis: the SDK operations carry the URL and
    HTTP method too, so nothing was left behind.

    Delegates rather than implementing, so the checker is usable directly in tests and
    in the drift canary without going through the descriptor.
    """
    return verify_all_drift(recipes)


def _verify_cli_surface(recipes: tuple[Recipe, ...]) -> tuple[tuple[bool, bool, str, str], ...]:
    """Adapt :func:`verify_all_cli` to the cloud-neutral tuple the pipeline reads.

    The adaptation lives here rather than in ``cli_surface`` so that module stays a
    straightforward ``az`` checker with its own richer result type, usable directly in
    tests and in the drift canary, while the shared CLI sees only the four facts it
    prints. Deliberately parallel to the AWS adapter without sharing it: the two
    modules return different result classes on purpose, and a shared adapter would need
    a shared class.
    """
    return tuple((r.ok, r.checked, r.command, r.detail) for r in verify_all_cli(recipes))


def describe_model_source() -> str:
    """Where Azure API definitions were read from.

    Delegates to :func:`remgen.providers.azure.drift.model_source_description`, which
    returns the literal ``"unavailable"`` when there is no source -- the contract the
    shared ``verify`` reads to mean exactly that. Anything else would be printed as if
    it were a path, so a hopeful sentence here would be reported as a location.
    """
    return model_source_description()


def render_shell(
    pairs: list[tuple[Recipe, Finding]],
    *,
    version: str,
    generated_at: str,
    unit: OutputUnit | None = None,
) -> str:
    """Render the ``az`` remediation script for one output unit.

    Implemented. Delegates to :func:`remgen.providers.azure.shell.render_cli_script`,
    passing :attr:`Provider.cli_requirement` so the header's version requirement and
    the descriptor cannot drift apart -- two places stating which ``az`` version is
    needed is how they come to disagree.

    The signature is stated explicitly rather than as ``*args, **kwargs``: this is
    the seam ``core`` calls, and a permissive signature would accept a future
    keyword that this function then silently ignored.
    """
    return render_cli_script(
        pairs,
        version=version,
        generated_at=generated_at,
        unit=unit,
        cli_requirement=_CLI_REQUIREMENT,
    )


def hcl_scope_block(unit: OutputUnit) -> str:
    """Render the ``azurerm`` scope statement. Implemented.

    Delegates to :func:`remgen.providers.azure.hcl.scope_block`. This used to raise, and
    the reason it did is worth keeping: unlike :func:`render_shell`, ``""`` is a
    *legitimate* return for the AWS implementation (a unit spanning regions), so a stub
    returning ``""`` here would have been silently accepted and emitted HCL with no
    subscription statement at all.

    The implementation corrects one thing that stub's docstring asserted. It said the
    Azure block is what stops a plan adopting a same-named resource in whichever
    subscription the credentials can see. It is not, and it cannot be: ``azurerm`` has no
    ``allowed_account_ids`` equivalent. What actually prevents that is a property of
    Azure rather than of this tool -- an ARM resource id contains its own subscription
    id, so the wrong provider scope yields a failed import rather than a wrong one. See
    :mod:`remgen.providers.azure.hcl` for the schema measurement behind that.
    """
    return azure_scope_block(unit)


def scope_conflict(finding: Finding) -> str | None:
    """Return why this finding's ARM id contradicts its subscription, or ``None``.

    **This closes a cross-subscription escape, found by generating a mismatched
    finding rather than by reading the code.** An ARM resource id begins
    ``/subscriptions/<id>/``, and every shipped recipe addresses its resource with
    ``--ids`` because :class:`~remgen.core.model.Recipe` requires ``{resource_id}`` and
    an ARM id can only be passed that way. ``az`` resolves ``--ids`` *in preference to*
    ``--subscription`` -- it overwrites every argument carrying an ``id_part`` from the
    parsed id. So given a finding whose ``account_id`` is subscription A and whose
    ``resource_id`` names subscription B, the generated script:

    * heads itself ``Scope: azure subscription A``,
    * runs a preflight confirming the caller can reach A,
    * and then mutates a resource in **B**, which the guard never mentioned.

    Verified end to end before this function existed: exit code 0, artifacts written,
    nothing warned. The HCL half had the same shape -- ``subscription_id = A`` beside
    an ``import`` block whose id names B.

    There is no equivalent hook on the AWS side and that is not an omission. No AWS
    identifier this tool renders contains an account, so a bucket name cannot disagree
    with ``account_id`` and ``sts get-caller-identity`` is a sufficient guard. The
    asymmetry is in the clouds, not in the coverage -- which is why this is a provider
    seam rather than a shared check that AWS passes vacuously.

    Only the subscription segment is compared. A ``resourceGroups`` mismatch is *not* a
    conflict: a finding carries no resource group, so there is nothing to disagree with,
    and location is deliberately excluded too -- an Azure ``.tf`` legitimately spans
    locations, and ``region`` is a filename and reporting concern rather than a routing
    one. Non-ARM ids (a bare storage-account name) return ``None``: they name no
    subscription, so they cannot contradict one, and rejecting them would refuse input
    ``--ids`` would reject on its own terms with a clearer message.
    """
    resource_id = finding.resource_id
    lowered = resource_id.lower()
    if not lowered.startswith("/subscriptions/"):
        return None
    segments = resource_id.split("/")
    # ["", "subscriptions", "<id>", ...] -- an id with the prefix and nothing after it
    # names no subscription to compare, so it is left to `--ids` to reject.
    if len(segments) < 3 or not segments[2]:
        return None
    embedded = segments[2]
    # Case-insensitive: ARM ids are case-preserving but not case-sensitive in the
    # subscription segment, and rejecting a differently-cased UUID for the *same*
    # subscription would be a false positive that costs a real remediation.
    if embedded.lower() == finding.account_id.lower():
        return None
    return (
        f"resource_id names subscription {embedded}, but the finding's subscription is "
        f"{finding.account_id}. Refusing to generate: every command addresses the "
        f"resource with --ids, which az resolves in preference to --subscription, so "
        f"this would mutate a resource in {embedded} from a script whose scope guard "
        f"confirms only {finding.account_id}."
    )


AZURE = Provider(
    cloud="azure",
    display_name="Azure",
    command="azremgen",
    credential_scope_noun="subscription",
    region_noun="location",
    # False, unlike AWS. An azurerm provider block carries no location; each
    # resource carries its own. Splitting per location would fragment output
    # without making it more correct. Subscription is still a hard boundary.
    hcl_provider_is_region_scoped=False,
    all_recipes=all_recipes,
    get_recipe=get,
    verify_recipes=verify_recipes,
    describe_model_source=describe_model_source,
    render_shell=render_shell,
    hcl_scope_block=hcl_scope_block,
    shell_extension=".sh",
    catalog_export_hint=(
        "Export the Azure policy catalog from Tenable Cloud Security as JSON "
        "(an array of {id, title, category} objects)."
    ),
    # This used to say installing the CLI does not provide API models. That was true of
    # the JSON models AWS ships and false of what `az` actually carries: 62 bundled
    # azure.mgmt.* SDK packages, which is what this axis reads. Printed only when the
    # axis could not run, so it has to name the thing that would fix it.
    models_unavailable_hint=(
        "Azure API definitions come from the azure.mgmt.* SDKs bundled inside the "
        "Azure CLI. Install az 2.50 or later, or set REMGEN_AZURE_SDK_DIR to a "
        "directory of azure.mgmt.* packages."
    ),
    cli_requirement=_CLI_REQUIREMENT,
    # Suffix-matched against the schema document's provider key, which is
    # registry.opentofu.org/hashicorp/azurerm under OpenTofu and
    # registry.terraform.io/hashicorp/azurerm under Terraform.
    tf_provider_source="hashicorp/azurerm",
    # Implemented, and the first Azure axis that can actually check something. It asks
    # `az` itself rather than reading a shipped index, because Azure ships no
    # equivalent of AWS's ac.index -- see remgen.providers.azure.cli_surface for the
    # three candidates and why the other two were rejected on measurement.
    verify_cli_surface=_verify_cli_surface,
    describe_cli_surface_source=cli_source_description,
    # Azure-only, because the conflict it detects is Azure-only: an ARM id names its own
    # subscription and `--ids` outranks `--subscription`. See scope_conflict.
    scope_conflict=scope_conflict,
)

__all__ = ["AZURE", "all_recipes", "get"]
