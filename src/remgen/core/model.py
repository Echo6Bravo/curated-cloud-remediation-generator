"""Core data model.

Everything in this project renders from :class:`Recipe`. A recipe is a *verified*
description of how to fix one Tenable Cloud Security policy violation, expressed
once and rendered into every output format.

Design rules that keep the generators honest:

* A recipe declares the AWS API operation and parameters it relies on, so
  :mod:`remgen.providers.aws.drift` can independently verify those still exist in the AWS
  service model. A recipe that cannot be verified is a bug, not a warning.
* A recipe declares its HCL resource type *and* the identifier shape needed to
  ``import`` an existing resource. Terraform/OpenTofu only manage what is in
  state; emitting a bare ``resource`` block for a live resource created outside
  IaC produces a conflict, not a fix. Import is mandatory, not optional.
* ``needs_replacement`` marks settings AWS cannot toggle in place (e.g. enabling
  encryption at rest on an existing resource). Those are surfaced loudly instead
  of emitting a command that will fail.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

# --------------------------------------------------------------------------
# Identifier validation.
#
# Every value that reaches a generator is treated as untrusted. Findings come
# from an external system, and resource names/ARNs in a real tenant can contain
# characters that are meaningful to a shell or to HCL. We allowlist instead of
# escaping, because an allowlist fails closed.
# --------------------------------------------------------------------------

#: Conservative allowlist for cloud resource identifiers, names and ARNs.
#: Permits alphanumerics and the punctuation cloud providers actually use in
#: identifiers. Deliberately excludes shell metacharacters, quotes, backslashes,
#: newlines, ``$``, backticks and HCL interpolation markers.
#:
#: A leading ``/`` is permitted because an Azure resource ID *is* a path
#: (``/subscriptions/<id>/resourceGroups/...``), and rejecting it would make the
#: primary identifier of an entire cloud unrepresentable. That is safe only in
#: combination with :func:`validate_path_segment`, which is what guards the
#: values that become filenames -- see the note there. Permitting the leading
#: slash here without that guard would not be safe.
_SAFE_IDENTIFIER = re.compile(r"^/?[A-Za-z0-9][A-Za-z0-9._:/=+@ -]{0,1023}$")

#: Values that become a *single* path component of an output filename. Far
#: stricter than :data:`_SAFE_IDENTIFIER`: no ``/``, no ``.`` at all, so neither
#: a separator nor a traversal component can appear.
_SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")

#: Terraform/OpenTofu resource *labels* must be a valid HCL identifier.
_HCL_LABEL_INVALID = re.compile(r"[^A-Za-z0-9_-]")


class UnsafeIdentifierError(ValueError):
    """Raised when a value from an untrusted source is unfit to render.

    Refusing to render is the correct outcome: a rejected finding is a visible
    gap, whereas a silently escaped one can still surprise a downstream tool.
    """


def validate_identifier(value: str, *, field_name: str) -> str:
    """Return ``value`` if it is a safe cloud identifier, else raise.

    This is the check for values that are *rendered into* an artifact -- a
    command argument, an HCL attribute, an import id. It is **not** sufficient
    for a value that becomes part of a filename: see
    :func:`validate_path_segment`.

    Args:
        value: Candidate identifier taken from finding data.
        field_name: Name used in the error message, to aid triage.

    Raises:
        UnsafeIdentifierError: If the value is empty, over-long, or contains
            characters outside the allowlist.
    """
    if not isinstance(value, str) or not value:
        raise UnsafeIdentifierError(f"{field_name}: expected a non-empty string, got {value!r}")
    if not _SAFE_IDENTIFIER.match(value):
        raise UnsafeIdentifierError(
            f"{field_name}: {value!r} contains characters that are not permitted in a "
            f"cloud identifier. Refusing to generate rather than escape."
        )
    return value


def validate_path_segment(value: str, *, field_name: str) -> str:
    """Return ``value`` if it is safe as one component of a filename, else raise.

    Separate from :func:`validate_identifier` because the two answer different
    questions, and conflating them was a real vulnerability rather than a
    theoretical one. Findings come from an external export, and
    :attr:`~remgen.core.layout.OutputUnit.filename` interpolates ``account_id``
    and ``region`` directly. ``validate_identifier`` permits ``/`` (legitimately
    -- S3 keys and Azure resource IDs contain them), so an ``account_id`` of
    ``1/../../../../tmp/x`` passed validation and wrote both artifacts *outside*
    the ``--out`` directory. Verified end to end before this function existed.

    The rule is therefore positional, not per-cloud: a value that becomes a path
    component may contain no separator and no ``.`` whatsoever, so neither
    ``../`` nor a bare ``..`` can be constructed. Every cloud's credential-scope
    id and region already satisfy it -- AWS account ids are digits, Azure
    subscription ids are UUIDs, regions and locations are alphanumeric with
    dashes -- so this rejects malformed input rather than constraining any real
    cloud's vocabulary.

    Raises:
        UnsafeIdentifierError: If the value could alter the write path.
    """
    if not isinstance(value, str) or not value:
        raise UnsafeIdentifierError(f"{field_name}: expected a non-empty string, got {value!r}")
    if not _SAFE_PATH_SEGMENT.match(value):
        raise UnsafeIdentifierError(
            f"{field_name}: {value!r} is not usable as a filename component. This value "
            f"becomes part of an output path, so it may contain only letters, digits, "
            f"'_' and '-' -- no '/' and no '.', which could redirect the write outside "
            f"the output directory. Refusing to generate rather than sanitize."
        )
    return value


#: Upper bound on stored free-form text. Real policy titles are well under this;
#: the cap exists so a malformed or hostile catalog record cannot flood a terminal
#: or a generated comment with a single unbounded string.
MAX_TEXT_LENGTH = 300


def collapse_whitespace(value: str, *, limit: int = MAX_TEXT_LENGTH) -> str:
    """Normalize free-form text for safe display: single-space, printable, bounded.

    Applied to text (policy titles, categories) that is rendered into comments and
    terminal output. Three separate hazards, all handled here:

    * A newline or carriage return would terminate the comment the value sits
      inside, turning the remainder into executable text.
    * A control character -- an ANSI escape in particular -- can rewrite a
      terminal's display, so the reader cannot trust what they are shown.
    * An unbounded length pushes everything else off screen. Truncation is marked
      with an ellipsis so a shortened value is never mistaken for the whole one.
    """
    if not isinstance(value, str):
        return ""
    cleaned = "".join(
        " " if ch.isspace() else ch for ch in value if ch.isprintable() or ch.isspace()
    )
    collapsed = " ".join(cleaned.split())
    if len(collapsed) > limit:
        return collapsed[: limit - 3] + "..."
    return collapsed


def to_hcl_label(value: str) -> str:
    """Convert an arbitrary identifier into a valid, stable HCL block label.

    HCL labels cannot contain the ``:``, ``/`` or ``.`` characters common in
    ARNs, so they are folded to underscores. A leading digit is prefixed because
    HCL identifiers may not start with one.

    A **path-shaped** identifier -- one beginning with ``/``, which is what every
    Azure resource ID looks like -- is reduced to its last segment first. Folding
    the whole thing produced a 131-character label
    (``subscriptions_0000..._resourcegroups_rg_providers_microsoft_storage_...``)
    in which the only distinguishing part sits at the end, past the point anyone
    reads. The label is cosmetic -- ``import`` is what binds a block to a real
    resource, and it carries the full id -- so shortening it cannot retarget
    anything, and collisions are handled by the caller
    (:func:`~remgen.core.generators.hcl.group_targets` counts labels per resource
    type and disambiguates with the scope). This branch is unreachable for any
    identifier that was valid before it existed: a leading ``/`` was rejected
    outright, so no AWS label can change shape.
    """
    if value.startswith("/"):
        value = value.rstrip("/").rsplit("/", 1)[-1] or value
    label = _HCL_LABEL_INVALID.sub("_", value)
    label = re.sub(r"_{2,}", "_", label).strip("_")
    if not label:
        label = "resource"
    if label[0].isdigit():
        label = f"r_{label}"
    return label.lower()


class Effort(str, Enum):
    """How disruptive applying the remediation is expected to be."""

    #: Single idempotent API call, no downtime, reversible.
    LOW = "low"
    #: In-place modification that may briefly interrupt service or apply in a
    #: maintenance window.
    MEDIUM = "medium"
    #: Cannot be changed in place; requires replacing the resource.
    REPLACEMENT = "replacement"


class CostImpact(str, Enum):
    """Ongoing cloud-provider cost created by applying the remediation.

    This is a first-class field rather than a prose caveat because usage-scaled
    cost is the failure mode most likely to surprise someone applying a fix
    fleet-wide. A reviewer should not have to read a docstring to find it.
    """

    #: No incremental charge.
    NONE = "none"
    #: Small and bounded (e.g. a fixed per-key or per-request charge).
    LOW = "low"
    #: Grows with data volume or traffic and has no natural ceiling. Enabling
    #: this across a large estate can be expensive in ways a lab never reveals.
    USAGE_SCALED = "usage_scaled"


class SafetyTier(str, Enum):
    """Aggregate safety classification, derived from the fields below.

    Used by the CLI to gate which remediations are emitted by default. The
    default is deliberately conservative: a user must opt in to anything that
    is irreversible, touches the data path, or scales in cost.
    """

    #: Reversible, no data-path impact, no downtime, no usage-scaled cost.
    SAFEST = "safest"
    #: Sound but carries a commitment: irreversible, cost-scaled, or blocks
    #: IaC teardown. Requires explicit opt-in.
    CAUTION = "caution"
    #: Touches the data path, needs replacement, or risks an outage.
    #: Not present in v1; reserved so the tiering is future-proof.
    DISRUPTIVE = "disruptive"

    @property
    def rank(self) -> int:
        """Position in the risk ordering, lowest risk first.

        Lives on the enum because more than one caller needs to compare two tiers:
        the CLI orders the withheld-count breakdown by it, and the HCL generator
        files a block that applies several policies under the riskiest of their
        tiers. Two private copies of this ordering that disagreed would put a
        ``caution`` change under a ``SAFEST`` banner, which is the one thing the
        tiering exists to prevent.
        """
        return {SafetyTier.SAFEST: 0, SafetyTier.CAUTION: 1, SafetyTier.DISRUPTIVE: 2}[self]


@dataclass(frozen=True)
class ApiCall:
    """The AWS API operation a remediation performs.

    This is the contract :mod:`remgen.providers.aws.drift` verifies against the shipped
    botocore service model, which is why the parameter names are recorded
    explicitly rather than being buried in a format string.
    """

    #: botocore service id, e.g. ``"s3"``, ``"rds"``.
    service: str
    #: API operation name in the service model, e.g. ``"PutBucketVersioning"``.
    operation: str
    #: Input shape member names this recipe sets, e.g. ``("Bucket", "VersioningConfiguration")``.
    parameters: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.service or not self.operation:
            raise ValueError("ApiCall requires both service and operation")
        if not self.parameters:
            raise ValueError(f"{self.service}.{self.operation}: parameters must not be empty")


@dataclass(frozen=True)
class HclTarget:
    """How to express the fix in OpenTofu/Terraform, import included.

    ``import_id_template`` is formatted with the finding's fields. It is the
    identifier form the AWS provider expects for ``import`` — which is often
    *not* the ARN, and differs per resource type. Getting this wrong is the
    difference between adopting the live resource and creating a duplicate.
    """

    #: Provider resource type, e.g. ``"aws_s3_bucket_versioning"``.
    resource_type: str
    #: Attribute lines to render inside the resource block. Values are rendered
    #: verbatim as HCL, so they must be literals or already-quoted strings.
    #: Values pass through ``str.format``, so a literal brace is not permitted
    #: here -- use :attr:`blocks` for nested HCL blocks instead.
    attributes: tuple[tuple[str, str], ...]
    #: ``str.format``-style template for the import identifier, e.g. ``"{resource_id}"``.
    import_id_template: str
    #: Nested HCL blocks, as ``(block_name, ((attr, value, comment), ...))``.
    #: Modelled separately from :attr:`attributes` because HCL's block braces
    #: would otherwise be misread as ``str.format`` placeholders. ``comment`` is
    #: the trailing comment without its ``#``; use ``""`` for none.
    blocks: tuple[tuple[str, tuple[tuple[str, str, str], ...]], ...] = ()
    #: Provider arguments that are *required* for this resource type but which a
    #: finding cannot supply (e.g. an RDS instance's ``engine``). An ``import``
    #: block must be paired with a ``resource`` block, and the provider rejects a
    #: resource block missing its required arguments.
    #:
    #: Given as ``(name, placeholder, comment)``. The placeholder is rendered
    #: verbatim and must be a type-valid HCL value, because ``tofu validate``
    #: rejects both a missing argument *and* ``null`` -- so a stub that still
    #: validates is the only way to emit configuration a user can check before
    #: completing it. ``comment`` is the trailing TODO text, without its ``#``.
    unresolvable_required_attributes: tuple[tuple[str, str, str], ...] = ()
    #: Names of required nested *blocks* the finding cannot supply. Declared here
    #: for the "incomplete" warning; the stub itself goes in :attr:`blocks`.
    unresolvable_required_blocks: tuple[str, ...] = ()
    #: Minimum provider version that supports these attributes.
    min_provider_version: str = "5.0"

    def __post_init__(self) -> None:
        # Attribute values are formatted with str.format, so a raw brace would be
        # parsed as a placeholder and fail at render time. Catching it here means
        # the error surfaces on import -- and in the test suite -- rather than on
        # the one finding that happens to exercise the recipe.
        for name, value in self.attributes:
            if "{" in value.replace("{resource_id}", "").replace("{region}", "").replace(
                "{account_id}", ""
            ).replace("{resource_name}", "").replace("{policy_id}", ""):
                raise ValueError(
                    f"{self.resource_type}.{name}: attribute values may not contain "
                    f"literal braces. Use HclTarget.blocks for nested HCL blocks."
                )

    @property
    def is_complete(self) -> bool:
        """True when the emitted resource block needs no human completion."""
        return not (self.unresolvable_required_attributes or self.unresolvable_required_blocks)

    @property
    def unresolvable_names(self) -> tuple[str, ...]:
        """Names of everything a human must complete, for warning text."""
        return tuple(n for n, _, _ in self.unresolvable_required_attributes) + (
            self.unresolvable_required_blocks
        )


@dataclass(frozen=True)
class Recipe:
    """A verified remediation for exactly one policy.

    Attributes:
        policy_id: Tenable Cloud Security policy UUID this remediates.
        policy_title: Human-readable policy title, for traceability in output.
        summary: One-line description of what the fix does.
        api: The AWS operation performed, used for drift verification.
        cli_template: ``str.format`` template for the ``aws`` CLI command.
            Placeholders are filled from validated finding fields only.
        hcl: How to express the same fix as IaC, or ``None`` if the resource has
            no suitable provider resource type.
        effort: Expected disruption.
        reversible: Whether the change can be undone. If True, ``reverse_hint``
            must say how.
        reverse_hint: The command or action that undoes this change.
        data_path_impact: True if applying this can drop, reject or reroute
            live traffic or requests. Anything True here is not ``SAFEST``.
        cost_impact: Ongoing AWS cost created by the change.
        blocks_iac_destroy: True if the change prevents ``terraform destroy`` /
            ``tofu destroy`` from succeeding. Matters for ephemeral environments.
        prerequisites: Things that must exist first (log groups, IAM roles).
            Rendered as comments so a reviewer sees them before running.
        caveats: Honest warnings — cost, downtime, replacement, partial fixes.
            Relocated to the run README, which is where reference detail lives.
        critical_caveats: The subset of warnings that must be read *before* the
            command runs, so they are rendered inline next to it as well as in the
            README. Reserved for a consequence the tier fields cannot express.
            ``safety_tier`` is derived from four structured fields, and a change can
            be reversible, free and in-place — therefore ``safest`` — while still
            withdrawing access somebody depends on. S3 Block Public Access is the
            case that forced this: honestly ``safest``, and it stops anonymous reads
            of a published dataset the moment it applies. Keep this empty unless the
            worst outcome of applying the recipe is invisible in the derived notes;
            a banner where every line shouts is a banner nobody reads.
        docs_url: Authoritative AWS documentation for the operation.
    """

    policy_id: str
    policy_title: str
    summary: str
    api: ApiCall
    cli_template: str
    hcl: HclTarget | None
    effort: Effort = Effort.LOW
    reversible: bool = True
    reverse_hint: str = ""
    data_path_impact: bool = False
    cost_impact: CostImpact = CostImpact.NONE
    blocks_iac_destroy: bool = False
    prerequisites: tuple[str, ...] = field(default_factory=tuple)
    caveats: tuple[str, ...] = field(default_factory=tuple)
    critical_caveats: tuple[str, ...] = field(default_factory=tuple)
    docs_url: str = ""

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise ValueError("Recipe requires a policy_id")
        if "{resource_id}" not in self.cli_template:
            raise ValueError(
                f"{self.policy_id}: cli_template must reference {{resource_id}} so the "
                f"command targets the finding's resource"
            )
        # A reversible recipe that does not say how to reverse it is not
        # actually actionable, so treat the omission as a defect.
        if self.reversible and not self.reverse_hint:
            raise ValueError(
                f"{self.policy_id}: reversible=True requires a reverse_hint explaining "
                f"how to undo the change"
            )
        # The two caveat tuples are disjoint, not nested. `caveats` is asserted to
        # appear in the README *and nowhere else*, which is what proves the reference
        # detail was relocated rather than duplicated back inline. A critical caveat
        # listed in both tuples would render twice in the README and break that
        # assertion, so promoting one means moving it, not copying it.
        both = [c for c in self.critical_caveats if c in self.caveats]
        if both:
            raise ValueError(
                f"{self.policy_id}: {both[0]!r} is in both `caveats` and "
                f"`critical_caveats`; promote a caveat by moving it, not by copying it"
            )

    @property
    def needs_replacement(self) -> bool:
        """True when the cloud cannot apply this change to an existing resource."""
        return self.effort is Effort.REPLACEMENT

    @property
    def safety_tier(self) -> SafetyTier:
        """Derive the safety tier from the individual safety attributes.

        Derived rather than hand-set so a recipe author cannot accidentally
        label something safe while also declaring it irreversible.
        """
        if self.data_path_impact or self.needs_replacement or self.effort is Effort.MEDIUM:
            return SafetyTier.DISRUPTIVE
        if (
            not self.reversible
            or self.cost_impact is CostImpact.USAGE_SCALED
            or self.blocks_iac_destroy
        ):
            return SafetyTier.CAUTION
        return SafetyTier.SAFEST

    @property
    def safety_notes(self) -> tuple[str, ...]:
        """Machine-derived, human-readable safety statements for the output.

        These are generated from the structured fields so that every artifact
        carries the same warnings, in the same words, without depending on a
        recipe author remembering to write them as prose.
        """
        notes: list[str] = []
        if not self.reversible:
            notes.append("NOT REVERSIBLE: this change cannot be fully undone.")
        elif self.reverse_hint:
            notes.append(f"Reversible: {self.reverse_hint}")
        if self.data_path_impact:
            notes.append("AFFECTS LIVE TRAFFIC: may drop or reject requests.")
        if self.cost_impact is CostImpact.USAGE_SCALED:
            notes.append(
                "COST SCALES WITH USAGE: charges grow with data volume and have no "
                "ceiling. Estimate volume before applying fleet-wide."
            )
        elif self.cost_impact is CostImpact.LOW:
            # No cloud named. This note read "Small incremental AWS cost." until the
            # first Azure recipe with a cost reached it -- and because that recipe is
            # CLI-only and SAFEST, the sentence appeared inside an Azure shell script
            # under an Azure banner. `safety_notes` is on `Recipe`, which has no
            # provider handle, so the name cannot be substituted here; the honest fix
            # is not to name a cloud in shared code. `Provider.display_name` exists for
            # text that must.
            notes.append("Small incremental cost from the cloud provider.")
        if self.blocks_iac_destroy:
            notes.append(
                "Blocks 'terraform destroy' / 'tofu destroy'. Disable deliberately "
                "before a planned teardown; avoid on ephemeral or CI environments."
            )
        if self.needs_replacement:
            notes.append("REQUIRES RESOURCE REPLACEMENT: cannot be changed in place.")
        return tuple(notes)


@dataclass(frozen=True)
class Policy:
    """One policy in the Tenable Cloud Security catalog.

    Titles are *not* put through :func:`validate_identifier`: they are free-form
    product text containing commas, parentheses and apostrophes, and they are only
    ever rendered into comments, never into a command or an HCL value. They are
    stripped of control characters, though -- a newline in a title would let it
    escape the comment it is rendered inside.
    """

    policy_id: str
    title: str
    category: str = ""

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise ValueError("Policy requires a policy_id")
        object.__setattr__(self, "title", collapse_whitespace(self.title))
        object.__setattr__(self, "category", collapse_whitespace(self.category))


@dataclass(frozen=True)
class Finding:
    """One policy violation on one resource.

    Deliberately minimal: the fields every adapter can supply. Identifiers are
    validated at construction so untrusted data cannot reach a generator.

    **This tool does not account for any exceptions configured in Tenable Cloud
    Security, and this class is where that boundary enters the tool.** There is no
    field for an exception, a suppression or an accepted risk, so no generator can
    consult one, and every finding is treated as one the operator intends to fix.
    Exceptions live in the platform and do not survive a findings export: whether an
    excepted resource reaches this constructor depends entirely on how the export was
    filtered, and the tool can neither detect that nor warn about it.

    Deliberate rather than an oversight. The project supplies verified recipes for
    common, safely scriptable misconfigurations without consulting the operator's
    specific environment -- it holds no cloud credentials and makes no cloud API
    calls, so it cannot read an exception list, a resource tag, or the intent behind
    a configuration. It reasons about the provider's published API surface and the
    finding it is given, and nothing else. Scoping the export is therefore the
    operator's job, which is why ``README.md`` says so in those words.

    Stated here rather than in a provider because the boundary is a property of
    findings ingest, which is shared. It holds for AWS, for Azure, and for any cloud
    added later -- a provider cannot opt out of it, and a new provider inherits it
    without having to rediscover it. Recipes whose remediation withdraws access that
    existing callers may be using must carry the intent question in their caveats;
    ``aws/recipes/s3.py``'s Block Public Access recipe is the worked example, since
    an intentionally-public bucket is the ordinary exception case rather than an
    exotic one. A CI gate keeps this docstring and ``README.md`` in agreement across
    every implemented cloud.
    """

    policy_id: str
    resource_id: str
    region: str
    account_id: str
    resource_name: str = ""

    def __post_init__(self) -> None:
        validate_identifier(self.policy_id, field_name="policy_id")
        validate_identifier(self.resource_id, field_name="resource_id")
        # region and account_id are held to the stricter path-segment rule, not
        # because they are more sensitive but because of where they *go*:
        # OutputUnit.filename interpolates both into a filename. Under the
        # identifier rule alone -- which permits '/', as S3 keys and Azure
        # resource IDs require -- an account_id of '1/../../../../tmp/x' wrote
        # both artifacts outside the --out directory. Validated here, at the
        # boundary where untrusted findings data enters, so no generator has to
        # remember to.
        validate_path_segment(self.region, field_name="region")
        validate_path_segment(self.account_id, field_name="account_id")
        if self.resource_name:
            validate_identifier(self.resource_name, field_name="resource_name")
