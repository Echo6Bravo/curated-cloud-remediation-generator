"""The shared command-line pipeline, parameterized by cloud.

One implementation drives every cloud's command. The steps -- load findings as
untrusted input, dedupe, pair with recipes, gate by safety level, split by scope,
render, write, reconcile the counts -- are identical everywhere, and a per-cloud
copy is how the counts stop reconciling. Everything cloud-specific arrives as a
:class:`~remgen.core.provider.Provider`, which is also why nothing here imports
from :mod:`remgen.providers`.

Four subcommands:

* ``generate`` -- turn findings into remediation artifacts. The main command.
* ``policies`` -- show the policy catalog, what is supported, and what changed.
* ``verify``   -- check every recipe against the cloud's current API definitions.
* ``recipes``  -- show the curated recipe set and its safety classification.

Safety posture of this interface:

* Nothing here calls a cloud API or Tenable. There is no ``--apply``. The tool
  writes files; the user runs them. That boundary is the point, so it is not
  configurable.
* ``generate`` emits only ``SAFEST``-level remediations unless the user opts in
  with ``--safety-level``. When remediations are withheld, the count and the exact
  flag to include them are printed -- a silent cap would read as "nothing else to
  do".
* Every run reports what it *could not* do: findings with no recipe, records that
  failed validation, and recipes whose API contract could not be verified.
* Output is split per cloud and per credential scope, and for HCL per region when
  the cloud's Terraform provider is region-scoped, because no format can target
  more than one credential scope at a time. That split is a correctness
  requirement rather than an ergonomic one; see :mod:`remgen.core.layout`.

Exit codes, so a scheduler can branch on them:

* ``0`` -- success.
* ``2`` -- usage or input error (bad arguments, unreadable input, unwritable output).
* ``3`` -- a recipe no longer matches the cloud's API definition. Nothing was
  generated.
* ``4`` -- recipes could not be verified at all (no API definitions available).
* ``5`` -- artifacts were written, but the run did not cover everything it was asked
  to. Two causes, deliberately sharing one code because they carry one claim: the
  policy-catalog change detection did not run (unreadable or unwritable baseline), or
  ``--strict`` was given and at least one input record was rejected. Distinct from
  ``0`` because a check that did not run must not be reported as a check that passed,
  and because a run that silently dropped a third of its input must not look clean.
  A separate code for the ``--strict`` case would have to define its precedence
  against a degraded catalog, which buys a scheduler nothing it cannot read off the
  summary. Note that ``--strict`` does *not* fire on findings whose policy has no
  recipe: partial coverage is the normal state of a curated catalog, not a shortfall
  of the run.
* ``6`` -- the HCL could not be generated correctly: two recipes target one resource
  and disagree about what to set, or two resources in different credential scopes
  would claim one import identifier. Nothing was generated. Distinct from ``3``
  because that means the cloud's API changed under a correct recipe set, while this
  means the tool is internally inconsistent; the two need different fixes.

  ``verify`` runs all four of its axes whatever any one of them reports, so the
  code below is the most urgent verdict rather than the first: ``4`` (an axis could
  not run, making every other verdict incomplete), then ``3``, then ``7``, then
  ``8``, then ``9``. The output always describes all four.
* ``7`` -- a recipe's HCL target no longer matches the Terraform/OpenTofu provider
  schema: an argument was renamed or removed, a resource type disappeared, or the
  recipe claims the provider requires something it does not. Separate from ``3``
  because the two halves of a recipe rot independently and are fixed in different
  places, and separate from ``6`` because the recipe set is self-consistent -- it is
  the provider that moved. Only ``verify`` returns it.
* ``8`` -- a recipe renders a console command the cloud's CLI no longer accepts: a
  renamed or removed subcommand or flag. Separate from ``3`` because a CLI can rename
  a flag while the underlying API operation is untouched, and the generated script
  runs the CLI, not the API.
* ``9`` -- a recipe is keyed to a policy id the Tenable catalog no longer contains, so
  it matches no findings and never fires again. Last in precedence and the most easily
  missed: the other three mean a shipped artifact does the wrong thing, while this one
  means an artifact is never produced at all, which looks exactly like a clean estate.
  Only ``verify`` returns it, and only when given ``--catalog`` -- there is no live
  Tenable adapter (see :mod:`remgen.core.sources`), so without an export the axis
  reports that it did not run rather than passing.
* ``130`` -- interrupted.

Note that ``3``, ``7``, ``8`` and ``9`` do not mean the other three axes passed -- only
that this one is the most urgent of those that failed. Every axis runs on every
``verify`` invocation, so the output describes all four regardless of the code. Read
the output, not just the code.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys
from dataclasses import replace
from pathlib import Path

from remgen import __version__
from remgen.core.artifacts import RunCounts, render_manifest, render_readme
from remgen.core.catalog import (
    BaselineState,
    CacheError,
    Snapshot,
    default_cache_dir,
    diff_catalog,
    load_snapshot,
    save_snapshot,
)
from remgen.core.drift import DriftStatus
from remgen.core.generators import HclGenerationError, render_hcl
from remgen.core.hcl_schema import (
    SCHEMA_ENV_VAR,
    SchemaSourceError,
    SchemaStatus,
    find_schema_path,
    load_provider_schema,
    verify_all_hcl,
)
from remgen.core.layout import (
    DEFAULT_MAX_PER_FILE,
    Format,
    describe_layout,
    plan_units,
)
from remgen.core.model import Finding, Recipe, SafetyTier
from remgen.core.provider import Provider
from remgen.core.sources import JsonFileSource, LoadResult, Rejection, SourceError

#: ``--safety-level`` value -> the levels it admits. Cumulative: each level includes
#: everything less risky, because "I accept irreversible changes" does not mean "and
#: not the safe ones". Declared as data so the flag's help text, the withheld-count
#: advice and the gate itself cannot disagree.
_LEVELS: dict[str, frozenset[SafetyTier]] = {
    "safest": frozenset({SafetyTier.SAFEST}),
    "caution": frozenset({SafetyTier.SAFEST, SafetyTier.CAUTION}),
    "all": frozenset(SafetyTier),
}

#: ``--format`` value -> the format it selects, plus the ``all`` alias. Both formats
#: are the default because they are complementary rather than alternative: the script
#: is for a one-off fix, the HCL for an estate already under IaC.
_FORMATS: dict[str, tuple[Format, ...]] = {
    "cli": (Format.CLI,),
    "hcl": (Format.HCL,),
    "all": (Format.CLI, Format.HCL),
}

_EPILOG = """\
examples:
  # See what is supported before doing anything
  {command} recipes

  # Confirm every recipe still matches the current {display} API definitions
  {command} verify

  # Generate remediations from an exported findings file
  {command} generate --findings findings.json --out ./artifacts

  # Emit only the shell script, or only the OpenTofu/Terraform configuration
  {command} generate --findings findings.json --out ./artifacts --format cli

  # Include remediations that carry a commitment (irreversible, cost-scaled)
  {command} generate --findings findings.json --out ./artifacts --safety-level caution

  # Track catalog changes; new policies are reported, never auto-remediated
  {command} policies --catalog policies.json

This tool never modifies {display}. It writes files for you to review and run.
"""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _emit(lines: list[str], stream=None) -> None:
    """Print ``lines`` to ``stream``, defaulting to the *current* stdout.

    Resolved at call time rather than as a default argument value: a default is
    bound at import, which would pin the original stdout and ignore any later
    redirection.
    """
    target = stream if stream is not None else sys.stdout
    for line in lines:
        print(line, file=target)


def _parse_formats(raw: str) -> tuple[Format, ...]:
    """Parse a ``--format`` value into the formats to emit.

    Accepts a comma-separated list (``cli,hcl``) as well as a single name and the
    ``all`` alias, so the flag reads the same whether one or both are wanted. A list
    rather than a boolean per format on purpose: a pair of booleans has an ambiguous
    "neither passed" state, and per-format flag *names* would not survive a second
    cloud -- ``--aws-cli`` beside ``--gcloud`` says nothing a command already scoped
    to one cloud does not.

    Raises:
        ValueError: On an unknown or empty name, naming what was given and what is
            accepted. Raised rather than silently dropping the token, because a
            typo that quietly emits half the output looks like a tool that lost
            findings.
    """
    names = [part.strip().lower() for part in raw.split(",")]
    if any(not name for name in names):
        raise ValueError(
            f"--format {raw!r}: empty format name. Give a comma-separated list of "
            f"{', '.join(sorted(_FORMATS))}."
        )
    selected: list[Format] = []
    for name in names:
        if name not in _FORMATS:
            raise ValueError(
                f"--format {raw!r}: unknown format {name!r}. Choose from "
                f"{', '.join(sorted(_FORMATS))}."
            )
        for fmt in _FORMATS[name]:
            if fmt not in selected:
                selected.append(fmt)
    # Ordered canonically rather than as typed, so `--format hcl,cli` and
    # `--format cli,hcl` produce byte-identical runs.
    return tuple(fmt for fmt in (Format.CLI, Format.HCL) if fmt in selected)


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------


def _dedupe(
    findings: tuple[Finding, ...],
) -> tuple[tuple[Finding, ...], int]:
    """Collapse findings identical in policy, resource, region and scope.

    Exports legitimately repeat a finding -- the same violation observed in two
    scans, or a record joined across views. Emitting the remediation twice means
    running the same idempotent API call twice (harmless) but also emitting two HCL
    blocks for one resource, which cannot validate. Deduping here keeps the
    generator's input a set, and the collapsed count is reported.
    """
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (
            finding.policy_id,
            finding.resource_id,
            finding.region,
            finding.account_id,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return tuple(unique), len(findings) - len(unique)


def _pair_findings(
    findings: tuple[Finding, ...], provider: Provider
) -> tuple[list[tuple[Recipe, Finding]], list[Finding]]:
    """Split findings into those with a recipe and those without."""
    matched: list[tuple[Recipe, Finding]] = []
    unmatched: list[Finding] = []
    for finding in findings:
        recipe = provider.get_recipe(finding.policy_id)
        if recipe is None:
            unmatched.append(finding)
        else:
            matched.append((recipe, finding))
    matched.sort(
        key=lambda p: (
            p[0].safety_tier.rank,
            p[0].policy_title,
            p[1].account_id,
            p[1].region,
            p[1].resource_id,
        )
    )
    return matched, unmatched


def _reject_scope_conflicts(
    result: LoadResult, provider: Provider
) -> tuple[LoadResult, tuple[Rejection, ...]]:
    """Move findings whose identifier contradicts their credential scope into rejections.

    A no-op for a provider with no :attr:`~remgen.core.provider.Provider.scope_conflict`
    hook, which is the honest state for AWS rather than a gap -- see that attribute for
    why the asymmetry is in the clouds.

    The index is reconstructed to be an *input record* number rather than a position
    among loaded findings, because both kinds of rejection print under one
    ``[record N]`` label and two numbering schemes behind one label is a worse defect
    than a missing number. Loaded findings are in input order and the loader's own
    rejections carry their input indices, so the k-th loaded finding is at the k-th
    input position that was not already rejected -- exact, not an estimate.
    """
    if provider.scope_conflict is None:
        return result, ()
    already_rejected = {r.index for r in result.rejections}
    input_indices = [
        i for i in range(len(result.findings) + len(already_rejected)) if i not in already_rejected
    ]
    kept: list[Finding] = []
    conflicts: list[Rejection] = []
    for position, finding in enumerate(result.findings):
        reason = provider.scope_conflict(finding)
        if reason is None:
            kept.append(finding)
        else:
            index = input_indices[position] if position < len(input_indices) else position
            conflicts.append(Rejection(index=index, reason=reason, raw=finding.resource_id))
    if not conflicts:
        return result, ()
    return (
        replace(
            result,
            findings=tuple(kept),
            # Sorted by input position so the report reads in file order. Appending
            # would list a conflict after every parse failure regardless of where the
            # offending record actually is, which is what a reader uses to find it.
            rejections=tuple(sorted(result.rejections + tuple(conflicts), key=lambda r: r.index)),
        ),
        tuple(conflicts),
    )


def _clip(text: str, limit: int = 160) -> str:
    """Shorten a message for terminal display.

    Rejection reasons quote the offending value, which for a malformed record can
    be arbitrarily long. An unclipped reason pushes the rest of the summary off
    screen, which is the opposite of surfacing a problem.
    """
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


#: Measured mean bytes per rendered remediation, by format. Taken from the *smallest*
#: measured run -- 1,000 findings across 40 accounts and 4 regions, at 324 B for the
#: shell script and 946 B for HCL -- and rounded up, deliberately. Per-policy and
#: per-file prose is stated once and amortizes as a run grows, so the true figure
#: falls with scale (measured: 996 B/finding combined at 10,000 findings, 819 B at
#: 50,000, against 1,364 B at 1,000). Anchoring on the small run therefore
#: over-predicts large runs, which is the safe direction for a size warning: it can
#: warn slightly early but will not miss. Down from 1,069 and 1,410 before shared
#: prose was hoisted out of the per-finding blocks. Re-measure if the generators'
#: comment structure changes; this only *predicts* size, and the run summary always
#: reports actual bytes.
_BYTES_PER_REMEDIATION = {Format.CLI: 338, Format.HCL: 975}


def _human_bytes(count: int) -> str:
    """Format a byte count for a summary line."""
    if count < 1024:
        return f"{count} B"
    for unit, scale in (("KB", 1024), ("MB", 1024**2), ("GB", 1024**3)):
        if count < scale * 1024 or unit == "GB":
            return f"{count / scale:.1f} {unit}"
    return f"{count} B"  # pragma: no cover -- unreachable, GB branch is terminal


def estimate_output_bytes(
    count: int, formats: tuple[Format, ...] = (Format.CLI, Format.HCL)
) -> int:
    """Estimate total output size for ``count`` remediations in ``formats``.

    Cheap on purpose: a multiplication, not a trial render. It exists so a run that
    is about to produce hundreds of megabytes says so up front rather than after the
    fact, which is when a surprised user has already waited for it. Scoped to the
    selected formats, so a ``--format cli`` run is not warned about bytes it will
    never write.
    """
    return count * sum(_BYTES_PER_REMEDIATION[fmt] for fmt in formats)


def _report_load(result: LoadResult) -> None:
    """Print anything the loader could not use."""
    if not result.rejections:
        return
    print(f"\n{len(result.rejections)} input record(s) were rejected and not remediated:")
    for rejection in result.rejections[:20]:
        print(f"  [record {rejection.index}] {_clip(rejection.reason)}")
    if len(result.rejections) > 20:
        print(f"  ... and {len(result.rejections) - 20} more")


def cmd_generate(args: argparse.Namespace, provider: Provider) -> int:
    if args.max_per_file < 0:
        print("error: --max-per-file must be 0 or greater", file=sys.stderr)
        return 2
    try:
        formats = _parse_formats(args.format)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    source = JsonFileSource(
        findings_path=args.findings,
        policies_path=args.catalog,
    )
    try:
        result = source.load()
    except SourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not result.findings and not result.rejections:
        print("No findings in the input. Nothing to generate.")
        return 0

    # Scope conflicts are rejected before pairing, so a contradictory finding cannot
    # reach a renderer. Reported through the same `rejections` channel as a malformed
    # record rather than a new one, because the reconciliation the summary prints has to
    # keep adding up: a finding refused here is visibly refused, not quietly absent.
    result, scope_conflicts = _reject_scope_conflicts(result, provider)

    unique_findings, duplicates = _dedupe(result.findings)
    matched, unmatched = _pair_findings(unique_findings, provider)

    # Verify the API contract before emitting anything that relies on it. A
    # recipe whose operation has changed shape must not be rendered as if valid.
    #
    # Skipped when the cloud has no recipes: there is nothing to verify, `matched` is
    # necessarily empty, and a provider under construction is entitled to have no
    # verifier yet. Guarded on the recipe set rather than on `matched` -- an empty
    # `matched` with a non-empty recipe set means the *findings* matched nothing,
    # which must still verify, because the next run's findings may match.
    all_provider_recipes = provider.all_recipes()
    drift_results = (
        {r.policy_id: r for r in provider.verify_recipes(all_provider_recipes)}
        if all_provider_recipes
        else {}
    )
    bad = {pid for pid, res in drift_results.items() if res.checked and not res.ok}
    if bad:
        print(
            f"\nerror: {len(bad)} recipe(s) no longer match the {provider.display_name} "
            f"service model. Refusing to generate. Run "
            f"'{provider.command} verify' for detail.",
            file=sys.stderr,
        )
        return 3
    unverified = [res for res in drift_results.values() if not res.checked]

    allowed = _LEVELS[args.safety_level]
    selected = [(r, f) for r, f in matched if r.safety_tier in allowed]
    withheld = [(r, f) for r, f in matched if r.safety_tier not in allowed]

    # Built once here, and both the manifest and the console summary below read from
    # it. Two independent derivations of "how many were rejected" is how a manifest
    # comes to disagree with the transcript of the run that produced it -- and a
    # consumer has no way to tell which one is lying.
    run_counts = RunCounts(
        records_read=len(result.findings) + len(result.rejections),
        usable_findings=len(result.findings),
        rejected=len(result.rejections),
        scope_conflicts=len(scope_conflicts),
        duplicates_merged=duplicates,
        distinct_findings=len(unique_findings),
        remediated=len(selected),
        withheld_by_safety_level=len(withheld),
        unsupported=len(unmatched),
    )

    # Forecast size before doing the work, so a run that will produce hundreds of
    # megabytes says so now rather than after the user has waited for it. Warn only
    # past a threshold; an unconditional size line is noise on a normal run.
    forecast = estimate_output_bytes(len(selected), formats)
    if forecast > 50 * 1024**2:
        print(
            f"\n  Note: {len(selected)} remediations will produce roughly "
            f"{_human_bytes(forecast)}.\n"
            f"  Most of that is the per-remediation comment header. Narrow the input, "
            f"select one\n  --format, or lower --max-per-file if you want smaller files "
            f"to review."
        )

    out_dir: Path = args.out
    generated_at = _now()

    # Output is split by scope before rendering. Cloud and credential scope are hard
    # boundaries for both formats, and region is one for HCL when this cloud's
    # Terraform provider is region-scoped, because neither an ambient-credential
    # shell script nor a provider configuration can address more than one credential
    # scope at a time. See remgen.core.layout.
    def _plan(fmt: Format, pairs: list[tuple[Recipe, Finding]]) -> list:
        return plan_units(
            pairs,
            fmt,
            cloud=provider.cloud,
            max_per_file=args.max_per_file,
            provider_is_region_scoped=provider.hcl_provider_is_region_scoped,
            extension=provider.shell_extension,
            scope_noun=provider.credential_scope_noun,
        )

    cli_units = _plan(Format.CLI, selected) if Format.CLI in formats else []
    hcl_units = (
        _plan(Format.HCL, [(r, f) for r, f in selected if r.hcl is not None])
        if Format.HCL in formats
        else []
    )

    # Rendering is pure, so do it before touching the filesystem: a template error
    # then fails without having written a half-populated output directory.
    # (relative path, text, make_executable) -- the companion files below are not
    # tied to a single output unit, so the write loop keys off paths rather than
    # units. Artifact paths include the cloud directory; the companion files sit at
    # the top so one README and one index cover the whole run.
    rendered: list[tuple[str, str, bool]] = [
        (
            unit.relative_path,
            provider.render_shell(
                list(unit.pairs),
                version=__version__,
                generated_at=generated_at,
                unit=unit,
            ),
            True,
        )
        for unit in cli_units
    ]
    try:
        rendered.extend(
            (
                unit.relative_path,
                render_hcl(
                    list(unit.pairs),
                    version=__version__,
                    generated_at=generated_at,
                    unit=unit,
                    command=provider.command,
                    scope_block=provider.hcl_scope_block,
                    provider_source=provider.tf_provider_source,
                    verified_major=provider.tf_provider_verified_major,
                ),
                False,
            )
            for unit in hcl_units
        )
    except HclGenerationError as exc:
        # The generated HCL would be wrong in a way `tofu validate` accepts: either
        # two recipes claim one resource and disagree, or two resources in different
        # accounts claim one import id. Both are defects in this tool rather than in
        # the user's input, and both mean nothing is written -- including the shell
        # script, which is already rendered but would otherwise leave an artifact set
        # that silently omits the HCL half.
        print(f"\nerror: {exc}", file=sys.stderr)
        print(
            f"Nothing was written. This is a defect in {provider.command} rather than "
            f"in your findings; please report it.",
            file=sys.stderr,
        )
        return 6

    # The shared instructions and the index, written once per run rather than
    # repeated in every artifact. See remgen.core.artifacts for why.
    all_units = cli_units + hcl_units
    if all_units:
        rendered.append(
            (
                "README.md",
                render_readme(
                    all_units,
                    provider=provider,
                    version=__version__,
                    generated_at=generated_at,
                    count=len(selected),
                ),
                False,
            )
        )
        rendered.append(
            (
                "manifest.json",
                render_manifest(
                    all_units,
                    version=__version__,
                    generated_at=generated_at,
                    command=provider.command,
                    counts=run_counts,
                ),
                False,
            )
        )

    written: list[tuple[Path, int]] = []
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        resolved_out = out_dir.resolve()
        for name, text, executable in rendered:
            path = out_dir / name
            # Containment is asserted here rather than argued from the inputs.
            # Every component of `name` is validated upstream -- the provider's
            # cloud id as a single alphanumeric segment, and a finding's
            # account_id and region by `validate_path_segment` -- but an earlier
            # version of this code carried a comment proving only the *cloud*
            # segment safe, which read as having considered the question and
            # stopped anyone from noticing that account_id and region are
            # interpolated into the filename too. An account_id of
            # '1/../../../../tmp/x' then wrote both artifacts outside --out.
            #
            # So the invariant is checked against the resolved path instead of
            # deduced from the validators: this is the last line before a write,
            # it costs one syscall per file, and it holds even if a future
            # caller adds a component nobody re-validated.
            if not path.resolve().is_relative_to(resolved_out):
                print(
                    f"\nerror: refusing to write {name!r}: it resolves to "
                    f"{path.resolve()}, outside the output directory {resolved_out}.",
                    file=sys.stderr,
                )
                print(
                    f"Nothing further was written. This is a defect in "
                    f"{provider.command} rather than in your findings; please report it.",
                    file=sys.stderr,
                )
                return 6
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            if executable:
                path.chmod(0o755)
            written.append((path, len(text.encode("utf-8"))))
    except OSError as exc:
        # A path that is an existing file, an unwritable parent, or a full disk.
        # Reported as a message: an operator reading a traceback learns nothing
        # actionable that this line does not already say.
        print(f"error: cannot write to {out_dir}: {exc}", file=sys.stderr)
        return 2

    # ---- Summary. Everything not done is stated explicitly. ----
    # The counts are printed so they reconcile: total in = usable + rejected, and
    # usable = duplicates + distinct, and distinct = written + withheld +
    # no-recipe. A summary whose numbers do not
    # add up invites the reader to assume the missing ones were fine.
    # Read off `run_counts`, the same object the manifest was rendered from, so the
    # numbers a human reads and the numbers a pipeline parses cannot drift apart.
    print(f"\n{provider.command} {__version__} -- generated {generated_at}")
    print(f"\n  Records read:         {run_counts.records_read}")
    print(f"    usable findings:    {run_counts.usable_findings}")
    if run_counts.rejected:
        print(f"    rejected:           {run_counts.rejected}")
    if run_counts.scope_conflicts:
        # Broken out of the rejected count rather than added to it -- these were
        # well-formed records, so leaving them indistinguishable from malformed input
        # would misdirect whoever has to fix the export.
        print(
            f"      scope conflicts:  {run_counts.scope_conflicts} "
            f"({provider.credential_scope_noun} mismatch)"
        )
    if run_counts.duplicates_merged:
        print(f"    duplicates merged:  {run_counts.duplicates_merged}")
        print(f"    distinct findings:  {run_counts.distinct_findings}")
    print(f"  Remediations written: {run_counts.remediated}")
    if run_counts.withheld_by_safety_level:
        print(f"    withheld by level:  {run_counts.withheld_by_safety_level}")
    if run_counts.unsupported:
        print(f"    no recipe:          {run_counts.unsupported}")
    total_bytes = sum(size for _, size in written)
    print(f"\n  Output: {out_dir}  ({len(written)} file(s), {_human_bytes(total_bytes)})")
    print(f"  Formats: {', '.join(fmt.value for fmt in formats)}")
    # The provider's region scoping is passed, not assumed: it is what separates "split
    # by region because the provider demands it" from "split by region because this
    # scope was too big to review", and only the planner and the provider know which.
    _emit(
        describe_layout(cli_units, provider_is_region_scoped=provider.hcl_provider_is_region_scoped)
    )
    _emit(
        describe_layout(hcl_units, provider_is_region_scoped=provider.hcl_provider_is_region_scoped)
    )
    if written and (args.verbose or len(written) <= 8):
        for path, size in written:
            print(f"    {path.name}  ({_human_bytes(size)})")
    elif written:
        print(f"    (use -v to list all {len(written)} files)")

    # Only meaningful when HCL was actually emitted: a --format cli run has no
    # resource blocks to complete, so the note would send the reader looking for
    # TODOs that are not there.
    if hcl_units:
        incomplete = [r for r, _ in selected if r.hcl is not None and not r.hcl.is_complete]
        if incomplete:
            print(
                f"\n  Note: {len(incomplete)} HCL block(s) contain TODO placeholders for "
                f"provider-required\n  arguments that findings do not carry. Complete "
                f"them before applying."
            )

    if Format.HCL in formats and Format.CLI not in formats:
        cli_only = [(r, f) for r, f in selected if r.hcl is None]
        if cli_only:
            print(
                f"\n  Note: {len(cli_only)} remediation(s) have no IaC equivalent and "
                f"were not\n  written, because --format excluded the CLI script. "
                f"Add 'cli' to include them."
            )

    if withheld:
        by_level: dict[SafetyTier, int] = {}
        for recipe, _ in withheld:
            by_level[recipe.safety_tier] = by_level.get(recipe.safety_tier, 0) + 1
        ordered = sorted(by_level.items(), key=lambda kv: kv[0].rank)
        detail = ", ".join(f"{n} {t.value}" for t, n in ordered)
        print(f"\n  Withheld by safety level: {len(withheld)} ({detail})")
        print(
            f"  These are excluded because --safety-level is "
            f"'{args.safety_level}'. To include them:"
        )
        print("    --safety-level caution   reversible-with-commitment, or cost-scaled")
        print("    --safety-level all       also changes that can affect availability")

    if unmatched:
        distinct = sorted({f.policy_id for f in unmatched})
        print(
            f"\n  No recipe available: {len(unmatched)} finding(s) across "
            f"{len(distinct)} policy/policies."
        )
        print("  Coverage is intentionally partial; these were not remediated.")
        if args.verbose:
            for policy_id in distinct:
                print(f"    {policy_id}")

    if unverified:
        print(
            f"\n  Warning: {len(unverified)} recipe(s) could not be verified against the "
            f"{provider.display_name}\n  service model ({unverified[0].detail})"
        )

    _report_load(result)

    degraded = False
    if result.policies:
        lines, degraded = _catalog_report(result, args, provider)
        _emit(lines)

    print(
        f"\nReview the output before running anything. This tool made no "
        f"{provider.display_name} changes."
    )
    # The artifacts were written, so this is not a failure -- but the catalog
    # change detection did not run, and a scheduler must be able to see that.
    #
    # `--strict` joins the same code rather than minting a new one, because it makes
    # the same claim: everything that could be written was, and something a caller
    # cares about did not make it in. A separate code would also have to define its
    # precedence against a degraded catalog in the run where both are true, and
    # "some input was lost" is not usefully more or less urgent than "drift went
    # unchecked" -- both mean read the summary. Rejections are excluded from the
    # default so the exit code keeps meaning "the tool worked": partial coverage is
    # the normal state of a curated catalog, and a nonzero default would train
    # schedulers to ignore it.
    if degraded:
        return 5
    if args.strict and result.rejections:
        print(
            f"\n  --strict: {len(result.rejections)} input record(s) were rejected, "
            f"so this run did not\n  cover everything it was given. Exit 5.",
            file=sys.stderr,
        )
        return 5
    return 0


# ---------------------------------------------------------------------------
# policies
# ---------------------------------------------------------------------------


def _catalog_report(
    result: LoadResult, args: argparse.Namespace, provider: Provider
) -> tuple[list[str], bool]:
    """Diff the catalog against the cached snapshot and describe the result.

    Returns:
        ``(lines, degraded)``. ``degraded`` is True when the change detection did
        not actually run -- an unreadable baseline, or a snapshot that could not be
        saved. The caller turns that into a non-zero exit code, because a check
        that did not run must not look like a check that passed.
    """
    cache_dir = args.cache_dir or default_cache_dir()
    previous, state = load_snapshot(cache_dir)
    diff = diff_catalog(result.policies, previous, state)
    lines = ["", *diff.summary_lines(cloud_label=provider.display_name)]
    degraded = state is BaselineState.UNREADABLE

    supported = {r.policy_id for r in provider.all_recipes()}
    covered = sum(1 for p in result.policies if p.policy_id in supported)
    lines.append(
        f"  Recipes available for {covered} of {len(result.policies)} policies "
        f"({len(supported)} recipes total). Coverage is intentionally partial."
    )

    if not args.no_save:
        try:
            path = save_snapshot(Snapshot(policies=result.policies, captured_at=_now()), cache_dir)
            lines.append(f"  Snapshot saved: {path}")
        except CacheError as exc:
            # Not fatal to the artifacts already produced, but it does mean the
            # next run has no baseline and will silently report no changes.
            lines.append(f"  WARNING: {exc}")
            lines.append(
                "  The baseline was not updated, so the next run cannot detect policy changes."
            )
            degraded = True
    return lines, degraded


def cmd_policies(args: argparse.Namespace, provider: Provider) -> int:
    if args.catalog is None:
        print(f"error: --catalog is required. {provider.catalog_export_hint}", file=sys.stderr)
        return 2
    try:
        result = JsonFileSource(policies_path=args.catalog).load()
    except SourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    lines, degraded = _catalog_report(result, args, provider)
    _emit(lines)

    if args.unsupported:
        supported = {r.policy_id for r in provider.all_recipes()}
        missing = [p for p in result.policies if p.policy_id not in supported]
        print(f"\n{len(missing)} policy/policies without a recipe:")
        for policy in sorted(missing, key=lambda p: (p.category, p.title)):
            print(f"  [{policy.category or 'uncategorized'}] {policy.title}")

    _report_load(result)
    return 5 if degraded else 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def _no_recipes_to_verify(provider: Provider) -> bool:
    """Report that this cloud has no recipes yet, and whether that ends the axis.

    Each axis iterates the recipe set, so a provider with an empty one passed every
    axis and printed "All 0 recipe(s) match the current Azure API definitions" --
    a sentence indistinguishable from a real pass, on a check that examined nothing.
    That is the false-negative shape this tool exists to avoid, and it is not
    hypothetical: a new provider *starts* with zero recipes, and the drift canary
    would have reported green for it until the first recipe landed.

    Reported rather than made an error. Zero recipes is the correct, expected state
    for a provider under construction, so failing would mean a cloud cannot be added
    incrementally. What it must not do is claim a pass.
    """
    if provider.all_recipes():
        return False
    print(
        f"  --   nothing to check: {provider.command} ships no recipes yet, so this "
        f"axis examined nothing.\n"
        f"       This is not a pass. It is reported on every axis so a green run "
        f"cannot be read as verified coverage."
    )
    return True


def _verify_hcl_axis(args: argparse.Namespace, provider: Provider) -> int:
    """Check every recipe's HCL target against the provider schema.

    Reported as a second section of ``verify`` rather than a separate command,
    because "is this recipe still correct" is one question with two halves that rot
    independently: AWS can leave ``UpdateTable`` untouched while the ``hashicorp/aws``
    provider renames an argument. A user who ran only one half would have checked
    only one of the two artifacts the tool emits.

    Returns the exit code for this axis alone; the caller returns it when the API
    axis passed. Exit 7 is specific to HCL drift so a canary can tell the two halves
    apart from the exit code without parsing output, and exit 4 is shared with the
    API axis because "the check could not run" needs the same response either way.
    """
    if not provider.tf_provider_source:
        return 0  # cloud has no HCL generation; nothing to check

    recipes = provider.all_recipes()
    with_hcl = [r for r in recipes if r.hcl is not None]
    path = find_schema_path(getattr(args, "provider_schema", None))

    print(f"HCL: checking {len(with_hcl)} recipe(s) against the provider schema.")
    if _no_recipes_to_verify(provider):
        return 0
    if path is None:
        # The ordinary case for a user who has never generated a schema. Reported,
        # and exit-code-neutral: making it fail would mean `verify` cannot pass
        # without a 19 MB artifact most users have no reason to produce. What it must
        # not do is stay silent, or a reader would take a clean run as "both halves
        # checked".
        print(
            f"  ?    not checked -- no provider schema available.\n"
            f"       To check the HCL half, generate one in a workspace that requires\n"
            f"       {provider.tf_provider_source}:\n"
            f"         tofu providers schema -json > schema.json\n"
            f"       then re-run with --provider-schema schema.json (or set "
            f"{SCHEMA_ENV_VAR}).\n"
        )
        return 0

    try:
        schema = load_provider_schema(path, source_prefix=provider.tf_provider_source)
    except SchemaSourceError as exc:
        # A schema was named, so the check was explicitly requested. An unusable one
        # is an error, not a downgrade to unchecked -- otherwise a canary pointed at
        # a stale path reports green forever.
        print(f"  FAIL schema unusable: {exc}\n", file=sys.stderr)
        return 4

    print(f"Schema source: {path} ({schema.source}, {len(schema.resources)} resource types)\n")
    results = verify_all_hcl(tuple(with_hcl), schema)
    failures = [r for r in results if r.status.is_failure]
    deprecated = [r for r in results if r.status is SchemaStatus.DEPRECATED]

    for res in results:
        mark = (
            "ok  " if res.ok and not res.issues else ("FAIL" if res.status.is_failure else "warn")
        )
        print(f"  {mark} {res.resource_type:<34} {res.status.value}")
        for issue in res.issues:
            print(f"       {issue.status.value}: {issue.detail}")
        if res.issues:
            print(f"       policy: {res.policy_title}")

    print()
    if failures:
        print(
            f"{len(failures)} recipe(s) disagree with the {provider.tf_provider_source} "
            f"schema. The .tf artifacts they produce may be rejected by the provider, "
            f"or may propose changes nobody asked for. Do not generate until fixed."
        )
        return 7
    if deprecated:
        print(
            f"{len(deprecated)} recipe(s) use arguments marked deprecated. Still valid "
            f"today; plan for their removal."
        )
    else:
        print(f"All {len(results)} HCL target(s) match the current provider schema.")
    return 0


def _verify_cli_axis(provider: Provider) -> int:
    """Check every recipe's console command against that CLI's own flag surface.

    The third axis. ``verify_recipes`` checks the API model; this checks the command
    string the artifact actually contains, which is a different thing the CLI is free
    to change on its own -- see :mod:`remgen.providers.aws.cli_surface`.

    Exit 8 on failure, distinct from ``3`` and ``7`` for the same reason those are
    distinct from each other: the axes rot independently, are fixed in different
    places, and a canary should be able to say which one moved without parsing output.
    That argument is what later added ``9`` for the policy axis rather than folding it
    in here -- see :func:`_verify_policy_axis`.
    """
    if provider.verify_cli_surface is None:
        # Said out loud rather than returned silently. `Provider` documents this case
        # as "reported as not run", and it previously printed nothing at all -- so
        # `verify` output showed two axes where the command documents three, and a
        # reader counting sections would not know the third had been skipped rather
        # than passed.
        print(
            f"CLI: not checked -- {provider.command} has no CLI-surface verifier yet.\n"
            f"  --   This axis did not run. It is one of four, and a clean run of the "
            f"other three does not cover it."
        )
        return 0

    recipes = provider.all_recipes()
    source = (
        provider.describe_cli_surface_source()
        if provider.describe_cli_surface_source
        else "unknown"
    )
    print(
        f"CLI: checking {len(recipes)} recipe(s) against the {provider.display_name} CLI surface."
    )
    print(f"Flag source: {source}\n")
    # Before calling the verifier, for the same reason as the API axis.
    if _no_recipes_to_verify(provider):
        return 0
    results = provider.verify_cli_surface(recipes)

    failures = 0
    unavailable = 0
    for ok, checked, label, detail in results:
        if not checked:
            mark, note = "?   ", detail
            unavailable += 1
        elif ok:
            mark, note = "ok  ", "flags accepted"
        else:
            mark, note = "FAIL", detail
            failures += 1
        print(f"  {mark} {label:<34} {note}")

    print()
    if unavailable:
        print(
            f"{unavailable} recipe(s) could not be checked against the CLI surface. "
            f"A check that did not run is not a check that passed."
        )
        return 4
    if failures:
        print(
            f"{failures} recipe(s) render a command the {provider.display_name} CLI no "
            f"longer accepts. The generated scripts would fail when run."
        )
        return 8
    print(f"All {len(results)} recipe(s) render commands the CLI accepts.")
    return 0


def _verify_api_axis(provider: Provider) -> int:
    """Check every recipe's API operation and parameters against the service models."""
    recipes = provider.all_recipes()
    source = provider.describe_model_source()

    print(f"Verifying {len(recipes)} recipe(s) against {provider.display_name} service models.")
    print(f"Model source: {source}\n")
    # Before `verify_recipes`, not after: a provider under construction is entitled to
    # have no verifier yet, and calling one to hand it an empty tuple would make the
    # axis fail on a cloud that has nothing to verify.
    if _no_recipes_to_verify(provider):
        return 0
    results = provider.verify_recipes(recipes)

    failures = 0
    unavailable = 0
    for res in results:
        if res.ok:
            mark, note = "ok  ", f"api {res.api_version}"
        elif not res.checked:
            mark, note = "?   ", res.detail
            unavailable += 1
        else:
            mark, note = "FAIL", res.detail
            failures += 1
        target = f"{res.service}.{res.operation}"
        print(f"  {mark} {target:<34} {note}")
        if res.checked and not res.ok:
            print(f"       policy: {res.policy_title}")

    print()
    if unavailable:
        # An unrunnable check is reported as unrunnable, never as a pass.
        print(
            f"{unavailable} recipe(s) could not be checked: no "
            f"{provider.display_name} service models found."
        )
        if provider.models_unavailable_hint:
            print(provider.models_unavailable_hint)
        return 4
    if failures:
        print(
            f"{failures} recipe(s) no longer match the {provider.display_name} API. "
            f"Do not generate until fixed."
        )
        return 3
    print(
        f"All {len(results)} recipe(s) match the current {provider.display_name} API definitions."
    )
    return 0


def _verify_policy_axis(args: argparse.Namespace, provider: Provider) -> int:
    """Check that every recipe's policy id still exists in the Tenable catalog.

    The fourth axis, and the only one whose upstream is Tenable rather than the cloud.
    It closes a **false negative** the other three cannot see: a recipe whose API call,
    provider arguments and CLI flags all verify perfectly is still dead if the policy id
    it is keyed to has been retired, because no export will ever contain that id again.
    Nothing fails, nothing warns, and the recipe silently matches zero findings -- the
    one failure mode that looks exactly like a clean estate.

    Runs only when given a catalog export. There is deliberately no live Tenable adapter
    in this project (see :mod:`remgen.core.sources`), so this axis has no way to fetch
    one, and an axis that invented a catalog would be worse than one that abstains.
    Without ``--catalog`` it reports "not run" and returns 0, matching how the HCL axis
    behaves without ``--provider-schema``: the axis did not run, and the run says so
    rather than counting silence as a pass.

    Exit 9 on drift, distinct from 3/7/8 for the same reason those differ from each
    other -- a canary should name which upstream moved without parsing output, and this
    one is fixed by re-triaging a policy rather than by editing a command.
    """
    recipes = provider.all_recipes()
    catalog_path = getattr(args, "catalog", None)

    print(f"Policies: checking {len(recipes)} recipe(s) against the policy catalog.")
    if catalog_path is None:
        print(
            "  --   not checked -- no --catalog given, and this tool has no live "
            "Tenable adapter\n"
            "       to fetch one. This axis did NOT run: a retired policy id would "
            "not be\n"
            f"       reported. {provider.catalog_export_hint}"
        )
        return 0

    try:
        result = JsonFileSource(policies_path=catalog_path).load()
    except SourceError as exc:
        # Unreadable input is "could not check", not "checked and passed". Exit 4 for
        # the same reason the other axes use it: a blind canary must not read green.
        print(f"  ?    could not read {catalog_path}: {exc}")
        return 4

    print(f"Catalog: {catalog_path} ({len(result.policies)} policy/policies)\n")
    if _no_recipes_to_verify(provider):
        return 0
    if not result.policies:
        # An export that parsed to nothing would mark every recipe as retired, which is
        # a wrong answer with high confidence -- the worst kind. It means the export is
        # empty or the wrong shape, so it is reported as unrunnable.
        print(
            f"  ?    the catalog parsed to zero policies, so every recipe would look "
            f"retired.\n"
            f"       Treated as 'could not check' rather than as {len(recipes)} retired "
            f"policies."
        )
        return 4

    live = {p.policy_id: p for p in result.policies}
    missing = 0
    renamed = 0
    # Printed before the per-recipe verdicts, not after, because a rejected record is
    # the one thing that turns this axis into a false positive: a policy the loader
    # could not parse is absent from `live` and reads as retired. The rejections are
    # named so a FAIL below is explainable rather than mysterious.
    if result.rejections:
        print(
            f"  !    {len(result.rejections)} catalog record(s) were rejected by the "
            f"loader and are\n"
            f"       absent from the comparison below, so a policy among them would be "
            f"reported\n"
            f"       as retired. Check these before acting on any FAIL:"
        )
        for rejection in result.rejections[:20]:
            print(f"         [record {rejection.index}] {_clip(rejection.reason)}")
        if len(result.rejections) > 20:
            print(f"         ... and {len(result.rejections) - 20} more")
        print()
    for recipe in recipes:
        policy = live.get(recipe.policy_id)
        if policy is None:
            missing += 1
            mark, note = "FAIL", "not in the catalog -- retired, or the wrong cloud's export"
        elif policy.title != recipe.policy_title:
            # Not a failure. A retitled policy still matches findings, so the recipe
            # works; what breaks is the artifact's own label, which is what a reviewer
            # reads to decide whether to apply it. Reported so it gets corrected, and
            # kept out of the exit code so it cannot mask a retirement.
            renamed += 1
            mark, note = "warn", f"title upstream is now {policy.title!r}"
        else:
            mark, note = "ok  ", "in the catalog"
        print(f"  {mark} {recipe.policy_id:<38} {note}")

    print()
    if renamed:
        print(
            f"{renamed} recipe(s) carry a title the catalog has since changed. The "
            f"remediation still applies; the label in generated artifacts is stale."
        )
    if missing == len(recipes):
        # Every single recipe missing against a catalog that *did* contain policies is
        # the signature of the wrong export -- running `awsremgen verify` with the Azure
        # catalog produces exactly this. Found by doing it. Reporting 9 there would be a
        # confident wrong answer whose stated fix (re-triage every recipe) is unrelated
        # to the actual one (pass the other file), so it is downgraded to "could not
        # check": the two causes are indistinguishable from this data, and 4 says so
        # while still outranking every other axis.
        #
        # For a cloud with exactly one recipe this also catches a genuine single
        # retirement, reporting 4 where 9 would be right. Accepted: the two are
        # *identical* in that case, so no rule could separate them, and the message
        # names re-triage as one of the two possibilities. It is still not a pass.
        print(
            f"None of the {len(recipes)} recipe(s) appear in this catalog, which "
            f"contains {len(result.policies)}.\n"
            f"Either this is the wrong cloud's export, or every recipe was retired at "
            f"once. Those\n"
            f"cannot be told apart from here, so this is reported as 'could not check' "
            f"rather than\n"
            f"as {len(recipes)} retirements. Confirm the export is "
            f"{provider.display_name}'s, then re-run."
        )
        return 4
    if missing:
        print(
            f"{missing} recipe(s) are keyed to a policy id the catalog no longer "
            f"contains. Those recipes match nothing and will never fire again -- a "
            f"silent gap, not an error anyone would see. Re-triage them."
        )
        return 9
    print(f"All {len(recipes)} recipe(s) are keyed to a policy that still exists.")
    return 0


def cmd_verify(args: argparse.Namespace, provider: Provider) -> int:
    """Check every recipe against all four upstreams it depends on.

    All four axes always run, even when an earlier one has already failed. An
    early return would have been simpler, and wrong for the two callers that matter:
    a maintainer fixing drift wants every problem in one pass rather than discovering
    the next one after each fix, and the drift canary reports on all four signals
    from a single run -- with an early return it could only ever see the first broken
    one, so a provider rename would stay hidden behind an unrelated API change for as
    long as that took to fix.

    Three of the four axes ask a cloud whether the remediation is still correct. The
    fourth asks Tenable whether the *finding* still exists, which is the half none of
    the others can see: a recipe keyed to a retired policy id verifies perfectly on all
    three cloud axes and matches nothing forever.

    One process has one exit code, so when several axes fail the most urgent wins:
    API drift (3) over HCL drift (7) over CLI drift (8) over a retired policy (9),
    because a wrong API call is what runs against live infrastructure while a retired
    policy only means a recipe never fires. "Could not check" (4) outranks all of them
    -- a blind canary is worse than a red one, since it reports nothing at all.
    """
    api_code = _verify_api_axis(provider)
    print()
    hcl_code = _verify_hcl_axis(args, provider)
    print()
    cli_code = _verify_cli_axis(provider)
    print()
    policy_code = _verify_policy_axis(args, provider)

    failed = {c for c in (api_code, hcl_code, cli_code, policy_code) if c != 0}
    # Explicit precedence rather than `min`, which would give the same answer today
    # only because 3 < 7 < 8 < 9 -- an accident of numbering that a new code could
    # break silently. 4 leads: an axis that could not run makes every other verdict
    # incomplete, and is what must be fixed before the rest can be trusted.
    for code in (4, 3, 7, 8, 9):
        if code in failed:
            return code
    # Any other non-zero code means an axis returned something undocumented, which is
    # a defect in this function's contract rather than a verdict about a recipe.
    return next(iter(failed), 0)


# ---------------------------------------------------------------------------
# recipes
# ---------------------------------------------------------------------------


def cmd_recipes(args: argparse.Namespace, provider: Provider) -> int:
    recipes = provider.all_recipes()
    print(f"{len(recipes)} curated recipe(s). Coverage is intentionally partial.\n")
    for tier in (SafetyTier.SAFEST, SafetyTier.CAUTION, SafetyTier.DISRUPTIVE):
        in_tier = [r for r in recipes if r.safety_tier is tier]
        if not in_tier:
            continue
        print(f"{tier.value.upper()} ({len(in_tier)})")
        for recipe in in_tier:
            print(f"  {recipe.policy_title}")
            print(f"    policy   {recipe.policy_id}")
            print(f"    api      {recipe.api.service}.{recipe.api.operation}")
            print(f"    hcl      {recipe.hcl.resource_type if recipe.hcl else '(none)'}")
            for note in recipe.safety_notes:
                print(f"    ! {note}")
        print()
    print("Default 'generate' emits SAFEST only; use --safety-level to include more.")
    return 0


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------


def build_parser(provider: Provider) -> argparse.ArgumentParser:
    """Build the parser for one cloud's command.

    Every user-visible string that names a cloud or a command comes from
    ``provider``, so ``--help`` describes the command the user actually typed and a
    copied example runs as written.
    """
    parser = argparse.ArgumentParser(
        prog=provider.command,
        description=(
            f"Generate reviewable {provider.display_name} remediation artifacts from "
            f"Tenable Cloud Security findings. Curated, best-effort, and "
            f"safety-tiered. Never modifies {provider.display_name}."
        ),
        epilog=_EPILOG.format(command=provider.command, display=provider.display_name),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{provider.command} {__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_cache_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--cache-dir",
            type=Path,
            default=None,
            metavar="DIR",
            help=f"where to store the policy-catalog snapshot (default: {default_cache_dir()})",
        )
        p.add_argument(
            "--no-save",
            action="store_true",
            help="do not update the snapshot (useful in CI, or for a dry comparison)",
        )

    noun = provider.credential_scope_noun
    gen = sub.add_parser(
        "generate",
        help="generate remediation artifacts from findings",
        # No indefinite article before the cloud name. "a AWS" and "a Azure" were both
        # wrong, and an `a`/`an` rule keyed on the first letter is wrong too -- it
        # depends on pronunciation, not spelling, so it would produce "an GCP" for a
        # cloud whose name is read as letters. Rephrasing so no article is needed is
        # correct for every cloud, including ones not added yet.
        description=(
            f"Generate remediation artifacts for {provider.display_name}: a CLI script "
            f"and import-aware OpenTofu/Terraform HCL."
        ),
    )
    gen.add_argument(
        "--findings",
        type=Path,
        required=True,
        metavar="FILE",
        help="JSON file of findings (array, or object with a 'findings' array)",
    )
    gen.add_argument(
        "--out",
        type=Path,
        default=Path("./artifacts"),
        metavar="DIR",
        help="output directory (default: ./artifacts)",
    )
    gen.add_argument(
        "--format",
        default="all",
        metavar="LIST",
        help=(
            "which output formats to write, comma-separated: cli (the "
            f"{provider.display_name} CLI as a shell script), hcl "
            "(import-aware OpenTofu/Terraform configuration), or all "
            "(default). Both are written by default because they serve different "
            "situations: the script for a one-off fix, the HCL for resources already "
            "under IaC. Choosing 'hcl' alone omits policies that have no IaC "
            "equivalent; the count is reported."
        ),
    )
    gen.add_argument(
        "--safety-level",
        choices=tuple(_LEVELS),
        default="safest",
        help=(
            "the most risk to accept; each level includes the safer ones. safest "
            "(default): reversible, no data-path impact, no usage-scaled cost. "
            "caution: also irreversible or cost-scaled changes. all: also changes "
            "that can affect availability."
        ),
    )
    gen.add_argument(
        "--catalog",
        type=Path,
        default=None,
        metavar="FILE",
        help="optional policy catalog JSON; enables new-policy detection this run",
    )
    gen.add_argument(
        "--max-per-file",
        type=int,
        default=DEFAULT_MAX_PER_FILE,
        metavar="N",
        help=(
            "soft cap on remediations per output file, for reviewability "
            f"(default: {DEFAULT_MAX_PER_FILE}; 0 disables size-based splitting). "
            f"Output is always split by cloud and by {noun}, "
            # Whether HCL splits regionally is a per-provider fact, and so is the
            # word for it. Hardcoding "and HCL also by region" told an Azure user
            # their .tf files were split by something they are not -- with the wrong
            # noun -- which is worse than saying nothing, because it describes a
            # split they will look for in the filenames and not find.
            + (
                f"and HCL also by {provider.region_noun}, "
                if provider.hcl_provider_is_region_scoped
                else ""
            )
            + f"because neither format can target more than one {noun} at a time -- "
            "that split is not affected by this flag."
        ),
    )
    gen.add_argument(
        "--strict",
        action="store_true",
        help=(
            "exit 5 if any input record was rejected, instead of 0. For unattended "
            "runs: rejections always print, but a scheduler reading only the exit "
            "code cannot otherwise tell a run that dropped half its input from a "
            "clean one. Findings with no curated recipe are not rejections and do "
            "not trigger this -- partial coverage is the normal state of a curated "
            "catalog."
        ),
    )
    gen.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="list unsupported policy ids and every output file",
    )
    add_cache_args(gen)
    gen.set_defaults(func=cmd_generate)

    pol = sub.add_parser(
        "policies",
        help="show catalog coverage and what changed since the last run",
        description="Diff the policy catalog against the cached snapshot.",
    )
    pol.add_argument(
        "--catalog", type=Path, required=True, metavar="FILE", help="policy catalog JSON"
    )
    pol.add_argument("--unsupported", action="store_true", help="list every policy with no recipe")
    add_cache_args(pol)
    pol.set_defaults(func=cmd_policies)

    ver = sub.add_parser(
        "verify",
        help=f"check recipes against the current {provider.display_name} service models",
        description=(
            f"Verify that every recipe still matches upstream, on all four axes: the "
            f"API operation and parameters against the {provider.display_name} service "
            f"models; each HCL target's resource type and arguments against the "
            f"Terraform/OpenTofu provider schema; each rendered command's subcommand "
            f"and flags against the CLI's own flag surface; and each recipe's policy id "
            f"against the Tenable policy catalog. The four rot independently -- a "
            f"renamed CLI flag or provider argument breaks a shipped artifact while the "
            f"API operation is untouched, and a retired policy id breaks nothing at all "
            f"while silently matching zero findings -- so all four always run and all "
            f"four are reported. Exit code names the most urgent: 4 an axis could not "
            f"run, 3 API drift, 7 provider-schema drift, 8 CLI-flag drift, 9 a recipe "
            f"keyed to a retired policy. Run this before trusting generated output."
        ),
    )
    ver.add_argument(
        "--provider-schema",
        type=Path,
        metavar="FILE",
        help=(
            "output of `tofu providers schema -json`, used to check the HCL half. "
            f"Defaults to ${SCHEMA_ENV_VAR}. Without it the HCL check is reported as "
            "not run rather than as passing. Generating it needs a workspace that has "
            "downloaded the provider, which is why this tool does not do it for you."
        ),
    )
    ver.add_argument(
        "--catalog",
        type=Path,
        metavar="FILE",
        help=(
            "policy catalog JSON, used to check that each recipe's policy id still "
            "exists upstream. Optional here and required by `policies`, because this "
            "tool has no live Tenable adapter and so cannot fetch one; without it the "
            "policy check is reported as not run rather than as passing. "
            f"{provider.catalog_export_hint}"
        ),
    )
    ver.set_defaults(func=cmd_verify)

    rec = sub.add_parser(
        "recipes",
        help="list the curated recipes and their safety classification",
    )
    rec.set_defaults(func=cmd_recipes)

    return parser


def main(provider: Provider, argv: list[str] | None = None) -> int:
    """Run one cloud's command. Each provider's console script calls this."""
    parser = build_parser(provider)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args, provider))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except SourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except CacheError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        # Backstop for filesystem conditions the subcommands do not anticipate
        # (full disk, revoked permission mid-run, a vanished path). An operator
        # gets a message and a usable exit code instead of a traceback.
        print(f"error: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "DriftStatus",
    "build_parser",
    "cmd_generate",
    "cmd_policies",
    "cmd_recipes",
    "cmd_verify",
    "estimate_output_bytes",
    "main",
]
