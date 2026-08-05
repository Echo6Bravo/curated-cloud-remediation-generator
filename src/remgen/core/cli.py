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
* ``5`` -- artifacts were written, but the policy-catalog change detection did not
  run (unreadable or unwritable baseline). Distinct from ``0`` because a check that
  did not run must not be reported as a check that passed.
* ``130`` -- interrupted.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

from remgen import __version__
from remgen.core.artifacts import render_manifest, render_readme
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
from remgen.core.generators import render_hcl
from remgen.core.layout import (
    DEFAULT_MAX_PER_FILE,
    Format,
    describe_layout,
    plan_units,
)
from remgen.core.model import Finding, Recipe, SafetyTier
from remgen.core.provider import Provider
from remgen.core.sources import JsonFileSource, LoadResult, SourceError

_LEVEL_ORDER = {SafetyTier.SAFEST: 0, SafetyTier.CAUTION: 1, SafetyTier.DISRUPTIVE: 2}

#: ``--safety-level`` value -> the levels it admits. Cumulative: each level includes
#: everything less risky, because "I accept irreversible changes" does not mean "and
#: not the safe ones". Declared as data so the flag's help text, the withheld-count
#: advice and the gate itself cannot disagree.
_LEVELS: dict[str, frozenset[SafetyTier]] = {
    "safest": frozenset({SafetyTier.SAFEST}),
    "caution": frozenset({SafetyTier.SAFEST, SafetyTier.CAUTION}),
    "all": frozenset(_LEVEL_ORDER),
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
            _LEVEL_ORDER[p[0].safety_tier],
            p[0].policy_title,
            p[1].account_id,
            p[1].region,
            p[1].resource_id,
        )
    )
    return matched, unmatched


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

    unique_findings, duplicates = _dedupe(result.findings)
    matched, unmatched = _pair_findings(unique_findings, provider)

    # Verify the API contract before emitting anything that relies on it. A
    # recipe whose operation has changed shape must not be rendered as if valid.
    drift_results = {
        r.policy_id: r for r in provider.verify_recipes(provider.all_recipes())
    }
    bad = {
        pid
        for pid, res in drift_results.items()
        if res.checked and not res.ok
    }
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
    rendered.extend(
        (
            unit.relative_path,
            render_hcl(
                list(unit.pairs),
                version=__version__,
                generated_at=generated_at,
                unit=unit,
                command=provider.command,
                docs_label=provider.docs_label,
                scope_block=provider.hcl_scope_block,
            ),
            False,
        )
        for unit in hcl_units
    )

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
                ),
                False,
            )
        )

    written: list[tuple[Path, int]] = []
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, text, executable in rendered:
            path = out_dir / name
            # The cloud segment means artifact paths have a parent to create. The
            # provider's cloud id is validated as a single alphanumeric segment, so
            # this cannot escape out_dir.
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
    total_in = len(result.findings) + len(result.rejections)
    print(f"\n{provider.command} {__version__} -- generated {generated_at}")
    print(f"\n  Records read:         {total_in}")
    print(f"    usable findings:    {len(result.findings)}")
    if result.rejections:
        print(f"    rejected:           {len(result.rejections)}")
    if duplicates:
        print(f"    duplicates merged:  {duplicates}")
        print(f"    distinct findings:  {len(unique_findings)}")
    print(f"  Remediations written: {len(selected)}")
    if withheld:
        print(f"    withheld by level:  {len(withheld)}")
    if unmatched:
        print(f"    no recipe:          {len(unmatched)}")
    total_bytes = sum(size for _, size in written)
    print(f"\n  Output: {out_dir}  ({len(written)} file(s), {_human_bytes(total_bytes)})")
    print(f"  Formats: {', '.join(fmt.value for fmt in formats)}")
    _emit(describe_layout(cli_units))
    _emit(describe_layout(hcl_units))
    if written and (args.verbose or len(written) <= 8):
        for path, size in written:
            print(f"    {path.name}  ({_human_bytes(size)})")
    elif written:
        print(f"    (use -v to list all {len(written)} files)")

    # Only meaningful when HCL was actually emitted: a --format cli run has no
    # resource blocks to complete, so the note would send the reader looking for
    # TODOs that are not there.
    if hcl_units:
        incomplete = [
            r for r, _ in selected if r.hcl is not None and not r.hcl.is_complete
        ]
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
        ordered = sorted(by_level.items(), key=lambda kv: _LEVEL_ORDER[kv[0]])
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
    return 5 if degraded else 0


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
    lines = ["", *diff.summary_lines()]
    degraded = state is BaselineState.UNREADABLE

    supported = {r.policy_id for r in provider.all_recipes()}
    covered = sum(1 for p in result.policies if p.policy_id in supported)
    lines.append(
        f"  Recipes available for {covered} of {len(result.policies)} policies "
        f"({len(supported)} recipes total). Coverage is intentionally partial."
    )

    if not args.no_save:
        try:
            path = save_snapshot(
                Snapshot(policies=result.policies, captured_at=_now()), cache_dir
            )
            lines.append(f"  Snapshot saved: {path}")
        except CacheError as exc:
            # Not fatal to the artifacts already produced, but it does mean the
            # next run has no baseline and will silently report no changes.
            lines.append(f"  WARNING: {exc}")
            lines.append(
                "  The baseline was not updated, so the next run cannot detect "
                "policy changes."
            )
            degraded = True
    return lines, degraded


def cmd_policies(args: argparse.Namespace, provider: Provider) -> int:
    if args.catalog is None:
        print(f"error: --catalog is required. {provider.catalog_export_hint}",
              file=sys.stderr)
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


def cmd_verify(args: argparse.Namespace, provider: Provider) -> int:
    recipes = provider.all_recipes()
    results = provider.verify_recipes(recipes)
    source = provider.describe_model_source()

    print(
        f"Verifying {len(recipes)} recipe(s) against {provider.display_name} "
        f"service models."
    )
    print(f"Model source: {source}\n")

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
        f"All {len(results)} recipe(s) match the current {provider.display_name} "
        f"API definitions."
    )
    return 0


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
        epilog=_EPILOG.format(
            command=provider.command, display=provider.display_name
        ),
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
            help="where to store the policy-catalog snapshot "
            f"(default: {default_cache_dir()})",
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
        description=(
            f"Generate a {provider.display_name} CLI script and import-aware "
            f"OpenTofu/Terraform HCL."
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
            "which output formats to write, comma-separated: cli (a "
            f"{provider.display_name} CLI shell script), hcl "
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
            f"Output is always split by cloud and by {noun}, and HCL also by region, "
            f"because neither format can target more than one {noun} at a time -- "
            "that split is not affected by this flag."
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
    pol.add_argument(
        "--unsupported", action="store_true", help="list every policy with no recipe"
    )
    add_cache_args(pol)
    pol.set_defaults(func=cmd_policies)

    ver = sub.add_parser(
        "verify",
        help=f"check recipes against the current {provider.display_name} service models",
        description=(
            f"Verify that every recipe's API operation and parameters still exist in "
            f"the {provider.display_name} service models. Run this before trusting "
            f"generated output."
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
