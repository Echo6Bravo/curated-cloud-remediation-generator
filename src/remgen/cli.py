"""Command-line interface.

Four subcommands:

* ``generate`` -- turn findings into remediation artifacts. The main command.
* ``policies`` -- show the policy catalog, what is supported, and what changed.
* ``verify``   -- check every recipe against the current AWS service models.
* ``recipes``  -- show the curated recipe set and its safety classification.

Safety posture of this interface:

* Nothing here calls AWS or Tenable. There is no ``--apply``. The tool writes
  files; the user runs them. That boundary is the point, so it is not
  configurable.
* ``generate`` emits only ``SAFEST``-tier remediations unless the user opts in
  with ``--tier``. When remediations are withheld, the count and the exact flag
  to include them are printed -- a silent cap would read as "nothing else to do".
* Every run reports what it *could not* do: findings with no recipe, records that
  failed validation, and recipes whose API contract could not be verified.
* Output is split per account, and for HCL per region, because neither format can
  target more than one AWS account at a time. That split is a correctness
  requirement rather than an ergonomic one; see :mod:`remgen.layout`.

Exit codes, so a scheduler can branch on them:

* ``0`` -- success.
* ``2`` -- usage or input error (bad arguments, unreadable input, unwritable output).
* ``3`` -- a recipe no longer matches the AWS service model. Nothing was generated.
* ``4`` -- recipes could not be verified at all (no AWS service models available).
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

from remgen import __version__, drift
from remgen.artifacts import render_manifest, render_readme
from remgen.catalog import (
    BaselineState,
    CacheError,
    Snapshot,
    default_cache_dir,
    diff_catalog,
    load_snapshot,
    save_snapshot,
)
from remgen.generators import render_cli_script, render_hcl
from remgen.layout import (
    DEFAULT_MAX_PER_FILE,
    Format,
    describe_layout,
    plan_units,
)
from remgen.model import Finding, Recipe, SafetyTier
from remgen.recipes import all_recipes, get
from remgen.sources import JsonFileSource, LoadResult, SourceError

_TIER_ORDER = {SafetyTier.SAFEST: 0, SafetyTier.CAUTION: 1, SafetyTier.DISRUPTIVE: 2}

_EPILOG = """\
examples:
  # See what is supported before doing anything
  remgen recipes

  # Confirm every recipe still matches the current AWS API definitions
  remgen verify

  # Generate remediations from an exported findings file
  remgen generate --findings findings.json --out ./artifacts

  # Include remediations that carry a commitment (irreversible, cost-scaled)
  remgen generate --findings findings.json --out ./artifacts --tier caution

  # Track catalog changes; new policies are reported, never auto-remediated
  remgen policies --catalog policies.json

This tool never modifies AWS. It writes files for you to review and run.
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


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------


def _dedupe(
    findings: tuple[Finding, ...],
) -> tuple[tuple[Finding, ...], int]:
    """Collapse findings identical in policy, resource, region and account.

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
    findings: tuple[Finding, ...],
) -> tuple[list[tuple[Recipe, Finding]], list[Finding]]:
    """Split findings into those with a recipe and those without."""
    matched: list[tuple[Recipe, Finding]] = []
    unmatched: list[Finding] = []
    for finding in findings:
        recipe = get(finding.policy_id)
        if recipe is None:
            unmatched.append(finding)
        else:
            matched.append((recipe, finding))
    matched.sort(
        key=lambda p: (
            _TIER_ORDER[p[0].safety_tier],
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
_BYTES_PER_REMEDIATION = {Format.AWSCLI: 338, Format.HCL: 975}


def _human_bytes(count: int) -> str:
    """Format a byte count for a summary line."""
    if count < 1024:
        return f"{count} B"
    for unit, scale in (("KB", 1024), ("MB", 1024**2), ("GB", 1024**3)):
        if count < scale * 1024 or unit == "GB":
            return f"{count / scale:.1f} {unit}"
    return f"{count} B"  # pragma: no cover -- unreachable, GB branch is terminal


def estimate_output_bytes(count: int) -> int:
    """Estimate total output size for ``count`` remediations, across both formats.

    Cheap on purpose: a multiplication, not a trial render. It exists so a run that
    is about to produce hundreds of megabytes says so up front rather than after the
    fact, which is when a surprised user has already waited for it.
    """
    return count * sum(_BYTES_PER_REMEDIATION.values())


def _report_load(result: LoadResult) -> None:
    """Print anything the loader could not use."""
    if not result.rejections:
        return
    print(f"\n{len(result.rejections)} input record(s) were rejected and not remediated:")
    for rejection in result.rejections[:20]:
        print(f"  [record {rejection.index}] {_clip(rejection.reason)}")
    if len(result.rejections) > 20:
        print(f"  ... and {len(result.rejections) - 20} more")


def cmd_generate(args: argparse.Namespace) -> int:
    if args.max_per_file < 0:
        print("error: --max-per-file must be 0 or greater", file=sys.stderr)
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
    matched, unmatched = _pair_findings(unique_findings)

    # Verify the API contract before emitting anything that relies on it. A
    # recipe whose operation has changed shape must not be rendered as if valid.
    drift_results = {r.policy_id: r for r in drift.verify_all(all_recipes())}
    bad = {
        pid
        for pid, res in drift_results.items()
        if res.status not in (drift.DriftStatus.OK, drift.DriftStatus.UNAVAILABLE)
    }
    if bad:
        print(
            f"\nerror: {len(bad)} recipe(s) no longer match the AWS service model. "
            f"Refusing to generate. Run 'remgen verify' for detail.",
            file=sys.stderr,
        )
        return 3
    unverified = [
        res for res in drift_results.values() if res.status is drift.DriftStatus.UNAVAILABLE
    ]

    allowed = {SafetyTier.SAFEST}
    if args.tier == "caution":
        allowed.add(SafetyTier.CAUTION)
    elif args.tier == "all":
        allowed |= {SafetyTier.CAUTION, SafetyTier.DISRUPTIVE}

    selected = [(r, f) for r, f in matched if r.safety_tier in allowed]
    withheld = [(r, f) for r, f in matched if r.safety_tier not in allowed]

    # Forecast size before doing the work, so a run that will produce hundreds of
    # megabytes says so now rather than after the user has waited for it. Warn only
    # past a threshold; an unconditional size line is noise on a normal run.
    forecast = estimate_output_bytes(len(selected))
    if forecast > 50 * 1024**2:
        print(
            f"\n  Note: {len(selected)} remediations will produce roughly "
            f"{_human_bytes(forecast)} across both formats.\n"
            f"  Most of that is the per-remediation comment header. Narrow the input "
            f"or lower\n  --max-per-file if you want smaller files to review."
        )

    out_dir: Path = args.out
    generated_at = _now()

    # Output is split by scope before rendering. Account is a hard boundary for
    # both formats and region is a hard boundary for HCL, because neither an
    # ambient-credential shell script nor an AWS provider configuration can
    # address more than one account at a time. See remgen.layout.
    cli_units = plan_units(selected, Format.AWSCLI, max_per_file=args.max_per_file)
    hcl_units = plan_units(
        [(r, f) for r, f in selected if r.hcl is not None],
        Format.HCL,
        max_per_file=args.max_per_file,
    )

    # Rendering is pure, so do it before touching the filesystem: a template error
    # then fails without having written a half-populated output directory.
    # (filename, text, make_executable) -- the companion files below are not tied to
    # a single output unit, so the write loop keys off names rather than units.
    rendered: list[tuple[str, str, bool]] = [
        (
            unit.filename,
            render_cli_script(
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
            unit.filename,
            render_hcl(
                list(unit.pairs),
                version=__version__,
                generated_at=generated_at,
                unit=unit,
            ),
            False,
        )
        for unit in hcl_units
    )

    # The shared instructions and the index, written once per run rather than
    # repeated in every artifact. See remgen.artifacts for why.
    all_units = cli_units + hcl_units
    if all_units:
        rendered.append(
            (
                "README.md",
                render_readme(
                    all_units,
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
                    all_units, version=__version__, generated_at=generated_at
                ),
                False,
            )
        )

    written: list[tuple[Path, int]] = []
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, text, executable in rendered:
            path = out_dir / name
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
    print(f"\nremgen {__version__} -- generated {generated_at}")
    print(f"\n  Records read:         {total_in}")
    print(f"    usable findings:    {len(result.findings)}")
    if result.rejections:
        print(f"    rejected:           {len(result.rejections)}")
    if duplicates:
        print(f"    duplicates merged:  {duplicates}")
        print(f"    distinct findings:  {len(unique_findings)}")
    print(f"  Remediations written: {len(selected)}")
    if withheld:
        print(f"    withheld by tier:   {len(withheld)}")
    if unmatched:
        print(f"    no recipe:          {len(unmatched)}")
    total_bytes = sum(size for _, size in written)
    print(f"\n  Output: {out_dir}  ({len(written)} file(s), {_human_bytes(total_bytes)})")
    _emit(describe_layout(cli_units))
    _emit(describe_layout(hcl_units))
    if written and (args.verbose or len(written) <= 8):
        for path, size in written:
            print(f"    {path.name}  ({_human_bytes(size)})")
    elif written:
        print(f"    (use -v to list all {len(written)} files)")

    incomplete = [r for r, _ in selected if r.hcl is not None and not r.hcl.is_complete]
    if incomplete:
        print(
            f"\n  Note: {len(incomplete)} HCL block(s) contain TODO placeholders for "
            f"provider-required\n  arguments that findings do not carry. Complete them "
            f"before applying."
        )

    if withheld:
        by_tier: dict[SafetyTier, int] = {}
        for recipe, _ in withheld:
            by_tier[recipe.safety_tier] = by_tier.get(recipe.safety_tier, 0) + 1
        ordered = sorted(by_tier.items(), key=lambda kv: _TIER_ORDER[kv[0]])
        detail = ", ".join(f"{n} {t.value}" for t, n in ordered)
        print(f"\n  Withheld by safety tier: {len(withheld)} ({detail})")
        print(f"  These are excluded because --tier is '{args.tier}'. To include them:")
        print("    --tier caution   reversible-with-commitment, or cost-scaled changes")
        print("    --tier all       also includes changes that can affect availability")

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
            f"AWS\n  service model ({unverified[0].detail})"
        )

    _report_load(result)

    degraded = False
    if result.policies:
        lines, degraded = _catalog_report(result, args)
        _emit(lines)

    print("\nReview both files before running anything. This tool made no AWS changes.")
    # The artifacts were written, so this is not a failure -- but the catalog
    # change detection did not run, and a scheduler must be able to see that.
    return 5 if degraded else 0


# ---------------------------------------------------------------------------
# policies
# ---------------------------------------------------------------------------


def _catalog_report(
    result: LoadResult, args: argparse.Namespace
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

    supported = {r.policy_id for r in all_recipes()}
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


def cmd_policies(args: argparse.Namespace) -> int:
    if args.catalog is None:
        print(
            "error: --catalog is required. Export the AWS policy catalog from Tenable\n"
            "Cloud Security as JSON (an array of {id, title, category} objects).",
            file=sys.stderr,
        )
        return 2
    try:
        result = JsonFileSource(policies_path=args.catalog).load()
    except SourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    lines, degraded = _catalog_report(result, args)
    _emit(lines)

    if args.unsupported:
        supported = {r.policy_id for r in all_recipes()}
        missing = [p for p in result.policies if p.policy_id not in supported]
        print(f"\n{len(missing)} policy/policies without a recipe:")
        for policy in sorted(missing, key=lambda p: (p.category, p.title)):
            print(f"  [{policy.category or 'uncategorized'}] {policy.title}")

    _report_load(result)
    return 5 if degraded else 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    recipes = all_recipes()
    results = drift.verify_all(recipes)
    source = drift.model_source_description()

    print(f"Verifying {len(recipes)} recipe(s) against AWS service models.")
    print(f"Model source: {source}\n")

    failures = 0
    unavailable = 0
    for res in results:
        if res.status is drift.DriftStatus.OK:
            mark, note = "ok  ", f"api {res.api_version}"
        elif res.status is drift.DriftStatus.UNAVAILABLE:
            mark, note = "?   ", res.detail
            unavailable += 1
        else:
            mark, note = "FAIL", res.detail
            failures += 1
        target = f"{res.service}.{res.operation}"
        print(f"  {mark} {target:<34} {note}")
        if res.status not in (drift.DriftStatus.OK, drift.DriftStatus.UNAVAILABLE):
            print(f"       policy: {res.policy_title}")

    print()
    if unavailable:
        # An unrunnable check is reported as unrunnable, never as a pass.
        print(
            f"{unavailable} recipe(s) could not be checked: no AWS service models found.\n"
            "Install AWS CLI v2, or set REMGEN_BOTOCORE_DATA_DIR to a botocore data dir."
        )
        return 4
    if failures:
        print(f"{failures} recipe(s) no longer match the AWS API. Do not generate until fixed.")
        return 3
    print(f"All {len(results)} recipe(s) match the current AWS API definitions.")
    return 0


# ---------------------------------------------------------------------------
# recipes
# ---------------------------------------------------------------------------


def cmd_recipes(args: argparse.Namespace) -> int:
    recipes = all_recipes()
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
    print("Default 'generate' emits SAFEST only; use --tier to include more.")
    return 0


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="remgen",
        description=(
            "Generate reviewable AWS remediation artifacts from Tenable Cloud Security "
            "findings. Curated, best-effort, and safety-tiered. Never modifies AWS."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"remgen {__version__}")
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

    gen = sub.add_parser(
        "generate",
        help="generate remediation artifacts from findings",
        description="Generate an aws CLI script and import-aware OpenTofu/Terraform HCL.",
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
        "--tier",
        choices=("safest", "caution", "all"),
        default="safest",
        help=(
            "which safety tiers to emit. safest (default): reversible, no data-path "
            "impact, no usage-scaled cost. caution: also irreversible or cost-scaled "
            "changes. all: also changes that can affect availability."
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
            "Output is always split by account, and HCL also by region, because "
            "neither format can target more than one account at a time -- that "
            "split is not affected by this flag."
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
        help="check recipes against the current AWS service models",
        description=(
            "Verify that every recipe's API operation and parameters still exist in the "
            "AWS service models. Run this before trusting generated output."
        ),
    )
    ver.set_defaults(func=cmd_verify)

    rec = sub.add_parser(
        "recipes",
        help="list the curated recipes and their safety classification",
    )
    rec.set_defaults(func=cmd_recipes)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
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


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
