# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **A committed sample run under `examples/`** — the input findings, the console output verbatim,
  and every artifact produced, with [`examples/README.md`](./examples/README.md) explaining why one
  input yields five artifacts, what a `TODO` placeholder means, and what happens to a malformed
  finding. The fixture deliberately includes a duplicate record, a policy with no recipe, a
  `resource_id` carrying shell metacharacters, and a record missing its region, so the sample shows
  the rejection and reconciliation behavior rather than only the happy path.
- **CI job `sample`**, blocking, which regenerates the sample and diffs it against what is
  committed — normalizing only the generation timestamp. Documentation that claims to be real
  output is mechanically checkable, so it is checked: a sample that silently describes an older
  version is worse than none, because a reader cannot tell. The job also runs `bash -n` and real
  `tofu fmt -check` / `init` / `validate` over the committed artifacts, and executes the
  wrong-account guard against a stub `aws` to prove it exits non-zero having issued no mutating
  calls. Every check was verified with a negative control that breaks the guarded property.
- `docs-refs` now asserts the sample's files exist and resolves relative links from inside
  `examples/` (`../SECURITY.md` only resolves relative to the linking document).

### Notes
- `examples/sample-output/` is *not* named `artifacts/` because `.gitignore` matches `artifacts/` at
  any depth; that name would have committed nothing while every doc still pointed at it.

## [0.1.0] — 2026-08-04

Initial release. Pre-1.0: the CLI surface and recipe schema may still change.

### Added
- **`remgen` CLI** with four subcommands — `generate` (emit artifacts), `recipes` (list coverage
  and safety classification), `verify` (check recipes against the installed AWS service models),
  and `policies` (diff the policy catalog against a local snapshot). The tool **never modifies
  AWS**; it writes files for a human to review and run.
- **5 curated recipes**, each hand-written and individually checked against the AWS service model
  and AWS documentation: CloudTrail log-file validation (`safest`), plus DynamoDB delete
  protection, RDS delete protection, KMS automatic key rotation, and S3 bucket versioning
  (`caution`). Coverage is intentionally partial — see [ROADMAP.md](./ROADMAP.md).
- **Three-tier safety classification** (`safest` / `caution` / `all`) with `safest` as the default,
  so a default run emits only remediations that are reversible, avoid the data path, need no
  restart or replacement, and carry no usage-scaled cost. Irreversibility, cost, and reversal
  commands are emitted **inline in each artifact**, not only in the docs — a warning in a separate
  file is a warning that gets skipped.
- **Two output formats from one validated `ApiCall`** — a fail-fast `aws` CLI shell script and
  import-aware OpenTofu/Terraform HCL that adopts the existing resource rather than proposing to
  create a new one. Rendering both from the same source means they cannot disagree about what will
  happen.
- **Execution-scope safety.** Output is split per account, and HCL additionally per region, because
  neither an `aws` invocation nor an IaC provider can target more than one account at a time. A
  file spanning two accounts would resolve identifiers against whichever account the runner is
  authenticated to — a same-named resource in the wrong account could be adopted and reconfigured
  while the run reported success. Generated scripts preflight `aws sts get-caller-identity` and
  exit non-zero without running anything on a mismatch; HCL sets `allowed_account_ids`. The
  `--max-per-file` soft cap (default 500) is for reviewability and cannot relax this split.
- **Drift verification** (`remgen verify`) reads AWS service-model JSON from an installed AWS CLI
  v2 or botocore **as data files** — never importing them as a Python package — and reports when
  an operation or parameter shape no longer matches a recipe, instead of emitting a command that
  will fail.
- **Catalog diffing** (`remgen policies`) reports newly appearing policies against a cached
  snapshot. New policies are **reported, never auto-remediated**: an unreviewed policy has no
  verified recipe, and inventing one automatically is the failure this design refuses.
- **Untrusted-input handling.** Findings are validated per record; a record that fails validation
  is collected as an explicit rejection rather than dropped, so input and output counts reconcile.
  A silently discarded finding would be a missed remediation that looks like a clean run.
- **Zero required runtime dependencies** — standard library only. A tool that emits commands you
  will run against production should not carry a dependency tree.
- Project docs: `README.md`, `ROADMAP.md` (including the unresolved question of how to gate
  non-reversible remediations), `NOTICE.md` (OpenTofu MPL-2.0 / Terraform BUSL-1.1 / botocore
  Apache-2.0 analysis), `CONTRIBUTING.md`, `SECURITY.md`.
- CI running the same gates as local development: `pytest`, `ruff`, `bandit`, and an
  OpenTofu-backed check that generated HCL actually parses.

### Known limitations at release
- Coverage is 5 policies; unsupported findings are reported as unsupported (`-v` lists them).
- No live Tenable Cloud Security API adapter — findings come from an exported JSON file. The
  interface such an adapter would implement is defined in `src/remgen/sources.py`.
- `verify` checks API shape, not AWS behavior.
- Terraform BUSL-1.1 posture is documented in `NOTICE.md` and still warrants Tenable counsel
  review before any public release or Exchange submission.
