# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- **BREAKING: the command is now `awsremgen`, not `remgen`.** The package restructured into a
  cloud-neutral core (`remgen.core`) plus one provider per cloud (`remgen.providers.aws`), so a
  second cloud can be added without editing the code that decides what AWS emits. The cloud is
  bound at the command name rather than a `--cloud` flag: it selects the recipe set, the
  API-definition verifier and the identity preflight all at once, so reading it from a flag would
  make "wrong cloud against these credentials" a reachable state. `--help` also stays accurate,
  because every cloud-specific string in it comes from the provider descriptor. There is no
  `remgen` shim; a command that silently became a different command would be worse than one that
  is not found.
- **BREAKING: `--tier` is now `--safety-level`.** No alias was kept. Two spellings for one setting
  invites passing both, at which point the tool has to guess a precedence the user never stated.
  A test asserts `--tier` no longer appears in `--help`. The levels are unchanged and remain
  cumulative — each includes everything less risky.
- **BREAKING: artifacts are written under a per-cloud directory** (`artifacts/aws/…`) and the cloud
  now appears in every filename (`remediate-aws-111111111111-us-east-1.tf`). `README.md` and
  `manifest.json` stay at the output root rather than one per cloud, because reconciling a run —
  showing that a finding without an artifact was *withheld or unsupported*, not lost — is a
  property of the whole run and no single per-cloud index could answer it.
- **BREAKING: manifest keys are cloud-neutral.** `accounts` → `scopes`, and each file entry's
  `account_id` → `scope_id` with the cloud's own word alongside it in `scope_noun`. New per-entry
  `cloud` and `path` fields, and a top-level `clouds` list. Renamed rather than aliased so a
  consumer reads one field on every cloud instead of probing for `account_id` or `subscription_id`.
- Whether region is a hard boundary for HCL is now declared per provider rather than assumed. It is
  true for `hashicorp/aws`, where region is set on the provider; `azurerm` takes `location` per
  resource and would not split the same way.
- `ruff format` is now adopted and enforced in CI. `ruff check` (linter) and `ruff format`
  (autoformatter) are separate tools sharing one binary, and only the first was being run — but
  `ruff format` reads `line-length` from `[tool.ruff]` whether a project opts in or not, so it
  already had an opinion and 14 of 38 files disagreed with it. That left `--check` permanently red
  with nothing recording whether it was a real finding or a tool the project ignored. Verified not
  to touch generated output: a regenerated sample diffs byte-for-byte, including the transcript.
- `recipe_notes(full=True)` and the `docs_label` chain that fed it (`Provider.docs_label` through
  `render_hcl` and `hcl_recipe_notes`) are removed — all unreachable, since `docs_label` was read
  only inside `if full:`. Replaced by a test asserting the summary, prerequisites, caveats and docs
  link appear in the run README and **not** in the `.sh`/`.tf`. `full=True` was the switch that
  would have undone the artifact-size work with every other test still green, so the guard replaces
  it rather than the deletion just removing it. One assertion that looked like it covered this
  (`"AWS docs" in out or not any(r.docs_url ...)`) was passing vacuously on a fixture with no
  `docs_url`.

- A failed `tofu init` in the HCL validation tests is now a **hard failure, not a skip**. The
  `skipif` above it has already confirmed a binary is present, so reaching a failed `init` means the
  toolchain *is* available and something else broke — a bad provider constraint in generated HCL, a
  corrupted plugin cache, a registry error. Skipping turned every one of those into a green run that
  had validated nothing, and because it was a *runtime* skip rather than a collection-time one, CI's
  "assert nothing was skipped" gate could not see it either. `REMGEN_ALLOW_TOFU_INIT_FAILURE=1`
  opts back in for genuinely offline work.
- The generated-HCL tests now reuse one warmed OpenTofu workspace for the session instead of running
  `init` per test, cutting the suite from **88s to 30s**. A plugin cache alone was not enough:
  measured, a fully warm `init` still costs 16.7s because it re-verifies the 663 MB provider, versus
  2.0s for `validate`. Copying the initialized `.terraform` tree (symlinks preserved — dereferencing
  them would copy 663 MB per workspace) skips only the re-download and re-verification of a provider
  that cannot change mid-session. Verified to cost no rigor: the reused workspace still rejects a
  missing required argument and an unsupported attribute, and injecting a bogus attribute into a
  real recipe still fails the fast path.

### Added
- **`tests/test_recipe_set.py`** asserts invariants of the recipe *set*. Every other recipe test is
  parametrized per recipe and therefore structurally cannot see a property that only exists across
  two entries — a duplicate policy id, two recipes claiming one HCL resource type, a title that
  makes two remediations indistinguishable in the run README. Each of the 15 invariants was verified
  by mutation: the recipe set was edited to violate it and the test confirmed to fail, so none is a
  set-level assertion that cannot fail. That sweep found three of its own assertions to be vacuous —
  they re-derived `safety_tier`/`safety_notes`, which are computed properties rather than authored
  fields — and they were replaced with assertions over authored data (a reversal must name the same
  service and subcommand it undoes; an irreversible recipe must say in `caveats` what is permanent;
  unbounded cost must come with a way to bound it). It also surfaced that `CostImpact.LOW` does not
  downgrade a recipe out of `safest`, which is now stated as an assertion rather than left implicit.
- **A scheduled upstream-drift canary** (`.github/workflows/drift-canary.yml`), weekly and
  deliberately **not** a gate. `ci.yml` already verifies recipes against the real AWS service models
  on every push, which covers drift while someone is working; this covers the opposite failure mode,
  a curated recipe set sitting untouched for months while AWS keeps changing its API. It installs
  the newest `botocore` unpinned — the one place a floating dependency is the point — and files or
  updates a tracking issue rather than only reddening a run nobody watches. Exit codes are handled
  individually, not collapsed to pass/fail: 3 ("a recipe no longer matches") is a code defect while
  4 ("could not check") means the canary went blind, and reporting either as success is the specific
  thing it exists to prevent.
- **CI job `canary-liveness`**, blocking, which asserts the canary is still `active`. GitHub
  silently disables `schedule` triggers after 60 days of repository inactivity — exactly the
  dormancy the canary exists to cover — and a disabled workflow produces no runs, no failures and no
  notification, making it indistinguishable from one that has been passing. The only way to notice
  is from something that runs on every push. An unreachable Actions API also fails rather than
  reading as a live canary.
- **`--format`** selects which output formats to write, as a comma-separated list (`cli`, `hcl`,
  `all`; default `all`). A value list rather than a boolean per format: a pair of booleans has an
  ambiguous "neither passed" state, and per-format flag *names* would not survive a second cloud.
  An unknown name is a hard error (exit 2) with nothing written, because a typo that quietly emits
  half the output looks like a tool that lost findings. Values are reordered canonically, so
  `hcl,cli` and `cli,hcl` produce byte-identical runs. Choosing `hcl` alone omits policies with no
  IaC equivalent and reports the count.
- **`tests/test_structure.py`** enforces the layering that two module docstrings already claimed a
  test enforced: `core` may not import from `providers`, and no provider may import another. Imports
  are read from the AST rather than by importing the module, so a lazy import inside a function body
  cannot satisfy the rule while breaking it. It also asserts the module set is non-empty, since the
  failure mode of a structural test is reporting green while checking nothing.
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
- The `sample`, `docs-refs` and `claims` CI jobs walk the output tree recursively now that artifacts
  sit under a per-cloud directory, and compare by path relative to the output root rather than by
  basename — two clouds may legitimately produce the same filename in different directories, and a
  basename match would compare the wrong pair. Each glob-driven check asserts it found files first,
  because a glob that stops matching turns a blocking gate into a no-op that still reports green.
- Structure is not coverage: Azure, GCP and OCI have a place to live but no recipes, no safety
  analysis and no API-definition verifier. Nothing in this release adds a second cloud.
- Several abstractions were deliberately *not* built yet, and say so in their docstrings: no shared
  shell-script skeleton, no plugin discovery for providers, and the scope hierarchy stays two levels
  deep. Each waits for the commit that adds a real second cloud, since guessing what two clouds
  share from a sample of one is how the wrong seam gets frozen in.

## [0.1.0] — 2026-08-04

Initial release. Pre-1.0: the CLI surface and recipe schema may still change.

> Left as written. The command names and module paths below (`remgen`, `--tier`,
> `src/remgen/sources.py`) are what this version actually shipped; see *Unreleased* above for what
> they are now. A changelog edited to match the present cannot be used to tell when something
> changed, which is the one thing it is for.

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
