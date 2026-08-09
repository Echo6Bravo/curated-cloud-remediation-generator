# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Four new Azure storage recipes — Batch 1 of the Azure register (4 → 8 recipes, all `safest`).**
  SFTP disabled, local-user authentication disabled, a SAS expiration policy, and allowing trusted
  Azure services through the account's network rules. Each was probed on all three axes before a line
  was written: `az --help` for the flag, the `azure.mgmt.storage` models bundled inside `az` for the
  SDK property, and a generated `azurerm` 5.0.1 schema for the IaC argument. That matters because the
  three vocabularies genuinely differ — the SFTP setting is `is_sftp_enabled` in the SDK,
  `--enable-sftp` on the CLI, and `sftp_enabled` in `azurerm`, so guessing one from another produces a
  recipe that verifies against nothing.

  **The register listed nine policies for this batch and four shipped**, which is the finding rather
  than a shortfall. Three are blob *service* properties whose command takes no `--ids`, so `Recipe`
  cannot express them at all and they moved to `R10`; Shared Key access moved to `R9`; and storage key
  expiration moved to a new class, `R11-no-iac-path-and-preview-cli`, because `--key-exp-days` is
  `[Preview]` and `key_policy` does not exist anywhere in the `azurerm` schema. Shared Key is the
  instructive one: it *passes* all three axes, and is still excluded, because disabling it breaks every
  account-key and SAS caller — `data_path_impact=True`, hence DISRUPTIVE, and v1 promises no disruptive
  remediation. Passing the axes is necessary, not sufficient.
- **The first recipe in this project with `hcl=None` — CLI only, deliberately, for the trusted-services
  bypass.** Every other recipe emits both formats. This one emits no HCL because both possible values
  of `azurerm`'s `network_rules` block generate configuration that is wrong in a way a reviewer would
  not see: `default_action = "Allow"` *opens* the account, and `default_action = "Deny"` — required in
  the block — empties the existing `ip_rules` and `virtual_network_subnet_ids` on apply, because both
  are `Computed` and absent from generated config reads as "set to none". Emitting nothing is the only
  honest option; the artifact README says "IaC resource: none; this policy is CLI only". This is a
  worse hazard than the replacement risk the tool already warns about, because that one is at least
  visible in a plan. `tests/test_azure_cli.py` grew a CLI-only branch for the same reason — its
  coverage helper asserted every recipe had an HCL target, and that assumption is now false.
  four buckets.** 217 policies: shipped (8), write-a-recipe-now (33), blocked on a named prerequisite
  (35), documented rejection (141). The headline is the **design ceiling: 76 of 217, or 35%** — the
  share of the Azure catalogue that can be expressed as a single idempotent, reversible, per-resource
  API call. That is meaningfully higher than AWS's 26%, because `az <service> update --ids` is a more
  uniform surface than AWS's per-service APIs.

  Deliberately the same shape as `AWS_POLICY_TRIAGE.md`, keeping the AWS class numbers where the
  argument is the same one, so a reader is not learning a second vocabulary and a class that turns out
  to be wrong is wrong in both places at once. The actionable recipes are batched by
  **`azure.mgmt` SDK package** rather than by `az` command group — `az postgres` and `az mysql` are
  both `azure.mgmt.rdbms`, and the SDK name is what `drift.py` resolves. Batch 1 landed in this same
  release (below); the six remaining batches hold 33 recipes, 46–61 h.

  One rejection class has no AWS counterpart and is the Azure-specific finding:
  **`R10-not-addressable-by-resource-id`** (27 policies). `Recipe` requires `cli_template` to name
  `{resource_id}`, and an ARM id reaches a command only through `--ids`, which is not universal in
  `az`. `providers/azure/recipes/__init__.py` already recorded this as the reason the planned Key
  Vault RBAC recipe does not exist; the class generalises that one finding to every policy it covers,
  with three measured causes — 11 where the update verb has no `--ids`, 13 where the setting is
  subscription-scoped and there is no per-resource id at all, and 3 where the setting is a sub-resource
  addressed by account name rather than by id.

  **Three assignments were corrected during the pass and all are recorded rather than quietly fixed.**
  A class called `R11-extension-required` was invented for the 14 Microsoft Defender policies on the
  theory that they need an `az` extension; they do not, `az security pricing create` is base CLI. That
  class had been derived from the policy *name* — the identical error that dissolved
  `R8-out-of-design-scope` in the AWS register — so it was dissolved into `R10`. Separately, five
  policies sat in `R10` that accept `--ids`, including `SQL Server Microsoft Defender`, which is
  per-server threat protection rather than the subscription plan it shares a name with. Moving them
  raised the ceiling from 35% to 37%. Third, implementing Batch 1 showed that its `--ids` probe had
  been run per *service* rather than per *policy*, which is not the same question: `az storage account
  update --ids` exists, but blob *service* properties are set by `az storage account
  blob-service-properties update`, which requires `--account-name` and accepts no `--ids` at all.
  Five policies left the ceiling as a result and it fell back to 35% — the direction an honest ceiling
  moves when the probe gets stricter. All three were found by reading a class's members, or writing its
  recipes, instead of trusting its label, which is what the class structure is for. The `--ids` claims
  behind batches 2–7 were made the same per-service way, so their recipe counts are upper bounds.

  Like the AWS register, it names what it does *not* cover: 40 `Custom` and
  `KubernetesAdmissionController` policies and 24 uncategorised ones, untriaged by any pass. UDM
  reports 1063 policies / 388 Azure-tagged; GraphQL reports 739 / 324, and the 64 gap is exactly those
  two groups.
- **Seven new tests in `tests/test_contributing_procedure.py`** (12 → 25 including parametrization),
  extending prose-versus-behaviour coverage to Azure and to the register claims. Every implemented
  cloud must have a register; each register's Shipped table must equal that cloud's recipes in both
  directions; the Azure section must name the Azure register and put the `--ids` check in its first
  half; `ROADMAP.md` must link a register per cloud; `azremgen`'s documented flags must exist and its
  flagless `verify` must behave as documented. The provider set is **discovered**, and an anti-vacuity
  guard fails if discovery returns fewer than two clouds. Mutation-tested rather than trusted for
  passing: ten mutations, each caught by the intended test — including `--ids` guidance moved to the
  end of the section rather than deleted, which is the realistic version of that regression.

### Changed
- **The triage-register CI gate is now per-cloud and provider-discovered.** It was written against
  `AWS_POLICY_TRIAGE.md` and `AWS.all_recipes()` by name, so it reported success for a repository in
  which Azure shipped four recipes and had no register at all — verified by running the previous gate
  against the previous tree. It now iterates the discovered `Provider` descriptors and requires
  `<CLOUD>_POLICY_TRIAGE.md` for any cloud that reaches a recipe, so adding a third cloud fails the
  build rather than silently skipping it. Same discipline as the `SECURITY.md` scope check, for the
  same reason: a hardcoded list must be edited by the commit that adds a cloud, and that is exactly
  the edit that gets forgotten. Measured on seven deliberate failures, including the missing-register
  case the old gate passed and an AWS case confirming the generalisation did not stop checking AWS.
- **`CONTRIBUTING.md` and `ROADMAP.md` no longer treat AWS as the only cloud with a register.**
  "Adding a recipe" points at the reader's cloud rather than at `AWS_POLICY_TRIAGE.md`, and states
  that a new cloud needs its own register before it can ship a recipe. The Azure section now points
  at `AZURE_POLICY_TRIAGE.md`, explains that its batches are SDK-package-shaped, and notes that every
  listed batch member was already probed for `--ids` while every `R10` member already failed that
  probe. `ROADMAP.md`'s Coverage section links both registers and quotes both design ceilings.

## [0.2.1] — 2026-08-07

A documentation and verification release: no generator behaviour changed, and the only diff in either
committed sample is the version string and timestamps. What it fixes is a class of defect this project
had no coverage for at all — **documents that make checkable claims about the code, and were not
checked.** Two of the three fixes below were found by pointing an instrument at that surface for the
first time; the third was found by reading the four policies a rejection covered instead of trusting
the category name they shared.

### Fixed
- **`SECURITY.md` told researchers a whole cloud's scope guards were out of scope.** It named only
  AWS's `sts get-caller-identity` preflight and `allowed_account_ids` under the highest-severity
  finding class, and listed Azure among the clouds that are "unimplemented, not silently broken" —
  while `azremgen` shipped four verified recipes, a subscription reachability preflight, and the
  `scope_conflict` check that closed a real cross-subscription escape. `examples/README.azure.md`
  links `SECURITY.md` as the explanation of the Azure boundary, so an Azure reader was sent to a
  document that said Azure did not exist. This is worse than a stale count: a security policy's job
  is to tell someone what to report, and this one excluded the guard most worth attacking. The
  wrong-scope bullet now lists each cloud's guards separately, because the escape routes differ —
  AWS has no identifier that embeds an account, so it needs no `scope_conflict` analogue.
- **Three documents told contributors that a green `verify` proved the HCL axis had run, when it
  proves the opposite.** `CONTRIBUTING.md`, `README.md` and `ROADMAP.md` all stated that `verify`
  without `--provider-schema` exits `4`. It exits `0` — deliberately, with a comment in
  `core/cli.py` explaining that requiring a 19 MB artifact would make the default invocation fail,
  and pinned by `test_verify_without_a_schema_says_so_and_does_not_claim_a_pass`. So the code was
  right and the prose was wrong, in the one direction that matters: the printed `? not checked`
  exists specifically to stop a reader taking a clean run as "both halves checked", and the
  documentation undid it. The docs now say the `Schema source:` line rather than the exit status is
  the evidence, and reserve exit `4` for a check that was *requested* and could not run — an unusable
  schema path, absent service models, a missing CLI surface.

### Added
- **CI now fails if `SECURITY.md` does not name every implemented cloud's scope guards.** The stale
  text above existed because nothing checked it; the recipe-count gate checks `README.md` only.
  Providers are **discovered**, not listed, since a hardcoded list would have to be edited by the
  same commit that adds a cloud — precisely the edit that was missed here. A descriptor that reaches
  no recipes is exempt: it genuinely is unimplemented, so the out-of-scope sentence is correct about
  it. Measured across nine cases before being trusted: the real pre-fix text fails on all three of
  its defects; a cloud named *only* in the out-of-scope section fails, so the section split is load
  bearing rather than a substring search; a simulated third cloud with recipes fails until the
  document names it; a recipe-less descriptor passes; zero discovered providers is an explicit error
  rather than a vacuous pass; and both dash forms parse, so an editor's autocorrect cannot disable
  the check. A renamed `**Out of scope:**` heading now reports which file to edit instead of raising
  a tuple-unpacking traceback.
- `src/remgen/providers/azure/__init__.py` added to the `docs-refs` path list, since `SECURITY.md`
  now sends a researcher there to find the cross-subscription guard.
- **`AWS_POLICY_TRIAGE.md` — every AWS-only policy in the catalogue, assigned to exactly one of four
  buckets** (shipped, write-a-recipe-now, blocked on a named prerequisite, documented rejection),
  with a prioritised service-batched recipe list and time estimates. `ROADMAP.md` previously answered
  "why does this policy have no recipe" for exactly three policies — VPC flow logs, Key Vault RBAC,
  SQL Server min-TLS — leaving the rest to be rediscovered one afternoon at a time. The headline is
  the **design ceiling: 61 of 237 policies (26%)**. The remaining 176 fall into eight rejection
  classes, so the register is eight arguments rather than one judgement per policy, and overturning a
  class reconsiders all its members together. It also records what it does *not* cover: the 17
  `Custom`, 28 `KubernetesAdmissionController` and 38 uncategorised policies that GraphQL omits, and
  why UDM (1063/427) and GraphQL (739/344) disagree — GraphQL is used because it is the only source
  that yields policy *names*, `RiskPolicyTitle` being a `CommonVirtual` property.
- **CI now cross-checks that register against the shipped recipes.** Two of its claims rot on the
  ordinary course of work, both silently: the shipped table goes stale the moment a recipe batch
  lands, and an overturned rejection leaves the document arguing against code that exists. The gate
  checks that the buckets partition the catalogue with no id in two of them, that the summary counts
  match the rows actually present, that the shipped table *equals* the recipe set in both directions,
  and that nothing shipped is also rejected. Measured on five failure cases before being trusted: a
  duplicated id, a landed recipe whose row was not moved, a stale summary count, a renamed section
  heading, and a document with every row deleted — that last one because zero rows is the shape in
  which this check passes vacuously. It deliberately does **not** check whether an assignment is
  *correct*; that is a judgement about an external API surface no job here can reach.
- **`tests/test_contributing_procedure.py` — the procedure docs are now tested against the tool.**
  `CONTRIBUTING.md` is executable instructions in prose: it names test functions as the enforcement
  for a rule, tells you which flags to run, and cites exit codes as evidence a check happened. None of
  that was checked by anything, which is how the exit-`4` error above survived three releases. Twelve
  cases now assert that every test function a doc cites exists (a renamed test otherwise leaves the
  sentence pointing at nothing while the suite stays green), that every flag a doc puts in a command
  block appears in that subcommand's `--help`, that the flagless `verify` behaves as documented — run,
  not read — and that `CONTRIBUTING.md` still points recipe authors at the register. Each was
  mutation-tested rather than trusted for passing: a renamed cited test, the real defective exit-`4`
  sentence reintroduced verbatim, a renamed `--safety-level`, a dropped register reference, and
  `verify` changed to fail without a schema. All five fail, each naming the document to edit.

### Changed
- **`CONTRIBUTING.md` now starts a recipe author at the triage register.** It said to take the policy
  UUID "from the live Tenable Cloud Security catalog", which since this release leads to a red build:
  the new `claims` gate requires the register row to move into *Shipped* in the same commit. A
  procedure doc that walks a contributor into a gate it never mentions is a defect in the doc, so
  *Adding a recipe* now names the register, says the row moves, and says that overturning a rejection
  means editing the class's reasoning rather than arguing one policy.
- **One triage assignment was corrected during the pass, and it is recorded rather than quietly
  fixed.** The four AWS-only `Kubernetes`-category policies were first rejected wholesale as
  in-cluster concerns — on the strength of the *category name*. Three are ordinary EKS control-plane
  calls (public node IPs, a public Kubernetes API endpoint, image scanning) and one needs a CMK, so
  all four are now assigned individually and the out-of-design-scope class no longer exists.
  Rejecting by category rather than by policy is the mistake the register exists to make visible.

## [0.2.0] — 2026-08-07

Second release, and the first with two clouds. Still pre-1.0: the CLI surface and recipe schema may
still change, which is why three breaking renames land in a MINOR bump rather than forcing 1.0.

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
- The catalog summary takes the cloud's name from the provider instead of hardcoding `"AWS"`.
  `CatalogDiff.summary_lines` is in `core` and is reached by every cloud, so four of its lines read
  "N AWS policies" regardless of which cloud was being remediated — correct behaviour described in
  the wrong cloud's vocabulary, the same failure `scope_noun` already exists to prevent. It defaults
  to an unlabelled "N policies" rather than to `"AWS"`, because a wrong cloud name reads as
  authoritative while a missing one reads as missing. This is the one visible change in the sample:
  the rejection message in `examples/sample-run.txt` now says "a cloud identifier" rather than "an
  AWS identifier". All seven artifact files are byte-identical.
- `to_hcl_label` reduces a **path-shaped** identifier — one beginning with `/`, which is what every
  Azure resource ID looks like — to its last segment before folding. Folding the whole thing gave a
  131-character label whose only distinguishing part was at the very end. The label is cosmetic:
  `import` is what binds a block to a real resource and it still carries the full id, so shortening
  cannot retarget anything. A test asserts the branch is unreachable for every AWS-shaped identifier
  — a leading `/` was rejected outright before path-shaped ids were permitted, so nothing that was
  previously *valid* can change shape. That is the claim a reviewer cannot check by reading, which is
  why it is asserted rather than argued.
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
- **The recipe set is split one module per AWS service.** `recipes/curated.py` is gone; the recipes
  live in `recipes/dynamodb.py`, `rds.py`, `cloudtrail.py`, `kms.py` and `s3.py`, each named for the
  botocore service id and each exporting a `RECIPES` tuple. The service is the unit the *verification*
  is done in — one API model, one CLI command group, one set of provider resource types — so it is
  also the unit a reviewer can bound a diff by: an S3 recipe touches `s3.py`, and a change to another
  service's file is now visible rather than buried in one growing module. Nothing shipped changed: the
  sample gate regenerates byte-identically.
  - **The modules are discovered, not listed.** A hand-maintained list is somewhere to forget, and
    forgetting there fails in the worst way available: the recipe exists, imports cleanly and passes
    review, while `all_recipes()` never returns it — so the policy reports as *unsupported*, every
    per-recipe test parametrizes over a set that excludes it, and nothing goes red. Discovery replaces
    that with a loud failure — a module in the package that does not export a well-formed `RECIPES`
    raises `ImportError` at startup, as does an empty package, which would otherwise emit nothing
    while reporting success.
  - The duplicate-`policy_id` guard is kept and now names the offenders (`Counter` rather than a
    quadratic scan). `REGISTRY` is a dict comprehension, so a repeated id does not raise on its own —
    the later entry wins and the earlier becomes unreachable through `get` while still being counted.
    The split makes that *easier* to do by accident, since a copy-pasted id in another file is no
    longer on the same screen, so the check matters more than before, not less.
  - Four new layout invariants in `tests/test_recipe_set.py`, each mutation-tested: every module on
    disk is actually reached by discovery, each module holds recipes only for the service it is named
    for, no module is empty or missing its export, and the package holds nothing that is not a service
    module. The filename-versus-contents check is the one that keeps the diff-bounding property true —
    without it, "adding to whichever file is already open" quietly restores the single-module blast
    radius.
- **The version had two sources of truth and nothing checked they agreed.** It was written in both
  `pyproject.toml` and `remgen/__init__.py`. `pyproject.toml` now declares `dynamic = ["version"]`
  and reads the package attribute, so there is one. The failure this removes is quiet and asymmetric:
  the copy stamped into every generated artifact header is the package's, so a drifted pair would
  make `pip show remgen` disagree with the artifacts that install produced — and the artifact, the
  thing a reader would trust, is the one that goes unchecked. Verified by building: the wheel
  metadata reads `0.2.0` from the module rather than from a literal.
- **New CI gate: `Version, tags and CHANGELOG agree`.** This repo was one step from the drift a
  release gate exists to catch — a single tag (`v0.1.0`), 16 commits past it, and 45 CHANGELOG
  bullets under `Unreleased` describing a tool whose command had been *renamed* — with nothing
  checking any of it. Four checks, three of them bidirectional because the drift starts from either
  side (notes written but never released, or a release cut without notes): a pushed tag needs a
  CHANGELOG section; a `Release X.Y.Z` commit needs its tag; a CHANGELOG section needs its tag; and
  `remgen.__version__` must equal the newest released section. The fourth is the one specific to
  this project rather than to changelogs in general — the version is stamped into every generated
  artifact, so a bump landing in the CHANGELOG but not the module makes each artifact misreport the
  code that produced it. Checks 2–4 run on every trigger, so drift surfaces on the PR that
  introduces it rather than at release time. `ci.yml` now also triggers on `v*` tag pushes, since a
  tag is the one artifact here that cannot be corrected in place.
  Eleven cases measured against a scratch repo rather than assumed, and each of the four drift shapes
  fails: `__version__` lagging the CHANGELOG, an untagged section, a tag with no section, a
  `Release` commit with no tag. The legitimate release-PR state passes through the carve-out; a
  section already on the base branch does **not**; an unreadable base fails loudly instead of
  exempting everything. Both dash forms parse, and a changed heading format is an explicit error
  rather than a silent zero-section pass — a gate that stops matching reads as green, which is the
  failure it was written to prevent.

### Security
- **A hostile `account_id` or `region` in a findings export could write artifacts outside `--out`.**
  `OutputUnit.filename` interpolates both into a filename, but both were validated only by
  `validate_identifier`, which permits `/` — and has to, because S3 keys and Azure resource IDs
  contain them. So an `accountId` of `1/../../../../tmp/target/PWNED` produced the relative path
  `aws/remediate-aws-1/../../../../tmp/target/PWNED-us-east-1.tf`, and `mkdir(parents=True)`
  obligingly created the intermediate directories. Confirmed by running the real CLI, not inferred
  from the regex: `--out` was left holding only `README.md` and `manifest.json` while both the `.sh`
  and the `.tf` landed in the traversal target. This predates the multi-cloud restructure and is
  unrelated to it.

  Fixed in two independent places, because the value is dangerous for two different reasons:
  - `validate_path_segment` is a new, stricter rule for values that become *one component* of a
    path — no `/` and no `.` at all, so neither a separator nor a traversal segment can appear. It
    is applied to `region` and `account_id` in `Finding.__post_init__`, at the boundary where
    untrusted data enters, so no generator or future output format has to remember the hazard. The
    rule is positional rather than per-cloud: every real credential-scope id and region already
    satisfies it (AWS account ids, Azure subscription UUIDs, `us-east-1`, `eastus`), so it rejects
    malformed input without narrowing any cloud's vocabulary. `validate_identifier` is unchanged and
    still permits `/`; its docstring now says outright that it is *not* sufficient for a value that
    becomes part of a filename.
  - `cmd_generate` now resolves every path and asserts `is_relative_to(--out)` immediately before
    writing, exiting **6** with nothing further written if it does not hold. This one is asserted
    rather than deduced: it is the last line before a write, costs one `stat` per file, and holds
    even for a filename component a future change adds and nobody re-validates. It has its own test
    that forces the branch by overriding `OutputUnit.filename` — a defence-in-depth check nothing
    exercises is indistinguishable from a deleted one — and that test was confirmed to fail against
    three mutants: the check disabled, the `return 6` removed so it reports and writes anyway, and
    the check rewritten as an unresolved `str.startswith`, which `..` walks straight through.

  **Why none of the existing layers caught it,** since that is the more useful finding: the quality
  review this project runs has no filesystem-path sink at all — its injection dimension lists
  HTML/SVG/CSV/shell/SQL, and the dimension covering generated artifacts asks what they do when
  *run*, not where they are *written*. The suite's 24 hostile-value payloads target `resource_id`
  only, so no test ever put a hostile `account_id` through a full `generate`. `bandit` has no taint
  analysis. CodeQL's `py/path-injection` is the right tool and would likely have found it, but its
  query packs cannot be fetched through this environment's TLS proxy, so that check has never
  actually run here.

  The aggravating factor is worth recording separately: the write loop already carried a comment
  reading "the provider's cloud id is validated as a single alphanumeric segment, so this cannot
  escape out_dir". That was *true about `cloud`* and silent about `scope_id` and `region`, which are
  interpolated into the same string. A comment that proves one component safe reads as having
  considered the question, and stops the next reader from checking the others — so it was worse than
  no comment. It is replaced by the assertion, which cannot be true of only one component.

### Fixed
- **The Azure SDK lookup found nothing on the layout GitHub's runners preinstall, so every Azure
  test silently skipped in CI.** `find_sdk_dir()` globbed upward from the resolved `az` launcher.
  The Debian package installs `/usr/bin/az` as a *bash wrapper rather than a symlink*, so
  `realpath` stops there and the parents are `/usr/bin`, `/usr`, `/` — while the packages sit in
  `/opt/az/lib/python3*/site-packages/azure/mgmt`, below none of them. Not a missing pattern: no
  glob rooted at the launcher can reach a tree that is not under the launcher.
  - **Three configurations agreed and the fourth disagreed, which is why this survived review.**
    Homebrew, pip and the MSI all resolve, and Homebrew's `az` is the same wrapper shape — it
    worked only because its interpreter happens to sit inside the same Cellar prefix. The
    `azure-drift` canary `pip install`s into `site-packages`, so it verified all four recipes green
    against real models on the same runner where every Azure test in `ci.yml` skipped.
  - **Fixed by reading the wrapper for the interpreter it names** and globbing from that as well.
    Both shipped wrapper shapes name one (Homebrew an absolute path, Debian
    `"$bin_dir"/../../opt/az/bin/python3`), and SDKs are installed against an interpreter by
    construction. The file is *read*, never executed, so the "no network calls, no binaries
    invoked" property this axis rests on is unchanged. Launcher parents are still searched first
    and first, so every layout that already resolved resolves identically.
  - **Verified against the real artifact, not a guess at it:** `azure-cli_2.88.0-1~noble_amd64.deb`
    — the runner's exact version — was unpacked and its 62 service packages and verbatim wrapper
    used as the fixture. `verify` reads all four recipes green off that tree, and the *exact*
    command CI runs now exits 0 where it exited 1. Both samples regenerate byte-identically, since
    only resolution changed.
  - **Three regression tests, mutation-checked.** Reverting the fix fails two of them. They cover
    the runner layout, a launcher naming no interpreter (which must still fall back to the globs,
    so supporting a new layout costs no existing one), and a shebang not being mistaken for the
    interpreter — `/opt/az/bin/az` starts `#!/mnt/repo/python_env/bin/python3`, a *build-machine*
    path absent from every installed system. The pre-existing layout test also called
    `lib/azure-cli/lib/…` "the MSI/deb layout"; the deb half of that was wrong and is corrected.
  - The first version of one test asserted `not any(parent.glob(p) for …)`. A generator is always
    truthy, so that assertion was vacuous; it only surfaced because the expected answer was "no
    matches". Rewritten over a list comprehension, with the trap recorded inline.
- **A cross-subscription escape: an Azure finding could remediate a resource in a subscription the
  script's own scope guard never named.** The most serious defect found in this project so far, and
  it was live in shipped code. An ARM resource id begins `/subscriptions/<id>/`, so an Azure finding
  names its subscription twice — once in `accountId`, once inside `resourceId` — and nothing compared
  them. Every recipe addresses its resource with `--ids`, because `Recipe` requires `cli_template` to
  name `{resource_id}` and an ARM id can only be passed that way; and `az` overwrites every argument
  carrying an `id_part` from the parsed id, `--subscription` among them. So a finding with
  `accountId` = A and a `resourceId` naming B produced a script headed `Scope: azure subscription A`,
  with a preflight confirming the caller can reach A, that **mutated a resource in B**. Exit code 0,
  artifacts written, nothing warned. The HCL half had the same shape: `subscription_id = A` beside an
  `import` block whose id named B.
  - Such a finding is now **rejected**, reported with its reason, and counted on its own summary line
    (`scope conflicts: N (subscription mismatch)`) so it cannot be read as an ordinary parse failure.
    Rejected rather than corrected in either direction: the two statements disagree and the tool has
    no basis for deciding which the exporter meant. Only that finding is refused — a whole-run
    failure would let one malformed record block work that is fine.
  - **Found by generating a mismatched finding, not by reading the code**, and specifically while
    checking whether anything cross-validated the two subscriptions *before* writing documentation
    that would have claimed the scope guard worked. Every new test asserts on the artifact or the
    exit path rather than on the predicate alone — a correct predicate that nothing calls is exactly
    the bug that was there.
  - Implemented as a **provider seam** (`Provider.scope_conflict`), `None` for AWS. That is not AWS
    being behind: no AWS `cli_template` interpolates an account — verified, all five print only
    `{resource_id}`/`{region}` — so an AWS identifier cannot contradict `accountId` and
    `sts get-caller-identity` is a sufficient guard. A shared check AWS passed vacuously would read
    as a coverage gap where there is none. Resource group and location are deliberately *not*
    compared: a finding carries no resource group, and an Azure `.tf` legitimately spans locations.
  - Mutation-tested seven ways (unwire the hook, compare case-sensitively, reject non-ARM ids, drop
    silently instead of reporting, never call the helper, index rejections by loaded position,
    remove the ordering sort). One survived its first run — the ordering test passed because the
    conflicting record happened to sort last anyway — so the fixture gained a fourth record whose
    parse failure falls *after* the conflict, and the mutant was then caught. Regenerating
    `examples/sample-output/` afterwards produced byte-identical AWS artifacts and transcript: a
    `core` change with no AWS output movement.
- **`verify` reported a pass on a cloud with no recipes.** Every axis iterates the recipe set, so an
  empty set passed all three and printed *"All 0 recipe(s) match the current Azure API
  definitions"* — a sentence a reader cannot distinguish from a real verification, on a check that
  examined nothing. This is not hypothetical: a new provider *starts* with zero recipes, so the
  drift canary would have reported green for Azure until the first recipe landed, which is the exact
  false-negative shape this tool exists to avoid. Each axis now reports **"nothing to check … This
  is not a pass"**. It still exits 0, deliberately: zero recipes is the correct state for a provider
  under construction, so failing would mean a cloud cannot be added incrementally. The requirement
  is on what it *says*. Found before any Azure code was written, by running a synthetic empty
  provider through the real `main()`.
- **The CLI-surface axis returned 0 while printing nothing at all.** A provider with no CLI verifier
  produced a `verify` transcript with two sections where the command documents three, so a reader
  counting them would conclude the third had passed — or would not learn it existed. The `Provider`
  docstring already promised it would be "reported as not run"; that promise was a comment. It now
  prints that the axis did not run and that a clean run of the other two does not cover it.
- **Two `NotImplementedError` crashes on a provider under construction**, both from calling a
  verifier before checking whether there was anything to verify: `_verify_api_axis` called
  `provider.verify_recipes(recipes)` ahead of the empty-set guard, and `cmd_generate` called it
  unconditionally. Both guards now precede the call. `cmd_generate`'s is on the **recipe set**, not
  on `matched` — an empty `matched` with a non-empty recipe set means the *findings* matched nothing
  and must still verify, because the next run's findings may match.
- **`--max-per-file` told Azure users their HCL was split by "region".** Wrong twice over: it is not
  Azure's word, and `azurerm` output is not split by location at all. Correct behaviour described in
  the wrong cloud's vocabulary is still a defect — a user would look for that split in the filenames
  and not find it, which reads as a bug in the tool. The clause is now conditional on the provider's
  `hcl_provider_is_region_scoped` and uses its own `region_noun`.
- **`AmbiguousImportError` said "account" on every cloud.** The message is what a user acts on when
  two resources in different credential scopes would claim one import identifier, and it named the
  wrong boundary for Azure. `group_targets` now takes a `scope_noun`, threaded from the output unit.
  The exit-6 refusal itself is unchanged. The test that covered it was asserting one cloud's
  vocabulary in a test about the *refusal*, so it has been split: the refusal test asserts the
  property, and a parametrized test asserts each cloud's noun is present **and the other cloud's is
  absent** — a message that appended the correct word while leaving the wrong one in place would
  satisfy a presence-only check.
- Every one of the four guards above was **mutation-tested**: made inert, silenced, or removed, and
  the covering test confirmed to fail in each case. Regenerating `examples/sample-output/` after all
  of this produced files **byte-identical** to the committed sample (modulo the timestamp), including
  the console transcript — which is the point of the exercise: two shared modules changed and no AWS
  output moved.
- **`--help` said "a AWS" and "a Azure": the indefinite article was hardcoded** in two places in the
  shared help text, so it was wrong for one cloud before Azure existed and wrong for both after.
  Fixed by **rephrasing so no article is needed**, not by an `a`/`an` rule keyed on the first letter:
  the choice depends on pronunciation rather than spelling, so a letter rule would emit "an GCP" for
  a cloud whose name is read as letters. Rephrasing is correct for every cloud, including ones not
  added yet.
  - Worth recording how it hid, because the same shape will hide the next one. A substring grep for
    `" a Azure"` reported the text clean: argparse wraps help at the terminal width and had wrapped
    *between* the article and the cloud name. The regression test therefore collapses whitespace
    before matching, and matches on a word boundary rather than a leading space — the first version
    of it required a leading space and **passed against its own mutant**, because the real text reads
    `cli (a Azure …` and the character before the article is `(`, not a space. Found by restoring the
    bug and watching the test stay green; the current version was confirmed to fail on the mutant and
    pass on the fix, across all five subcommands of both commands.
  - The sample was regenerated after this too: **byte-identical** again, transcript included, so the
    fix touched only help text.
- **One resource now gets one HCL block, however many policies it violates.** Two findings on the
  same live resource — an S3 bucket that is both unversioned and unencrypted — previously produced
  two `import` blocks carrying the same `id`. That file is *valid configuration*: real
  `tofu validate` reports "Success!", because nothing at parse time knows the two ids name one
  resource. The conflict surfaces at `plan`/`apply` against live infrastructure, which is the worst
  place to find it. `group_targets` now merges contributing recipes per resource and a genuine
  disagreement about what to set raises `HclMergeConflict` rather than picking a winner. The old
  `assign_labels` is removed: label disambiguation *hid* this defect, making the labels unique while
  leaving both imports pointed at the same resource.
  - The merge key is the **rendered** import id, not the template. `aws_cloudtrail` builds its id as
    `arn:aws:cloudtrail:{region}:{account_id}:trail/{resource_id}`, so keying on the template would
    collapse every trail in a file into one block. Account and region are in the key too, because a
    `{resource_id}`-style id carries neither and `GameScores` in two accounts is two tables.
  - A merged block is filed under the **riskiest** tier of its contributors, requires the **highest**
    provider version of its parts (compared numerically — `"5.12" < "5.9"` as a string), and states
    the union of their safety notes. Filing a `caution` change under a `SAFEST` banner is the one
    thing the tiering exists to prevent, so `SafetyTier.rank` now lives on the enum and the CLI and
    the generator share it instead of keeping two orderings that could disagree.
  - A recipe supplying a real value **supersedes** another's TODO placeholder in either direction, so
    a merged block can need less human completion than either part did.
  - `render_one` is now a thin wrapper over `group_targets`. Rendering pair-by-pair is what produced
    the duplicate imports, and no per-block function can detect it — the collision is a property of
    the set.
- **A second, pre-existing defect found while doing the above: two same-named resources in different
  accounts would claim one import id.** Whichever account the provider authenticated to, one block
  would adopt and reconfigure the *wrong* account's resource — the worst outcome this tool can
  produce. `plan_units` already prevents it by splitting on account, but the generator never
  asserted it, and "a different module is careful" is not a property the generator can verify. It
  now raises `AmbiguousImportError`. A test proves the guard is unreachable through the normal path,
  so it is a backstop rather than a broken tool.
- **New exit code `6`:** the HCL could not be generated correctly. Nothing is written, including the
  shell script — which is already rendered by that point but would otherwise leave an artifact set
  silently missing its HCL half. Distinct from `3`, which means the cloud's API changed under a
  correct recipe set; `6` means the tool is internally inconsistent, and the two need different
  fixes.
- The set-level guard that *banned* two recipes sharing an HCL resource type is replaced by one that
  fires the whole recipe set at a single resource and asserts the merge succeeds. Sharing a resource
  type is now allowed; sharing one while disagreeing about a value is not. It states plainly that no
  two shipped recipes overlap yet, so today it proves the merge is a no-op on this set and starts
  doing work on the first recipe that overlaps an existing one. Every new negative control was
  verified by mutation — including the version comparison, which was initially written with a
  `5.0`/`5.12` pair that a lexicographic comparison also passes, and now uses `5.9`/`5.12`.
- Nothing in the committed sample *merges*, and that is the expected result rather than a missed
  regeneration: no two shipped recipes target the same resource type. (The sample did change in this
  release, for the unrelated reason below — five `TODO` stubs were removed.)
- **Five of the seven `TODO` stubs in generated HCL were wrong, and one shape of wrong destroys
  data.** The new provider-schema check (below) found that `aws_dynamodb_table`'s `hash_key` and its
  `attribute` block, and `aws_db_instance`'s `engine`, `allocated_storage` and `username`, are
  `optional` in the schema — five declarations across two recipes — even though the provider
  *documentation* describes them as required. Docs describe what *creating* a resource needs; the
  schema describes what the parser demands. Only `aws_cloudtrail.s3_bucket_name` and
  `aws_db_instance.instance_class` are genuinely required, and both keep their stubs.
  - This was not a redundant line. Every block this tool emits is paired with `import`, so the
    resource already exists: **omitting an `optional` argument means "keep the live value" and
    produces no diff, while `hash_key = "TODO"` means "set it to the literal string `TODO`"** — and
    `hash_key` forces replacement, so applying the old output **destroyed and recreated the table**.
    `tofu validate` accepts both files identically, which is exactly why the check has to be the
    schema rather than the parser.
  - Verified empirically in both directions against real `tofu` before the recipes were touched:
    removing all five arguments yields "Success!", and removing `instance_class` yields "Missing
    required argument". The schema's `required` flag matches what the parser demands, exactly.
  - `examples/sample-output/` and `examples/sample-run.txt` are regenerated accordingly — the
    DynamoDB block now carries no placeholders at all, the RDS block carries one instead of four, and
    the run reports 2 incomplete blocks rather than 3.
- **Twelve negative controls in `tests/test_cli_surface.py` were reaching into the recipe set by
  index.** `RECIPES[0]` was the DynamoDB recipe when the recipes lived in one file; after the split it
  is whatever service sorts first (CloudTrail). Each of those tests breaks a specific flag with
  `str.replace`, which is a **silent no-op when the substring is absent** — so against the wrong recipe
  the "mutated" command comes back unchanged and the test asserts that a *correct* command is rejected,
  passing only if the checker is broken. They now look the recipe up by service and assert the mutation
  landed (`broken.cli_template != recipe.cli_template`) before asserting the result, so a template
  change makes the test fail rather than go vacuous. Found by mutation-testing the split, not by a
  failing run — the whole set was still green.
- **`test_policy_ids_look_like_uuids` used `str.islower()` as a lowercase check.** `islower()` is
  `False` for any string containing no cased characters, so a policy UUID made only of digits and
  dashes failed the assertion for having no letters rather than for being uppercase — reporting a
  correct id as broken. Now compared against its own `.lower()`, and confirmed still to catch a
  genuinely uppercase id.

### Added
- **A committed Azure sample run, and CI that keeps it honest.**
  `examples/findings.azure.sample.json`, `examples/sample-output-azure/` and
  `examples/sample-run.azure.txt`, documented in `examples/README.azure.md` — which covers only what
  differs from the AWS sample rather than restating the shared explanation, because a second copy is
  a second copy to drift.
  - The fixture is built to force the behaviours that are Azure-specific: two policies on **one**
    resource (proving the HCL merge, since two `import` blocks naming one resource are valid
    configuration that fails only at plan/apply), two locations in **one** subscription (proving
    Azure does *not* split `.tf` by location), a second subscription (a hard boundary in both
    formats), and three deliberate rejections including the cross-subscription conflict above.
  - Verified with real tools rather than substring checks: both `.tf` pass `tofu fmt -check` + `init`
    + `validate` against the real `hashicorp/azurerm` provider, both `.sh` pass `bash -n` and
    `shellcheck`, and the subscription guard exits 1 against a stub `az` having issued **zero**
    mutating calls.
  - `ci.yml`'s `sample` job now drives both clouds through **one** parameterized loop rather than a
    copied block, and each cloud parses against its own provider declaration
    (`.github/provider-check.azure.tf`) — one combined file would pull each cloud's provider into the
    other's workspaces. A separate step asserts the cross-subscription record is refused **by name**
    and that the wrong subscription id appears in no artifact, because the diff alone would pass if
    someone regenerated the sample after the guard broke. Measured while wiring it: with `az` absent
    the Azure artifacts are byte-identical but the transcript gains a "could not be verified"
    warning, so the job now asserts `az` is present and says why, rather than failing the diff for a
    reason that is not drift.
- **An `azure-drift` job in the drift canary, watching TWO upstreams rather than three.** Not an
  unfinished third signal, and the workflow says so at length so the next reader does not "fix" it.
  Azure's three *axes* map onto two release trains: `azure-cli` feeds **both** the API axis (the
  bundled `azure.mgmt.*` SDK models, which `drift.py` deliberately prefers over an importable
  `azure.mgmt` so it reads the version `az` uses) and the CLI axis (`az … --help`), while
  `hashicorp/azurerm` moves independently. One `pip install --upgrade azure-cli` therefore moves two
  signals at once. All three axes still run and report separately, and exit 3 is still distinguished
  from 8 — what is genuinely weaker than AWS is *independence*, not coverage.
  - Every issue title names Azure. The AWS job files against the same repo with the same label and
    titles are what the dedupe search matches on, so a shared title would post an Azure drift as a
    comment on an open AWS one and lose it.
  - A preflight checks both lookups can run and checks the SDK directory for **content**, not just
    existence: measured that a directory which exists but holds no service packages makes `verify`
    exit **3**, not 4 — every recipe's service is simply absent — so the canary would have filed "a
    curated recipe no longer matches the Azure API" for a run that read nothing.
  - Nothing in the job authenticates, which is what lets it run on a schedule in a public repo at
    all. Measured against an empty `AZURE_CONFIG_DIR`: all three axes exit 0 with 4 ok each and no
    login prompt.
  - `ci.yml`'s `canary-liveness` gate now asserts **both** job names, not just the file. The Actions
    API reports one `state` per workflow, so deleting one job leaves a file that still exists, still
    has a schedule and is still `active` while watching one cloud — the indistinguishable-from-passing
    state that gate exists to rule out.
- **Azure's first four curated recipes, and with them Azure's first real coverage.** Three storage
  account settings (HTTPS-only, minimum TLS version, cross-tenant replication) and SQL database
  transparent data encryption. All four are `safest`, which is not a claim that Azure is safer: it is
  what a first recipe set looks like when the riskier candidates are deferred rather than
  reclassified. Each was verified on all three axes before being written down — the bundled
  `azure.mgmt` SDK model property, the `azurerm` schema argument, and the flag `az <command> --help`
  actually accepts — because all three vocabularies differ for the *same* setting and no two of them
  can be inferred from the third.
  - **The three-vocabulary problem, measured rather than assumed.** HTTPS-only is
    `enable_https_traffic_only` in the SDK, `--https-only` on the CLI, and
    `https_traffic_only_enabled` in `azurerm`. Cross-tenant replication is
    `allow_cross_tenant_replication` / `--allow-cross-tenant-replication` /
    `cross_tenant_replication_enabled`. Only `minimum_tls_version` is nearly the same word in all
    three, and it is still spelled differently in each. A recipe written from one axis and assumed
    correct on the others fails on whichever axis nobody checked.
  - **Two planned recipes were dropped rather than approximated**, and both are recorded beside where
    they would have gone, in `src/remgen/providers/azure/recipes/__init__.py`. **Key Vault RBAC**:
    `Recipe` requires `{resource_id}` in `cli_template` and an ARM id can only be passed to a command
    accepting `--ids`, which `az keyvault update` does not — so the recipe cannot be *expressed*, not
    merely cannot be verified. **SQL Server minimum TLS**: `azurerm_mssql_server` enforces
    `administrator_login` and `administrator_login_password` through `ExactlyOneOf`/`AtLeastOneOf`
    rules the machine-readable schema does not express, so the schema axis passes and `tofu validate`
    then fails; shipping it meant emitting a credential-shaped placeholder into generated
    configuration. `azurerm_mssql_database` covers TDE instead. Both remain visible as unsupported
    policies rather than being quietly forgotten.
  - **Every generated `az` command prints a warning, and it is expected.** `az` overwrites each
    argument carrying an `id_part` from the parsed id, and `--subscription` carries
    `id_part='subscription'` — so with `--ids` it warns that `--subscription` "will be ignored". The
    flag stays in every template: `SubscriptionNotPinnedError` requires it, the script header promises
    it, and the target subscription is still explicit because the ARM id contains it. What changes is
    only which token carries it.
  - **An import id is a full ARM path, and a type-valid placeholder is the dangerous kind.** The first
    SQL recipe used a `server_id` stub shaped like a name; `azurerm` parses import ids with its own
    `commonids` types, so that failed `tofu validate` with "invalid URI for request" rather than a
    not-found. Related and worse: `"TODO"` does not validate for three of
    `azurerm_storage_account`'s five required arguments (a name pattern and two enums), so its
    placeholders are plausible-looking values — and `name` and `account_tier` are ForceNew, meaning an
    unedited block destroys the account rather than mis-tagging it. The inline comment is therefore the
    only thing distinguishing a stub from an answer, and a test requires every one to be non-empty and
    to contain "TODO".
  - **`tests/test_azure_recipe_set.py`, `tests/test_azure_drift.py` and `tests/test_azure_hcl.py`** —
    90 tests, deliberately separate files rather than a cloud-branching parametrization of the AWS
    ones. Three rules are Azure's alone (`--ids` required, `--subscription` required,
    `learn.microsoft.com` as the docs host) and two AWS rules are simply wrong here (`--region`, the
    `API_<Operation>.html` URL shape). Every new guard was mutation-tested: 25 mutations across
    `storage.py`, `sql.py`, `recipes/__init__.py`, `drift.py` and `hcl.py`, all caught. The strongest
    result is that disabling either SDK model reader fails both its fixture test *and* the
    real-bundled-SDK test, so both readers are load-bearing against real Azure rather than only
    against fixtures.
  - **One mutation was invalid and is worth recording as such.** Editing the storage stub tuple looked
    like it should break the merge test and did not — all three storage recipes *share* that constant,
    so all three changed identically and merged cleanly, which is correct behaviour. Redone two ways
    that do fail: giving one recipe a differing stub (raises `HclMergeConflict`) and splitting all
    three onto distinct resource types (fails the "at least one block merged more than one recipe"
    assertion, which exists so the merge test cannot pass vacuously). An intermediate attempt that
    renamed only two of the three still passed, which is why the third renames all of them.
- **End-to-end Azure coverage that produces real artifacts, which had been missing.** Every finding
  fixture in `tests/test_azure_cli.py` used a policy id no recipe covers — correctly, since those
  tests pin the zero-coverage reporting — with the consequence that `azremgen generate` had never once
  written an Azure artifact under test. The recipes were verified on all three axes and each generator
  was unit-tested, but nothing had run the whole path and looked at the file that came out. Five tests
  now do, driven by findings **derived from `all_recipes()`** so a new recipe is exercised the day it
  lands: the summary reconciles and the files exist; every emitted `az` command carries `--ids` and its
  `--subscription`; the script passes `bash -n`; the `.tf` passes a real `tofu fmt -check` and
  `validate` against `hashicorp/azurerm`; and `verify` exits 0 on all three axes at once against the
  real toolchain. That last one matters more for Azure than for AWS, because its three axes read three
  unrelated sources and nothing else confirmed one machine can satisfy all three simultaneously.
  Confirmed by mutation, including that a recipe added for a resource type the fixtures cannot address
  **fails** rather than silently skipping.
  - `tests/conftest.py` gains `AZURERM_PROVIDER_TF` and the `azurerm_workspace_template` /
    `real_azurerm_schema_path` session fixtures. A second pair rather than a parameterization of the
    AWS ones: it is a second `init` and a second provider download, so folding them together would
    make every AWS-only run pay for Azure. The provider blocks are also not the same shape, which is
    the point — `azurerm` takes no `region`, and `subscription_id` is required from azurerm 4.0 onward.
- **`azremgen`, the Azure command, and `remgen.providers.azure`.** It shipped with **no recipes** and
  remediated nothing; what it shipped was the provider descriptor, the entry point, and the three
  unimplemented pieces. (The recipes are above; this entry is the ordering, which is the part worth
  keeping.) Shipping the command before its coverage is deliberate. The cloud-neutral
  core was written against exactly one provider, and an abstraction validated against one instance
  is a guess — running the *real* shared pipeline down a second descriptor is the only thing that
  distinguishes "cloud-neutral" from "AWS with the strings moved". It found four defects
  immediately, all of them in `core` rather than in Azure; they are in **Fixed** below.
  - Three claims in the descriptor differ from AWS and change output rather than labelling it:
    `credential_scope_noun="subscription"`, `region_noun="location"`, and
    `hcl_provider_is_region_scoped=False`. The last is the consequential one: an `azurerm` provider
    block carries no location — each resource carries its own — so Azure `.tf` files may legitimately
    span locations. Setting it `True` would split output per location, producing more files than the
    provider requires and implying a constraint that does not exist. The subscription remains a hard
    boundary, exactly as the account is for AWS.
  - The unimplemented pieces **raise `NotImplementedError`** rather than returning a placeholder,
    because each has a *legal, quiet* return value that would be a wrong answer with no symptom:
    `render_shell` returning `""` is a valid runnable script that remediates nothing and that a
    reviewer could read, approve and run; `hcl_scope_block` returning `""` is legal too (the AWS
    implementation returns it for a region-spanning unit) and would emit HCL with **no subscription
    guard**; `verify_recipes` returning `()` is indistinguishable from "every recipe passed" one
    frame up. Each is asserted to raise. This is what made the two `NotImplementedError`s listed
    under **Fixed** appear as loud failures during development instead of as silent passes — a stub
    returning `()` would have hidden both. All three are implemented now, and each swap followed the
    same rule: the test that asserted a piece raises was not simply shortened, because removing a
    name from it downgrades the guarantee from *raises* to *untested*. Every removal is paired with
    an explicit "is implemented and no longer raises" test and a note in the parametrization saying
    so, so the file records which pieces were ever stubs and what replaced the assertion.
  - `verify_cli_surface` is left `None` rather than stubbed, because `None` is reported as *did not
    run* while a stub returning `()` would be counted as zero failures out of zero checks.
  - **Azure has no botocore equivalent.** The `az` CLI ships no JSON API models and nothing like
    `ac.index`, so the API axis has no local source of truth to check a recipe against. The three
    options and the decision are recorded in `verify_recipes`' docstring; the chosen approach is to
    read the `aaz` command trees, which declare `url`, method and `api-version` inline and are
    statically AST-readable without importing or reaching the network, with a per-recipe fallback to
    reporting the axis as could-not-check (exit 4). Not binding until the first Azure recipe exists.
- **The Azure `az` script generator (`remgen.providers.azure.shell`), and with it Azure's first real
  output format.** `--format cli` is implemented for Azure instead of raising. When this landed
  neither format was reachable — with no recipes every finding was classified "no recipe" before a
  renderer was called, so `--format` changed only the summary line (measured: `cli`, `hcl` and
  `cli,hcl` all exited 0 writing nothing, `bogus` exited 2). Both are reachable now that recipes ship,
  and both are exercised end to end. The shape follows the AWS generator — emitted never executed, `set -euo
  pipefail`, one
  command per resource, safety notes as comments, one file per credential scope — because those
  decisions are about reviewability and are not cloud-specific. **The guard is not a translation.**
  - **It checks reachability, not activeness, and this deliberately inverts the AWS behaviour.** The
    AWS guard rests on a property Azure does not have: an AWS credential set names exactly one
    account, so "these credentials are for the wrong account" is a fact the script can establish and
    refuse on. One `az login` routinely spans many subscriptions — three on the machine this was
    developed against, measured rather than assumed — and `--subscription` is a *global argument*
    every mutating command accepts. Refusing on an active-subscription mismatch would therefore be
    both annoying and unsafe: annoying because the user's default is often simply a different
    subscription they legitimately hold, and unsafe because refusing on it implies the active
    subscription is what the commands target, which the explicit flags make false. So the preflight
    asserts the target is *accessible* (`az account list --query "length([?id=='…'])"`, read-only,
    returning a count rather than any other subscription's details) and *reports* a mismatch without
    exiting.
  - **The inversion is stated in the generated artifact, not only in the source.** A reviewer who
    knows the AWS script will assume this one also refuses on mismatch, and a docstring cannot reach
    someone reading a generated file. The script says so itself, and a test asserts it does.
  - **`SubscriptionNotPinnedError`: the header's promise is enforced, not trusted.** The relaxed
    guard is only safe because every command names its subscription, so the two decisions are
    coupled — an unpinned command would silently inherit whichever subscription the caller's shell
    had selected, and the guard, relaxed on the strength of the promise, would not catch it.
    `render_one` raises if a rendered command omits `--subscription`, naming the recipe and how to
    fix it. Checked on the **rendered** command rather than the template, because a template could
    build the flag from a placeholder; what must be true is that the line the user runs contains it.
    This is the "comment that proves one component safe" failure mode caught in our own code: a
    reader who sees the promise stops checking the commands, which makes the promise worse than no
    comment unless it is a check.
  - The version requirement is **one literal**, stated in the descriptor and threaded into the
    header, rather than a second independent string that drifts the first time the minimum changes
    and leaves the reader of the stale one no way to tell. Asserted through the real
    `AZURE.render_shell` seam, not just the direct call.
  - `render_shell`'s signature is spelled out rather than `*args, **kwargs`: it is the seam `core`
    calls, and a permissive signature would accept a future keyword it then silently ignored.
  - Verified as a program, not a string: `bash -n`, `shellcheck` clean, and three behavioural runs
    against a **PATH-stubbed** `az` (never the real tenant) proving the not-logged-in and
    unreachable-subscription paths make **zero** mutating calls, and that a mere active-subscription
    mismatch proceeds and targets the **pinned** subscription rather than the active one. Deleting
    the reachability guard failed a test *and* behaviourally mutated an unreachable subscription;
    replacing it with the AWS activeness guard failed a test too.
- **Azure's CLI-surface axis (`remgen.providers.azure.cli_surface`) — the first of the three
  `verify` axes that can actually check something on Azure.** `verify` now reports a real flag
  source (`/opt/homebrew/bin/az (az 2.89.0)`) instead of "did not run". It said "nothing to check"
  while the recipe set was empty, because the axis short-circuits on an empty set *before* calling
  the verifier — an implemented axis and a vacuous pass are separate questions, and that branch is
  still pinned against an emptied descriptor now that Azure has recipes, since it is the state every
  future cloud starts in.
  - **The source was chosen by measurement, and the measurement inverted the recorded plan.** The
    plan, written into `verify_recipes`' docstring, was that `az`'s `aaz` command trees would serve
    both the API axis and this one. Three candidates were measured against `az` 2.89.0 first:
    - **`aaz` trees.** Only 34 of 65 command modules have one, which was known. What decided it is
      that *the commands a recipe would name are mostly absent*: `storage account update` — the
      likeliest first Azure recipe — has an `aaz/latest/storage/account/` directory with **no
      `_update.py`**; `sql/aaz` holds only managed-instance commands; `postgresql/aaz` only
      `network vnet`. Of 14 candidate remediation commands, 3 are `aaz`. Since could-not-check is
      exit-code-neutral, an `aaz`-based check would have been **quietly blind for precisely the
      commands most likely to drift** — the worst available failure mode, because it reports green.
    - **`commandIndex.latest.json`**, which does ship with the package, is group→module only (102
      entries, no flags).
    - **Importing `azure.cli.core` and asking the loader.** Not importable from our interpreter — it
      lives in `az`'s own virtualenv, and putting that `site-packages` on `sys.path` would shadow
      our dependencies with `az`'s pinned ones. More decisively, **it is not ground truth**: it
      lists flags `az` then rejects (`--account-name`, `--cmd`, `--immutability-policy-state`,
      `--federated-identity-client-id` all produce "unrecognized arguments") while *omitting*
      `--subscription`, which `az` accepts. A source that disagrees with the CLI in both directions
      produces false failures and false passes at once. The test named
      `test_the_loader_over_reported_flags_are_correctly_rejected` asserts the chosen source does
      not repeat that mistake.
    So the axis asks `az` itself: `az <command> --help`, parsed by section. `aaz` remains the right
    source for the **API** axis, where it is the only local statement of the REST contract. The two
    axes reading different sources is a decision, not an inconsistency to tidy up.
  - **`verify_recipes`' docstring was corrected in place**, not just contradicted in a changelog. It
    still records the API-axis decision it always did; it now also states that the CLI axis does not
    use `aaz` and why the measurement refuted that part of the plan. A stale plan left in the code
    is what the next person reads.
  - **The union of every help section except `Examples`, rather than trusting the "Global Arguments"
    heading.** Section placement is genuinely inconsistent: `--subscription` is filed under
    *Resource Id Arguments* for `storage account update` and under *Global Arguments* for `keyvault
    update`. Since `azure.shell` refuses to render a command that does not pin `--subscription`, a
    globals-only rule would have failed **every** Azure recipe and blamed Azure for it.
  - **A false-failure bug found by checking a real command instead of a fixture.** The first flag
    pattern required the option strings to be followed directly by `:`, so it silently dropped every
    flag `az` annotates — `--status    [Required] : …`. The flags it could not see were therefore
    exactly a command's **mandatory** ones, the ones a recipe is certain to pass. Surfaced when
    `az sql db tde set --status Enabled` was reported `flag_missing` for a flag that is real and
    required; before the fix that command parsed to 13 flags without `--status`, after it 14 with.
  - **An empty accepted-flag set is could-not-check, not a fact.** A successful `--help` that parses
    to nothing means the output shape changed; returning the empty set would read as "this command
    accepts no flags" and produce a wall of confident `flag_missing` failures pointing the reader at
    Azure. `_accepted_flags` returns `None` there.
  - **Nothing in the axis invokes a mutating command.** `az` does parse arguments before
    authenticating — a bogus flag gives rc=2 "unrecognized arguments" with no credentials at all —
    so flag validity is observable by running the real command. That shortcut was rejected and then
    closed off: taking it means naming a mutating operation to a process that might have credentials
    after all. `--help` yields the same information and cannot act.
    `test_the_axis_never_invokes_anything_but_help` records every argv the module spawns and asserts
    each ends in `--help`. Its first version banned mutating verbs in the argv and **failed on
    correct code**, because `az storage account update --help` necessarily contains `update` — the
    property that matters is the terminator, not the vocabulary.
  - Validated against real acceptance rather than against itself: 14 flags probed with **read-only**
    verbs only (`storage account show`, `keyvault show`, `sql db tde show`), 0 unrecognized. Works
    with all network access denied and an empty `AZURE_CONFIG_DIR`.
  - **Two of these tests were inert when first written, and mutation-testing is what said so.**
    Deleting the `Examples` exclusion left the suite green twice: the first fixture's example line
    began with `az` and the second was `--flag value`, neither of which the flag pattern matches at
    all. Rather than contrive a justification, the claim was measured — across 15 real commands,
    dropping the exclusion changes the parsed flag set for **none** of them — so the rule is
    documented as *defensive rather than load-bearing* on `az` 2.89.0, and the test uses the one
    shape that does leak (a bare flag alone on a wrapped line) to pin it against a future format
    change. Deleting `or None` from the empty-set branch also stayed green until a test drove
    `_accepted_flags` rather than the parser. Twelve mutants total were applied and all are caught.
- **The Azure descriptor's `verify_cli_surface` assertion is inverted, and the reasoning it replaced
  is worth keeping straight.** `test_structure.py` required it to be `None`, on the grounds that
  `None` prints "did not run" while a *stub* returning `()` would count as zero failures out of zero
  checks. That is an argument about stubs and does not reach a real verifier. The guarantee is
  unchanged; what enforces it moved to `_no_recipes_to_verify`, which runs before the verifier. The
  test now asserts the axis *is* wired and that it names its source, and `tests/test_azure_cli.py`
  pins the output half — including that "did not run" no longer appears, since it would now be a
  false statement about a check that ran.
- **`core/cli.py`'s no-CLI-verifier branch kept its coverage.** It was reachable only through Azure
  and stopped being reachable the moment that axis landed, so it would have become untested shared
  code that the next cloud passes through before its verifier exists — exactly when a silent
  `return 0` reports two axes as though they were three. `tests/test_cli.py` now drives it through a
  `dataclasses.replace` copy of the real AWS descriptor with that one field cleared, so the shared
  branch is exercised rather than a mock of it. Confirmed by mutation: making the branch silent
  fails that test and nothing else.
- **First `subprocess` use in shipped code**, so bandit's B404/B603 and ruff's S603 fired for the
  first time. Suppressed per call site with the argument written above each — argv lists only, never
  a shell; the only variable in one is which `az` the user's own PATH or `REMGEN_AZ_CLI` names —
  rather than project-wide in `pyproject.toml`, which would also silence the next `subprocess` call
  that might deserve the finding. The suppression comments carry the bare test id and nothing else:
  bandit parses every word after its marker as a test id, so prose there produced ~20 "Test in
  comment: … ignoring" lines per run, which is how a real bandit warning goes unnoticed.
- **`tests/test_azure_shell.py`**, which tests the generator directly. That was a necessity when no
  recipe could reach it through the CLI and is now a choice: the generator's contract includes inputs
  the curated set must never contain — an unpinned template, one naming the wrong subscription, an
  empty recipe list — and the end-to-end path can only exercise what a real recipe produces. Its most
  important assertions are that the script does **not** behave like the
  AWS one, in both directions, so a future contributor "fixing the inconsistency" is told why it is
  not one. The mismatch branch is asserted informational by extracting the branch body and checking
  it contains no `exit` — a substring check for the note alone cannot distinguish "prints a note"
  from "prints a note then exits".
- **`tests/test_azure_cli.py`** drives `azremgen` end to end through the real `main()`. Its original
  value was not Azure coverage — there was none — but that it runs the same `remgen.core.cli` down a
  different descriptor and asserts the output describes the cloud the user asked for: the three
  `verify` axes each account for themselves, `generate`'s counts reconcile at zero coverage, nothing
  is written, the closing line names Azure, and no AWS vocabulary appears. Those assertions survive
  against a `dataclasses.replace` copy of the real descriptor with its recipe set emptied, because
  each is a property of *core*'s reporting of an empty set — the state the next cloud starts in —
  rather than an accident of Azure's timing. Full ARM resource ids
  (`/subscriptions/…/providers/Microsoft.Storage/storageAccounts/…`) and UUID subscription ids are
  asserted *accepted*, which is the test that fails if a future tightening of `validate_identifier`
  makes an entire cloud's primary identifier unrepresentable — confirmed by mutation.
- **`tests/test_structure.py` now enforces its rules by discovery, not by list.** Provider packages
  are enumerated from the filesystem, so adding a cloud cannot silently opt it out of the structural
  checks; a hardcoded list would have to be edited by the same commit that adds the provider, and
  the edit easiest to forget is the one that exempts the new code. The no-cross-provider-import rule
  now applies to every provider and can finally fail — with one cloud it was a rule without a
  counterexample. The tempting violation is concrete: Azure needs a shell generator and AWS has one,
  so `from remgen.providers.aws.shell import …` is the shortest path to a working `azremgen` and the
  one that makes an Azure change able to alter AWS output.
- **`tests/test_recipe_set.py`** asserts invariants of the recipe *set*. Every other recipe test is
  parametrized per recipe and therefore structurally cannot see a property that only exists across
  two entries — a duplicate policy id, two recipes sharing an HCL resource type, a title that
  makes two remediations indistinguishable in the run README. Every invariant in the file was verified
  by mutation — the recipe set was edited to violate it and the test confirmed to fail — so none is a
  set-level assertion that cannot fail. (Stated without a count on purpose: a number here rots the
  next time an invariant is added, and unlike the README's recipe count nothing checks it.) That sweep found three of its own assertions to be vacuous —
  they re-derived `safety_tier`/`safety_notes`, which are computed properties rather than authored
  fields — and they were replaced with assertions over authored data (a reversal must name the same
  service and subcommand it undoes; an irreversible recipe must say in `caveats` what is permanent;
  unbounded cost must come with a way to bound it). It also surfaced that `CostImpact.LOW` does not
  downgrade a recipe out of `safest`, which is now stated as an assertion rather than left implicit.
- **A set-level invariant that each recipe's `docs_url` names the operation the recipe actually
  calls.** Every entry links `API_<Operation>.html`, so the operation is recoverable from the URL and
  comparable to `api.operation` instead of eyeballed. The failure mode this catches is not a malformed
  link but a *working* link to the wrong page — the result of copying the nearest recipe, which is how
  this file grows. The run README renders it as "[Documentation]", so a reviewer following it to check
  what a remediation does would read another call's parameters, permissions and consequences. Nothing
  else compared the two: the prose check only asserts the string is non-empty, and `verify` checks the
  operation against botocore without reading the link. Mutation-tested three ways (a neighbour's
  operation, a non-AWS host, a URL truncated to the section index). It deliberately does not assert
  the URL *resolves* — this suite makes no network calls.
- **Two candidate invariants are recorded in `tests/test_recipe_set.py` as deliberately rejected**,
  with the reasoning, because both look like obvious gaps: a set-level assertion about what a merged
  block inherits (already covered against constructed overlaps in `tests/test_generators.py`, and at
  the set level it could not fail today — no two shipped recipes share a resource type, so every group
  has one contributor and the check is trivial while appearing to verify the merge), and an assertion
  that each safety note names its resource (`safety_notes` is a computed property, so it would
  re-derive the formula and pass unconditionally — the same trap that made three original invariants
  vacuous). `CONTRIBUTING.md` points at the list and asks that a rejected invariant be added to it
  rather than left for the next person to rediscover.
- **`verify` now checks all three upstreams a recipe depends on, not one.** They are maintained by
  different projects and rot independently, and checking one while reporting a pass is how a shipped
  artifact rots in silence. The AWS CLI can rename `--deletion-protection-enabled` while
  `dynamodb.UpdateTable` keeps its `DeletionProtectionEnabled` member; the Terraform provider can
  rename an argument while both are untouched. Each breaks a file this tool already wrote and is
  invisible to the other two checks.
  - **`remgen.core.hcl_schema`** checks each recipe's HCL resource type and every argument it emits
    against `tofu providers schema -json`. Seven outcomes, each with its own status rather than a
    boolean: a missing resource type, a missing argument, a deprecated one, and the
    `NOT_REQUIRED` case above. In `core` rather than the AWS provider because the schema format is a
    property of Terraform, not of a cloud — only the source address differs. It takes a **path**
    (`--provider-schema`, or `$REMGEN_TF_SCHEMA`) and deliberately does not run `tofu`: producing a
    schema downloads the provider, and a tool whose safety argument is "no network calls, no
    subprocesses" should not fetch hundreds of megabytes from a registry.
  - **`remgen.providers.aws.cli_surface`** checks each rendered `aws` command — and its
    `reverse_hint`, the command someone runs in a hurry having just broken something — against
    `awscli/data/ac.index`, the CLI's own autocomplete index, read read-only. Not derived from the
    API member names: derivation looks like kebab-casing and is not (`DBInstanceIdentifier` →
    `--db-instance-identifier`, per `botocore.xform_name`), and a derived flag would be checked
    against the derivation, making a CLI-side rename — the exact drift this catches — invisible.
    Both AWS CLI v2 install layouts are found; supporting only the package layout would have
    reported `UNAVAILABLE` on precisely the machine the canary runs on, and `UNAVAILABLE` is
    exit-code-neutral, so the canary would have gone quietly blind.
  - **New exit codes `7`** (provider-schema drift) and **`8`** (CLI-flag drift), distinct from `3`
    (API drift) because they are three different fixes in three different files. Not `6`, which
    already means "the HCL could not be generated correctly" — an internal inconsistency, a different
    response. All three axes **always run** and all three are always reported, so one broken upstream
    cannot hide a second behind it; the process exits with the most urgent verdict via explicit
    precedence `(4, 3, 7, 8)` rather than `min()`, which gives the same answer today only because
    `3 < 7 < 8` — an accident of numbering a new code could break silently.
  - Every status on both axes was mutation-tested, including against a mutated copy of the real 19 MB
    schema, each with a passing control so "everything fails" cannot masquerade as a working negative
    control. `test_no_shipped_recipe_stubs_an_argument_the_provider_does_not_require` pins the exact
    set of stubs, and the real-parser test has a backward half — stripping `instance_class` must make
    validation *fail* — because the forward direction alone proves nothing about a permissive parser.
- **A scheduled upstream-drift canary** (`.github/workflows/drift-canary.yml`), weekly and
  deliberately **not** a gate, watching all three upstreams. `ci.yml` already verifies recipes on
  every push, which covers drift while someone is working; this covers the opposite failure mode, a
  curated recipe set sitting untouched for months while its upstreams keep moving. Everything it
  resolves is unpinned — the newest `botocore`, the newest provider, `tofu` at `latest`, the runner's
  own CLI — which is the one place a floating dependency is the point: a pinned canary verifies a
  snapshot and reports "no drift" forever. It files or updates a tracking issue rather than only
  reddening a run nobody watches, with a **distinct title per signal**, because each is a different
  fix and two can be open at once (sharing a title would make the second a comment on the first and
  lose it). Exit codes are handled individually rather than collapsed to pass/fail: `3`/`7`/`8` name
  *which* upstream moved, while `4` means the canary went blind — which is worse than red, because a
  red run names a fix and a blind one reports nothing. Reporting any of them as success is the
  specific thing this workflow exists to prevent.
- **CI preconditions for each skipif-gated suite.** `ci.yml` already asserted `tofu` and the AWS
  service models were present so their tests could not silently skip; the AWS CLI's `ac.index` is now
  asserted too, and each gate names what stops being checked without it, because "something skipped"
  is not actionable.
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
- **The AWS provider plugin cache is now restored in CI**, in both jobs that run `tofu`. The tests
  already shared one plugin directory locally (`~/.cache/remgen-test-tofu-plugins`), but CI had no
  `actions/cache` step at all, so every run re-downloaded a **~147 MB provider zip that unpacks to
  ~663 MB** — four `init`s between the two jobs. The `sample` job additionally points
  `TF_PLUGIN_CACHE_DIR` at that directory so its three per-file workspaces share one copy; without it
  each `.terraform` holds a real 680 MB provider binary instead of a symlink tree.
  - Two properties were **verified before trusting it**, because a build cache that can influence a
    result is worse than no cache: a **stale** cache cannot pin an old provider (with only an older
    5.x present, `init` under `~> 5.0` still resolved and fetched 5.100.0), and a **corrupt** one fails
    loudly — a truncated cached package makes `init` fail with *"does not match the content of the
    downloaded package"*, and the suite reports the workspace could not be initialized rather than
    validating against a damaged provider. So the cache can cost a red build; it cannot manufacture a
    green one. Both paths were exercised end to end against a restored directory. A poisoned entry is
    abandoned by bumping the `-v1-` key prefix.
  - **The canary is deliberately excluded.** It exists to resolve an upstream nobody has seen yet, so
    a cache would almost always miss, and its presence would invite the question of whether a cached
    artifact is what the run compared against. Stated in a comment in the workflow so its absence
    reads as a decision rather than an omission.
  - The two jobs get **separate cache keys**, because they check different provider majors and one
    shared key had them evicting each other's provider on every run: the fixtures constrain `~> 5.0`
    (5.100.0) and the sample job `>= 5.0`, which now resolves 6.58.0 since the AWS provider released
    6.x. That spread is left alone on purpose — both were confirmed to agree on the two schema facts
    this tool depends on (`aws_dynamodb_table` validates with no `hash_key`; `aws_db_instance` still
    rejects a block missing `instance_class`), so it is extra coverage rather than an inconsistency.
    The keys hash the file that actually determines the constraint, which is why the sample job's
    provider block moved out of the workflow into **`.github/provider-check.tf`**: keyed on `ci.yml`,
    every unrelated workflow edit would have discarded 147 MB.

### Notes
- `examples/sample-output/` is *not* named `artifacts/` because `.gitignore` matches `artifacts/` at
  any depth; that name would have committed nothing while every doc still pointed at it.
- The `sample`, `docs-refs` and `claims` CI jobs walk the output tree recursively now that artifacts
  sit under a per-cloud directory, and compare by path relative to the output root rather than by
  basename — two clouds may legitimately produce the same filename in different directories, and a
  basename match would compare the wrong pair. Each glob-driven check asserts it found files first,
  because a glob that stops matching turns a blocking gate into a no-op that still reports green.
- The `claims` job counts recipes and tier splits **per cloud**, and each tier split is matched only
  within its own cloud's sentence in the README. A whole-document substring search would let AWS's
  split be satisfied by Azure's sentence whenever the two share a number — which is the case today:
  AWS has 4 `caution` and Azure has 4 `safest`. A cloud with no sentence at all is an error rather
  than an absence nobody notices.
- Structure is not coverage, and Azure is now the evidence for that rather than the illustration of
  it: it has recipes, and getting them took a source chosen by measurement after the first plan
  proved to cover 5 of 18 commands, a safety analysis that excluded a remediation passing all three
  axes, and an API verifier with no botocore equivalent to read. GCP and OCI still have only a place
  to live.
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
