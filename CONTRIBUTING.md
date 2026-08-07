# Contributing

Thanks for considering a contribution. The bar here is deliberately specific, because this tool
emits commands that people run against production cloud accounts.

## Where code goes

The package is split so that adding a cloud cannot change what an existing cloud emits:

| Path | Holds | Rule |
| --- | --- | --- |
| `src/remgen/core/` | The shared pipeline — findings loading, dedupe, safety gating, layout, HCL rendering, the CLI. | **Must not import from `providers`.** Anything cloud-specific it needs arrives through `core/provider.py`. |
| `src/remgen/providers/aws/` | AWS recipes, the shell-script generator, the service-model verifier, and the `Provider` descriptor wiring them together. | Must not import another provider. Shared code goes in `core`, where both clouds' tests cover it. |

`tests/test_structure.py` enforces both rules by parsing imports from the AST, so a lazy import
inside a function body cannot satisfy them while breaking them. If a change needs `core` to know
something about a cloud, add a field to `Provider` rather than an import — a failure there names the
import to invert.

Each cloud gets its own console command (`awsremgen`, `azremgen`) rather than a `--cloud` flag. See
[One command per cloud](./README.md#one-command-per-cloud) for why; the short version is that the
cloud selects the recipe set, the API verifier and the identity preflight together, so it should not
be a value a typo can change.

Adding a command means adding it to `[project.scripts]`. The suite imports `main` directly, so it
cannot see a typo there — CI runs every declared script *as a command* and checks each names itself
in its own `--help`, which is what catches a new command accidentally bound to another cloud's
provider.

## The one rule that matters most

**A recipe is not a mapping exercise.** Adding coverage is the most requested change and the
easiest one to do badly. A recipe that "looks right" and emits a command that fails — or worse,
succeeds in a way the user did not intend — is worse than no recipe at all, because the user
trusted it.

## Adding a recipe

**Where it goes: one module per AWS service**, under `src/remgen/providers/aws/recipes/`, named for
the botocore service id — `dynamodb.py`, `rds.py`, `s3.py`. An RDS recipe goes in `rds.py`; a recipe
for a service with no file yet gets a new one. Each module exports a `RECIPES` tuple and nothing else,
and the package **discovers** them, so there is no list to add yourself to.

Two consequences worth knowing before you start:

- **Only recipe modules may live in that package.** Every module in it is imported as a recipe source,
  so a helper dropped there raises `ImportError` at startup for not exporting `RECIPES`. Helpers go one
  level up.
- **The filename is checked against the contents.**
  `test_each_service_module_only_holds_recipes_for_that_service` fails if `s3.py` holds an RDS recipe.
  The point is that a reviewer reading a diff to one file knows which service it can possibly affect,
  so adding your recipe to whichever file is already open is the thing to avoid.

Discovery is deliberate rather than a convenience: a hand-maintained list is somewhere to forget, and
forgetting there fails silently in the worst way — the recipe exists, imports cleanly and passes
review, while `all_recipes()` never returns it, so the policy reports as *unsupported*, every
per-recipe test parametrizes over a set that excludes it, and nothing anywhere goes red.
`test_every_service_module_on_disk_is_actually_discovered` walks the directory and asserts the
aggregate contains every module's entries, so that failure mode cannot come back.

**Start by picking a policy from [AWS_POLICY_TRIAGE.md](./AWS_POLICY_TRIAGE.md).** It assigns every
AWS-only policy in the catalogue to one of four buckets, and the *Write a recipe now* section is the
prioritised, service-batched list of what is ready to be written — with the UUID you need in the same
row. Two things follow from that, both enforced:

- **Moving the row is part of your commit.** When your recipe lands, its row moves out of *Write a
  recipe now* into *Shipped*, and the counts in the *Result* table change with it. A `claims` gate
  compares that table against the recipes reachable from the provider descriptor, in both directions,
  so leaving the row behind fails the build rather than leaving the register quietly claiming your
  work is outstanding.
- **If you want to write one the register rejects, argue the class, not the policy.** The eight
  rejection classes are the unit: a policy is rejected because it is an instance of one. Overturning
  one means editing that class's reasoning and moving every member it no longer covers — which is the
  point, since `ROADMAP.md` cites those classes as the answer to "why does this policy have no
  recipe". The same gate fails if a rejected policy gains a recipe without its row moving.

Every field must be verified against a primary source, not inferred from a similar recipe:

1. **Policy UUID** from `AWS_POLICY_TRIAGE.md`, or from the live Tenable Cloud Security catalog for a
   policy the register does not cover (it triages AWS-only policies; `Custom`, admission-controller
   and uncategorised ones are outside it). Not invented, not guessed.
2. **API call and parameters** confirmed against the AWS service model (`service-2.json`) —
   the same source `awsremgen verify` reads. Confirm the operation name and every parameter's shape.
3. **HCL resource type and attribute** confirmed against the provider **schema**
   (`tofu providers schema -json`), not only the documentation — the same source `awsremgen verify`
   reads for its HCL axis. The docs and the schema disagree, and the schema is what the parser
   enforces (see the next point).
4. **Rendered `aws` command** confirmed against the CLI's own flag surface, which `verify` reads from
   `awscli/data/ac.index`. Do not derive the flag from the API member name: `DBInstanceIdentifier` is
   `--db-instance-identifier`, and the rule that produces that lives in `botocore.xform_name`. The
   `reverse_hint` is checked too, so it must name real flags.
5. **Reversal command**, actually run, or an explicit `reversible=False` with the reason.
6. **Safety classification** — and be honest about it. Ask specifically: is it reversible? does it
   touch the data path? does it require a restart or replacement? does it add usage-scaled cost?
   does it interfere with `terraform destroy` / `tofu destroy`? Each of those has a field.
7. **Safety notes and caveats** written for someone who will read them at 2am during an incident.

**Never add an `unresolvable_required_*` stub the schema does not mark `required`.** This is the one
place in a recipe where being generous causes data loss, and the documentation will mislead you: the
AWS provider docs describe `aws_dynamodb_table`'s `hash_key` and `aws_db_instance`'s `engine` as
required, and the schema marks both `optional`. Docs describe what *creating* a resource needs; the
schema describes what the parser demands, and every block this tool emits is paired with `import`, so
the resource already exists. Omitting an optional argument means "keep the live value" and produces no
diff. Emitting `hash_key = "TODO"` means "set it to the literal string `TODO`" — and `hash_key` forces
replacement, so it **destroys and recreates the table**. `tofu validate` accepts both files
identically, which is why the check is the schema and not the parser. `verify` fails with
`NOT_REQUIRED` (exit `7`) if you add one, and
`test_no_shipped_recipe_stubs_an_argument_the_provider_does_not_require` pins the current set.

**If your recipe shares an HCL resource type with an existing one, it must agree with it.** That is
allowed and handled: `group_targets` merges both into a single `import` + `resource` pair for a
resource that violates both policies, because two `import` blocks naming one resource are *valid
configuration* — `tofu validate` reports "Success!" — and fail only at `plan`/`apply` against live
infrastructure. What is not allowed is two recipes setting the same attribute to different values;
that raises `HclMergeConflict`, the run exits `6` and writes nothing. Reconcile the two recipes, or
give them separate resource types. A shared attribute set to the *same* value is fine, and a real
value you supply supersedes another recipe's `TODO` placeholder. Note what the merged block inherits:
the riskiest tier of its contributors, the highest of their provider versions, and the union of their
safety notes — so check that your recipe's tier is right, because it will now also gate someone
else's.

Then prove it end to end:

- `awsremgen verify --provider-schema <schema.json>` passes for the new recipe on **all three** axes.
  **You must pass the flag.** Without it the HCL axis prints `? not checked` and `verify` still exits
  `0` — deliberately, since requiring a 19 MB artifact would make the common path fail, and
  `test_verify_without_a_schema_says_so_and_does_not_claim_a_pass` pins that. So a green exit code is
  *not* evidence your recipe's HCL was checked: the only evidence is the `Schema source:` line in the
  HCL section. Read it. Exit `4` means a check was requested and could not run — an unusable schema
  path, absent service models, a missing CLI surface — which is a different situation from never
  having asked.
- Generated HCL passes **real** `tofu init` / `validate` / `fmt -check` — in its own workspace, per
  file. A substring assertion is not proof; real parsers reject artifacts that substring checks
  accept.
- The generated shell script's identity preflight is exercised: it must exit non-zero and run
  **zero** commands when pointed at the wrong account.
- Tests cover the new recipe at the smallest input size where a bug could appear (two items, two
  accounts, two regions), not just a single happy-path finding.

A new recipe changes the shipped output, so it also changes the committed sample. **There is one
sample per cloud**, and you regenerate the one your recipe affects, in the same commit — CI diffs both
against a fresh run and fails on drift:

```bash
# AWS
awsremgen generate --findings examples/findings.sample.json --out ./artifacts \
  --safety-level caution -v > examples/sample-run.txt 2>&1
rm -rf examples/sample-output && mkdir examples/sample-output
cp -R ./artifacts/. examples/sample-output/    # -R: artifacts are under a per-cloud directory

# Azure. Note: no --safety-level, because all four shipped recipes are `safest` and the
# default already covers them. The first `caution` Azure recipe changes this command, the
# committed sample, and CI's parameter table together -- all three, or the diff fails.
rm -rf ./artifacts
azremgen generate --findings examples/findings.azure.sample.json --out ./artifacts \
  -v > examples/sample-run.azure.txt 2>&1
rm -rf examples/sample-output-azure && mkdir examples/sample-output-azure
cp -R ./artifacts/. examples/sample-output-azure/
```

Run both from the repo root with `./artifacts` as the output, because the console transcript quotes
the output path verbatim and CI normalizes only the timestamp. Clear `./artifacts` between the two:
the second run does not delete files the first wrote, so a stale AWS artifact would be copied into the
Azure sample.

If your recipe covers a policy worth demonstrating, add a finding for it to that cloud's fixture
rather than leaving the sample silent about it. Keep the deliberately-bad records — they are what makes
each sample show rejection and reconciliation instead of only the happy path. In
`findings.azure.sample.json` the cross-subscription record is load-bearing beyond illustration: a
dedicated CI step asserts by name that the run still refuses it and that the wrong subscription id
appears in no artifact, so removing it fails that step rather than quietly reducing coverage.

**Do not weaken an existing safety assertion to make a new recipe pass.** If a new recipe trips a
safety check, the check is usually right. Replace a blanket ban with an exact allowlist that stays
accounted for, rather than loosening the pattern.

## Adding an Azure recipe

Everything above applies, with different sources: the API axis reads the `azure.mgmt.*` SDK packages
bundled inside `az` rather than botocore service models, the CLI axis reads `az <command> --help`
rather than `ac.index`, and the HCL axis reads an `azurerm` schema. Modules go under
`src/remgen/providers/azure/recipes/`, named for the **SDK package** rather than the `az` command
group — the two differ (`az postgres` is `azure.mgmt.rdbms`), and the SDK name wins because that is
what `drift.py` resolves.

Five findings from the first four recipes will save you a rewrite. The first four are recorded in
`src/remgen/providers/azure/recipes/__init__.py`, next to where the dropped recipes would have gone;
the fifth is in `src/remgen/providers/azure/__init__.py`, beside the check that enforces it.

1. **Check `--ids` before choosing a command, not after writing the recipe.** `Recipe` requires
   `{resource_id}` in `cli_template`, and an ARM id can only be passed to a command accepting `--ids`.
   Not every command does: `az keyvault update` does not, so a Key Vault RBAC recipe cannot be
   *expressed* — which is a different failure from cannot be verified, and it is the one that wastes
   your afternoon if you find it last.
2. **Expect the `--subscription` warning, and keep the flag.** With `--ids`, `az` overwrites every
   argument carrying an `id_part` from the parsed id, and `--subscription` carries
   `id_part='subscription'` — so it warns the flag "will be ignored". Leave it in:
   `SubscriptionNotPinnedError` requires it, the script header promises it, and the subscription is
   still explicit because the ARM id contains it.
3. **The schema axis passing does not mean `tofu validate` will.** `azurerm_mssql_server` enforces its
   administrator credentials through `ExactlyOneOf`/`AtLeastOneOf` rules the machine-readable schema
   does not express. That is why the SQL Server TLS recipe was dropped rather than shipped with a
   credential-shaped placeholder, and why the end-to-end `tofu validate` test is not redundant with
   the schema axis.
4. **Never assume one vocabulary from another.** The same setting has three different names: SDK
   `enable_https_traffic_only`, CLI `--https-only`, `azurerm` `https_traffic_only_enabled`. Look each
   one up. Guessing the provider argument from the SDK property is the single most likely way to write
   a recipe that verifies on two axes and fails on the third.

5. **`--ids` outranks `--subscription`, which is a security property and not only a warning.** Item 2
   explains why the flag stays. What it does *not* say, and what cost this project a live defect: the
   same precedence means a finding whose ARM id names a different subscription than its `accountId`
   would have been remediated **in the id's subscription**, from a script whose guard confirmed only
   the other one. `Provider.scope_conflict` now rejects such a finding. If you are adding a recipe,
   the thing to know is that this guard depends on the id's second segment being the subscription —
   so a recipe whose `{resource_id}` is *not* an ARM id (a bare name, a nested child id you have
   rewritten) is outside what that check can see, and needs its own argument for why the target
   subscription cannot be wrong.

Two more things about Azure output that look like bugs and are not. Azure HCL is **not split by
location** — an `azurerm` provider block carries no location, so one file may legitimately span
several. And the scope block is a **weaker guard than the AWS one**: `azurerm` has no
`allowed_account_ids` equivalent, so `subscription_id` selects a subscription rather than asserting
which one is acceptable. `tests/test_azure_hcl.py` asserts the block never *claims* that guard, and
that any mention of the AWS argument is a denial of it — the failure it exists to catch is prose
copied from the AWS block, where the same sentence is true.

Azure recipe tests go in `tests/test_azure_*.py`, not into the AWS files as a cloud-branching
parametrization. Three of Azure's rules are its alone (`--ids` required, `--subscription` required,
`learn.microsoft.com` docs host) and two AWS rules are simply wrong here (`--region`, the
`API_<Operation>.html` URL shape), so a shared parametrization would have to be `if cloud ==` on most
assertions — at which point the two files were never one test.

## Fixture hygiene

Generate test axes independently. Deriving them from one loop counter (`account = i % 40`,
`region = i % 4`) silently couples them, so combination-dependent behavior is never exercised and
any measurement taken on those fixtures flatters the code. This has already caused one bad
measurement in this project's history.

## Gates

All of these must pass, and all of them run in CI as blocking checks:

```bash
pip install -e '.[dev]'
pytest                  # full suite, no -k narrowing
ruff check .
ruff format --check .   # or `ruff format .` to fix
bandit -q -r src/
```

`ruff format` is the autoformatter and `ruff check` is the linter — same binary, different tools, and
CI runs both. Formatting is therefore mechanical: do not spend review comments on it, and do not
hand-format against it. It provably does not change generated output, so reformatting a generator is
safe.

The OpenTofu-backed tests run a real binary, so the suite takes ~30s rather than a few seconds. That
is already the fast path: one warmed workspace is shared for the session, because a fully warm `tofu
init` still costs 16.7s per workspace while `validate` costs 2.0s. Do not skip these tests locally
and do not narrow the suite to the ones you expect to be affected — the ones you did not expect to be
affected are the point.

The first run downloads the AWS provider (a ~147 MB zip that unpacks to ~663 MB) into
`~/.cache/remgen-test-tofu-plugins`, and later runs reuse it. `REMGEN_TEST_TOFU_CACHE` moves it. CI
restores the same directory with `actions/cache`, so a PR does not re-download it either. If you are
offline and `init` cannot reach the registry, the tests **fail** rather than skip — a skip would report
green having validated nothing. `REMGEN_ALLOW_TOFU_INIT_FAILURE=1` opts into skipping, deliberately,
for that case only.

Two things about that cache were verified rather than assumed, because a build cache that can affect a
result is worse than no cache:

- **A stale cache cannot pin an old provider.** With only an older 5.x present, `init` under `~> 5.0`
  still resolves and fetches 5.100.0. The cache never silently decides what you validate against.
- **A corrupt cache fails loudly.** A truncated cached package makes `init` fail with *"does not match
  the content of the downloaded package"*, and the suite reports "`tofu` is present but the template
  workspace could not be initialized, so the parser check never ran." The cache can cost you a red
  build; it cannot produce a green one. If you hit that, delete the directory (or bump the `-v1-` key
  prefix in `ci.yml`).

Note that the suite and the CI sample job check **different provider majors** — the fixtures use
`~> 5.0` (5.100.0) and `.github/provider-check.tf` uses `>= 5.0` (6.58.0). That is left alone on
purpose: both were confirmed to agree on the schema facts this tool depends on, so the spread is extra
coverage. Their plugin caches are keyed separately for the same reason; one shared key would have the
two jobs evicting each other's provider on every run.

### Adding a recipe

`tests/test_recipe_set.py` holds the invariants a new entry has to satisfy, and each one states what
breaks if it does not. Read the failure message before working around it: two recipes on one HCL
resource type, for example, is currently a real defect that `tofu validate` reports as **valid**.

When adding an invariant there, check that it constrains an *authored* field. `safety_tier` and
`safety_notes` are computed properties, so an assertion about them re-implements the derivation and
passes unconditionally — three of the original invariants did exactly that and had to be rewritten.
Prove a new one fails by mutating the recipe set to violate it.

Check the module docstring before writing one: two candidate invariants are recorded there as
**deliberately rejected**, with the reason. Both look like obvious gaps, and one of them (a set-level
assertion about what a merged block inherits) would pass today only because no two shipped recipes
overlap — a test that appears to check the merge while its input makes the check trivial. If you
reject a proposed invariant, add it to that list rather than leaving the next person to rediscover it.

Watch for assertions that depend on a recipe's *position* in the set. The per-service split means
order is now "the order service modules are discovered in", and a test that indexed the set to get a
specific recipe would quietly start testing a different one. The dangerous shape is a negative control
built with `str.replace`: that is silent when the substring is absent, so the mutated recipe comes back
unchanged and the test asserts that a **correct** command is rejected. `tests/test_cli_surface.py`
looks its recipe up by service and asserts the mutation actually landed.

## Scope

Some omissions are deliberate design decisions, not gaps. Before proposing one, read
[ROADMAP.md](./ROADMAP.md): no boto3 generator, no live API adapter, no shared shell-script skeleton,
no provider plugin discovery, and the unresolved question of how to gate non-reversible remediations.
If you want to change one of those, argue the tradeoff rather than just supplying the code.

**A second cloud is in scope, but it is the AWS work again, not a parameterization of it.** The
structure exists (`core` is cloud-neutral, output splits by cloud), and that is the easy part. A new
cloud needs its own verified recipe set, its own safety classification per remediation, its own IaC
mapping, and its own source of API definitions to verify against. A provider descriptor with no
verified recipes is a directory, not support — do not add one **to claim coverage**.

`remgen.providers.azure` shipped as a descriptor with no recipes, and it was not an exception to that
rule — it was the distinction the rule draws. It existed to *test the core*, and every surface said
so: the README called it out under Known limitations, `verify` reported "nothing to check … this is
not a pass" on all three axes, and `generate` wrote nothing. That is the bar for landing a descriptor
early, and it is still the bar; Azure has recipes now, and the zero-coverage behaviour is pinned
against an **emptied copy** of the real descriptor rather than deleted, because it is the state your
new cloud will start in. If you add one, the unimplemented pieces must **raise**, never return a
placeholder: each of
`render_shell`, `hcl_scope_block` and `verify_recipes` has a *legal, quiet* return value that is a
wrong answer with no symptom (`""` is a runnable script that fixes nothing; `""` is also legal HCL
with no scope guard; `()` is indistinguishable from "every recipe passed"). Assert each raise. Two
real crashes surfaced this way during the Azure work and would have been silent passes otherwise.

`tests/test_structure.py` holds the list of names asserted to raise. When you implement one, taking
it off that list is only half the change: the guarantee silently downgrades from *raises* to
*untested* unless real coverage lands in the same commit. All three of Azure's are the worked
example — each left the list as it was implemented, and each removal is paired with an explicit test
asserting the real behaviour and a note in the parametrization recording that it was once a stub.

An implemented piece is not required to mirror AWS's. `remgen.providers.azure.shell` follows the AWS
script's *shape* — emitted never executed, one command per resource, one file per credential scope —
because those are reviewability decisions and not cloud-specific. Its credential guard deliberately
does the opposite: AWS refuses when the active account differs from the target, and Azure does not,
because one `az login` legitimately spans subscriptions and every generated command names
`--subscription` explicitly. If you find yourself "fixing that inconsistency", read
`test_azure_shell.py` first — it asserts the difference in both directions, and the coupling is
enforced at render time by `SubscriptionNotPinnedError`, because the relaxed guard is only safe while
the pinning holds.

**If you add a cloud's CLI-surface axis, pick its source by measuring, not by symmetry with AWS.** The
axis is cloud-neutral; the thing it reads is not. AWS queries `ac.index`, a SQLite table the CLI
ships. Azure ships nothing equivalent, and the three candidates behaved differently enough that the
choice was not a matter of taste — `src/remgen/providers/azure/cli_surface.py` records all three and
why two lost, so you can check whether your cloud has the same shape. Two findings there generalize.
First, **a source that cannot see most of the commands your recipes will name is worse than no
source**, because could-not-check is exit-code-neutral and the axis reports green while blind; that is
what ruled out `az`'s `aaz` trees, and it was only visible after listing the real directories for the
commands a recipe would actually use. Second, **the CLI's internal command loader is not the CLI**:
`az`'s lists flags `az` then rejects and omits one it accepts, so it would have produced false
failures and false passes simultaneously. Ask the CLI, and validate the parse against what the CLI
actually accepts — using **read-only verbs only**. A verifier must never invoke a mutating command,
even one it expects to fail argument parsing; `test_azure_cli_surface.py` asserts that property by
recording every argv the module spawns.

## Cutting a release

The version has **one** source of truth: `__version__` in `src/remgen/__init__.py`. `pyproject.toml`
declares `dynamic = ["version"]` and reads that attribute, so do not add a `version =` line back —
the two copies drifting is what motivated this, and the copy stamped into every artifact header is
the module's, so a mismatch would make `pip show remgen` disagree with the artifacts that install
produced. Keep it a plain string literal: setuptools parses the assignment rather than importing the
module, so anything computed will not resolve at build time.

The **Version, tags and CHANGELOG agree** job enforces the four ways this can drift, so these steps
are not optional bookkeeping — skip one and the build fails.

1. Bump `__version__`. **Regenerate both committed samples in the same commit** — the version is in
   every artifact header, so the `sample` job stays red until you do:

   ```bash
   rm -rf ./artifacts && awsremgen generate --findings examples/findings.sample.json \
     --out ./artifacts --safety-level caution -v > examples/sample-run.txt 2>&1
   rsync -a --delete ./artifacts/ examples/sample-output/
   rm -rf ./artifacts && azremgen generate --findings examples/findings.azure.sample.json \
     --out ./artifacts -v > examples/sample-run.azure.txt 2>&1
   rsync -a --delete ./artifacts/ examples/sample-output-azure/
   rm -rf ./artifacts
   ```

   `--out ./artifacts` is load-bearing, not tidiness: the transcript echoes the path it was given,
   so a different one diffs against the committed transcript and fails for a reason that is not
   drift. Check the diff touches **only** version strings and timestamps — anything else means the
   bump changed behaviour and belongs in its own commit with its own reasoning.
2. Rename `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD` and open a fresh `## [Unreleased]` above
   it. **The dash is an em dash (—)**, matching the existing headings.
3. Merge that PR to `main`, *before* tagging: the job fails on a tag whose CHANGELOG section is not
   yet on `main`. One narrow carve-out keeps this from requiring a red merge — on a **pull request**,
   a version section the PR itself adds may be untagged, since the tag has to point at a merge commit
   that does not exist yet. It is scoped by diffing the base branch's `CHANGELOG.md`, so a section
   already on `main` and still untagged is real drift and stays an error.
4. Tag the merge commit and push **immediately** — `git tag -a vX.Y.Z -m "..." && git push origin
   vX.Y.Z`. Between step 3 and this push `main` is legitimately red, because the carve-out is
   PR-only by design; keep that window to a minute.
5. `gh release create vX.Y.Z --title "..." --notes "..."`

Pick the bump by what changed, not by how much work it was. Pre-1.0, a renamed command or flag is
**MINOR** rather than MAJOR — 0.2.0 carried three breaking renames — because 0.x already tells a
consumer the surface is unstable, and `0.1.0`'s own release note says so. Post-1.0 that stops being
true and the same change is MAJOR. A version consumed by a release commit is spent: do not reuse it
even if the release was never tagged.

## Commits

Explain **why**, not just what. A commit that says "add S3 recipe" is less useful in six months
than one that records which source confirmed the parameter shape and why the safety tier is what
it is.

Do not add model or AI attribution trailers to commits.

## Reporting security issues

See [SECURITY.md](./SECURITY.md) — do not open a public issue for a security problem.
