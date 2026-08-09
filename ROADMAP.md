# Roadmap

This file exists because three source modules point at it (`core/sources.py`,
`providers/aws/recipes/__init__.py`, `core/generators/__init__.py`). Each deliberately does *less*
than it could, and this is where the reasoning lives so a reader can check it rather than guess.

Nothing here is a commitment to a date. Items are ordered by what would most increase the tool's
value per unit of added risk.

## The open question: should later versions ship non-reversible remediations?

This is the decision that most changes the tool's character, and it is deliberately unresolved.
Recording the shape of it so it can be decided on purpose.

**Where things stand today.** Non-reversible remediations already ship, but never by default. KMS
automatic key rotation cannot be fully undone once enabled, and it is classified `caution`, so
`--safety-level safest` (the default) will not emit it. A user must pass `--safety-level caution` to
get it. So the current answer is *"yes, gated behind an explicit flag."*

**Why that may not be enough.** `--safety-level` is a single decision applied to a whole run. A user
who passes `--safety-level caution` for one recipe they understand gets *every* caution-level recipe
in the same breath, including ones they have not thought about. The flag communicates "I accept risk
in general," not "I accept this specific irreversible change to these specific resources." Those are
different consents, and the tool currently cannot tell them apart.

Renaming `--tier` to `--safety-level` did not change this. It made the flag say what it gates; it
still gates a whole run.

**Options, with the tradeoff each makes.**

1. **Keep `--safety-level` as-is.** Simplest, and already conservative by default. Cost: the
   whole-run consent problem above.
2. **Per-recipe opt-in** (`--allow kms-key-rotation`), where irreversible recipes require naming
   the specific recipe rather than a level. Consent becomes specific. Cost: more friction, and a
   longer command line that users will be tempted to script around — at which point the friction
   stops working.
3. **Emit irreversible remediations, but commented out** with the warning and the enabling
   instruction inline. The artifact documents the fix without arming it. Cost: a reviewer may
   uncomment mechanically without reading, and it makes the artifact less directly runnable.
4. **Split them into a separate output file** (`irreversible.sh`) that must be run deliberately.
   Cost: another file to reconcile, and it fragments the per-cloud/per-account/per-region layout that
   currently has a correctness justification.
5. **Never ship them.** Safest, and cheapest to reason about. Cost: excludes real security value —
   key rotation is genuinely worth doing.

**How the warnings would need to work regardless of the choice.** The current rule stands and
should not be traded away: irreversibility, cost, and blast-radius warnings stay **inline in the
artifact**, next to the specific resource they apply to, never hoisted to a header or a companion
file. A warning a reader has to go find is a warning that gets skipped. Reference detail
(prerequisites, docs links, summaries) may be hoisted; consequence warnings may not.

**Also unresolved:** whether "irreversible" and "expensive" deserve separate levels. They are
currently both `caution`, but they fail differently — one is a permanent state change, the other is
a recurring invoice. A user might reasonably accept one and refuse the other.

**Recommendation if it must be decided now:** option 2 (per-recipe opt-in) for irreversible
changes, keeping `--safety-level` for cost-scaled ones. It matches consent to the actual unit of
risk. This should be settled before coverage grows much, because every recipe added under the
current scheme makes changing it more disruptive — and adding a second cloud multiplies that, since
each one brings its own irreversible operations under the same flag.

## Coverage

- **More curated recipes.** The constraint is not effort, it is verification. Each recipe needs its
  API call, parameters, HCL resource/attribute, reversal command, and safety classification checked
  individually against the AWS service model and AWS documentation. Bulk generation is the failure
  mode this project is organized to avoid.
- **Explicitly excluded, and why:** VPC flow logs is a single API call but bills on ingested volume
  with no ceiling. It stays out of the default set regardless of how easy it is to script. Ease of
  scripting is not a safety argument.
- **Which policies, specifically:** there is one register per implemented cloud —
  [AWS_POLICY_TRIAGE.md](AWS_POLICY_TRIAGE.md) (237 AWS-only policies) and
  [AZURE_POLICY_TRIAGE.md](AZURE_POLICY_TRIAGE.md) (217 Azure-only) — each assigning every policy to
  one of four buckets: shipped, write-a-recipe-now, blocked on a named prerequisite, or documented
  rejection. Each carries its rejection classes and a prioritised, service-batched recipe list. The
  VPC flow logs exclusion above is one member of one AWS class; the register generalises it. Both also
  record what they do *not* cover: the `Custom`, `KubernetesAdmissionController` and uncategorised
  policies, which no pass has triaged.
- **The design ceiling, per cloud, is the number worth quoting** rather than a coverage percentage:
  61 of 237 for AWS (26%), 76 of 217 for Azure (35%). The rest cannot be expressed as one idempotent,
  reversible, per-resource API call, and the registers say why by class rather than by policy. Azure's
  ceiling is higher because `az <service> update --ids` is a more uniform surface than AWS's
  per-service APIs — and Azure has one rejection class AWS does not, for the commands where that
  uniformity fails.
- **Recipes are split one module per AWS service** (`recipes/dynamodb.py`, `recipes/rds.py`, ...),
  because the service is the unit the *verification* is done in: one API model, one CLI command group,
  one set of provider resource types. A single growing file made a new recipe's diff span everything,
  which is the shape under which a change to an unrelated remediation is easiest to miss.
  The modules are discovered rather than listed, since the failure mode of a list is silent — the
  recipe exists and is never returned, so the policy reports as *unsupported* and no test goes red.
- **Not planned: subdividing further than service.** A per-policy file would put the set-level
  invariants (import-id collisions, merge conflicts, duplicate titles) at a distance from every file
  they constrain, and those are the invariants that catch the mistakes real parsers do not.

## Additional clouds — GCP, OCI

**Azure is no longer on this list.** `azremgen` ships curated recipes verified on all four
axes, generates both formats, has a committed sample regenerated by CI on every push, and has its own
job in the drift canary. Its coverage is partial and that is stated wherever it matters — but it is
support, not structure. What remains Azure-specific work lives under [Azure coverage](#azure-coverage)
below rather than here.

The structure to hold the rest exists. `remgen.core` is cloud-neutral, output already splits by cloud,
and everything cloud-specific reaches the shared pipeline through one `Provider` descriptor
(`src/remgen/core/provider.py`); `src/remgen/providers/aws/` and `src/remgen/providers/azure/` are two
worked examples rather than one. A test parses imports to keep `core` from depending on any provider,
and to keep the two providers from importing each other, so adding a cloud cannot quietly change what
either existing one emits.

**Structure is not coverage, and the hard part is not the structure.** Each cloud needs its own
curated recipe set, its own safety classification per remediation, its own IaC resource and attribute
mapping, and its own source of API definitions to verify against — the equivalent of the AWS
service-model reader. None of that is a parameterization of the AWS work; it is the AWS work again.
Azure is the evidence, and the surprise was where the work landed: adding it produced four recipes
and a longer list of defects in **shared** code than in the new provider — `verify` passing on an
empty recipe set, a CLI axis that returned 0 while printing nothing, `--max-per-file` describing
Azure's split in AWS's vocabulary, `AmbiguousImportError` saying "account" on every cloud, and a
cross-subscription escape that had no AWS analogue at all. Every one was an AWS-shaped assumption
that had looked correct for exactly as long as there was one cloud. A cloud with a provider descriptor
and no verified recipes would be a directory, not support; a cloud added without re-examining `core`
would ship the second cloud's bugs into the first.

Known per-cloud differences already accounted for in the design:

- **Credential scope is not "account" everywhere.** Azure has subscriptions, GCP has projects, OCI
  has compartments and tenancies. The scope is carried as `scope_id` with the cloud's own word in
  `scope_noun`, so a correct split is never described in the wrong cloud's vocabulary.
- **Region is not always a provider-level binding.** `hashicorp/aws` sets region on the provider, so
  HCL must split per region. `azurerm` takes `location` per resource and would not. This is declared
  per provider rather than assumed, because assuming AWS's answer would over-split Azure output for
  no correctness reason.
- **A scope hierarchy deeper than two levels.** GCP projects nest under folders and organizations;
  OCI compartments nest arbitrarily. The layout is deliberately two levels deep today and will need
  revisiting for those, which is why it was not generalized in advance from a sample of one.

**Deliberately not built yet, and stated in the relevant docstrings:** no shared shell-script
skeleton, no plugin discovery for providers, no deeper scope hierarchy. A real second cloud now
exists, so the first of those is no longer waiting on evidence — and the evidence says **do not build
it**. Azure's script generator is not a translation of the AWS one: the guard checks reachability
rather than identity, because one `az login` spans subscriptions, and a shared skeleton would have to
parameterize the part that is actually different. The other two still wait for a third cloud.
Guessing what N clouds share from a sample of one is how the wrong seam gets frozen in, and this
codebase's whole safety argument depends on the seams being in the right places.

## Azure coverage

Referenced by `src/remgen/providers/azure/recipes/__init__.py`, which records each measurement beside
the recipe it constrains.

Four recipes ship: three `azurerm_storage_account` settings (HTTPS-only, minimum TLS version,
cross-tenant replication) and `azurerm_mssql_database` transparent data encryption. All four are
`safest`. That is not a claim Azure is safer — it is what a first recipe set looks like when the
riskier candidates are deferred rather than reclassified.

**Two policies were investigated and deliberately left uncovered**, because the shape of a correct
recipe does not exist for them rather than because nobody got round to them. Both are recorded here so
the next person does not spend the same afternoon rediscovering them:

- **Key Vault RBAC authorization.** `az keyvault update` accepts no `--ids`. Every shipped Azure
  recipe pins its target subscription *through* the ARM id in `--ids`, so a recipe here could not be
  expressed at all without weakening the one property the Azure guard rests on. Not a missing recipe;
  a missing command shape.
- **SQL Server minimum TLS version.** `azurerm_mssql_server` enforces `administrator_login` and
  `administrator_login_password` through `ExactlyOneOf`/`AtLeastOneOf`, which the JSON schema does not
  express. So the schema axis *passes* and `tofu validate` then fails — a recipe that verifies green
  and produces HCL that does not load. This is the clearest case yet that the schema axis is
  necessary and not sufficient.

What would extend coverage, in rough order of value:

- **A `caution`-tier Azure recipe.** Until one exists, `--safety-level` is untested on Azure by
  anything but AWS's fixtures, and the Azure sample deliberately passes no level flag. The first one
  to land changes that command, the committed sample, and CI's parameter table together.
- **Recipes whose CLI command takes no `--ids`.** These need a different subscription-pinning
  argument than "the ARM id contains it", and `SubscriptionNotPinnedError` exists so that such a
  recipe cannot be added without confronting the question.
- **A constraint the schema axis cannot see.** The SQL Server case above is currently absorbed by not
  shipping the recipe. Covering that class properly means a fourth axis that runs `tofu validate` on
  generated HCL — which the test suite already does for the *shipped* recipes, so the gap is in
  `verify` rather than in the tests.

## Sources — a live Tenable Cloud Security API adapter

Referenced by `src/remgen/core/sources.py`.

Findings are read from a JSON file you export. A live API adapter is not implemented because doing
it properly needs tenant credentials to verify against, and an adapter that has never run against a
real tenant would be untested code wearing the costume of a feature. `core/sources.py` defines the
interface such an adapter would implement, so the shape is settled even though the implementation
is not.

Prerequisites for building it: a test tenant, a decision on credential handling (never a plaintext
file — OS keyring or environment injection), pagination and rate-limit behavior verified against
real responses, and reconciliation between the API's finding count and the tool's processed count
so a silently truncated page cannot look like a clean run.

## Generators

Referenced by `src/remgen/core/generators/__init__.py`.

- **No boto3/Python-SDK generator.** It would be a third rendering of the same `ApiCall` with no
  capability the CLI script lacks, and every additional format is another surface that can silently
  drift from the service model. Adding it needs a concrete use case the existing two formats
  cannot serve. If one appears, `--format` already takes a list, so it is a new value rather than a
  new flag.
- **Possible:** a machine-readable plan output (JSON) describing what *would* be emitted, for
  pipelines that want to gate on the diff before artifacts exist.

## Verification

- **`verify` checks shape, not semantics — on all three cloud axes.** It confirms that an operation, a
  provider argument and a CLI flag still exist with the expected shapes. It cannot confirm AWS's
  behavior is unchanged, that a flag still means what it meant, or that a provider argument still maps
  to the same API field. Closing that gap realistically means integration tests against a live
  account, which is a substantially different project with a real cost.
- **Possible:** pin an expected service-model hash per recipe so a *silent* upstream change is
  reported rather than only outright renames. The same idea applies per-axis now: a schema hash and an
  `ac.index` hash would each turn "renamed" into "changed at all".
- **The HCL axis takes a schema file rather than generating one.** `verify` deliberately does not run
  `tofu`: producing a schema downloads the provider, and a tool whose entire safety argument is "it
  makes no network calls and invokes no binaries" should not fetch hundreds of megabytes from a
  registry. The cost is a setup step, and a `not checked` on a default invocation — exit-code-neutral,
  so the printed section rather than the exit status is what distinguishes "checked" from "skipped". A
  `--generate-schema` flag would remove the step and the property; the property is worth more. The
  policy axis reports `not checked` the same way for a stronger reason: it needs a `--catalog` export
  and there is no live Tenable adapter to fetch one even in principle, so unlike the schema this is
  not a step the tool is declining to take.
- **The CLI axis depends on an internal AWS CLI file.** `awscli/data/ac.index` is the CLI's own
  autocomplete index, not a documented interface, and AWS may restructure or drop it. It is read
  read-only and its absence degrades to exit `4` rather than a false pass, so the failure mode is
  "unwatched", not "wrong" — but there is no stable public alternative, and deriving flag names from
  the service model is not one: a derived flag is checked against the derivation, which makes a
  CLI-side rename invisible. Two install layouts are searched (package and PyInstaller bundle); a
  third would need adding to `_INDEX_PATTERNS`.
- **`tofu validate` cannot catch a wrong `import` id, and never will.** Two `import` blocks carrying
  the same `id`, or an `id` that names no resource at all, are both *valid configuration* — real
  `validate` reports "Success!", because resolving an id requires calling the cloud. So the generator
  asserts these itself (`HclMergeConflict`, `AmbiguousImportError`, exit `6`) rather than relying on
  the parser, and the `.tf` header tells the reader to check that `plan` reports
  `N to import, 0 to add`. That plan check is the only place a wrong-but-well-formed id is visible,
  and it needs live credentials, so it stays a documented human step rather than a gate.
- **All three cloud upstreams are now watched weekly** (`.github/workflows/drift-canary.yml`), against
  the *newest* published botocore, provider and runner-bundled CLI rather than pinned ones — a pinned
  canary verifies a snapshot and reports "no drift" forever. Each verdict files its own issue, because
  each is a different fix in a different file and two can be open at once. Exit `4` ("an axis could not
  run") files an issue too and is treated as worse than red: a red run names a fix, a blind one reports
  nothing.

  **Three upstreams watched, four axes reported, and the gap is deliberate.** The policy axis needs a
  Tenable catalog export, and a public scheduled workflow has no tenant to get one from — so the canary
  reports it as not run rather than as passing. It still carries a branch for exit `9`, which it cannot
  currently reach: without one, the first real retirement would fall through to "the canary itself is
  broken" and be diagnosed as the wrong problem. Watching this axis needs a credentialed runner, which
  is a different decision from anything else on this list.
- **`schedule` triggers are the weak link, and nothing in this repo can fix it.** GitHub disables them
  after 60 days of repository inactivity and does not re-enable them when activity resumes — so the
  canary's own liveness is asserted by a job in `ci.yml`, which runs on every push. A canary that
  silently stopped running is indistinguishable from one that keeps passing.
- **The provider plugin cache is deliberately absent from the canary**, and present in the two `ci.yml`
  jobs that parse HCL. Every `tofu init` otherwise fetches a 147 MB provider zip, and the two jobs run
  four inits between them. Two properties were verified before trusting it, because a build cache that
  can influence a *result* is worse than no cache: a stale cache does not pin an old provider (`init`
  under `~> 5.0` still resolves 5.100.0 with only an older 5.x cached), and a corrupt one makes `init`
  fail outright rather than validate against a damaged package. So the cache can cost a red build and
  cannot manufacture a green one. The canary is excluded on different grounds — it exists to fetch an
  upstream nobody has seen, so a cache would almost always miss and would invite the question of
  whether a cached artifact is what it compared against.
- **The suite and the sample gate check different provider majors** (`~> 5.0` → 5.100.0 in the test
  fixtures; `>= 5.0` → 6.58.0 in `.github/provider-check.tf`, since the AWS provider released 6.x).
  Left as-is on purpose: both were confirmed to agree on the two schema facts this tool depends on, so
  the spread is coverage rather than an inconsistency. It does mean their caches must be keyed
  separately, or the two jobs evict each other's provider on every run.

  Note that neither is the bound the *generated* HCL carries. That comes from
  `Provider.tf_provider_verified_major` — 6 for `hashicorp/aws`, 5 for `hashicorp/azurerm` — and it is
  the one of the three a user actually inherits, so raising it is a claim that the recipes were
  re-verified rather than a CI-configuration change.

## Operational

- **CI-friendly exit codes** are already distinct; documenting them as a stable contract (so a
  scheduler can branch on them) would make them a compatibility promise worth keeping.
- **Findings-count reconciliation** is enforced internally; surfacing it as a machine-readable
  summary would let pipelines assert that nothing was dropped.
