# Roadmap

This file exists because three source modules point at it (`core/sources.py`,
`providers/aws/recipes/curated.py`, `core/generators/__init__.py`). Each deliberately does *less*
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

## Additional clouds — Azure, GCP, OCI

The structure to hold them now exists. `remgen.core` is cloud-neutral, output already splits by
cloud, and everything cloud-specific reaches the shared pipeline through one
`Provider` descriptor (`src/remgen/core/provider.py`); `src/remgen/providers/aws/` is the worked
example. A test parses imports to keep `core` from depending on any provider, so adding a cloud
cannot quietly change what AWS emits.

**Structure is not coverage, and the hard part is not the structure.** Each cloud needs its own
curated recipe set, its own safety classification per remediation, its own IaC resource and attribute
mapping, and its own source of API definitions to verify against — the equivalent of the AWS
service-model reader. None of that is a parameterization of the AWS work; it is the AWS work again.
A cloud with a provider descriptor and no verified recipes would be a directory, not support.

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
skeleton, no plugin discovery for providers, no deeper scope hierarchy. Each waits for the commit
that adds a real second cloud. Guessing what two clouds share from a sample of one is how the wrong
seam gets frozen in, and this codebase's whole safety argument depends on the seams being in the
right places.

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

- **`verify` checks shape, not semantics.** It confirms an operation and its parameters still exist
  with the expected types. It cannot confirm AWS's behavior is unchanged. Closing that gap
  realistically means integration tests against a live account, which is a substantially different
  project with a real cost.
- **Possible:** pin an expected service-model hash per recipe so a *silent* upstream change is
  reported rather than only outright renames.
- **The AWS service-model canary exists** (`.github/workflows/drift-canary.yml`, weekly). Two further
  upstream surfaces are still unwatched, and both are blocked on validating generated HCL against the
  provider *schema* rather than only its parser: the `hashicorp/aws` provider schema (an attribute
  renamed or made required breaks emitted HCL while `tofu validate` on the current provider still
  passes) and AWS CLI flag spellings (the service model constrains the API parameter, not the
  `--flag` the script actually types). Until then, drift in either is caught only by a human reading
  a failure.

## Operational

- **CI-friendly exit codes** are already distinct; documenting them as a stable contract (so a
  scheduler can branch on them) would make them a compatibility promise worth keeping.
- **Findings-count reconciliation** is enforced internally; surfacing it as a machine-readable
  summary would let pipelines assert that nothing was dropped.
