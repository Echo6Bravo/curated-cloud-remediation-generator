# curated-cloud-remediation-generator (`awsremgen`)

Turns Tenable Cloud Security findings into **review-ready remediation artifacts** — a vendor CLI
script and import-aware OpenTofu/Terraform configuration — for a deliberately small, curated set of
policies.

**Two clouds have coverage: AWS (`awsremgen`) and Azure (`azremgen`).** The shared pipeline lives in
`remgen.core` and each cloud is a provider under `remgen.providers`, so GCP and OCI can be added
without editing the code that decides what AWS emits. Coverage is deliberately uneven and far from
complete on either cloud — see [Known limitations](#known-limitations) for what each one does and
does not do. There is deliberately no `remgen` umbrella command: see
[One command per cloud](#one-command-per-cloud).

**It never modifies your cloud.** It writes files to a directory. You read them, you decide, you
run them.

```bash
awsremgen recipes                                            # what is supported, and how risky each is
awsremgen verify                                             # do the recipes still match upstream, on all four axes?
awsremgen generate --findings findings.json --out ./artifacts
```

## See it before you install it

[`examples/`](./examples) holds a complete real run **per cloud**, committed: the input findings, the
console output verbatim, and every artifact each produced. Start with
[`examples/README.md`](./examples/README.md), which walks through why one input produced five
artifacts, what a `TODO` placeholder means, and what happens to a malformed finding.

Then [`examples/README.azure.md`](./examples/README.azure.md) for the Azure run. It covers only what
*differs* rather than repeating the shared explanation: why Azure's HCL never splits by location,
why the guard checks reachability instead of identity, why `az` prints
`option '--subscription' will be ignored` on every line and the flag stays anyway, and the one
rejection AWS cannot have.

CI regenerates both samples on every push and fails if either differs, so neither can quietly become
a picture of an older version.

## One command per cloud

`awsremgen` is the whole interface for AWS. There is no `remgen --cloud aws`, and that is a
deliberate choice rather than an unfinished one.

A cloud flag would make the cloud a runtime value in a tool whose entire safety argument is about
scope. Every generated artifact is bound to one cloud, one credential scope and (for HCL) one
region, and the value that decides which is the same value that decides which recipes, which API
verifier and which identity preflight apply. Reading that from a flag means a typo selects a
different cloud's recipe set against the credentials you have loaded. Reading it from the command
name means the wrong cloud is not a state the program can reach — `awsremgen` is compiled against
exactly one `Provider`.

It also keeps `--help` honest. Help text, examples, the safety table's wording and the credential
noun in every filename all come from that provider, so what the command prints describes what the
command does. A multi-cloud command would have to describe all of them, or describe none
specifically.

Adding a cloud therefore adds a command (`azremgen`, `gcpremgen`) and a directory under
`src/remgen/providers/`, and touches nothing under `src/remgen/core/`. A test in
`tests/test_structure.py` enforces that direction by parsing the imports rather than trusting the
convention: `core` may not import from `providers`, and no provider may import another. That rule is
only now testable — with one cloud it had no counterexample, and the tempting violation was real:
Azure needs a shell generator and AWS has one. Azure got its own, sharing only the genuinely
cloud-neutral helpers in `core`. That turned out to matter rather than being a formality, because the
one piece that looked most reusable — the credential-scope guard — has to behave *differently* on
Azure, where a single login legitimately spans subscriptions. Importing the AWS generator would have
carried that guard along with the parts that do transfer.

`azremgen` is the first exercise of this. It was deliberately installed *before* its recipes existed,
because an abstraction validated against a single provider is a guess: the only way to tell
"cloud-neutral" from "AWS with the strings moved" is to run the same pipeline down a second
descriptor. Doing so immediately surfaced four defects in `core` — a `verify` that reported a pass
having checked nothing, an axis that returned success while printing nothing, two crashes, and help
text that described Azure output in AWS's vocabulary. All four are fixed, and none was visible from
the AWS side.

Writing the recipes then reversed the direction: Azure pushed back on the *design*, three times, and
each correction is recorded in the code beside the thing it changed. A planned Key Vault recipe could
not be written at all, because `Recipe` requires the template to name `{resource_id}` and
`az keyvault update` does not accept `--ids`. A planned SQL Server recipe could not be written
either, because the provider requires an administrator password through a cross-argument rule the
machine-readable schema does not express — so satisfying it would have meant emitting a
credential-shaped placeholder into generated configuration. And the API axis's original plan, reading
`az`'s `aaz` command trees, was abandoned on measurement: only 5 of 18 candidate commands have an
`aaz` leaf, and the two most valuable were both absent.

## What this is, and what it is not

The name is literal, and each word in it is a limitation worth stating plainly.

**Curated.** Coverage is partial by design and will stay that way. This release ships **6 recipes**
for AWS and **8 recipes** for Azure. Tenable Cloud Security has far more policies than that on both
clouds, and most of them are *scriptable* — but scriptable is not the same as safe to script
universally, and the gap between those two is where an automated remediation hurts someone. Every
recipe here was written and checked individually against that cloud's own API definitions and
documentation. None were generated in bulk.

The clearest evidence that this is curation rather than triage: one Azure remediation passes all
three verification axes and is still excluded. Disabling Shared Key access on a storage account is a
genuinely good hardening step, and it breaks every caller using an account key or a SAS — which is
most tooling, including parts of `az` itself. That is a migration, not a single call, and shipping it
beside seven storage settings that break nothing would misrepresent it.

**Generator, not an agent.** The tool produces text. It holds no cloud credentials, makes no cloud
API calls, and has no code path that mutates a cloud environment. The artifacts it writes are
inert until you run them yourself.

**Best-effort.** The generated commands and configuration are derived from the AWS service models
and public AWS documentation as they existed when the recipe was written, and are re-checked by
`awsremgen verify` against the service models, the provider schema and the CLI's own flag surface
installed on your machine. That is a strong check, not a guarantee. AWS changes APIs, your account may have organizational policies (SCPs), resource
states, or drift the tool cannot see, and a command that is correct in general can still fail — or
succeed in a way you did not intend — in your specific environment. **Review every artifact before
running it, and run it somewhere non-production first.** Treat the output as a well-informed first
draft written by someone who cannot see your account.

**Not an official Tenable product.** This is a community contribution authored by a Tenable
employee (hence `Copyright (c) 2026 Tenable, Inc.` on the MIT license). It is not supported by
Tenable, and it is not part of the Tenable Cloud Security product.

## How the remediations are generated

There is no model in the loop and nothing is inferred at runtime. The chain from a finding to an
artifact is fixed and inspectable:

1. **A curated recipe** (`src/remgen/providers/aws/recipes/`, one module per AWS service) maps one
   Tenable Cloud Security policy UUID to one AWS API call, its parameters, the equivalent
   Terraform/OpenTofu resource type and attribute, and an explicit safety classification. These are
   hand-written. Each carries the policy UUID from the live catalog so it can be traced back.
2. **Findings are parsed as untrusted input.** Every record is validated. A record that fails
   validation is collected as an explicit *rejection* rather than dropped, so the input count
   always reconciles with the output count — a silently discarded finding would be a missed
   remediation that looks like a clean run.
3. **Two generators render the same validated call** — a fail-fast `aws` CLI shell script, and
   import-aware HCL that adopts the existing resource rather than proposing to create a new one.
   Both render from the same `ApiCall`, so they cannot disagree about what will happen. Pick one
   with `--format cli` or `--format hcl`; both are written by default. On the HCL side, one live
   resource gets exactly one `import` + `resource` pair no matter how many policies it violates:
   two `import` blocks naming the same resource are *valid configuration* — `validate` passes — and
   fail only at `plan`/`apply` against live infrastructure, so the generator merges them instead and
   refuses to emit anything if two recipes disagree about a value.
4. **`awsremgen verify` re-checks every recipe against all four upstreams it depends on**, because
   they are maintained by different people and rot independently — see
   [What `verify` actually checks](#what-verify-actually-checks). All four always run, so one
   broken upstream cannot hide a second behind it.
5. **`awsremgen policies` diffs the policy catalog** against a local snapshot from your last run.
   New policies are **reported, never auto-remediated** — an unreviewed policy has no recipe, and
   inventing one automatically is precisely the failure this design refuses.

## What `verify` actually checks

A recipe depends on **four** upstreams, owned by four different projects, which change on their own
schedules. Checking one and reporting a pass is how a shipped artifact rots in silence, so `verify`
checks all four and always reports all four:

| Axis | Source | What breaks if it moves | Exit |
| --- | --- | --- | --- |
| **API operation and parameters** | AWS service models (`service-2.json`, from your AWS CLI v2 or botocore install) | The operation or a parameter was renamed — AWS rejects the call | `3` |
| **HCL resource type and arguments** | `hashicorp/aws` provider schema (`tofu providers schema -json`) | The generated `.tf` no longer loads, or a `TODO` stub claims to be required when it is not | `7` |
| **Rendered `aws` command** | The AWS CLI's own autocomplete index (`awscli/data/ac.index`) | The subcommand or a flag was renamed — the generated script fails with "Unknown options" | `8` |
| **Policy id** | Your Tenable policy catalog export (`--catalog`) | The policy was retired, so the recipe matches zero findings and silently never fires again | `9` |

Why four rather than one: the AWS CLI is free to rename `--deletion-protection-enabled` while
`dynamodb.UpdateTable` keeps its `DeletionProtectionEnabled` member, and the Terraform provider is
free to rename an argument while both of those are untouched. Each of those breaks a file this tool
already wrote, and each is invisible to the other checks. The reverse command in each artifact —
the one someone runs in a hurry, having just broken something — is checked too.

The fourth axis is the odd one out, and the reason it exists is the failure mode it catches. The other
three ask a cloud whether a remediation is still *correct*; this one asks Tenable whether the finding
still *exists*. A recipe keyed to a retired policy id passes all three cloud axes perfectly and then
matches nothing, forever — which produces no error, no warning, and an empty artifact set that looks
exactly like a clean estate. It is exit `9`, last in precedence, because a wrong API call runs against
live infrastructure while this one merely never runs at all. It needs `--catalog`: there is no live
Tenable adapter in this tool, so without an export the axis reports that it did not run.

The flag names are read from the CLI's own index rather than derived from the API member names.
Derivation looks like kebab-casing and is not (`DBInstanceIdentifier` → `--db-instance-identifier`),
and more importantly a derived flag would be checked against the derivation instead of against the
CLI, making a CLI-side rename — the exact drift this exists to catch — invisible.

The sources in that table are AWS's. The **axes** are cloud-neutral; the thing each axis reads is
not, and Azure demonstrates why that distinction is in the design. Azure ships no equivalent of
`ac.index`, so `azremgen`'s CLI axis asks `az <command> --help` and parses it — the CLI's own
statement of its surface. That means it needs `az` installed rather than a bundled data file, and
that a missing `az` is reported as could-not-check rather than as a pass. Which `az` answered is
printed on the `Flag source:` line, so a drift report can be reproduced.

**A check that could not run is never reported as a pass.** An axis whose inputs are missing prints
`not checked` and never a pass line. Where it was *asked* for and could not run — an unusable schema
path, absent service models, no CLI surface — it exits `4`, which the weekly
[drift canary](./.github/workflows/drift-canary.yml) treats as worse than red: a red run names a fix,
a blind one reports nothing. The one case that is exit-code-neutral is a bare `verify` with no
`--provider-schema`, because requiring a 19 MB artifact would make the default invocation fail; there
the printed `not checked` is what carries the signal, so read the section rather than the exit code. No axis is entirely free of setup, and what each needs differs by
cloud: AWS's API axis reads a data file its CLI already bundles, Azure's two need `az` itself present,
and **both** clouds' HCL axis needs a schema you generate, because producing one downloads the
provider and this tool does not shell out:

```bash
mkdir -p /tmp/schema-ws
cat > /tmp/schema-ws/main.tf <<'TF'
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
TF
tofu -chdir=/tmp/schema-ws init -backend=false
tofu -chdir=/tmp/schema-ws providers schema -json > /tmp/schema.json

awsremgen verify --provider-schema /tmp/schema.json   # or export REMGEN_TF_SCHEMA=/tmp/schema.json
```

For Azure, the same procedure with `azurerm = { source = "hashicorp/azurerm" }`, written to a
different path, then `azremgen verify --provider-schema /tmp/az-schema.json`. Two schemas, not one:
`tofu providers schema -json` keys its output by provider source address, so a document is for one
provider. Handing either command the other cloud's schema is caught by that lookup and reported as
`schema unusable` with exit `4` — could-not-check, not a pass.

### What the schema check found on the shipped recipes

It was not a formality. Four arguments this generator stubbed as `TODO` because the AWS provider
*documentation* describes them as required — `aws_dynamodb_table`'s `hash_key` and `attribute` block,
`aws_db_instance`'s `engine`, `allocated_storage` and `username` — are `optional` in the schema. Docs
describe what *creating* a resource needs; the schema describes what the parser demands, and only two
of the six stubs were genuinely required.

On a resource adopted by `import`, that gap is not cosmetic. Omitting an optional argument means
"keep the live value" and produces no diff. Emitting `hash_key = "TODO"` means "set it to the literal
string `TODO`" — and `hash_key` forces replacement, so applying it **destroys and recreates the
table**. `tofu validate` accepts both files identically. That is why a false "the provider requires
this" claim is now a *failure* of the HCL axis rather than a redundant line, and why the four stubs
are gone from the recipes and from `examples/sample-output/`.

## Safety is a level, not a disclaimer

Remediations are classified, and the default emits only the safest ones. `awsremgen recipes` prints
the classification and the reversal command for every recipe.

Levels are **cumulative**: each includes everything less risky, because "I accept irreversible
changes" does not mean "and not the safe ones".

| `--safety-level` | What it adds | Emitted by default |
| --- | --- | --- |
| **safest** | Reversible, no data-path impact, no restart or replacement, no usage-scaled cost. | Yes |
| **caution** | Also irreversible changes, added cost, and anything that interacts with teardown workflows. | No — `--safety-level caution` |
| **all** | Also changes that can affect availability. | No — `--safety-level all` |

Two consequences of this that are easy to miss:

- **Selection was constrained by safety, not by effort.** Policies were excluded from v1 even when
  the remediation is a single API call. VPC flow logs is the standing example: one call, but it
  bills on ingested volume with no ceiling, so enabling it fleet-wide from a script can produce a
  surprising invoice. That belongs behind a deliberate decision, not a default.
- **Warnings stay inline, next to the thing they warn about.** Every irreversibility note, cost
  note, and reversal command is emitted in the artifact itself, not only here. A warning in a
  different file is a warning that gets skipped.
- **A tier is derived, so one warning is authored.** `safest` is computed from four fields —
  reversible, ongoing cost, data-path impact, whether it blocks `tofu destroy` — and none of them
  means "withdraws access something is using today". S3 Block Public Access is reversible, free and
  applied in place, so it derives to `safest` honestly, and it stops anonymous reads the moment it
  runs. A recipe can therefore promote one caveat to render inline beside the command, marked `!!`.
  Six recipes across both clouds use it; every other caveat lives in the run's `README.md`, because
  repeating a paragraph of reference text beside each of hundreds of commands is what made comments
  most of the output. The bar is stated and tested: `caution` and `disruptive` recipes may not use
  it — their banner already says to read every note — and a promoted caveat may not paraphrase a note
  the four fields already produce.

Of the 6 shipped AWS recipes, **2 are `safest`** and **4 are `caution`** — so a default run is
conservative, and most of the AWS set requires you to opt in explicitly. Of the 8 shipped
Azure recipes, **8 are `safest`**, which is not a claim that Azure is safer: it is what a first
recipe set looks like when the riskier candidates are deferred rather than reclassified. The one
Azure remediation that would have landed in a higher tier was excluded instead — see
[What this is, and what it is not](#what-this-is-and-what-it-is-not).

## Output is split so a human can actually review it

Artifacts are split **per cloud**, then **per account**, and HCL additionally **per region**. The
account and region splits are a correctness requirement rather than tidiness: neither an `aws` CLI
invocation nor a Terraform/OpenTofu provider can target more than one account at a time. A single
file spanning two accounts would resolve resource identifiers against whichever account the runner
happens to be authenticated to — a same-named table in the wrong account could be adopted and
reconfigured while the run reports success. Nothing throws. That is why the split is not optional.

```
artifacts/
├── README.md          ← one per run: review checklist and policy reference
├── manifest.json      ← one per run: machine-readable index of every file
└── aws/
    ├── remediate-aws-111111111111-all-regions.sh
    └── remediate-aws-111111111111-us-east-1.tf
```

The cloud is both a directory and part of every filename, so a file stays self-describing after
someone copies it out of the tree. `README.md` and `manifest.json` sit at the top rather than once
per cloud, because reconciling a run — confirming a finding that produced no artifact was *withheld
or unsupported*, not lost — is a property of the whole run and would be unanswerable from any single
per-cloud index.

Region is a hard boundary for HCL only when a cloud's Terraform provider is region-scoped, which
`hashicorp/aws` is (region is set on the provider). It is a soft one for the CLI, where `--region`
travels on each command — which is why `.sh` files say `all-regions`. That property is declared per
provider rather than assumed, since `azurerm` takes `location` per resource and would not split the
same way.

`--max-per-file` adds a further *soft* cap for reviewability (default 500, `0` disables it). It
does not and cannot relax the cloud/account/region split.

Generated AWS shell scripts include an identity preflight: they check the caller's account with
`aws sts get-caller-identity` and **exit non-zero without running anything** if it does not match
the account the file was generated for. HCL sets `allowed_account_ids` on the provider for the same
reason.

**Azure's preflight deliberately does the opposite, and the difference is not an inconsistency.** An
AWS credential set names exactly one account, so "these credentials are for the wrong account" is a
fact a script can establish and refuse on. One `az login` routinely spans many subscriptions, and
`--subscription` is a global argument every mutating command accepts — so refusing on an
active-subscription mismatch would be both unhelpful (the user's default is often simply a different
subscription they legitimately hold) and misleading, because it implies the active subscription is
what determines the target when the command names it explicitly. The Azure script checks
*reachability* instead and reports a mismatch as information. That relaxation is only safe while
every command pins its subscription, so it is enforced at render time: `azremgen` refuses to write a
command that does not, rather than trusting the recipe author.

### The cross-subscription conflict, and why only Azure has one

Pinning `--subscription` on every command turned out not to be sufficient, and the gap is worth
stating plainly because it was real shipped behaviour rather than a hypothetical.

An ARM resource id begins `/subscriptions/<id>/`, so an Azure finding names its subscription
**twice**: once in `accountId` and once inside `resourceId`. Every recipe addresses its resource with
`--ids`, because a recipe's command template must name the resource id and an ARM id can only be
passed that way. And `az` resolves `--ids` *in preference to* `--subscription` — it overwrites every
argument carrying an `id_part` from the parsed id, and `--subscription` is one of them.

So a finding whose `accountId` was subscription A and whose `resourceId` named subscription B
produced a script that:

- headed itself `Scope: azure subscription A`,
- ran a preflight confirming the caller can reach A,
- and then mutated a resource in **B**, which the guard never mentioned.

Exit code 0. Artifacts written. Nothing warned. The HCL half had the same shape:
`subscription_id = A` beside an `import` block whose id named B.

Such a finding is now **rejected**, counted separately in the run summary, and reported with the
reason:

```
    rejected:           3
      scope conflicts:  1 (subscription mismatch)
```

A rejection rather than a warning, and rather than trusting the id over `accountId`: the two
statements disagree and the tool has no basis for deciding which one the exporter meant. Only that
one finding is refused — the rest of the run proceeds — because a whole-run failure would make one
malformed record block work that is fine.

**There is no AWS equivalent and that is not a gap in coverage.** No AWS identifier this tool renders
contains an account id, so a bucket or table name cannot contradict `accountId`, and
`sts get-caller-identity` is a sufficient guard on its own. The check is therefore declared per
provider — `None` for AWS meaning *this cloud has no such conflict to detect* — rather than being a
shared check that AWS passes vacuously. A shared check would read as though AWS were merely behind.

Two things are deliberately **not** treated as conflicts. A resource-group mismatch, because a
finding carries no resource group and so there is nothing to disagree with. And location, because an
Azure `.tf` legitimately spans locations. A non-ARM id (a bare account name) is also not a conflict:
it names no subscription, so it cannot contradict one.

See [`examples/README.azure.md`](./examples/README.azure.md) — the committed Azure sample includes
exactly such a record, and CI asserts both that the run still refuses it and that the wrong
subscription id appears in no artifact.

## Dependencies and versions

**Runtime Python dependencies: none.** The tool is standard-library only. This is deliberate —
a remediation generator that pulls a dependency tree is a supply-chain surface attached to
something that produces commands you will run against production.

| Requirement | Version | Required? | Why |
| --- | --- | --- | --- |
| Python | **≥ 3.10** | **Yes** | Runtime. Developed and tested on 3.14.6. |
| AWS CLI v2 **or** botocore | any recent | **For `verify`'s API axis** | Source of the AWS service-model JSON. Read **as data files from disk** — never imported as a Python package, never invoked. Generation works without it; `awsremgen verify` reports the axis as not run and tells you so. |
| AWS CLI v2 | any recent | **For `verify`'s CLI axis**, and to *run* the output | Its `awscli/data/ac.index` is the CLI's own record of the flags it accepts. Read read-only as a SQLite file; the tool never shells out to `aws`. Both the package layout (Homebrew, pip) and the PyInstaller bundle (official installer) are found. |
| Azure CLI (`az`) | any recent (tested 2.89.0) | **For both of `azremgen verify`'s Azure-specific axes**, and to *run* the output | Two unrelated things are read from it. The API axis parses the 62 `azure.mgmt.*` SDK packages bundled inside it, with `ast` — nothing imported, nothing executed, no network. The CLI axis runs `az <command> --help` and parses the result, because Azure ships no `ac.index` equivalent; **only** `--help`, asserted by a test that records every argv the module spawns. Override the SDK location with `REMGEN_AZURE_SDK_DIR` or the binary with `REMGEN_AZ_CLI`. Generation works without `az`; both axes report could-not-check. |
| OpenTofu | ≥ 1.6 (tested 1.12.5) | **To generate `verify`'s schema input**, and to *run* the output | Never invoked by the tool. You run `tofu providers schema -json` yourself and pass the file to `--provider-schema`. Both clouds' HCL axes read a schema this way; the provider you generate it for has to match the cloud you are verifying. |
| Terraform | ≥ 1.6 | Optional alternative | Never invoked, never a dependency — see [NOTICE.md](./NOTICE.md) for the BUSL-1.1 analysis. |
| pytest / ruff / bandit | see `[dev]` extra | Development only | `pip install -e '.[dev]'` |

Pinned dev ranges live in `pyproject.toml` under `[project.optional-dependencies]`.

### The provider version the generated HCL asks for

Each `.tf` file carries a commented `required_providers` block, and the interesting half is the
**upper** bound. Both providers ship a major roughly annually and both relocate arguments when they
do — `hashicorp/aws` v5 to v6 moved the `aws_s3_bucket` sub-arguments, which is the resource type two
of these recipes write. With a floor and no ceiling, `init` resolves whatever is newest on the day
*you* run it, so a file generated against a verified provider breaks in your terminal against a major
nobody tested — and reads as a defect in the file rather than as an untested combination.

The ceiling is therefore the *next* major, exclusive, taken from a per-cloud value that records what
was actually verified: `hashicorp/aws` at 6.x and `hashicorp/azurerm` at 5.x today. Raising either is a
claim that the recipes were re-verified against the newer major, so it moves in the commit that does
one. The two clouds differ, which is why the value is per cloud rather than shared.

The floor is a different claim from the ceiling, and the block says so when they differ: it is the
release in which each argument first existed (`>= 5.0` for AWS), which is older than what was
verified — so an AWS file's range admits a 5.x nobody tested, and the block tells you to pin `6.x` if
you want only the verified one. Azure's range is wholly inside its verified major, so it carries no
such note. The whole block is commented for the same reason the `provider` block is: a module may hold
exactly one `required_providers` configuration, and these files are meant to be dropped into a
workspace that already has one.

## Install

```bash
git clone https://github.com/Echo6Bravo/curated-cloud-remediation-generator.git
cd curated-cloud-remediation-generator
pip install -e .          # or: pip install .
awsremgen --version
```

No install is strictly required —
`PYTHONPATH=src python3 -c 'import sys; from remgen.providers.aws.cli import main; sys.exit(main())'`
works from a clone.

## Usage

```bash
# 1. See what exists and how risky it is, before generating anything
awsremgen recipes

# 2. Confirm the recipes still match upstream on your machine, on all four axes
awsremgen verify --provider-schema /tmp/schema.json

# 3. Generate. Default safety level is 'safest'; default output is ./artifacts
awsremgen generate --findings findings.json --out ./artifacts

# 4. Opt in to remediations that carry a commitment
awsremgen generate --findings findings.json --out ./artifacts --safety-level caution

# 5. Emit only one format
awsremgen generate --findings findings.json --out ./artifacts --format cli

# 6. Track catalog drift; new policies are reported, never auto-remediated
awsremgen policies --catalog policies.json
```

`--findings` accepts a JSON array, or an object with a `findings` array. `--format` takes a
comma-separated list (`cli`, `hcl`, or `all`); an unrecognized name is an error rather than a
silently skipped format, because half the expected output looks like a tool that lost findings.
Choosing `hcl` alone omits policies with no IaC equivalent, and the run says how many. Run
`awsremgen generate --help` for the full flag list, including `--cache-dir` and `--no-save` for
CI use.

**Then review the artifacts and run them yourself.** The tool's job ends when the files are
written.

To see all of that without a findings export of your own, run it against the committed fixture:

```bash
awsremgen generate --findings examples/findings.sample.json --out ./artifacts --safety-level caution -v
```

The result is what [`examples/sample-output/`](./examples/sample-output) contains, and
[`examples/sample-run.txt`](./examples/sample-run.txt) is the console output it prints.

## Known limitations

- **Coverage is 6 AWS policies and 8 Azure policies.** If your finding's policy has no recipe, it is
  reported as unsupported (`-v` lists them). That is the honest answer, not a gap to be filled by
  guessing.
- **This tool does not account for any exceptions you may have configured in Tenable Cloud Security.**
  Exceptions, suppressions and accepted-risk decisions live in the platform and **do not survive a
  findings export**. A `Finding` carries a policy id, a resource id, a region and an account — there
  is no field for an exception, so no recipe can consult one, and every finding you supply is treated
  as one you intend to fix.

  This is a deliberate boundary rather than an oversight. The tool provides verified recipes for
  common, safely scriptable misconfigurations **without consulting your specific environment**: it
  holds no cloud credentials and makes no cloud API calls, so it cannot read your exception list, your
  resource tags, or the intent behind a configuration. It reasons only about the cloud provider's
  published API surface and the finding you hand it. The practical consequence is that **scoping the
  export is yours to do** — if a resource is excepted because its exposure is intentional, keep that
  finding out of the input rather than relying on the tool to infer intent.

  This holds for AWS, for Azure, and for any cloud added later. It is a property of findings ingest,
  which is shared, so it is stated on `Finding` itself in
  [`src/remgen/core/model.py`](./src/remgen/core/model.py) rather than in a provider, and a CI gate
  keeps this section and that docstring in agreement.

  It matters most for remediations that withdraw access existing callers may be using, where an
  exception is the ordinary case rather than an exotic one: **S3 Block Public Access** on a
  deliberately public static site or published dataset, Azure storage **HTTPS-only** or **minimum
  TLS** against a legacy client, **SFTP disable** against a running transfer job. Those recipes put
  the intent question in their caveats and in the generated artifact, which is the only place the tool
  can raise it.
- **Azure's coverage is 2 services, and one gap is deliberate and named.**
  `azremgen` covers seven storage-account settings and SQL database TDE. Two planned recipes were
  dropped rather than approximated, and both remain visible as unsupported policies:
  Key Vault RBAC (`az keyvault update` does not accept `--ids`, so a template cannot address the
  resource at all) and SQL Server minimum TLS (`azurerm_mssql_server` requires an administrator
  password through a rule the schema does not express, so the block would carry a credential-shaped
  placeholder). Reasons are recorded in
  [`src/remgen/providers/azure/recipes/`](./src/remgen/providers/azure/recipes/), beside where the
  recipe would have gone.
- **Azure's three `verify` axes are all implemented, and they read three different sources.** The
  API axis parses the 62 `azure.mgmt.*` SDK packages bundled inside `az` — Azure ships no botocore
  equivalent, so there is no single vendor JSON model to read; the HCL axis reads the `azurerm`
  schema you generate; the CLI axis asks your installed `az` what flags each command accepts, and
  names the CLI version it asked. All three are checked per run and none of them reports a pass when
  it could not run.
- **Azure HCL is not split by location, and that is correct rather than missing.** An `azurerm`
  provider block carries no location — each resource carries its own — so a `.tf` file may span
  locations. Subscription remains a hard boundary. The scope block is also a **weaker guard than the
  AWS one**, because `azurerm` has no `allowed_account_ids` equivalent: `subscription_id` selects a
  subscription rather than asserting which one is acceptable. Confirm the workspace's provider
  yourself; the generated file says so where the AWS one can rely on the provider to fail.
- **Every Azure `az` command in a generated script prints a warning, and it is expected.** Each
  recipe addresses its resource with `--ids`, and `az` then reports that `--subscription` "will be
  ignored". The flag stays: the subscription is still explicit because the ARM id contains it, and
  the script generator refuses to render a command that pins neither.
- **GCP and OCI are not implemented.** The structure to hold them exists — `remgen.core` is
  cloud-neutral and the output layout already splits by cloud — but structure is not coverage. Each
  cloud needs its own recipe set, safety analysis, IaC resource mapping and API-definition verifier,
  none of which is a parameterization of the AWS work. Azure is the evidence for that rather than a
  counterexample: its API axis had no equivalent of botocore's bundled models, and the source it
  ended up reading was chosen by measurement after the first plan proved to cover 5 of 18 commands.
- **No live Tenable Cloud Security API adapter.** Findings come from a JSON file you export. An
  API adapter needs tenant credentials to verify against, and an adapter that has never run
  against a real tenant would be untested code wearing the costume of a feature. The interface it
  would implement is in `src/remgen/core/sources.py`. See [ROADMAP.md](./ROADMAP.md).
- **No boto3/Python-SDK output format.** It would be a third rendering of the same API call with
  no capability the CLI script lacks, and each additional format is another surface that can drift
  from the service model.
- **`verify` cannot check semantics** — on all four axes it confirms that names still exist and
  shapes still match. It cannot confirm that AWS's *behavior* is unchanged, that a flag still means
  what it meant, or that a provider argument still maps to the same API field.
- **`verify`'s HCL axis needs a schema you generate.** Producing one downloads the provider, and a
  tool that emits commands against production should not shell out to something that fetches
  hundreds of megabytes from a registry, so it takes a file rather than running `tofu`. Without one
  the axis prints `not checked` and never a pass line — but `verify` still exits `0`, because failing
  by default would make the flagless invocation unusable. The `Schema source:` line, not the exit
  code, is what tells you the HCL half was checked.
- **Your account can still reject a valid command** (SCPs, permission boundaries, resource state).
  The generated scripts fail fast and loudly when that happens rather than continuing.

## Project

- [examples/README.md](./examples/README.md) — a committed real run: input, console output, and
  every artifact, annotated.
- [ROADMAP.md](./ROADMAP.md) — what is deferred and why, including the open question of whether
  to ship non-reversible remediations.
- [NOTICE.md](./NOTICE.md) — third-party licensing analysis (OpenTofu MPL-2.0, Terraform BUSL-1.1,
  the AWS provider's docs MPL-2.0, botocore Apache-2.0). Generating HCL is in bounds under BUSL:
  this tool is free, embeds nothing, and never invokes either binary.
- [CHANGELOG.md](./CHANGELOG.md) — release history.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — the bar a new recipe must clear.
- [SECURITY.md](./SECURITY.md) — how to report a security issue.

## License

[MIT](./LICENSE) © 2026 Tenable, Inc.
