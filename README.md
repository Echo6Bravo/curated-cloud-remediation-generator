# curated-cloud-remediation-generator (`awsremgen`)

Turns Tenable Cloud Security findings into **review-ready remediation artifacts** — a vendor CLI
script and import-aware OpenTofu/Terraform configuration — for a deliberately small, curated set of
policies.

**AWS is the only cloud implemented today.** Its command is `awsremgen`. The shared pipeline lives
in `remgen.core` and each cloud is a provider under `remgen.providers`, so Azure, GCP and OCI can be
added without editing the code that decides what AWS emits. There is deliberately no `remgen`
umbrella command: see [One command per cloud](#one-command-per-cloud).

**It never modifies your cloud.** It writes files to a directory. You read them, you decide, you
run them.

```bash
awsremgen recipes                                            # what is supported, and how risky each is
awsremgen verify                                             # do the recipes still match the live AWS APIs?
awsremgen generate --findings findings.json --out ./artifacts
```

## See it before you install it

[`examples/`](./examples) holds a complete real run, committed: the input findings, the console
output verbatim, and every artifact it produced. Start with
[`examples/README.md`](./examples/README.md), which walks through why one input produced five
artifacts, what a `TODO` placeholder means, and what happens to a malformed finding.

CI regenerates that sample on every push and fails if it differs, so it cannot quietly become a
picture of an older version.

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
convention: `core` may not import from `providers`, and no provider may import another.

## What this is, and what it is not

The name is literal, and each word in it is a limitation worth stating plainly.

**Curated.** Coverage is partial by design and will stay that way. This release ships **5 recipes**,
all AWS. Tenable Cloud Security has far more AWS policies than that, and most of them are
*scriptable* — but scriptable is not the same as safe to script universally, and the gap between
those two is where an automated remediation hurts someone. Every recipe here was written and
checked individually against the AWS API definitions and AWS documentation. None were generated in
bulk.

**Generator, not an agent.** The tool produces text. It holds no cloud credentials, makes no cloud
API calls, and has no code path that mutates a cloud environment. The artifacts it writes are
inert until you run them yourself.

**Best-effort.** The generated commands and configuration are derived from the AWS service models
and public AWS documentation as they existed when the recipe was written, and are re-checked
against your locally installed service models by `awsremgen verify`. That is a strong check, not a
guarantee. AWS changes APIs, your account may have organizational policies (SCPs), resource
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

1. **A curated recipe** (`src/remgen/providers/aws/recipes/curated.py`) maps one Tenable Cloud
   Security policy UUID to one AWS API call, its parameters, the equivalent Terraform/OpenTofu
   resource type and attribute, and an explicit safety classification. These are hand-written. Each
   carries the policy UUID from the live catalog so it can be traced back.
2. **Findings are parsed as untrusted input.** Every record is validated. A record that fails
   validation is collected as an explicit *rejection* rather than dropped, so the input count
   always reconciles with the output count — a silently discarded finding would be a missed
   remediation that looks like a clean run.
3. **Two generators render the same validated call** — a fail-fast `aws` CLI shell script, and
   import-aware HCL that adopts the existing resource rather than proposing to create a new one.
   Both render from the same `ApiCall`, so they cannot disagree about what will happen. Pick one
   with `--format cli` or `--format hcl`; both are written by default.
4. **`awsremgen verify` re-checks every recipe against the AWS service models** on your machine
   (read as JSON data from your AWS CLI v2 or botocore install — see *Dependencies*). If AWS has
   renamed an operation or changed a parameter shape, this reports drift instead of emitting a
   command that will fail.
5. **`awsremgen policies` diffs the policy catalog** against a local snapshot from your last run.
   New policies are **reported, never auto-remediated** — an unreviewed policy has no recipe, and
   inventing one automatically is precisely the failure this design refuses.

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

Of the 5 shipped recipes, **1 is `safest`** and **4 are `caution`** — so a default run is
conservative, and the majority of this release requires you to opt in explicitly.

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

Generated shell scripts include an identity preflight: they check the caller's account with
`aws sts get-caller-identity` and **exit non-zero without running anything** if it does not match
the account the file was generated for. HCL sets `allowed_account_ids` on the provider for the same
reason.

## Dependencies and versions

**Runtime Python dependencies: none.** The tool is standard-library only. This is deliberate —
a remediation generator that pulls a dependency tree is a supply-chain surface attached to
something that produces commands you will run against production.

| Requirement | Version | Required? | Why |
| --- | --- | --- | --- |
| Python | **≥ 3.10** | **Yes** | Runtime. Developed and tested on 3.14.6. |
| AWS CLI v2 **or** botocore | any recent | **For `verify` only** | Source of the AWS service-model JSON. Read **as data files from disk** — never imported as a Python package, never invoked. Generation works without it; `awsremgen verify` degrades and tells you so. |
| AWS CLI v2 | any recent | To *run* the output | Only you run the generated script. The tool never shells out to `aws`. |
| OpenTofu | ≥ 1.6 (tested 1.12.5) | To *run* the output | Never invoked by the tool. |
| Terraform | ≥ 1.6 | Optional alternative | Never invoked, never a dependency — see [NOTICE.md](./NOTICE.md) for the BUSL-1.1 analysis. |
| pytest / ruff / bandit | see `[dev]` extra | Development only | `pip install -e '.[dev]'` |

Pinned dev ranges live in `pyproject.toml` under `[project.optional-dependencies]`.

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

# 2. Confirm the recipes still match the AWS APIs on your machine
awsremgen verify

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

- **Coverage is 5 policies, AWS only.** If your finding's policy has no recipe, it is reported as
  unsupported (`-v` lists them). That is the honest answer, not a gap to be filled by guessing.
- **Azure, GCP and OCI are not implemented.** The structure to hold them exists — `remgen.core`
  is cloud-neutral and the output layout already splits by cloud — but structure is not coverage.
  Each cloud needs its own recipe set, safety analysis, IaC resource mapping and API-definition
  verifier, none of which is a parameterization of the AWS work.
- **No live Tenable Cloud Security API adapter.** Findings come from a JSON file you export. An
  API adapter needs tenant credentials to verify against, and an adapter that has never run
  against a real tenant would be untested code wearing the costume of a feature. The interface it
  would implement is in `src/remgen/core/sources.py`. See [ROADMAP.md](./ROADMAP.md).
- **No boto3/Python-SDK output format.** It would be a third rendering of the same API call with
  no capability the CLI script lacks, and each additional format is another surface that can drift
  from the service model.
- **`verify` cannot check semantics** — it confirms the operation and parameters still exist and
  have the expected shape. It cannot confirm that AWS's *behavior* is unchanged.
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
