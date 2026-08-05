# curated-aws-remediation-generator (`remgen`)

Turns Tenable Cloud Security AWS findings into **review-ready remediation artifacts** — an
`aws` CLI script and import-aware OpenTofu/Terraform configuration — for a deliberately small,
curated set of policies.

**It never modifies AWS.** It writes files to a directory. You read them, you decide, you run them.

```bash
remgen recipes                                            # what is supported, and how risky each is
remgen verify                                             # do the recipes still match the live AWS APIs?
remgen generate --findings findings.json --out ./artifacts
```

## See it before you install it

[`examples/`](./examples) holds a complete real run, committed: the input findings, the console
output verbatim, and every artifact it produced. Start with
[`examples/README.md`](./examples/README.md), which walks through why one input produced five
artifacts, what a `TODO` placeholder means, and what happens to a malformed finding.

CI regenerates that sample on every push and fails if it differs, so it cannot quietly become a
picture of an older version.

## What this is, and what it is not

The name is literal, and each word in it is a limitation worth stating plainly.

**Curated.** Coverage is partial by design and will stay that way. This release ships **5 recipes**.
Tenable Cloud Security has far more AWS policies than that, and most of them are
*scriptable* — but scriptable is not the same as safe to script universally, and the gap between
those two is where an automated remediation hurts someone. Every recipe here was written and
checked individually against the AWS API definitions and AWS documentation. None were generated in
bulk.

**Generator, not an agent.** The tool produces text. It holds no AWS credentials, makes no AWS
API calls, and has no code path that mutates a cloud environment. The artifacts it writes are
inert until you run them yourself.

**Best-effort.** The generated commands and configuration are derived from the AWS service models
and public AWS documentation as they existed when the recipe was written, and are re-checked
against your locally installed service models by `remgen verify`. That is a strong check, not a
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

1. **A curated recipe** (`src/remgen/recipes/aws_curated.py`) maps one Tenable Cloud Security
   policy UUID to one AWS API call, its parameters, the equivalent Terraform/OpenTofu resource
   type and attribute, and an explicit safety classification. These are hand-written. Each carries
   the policy UUID from the live catalog so it can be traced back.
2. **Findings are parsed as untrusted input.** Every record is validated. A record that fails
   validation is collected as an explicit *rejection* rather than dropped, so the input count
   always reconciles with the output count — a silently discarded finding would be a missed
   remediation that looks like a clean run.
3. **Two generators render the same validated call** — a fail-fast `aws` CLI shell script, and
   import-aware HCL that adopts the existing resource rather than proposing to create a new one.
   Both render from the same `ApiCall`, so they cannot disagree about what will happen.
4. **`remgen verify` re-checks every recipe against the AWS service models** on your machine
   (read as JSON data from your AWS CLI v2 or botocore install — see *Dependencies*). If AWS has
   renamed an operation or changed a parameter shape, this reports drift instead of emitting a
   command that will fail.
5. **`remgen policies` diffs the policy catalog** against a local snapshot from your last run.
   New policies are **reported, never auto-remediated** — an unreviewed policy has no recipe, and
   inventing one automatically is precisely the failure this design refuses.

## Safety is a tier, not a disclaimer

Remediations are classified, and the default emits only the safest ones. `remgen recipes` prints
the classification and the reversal command for every recipe.

| Tier | What it means | Emitted by default |
| --- | --- | --- |
| **safest** | Reversible, no data-path impact, no restart or replacement, no usage-scaled cost. | Yes |
| **caution** | Irreversible, or adds cost, or interacts with teardown workflows. | No — `--tier caution` |
| **all** | May affect availability. | No — `--tier all` |

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

Artifacts are split **per account**, and HCL additionally **per region**. This is a correctness
requirement rather than tidiness: neither an `aws` CLI invocation nor a Terraform/OpenTofu provider
can target more than one account at a time. A single file spanning two accounts would resolve
resource identifiers against whichever account the runner happens to be authenticated to — a
same-named table in the wrong account could be adopted and reconfigured while the run reports
success. Nothing throws. That is why the split is not optional.

`--max-per-file` adds a further *soft* cap for reviewability (default 500, `0` disables it). It
does not and cannot relax the account/region split.

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
| AWS CLI v2 **or** botocore | any recent | **For `verify` only** | Source of the AWS service-model JSON. Read **as data files from disk** — never imported as a Python package, never invoked. Generation works without it; `remgen verify` degrades and tells you so. |
| AWS CLI v2 | any recent | To *run* the output | Only you run the generated script. The tool never shells out to `aws`. |
| OpenTofu | ≥ 1.6 (tested 1.12.5) | To *run* the output | Never invoked by the tool. |
| Terraform | ≥ 1.6 | Optional alternative | Never invoked, never a dependency — see [NOTICE.md](./NOTICE.md) for the BUSL-1.1 analysis. |
| pytest / ruff / bandit | see `[dev]` extra | Development only | `pip install -e '.[dev]'` |

Pinned dev ranges live in `pyproject.toml` under `[project.optional-dependencies]`.

## Install

```bash
git clone https://github.com/Echo6Bravo/curated-aws-remediation-generator.git
cd curated-aws-remediation-generator
pip install -e .          # or: pip install .
remgen --version
```

No install is strictly required — `PYTHONPATH=src python3 -c 'from remgen.cli import main; main()'`
works from a clone.

## Usage

```bash
# 1. See what exists and how risky it is, before generating anything
remgen recipes

# 2. Confirm the recipes still match the AWS APIs on your machine
remgen verify

# 3. Generate. Default tier is 'safest'; default output is ./artifacts
remgen generate --findings findings.json --out ./artifacts

# 4. Opt in to remediations that carry a commitment
remgen generate --findings findings.json --out ./artifacts --tier caution

# 5. Track catalog drift; new policies are reported, never auto-remediated
remgen policies --catalog policies.json
```

`--findings` accepts a JSON array, or an object with a `findings` array. Run
`remgen generate --help` for the full flag list, including `--cache-dir` and `--no-save` for
CI use.

**Then review the artifacts and run them yourself.** The tool's job ends when the files are
written.

To see all of that without a findings export of your own, run it against the committed fixture:

```bash
remgen generate --findings examples/findings.sample.json --out ./artifacts --tier caution -v
```

The result is what [`examples/sample-output/`](./examples/sample-output) contains, and
[`examples/sample-run.txt`](./examples/sample-run.txt) is the console output it prints.

## Known limitations

- **Coverage is 5 policies.** If your finding's policy has no recipe, it is reported as
  unsupported (`-v` lists them). That is the honest answer, not a gap to be filled by guessing.
- **No live Tenable Cloud Security API adapter.** Findings come from a JSON file you export. An
  API adapter needs tenant credentials to verify against, and an adapter that has never run
  against a real tenant would be untested code wearing the costume of a feature. The interface it
  would implement is in `src/remgen/sources.py`. See [ROADMAP.md](./ROADMAP.md).
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
  botocore Apache-2.0) and a standing recommendation for Tenable counsel review before public
  release.
- [CHANGELOG.md](./CHANGELOG.md) — release history.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — the bar a new recipe must clear.
- [SECURITY.md](./SECURITY.md) — how to report a security issue.

## License

[MIT](./LICENSE) © 2026 Tenable, Inc.
