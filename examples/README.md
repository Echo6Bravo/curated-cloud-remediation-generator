# Sample input and output

A real run, committed so you can read what `remgen` produces before installing it.

| File | What it is |
| --- | --- |
| [`findings.sample.json`](./findings.sample.json) | The input. 10 records, deliberately including a duplicate, an unsupported policy, and two that get rejected. |
| [`sample-run.txt`](./sample-run.txt) | The console output of the run, verbatim. |
| [`sample-output/`](./sample-output) | Every file the run wrote. |

Reproduce it exactly:

```bash
remgen generate --findings examples/findings.sample.json --out ./artifacts --tier caution -v
```

Output is deterministic apart from the `Generated:` timestamp, so your artifacts should match
`sample-output/` byte for byte otherwise. CI regenerates this on every push and fails if it drifts,
which is what keeps this directory from becoming a stale picture of an older version.

`--tier caution` is used here rather than the default because it exercises more of the tool. The
default is `safest`, and on this same input it emits **1** remediation instead of 6, withholds 5,
and prints the flag needed to include them — see [Safety tiers](#what-the-safety-tier-actually-gates)
below.

## What the input is designed to show

Six records are ordinary findings across two accounts and two regions. The other four are there
because how a tool handles bad input is more informative than how it handles good input:

| Record | Why it is in the fixture | What remgen does |
| --- | --- | --- |
| A second `checkout-sessions` record | Exports repeat findings — the same violation seen in two scans, or a record joined across views | Collapses it, reports `duplicates merged: 1`. Two HCL blocks for one resource would not validate. |
| Policy `c1f0a4d2…` | A policy with no curated recipe | Reported as `no recipe: 1` and listed by id. Coverage is partial on purpose; guessing a remediation is the failure this design refuses. |
| `resource_id` of `acme-logs; aws s3 rb s3://acme-prod --force` | A resource identifier carrying shell metacharacters | **Rejected.** Identifiers are allowlisted, and the tool refuses to render rather than escaping. A rejected finding is a visible gap; an escaped one is a surprise waiting in someone's shell. |
| A KMS record with no `region` | Missing a required field | **Rejected.** Region is part of both the command and the file's scope, so defaulting it would send a remediation somewhere nobody asked for. |

Rejections are *reported*, never dropped. That is why the counts in `sample-run.txt` reconcile:

```
10 records read = 8 usable + 2 rejected
 8 usable       = 1 duplicate merged + 7 distinct
 7 distinct     = 6 remediations written + 1 with no recipe
```

A summary whose numbers do not add up invites you to assume the missing ones were fine.

## What the output looks like

Seven files from six remediations:

```
sample-output/
├── README.md                                  ← per-run instructions and policy reference
├── manifest.json                              ← machine-readable index of every file
├── remediate-111111111111-all-regions.sh      ← 4 remediations
├── remediate-222222222222-all-regions.sh      ← 2 remediations
├── remediate-111111111111-us-east-1.tf        ← 3
├── remediate-111111111111-us-west-2.tf        ← 1
└── remediate-222222222222-us-east-1.tf        ← 2
```

**Why five artifacts and not one.** Two accounts produce two shell scripts, and the HCL splits
again by region into three. This is a correctness requirement, not tidiness: neither an `aws`
invocation nor an AWS provider can target more than one account at a time. A file spanning two
accounts would resolve identifiers against whichever account the runner is authenticated to, and a
same-named resource in the wrong account could be adopted and reconfigured **while the run reports
success**. Nothing throws. Region is a hard boundary for HCL (the provider is region-scoped) but a
soft one for the CLI (`--region` travels on each command), which is why the `.sh` files say
`all-regions` and the `.tf` files do not.

The account is in every filename because whoever runs these has to select credentials per file.

### The scope guard, and proof it works

Each `.sh` file checks the caller's account before doing anything:

```bash
expected_account="111111111111"
actual_account="$(aws sts get-caller-identity --query Account --output text)"
if [[ "$actual_account" != "$expected_account" ]]; then
  echo "error: these remediations are for account $expected_account," >&2
  ...
  exit 1
fi
```

Pointed at the wrong account, the committed sample exits `1` having issued **zero** mutating calls.
The HCL equivalent is `allowed_account_ids` on the provider block, which fails the plan rather than
importing the wrong resource.

### HCL adopts, it does not create

Every `.tf` pairs an `import` block with a `resource` block:

```hcl
import {
  to = aws_s3_bucket_versioning.acme-web-assets-use1
  id = "acme-web-assets-use1"
}

resource "aws_s3_bucket_versioning" "acme-web-assets-use1" {
  bucket = "acme-web-assets-use1"

  versioning_configuration {
    status = "Enabled"
  }
}
```

A `resource` block alone would propose creating a duplicate rather than fixing what exists.
`tofu plan` must report `N to import, 0 to add` — any "to add" means an import id is wrong, and you
should not apply.

**`TODO` placeholders are expected, and you must complete them.** Three of the blocks in this
sample contain them, and the run says so. The AWS provider requires arguments a finding cannot
supply — a DynamoDB table's `hash_key`, an RDS instance's `engine` — so the generator emits a
type-valid stub instead:

```hcl
resource "aws_dynamodb_table" "checkout-sessions" {
  name                        = "checkout-sessions"
  deletion_protection_enabled = true
  hash_key                    = "TODO" # TODO: set to the table's existing hash key

  attribute {
    name = "TODO" # TODO: must match the table's hash key
    type = "S"    # TODO: S, N or B -- must match the live table
  }
}
```

A stub is the only way to emit configuration that validates before you complete it — `tofu validate`
rejects both a missing required argument and `null`. **Applying with the placeholders still in place
would reconfigure the resource incorrectly.** They are not cosmetic.

### What safety looks like in the artifact

Warnings are emitted next to the commands they describe, not only in the docs, because a warning in
another file is a warning that gets skipped:

```bash
# POLICY: S3 Bucket versioning is not enabled
# Policy ID: 284b1210-a31e-48ce-97af-f4d825ef132d
# Resources: 1
#
# NOT REVERSIBLE: this change cannot be fully undone.
# COST SCALES WITH USAGE: charges grow with data volume and have no ceiling. Estimate
# volume before applying fleet-wide.
```

These notes are derived from the recipe's structured fields (`reversible`, `cost_impact`,
`blocks_iac_destroy`), not hand-written per recipe, so every artifact carries the same warning in
the same words and no author can forget one.

### What the safety tier actually gates

The same input at each tier:

| Tier | Written | Withheld | What is withheld |
| --- | --- | --- | --- |
| `safest` (default) | 1 | 5 | Everything irreversible, cost-scaled, or that blocks `tofu destroy` |
| `caution` (this sample) | 6 | 0 | — |

The default is not a suggestion — you get one CloudTrail remediation and an explicit note naming
the flag that would include the rest. Withheld work is always counted; a silent cap would read as
"nothing else to do".

## Verified, not just eyeballed

The committed sample was checked with real tools rather than substring assertions:

- All three `.tf` files pass `tofu init` + `tofu validate` + `tofu fmt -check`, each in its own
  workspace with a standalone provider — which is how they are meant to be used.
- Both `.sh` files pass `bash -n` and `shellcheck` with no findings.
- The account guard was exercised against a stub `aws` reporting a different account: exit `1`, zero
  mutating calls.
- Regenerating produces byte-identical files apart from the timestamp.

## What this sample cannot tell you

The account ids (`111111111111`, `222222222222`) and resource names are synthetic. The **policy
UUIDs are real** and match the shipped recipes, so a finding you export for one of these five
policies will match. Everything else here is illustrative, and no command in `sample-output/` was
ever run against AWS — see [SECURITY.md](../SECURITY.md) for why that boundary is not configurable.
