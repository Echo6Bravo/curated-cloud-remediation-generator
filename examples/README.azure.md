# Sample Azure input and output

A real `azremgen` run, committed so you can read what it produces before installing anything.

Read [`README.md`](./README.md) first if you have not. It covers what the two clouds share —
why rejections are reported rather than dropped, why HCL adopts with `import` instead of creating,
why `TODO` placeholders are not cosmetic, and how the counts reconcile. **This document covers only
what is different about Azure**, because a second copy of the shared explanation is a second copy to
drift.

| File | What it is |
| --- | --- |
| [`findings.azure.sample.json`](./findings.azure.sample.json) | The input. 10 records, including a duplicate, an unsupported policy, and three that get rejected. |
| [`sample-run.azure.txt`](./sample-run.azure.txt) | The console output of the run, verbatim. |
| [`sample-output-azure/`](./sample-output-azure) | Every file the run wrote. |

Reproduce it exactly:

```bash
azremgen generate --findings examples/findings.azure.sample.json --out ./artifacts -v
```

**No `--safety-level` flag, unlike the AWS sample.** All eight shipped Azure recipes are `safest`, so
the default already emits every one and passing `caution` would exercise the flag rather than the
tool. That is a fact about the current recipe set rather than a property of Azure: the day a
`caution` Azure recipe lands, this command and the committed sample change together.

**`safest` does not mean nothing stops working, and five of these eight recipes prove it.** The tier
derives from four fields -- reversible, cost, data-path impact, whether it blocks `tofu destroy` --
and none of them means "withdraws access something is using today". Disabling SFTP, disabling local
users, requiring HTTPS, requiring TLS 1.2 and disabling cross-tenant replication are each honestly
`safest` by that formula, and each one breaks a client that depends on what it turns off. Those five
carry their warning inline, marked `!!`, next to the command rather than in this file. Three of them
appear in this sample; here is one:

```bash
# !! Any client still connecting over plain HTTP will fail after this change. That
#    traffic is unencrypted today, which is the finding -- but confirm no legacy client
#    depends on it before applying fleet-wide.
```

Where a merged `.tf` block applies several such policies at once, each line is tagged with the policy
it comes from -- applying the block applies all of them, so one contributor's warning is not the
block's whole story.

CI regenerates both samples on every push and fails if either drifts.

## What differs from the AWS sample

Five things, and each one changes the artifacts rather than only the prose.

### 1. Output splits by subscription only — never by location

```
sample-output-azure/
├── README.md
├── manifest.json
└── azure/
    ├── remediate-azure-8f4a1c62-…-all-regions.sh    ← 4 remediations
    ├── remediate-azure-8f4a1c62-…-all-regions.tf    ← 3 resource blocks
    ├── remediate-azure-d27e6b04-…-all-regions.sh    ← 1
    └── remediate-azure-d27e6b04-…-all-regions.tf    ← 1
```

Four files from five remediations, where AWS's seven produced five. The AWS `.tf` output splits again
by region because an AWS provider block *is* region-scoped. An `azurerm` provider block carries no
location at all — every resource names its own — so one `.tf` legitimately spans locations, and
splitting per location would fragment output without making it more correct.

The sample demonstrates this rather than asserting it. The input puts `acmeprodlogs01` in `eastus` and
`acmeeuexports` in `westeurope`; both land in the same `.tf`, under `rg-platform-prod` and
`rg-eu-analytics` respectively. Subscription remains a hard boundary in both formats, which is why
`acmesandboxdata` gets its own pair of files.

Note what this means for `manifest.json`: every Azure entry has `"region": null`, and every filename
says `all-regions`. Not missing data — the field records the *scope of the file*, and an Azure file
has no single location. The finding's location is still carried per finding; it simply does not route
output. It is also not filled in inside the `.tf` body: `location` is one of the five required
`azurerm_storage_account` arguments, and it is stubbed `"TODO-location"` alongside the other four
rather than interpolated from the finding. That is worth knowing before you complete a block by hand
— the value you need is the resource's configured location, and the file will not have pre-filled it
for you from the finding.

### 2. The guard checks reachability, not identity

The AWS script refuses when the caller's account is not the script's account. An Azure login spans
subscriptions, so that check would be wrong here — your active subscription being something else is
normal and not an error. What the script refuses is a subscription the credentials cannot reach:

```bash
expected_subscription="8f4a1c62-5d90-4e7b-9a3f-2c6b8d10e5a7"
reachable="$(az account list --query "length([?id=='$expected_subscription'])" --output tsv)"
if [[ "$reachable" != "1" ]]; then
  echo "error: subscription $expected_subscription is not available to these" >&2
  ...
  exit 1
fi
```

A different *active* subscription prints a note and proceeds, because every command below names
`--subscription` explicitly. Pointed at credentials that cannot see the target, the committed sample
exits `1` having issued **zero** mutating calls — CI executes that against a stub `az` on every push.

**The HCL half is weaker here than on AWS, and the artifact says so.** `azurerm` has no
`allowed_account_ids` equivalent: `subscription_id` *selects* a subscription, it does not assert
which one is acceptable, so a wrong value is not rejected. What prevents a wrong-resource import is a
property of Azure rather than of this tool — an ARM resource id contains its own subscription id, so
the wrong provider scope yields a failed import ("resource not found") rather than a wrong one.

### 3. Every command names `--subscription`, and `az` says it will ignore it

Running a generated script prints, on every line:

```
option '--subscription' will be ignored due to use of '--ids'
```

That is expected and the flag stays. Every recipe addresses its resource with `--ids` because an ARM
id can only be passed that way, and `az` overwrites every argument carrying an `id_part` from the
parsed id — `--subscription` is one of them. The target subscription is still explicit on the command
line, because the ARM id contains it. The flag is kept so that a future recipe which does *not* use
`--ids` cannot silently inherit whatever subscription happened to be active; a render-time check
enforces its presence. Read from `az`'s own `azure/cli/core/commands/arm.py`.

### 4. A rejection AWS cannot have: the cross-subscription conflict

`findings.azure.sample.json` carries a record that is well-formed, whose `resource_id` is a valid ARM
id, and which is **refused**:

```json
{
  "policyId": "bed905d4-758c-4698-9ed8-4cdd4271eb4e",
  "resourceId": "/subscriptions/99999999-9999-9999-9999-999999999999/…/storageAccounts/acmewrongsub",
  "accountId": "8f4a1c62-5d90-4e7b-9a3f-2c6b8d10e5a7"
}
```

The id names one subscription and `accountId` names another. Because `--ids` outranks
`--subscription`, generating this would have produced a script headed
`Scope: azure subscription 8f4a1c62…`, with a preflight confirming `8f4a1c62…`, that mutated a
resource in `99999999…`. Exit code 0. Artifacts written. Nothing warned.

That was real, shipped behaviour, found by generating exactly this record rather than by reading the
code. The run now reports it as a distinct sub-count:

```
    rejected:           3
      scope conflicts:  1 (subscription mismatch)
```

**There is no AWS equivalent, and that is not a coverage gap.** No AWS identifier this tool renders
contains an account, so a bucket name cannot disagree with `accountId` and
`sts get-caller-identity` is a sufficient guard. The asymmetry is in the clouds. Only the
subscription segment is compared — a finding carries no resource group, so there is nothing to
disagree with, and location is deliberately excluded because an Azure `.tf` legitimately spans
locations.

### 5. Placeholders are heavier, and one is a name you cannot guess

Every Azure resource block in this sample carries `TODO`s, where two of five AWS blocks did.
`azurerm_storage_account` requires five arguments a finding does not carry (`name`,
`resource_group_name`, `location`, `account_tier`, `account_replication_type`), and each is a real
schema requirement measured with `azremgen verify`'s HCL axis rather than read from documentation.

The shared README explains why a stub is the only way to emit configuration that validates. Two
Azure-specific notes:

- **`name` for a storage account is not the last segment of the ARM id you can copy blindly** — it
  must be 3–24 lowercase alphanumerics, so the placeholder is `todoreplacethisname` rather than
  `TODO`, which would not be a legal value and would fail for the wrong reason.
- **`azurerm_mssql_database` needs `server_id`, a whole ARM id**, so its placeholder is a
  structurally-valid id with `TODO-` segments. The comment says where to get the real one: the import
  id above, truncated before `/databases/`.

Several of these are `ForceNew`. The artifact says so on the line itself, because applying a wrong
value there destroys and recreates the resource.

## What the input is designed to show

Six records are ordinary findings; the other four are there because how a tool handles bad input is
more informative than how it handles good input.

| Record | Why it is in the fixture | What azremgen does |
| --- | --- | --- |
| A second `acmeprodlogs01` record, different policy | Two policies on **one** resource | One `import` and one `resource` block applying both settings, labelled with both policies. Two `import` blocks naming one resource are *valid configuration* — `validate` passes — and fail only at plan/apply. |
| `acmeeuexports` in `westeurope` | A second location in the same subscription | Written to the **same** `.tf` as the `eastus` resources. See §1. |
| `acmesandboxdata` in a second subscription | A hard boundary in both formats | Its own `.sh` and its own `.tf`. |
| A duplicate `acmeeuexports` record | Exports repeat a finding seen in two scans | Collapsed, reported as `duplicates merged: 1`. |
| Policy `d1b5f4a0…` | A policy with no curated recipe | Reported as `no recipe: 1` and listed by id. **This id is synthetic**, unlike the four real ones — it stands in for Key Vault RBAC, deliberately uncovered because `az keyvault update` accepts no `--ids`. The behaviour shown is what happens to *any* unmatched id. |
| `/subscriptions/99999999…` with `accountId` `8f4a1c62…` | A cross-subscription conflict | **Rejected.** See §4. |
| `…/storageAccounts/acme$(az account clear)` | Shell metacharacters in an identifier | **Rejected.** Identifiers are allowlisted and the tool refuses to render rather than escaping. |
| No `accountId` | Missing a required field | **Rejected.** The subscription is part of every command and part of the file scope, so defaulting it would send a remediation somewhere nobody asked for. |

The counts in `sample-run.azure.txt` reconcile:

```
10 records read = 7 usable + 3 rejected
 7 usable       = 1 duplicate merged + 6 distinct
 6 distinct     = 5 remediations written + 1 with no recipe
```

## Verified, not just eyeballed

- Both `.tf` files pass `tofu init` + `tofu validate` + `tofu fmt -check`, each in its own workspace
  against the real `hashicorp/azurerm` provider.
- Both `.sh` files pass `bash -n` and `shellcheck` with no findings.
- The subscription guard was exercised against a stub `az` reporting the target unreachable: exit
  `1`, zero mutating calls. The stub is written before anything runs, and it logs every non-read-only
  call so that an exit-1 reached *after* a mutation would still fail.
- The cross-subscription record is asserted absent from every artifact by name, not only by the
  transcript diff — a diff alone would pass if someone regenerated the sample after the guard broke.
- Every recipe behind these artifacts passes `azremgen verify` on all three axes: the `azure.mgmt.*`
  SDK models bundled with `az`, the `azurerm` provider schema, and `az`'s own flag surface.

## What this sample cannot tell you

The subscription ids and resource names are synthetic. **Four of the five policy UUIDs are real** and
match the shipped recipes; `d1b5f4a0…` is not, and is labelled as such above and in the fixture. No
command in `sample-output-azure/` was ever run against Azure — see [SECURITY.md](../SECURITY.md) for
why that boundary is not configurable.

Coverage is four recipes. Two Azure policies were investigated and deliberately left uncovered
because the *shape* of a correct recipe does not exist for them, not because nobody got round to
them; `src/remgen/providers/azure/recipes/__init__.py` records both measurements.
