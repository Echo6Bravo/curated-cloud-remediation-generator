# Azure policy triage

Every Azure-only policy in the Tenable Cloud Security catalogue, assigned to exactly one of four
buckets: shipped, write-a-recipe-now, blocked-on-a-named-prerequisite, or documented rejection.

The Azure counterpart to [`AWS_POLICY_TRIAGE.md`](./AWS_POLICY_TRIAGE.md), and deliberately the same
shape: same four buckets, and rejection classes that **keep the AWS numbers** where the argument is
the same one. `R2-requires-replacement` means the same thing in both files. A reader who has read one
register is not learning a second vocabulary, and a class that turns out to be wrong is wrong in both
places at once. One class here has no AWS counterpart, and it is the interesting one:
[`R10-not-addressable-by-resource-id`](#r10-not-addressable-by-resource-id-24).

**Status: desk triage.** Bucket assignment was made from the policy title, the service's API surface,
and -- new in this pass -- a **measured probe of the `az` command each policy would need**. It is *not*
the per-recipe three-axis verification `CONTRIBUTING.md` describes; that happens when a recipe is
written, and it is allowed to overturn an assignment here.

**Two assignments were corrected during the pass, and both are recorded rather than quietly fixed,**
because they are the same mistake in two costumes.

1. A class called `R11-extension-required` was created for the 14 `Microsoft Defender` policies, on the
   theory that they need an `az` extension. They do not: `az security pricing create` is in the base
   CLI. The class had been derived from the *policy name* rather than from probing the command -- the
   identical error that dissolved `R8-out-of-design-scope` in the AWS register. The real constraint is
   that the Defender plan is subscription-scoped, which is `R10`, so `R11` was dissolved into it.
2. Five policies sat in `R10` that do not belong there. CosmosDB key-management access, Event Hub and
   Service Bus local authentication, Storage Account local-user authentication, and `SQL Server
   Microsoft Defender` all accept `--ids`. The last is the sharpest: it is *per-server* advanced threat
   protection (`az sql server advanced-threat-protection-setting update`), an entirely different thing
   from the subscription-wide Defender plan it shares a name with. All five moved to *Write a recipe
   now*, raising the ceiling from 35% to 37%.

Both were caught by reading the members of a class instead of trusting its label. That is what the
class structure is for, and it is why the corrections stay visible here.

## Which catalogue this counts

The tenant exposes the policy catalogue through two APIs and **they disagree**:

| Source | Total policies | Azure |
| --- | --- | --- |
| UDM (`RiskPolicyModel`, `RiskPolicyTenantTypes In ["Azure"]`) | 1063 | 388 |
| GraphQL (`{ Policies { Id Name Category Providers } }`) | 739 | 324 tagged |

The 388-to-324 gap is accounted for exactly: GraphQL omits the
40 `Custom` and `KubernetesAdmissionController` policies and the
24 with a `null` category -- 64 in total. The same reconciliation held for AWS
(83 there), which is what makes it a property of the two APIs rather than a coincidence.

**This document triages the 217 GraphQL Azure-*only* policies.** GraphQL is the only source that
yields policy *names* -- `RiskPolicyTitle` is a `CommonVirtual` property and cannot be selected in UDM
-- and a name is the minimum needed to reason about a remediation. Azure-*tagged* is the wrong
denominator: 324 tagged versus 217 Azure-only, the difference being the 94
Kubernetes and 13 workload-protection policies tagged for every provider at once, which are in-cluster
concerns rather than Azure control-plane calls.

**What that leaves uncounted, stated plainly:** the 40 `Custom` and
`KubernetesAdmissionController` policies and the 24 with no category. Those 64
have not been triaged by anything in this file. A future pass should say so here rather than quietly
changing the totals.

## Result

| Bucket | Policies | Share |
| --- | --- | --- |
| Shipped | 4 | 1.8% |
| Write a recipe now | 42 | 19.4% |
| Blocked on a prerequisite | 35 | 16.1% |
| Documented rejection | 136 | 62.7% |
| **Total** | **217** | |

The design ceiling is **81 of 217** (37%). Quoted against the ceiling rather than the
catalogue, that is the useful output: about 63% of the Azure catalogue cannot be expressed as a
single idempotent, reversible, per-resource API call, and the reasons collapse into
9 classes rather than one judgement per policy.

**Azure's ceiling is meaningfully higher than AWS's 26%,** and the reason is worth stating: `az`
exposes a far more uniform `<service> update --ids` surface than AWS's per-service APIs, so more
policies reduce to one flag on one resource. Where Azure is *worse* is that the uniformity has holes,
and the holes are invisible until probed -- which is what `R10` is.

## Shipped

| Policy id | Policy | Category |
| --- | --- | --- |
| `f3c5d6e7-d8f0-48fd-97ab-16585ff981f3` | SQL Database is not encrypted with transparent data encryption | Data |
| `29307516-af03-445b-a22c-5dfa62598b22` | Storage Account cross-tenant replication is enabled | Data |
| `bed905d4-758c-4698-9ed8-4cdd4271eb4e` | Storage Account in transit is not enabled | Data |
| `0662810d-c71d-46a3-a937-e1c2b24792e4` | Storage Account insecure communication | Network |

## Write a recipe now

Batched by the **`azure.mgmt` SDK package**, because that is the unit verification happens in: one SDK
model, one `az` command group, one family of `azurerm` resource types, one `recipes/<service>.py`. Note
the SDK package is *not* always the command group -- `az postgres` and `az mysql` are both
`azure.mgmt.rdbms`, which is why they are one module -- and the SDK name wins, because that is what
`providers/azure/drift` resolves.

**Every batch below was probed for `--ids` support before being put here.** A service whose update verb
cannot take an ARM id is in `R10`, not in this table; that check is step one of an Azure recipe, not a
detail to discover afterwards.

| # | Batch | Module | Recipes | Estimate | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | storage | extend | 9 | 4-6 h | Nine recipes into a module that already holds three recipes, so the SDK model, the `azurerm_storage_account` schema and the `--ids` behaviour are all already established. Best coverage-per-hour in the set: SFTP, static-website hosting and Shared Key access each close a distinct exposure with one flag. |
| 2 | sql | extend | 4 | 4-6 h | Extends a shipped module. Minimum-TLS is the policy whose *first* attempt was dropped for the `ExactlyOneOf` schema gap recorded in `recipes/__init__.py`; it is back here because `az sql server update --ids` is a CLI path that does not require the credential arguments `azurerm_mssql_server` does. Expect the HCL axis to be the hard part, and expect it to possibly fall to R6. |
| 3 | rdbms | new | 10 | 11-14 h | The largest batch and the best-understood: eight of the ten are server *parameters* set through one `az mysql/postgres flexible-server parameter set` shape, so recipe two onwards is near-mechanical. Note the module is named for the SDK package (`azure.mgmt.rdbms`), not the command group -- `az postgres` and `az mysql` both live in it, which is why they are one module and not two. |
| 4 | web | new | 8 | 10-13 h | Eight App Service recipes. Two command shapes -- `az webapp update` and `az webapp config set` -- so the CLI axis has to be established twice. `azurerm_linux_web_app`/`azurerm_windows_web_app` are distinct resource types with a shared schema block, which is the residual risk on the HCL axis. |
| 5 | compute | new | 4 | 8-11 h | Four recipes across two SDK services (`disk`, `vm`) that share `azure.mgmt.compute`. Managed Disk public-access and data-access-auth are adjacent settings on one resource. |
| 6 | servicebus + eventhub | new (paired) | 5 | 7-9 h | Five recipes, two modules, near-identical namespace shapes -- minimum TLS and local auth exist on both. Paired for the same reason the AWS register pairs docdb+neptune: the second module inherits most of the first's reasoning. |
| 7 | redis + cosmosdb | new | 2 | 6-8 h | Two recipes, two new modules: the worst overhead-to-coverage ratio here, hence last. `az cosmosdb update` disabling key-based metadata write access may prove to be R9 rather than a clean recipe, since existing key-authenticated callers break. |

**Total: 42 recipes, 50-67 h**, plus 5-8 h for this document's rejection register once each
class is written against its members. Roughly 7-10 working days.

### Basis for the estimates

Per recipe: **3-4 h**, and it is verification rather than authorship -- the code is around sixty lines.
The hours go to the SDK model and exact property names; `--ids` support and flag existence on the
pinned CLI; the `azurerm` resource type and attribute names against the machine-readable schema; a
hand-run `tofu import` to confirm the import-id template against the provider's `commonids` types; the
reversal command; and the five safety attributes. A new module adds about **2 h** for wiring and sample
regeneration.

**Azure carries one cost AWS does not**, and it is folded into the ranges above: there is no botocore
equivalent, so the model axis resolves against the `azure.mgmt.*` SDKs bundled in the Azure CLI. When a
policy's service is not in a bundled SDK, the model axis cannot verify it at all -- which is a
discovery that turns a batch member into a rejection, and the reason the `web` and `rdbms` batches
carry the widest ranges.

**These are bottom-up estimates from that checklist, not measurements.** No wall-clock record exists
for the recipes already shipped, so there is no calibration factor in them. Treat the ranges as the
width of that ignorance.

### Per-policy assignment

**`recipes/rdbms.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `b873aada-5692-4d23-a28b-11748865833a` | MySQL Database Server encryption in transit is not enabled | Data |
| `e85cd92c-6e52-4f7d-81c0-9dd461936b87` | MySQL Database Server parameter audit_log_enabled is not enabled | Logging |
| `844be7b0-2373-439f-b107-e1380987ff4e` | MySQL Database Server parameter audit_log_events does not meet minimum requirements | Logging |
| `eeb6a400-ff99-498d-b202-386843300617` | MySQL Database Server parameter tls_version does not meet minimum requirements | Network |
| `28428a61-affe-4459-804a-a51897f23113` | PostgreSQL Database Server encryption in transit is not enabled | Data |
| `f1adffde-68bb-4215-a445-fef3c73189b0` | PostgreSQL Database Server log_retention_days does not meet minimum requirements | Logging |
| `f313c089-493b-45f3-8b05-eeeccdd39f8b` | PostgreSQL Database Server parameter connection throttling is not enabled | Logging |
| `3d700876-b48d-4030-8bed-beb036f384ce` | PostgreSQL Database Server parameter log_checkpoints is not enabled | Logging |
| `5e1613a8-2b87-4243-bf95-3aeefeb8870c` | PostgreSQL Database Server parameter log_connections is not enabled | Logging |
| `81e9b24f-4667-4f4b-9189-e2935ab1bcc9` | PostgreSQL Database Server parameter log_disconnections is not enabled | Logging |

**`recipes/storage.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `bfa6917c-773b-43d8-acc3-9cb90de0fbde` | Storage Account Azure trusted services access is not enabled | Network |
| `052f0af6-7341-4da6-b49c-d524f462cd2f` | Storage Account SAS expiration policy is not set | Iam |
| `a86dc2ab-4069-44b2-b55c-1e46b529eb2d` | Storage Account SFTP is enabled | Data |
| `392599b3-00dc-40bb-9b50-24e6e881eb6a` | Storage Account Shared Key access is enabled | Iam |
| `8a9a2bc3-4f41-4607-a67e-5b29ca88f2aa` | Storage Account access key has no expiration policy | Data |
| `77610610-c281-44ea-afd4-f8e8847a7bd2` | Storage Account blob versioning is not enabled | Data |
| `e4da24ba-a2c6-4b9e-ae02-0764ed4718a0` | Storage Account local user authentication is enabled | Iam |
| `e11afc3b-7499-4ddb-807c-6dbd78da22ad` | Storage Account soft delete protection is not enabled | Data |
| `44e127a4-806b-4e78-9899-7b0820f21094` | Storage Account static website hosting is enabled | Data |

**`recipes/web.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `62b190de-194c-40fe-a63b-f619e96c8727` | App Service Always On is not enabled | Compute |
| `48601a8f-6ff6-4f82-befc-a3d49fb0c7ae` | App Service FTP encryption is not enabled | Compute |
| `dbe0cdee-42d9-4bfe-8289-52918e81a611` | App Service HTTP logging is not enabled | Logging |
| `4547e6b8-41aa-409a-bd1b-1f9c16c39f58` | App Service HTTP version does not meet minimum requirements | Compute |
| `85e9c63e-7111-4ed1-9a59-972475a282aa` | App Service client certificate is disabled | Compute |
| `3e9011da-bd2e-44df-8ff9-9d4b2cff969b` | App Service insecure communication | Network |
| `42efda67-c4d7-450f-adf0-cbbc80624ee3` | App Service public network access is enabled | Compute |
| `3bc2c66e-6998-4ed2-a658-d5fa6fab2869` | App Service remote debugging is enabled | Compute |

**`recipes/sql.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `d9bc5094-87bc-49ba-99fe-f0aa7847a144` | SQL Database Ledger is not enabled | Data |
| `675d3b4d-8168-4bc8-bae2-ebad12102b53` | SQL Server Microsoft Defender is not enabled | Data |
| `17af7bf3-0f70-4822-bc09-e41bfd97dbdf` | SQL Server TLS version does not meet minimum requirements | Data |
| `8c61dad4-1c81-4fc8-9683-329176c1e46e` | SQL Server auditing is not enabled | Logging |

**`recipes/compute.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `fc918c18-38dd-4eeb-8eb4-a4e07daed68a` | Managed Disk data access authentication is not enabled | Data |
| `86cd886f-eb65-422a-b86b-157629db190b` | Managed Disk does not block public access | Data |
| `421ee0cc-1bed-4fcf-82e9-e21635586851` | Virtual Machine Boot Diagnostics is not enabled | Logging |
| `b102fbb0-3540-407c-a41d-a8a4b0a19f32` | Virtual Machine Linux SSH key authentication is not enabled | Compute |

**`recipes/servicebus.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `0b9d7fb8-2bd1-4349-b825-c89f6ec2a085` | Service Bus Namespace infrastructure-level encryption is not enabled | Data |
| `33625300-4280-4ae9-9df4-2ddf4442316b` | Service Bus Namespace local authentication is enabled | Iam |
| `e527075c-6ac0-4c7b-90f2-e5bf85d78dfe` | Service Bus Namespace minimum TLS version is below 1.2 | Data |

**`recipes/eventhub.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `645f322c-e9ed-4b36-9e9c-904553c1dad6` | Event Hub Namespace local authentication is enabled | Iam |
| `38bb62b9-8f40-4cae-83fb-b195a73bce18` | Event Hub Namespace minimum TLS version is below 1.2 | Data |

**`recipes/redis.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `cd8c3a61-2952-484a-9fa2-00566605b4b5` | Redis Cache encryption in transit is not enabled | Data |

**`recipes/cosmosdb.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `de69dee4-0e9a-4d0c-bcec-b7874f84c6e4` | CosmosDB Account key management access is enabled | Iam |

## Blocked on a named prerequisite

Writable in principle, but each needs an input the finding does not carry. Filed separately from
rejection because the blocker is a *named, removable* thing rather than an argument about shape.

### `P1-needs-cmk` (16)

**Prerequisite:** a customer-managed key the finding does not name.
Every one of these asks for encryption with a CMK rather than a platform key. The remediation is not the flag -- it is choosing or creating a Key Vault key, granting the resource's managed identity wrap/unwrap on it, and accepting that losing the key destroys the data. A generator that invented a key id would be guessing at the one input whose loss is unrecoverable. These become writable the day a recipe can take an operator-supplied key id as a parameter, which is a `Recipe` model change and not a per-policy problem.

| Policy id | Policy | Category |
| --- | --- | --- |
| `f6d5486d-8acd-4e61-a5a0-ff233a4be1e5` | AKS Cluster disk encryption set is not configured | Kubernetes |
| `7c05effb-9b6c-40f6-bd5f-5f3e4de8b9ef` | Activity log Blob Container is not encrypted with CMK | Logging |
| `30b4522a-6a00-43ed-be77-50dffe8953a4` | Automation Account variables are not encrypted | Data |
| `35a5914f-ddf4-4a65-9404-0530cc627ec6` | Azure Data Explorer Cluster is not encrypted with CMK | Data |
| `e95e7dbe-7c94-4bbf-81aa-cdf004a1bd8d` | Batch Account is not encrypted with CMK | Data |
| `f08e0354-bebc-409b-9651-50e3526bd52e` | Compute Disk OS disk is not encrypted with CMK | Compute |
| `74e82a7b-520c-4c2f-a7a1-a2c1a233f86f` | Compute Disk data disk is not encrypted with CMK | Compute |
| `a7f708a2-6778-410d-aece-8983b2c46cb9` | Compute Disk is not double encrypted | Compute |
| `f704c039-7a6b-4baa-8608-9f60331deb56` | Data Explorer disk encryption is not enabled | Data |
| `305c8cab-ff62-4858-8e29-37e0dff75b26` | Event Hub Namespace SKU does not support CMK encryption | Data |
| `14b1ecf5-1365-4ef6-a02b-edf101edf7d6` | Kubernetes secrets are not encrypted with CMK | Kubernetes |
| `3cd4f4b2-7a6e-440a-913f-22ed007e0705` | Machine Learning Workspace is not encrypted with CMK | Ai |
| `bc1034ef-e1a2-4212-ace2-bcdd39964614` | SQL Server transparent data encryption is not encrypted with CMK | Data |
| `779e1a1f-0570-4875-a35e-4f4273a24983` | Service Bus Namespace is not encrypted with CMK | Data |
| `28e7e19e-03b7-4bc6-b03d-dba2b85ec11c` | Storage Account infrastructure encryption is not enabled | Data |
| `58813b2c-1997-4382-a866-3c8950f1b100` | Storage Account is not encrypted with CMK | Data |

### `P2-needs-private-endpoint` (11)

**Prerequisite:** a private endpoint and the VNet subnet it lands in.
"Private endpoint is not configured" is a request to create a resource in a network the finding does not describe. It needs a subnet with `private_endpoint_network_policies` disabled, a private DNS zone, and a zone-group link -- three resources and a DNS decision, none of which are in the finding. This is `R5-build-out-not-remediation` in substance; it is filed as blocked rather than rejected because a recipe *could* take a target subnet id as a parameter, whereas nothing parameterises the R5 members.

| Policy id | Policy | Category |
| --- | --- | --- |
| `58e99152-c4bd-4b29-945c-3da558660a8b` | Azure Cache for Redis private endpoint is not configured | Data |
| `fd25ba1c-76e3-4087-9370-d1f604c33c3e` | CosmosDB Account is not associated with private endpoint | Network |
| `1537571a-8d1b-407a-88e3-40bd2ec58dfb` | Data Factory private link is not configured | Network |
| `20669aa1-5dea-49fc-a7c7-43a76f68f4c3` | Event Hub Namespace private link is not configured | Data |
| `d13fba1f-4a62-426b-9194-30fdd4580121` | Key Vault is not associated with private endpoint | Network |
| `61471a68-0eaa-4f7a-9d13-a6eda494cfe4` | Machine Learning Workspace Managed Virtual Network Isolation is not enabled | Ai |
| `e118057a-9bc6-4fd8-b9dd-b171c8230b3c` | Machine Learning Workspace private link endpoints are not approved | Ai |
| `aa57bfcd-161f-416d-83ed-2334a192b058` | SQL Managed Instance does not have a private endpoint | Data |
| `7fb0ad1b-2d25-4a1e-8ae8-b2db925f87f5` | SQL Server private endpoint is not configured | Data |
| `439302a3-1dc3-40ec-9d88-ea24cd0d5d8e` | Service Bus Namespace private link is not configured | Data |
| `f84505e0-a3f1-4def-9f0d-c829dee8a34e` | Storage Account is not associated with private endpoint | Network |

### `P3-needs-entra-principal` (8)

**Prerequisite:** a Microsoft Entra ID principal chosen by a human.
Setting an Entra-only admin, or enabling Entra authentication, requires naming *which* principal becomes the administrator. Choose wrong and you have either locked out the operators or handed control to the wrong group; both are worse than the finding. The object id is also tenant-scoped rather than subscription-scoped, so it is not derivable from anything in the finding.

| Policy id | Policy | Category |
| --- | --- | --- |
| `972c42c6-4370-4fec-90dd-29ef01c6dcd2` | AKS Cluster Microsoft Entra ID authentication is not enabled | Kubernetes |
| `0150c1ce-8a7f-4fe3-a4af-6903e140a5bb` | App Service Microsoft Entra ID registration is not set | Compute |
| `a3c4cbc6-bf98-4414-bc4b-ad33757bed84` | App Service authentication is not enabled | Compute |
| `182d3c85-90c3-4aeb-94ab-77262ba5ac35` | Batch Account managed identity is not set | Iam |
| `4819b1ca-5352-4a96-bbc2-b9d3ebc1d092` | MySQL Database Server Microsoft Entra ID-only authentication is not enabled | Data |
| `7d551b9e-8b45-48be-99c3-ed4f529c969b` | PostgreSQL Database Server Microsoft Entra ID-only authentication is not enabled | Data |
| `1b837bac-f6bd-401d-9caa-28965e1909ce` | SQL Server Microsoft Entra ID admin is not set | Data |
| `fe872991-9358-4abb-95f0-ba704dcc6c21` | SQL Server Microsoft Entra ID-only authentication is not enabled | Data |

## Documented rejection

9 classes, ordered by size. A class is the unit of rejection: a policy is
rejected *because it is an instance of one of these*, which is what keeps the register from being a
heap of unrelated opinions. If a class turns out to be wrong, every member is reconsidered together --
and this pass has already dissolved one class and moved five policies out of another, so that is a
live process rather than a disclaimer.

| Class | Policies | One-line reason |
| --- | --- | --- |
| [`R2-requires-replacement`](#r2-requires-replacement-35) | 35 | No in-place API exists. |
| [`R10-not-addressable-by-resource-id`](#r10-not-addressable-by-resource-id-24) | 24 | No per-resource ARM id to bind the finding to. |
| [`R3-policy-document-rewrite`](#r3-policy-document-rewrite-22) | 22 | Target state is a diff against a document with unknown callers. |
| [`R5-build-out-not-remediation`](#r5-build-out-not-remediation-18) | 18 | Creates net-new subscription-scoped infrastructure. |
| [`R1-detection-no-target-state`](#r1-detection-no-target-state-14) | 14 | A detection, not a misconfiguration. |
| [`R4-unbounded-log-ingest`](#r4-unbounded-log-ingest-10) | 10 | One call, unbounded recurring bill. |
| [`R7-requires-secret-or-rotation`](#r7-requires-secret-or-rotation-7) | 7 | Needs an input no generator can supply. |
| [`R6-no-partial-update-command`](#r6-no-partial-update-command-4) | 4 | Missing command shape, not a missing recipe. |
| [`R9-blast-radius-beyond-resource`](#r9-blast-radius-beyond-resource-2) | 2 | Effect extends past the named resource. |

### `R2-requires-replacement` (35)

**Reason:** No in-place API exists.

The largest class, and the same shape as its AWS counterpart. Unmanaged-to-managed disk conversion, trusted launch, AKS network plugin, node public IPs, host encryption, zone redundancy, an SKU that cannot hold a CMK, a Service Fabric protection level: each is set at create time. Also here is the whole "X is exposed to the internet" family (13 members). Those look like a flag but are not -- the remediation is a private endpoint plus a public-access denial plus a firewall rule set, and doing only the last part is how you take an outage without fixing the finding. Generated HCL for any of these emits a *forces replacement* plan, which for a database or a cluster means data loss proposed as a routine change.

| Policy id | Policy | Category |
| --- | --- | --- |
| `a10b4889-63d8-48ca-9330-4a0c66b79083` | AKS Cluster Azure CNI networking is not enabled | Kubernetes |
| `614a93a5-c795-464b-b56a-d72d2b3cacad` | AKS Cluster Kubernetes API is exposed to the internet | Kubernetes |
| `4a55cdac-b049-4773-9400-7a77aa8eb549` | AKS Cluster agent pools are not using Virtual Machine Scale Sets | Kubernetes |
| `b6d419cd-141d-4e26-bcb9-687735093bd2` | AKS Cluster contains nodes with public IPs | Kubernetes |
| `6edc8e4b-886f-40f6-802d-c3701557af31` | AKS Cluster host encryption is not enabled | Kubernetes |
| `86157796-e1cc-4a37-8ffc-a0f5e93e246d` | AKS Cluster is using Free tier | Kubernetes |
| `9a45f7f1-57a6-4602-90ac-761d7629d99d` | App Service .NET Core version does not meet minimum requirements | Compute |
| `f66c881d-eb53-4145-92ae-fd10828e4882` | App Service Java version does not meet minimum requirements | Compute |
| `1dbc48f9-698c-4033-8000-c1cc89089efd` | App Service PHP version does not meet minimum requirements | Compute |
| `c7f02dd5-9e01-485a-bb7f-a2d383abaf18` | App Service SCM Site is exposed to the internet | Network |
| `ac14bffa-bf91-48fe-a9c8-e67bafd1748a` | App Service is exposed to the internet | Network |
| `468a1edc-e3e2-4df5-ba24-aff4469154a0` | Automation Account unrestricted inbound internet access | Network |
| `76852d17-3a3b-41e3-a08f-5b5e282c5153` | Azure AI Service is exposed to the internet | Ai |
| `44cba9dd-4cb9-4f97-86ab-fb41b83c8192` | Bot Service is exposed to the internet | Ai |
| `d93f57f3-60e7-47cb-85c5-88f8c5577351` | Container Registry is exposed to the internet | Network |
| `e2eb838b-4ce9-4f3d-bdc2-b0921b420089` | Container Registry is using deprecated SKU | Kubernetes |
| `f784dbdf-7750-4a21-8575-bce20bef9e32` | CosmosDB Account is exposed to the internet | Network |
| `7225eb00-c95a-4a10-8fec-3da2e5fcd9a3` | Event Hub Namespace zone redundancy is not enabled | Data |
| `81425577-c54d-4376-ab15-3e1649f0fd6c` | Event Hubs Namespace is exposed to the internet | Data |
| `b4a79cd8-a7de-4f51-b51e-cb50c2b5fae7` | Key Vault SKU does not support HSM-protected keys | Secrets |
| `f6555596-ce8e-44fa-9269-29b89f4ae462` | Key Vault is exposed to the internet | Network |
| `01065e3c-889b-4fc9-bdeb-437e09f619a4` | Logic App is exposed to the internet | Network |
| `0f69e6fb-bd15-4d63-930c-849bedf5f250` | Machine Learning Workspace is exposed to the internet | Ai |
| `8efe6f64-9f54-4688-a05a-61f33f227696` | MySQL Database Server is exposed to the internet | Network |
| `b8e156e1-4c6e-4f23-b46a-6af77e45b7aa` | PostgreSQL Database Server is exposed to the internet | Network |
| `95e13557-3713-4fb0-83ff-04cffd4b2013` | SQL Server is exposed to the internet | Network |
| `0dd2991a-4ebe-46ec-8616-4f56113b9a7a` | Service Bus Namespace zone redundancy is not enabled | Data |
| `d1ff0b27-22d0-41e0-adb1-99020920ea36` | Service Fabric Cluster protection level security is not set | Compute |
| `dedc60e9-acda-492d-aa9e-c915b91ebbdb` | Storage Account geo-redundant storage is not enabled | Data |
| `0b6d8411-0114-463d-b533-662d5bb75254` | Storage Account is exposed to the internet | Network |
| `327018ab-bd12-4ba0-95aa-3c8a2195e5b8` | Subnet unrestricted inbound internet access | Network |
| `43d3165a-7cb1-4eb4-b726-5178582bd414` | Virtual Machine Scale Set is exposed to the internet | Network |
| `14f5990b-29c6-4060-b7c7-abdc6387378d` | Virtual Machine is exposed to the internet | Network |
| `995deb71-0dc4-4104-a89e-fdd4ad3ef4a3` | Virtual Machine is using unmanaged disk | Compute |
| `bffad34b-cd82-4c77-89a2-be9c704e9a88` | Virtual Machine trusted launch is not enabled | Compute |

### `R10-not-addressable-by-resource-id` (24)

**Reason:** No per-resource ARM id to bind the finding to.

**The Azure-specific class, and the one with no AWS counterpart.** `Recipe` requires `cli_template` to name `{resource_id}`, and an ARM resource id can only be handed to a command that accepts `--ids`. That is not universal in `az`, and `providers/azure/recipes/__init__.py` already records it as the reason the planned Key Vault RBAC recipe does not exist -- this class generalises that one finding to every policy it covers.

Two measured causes, kept in one class because the consequence is identical and overturning one means overturning both:

* **The update verb exists but takes no `--ids`** (11 members). Probed on a clean Azure CLI 2.89.0: `az keyvault update`, `az acr update`, `az aks update`, `az aks enable-addons`, `az aks disable-addons`, `az batch account set`, `az cognitiveservices account update` and `az bot update` all lack it.
* **The setting is subscription-scoped** (13 members). The Microsoft Defender plan policies are set with `az security pricing create --name <plan>`, which addresses a *plan* rather than a resource, so there is no id for a per-resource finding to carry.

These become writable if `Recipe` grows a way to express a subscription-scoped or name-addressed command. That is a core-model change, so it would move all 24 at once.

| Policy id | Policy | Category |
| --- | --- | --- |
| `a478aa6a-16ca-4e96-bf67-dd9974f38f0f` | AKS Cluster Azure Policy add-on is not enabled | Kubernetes |
| `27e0e54d-7a9e-42c4-9c1f-5b23134ae46f` | AKS Cluster Azure RBAC for Kubernetes authorization is not enabled | Kubernetes |
| `dda8b3f9-f941-4f99-bc97-6d37c1366589` | AKS Cluster HTTP application routing add-on is enabled | Kubernetes |
| `dddb467b-ed41-48d1-b3ff-47a28fa94f77` | AKS Cluster local authentication methods are enabled | Iam |
| `d2a57dfb-61cc-4630-abb8-7fb73e18a08b` | Azure AI Service data loss prevention is not enabled | Ai |
| `fcbdd1d2-5211-41ba-a66b-a23c8790e253` | Azure AI Service local authentication is enabled | Ai |
| `b5f8e27e-6e4d-4575-88d9-a50ced557b68` | Batch Account local authentication is enabled | Iam |
| `15e4dcf1-9b9e-4e76-885c-b451ac7ee113` | Bot Service local authentication is enabled | Ai |
| `d9b2630d-fe0f-4abc-a37d-94a2e4095e3a` | Container Registry admin user is enabled | Iam |
| `0589c41a-1fb5-494b-958d-680267b981f5` | Container Registry anonymous pull access is enabled | Compute |
| `75ba091e-f1de-4478-8dac-cf3d1fb0e43e` | Key Vault role-based access control is not enabled | Iam |
| `fc7a4b21-96c6-4d7c-ad3b-d6ad060e8ab0` | Microsoft Defender for AI Services is not enabled | Monitoring |
| `709dc747-f861-4832-b81d-8672463f8ca1` | Microsoft Defender for APIs is not enabled | Monitoring |
| `0e0e6cad-c76d-4842-a65c-09ecfc26a1c1` | Microsoft Defender for App Services is not enabled | Monitoring |
| `cdfff942-7fe0-4eeb-932f-9af20ba3aa29` | Microsoft Defender for Azure Cosmos DB is not enabled | Monitoring |
| `1efe1729-1be0-45f6-abab-107f4cd2b24a` | Microsoft Defender for Azure SQL Databases is not enabled | Monitoring |
| `d6b8d62d-4fe1-4414-b477-651eb9ffde9c` | Microsoft Defender for Containers is not enabled | Monitoring |
| `9d0dd71f-4938-4aa7-a32a-5f26b6cd0224` | Microsoft Defender for Defender CSPM is not enabled | Monitoring |
| `d5a06d00-009d-4478-8fc3-18b70cb26eec` | Microsoft Defender for Key Vault is not enabled | Monitoring |
| `d79c7ada-9c91-46de-a895-269b81e4a1c6` | Microsoft Defender for Open-Source Relational Databases is not enabled | Monitoring |
| `ea3a3937-134f-4444-b344-8c93f441b2b3` | Microsoft Defender for Resource Manager is not enabled | Monitoring |
| `773abf2a-2cc4-42f2-aa46-4406dbfaf546` | Microsoft Defender for SQL Servers on Machines is not enabled | Monitoring |
| `11aecb34-3c8e-469f-8ab5-451153195ec3` | Microsoft Defender for Servers is not enabled | Monitoring |
| `59833e60-5303-4b18-8dee-09352a369359` | Microsoft Defender for Storage is not enabled | Monitoring |

### `R3-policy-document-rewrite` (22)

**Reason:** Target state is a diff against a document with unknown callers.

NSG rules, role assignments, WAF managed-rule sets, Event Hub and Service Bus authorization rules, Application Gateway listener SSL profiles. The fix is not a value but an edit to a document whose other entries are load-bearing for callers the finding does not enumerate. "Unrestricted SSH inbound" is the clear case: the safe change is to narrow the source prefix to the addresses that legitimately need it, and nothing in the finding knows what those are. The four `Overpermissive`/`Overprivileged` members are the same problem stated as identity rather than network.

| Policy id | Policy | Category |
| --- | --- | --- |
| `679f0e39-fb51-46e2-a1ce-630080cc389c` | Application Gateway HTTP/2 is not enabled | Network |
| `84bac514-b449-4211-9dd7-7b9a4cb52db5` | Application Gateway TLS version does not meet minimum requirements | Network |
| `7eac4f2d-2dc5-4c03-943b-e8b38da63fb2` | Application Gateway WAF Policy Request Body Inspection is not enabled | Network |
| `a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d` | Application Gateway is not associated with WAF Policy | Network |
| `a404d2fa-a8a2-49b3-bf78-0ea58ab42b89` | Application Gateway listener SSL profile is not set | Network |
| `c43ef16c-b6bc-4b66-a351-13273022e307` | Application Gateway listener encryption in transit is not enabled | Network |
| `a042fbb2-5bb6-4962-8205-df686c828337` | Event Hub Instance authorization rules are not set | Data |
| `e78930ed-7200-4aa5-9770-103e4fd6f31b` | Front Door WAF Policy has disabled managed rules | Network |
| `052bba32-114c-4627-a87a-538b5ba0744d` | Front Door WAF Policy is not enabled | Network |
| `577e7351-b9c6-404c-9f20-6aad3b478cb7` | Microsoft Entra ID external or guest user with admin role in subscription | Iam |
| `b967b2ea-bfa9-4ece-b1d2-83e0671275ba` | Network Security Group insecure inbound internet access via service tag | Network |
| `42ba1316-1940-47ec-823e-20fadf555f49` | Network Security Group unrestricted RDP inbound internet access | Network |
| `176a2ba9-af9b-4b51-91fc-84a78ebf719a` | Network Security Group unrestricted SSH inbound internet access | Network |
| `7b571b44-f125-41b8-ac13-2f0dbeeacfac` | Network Security Group unrestricted UDP inbound internet access | Network |
| `1d3d0e9e-9853-4d7b-bb3a-fe023c2f7ab0` | Overpermissive Azure Data Factory | Network |
| `03fb7ae8-7fc7-4c6d-8a1a-5720548aee4a` | Overpermissive Batch Account | Network |
| `93c11fab-e7c1-42ae-a3e9-ea11381129a2` | Overpermissive Service Bus Namespace | Network |
| `fd886610-a4be-4703-8e39-81b24b28b2c5` | Overprivileged Managed Identity in subscription | Iam |
| `3f778544-689a-4661-a077-3927bd9358c0` | Overprivileged Microsoft Entra ID Application in subscription | Iam |
| `d04269b9-7c5d-44d1-9227-e741fcf005f3` | Overprivileged Microsoft Entra ID Group in subscription | Iam |
| `d04543b7-8dbf-47e5-a78d-259ab54c2954` | Overprivileged Microsoft Entra ID User in subscription | Iam |
| `8d2ca649-ae40-4faa-a48b-dc8dbc0c5839` | Service Bus Namespace has non-root authorization rules | Iam |

### `R5-build-out-not-remediation` (18)

**Reason:** Creates net-new subscription-scoped infrastructure.

The ten `Missing subscription alarm` policies dominate: each wants an activity-log alert rule that does not exist, complete with an action group and notification targets. Also here: VM agent installation, Windows automatic updates, an AKS upgrade channel, a Data Factory Git repository, a locked immutability policy. These are provisioning tasks. A tool whose contract is one reversible call against one existing resource cannot express them, and stretching it to try is how a remediation generator turns into a half-configured infrastructure tool.

| Policy id | Policy | Category |
| --- | --- | --- |
| `ab0d6e22-7097-44a9-880e-fd1dff0c089a` | AKS Cluster node pool has fewer than 3 nodes | Kubernetes |
| `2035dae1-1c78-4ced-9235-770cb12e8d94` | AKS Cluster upgrade channel is not configured | Kubernetes |
| `3bbc0081-ca3f-412f-b292-bb61bf6e6be3` | App Service health check is not configured | Compute |
| `f5158c26-29bd-4d55-9615-7ec51c49caed` | Container Registry retention policy is not enabled | Compute |
| `63057d99-a68f-4515-94f1-a7234d6eb6a3` | Data Factory Git repository is not configured | Management |
| `09e11b2b-f944-4fbe-a6c6-ed2006064b7a` | Missing subscription alarm – create or update SQL Server firewall rule | Monitoring |
| `b4a35256-a166-4cef-96e5-7e25b30ac381` | Missing subscription alarm – create or update network security group | Monitoring |
| `c64cb9f6-a6fe-47aa-ab80-192f04623adc` | Missing subscription alarm – create or update public IP address rule | Monitoring |
| `6cf842bb-cf5b-4abd-8d2c-68db68274f14` | Missing subscription alarm – create or update security solution | Monitoring |
| `d5ae6023-1e1c-432d-a3f7-8f18b846edb0` | Missing subscription alarm – create policy assignment | Monitoring |
| `e9a9b3af-ede3-4de1-9956-f0249f618433` | Missing subscription alarm – delete SQL Server firewall rule | Monitoring |
| `5f4ff771-b0ed-49d8-ae5a-684552638d62` | Missing subscription alarm – delete network security group | Monitoring |
| `7d847303-32a0-47fe-89e8-693de041b5ce` | Missing subscription alarm – delete policy assignment | Monitoring |
| `95946755-b7cc-484c-90fa-ccbfdd87d591` | Missing subscription alarm – delete public IP address rule | Monitoring |
| `1983e2f3-37a9-4c76-ade8-c010570f879a` | Missing subscription alarm – delete security solution | Monitoring |
| `b95d7aa7-7194-4269-b117-a33197321618` | Storage Account immutability policy is not enabled and locked | Data |
| `735b8da7-dd29-4d16-aee3-41d417f5796f` | Virtual Machine agent is not installed | Compute |
| `f0930d0b-cd32-4fbc-9d2a-2914fa767028` | Windows Virtual Machine automatic updates are not enabled | Compute |

### `R1-detection-no-target-state` (14)

**Reason:** A detection, not a misconfiguration.

"Unusual Network Access Management", "New privileged identity in subscription", "Inactive Managed Identity", "Azure resource tags are exposing secrets". These report that something *happened* or that something *looks wrong*, with no attribute whose value is the fix. There is no target state to write, so there is nothing for an idempotent call to converge on. Two members are worth naming because they look actionable and are not: an expired Key Vault certificate needs a *new certificate* (R7 territory), and a predictable SQL administrator login name cannot be changed at all after server creation.

| Policy id | Policy | Category |
| --- | --- | --- |
| `65df6b30-1321-4eb6-91d6-adb6c5fca117` | AKS Cluster is running images that are not scanned for vulnerabilities | Kubernetes |
| `642389d9-6311-458a-8b35-57b2925e9e27` | AKS Cluster system nodes run non-critical workloads | Kubernetes |
| `adaca448-1a43-49d5-b211-35aae58e02a4` | Azure resource tags are exposing secrets | Secrets |
| `e555f01e-2c7c-4c1b-9f07-b8188311110d` | Compute Disk is unattached | Management |
| `fbf4ac2a-ad44-44c9-828e-5bed0ee62131` | Inactive Managed Identity | Iam |
| `54765b71-b0f6-4d62-b67a-ff03bfc51f10` | Key Vault Certificate is expired | Network |
| `d6d67be5-e555-4bac-9a91-69241225a9e3` | Logic App is exposing secrets | Secrets |
| `d75ac28d-16c3-459f-88b5-4dd97f25809c` | New Azure subscription | Management |
| `bb69a023-d26c-4f94-9ea4-b75f84904902` | New privileged identity in subscription | Iam |
| `a6ce2a7b-285b-4160-af8e-184433bc6232` | Public Storage Account Blob Container | Data |
| `b51863eb-3e39-48e9-9333-619a47cd5dca` | Public activity log Blob Container | Logging |
| `3ca34d77-bc53-4f09-bb88-35669d0419cf` | SQL Server administrator login name is predictable | Data |
| `8b33f8cd-60fc-4008-9c54-dd4aade3f0a9` | Unusual Network Access Management | AnomalyDetection |
| `7a64ea40-3b6c-44ad-bd30-cb876fa1b718` | Unusual Permission Management | AnomalyDetection |

### `R4-unbounded-log-ingest` (10)

**Reason:** One call, unbounded recurring bill.

Diagnostic settings, blob/queue/table service logging, AKS Azure Monitor, Key Vault logging, App Service request tracing. Each is genuinely a single idempotent call, and each attaches a destination that then bills per GB ingested for as long as it stays on. The destination -- which workspace, which storage account, what retention -- is a cost decision with no safe default, and picking one for an operator is picking their bill. This is the class most likely to be *partially* overturned: a recipe that requires an existing destination id as a parameter is defensible in a way that one which provisions a workspace is not.

| Policy id | Policy | Category |
| --- | --- | --- |
| `911e34cd-e426-4a89-b456-6d1a001cf609` | AKS Cluster Azure Monitor logging is not enabled | Logging |
| `0edf1ea9-8855-438e-ae7c-0609a08e309f` | App Service Web App failed request tracing is not enabled | Logging |
| `d55b22c8-43d4-4a15-9032-ce696eed48f6` | App Service detailed error messages are not enabled | Logging |
| `8730e98c-633d-494c-ada1-aae310e4adf8` | Key Vault logging is not enabled | Logging |
| `c7b1b91c-c498-4e21-a3ac-0a042b4b2c3d` | Machine Learning Workspace logging is not enabled | Ai |
| `2bb461d0-599d-4905-a65b-fdc6f97a2250` | Missing Activity log diagnostic settings | Logging |
| `53e62436-7aa9-4403-866c-63cd7a5aa3e7` | SQL Server audit retention for storage account is not set | Data |
| `c9e0acfc-f131-4f28-9e54-4351e96f39cc` | Storage Account blob service logging is not enabled | Logging |
| `0cb1b644-5a38-4e92-bb91-8154cbc2fb4c` | Storage Account queue service logging is not enabled | Logging |
| `56451881-cb18-4c20-a97a-4384aa8f7922` | Storage Account table service logging is not enabled | Logging |

### `R7-requires-secret-or-rotation` (7)

**Reason:** Needs an input no generator can supply.

Key rotation, certificate rotation, storage access-key rotation, automatic-rotation policies. Rotation is not a setting; it is an operation that invalidates credentials currently in use by callers the finding cannot enumerate. Enabling an automatic-rotation *policy* is closer to writable, but it schedules the same breakage for a later date without telling anyone, which is worse than leaving the finding open. This project does not author secrets, and rotating one is the same commitment as creating one.

| Policy id | Policy | Category |
| --- | --- | --- |
| `00386671-1924-4325-b414-d6c718a1b009` | Key Vault Certificate automatic rotation is not enabled | Data |
| `4e4524b9-dcab-4aa6-9c75-7b3ae5136365` | Key Vault Certificate is not rotated | Data |
| `c123ad88-98c5-4d83-a31c-04a106fab21f` | Key Vault Key automatic rotation is not enabled | Data |
| `397726b5-47d3-4bad-9649-9f913f11e75b` | Key Vault Key is not rotated | Data |
| `33a4f534-a154-4aec-8555-92e3c97987df` | Key Vault Secret is not rotated | Data |
| `43a5db33-db62-4096-a03d-0ec87120dd30` | Storage Account access key is not rotated | Data |
| `c223ad65-e7b1-4d85-a783-92e271f07017` | Storage Account access key is not rotated before expiration | Data |

### `R6-no-partial-update-command` (4)

**Reason:** Missing command shape, not a missing recipe.

Key Vault key and secret expiration, secret content type, certificate validity period. The `az keyvault` verbs for these replace the object's attribute set rather than patching one field, so a generated call would silently reset the attributes it did not mention. Small class, and the one most likely to move: a later CLI version that grows a patch verb makes every member writable at once, which is exactly why they are grouped rather than argued individually.

| Policy id | Policy | Category |
| --- | --- | --- |
| `47d41521-d3a1-457e-8709-34b0c7219d8a` | Key Vault Certificate validity period is longer than 12 months | Secrets |
| `49046962-4b7a-429a-8312-7b7bb7f65a45` | Key Vault Key expiration is not set | Data |
| `b62e230a-77b8-444b-9c47-dfeeff5eb2d2` | Key Vault Secret content type is not set | Secrets |
| `8eaee3e6-c334-438d-95f3-cc372a1a3b0d` | Key Vault Secret expiration is not set | Data |

### `R9-blast-radius-beyond-resource` (2)

**Reason:** Effect extends past the named resource.

Two members. App Service encryption-in-transit terminates existing HTTP clients, and Key Vault delete protection cannot be turned off once on -- an irreversible setting fails this project's reversibility requirement even though enabling it is a single call. Small class, but it is the one that keeps reversibility from being negotiable.

| Policy id | Policy | Category |
| --- | --- | --- |
| `5cc4e3e7-9781-4560-a5df-b52608a82733` | App Service encryption in transit is not enabled | Data |
| `4a8b266c-9568-4022-a84f-ada0e28d5a0a` | Key Vault delete protection is not enabled | Data |

## Keeping this file honest

Three claims here rot, and a CI step in the `claims` job checks each:

1. **The buckets partition the catalogue.** Every policy id appears exactly once across all four
   sections, and the totals in *Result* match the rows actually present. A policy silently in two
   buckets, or in none, is the failure mode a hand-maintained register has.
2. **The shipped list is the shipped set.** The *Shipped* table must equal the policy ids reachable
   from the Azure provider descriptor, in both directions. This is the claim that goes stale the moment
   a batch lands.
3. **Nothing is shipped that this file rejects.** A policy id in any rejection class must not have a
   recipe. If a rejection is overturned, the row moves *and* the class's reasoning is edited.

The gate is per-cloud and driven by the **discovered** provider descriptors, not a hardcoded list of
documents. Adding a third cloud therefore fails the build until that cloud has a register, which is the
same discipline `SECURITY.md`'s scope-guard check uses and for the same reason: the edit that adds a
cloud is exactly the edit where a per-cloud document gets forgotten.

What the gate deliberately does *not* check is whether an assignment is *correct*. That is a judgement
about an external API surface, and no CI job here can reach one. Two assignments in this pass were
wrong in ways no gate would have caught -- both found by probing `az`, which is why the probe is written
into the contributor procedure rather than left to diligence.
