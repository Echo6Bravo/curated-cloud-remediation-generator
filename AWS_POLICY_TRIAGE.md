# AWS policy triage

Every AWS-only policy in the Tenable Cloud Security catalogue, assigned to exactly one of four
buckets: shipped, write-a-recipe-now, blocked-on-a-named-prerequisite, or documented rejection.

This is the register `ROADMAP.md` points at for *why a given policy has no recipe*. The two
rejections recorded in that file's Azure coverage section are the pattern; this generalises it to
AWS, where the answer for most of the catalogue is that no safe recipe shape exists rather than
that nobody has written one yet.

**Status: desk triage.** Bucket assignment was made from the policy title, the service's API
surface and the rejection classes below. It is *not* the per-recipe three-axis verification
described in `CONTRIBUTING.md`; that happens when a recipe is written, and it is allowed to
overturn an assignment here. Two such reversals are predicted in the batch table.

One assignment was already corrected during the pass, and it is the useful warning: the four
AWS-only `Kubernetes`-category policies were first rejected wholesale as in-cluster concerns, on
the strength of the *category name*. Three of them are ordinary EKS control-plane calls -- public
node IPs, a public Kubernetes API endpoint, and image-scanning -- and one needs a CMK. They are now
assigned individually. Rejecting by category rather than by policy is the mistake this register is
meant to make visible, so it is recorded here rather than quietly fixed.

## Which catalogue this counts

The tenant exposes the policy catalogue through two APIs and **they disagree**:

| Source | Total policies | AWS |
| --- | --- | --- |
| UDM (`RiskPolicyModel`, `RiskPolicyTenantTypes In ["Aws"]`) | 1063 | 427 |
| GraphQL (`{ Policies { Id Name Category Providers } }`) | 739 | 344 tagged |

The 427-to-344 gap is accounted for exactly: GraphQL omits `Custom` (17, tenant-authored),
`KubernetesAdmissionController` (28) and the 38 policies with a `null` category -- 83 in total. It
also uses different category names (`Access` where UDM says `Iam`, `WorkloadProtection` where UDM
says `WorkloadAnalysis`).

**This document triages the 237 GraphQL AWS-*only* policies**, for two reasons. GraphQL is the
only source that yields policy *names* -- `RiskPolicyTitle` is a `CommonVirtual` property and
cannot be selected in UDM -- and a name is the minimum needed to reason about a remediation. And
AWS-*tagged* is the wrong denominator: 344 tagged versus 237 AWS-only, the difference being
Kubernetes and workload policies tagged for every provider at once, which are in-cluster concerns
rather than cloud control-plane calls.

**What that leaves uncounted, stated plainly:** the 17 `Custom` policies (tenant-authored, no
stable upstream to verify a remediation against), the 28 `KubernetesAdmissionController` policies,
and the 38 with no category. Those 83 have not been triaged by anything in this file. A future
pass over them should say so in this section rather than quietly changing the totals.

## Result

| Bucket | Policies | Share |
| --- | --- | --- |
| Shipped | 6 | 2.5% |
| Write a recipe now | 24 | 10.1% |
| Blocked on a prerequisite | 31 | 13.1% |
| Documented rejection | 176 | 74.3% |
| **Total** | **237** | |

The design ceiling is **61 of 237** (26%). That number
is the useful output of this exercise: roughly three quarters of the AWS catalogue cannot be
expressed as a single idempotent, reversible, per-resource API call, and the reasons collapse into
8 classes rather than one judgement per policy. A coverage figure quoted against
237 without that context reads as a backlog; quoted against the ceiling it reads as what it is.

## Shipped

| Policy id | Policy | Category |
| --- | --- | --- |
| `8d1140ba-c917-44d7-b2ea-084f9dffe707` | CloudTrail S3 Bucket log file validation is not enabled | Logging |
| `468d7976-445f-44c2-b9fb-45fb1005f373` | DynamoDB Table delete protection is not enabled | Data |
| `995e8d78-940a-45bf-bac1-61a1fdb00d7a` | KMS Key automatic key rotation is not enabled | Data |
| `4d6662cd-9f34-41eb-b152-f24c692d4fbf` | RDS Instance delete protection is not enabled | Data |
| `80b8e9b6-c285-4939-b115-452dfd65bbcc` | S3 Bucket block public access is not enabled | Data |
| `284b1210-a31e-48ce-97af-f4d825ef132d` | S3 Bucket versioning is not enabled | Data |

## Write a recipe now

Batched by AWS service, because the service is the unit verification happens in -- one API model,
one CLI command group, one family of provider resource types, one `recipes/<service>.py`. This is
the same axis `ROADMAP.md` gives for the module split.

| # | Batch | Module | Recipes | Estimate | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | ec2 | new | 4 | 8-11 h | IMDSv2 closes SSRF-to-credential-theft; the snapshot/image `reset-*-attribute` calls de-publicise data. All four single-call, reversible, free. |
| 2 | rds | extend | 4 | 5-7 h | Patterns already proven in the module. Cluster delete protection mirrors the shipped instance recipe almost exactly. |
| 3 | docdb + neptune | new (paired) | 5 | 7-9 h | Both RDS-API-shaped, so the rds batch does most of the reasoning. Distinct HCL resource types and import ids is the residual cost. |
| 4 | s3 | extend | shipped | -- | **Landed.** One recipe, as listed. All four Block Public Access flags are set: the policy asks whether BPA is enabled, and a subset would emit a command that runs cleanly and leaves the finding open. Ships `safest` because every field that derives `caution` is honestly false -- see the module comment for why the tier cannot express "reversible, free, and may still cut off your public website", and what would have to change to fix that. |
| 5 | apigateway | new | 4 | 9-12 h | Four recipes, one module. Execution logging is adjacent to R4 and moves to rejection if it provisions ingest rather than writing to an existing group. |
| 6 | kms + acm | extend + new | 2 | 4-6 h | Small. The KMS entry needs a written note on why two near-identical policy ids get one recipe rather than two. |
| 7 | athena | new | 2 | 4-6 h | `update-work-group` takes a nested config struct; becomes R6 if partial update is not honoured. |
| 8 | elbv2 + elasticache + dms | 3 new | 3 | 8-11 h | Lowest priority: three module setups for three recipes, the worst overhead-to-coverage ratio in the set. The ELB listener policy may fall to P1 on old-client breakage. |

**Total: 24 recipes, 45-62 h**, plus 6-9 h for this document's rejection register once the
classes are written against each member. Roughly 7-9 working days.

### Basis for the estimates

Per recipe: **3-4 h**, and it is verification rather than authorship. The code is around sixty
lines (`recipes/dynamodb.py` is 66). The hours go to: the API model and exact parameter names; CLI
flag existence on the pinned CLI version; the provider resource type and attribute names against
the machine-readable schema; a hand-run `terraform import` to confirm the import-id template -- the
comment in `recipes/dynamodb.py` recording that import is exactly this step; the reversal command;
and the five safety attributes. A new
module adds about **2 h** for wiring, the service-id assertion in `tests/test_recipe_set.py`, and
sample regeneration.

**These are bottom-up estimates from that checklist, not measurements.** No wall-clock record
exists for the nine recipes already shipped across both clouds, so there is no calibration factor in
them. Treat the ranges as the width of that ignorance.

### Per-policy assignment

**`recipes/ec2.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `d7d21b80-415d-4c55-80ea-0d51231337da` | EC2 Instance metadata service supports insecure version | Compute |
| `7b123d62-231a-4e2e-85ff-23502ab97645` | EC2 Instance metadata response hop limit does not meet minimum requirements | Compute |
| `b2449a24-1068-48ed-8587-c6d62c47ea98` | Public EBS Snapshot | Data |
| `2d9d7738-6ba0-435b-a61c-41d7adf79836` | Public EC2 Image | Data |

**`recipes/rds.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `03242d06-4bec-44b5-89fa-0ebb4d926242` | RDS Cluster delete protection is not enabled | Data |
| `b03ad608-ad17-4165-95bd-3611db4f2185` | Public RDS Snapshot | Data |
| `12ecb360-5e79-49ee-b771-7358670a185d` | RDS Cluster automatic minor version upgrade is not enabled | Data |
| `ca0fddf1-a200-458c-a3cb-b78ad774c3d8` | RDS Instance automatic minor version upgrade is not enabled | Data |

**`recipes/docdb.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `53e6e298-1d59-4784-85a3-16a0a337a8ba` | DocumentDB Cluster delete protection is not enabled | Data |
| `af6ffc0a-3264-4099-9bbb-a47ad68987e1` | Public DocumentDB Cluster Snapshot | Data |

**`recipes/neptune.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `a4b1787d-5cc2-4f19-afb9-83351c54565f` | Neptune Cluster delete protection is not enabled | Data |
| `4d736b38-2371-4829-912f-ed776a899988` | Public Neptune Cluster Snapshot | Data |
| `677e265c-b3ca-4f04-8753-56c926350951` | Neptune Instance automatic minor version upgrade is not enabled | Data |

**`recipes/s3.py`**

| Policy id | Policy | Category |
| --- | --- | --- |

**`recipes/apigateway.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `c2b92902-031d-4067-ab0b-e0afb81a6c53` | API Gateway insecure communication | Network |
| `2a03c759-c695-44c4-b0bd-0db42daf617e` | API Gateway REST API cache encryption is not enabled | Network |
| `ccca433e-17c0-48f4-aa46-4fc649d67854` | API Gateway execution logging is not enabled | Logging |
| `a5ce99f6-181f-4a3a-8755-8f515d4fc25b` | API Gateway X-Ray tracing is not enabled | Logging |

**`recipes/kms.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `5f29b14f-7fa9-4473-b724-4fe6d7f05a5d` | KMS Key is not rotated | Data |

**`recipes/acm.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `e36e67e5-9678-495a-8fad-7bb871e5ac1d` | ACM Certificate transparency logging is not enabled | Network |

**`recipes/athena.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `57c5f5fd-ff88-4342-a481-0b2db47b8d4f` | Athena Workgroup query results are not encrypted | Data |
| `b7bf3263-f29c-46bb-92c2-d52ebd16a2db` | Athena Workgroup does not publish logs to CloudWatch | Logging |

**`recipes/elbv2.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `b6134b62-3e90-493a-a7e7-e71ea53f46ef` | Load Balancer insecure communication | Network |

**`recipes/elasticache.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `8be59073-b3ec-4c44-80af-bab2a45b84d5` | ElastiCache Redis OSS Cluster Cache automatic minor version upgrade is not enabled | Data |

**`recipes/dms.py`**

| Policy id | Policy | Category |
| --- | --- | --- |
| `14e42180-00af-4726-a4a1-e66d10e44891` | DMS Replication Instance automatic minor version upgrade is not enabled | Data |

## Blocked on a named prerequisite

Scriptable in principle. Each is held by one identified missing thing, named so that resolving it
unlocks a known set rather than requiring this triage to be redone. These 27 are the leverage in
the whole table: two design decisions unlock more policies than all eight recipe batches combined.

### `P1-consent-gate` (11)

**Prerequisite:** The unresolved `--safety-level` question.
Security-group and NACL open-ingress rules, public-access disables, access-key deactivation, SageMaker root access. Each is a single reversible call, and each can sever live traffic or a running integration. They are blocked on the consent question in ROADMAP.md (*Safety-level consent*), whose current recommendation is per-recipe opt-in for this class. `caution` does not carry enough signal to mean "may drop production traffic", and shipping them under it would be the reclassification the tier system exists to prevent.

| Policy id | Policy | Category |
| --- | --- | --- |
| `d2d00a29-a1b3-4480-9831-8c85db21bbe2` | Security Group unrestricted inbound internet access | Network |
| `0db15ef9-8019-4bac-87a6-358070c58cb8` | Default Security Group has rules configured | Network |
| `ccb868b4-cbf0-46c1-b612-a81e206137b5` | Network ACL unrestricted inbound internet access | Network |
| `3652d657-40dd-4a04-b7ab-c8e560417af0` | RDS Instance is exposed to the internet | Network |
| `e86ac2fa-316a-4a7b-a1f7-d0f4761ecd29` | Redshift Cluster is exposed to the internet | Network |
| `e8dd8760-f872-4580-b5ea-d67c4759aae7` | DMS Replication Instance public access is enabled | Data |
| `d035ffcf-8803-436c-aeb9-81ec0c3cf4e8` | EKS Cluster Kubernetes API is exposed to the internet | Kubernetes |
| `d91a4402-5cdc-4f25-b8ad-7e6006f3ed12` | IAM User active access keys are not rotated | Iam |
| `e1323135-5799-484b-96e6-478354c407a9` | IAM User has multiple active access keys | Iam |
| `ca9d3ffc-6ff0-4716-b467-75a609b31120` | IAM User unused access keys | Iam |
| `5d1d651c-559c-45e1-8552-c797d402fb0f` | SageMaker Notebook Instance root access is enabled | Ai |

### `P2-operator-parameter` (18)

**Prerequisite:** A value the finding does not contain.
CMK-encryption policies (*which* key?), retention-period minimums (*how many* days?), password policy, access-log destinations (*which* bucket?). Blocked on a parameter-input mechanism that does not exist. Inventing one per recipe is how `--max-per-file` came to describe one cloud's split in the other's vocabulary.

| Policy id | Policy | Category |
| --- | --- | --- |
| `c65682c4-7a16-4988-a8de-216ae9ae6936` | S3 Bucket is not encrypted with KMS | Data |
| `b14c59ae-d215-40e9-a158-89afab574c28` | DynamoDB Table is not encrypted with KMS | Data |
| `3efb53f0-ad91-48dd-a576-c4f2fec5677a` | Kinesis Data Stream is not encrypted with KMS | Data |
| `8fb0eedf-b0b5-45b5-a6ea-ed93f69afbdf` | SNS Topic is not encrypted with KMS | Data |
| `2208ef3f-a0b6-4445-ae49-782c74f2fe50` | SQS Queue is not encrypted with KMS | Data |
| `741a7ff4-adf4-49d7-9d99-92c8c767d0f5` | Data Firehose Stream is not encrypted with KMS | Data |
| `c1cf899c-0557-4b9c-a501-868015841613` | CloudTrail Logs are not encrypted with CMK | Logging |
| `fa2c5e6e-d355-4cf9-97b4-e2e1818989a1` | DocumentDB Cluster backup automatic retention period does not meet minimum requirements | Data |
| `5c0a767a-a8a5-492b-b068-075d3cc5e902` | ElastiCache Redis OSS Cluster Cache automatic backup retention period does not meet minimum requirements | Data |
| `f1a3d8d9-33b0-4e59-9466-130ff292dc3a` | Neptune Cluster backup automatic retention period does not meet minimum requirements | Data |
| `b395f754-59fe-4e8f-90b5-b88ee2c43a10` | RDS Cluster backup automatic retention period does not meet minimum requirements | Data |
| `15623eeb-4d91-42fc-9b89-cd2730aeba6d` | RDS Instance backup automatic retention period does not meet minimum requirements | Data |
| `20d76b24-f842-4d3b-a7ad-2dad17ee6d57` | Redshift Cluster backup automatic retention period does not meet minimum requirements | Data |
| `90c603af-6afd-4cd2-a945-edf235ac0f1c` | Password length does not meet minimum requirements | Iam |
| `68dcfde9-b903-4511-a6e6-60632eb47cf8` | Password reuse policy does not meet minimum requirements | Iam |
| `5fabe15c-749d-40ee-827b-a7597151a686` | Load Balancer access log is not enabled | Network |
| `f8257779-cab7-451b-82c8-8929bf3b3fd2` | Redshift Cluster audit logging is not enabled | Logging |
| `536beb5c-d4b1-465b-a1be-1061c2743b75` | Kubernetes secrets are not encrypted with KMS | Kubernetes |

### `P3-unverifiable-precondition` (2)

**Prerequisite:** Succeeds or hard-fails on unreported state.
ElastiCache automatic failover requires a multi-AZ replication group; MSK in-transit encryption is create-time on some cluster shapes. The finding does not report the precondition, so the generated command's outcome is not predictable from the finding alone.

| Policy id | Policy | Category |
| --- | --- | --- |
| `d607afd5-8850-4abe-87c0-5aa9484551d4` | ElastiCache Redis OSS Cluster Cache automatic failover is not enabled | Data |
| `16fbc212-12c9-4947-a37c-771addbdc090` | MSK Cluster encryption in transit is not enabled | Data |

## Documented rejection

Eight classes, ordered by size. A class is the unit of rejection: a policy is rejected *because it
is an instance of one of these*, which is what keeps the register from being a heap of unrelated
opinions. If a class turns out to be wrong, every member is reconsidered together.

| Class | Policies | One-line reason |
| --- | --- | --- |
| [`R2-requires-replacement`](#r2-requires-replacement-45) | 45 | No in-place API exists |
| [`R3-policy-document-rewrite`](#r3-policy-document-rewrite-35) | 35 | Target state is a diff against an unknown-caller policy |
| [`R5-build-out-not-remediation`](#r5-build-out-not-remediation-29) | 29 | Creates net-new account-scoped infrastructure |
| [`R4-unbounded-log-ingest`](#r4-unbounded-log-ingest-24) | 24 | One call, unbounded recurring bill |
| [`R7-requires-secret-or-mfa`](#r7-requires-secret-or-mfa-18) | 18 | Needs an input no generator can supply |
| [`R9-blast-radius-beyond-resource`](#r9-blast-radius-beyond-resource-9) | 9 | Deletion of something with unknown consumers |
| [`R1-detection-no-target-state`](#r1-detection-no-target-state-8) | 8 | A detection, not a misconfiguration |
| [`R6-no-partial-update-command`](#r6-no-partial-update-command-8) | 8 | Missing command shape, not missing recipe |

### `R2-requires-replacement` (45)

**Reason:** No in-place API exists.
Encryption-at-rest on an existing EBS volume, RDS instance, OpenSearch domain or SageMaker notebook; attaching a Lambda to a VPC; an expired certificate. The fix is snapshot-recreate-cutover, not an attribute change. Generated HCL would emit a *forces replacement* plan -- the same hazard `recipes/dynamodb.py` already records for `hash_key`, where proposing the change was worse than omitting it because the resource cannot be replaced without losing its data.

| Policy id | Policy | Category |
| --- | --- | --- |
| `24b77c49-4545-4061-8e83-e6fd1a4948ee` | 3rd-party IAM Role External ID is not set | Iam |
| `8e6cbdad-4775-4ad7-898f-16a7b69f2cb6` | ACM Certificate domain name contains wildcard | Iam |
| `ad591f3f-3f88-4c8b-8b5f-ea93f6de2dc6` | ACM Certificate is expired | Network |
| `ffcf4980-1a95-49f1-8220-6234af4b925e` | ACM Certificate is in invalid or failed state | Network |
| `3bcfb91f-b7d6-4d61-9793-986fd0a13e96` | ACM Certificate key length does not meet minimum requirements | Data |
| `9cbbab3d-da6b-48b9-ab70-01d979ba85f0` | AWS Account support role is not set | Iam |
| `20e98b88-ecf9-42a6-b00e-4eb28fb85149` | DAX Cluster is not encrypted with KMS | Data |
| `35c5bee3-b88f-4456-884b-9d3530d07df9` | DMS Certificate is expired | Data |
| `1c26e6ec-d311-4057-b0b2-2259bd41846f` | Data Firehose Stream source record backup is not enabled | Data |
| `a964fe13-f099-46fe-ae37-04a703e8f5ad` | DocumentDB Cluster Snapshot is not encrypted with KMS | Data |
| `04fb3536-3a9f-4457-85ca-7c080922e076` | EBS Snapshot is not encrypted with KMS | Data |
| `a3e6018e-98d8-47d3-9f6b-0cf442e9e3c9` | EBS Volume is not encrypted with KMS | Data |
| `acd1c463-7388-43fa-ac3b-772f1dd61ae1` | EC2 Instance IAM Instance Profile is not set | Iam |
| `34b1ff42-455c-4437-a6e2-872169de9030` | EFS Access Point user identity is not set | Network |
| `dd96ca1f-187d-4fe4-b6aa-a3799fae4688` | EFS File System is not encrypted with KMS | Data |
| `29ca7702-1c67-4f71-aded-61c259b16f42` | EFS Mount Target is associated with public IP address | Network |
| `3c7fb6e7-b834-4bde-8db4-e317f17a1ccb` | EKS Cluster contains nodes with public IPs | Kubernetes |
| `bf0c56b2-e36a-4725-80ba-41a43d5fd54a` | EMR Studio is using a shadow resource S3 bucket | Data |
| `d63dcb54-93bf-4a11-8d01-61a1bcab50f5` | ElastiCache Redis OSS Cluster Cache encryption in transit is not enabled | Data |
| `13044447-5d36-49c7-a4cc-fec4d27a196a` | ElastiCache Redis OSS Cluster Cache is not encrypted with KMS | Data |
| `31fa3888-304f-4674-b829-2fbb642e8463` | ElastiCache Redis OSS Cluster Cache is using the default subnet group | Data |
| `ffe865b6-cc3e-4f26-95e6-3f865a5788d4` | Glue Job is using a shadow resource S3 bucket | Data |
| `9a1fb19d-199a-441c-98a6-7634020ac8c9` | IAM Server Certificate is expired | Iam |
| `c7fb0393-9d98-4582-a20f-83616f11b8a2` | KMS Key is expiring in 30 days or less | Network |
| `9e86581c-d593-472e-a9a3-c23d0f05ea93` | Lambda Function does not operate in multiple Availability Zones | Compute |
| `e85ad469-587d-4c20-bcd8-6a17e79582be` | Lambda Function is not associated with a VPC | Network |
| `3c06b27a-6a98-4116-9df4-7555e35d7e04` | Lambda Function is using deprecated runtime | Compute |
| `084ec9f6-fbe7-4280-8fd9-76680764cf4f` | Load Balancer is exposed to the internet | Network |
| `6a7fe0ea-7066-4cd2-b55c-49fc893ea2ce` | Neptune Cluster Snapshot is not encrypted with KMS | Data |
| `f164c0c9-5a56-4fad-9c67-9a51bb9a64b6` | Network Firewall Policy is not associated with a rule group | Network |
| `1b2c2523-2328-41f6-961a-4907c09f2d35` | OpenSearch Domain encryption in transit is not enabled | Network |
| `c30567d6-4b1e-4034-97b9-0c8f85f6aca6` | OpenSearch Domain is not encrypted with KMS | Data |
| `99eb6874-81a5-4184-9044-a1e2c5061bde` | OpenSearch Domain node-to-node encryption in transit is not enabled | Data |
| `891869ef-a69a-40a0-91a3-82ca2fa11648` | Public MQ Broker | Network |
| `28a94ea2-90c3-4c37-8456-ceca4fef191b` | RDS Cluster is not encrypted with KMS | Data |
| `c32b85bd-737a-4003-a879-b21010abd707` | RDS Instance is not associated with a VPC | Network |
| `5713c712-5973-468e-ab4f-050ce92c5edd` | RDS Instance is not encrypted with KMS | Data |
| `f85ea5f3-0d0d-4ecf-92a8-dc0294946627` | RDS Snapshot is not encrypted with KMS | Data |
| `efe56d71-430d-4497-8c9e-d899ccea4c18` | Redshift Cluster encryption in transit is not enabled | Network |
| `45e2affe-b81d-4048-b12b-282f6a0f6cb1` | Redshift Cluster is not encrypted with KMS | Data |
| `5e5f6bfc-98bc-4741-b46d-a9b6aad11e5c` | Redshift Cluster is using the default master username | Data |
| `18f639db-0d19-4989-be25-73ab4e77926b` | Route 53 hosted zone DNSSEC is not enabled | Network |
| `94e8c8f1-915c-4f8f-86a3-1fea9083de3b` | SageMaker Domain is not encrypted with CMK | Ai |
| `e4bfe6cc-0f6c-4726-a9a0-f59f6b483f8d` | SageMaker Notebook Instance direct internet access is enabled | Ai |
| `3f84c82e-bb7c-4bf3-b807-4c93716a1b4f` | SageMaker Notebook Instance is not encrypted with CMK | Ai |

### `R3-policy-document-rewrite` (35)

**Reason:** Target state is a diff against an unknown-caller policy.
`Public S3 Bucket`, `Overprivileged IAM Role`, API Gateway authorization. Remediation edits an existing JSON policy document, and its safe form depends on which legitimate callers exist -- which the finding does not enumerate. Not derivable from a resource id, so there is no templatable command.

| Policy id | Policy | Category |
| --- | --- | --- |
| `6d48f53e-5983-45db-9739-eb0ddc557786` | API Gateway API is not associated with WAF web ACL | Network |
| `6746fc84-cc5a-4734-87da-e24dca7ff73f` | API Gateway API key authorization is not enabled | Network |
| `0252a65d-7538-463b-831c-5acf983e4c76` | API Gateway REST API request validation is not set | Network |
| `f5a1f284-8686-46ec-a38a-1868f6fbe54e` | API Gateway authorization is not set | Network |
| `587d01c9-44d6-4a7c-9203-6e4527f2e6d6` | API Gateway client certificate is not set | Network |
| `ed19e4b8-7bfd-4eaf-b925-cef488431854` | AppSync GraphQL API authentication with API key is set | Data |
| `1eef9be9-d748-46a9-a0b1-4a139bab528c` | AppSync GraphQL API is not associated with WAF web ACL | Network |
| `0206314d-2861-45aa-9589-6975c0928825` | CloudFront Distribution is not associated with WAF web ACL | Network |
| `f3d30888-038a-47a5-b3b3-65a687d03a3e` | External IAM Role | Iam |
| `55edc669-f980-4792-8fc1-1d8dfe1c9981` | IAM Policy with full administrative privileges "*:*" is attached | Iam |
| `fd7d738d-c8c8-4df8-a2f2-d37e97e85539` | IAM User has policies attached | Iam |
| `193a6bfe-d3cf-4e0c-bfad-85ad70671723` | OpenSearch Domain fine-grained access control is not enabled | Data |
| `c2d9b373-00fd-4286-818a-0f11c225e198` | Overpermissive ECR Repository | Iam |
| `ecd58935-6ab2-43c9-a987-8e021f368dd5` | Overpermissive S3 Bucket | Iam |
| `8a3e622c-c09b-4010-9988-efe24e8cdad8` | Overpermissive Secrets Manager secret | Iam |
| `611b14a1-6cc0-44d7-bcb6-517fb4250897` | Overpermissive VPC Endpoint | Iam |
| `7e72f065-78f0-4261-9d4b-c7d6f30ad412` | Overprivileged IAM Group | Iam |
| `d15f824c-f166-42e5-92c9-25eef369afb3` | Overprivileged IAM Role | Iam |
| `6683bdc2-4842-4665-801b-ac2a7aaf33e9` | Overprivileged IAM User | Iam |
| `a7e9b555-486a-414d-a883-19f290b9d338` | Overprivileged SSO Permission Set | Iam |
| `92427712-9d59-4f77-b180-c486fcee7ca3` | Public CloudTrail S3 Bucket | Logging |
| `5bc2fdf6-3ecd-427e-9d78-58ed1e3bf5f4` | Public ECR Repository | Data |
| `804c8ef6-a8dc-4d0a-a253-779523168394` | Public IAM Role | Iam |
| `1ff94f6b-e1f8-4d8f-840f-aa7c8c5546a1` | Public KMS Key | Data |
| `aad983b8-d82a-45cf-a06c-c599c03fa263` | Public Lambda Function | Compute |
| `4255395c-4a01-41ca-b8aa-5dc96c3d7812` | Public OpenSearch Domain | Data |
| `f02421d9-f4ef-4531-9884-4df31511e40a` | Public S3 Bucket | Data |
| `4d39cab0-a3b1-41b6-8ad4-9aae6834a72a` | Public SNS Topic | Data |
| `98ef334d-8b60-4f2d-9775-74368c8974a3` | Public SQS Queue | Data |
| `862675a2-9633-49a7-9f77-fa33ac1ff6db` | Public Secrets Manager secret | Secrets |
| `255150dc-9cb0-4c0d-8432-852c998508d5` | S3 Bucket encryption in transit is not enabled | Data |
| `0d0e6d55-ec8f-4dae-8bc2-a907642ca76d` | S3 Bucket global view ACL permissions is enabled | Network |
| `7ae87f2a-8733-42c9-95e0-f78a4d7fa5f3` | SNS Subscription encryption in transit is not enabled | Data |
| `f41744c6-ed68-4fd6-818f-2a6bc5bbbe42` | SNS Topic encryption in transit is not enabled | Data |
| `8458521c-09e9-4e7a-935f-027bf6d4f1b0` | WAF Web ACL logging is not enabled | Logging |

### `R5-build-out-not-remediation` (29)

**Reason:** Creates net-new account-scoped infrastructure.
The fifteen `Missing CloudWatch alarm - *` policies, twelve GuardDuty enables, Config, Security Hub, IAM Access Analyzer. Each needs a metric filter plus SNS topic plus subscription plus alarm, or an account-wide detector -- construction, not a fix to a named resource. There is also no clean reversal: deleting what you created is not the same as restoring prior state.

| Policy id | Policy | Category |
| --- | --- | --- |
| `2a67af06-af8f-45c1-8f8f-3976bb78dbb6` | AWS GuardDuty is not enabled for all regions | Management |
| `954ea3d6-9f46-46bd-a170-217c4f466ac5` | AWS config is not enabled for all regions | Management |
| `8864e51d-7fe5-4893-9f8e-8415b9e52be9` | AWS security hub is not enabled for all regions | Management |
| `f47ec0f6-9257-4c1c-b97d-f45a6012b020` | EKS Cluster is running images that are not scanned for vulnerabilities | Kubernetes |
| `187a2248-f867-4c58-94e8-5a7bd0cde70f` | GuardDuty EC2 Runtime Monitoring is not enabled for all regions | Management |
| `78dba9be-c519-4701-9800-4581ecea6f3b` | GuardDuty ECS Runtime Monitoring is not enabled for all regions | Management |
| `d31b8f5a-77bb-4420-a313-54d89a98f9ab` | GuardDuty EKS Protection is not enabled for all regions | Management |
| `9c7d399e-5bc0-42cd-bf37-02e1c374e1b8` | GuardDuty EKS Runtime Monitoring is not enabled for all regions | Management |
| `b25475c2-0f0b-496c-8c03-cd188606552b` | GuardDuty Lambda Protection is not enabled for all regions | Management |
| `7803deea-331f-43d9-8716-0f8e8d9d3b98` | GuardDuty Malware Protection for EC2 is not enabled for all regions | Management |
| `8331204d-fb43-4b34-ae1e-a283f5e3cbb7` | GuardDuty RDS Protection is not enabled for all regions | Management |
| `48c3d373-b2f3-4c26-8ae6-060d91d9ee26` | GuardDuty Runtime Monitoring is not enabled for all regions | Management |
| `00c8e4b7-3841-4311-a323-aaf8b185d61e` | GuardDuty S3 Protection is not enabled for all regions | Management |
| `29493618-1bcd-48a2-be73-25b0fde6dc37` | IAM access analyzer is not enabled for all regions | Iam |
| `19e2681b-4405-4d69-8283-6610b0d59350` | Missing CloudWatch alarm - CloudTrail configuration changes | Monitoring |
| `346a8e20-d3fb-402f-8b7d-b7322a234ba1` | Missing CloudWatch alarm - IAM policy changes | Monitoring |
| `ccdd1ef6-3027-4b51-88c9-9aedde81e991` | Missing CloudWatch alarm - NACL changes | Monitoring |
| `ddaa97bb-52a0-4b9f-a6e9-765a725df90f` | Missing CloudWatch alarm - Organization changes | Monitoring |
| `ec0ec690-b0d8-40e5-817c-614d811e4705` | Missing CloudWatch alarm - S3 Bucket policy changes | Monitoring |
| `5e49cf7b-aeaa-40aa-9c37-525d1c32c2af` | Missing CloudWatch alarm - Security Group changes | Monitoring |
| `64b0da2c-1ce4-45b9-80b1-3d1757d6e2d4` | Missing CloudWatch alarm - VPC changes | Monitoring |
| `b5e017a7-3791-4fcc-97d0-df205bb337ba` | Missing CloudWatch alarm - configuration changes | Monitoring |
| `ac0ae7cb-2493-4af2-8fab-13291d6e2031` | Missing CloudWatch alarm - disabled KMS keys | Monitoring |
| `4d19360f-dd7c-4096-8e44-3b5dc300ea4f` | Missing CloudWatch alarm - management console MFA disabled | Monitoring |
| `2babf5ea-47d4-4937-b29f-6bf52e041f8a` | Missing CloudWatch alarm - management console authentication failures | Monitoring |
| `eb3fd373-ada7-46e0-9271-6a95610f3cd5` | Missing CloudWatch alarm - network gateway changes | Monitoring |
| `e9c4bc2d-c260-43bb-b03b-319ec3803602` | Missing CloudWatch alarm - root account usage | Monitoring |
| `1f17e65b-128c-447e-ab29-8b893e6dfc92` | Missing CloudWatch alarm - route table changes | Monitoring |
| `a12cbba2-42f4-4660-b672-16c3dc80a03e` | Missing CloudWatch alarm - unauthorized API calls | Monitoring |

### `R4-unbounded-log-ingest` (24)

**Reason:** One call, unbounded recurring bill.
Every `does not publish logs to CloudWatch`, access-logging and flow-logs policy. This is the existing VPC-flow-logs exclusion (ROADMAP.md, Coverage) generalised: trivially scriptable and still out, because ease of scripting is not a safety argument. Cost scales with traffic the tool cannot see, so no `cost_impact` value short of "unbounded" would be honest.

| Policy id | Policy | Category |
| --- | --- | --- |
| `3729aefb-a6a4-4e8a-9a1d-f311522393c3` | API Gateway access logging is not enabled | Logging |
| `59924c08-a2b8-4df0-9fc5-da62095ded5c` | API Gateway data tracing is not enabled | Logging |
| `244e0a91-6f06-4c04-9b1a-de8d8bfec5b6` | AppSync GraphQL API field-level logging is not enabled | Logging |
| `17bbebab-44a3-4885-b04a-6764b04c202b` | CloudFront Distribution logging is not enabled | Logging |
| `218892ee-aa70-4edc-989a-7aa19748539e` | CloudTrail Logs does not publish logs to CloudWatch | Logging |
| `c12e3189-1e96-4ba9-8b02-da5234bc9193` | CloudTrail S3 Bucket logging is not enabled | Logging |
| `9cc1dbdc-255a-4283-a8fc-1e4c308aa120` | CodeBuild Project logging is not enabled | Logging |
| `264718a0-cd2b-42b3-a03d-454c5f91a63d` | DMS Database Migration Task does not publish logs to CloudWatch | Data |
| `c27e9c54-4c75-43ec-962e-c308a52e1d47` | DMS Database Migration Task source database logging does not meet minimum requirements | Logging |
| `ec359710-7977-4109-8969-fec28dba9f94` | DMS Database Migration Task target database logging does not meet minimum requirements | Data |
| `3637a592-12cd-44c0-a820-276ce64fd1cc` | Data Firehose Stream does not publish logs to CloudWatch | Data |
| `652753c5-db75-4a1a-82ec-065f81fc3b88` | DocumentDB Cluster does not publish logs to CloudWatch Logs | Logging |
| `64a173d7-5bae-4be2-8216-b691668f6776` | EKS Cluster control plane logging is not enabled | Logging |
| `12dcbe1a-8709-4ba6-a7d4-ae03e7b8727e` | Elastic Beanstalk Environment does not publish logs to CloudWatch Logs | Logging |
| `7f310ea9-a0cc-4b1d-9db6-dec7acb0911b` | Missing multi-regional CloudTrail | Logging |
| `cc80048a-6c6c-48d8-ba2a-01468b04d2c8` | Neptune DB Cluster does not publish logs to CloudWatch Logs | Logging |
| `f95a036d-b5a3-4efb-b55a-6abcd088b074` | Network Firewall logging is not enabled | Logging |
| `b484739c-13e6-47b8-a0bd-d97b6f0c43ec` | OpenSearch Domain does not publish logs to CloudWatch Logs | Logging |
| `f74383c8-6ce3-47aa-9a60-0ba10a339205` | RDS Cluster does not publish logs to CloudWatch Logs | Logging |
| `d5504dc9-17a2-4cfd-a47a-ceddeff91434` | RDS Instance does not publish logs to CloudWatch Logs | Logging |
| `87a1916f-53d2-4945-b4ab-1a38ec0d3fb2` | Redshift Cluster user activity logging is not enabled | Logging |
| `83a2addd-0d3e-4cab-b3fd-4717341fbda4` | S3 Bucket object-level logging for read events is not enabled | Logging |
| `49ecde54-f374-446e-83dd-a1f00614f51f` | S3 Bucket object-level logging for write events is not enabled | Logging |
| `b1ef2f2e-4b10-4fed-904c-cd8eff6091b0` | VPC Flow Logs is not set | Logging |

### `R7-requires-secret-or-mfa` (18)

**Reason:** Needs an input no generator can supply.
The eight `is exposing secrets` policies (the fix is rotate-then-purge, which needs the *new* secret value), MFA-not-enabled (needs a device), Redis AUTH tokens, DMS credentials, S3 MFA delete (requires root plus a serial number). A recipe that prompts for a secret would also be a recipe that puts one on a command line.

| Policy id | Policy | Category |
| --- | --- | --- |
| `b8106117-ebaf-4dcb-90c6-3f69d7baebf2` | AWS resource tags are exposing secrets | Secrets |
| `7bf79be0-a223-48d5-8223-3c8e406cf309` | CloudFormation Stack is exposing secrets | Secrets |
| `6eb7ab9c-1d5c-4017-a70c-8d540252b98a` | CodeBuild Project is exposing secrets | Data |
| `560081c3-de75-4a05-9215-db3167a0f057` | DMS Database Migration Task data validation is not enabled | Data |
| `c7c8295d-5324-4b00-855a-fb33c23668d7` | DMS Endpoint MongoDB authentication mechanism is not enabled | Data |
| `0e474949-eac4-4e00-8d3d-c38f5804b864` | DMS Endpoint encryption in transit is not enabled | Data |
| `674b2c55-557d-4438-994f-74f3894c4080` | DMS Endpoint for Redis OSS TLS is not enabled | Data |
| `157b7dcc-5818-4618-9f65-09876e29379d` | EC2 Instance is exposing secrets | Secrets |
| `2c0c842c-fc03-4a84-9183-3904ada870cf` | ECS Task Definition is exposing secrets | Secrets |
| `f31c2978-1de0-4e68-8cfd-0711d8dc6132` | ElastiCache Redis OSS Cluster Cache AUTH is not enabled | Data |
| `fe72e466-1a75-48c8-abde-9471fc16983d` | IAM User MFA is not enabled | Iam |
| `45475cbd-f081-45a1-9c15-2149302ea2ce` | IAM User unused password | Iam |
| `d9c76142-e8e8-400a-b97f-350a426e3e9e` | Lambda Function is exposing secrets | Secrets |
| `a59b021d-4ff2-478e-bca8-2e67fa952967` | Root User MFA is not enabled | Iam |
| `e629e9f4-799c-4591-90b7-3bdc542da1df` | Root User has access key | Iam |
| `34a8319d-5a57-4a1c-bb29-94e2d0e2f227` | S3 Bucket MFA delete is not enabled | Data |
| `334d3718-4f59-4939-a7db-5f5f268094e9` | Secrets Manager secret automatic rotation is not enabled | Secrets |
| `3e1a0f1b-7169-4541-8d67-3f2186339240` | Systems Manager Parameter is exposing a secret | Secrets |

### `R9-blast-radius-beyond-resource` (9)

**Reason:** Deletion of something with unknown consumers.
Inactive IAM user, role and group; unused security group; unused SSO permission-set assignments; `RDS Cluster is exposed to a local file read vulnerability`; `EC2 Instance is exposed to the internet`. "Unused" is an observation window, not a fact, and the correct remediation for an exposure path may be at any hop along it. The resource named in the finding is not reliably the resource to change.

| Policy id | Policy | Category |
| --- | --- | --- |
| `3e9e209d-7f32-468b-b744-d94a6058eefa` | EC2 Instance is exposed to the internet | Network |
| `53cd1005-c654-4448-88da-afb8846e9712` | Inactive IAM Group | Iam |
| `6c38a4eb-349b-44fe-90cb-35ccf96d865d` | Inactive IAM Role | Iam |
| `eecbcdc0-70a8-4b58-9d59-5ab3f184fecb` | Inactive IAM User | Iam |
| `059fd73f-80fc-486b-8385-74d9115dc9f0` | RDS Cluster is exposed to a local file read vulnerability | Data |
| `54bf3fa0-6b95-4b77-b57a-b5098a303074` | SSO Group with unused permission set assignment | Iam |
| `9aa74d2a-9efe-47fe-85c3-aaa222c6d2f5` | SSO User with unused permission set assignment | Iam |
| `862aa26b-f8ea-4182-80b4-0e8432585c8f` | Unused SSO Permission Set | Iam |
| `ee86ab48-7091-4163-9577-b23fde5bfec3` | Unused Security Group | Network |

### `R1-detection-no-target-state` (8)

**Reason:** A detection, not a misconfiguration.
The five `Unusual *` anomaly policies, `Root User activity detected`, `New privileged identity`, `New AWS Account`. There is no misconfigured attribute to set, so there is nothing for a recipe to be *about*. These are correctly policies; they are not correctly remediations.

| Policy id | Policy | Category |
| --- | --- | --- |
| `51fc8c29-8964-451d-96f0-2717ce7537bd` | New AWS Account | Management |
| `c6242dfb-ec50-42f4-baf8-911edf8a541c` | New privileged identity | Iam |
| `497c5527-f249-4df1-a7f1-62a5fcae705d` | Root User activity detected | Iam |
| `d57c8036-120d-456c-91c7-2c18bd93ccf8` | Unusual Data Access | AnomalyDetection |
| `2d85458f-57d2-458b-a759-70104a135fc5` | Unusual Network Access Management | AnomalyDetection |
| `7f9de72e-6c86-4738-9ab6-7f7327531fe8` | Unusual Permission Management | AnomalyDetection |
| `4232561d-e9d7-4178-b8d0-440ab94fce5e` | Unusual Privilege Escalation | AnomalyDetection |
| `02467f87-248a-4f0f-bbb7-af476840e857` | Unusual Reconnaissance | AnomalyDetection |

### `R6-no-partial-update-command` (8)

**Reason:** Missing command shape, not missing recipe.
CloudFront (`update-distribution` requires the complete distribution config plus an `--if-match` ETag), Glue connections, Cognito identity pools. Expressing these needs read-modify-write, which is not idempotent and cannot be pinned the way a single addressed call can. This is the same class as the Key Vault RBAC rejection in ROADMAP.md's Azure coverage section: `az keyvault update` accepts no `--ids`.

| Policy id | Policy | Category |
| --- | --- | --- |
| `5544a597-d583-445e-9626-04eb9283cab1` | CloudFront Distribution S3 origin access control is not enabled | Network |
| `d29d746f-0ca4-409d-9516-4cbd84023cc0` | CloudFront Distribution custom origin encryption in transit is not enabled | Network |
| `3d371711-b308-4f18-a006-a38dee8972c7` | CloudFront Distribution default root object is not set | Network |
| `fdda9b5c-062e-4353-acaf-9b0e54ec386a` | CloudFront Distribution insecure communication | Network |
| `6e18c5a1-e3ba-4850-9c1e-5aaca1e99753` | CloudFront Distribution is using the default SSL certificate | Network |
| `56774f82-bde8-4f69-9013-069fa9b2f760` | CloudFront Distribution viewer encryption in transit is not enabled | Network |
| `8a0a3d27-76a7-4938-b3de-4f0b4b4b9c7c` | Cognito Identity Pool unauthenticated guest access is enabled | Iam |
| `cc4854c5-ab38-471d-8db4-6b835caba3c3` | Glue Connection encryption in transit is not enabled | Network |

## Keeping this file honest

Three claims here rot, and a CI step in the `claims` job checks each:

1. **The buckets partition the catalogue.** Every policy id appears exactly once across all four
   sections, and the totals in *Result* match the rows actually present. A policy silently in two
   buckets, or in none, is the failure mode a hand-maintained register has.
2. **The shipped list is the shipped set.** The *Shipped* table must equal the policy ids reachable
   from the AWS provider descriptor. This is the claim that goes stale the moment a batch lands:
   writing the `ec2` recipes without moving those four rows out of *Write a recipe now* leaves the
   document asserting work is outstanding that is done.
3. **Nothing is shipped that this file rejects.** A policy id in any rejection class must not have
   a recipe. If a rejection is overturned, the row moves and the class's reasoning is edited --
   which is the point, because that reasoning is cited from `ROADMAP.md`.

What the gate deliberately does *not* check is whether an assignment is *correct*. That is a
judgement about an external API surface, and no CI job in this repo can reach one. The gate
enforces that the document is internally consistent and agrees with the code; the classes above
are the argument, and they are meant to be argued with.
