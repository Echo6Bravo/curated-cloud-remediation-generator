# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report privately via GitHub's
[private vulnerability reporting](https://github.com/Echo6Bravo/curated-cloud-remediation-generator/security/advisories/new)
on this repository. Include what you did, what happened, and what you expected — a reproduction is
worth more than a description.

This is a community project maintained on a best-effort basis, not a supported Tenable product.
There is no response-time SLA. If the issue affects the Tenable Cloud Security product itself
rather than this tool, report it through
[Tenable's official channel](https://www.tenable.com/security) instead.

## What counts as a vulnerability here

This tool's security posture is unusual and worth being specific about: **it holds no credentials,
makes no network calls, and never modifies a cloud.** It reads local JSON and writes local text
files. So the interesting failures are not the usual ones.

**In scope — these are real and I want to hear about them:**

- **A generated artifact that acts on the wrong scope.** The highest-severity class. If you can
  make the tool emit a script or HCL file that targets a different cloud, credential scope or region
  than the one it claims, that is a critical finding. The failure mode is a *silent success* against
  the wrong resources. The guards differ per cloud, because the escape routes do:
  - **AWS** — the per-cloud/per-account/per-region output split, the
    `aws sts get-caller-identity` preflight, and `allowed_account_ids` in the generated HCL.
  - **Azure** — the `az account list` reachability preflight, `subscription_id` in the generated
    HCL, and `scope_conflict` in `src/remgen/providers/azure/__init__.py`, which refuses to
    generate when a finding's ARM `resource_id` names a different subscription than its
    `account_id`. That check exists because `az` resolves `--ids` *in preference to*
    `--subscription`, so a mismatched pair would mutate a resource in one subscription from a
    script whose guard confirms another. A way past it is the Azure equivalent of defeating the
    AWS preflight. Also in scope: a rendered `az` command that does not pin its subscription at
    all, which `SubscriptionNotPinnedError` is meant to make unreachable.
- **Anything written outside `--out`.** The cloud id becomes a directory name in the output path, so
  a value that is not a single path segment would escape it. It is validated where it is set rather
  than at each path join, and a way past that check is a path-traversal finding.
- **Injection through a finding record into generated output.** Findings are untrusted input. A
  crafted resource name, ARN, ARM id, account id or subscription id that escapes quoting and becomes
  executable shell or breaks HCL structure is a vulnerability.
- **A finding silently dropped.** Input and output counts must reconcile. A record that vanishes
  without being reported as a rejection is a missed remediation that looks like a clean run.
- **A remediation misclassified as safer than it is** — an irreversible, cost-scaled, or
  availability-affecting change emitted under `--safety-level safest`.
- **A secret written to disk**, into an artifact, or into the cache directory.
- **Path traversal** via `--out`, `--cache-dir`, or a value inside a finding record.

**Out of scope:**

- A cloud API call that fails in your account because of SCPs, Azure Policy, permission boundaries,
  RBAC, or resource state. The generated scripts fail fast on this by design.
- The consequences of running a `--safety-level caution` or `--safety-level all` artifact you chose
  to run. Those levels require an explicit opt-in and the warnings are inline in the artifact.
- Missing coverage. An unsupported policy is reported as unsupported; that is the documented
  behavior, not a vulnerability. The same goes for a cloud with no recipes: GCP and OCI are
  unimplemented, not silently broken. Partial coverage on a *supported* cloud is the same —
  `awsremgen` and `azremgen` each cover a small curated subset, and `policies --unsupported`
  reports the gap.

## Supported versions

Pre-1.0. Only the latest release receives fixes.

## Handling of credentials and data

The tool never asks for, stores, or transmits cloud or Tenable credentials. Findings you supply are
read from a local file and never leave your machine. The only state written is a policy-catalog
snapshot under `--cache-dir` (default `~/.cache/remgen`), which contains policy metadata — not
findings and not credentials.

Generated artifacts describe your infrastructure, including account ids and resource names.
**Treat the output directory as sensitive** and do not commit it; `artifacts/` and `out/` are
already in `.gitignore`.
