# Third-party notices and licensing posture

**This document is not legal advice.** It records the licensing analysis behind this
project's design so that a reviewer can check the reasoning. If you redistribute or
commercialize this tool, have your own counsel confirm it.

## Summary

This tool **generates configuration text**. It does not bundle, link to, embed, or
require any third-party binary in order to produce its output.

| Component | License | How we relate to it |
| --- | --- | --- |
| OpenTofu | MPL-2.0 | Primary HCL target. Not bundled; user supplies their own binary. |
| Terraform ≥ 1.6 | BUSL-1.1 (Licensor: IBM) | Documented as compatible. Not bundled, not required, never invoked by the tool. |
| botocore service models (`service-2.json`) | Apache-2.0 | Read as data at runtime from an existing AWS CLI v2 / botocore install. Not vendored into this repo. |
| AWS CLI v2 | Apache-2.0 | Optional. Only used as a convenient source of the service models, and by the user to run generated commands. |

## OpenTofu (MPL-2.0)

OpenTofu is licensed under the Mozilla Public License 2.0, verified from the
`LICENSE` file at <https://github.com/opentofu/opentofu>. MPL-2.0 places no
restriction on generating configuration consumed by the tool. OpenTofu is our
default HCL target for this reason.

## Terraform (BUSL-1.1) — why generating HCL is in bounds

Terraform 1.6.0 and later are licensed under the Business Source License 1.1, with
IBM as Licensor. The Additional Use Grant restricts one thing: offering the
*Licensed Work* to third parties on a hosted or embedded basis **in order to compete
with IBM's paid versions**. Quoting the license text directly:

> A "competitive offering" is a Product that is offered to third parties **on a paid
> basis**, including through paid support arrangements, that significantly overlaps
> with the capabilities of IBM Corp.'s paid version(s) of the Licensed Work. […]
> **In addition, Products that are not provided on a paid basis are not competitive.**

> "Embedded" means including the source code or executable code from the Licensed
> Work in a competitive offering. "Embedded" also means packaging the competitive
> offering in such a way that the Licensed Work must be accessed or downloaded for
> the competitive offering to operate.

Applied to this project:

1. **We are not a paid product.** This tool is free and MIT-licensed, so by the
   license's own words it is not a competitive offering.
2. **We do not embed the Licensed Work.** No Terraform source or executable is
   included, vendored, downloaded, or shelled out to.
3. **We do not require Terraform to operate.** Generation completes with no
   Terraform (or OpenTofu) binary present at all. The output is text.
4. **We generate configuration, not a Terraform substitute.** HCL configuration
   files are the user's own input to their own binary; they are not the Licensed Work.

**Deliberate design constraint:** to keep point 3 unambiguously true, Terraform is
never a dependency of this project — not in `pyproject.toml`, not in CI as a
requirement, and never invoked at runtime. Our CI *optionally* uses a Terraform or
OpenTofu binary to syntax-check generated output; those checks skip cleanly when no
binary is present.

## Recommendation before public release

Because this repository is published under `Copyright (c) 2026 Tenable, Inc.`, the
BUSL reading above should be confirmed by Tenable legal counsel prior to public
release or Exchange submission. The analysis is documented here to make that review
cheap, not to substitute for it.

## Trademarks

Terraform is a trademark of IBM/HashiCorp. OpenTofu is a trademark of the Linux
Foundation. AWS and Amazon Web Services are trademarks of Amazon.com, Inc. Tenable
is a trademark of Tenable, Inc. Use of these names is descriptive and does not imply
endorsement.
