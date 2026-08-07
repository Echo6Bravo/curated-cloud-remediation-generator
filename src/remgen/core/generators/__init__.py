"""Cloud-neutral output generation.

A generator turns ``(Recipe, Finding)`` pairs into one review-ready artifact.
Generators never call a cloud API and never shell out; they return text.

What is here:

* :mod:`remgen.core.generators.hcl` -- import-aware OpenTofu/Terraform
  configuration. Shared, because HCL syntax, ``import`` semantics, label
  uniqueness and ``tofu fmt`` alignment are properties of the configuration
  language rather than of any cloud. The provider supplies only the scope
  statement and the documentation label.
* :mod:`remgen.core.generators.common` -- template substitution with a second
  independent allowlist check, comment wrapping, policy grouping, and the recipe
  notes and tier banners both formats render.

What is **not** here: the shell-script generator. Flag syntax, identity preflight
and which calls are idempotent differ per vendor CLI, so each provider writes its
own -- see :mod:`remgen.providers.aws.shell`. There is deliberately no shared
skeleton yet: with one instance, a "generic" shell generator would be a guess about
what ``az``, ``gcloud`` and ``oci`` need. The second cloud is what should force the
common parts out, against two real cases rather than one.

A deliberate omission: there is no SDK-code generator (boto3 or otherwise). It
would be a third rendering of the same ``ApiCall`` with no capability the CLI
script lacks, and every additional format is another surface that can silently
drift from the API definition. See ROADMAP.md.
"""

from __future__ import annotations

from remgen.core.generators.hcl import (
    AmbiguousImportError,
    HclGenerationError,
    HclMergeConflict,
    render_hcl,
)

__all__ = [
    "AmbiguousImportError",
    "HclGenerationError",
    "HclMergeConflict",
    "render_hcl",
]
