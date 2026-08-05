"""Output generators.

Each generator turns ``(Recipe, Finding)`` pairs into one review-ready artifact.
Generators never call AWS and never shell out; they return text.

Two formats ship in v1:

* :mod:`remgen.generators.awscli` -- a reviewable, fail-fast shell script.
* :mod:`remgen.generators.hcl` -- import-aware OpenTofu/Terraform configuration.

A deliberate omission: there is no boto3/Python-SDK generator. It would be a
third rendering of the same ``ApiCall`` with no capability the CLI script lacks,
and every additional format is another surface that can silently drift from the
service model. See ROADMAP.md.
"""

from __future__ import annotations

from remgen.generators.awscli import render_cli_script
from remgen.generators.hcl import render_hcl

__all__ = ["render_cli_script", "render_hcl"]
