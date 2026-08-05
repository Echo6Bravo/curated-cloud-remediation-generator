"""Curated AWS remediation generator.

Turns Tenable Cloud Security AWS policy findings into review-ready remediation
artifacts: ``aws`` CLI commands and import-aware OpenTofu/Terraform HCL.

This package NEVER mutates AWS. It emits text for a human to review and run.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
