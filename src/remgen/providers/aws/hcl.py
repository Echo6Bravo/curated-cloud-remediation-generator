"""The AWS-specific part of HCL rendering: the scope statement.

Everything else about generating configuration -- import blocks, label uniqueness,
attribute alignment, TODO stubs -- is cloud-neutral and lives in
:mod:`remgen.core.generators.hcl`. What is here is the one block that names a real
provider type and its credential guard, and the paragraph explaining why the file
covers a single account and region.

That paragraph is not decoration. ``allowed_account_ids`` is the difference between
a plan that fails and a plan that succeeds against a same-named resource in the
wrong account, and a reader who does not know that will delete a commented block
they think is boilerplate.
"""

from __future__ import annotations

from remgen.core.layout import OutputUnit

#: Scope statement plus a commented provider block. The block is commented rather
#: than active because the header instructs the user to place this file in an
#: existing workspace, which already declares a provider -- a second declaration is
#: a "Duplicate provider configuration" error. Commented, it serves the standalone
#: case without breaking the documented one.
_SCOPE = """
# ---------------------------------------------------------------------------
# SCOPE: {scope}
#
# This file covers ONE account and ONE region, because that is all an AWS provider
# configuration covers. A provider pointed at another account will not fail -- it
# will import a same-named resource from the account it can see. Confirm this
# workspace's provider targets account {account_id} in {region}.
#
# Standalone use: uncomment this block. `allowed_account_ids` makes a credential
# mismatch fail the plan instead of importing the wrong resource.
#
# provider "aws" {{
#   region              = "{region}"
#   allowed_account_ids = ["{account_id}"]
# }}
# ---------------------------------------------------------------------------
"""


def scope_block(unit: OutputUnit) -> str:
    """Return the scope statement for ``unit``, or ``""`` if it spans regions.

    A file spanning regions gets no statement because the block would have no
    single region to name. The AWS layout never produces such a unit for HCL --
    region is a hard boundary for this provider -- so this is a guard rather than a
    supported case: emitting a block naming the wrong region would be worse than
    emitting none.
    """
    if unit.region is None:
        return ""
    return _SCOPE.format(
        scope=unit.scope_description,
        account_id=unit.scope_id,
        region=unit.region,
    )


__all__ = ["scope_block"]
