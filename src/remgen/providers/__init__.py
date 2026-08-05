"""One package per cloud.

Each provider package holds what is genuinely cloud-specific: its curated recipe
set, drift verification against that cloud's own API definitions, its shell
generator, and the scope statement its Terraform provider requires. Each exposes a
:class:`~remgen.core.provider.Provider` and ships one console command.

Providers import from :mod:`remgen.core`; never the reverse. Providers must also
not import each other -- two clouds sharing code directly is how a change made for
one silently alters the other's artifacts. If two providers need the same thing, it
belongs in ``core``.

Implemented: ``aws``. Azure, GCP and OCI are planned; see ROADMAP.md.
"""

from __future__ import annotations

__all__: list[str] = []
