"""Cloud-neutral core: everything that is the same in every cloud.

The pipeline, the model, the safety tiering, the output split, HCL rendering and
the run's companion files live here. Nothing in this package may import from
:mod:`remgen.providers` -- the dependency runs one way only, enforced by a test,
so that adding or changing a cloud cannot alter another cloud's output.

What a cloud supplies to this core is listed in :mod:`remgen.core.provider`.
"""

from __future__ import annotations

__all__: list[str] = []
