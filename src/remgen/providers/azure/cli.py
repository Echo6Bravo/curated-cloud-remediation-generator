"""The ``azremgen`` console entry point.

Thin by design, and identical in shape to :mod:`remgen.providers.aws.cli` -- which
is the point of having two. The whole pipeline is in :mod:`remgen.core.cli`; this
module only supplies the Azure provider descriptor to it. If this file ever needs
more than a descriptor and a call, something cloud-specific has leaked out of
:class:`~remgen.core.provider.Provider` and belongs there instead.

This command shipped **before** any Azure recipe existed, and that ordering was the
point: the shared pipeline was driven by a second cloud before any Azure remediation
was authored, because an abstraction validated against one instance is a guess. It
found three defects, all of them in ``core`` -- see ``tests/test_azure_cli.py``.

It now ships recipes, so ``generate`` emits real artifacts and ``verify`` checks all
three axes. Coverage is still partial by design: a policy with no recipe is reported
by ``azremgen policies --unsupported`` and counted in the run summary, so a gap is
visible rather than silent.
"""

from __future__ import annotations

from remgen.core.cli import main as _main
from remgen.providers.azure import AZURE


def main(argv: list[str] | None = None) -> int:
    """Run ``azremgen``. Returns the process exit code."""
    return _main(AZURE, argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
