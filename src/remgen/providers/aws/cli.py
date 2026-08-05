"""The ``awsremgen`` console entry point.

Thin by design. The whole pipeline is in :mod:`remgen.core.cli`; this module only
supplies the AWS provider descriptor to it. Anything that grows here is a sign that
something cloud-specific has leaked out of the descriptor and should be added to
:class:`~remgen.core.provider.Provider` instead.

There is one command per cloud rather than one command with a ``--cloud`` flag,
because credentials, recipe coverage and API verification are all per cloud. A
single command would imply an estate-wide run that no single credential set can
perform.
"""

from __future__ import annotations

from remgen.core.cli import main as _main
from remgen.providers.aws import AWS


def main(argv: list[str] | None = None) -> int:
    """Run ``awsremgen``. Returns the process exit code."""
    return _main(AWS, argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
