"""The result of checking a recipe against its cloud's live API definitions.

Only the *shape* of the answer lives here. Producing it does not generalize: AWS
publishes machine-readable botocore service models, Azure has ARM schemas, GCP has
discovery documents, and each is read differently. So each provider implements its
own verification and reports it in these terms -- see
:mod:`remgen.providers.aws.drift`.

The one rule that is shared, and the reason this type is in ``core``: **a check
that could not run is reported as ``UNAVAILABLE``, never as a pass.** The CLI
turns that into its own exit code (``4``) precisely so a scheduler cannot mistake
"no models installed" for "all recipes verified". Any provider that collapses the
two would make the tool claim verification it never performed, which is worse
than not verifying at all -- the claim is what a user acts on.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DriftStatus(str, Enum):
    """Outcome of verifying one recipe against its cloud's API definitions."""

    OK = "ok"
    #: The operation no longer exists in the API definition.
    OPERATION_MISSING = "operation_missing"
    #: The operation exists but one or more parameters do not.
    PARAMETER_MISSING = "parameter_missing"
    #: No definition found for the service at all.
    SERVICE_MISSING = "service_missing"
    #: No definition source available; the check could not be performed. Distinct
    #: from every value above, all of which mean the check ran and found a problem.
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class DriftResult:
    """Result of verifying a single recipe."""

    policy_id: str
    policy_title: str
    service: str
    operation: str
    status: DriftStatus
    detail: str = ""
    api_version: str = ""

    @property
    def ok(self) -> bool:
        return self.status is DriftStatus.OK

    @property
    def checked(self) -> bool:
        """True when verification actually ran, whatever it concluded.

        Exists so callers distinguish "ran and passed" from "did not run" without
        re-deriving the rule from the status enum, which is where the two get
        conflated.
        """
        return self.status is not DriftStatus.UNAVAILABLE


__all__ = ["DriftResult", "DriftStatus"]
