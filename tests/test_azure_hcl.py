"""Tests for the Azure HCL scope block.

Small module, and the tests are about one thing: **the block must not claim a guard
Azure does not have.** ``azurerm`` has no ``allowed_account_ids`` equivalent, so
``subscription_id`` *selects* a subscription rather than asserting which one is
acceptable -- a wrong value is not rejected. The AWS block's promise ("the plan fails
if your credentials are for another account") is therefore false here, and the danger is
that it is exactly the sentence someone would copy across while making the two clouds
"consistent".

So most of what follows asserts the *absence* of a claim, which is unusual enough to be
worth stating: a test that only checked for the subscription id would pass on a block
that also promised a guard, and the wrong promise is worse than the missing one because
it is the reason a reader stops checking.

Two further properties get their own tests because each is a real divergence from AWS
rather than an accident of implementation:

* the block is emitted for a unit with **no region**, which is the normal Azure case
  (``hcl_provider_is_region_scoped=False``) and the guard case on the AWS side;
* the provider block is **commented out**, because the header tells the user to drop the
  file into a workspace that already declares a provider.

The rendered output is also validated by a real ``tofu validate`` in
``tests/test_generators.py``'s Azure end-to-end path; what is here is the reasoning the
parser cannot check.
"""

from __future__ import annotations

import pytest

from remgen.core.layout import Format, OutputUnit
from remgen.providers.azure.hcl import scope_block

SUBSCRIPTION = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"


def _unit(*, scope_id: str = SUBSCRIPTION, region: str | None = None, part=None, total=1):
    return OutputUnit(
        fmt=Format.HCL,
        cloud="azure",
        scope_id=scope_id,
        region=region,
        part=part,
        total_parts=total,
        pairs=(),
        scope_noun="subscription",
    )


def test_the_block_names_the_subscription_it_covers():
    out = scope_block(_unit())
    assert SUBSCRIPTION in out
    assert 'provider "azurerm"' in out
    assert f'subscription_id = "{SUBSCRIPTION}"' in out


def test_the_block_names_no_other_subscription():
    # Guards against a formatting bug that substituted a constant, or the scope
    # description and the provider argument being filled from different fields.
    out = scope_block(_unit())
    assert OTHER not in out
    assert out.count(SUBSCRIPTION) >= 2, "both the scope comment and the provider argument"


@pytest.mark.parametrize(
    "claim",
    [
        "allowed_subscription_ids",
        "will fail",
        "fails the plan",
        "refuses",
        "prevents",
    ],
)
def test_the_block_never_claims_a_guard_azure_does_not_have(claim):
    """The central property of this module, asserted as an absence.

    Of ``azurerm``'s 29 provider arguments (schema 5.0.1) not one is an allow-list. So
    any sentence here promising that a wrong ``subscription_id`` is rejected is false,
    and it is false in the direction that costs something: a reader who believes the file
    is self-guarding stops confirming the workspace's provider themselves, which is the
    one thing that actually protects them.

    Phrased as a list of the words such a claim would use, because the failure will
    arrive as prose rather than as code -- most likely copied from the AWS block, which
    says all of this truthfully about a provider that supports it.

    ``allowed_account_ids`` is deliberately **not** in this list, and the first version
    of this test had it there and failed on correct output. The block does name that
    argument -- to say azurerm has no equivalent of it -- which is the honest sentence
    rather than the false claim. Polarity is the thing under test, not vocabulary, so it
    gets its own assertion in
    :func:`test_any_mention_of_the_aws_guard_is_a_denial_of_it`.
    """
    out = scope_block(_unit())
    assert claim not in out, (
        f"the Azure scope block says {claim!r}. azurerm has no allow-list argument, so a "
        f"wrong subscription_id is not rejected -- this promises a guard that does not "
        f"exist. The AWS block may say this; this one may not."
    )


def test_any_mention_of_the_aws_guard_is_a_denial_of_it():
    """``allowed_account_ids`` may appear, but only in the sentence saying it does not.

    The distinction the test above cannot make. Naming the AWS argument is how the block
    tells a reader who knows the AWS output what is different here, so forbidding the
    word outright would delete the explanation along with the risk. What must not happen
    is the same word in a sentence that implies azurerm honours it -- which is what a
    half-finished copy of the AWS block produces.
    """
    out = scope_block(_unit())
    for line_number, line in enumerate(out.splitlines()):
        if "allowed_account_ids" not in line:
            continue
        window = " ".join(out.splitlines()[max(0, line_number - 1) : line_number + 2])
        assert "has no" in window, (
            f"`allowed_account_ids` is named at line {line_number} without saying azurerm "
            f"has no equivalent: {line!r}"
        )
        break
    else:
        pytest.fail(
            "the block no longer explains that azurerm has no `allowed_account_ids` "
            "equivalent; a reader coming from the AWS output would assume it does"
        )


def test_the_block_tells_the_reader_to_confirm_the_subscription_themselves():
    """Having no guard, the block owes the reader the instruction that replaces it.

    The counterpart to the test above: removing the false claim is only half of it, and a
    block that simply said nothing would leave the reader with no idea that confirming
    the provider scope is now their job.
    """
    out = scope_block(_unit())
    assert "CONFIRM" in out
    assert "does not assert which one is acceptable" in out


def test_the_block_explains_what_a_wrong_subscription_actually_does():
    """The one thing working in Azure's favour, and it is worth stating.

    An ARM resource id contains its own subscription id, so unlike an AWS bucket name
    there is no same-named resource in another subscription to silently adopt: the wrong
    provider scope produces a *failed* import, not a wrong one. Asserted because it is
    the sentence that makes the missing guard tolerable, and because without it the
    honest "there is no allow-list" reads as a much larger hazard than it is.
    """
    out = scope_block(_unit())
    assert "resource not found" in out


def test_the_provider_block_is_commented_out():
    """The file is meant to be dropped into a workspace that already has a provider.

    An active second declaration is a "Duplicate provider configuration" error, so an
    uncommented block would make every generated file fail to validate in exactly the
    way the header instructs the user to use it. The `import` blocks are what must be
    live; this is a convenience for standalone use.
    """
    out = scope_block(_unit())
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        assert stripped.startswith("#"), f"uncommented line in the scope block: {line!r}"


def test_features_is_present_in_the_commented_block():
    """Present because it is conventional, not because it is required.

    Worth pinning both halves. It stays because this is code the reader is invited to
    uncomment and compare against the documentation, where every example shows it. But
    the module's comment used to claim it was *required*, and that was measured wrong: the
    schema sets no ``min_items`` on it, and a provider block without it validates on
    azurerm 5.0.1, 4.81.0 and 3.117.1. If a future reader deletes the line, this test
    should make them read that comment rather than only the diff.
    """
    assert "features {}" in scope_block(_unit())


def test_a_unit_with_no_region_still_gets_a_block():
    """``region is None`` is the normal Azure case, not a guard case.

    This is the divergence from AWS most likely to be "fixed" into a bug. The AWS
    implementation returns ``""`` for a region-spanning unit, because its block
    *contains* a region and naming the wrong one is worse than naming none. An
    ``azurerm`` provider block carries no location at all, so nothing is left
    undetermined and there is nothing to omit -- and since Azure HCL is never split by
    location, ``None`` is what every Azure unit carries. Returning ``""`` here would
    strip the subscription statement from every Azure file that is generated.
    """
    out = scope_block(_unit(region=None))
    assert out.strip(), "no scope block for a unit with no region -- that is every Azure unit"
    assert SUBSCRIPTION in out
    assert "all regions" in out


def test_the_block_says_the_file_may_span_locations():
    # The reader has to know the absence of a location split is deliberate, or the
    # single file for several locations looks like a missing feature.
    out = scope_block(_unit())
    assert "may span locations" in out
    assert "each resource names its own" in out


def test_a_part_number_reaches_the_scope_description():
    # Large runs are chunked, and a reader holding file 2 of 3 needs to know there are
    # others -- the scope line is where the layout says so.
    out = scope_block(_unit(part=2, total=3))
    assert "part 2 of 3" in out


def test_the_block_uses_azures_noun_and_not_awss():
    """Correct behaviour described in the wrong cloud's words is still a defect.

    ``account`` would send an Azure reader looking for an account-level setting that
    does not exist, and it is the word the AWS block uses throughout -- so it arrives
    by the same copy that brings the false guard claim.
    """
    out = scope_block(_unit())
    assert "subscription" in out
    assert "account" not in out.replace("allowed_account_ids", ""), (
        "AWS's scope noun leaked into the Azure scope block"
    )


def test_the_block_is_stable_for_the_same_unit():
    # Artifacts are compared byte-for-byte by the sample-output check, so any
    # nondeterminism here shows up as a spurious diff nobody can explain.
    assert scope_block(_unit()) == scope_block(_unit())
