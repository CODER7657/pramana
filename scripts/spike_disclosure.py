"""SPIKE -- Day 1/2 experiment. Defensive research against our own sandbox.

HYPOTHESIS
----------
AP2 constraint evaluation is *presence-driven*: ``create_payment_evaluator`` is
invoked once per constraint found in the open mandate. A constraint that is not
disclosed produces no evaluator and therefore no violation.

Selective disclosure is a first-class AP2 privacy feature. If an issuer marks
entries of the ``constraints`` array as selectively disclosable -- a plausible
privacy choice, since a bank may not want a merchant to learn the customer's
total budget -- then a holder or delegate can *withhold* the spending cap while
presenting a chain that still verifies cryptographically.

If that holds, the privacy feature and the security control are in direct
conflict, and AP2 resolves it unsafely: the payment clears with no cap.

This script proves or disproves that empirically. It runs entirely against
locally generated keys and mandates. It performs no network I/O, targets no
third-party system, and generates no novel attacks.
"""

from __future__ import annotations

import sys
from typing import Any

from jwcrypto.jwk import JWK

from ap2.sdk.constraints import MandateContext, create_payment_evaluator
from ap2.sdk.disclosure_metadata import DisclosureMetadata
from ap2.sdk.generated.open_payment_mandate import (
    AllowedPayees,
    Budget,
    OpenPaymentMandate,
)
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.mandate import MandateClient

BUDGET_CAP = 5_000.0
CURRENCY = "INR"
# UNITS TRAP: Budget.max is in MAJOR units and BudgetEvaluator multiplies it
# by 100. Amount.amount is in MINOR units. A cap of 5000.0 INR is therefore
# 500_000 paise. Getting this wrong silently inverts the test.
ATTEMPTED = 750_000  # paise = INR 7,500 -- genuinely above the INR 5,000 cap


def hr(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def keypair() -> JWK:
    return JWK.generate(kty="EC", crv="P-256")


def build_open_mandate(merchant: Merchant, holder: JWK) -> OpenPaymentMandate:
    """An open mandate carrying a spending cap and a payee allowlist."""
    return OpenPaymentMandate(
        constraints=[
            Budget(max=BUDGET_CAP, currency=CURRENCY),
            AllowedPayees(allowed=[merchant]),
        ],
        cnf={"jwk": holder.export_public(as_dict=True)},
    )


def build_closed_mandate(merchant: Merchant) -> PaymentMandate:
    """The closed mandate the delegate presents -- deliberately over the cap."""
    return PaymentMandate(
        transaction_id="txn-spike-0001",
        payee=merchant,
        payment_amount=Amount(currency=CURRENCY, amount=ATTEMPTED),
        payment_instrument=PaymentInstrument(id="pi_test_upi", type="upi"),
    )


def evaluate(open_m: OpenPaymentMandate, closed_m: PaymentMandate) -> list[str]:
    """Run AP2's own constraint evaluation exactly as an integrator would."""
    ctx = MandateContext(total_amount=0, total_uses=0)
    violations: list[str] = []
    for c in open_m.constraints:
        violations.extend(create_payment_evaluator(c, ctx).evaluate(closed_m))
    return violations


def main() -> int:
    client = MandateClient()
    bank, sa = keypair(), keypair()
    merchant = Merchant(id="mrc_razorpay_test", name="Test Merchant")

    open_m = build_open_mandate(merchant, sa)
    closed_m = build_closed_mandate(merchant)

    hr("SETUP")
    print(f"Spending cap (Budget constraint) : {BUDGET_CAP:,.0f} {CURRENCY}")
    print(f"Cap in minor units               : {int(BUDGET_CAP * 100):,} paise")
    print(f"Amount the closed mandate charges: {ATTEMPTED:,} paise "
          f"(INR {ATTEMPTED / 100:,.0f})")
    print(f"Constraints in the open mandate  : "
          f"{[type(c).__name__ for c in open_m.constraints]}")

    # -- Control: every constraint visible -------------------------------
    hr("CONTROL -- all constraints disclosed")
    violations = evaluate(open_m, closed_m)
    print(f"violations: {violations}")
    control_blocked = bool(violations)
    print(f"\n=> over-cap payment {'BLOCKED' if control_blocked else 'ALLOWED'}")

    # -- Experiment: the Budget constraint is withheld -------------------
    # Simulating what a verifier sees after a delegate exercised selective
    # disclosure on constraints[0]. We reconstruct the *effective payload*
    # the verifier would parse -- the array is still valid, just shorter.
    hr("EXPERIMENT -- Budget constraint withheld via selective disclosure")
    redacted = OpenPaymentMandate(
        constraints=[c for c in open_m.constraints if not isinstance(c, Budget)],
        cnf=open_m.cnf,
    )
    print(f"constraints now             : "
          f"{[type(c).__name__ for c in redacted.constraints]}")
    print(f"model still schema-valid    : True (parsed without error)")

    violations = evaluate(redacted, closed_m)
    print(f"violations                  : {violations}")
    attack_succeeds = not violations
    print(f"\n=> over-cap payment {'ALLOWED' if attack_succeeds else 'BLOCKED'}")

    # -- Can an issuer actually mark constraints disclosable? ------------
    hr("PRECONDITION -- is constraints[] markable as selectively disclosable?")
    try:
        sd = DisclosureMetadata(
            children={"constraints": DisclosureMetadata(sd_array_indices=[0, 1])}
        )
        token = client.create([open_m], bank, sd=sd)
        print("DisclosureMetadata accepted on constraints[]: True")
        print(f"root SD-JWT issued, length {len(token)} chars")
        print(f"disclosure segments in token: {token.count('~')}")
        precondition = True
    except Exception as exc:  # noqa: BLE001 -- spike: report, do not raise
        print(f"DisclosureMetadata rejected: {type(exc).__name__}: {exc}")
        precondition = False

    # -- Verdict ---------------------------------------------------------
    hr("RESULT")
    print(f"  control blocks over-cap payment : {control_blocked}")
    print(f"  withheld-constraint attack works: {attack_succeeds}")
    print(f"  issuer can mark constraints SD  : {precondition}")
    print()
    if control_blocked and attack_succeeds:
        print("  CONFIRMED: an absent constraint produces no violation.")
        print("  A withheld spending cap is indistinguishable, to the")
        print("  evaluator, from a cap that was satisfied.")
        print()
        print("  PRAMANA's control: require the *presence* of every")
        print("  policy-mandated constraint. Absence -> INDETERMINATE -> REJECT.")
        return 0
    print("  NOT CONFIRMED -- hypothesis does not hold as stated. Investigate.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
