"""AP2 already asserts required presence -- and the assertion is withholdable.

Raised by a community commenter on AP2#339, who pointed out that
`check_payment_constraints` is not purely presence-driven. It already contains
a required-presence assertion:

    has_recurrence = any(isinstance(c, AgentRecurrence) for c in constraints)
    if has_recurrence:
        if not has_amount: violations.append('... requires payment.amount_range')
        if not has_budget:  violations.append('... requires payment.budget')

They are right, we had not found it, and it narrows the original claim. "AP2
evaluates only what is disclosed" is too broad as written: for one shape, the
SDK does demand that a constraint be *present* and reports a violation when it
is not. That is exactly the pattern this project argues for.

What this script establishes is where that pattern stops.

The assertion is **triggered by** `AgentRecurrence` -- which is itself just
another entry in the same `constraints` array, and therefore just as
selectively disclosable as the `Budget` it protects. A holder who withholds the
cap gets caught. A holder who withholds the cap *and* the recurrence marker
does not, because there is nothing left to trigger the check.

    cap INR 5,000, charge INR 7,500 (over the cap)

    budget + recurrence + range   -> BLOCKED   budget evaluator
    budget WITHHELD, recurrence   -> BLOCKED   the presence assertion fires
    budget + recurrence WITHHELD  -> ALLOWED   nothing left to fire
    budget WITHHELD, nothing else -> ALLOWED

So the defence is real but self-defeating: it protects only the holder who
chose to disclose the thing that triggers it, and an adversary is precisely the
party who will not. A presence assertion whose own trigger is withholdable is a
presence assertion an adversary opts out of.

This is a sharper statement of the finding than the one we filed, and it came
from someone else reading the code. Credited in POSTMORTEM.md.

Note on scope: this calls `check_payment_constraints` directly with the
constraint sets a verifier is left holding after redaction, rather than driving
a real SD-JWT presentation. That is deliberate -- it isolates the assertion
logic from the disclosure plumbing, which `spike_chain_e2e.py` already
exercises end to end. A separate observation from attempting the SD-JWT route:
an `AgentRecurrence` mandate could not be issued with selective disclosure at
all, because the `Frequency` enum is not JSON-serialisable where the SD-JWT
library hashes array-element disclosures. That fails closed and is a
robustness bug rather than a security one.

Local objects only, no network, no third-party system. See SECURITY.md.
"""

from __future__ import annotations

import sys

from ap2.sdk.constraints import MandateContext
from ap2.sdk.generated.open_payment_mandate import (
    AgentRecurrence,
    AmountRange,
    Budget,
    OpenPaymentMandate,
)
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.payment_mandate_chain import check_payment_constraints

CAP_MAJOR = 5_000.0
ATTEMPTED = 750_000  # paise = INR 7,500, over the INR 5,000 cap


def main() -> int:
    merchant = Merchant(id="mrc_grocer", name="Grocer")
    closed = PaymentMandate(
        transaction_id="txn-recurrence",
        payee=merchant,
        payment_amount=Amount(currency="INR", amount=ATTEMPTED),
        payment_instrument=PaymentInstrument(id="pi_upi", type="upi"),
    )
    budget = Budget(max=CAP_MAJOR, currency="INR")
    recurrence = AgentRecurrence(frequency="MONTHLY", max_occurrences=12)
    amount_range = AmountRange(currency="INR", max=ATTEMPTED, min=0)

    print("=" * 74)
    print("AP2's OWN PRESENCE ASSERTION -- and the disclosure that disables it")
    print("=" * 74)
    print(f"  cap INR {CAP_MAJOR:,.0f}   charge INR {ATTEMPTED / 100:,.0f}"
          f"   (over the cap)\n")

    scenarios = (
        ("budget + recurrence + range  ", [budget, recurrence, amount_range]),
        ("budget WITHHELD, recurrence  ", [recurrence, amount_range]),
        ("budget + recurrence WITHHELD ", [amount_range]),
        ("budget WITHHELD, nothing else", []),
    )

    allowed_when_triggered = None
    allowed_when_untriggered = None

    for label, constraints in scenarios:
        mandate = OpenPaymentMandate(constraints=constraints, cnf={"jwk": {}})
        violations = check_payment_constraints(
            mandate,
            closed,
            mandate_context=MandateContext(total_amount=0, total_uses=0),
        )
        allowed = not violations
        print(f"  {label} -> {'ALLOWED' if allowed else 'BLOCKED'}")
        for v in violations:
            print(f"       {v}")
        if label.startswith("budget WITHHELD, recurrence"):
            allowed_when_triggered = allowed
        if label.startswith("budget + recurrence WITHHELD"):
            allowed_when_untriggered = allowed
    print()

    if allowed_when_triggered is False and allowed_when_untriggered is True:
        print("  The assertion fires when the cap alone is withheld, and does")
        print("  not when the marker that triggers it is withheld too. Both")
        print("  live in the same selectively-disclosable array, so an")
        print("  adversary simply withholds one more entry.")
        print()
        print("  A presence assertion whose own trigger is withholdable is a")
        print("  presence assertion an adversary opts out of.")
        return 0

    print("  Behaviour differs from what this spike was written to show.")
    print("  Read the table above before repeating any claim from it.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
