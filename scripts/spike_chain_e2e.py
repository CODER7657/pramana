"""SPIKE stage 2 -- end-to-end chain, with a genuinely withheld disclosure.

Stage 1 (spike_disclosure.py) simulated the effective payload a verifier would
parse. That is not sufficient evidence for the load-bearing claim, which is:

    the delegation chain still verifies cryptographically while the
    constraint is absent.

This script performs the real thing: issue a root SD-JWT with the constraints
array marked selectively disclosable, present it through a delegation hop while
withholding the Budget disclosure, then run the verifier and AP2's own
constraint evaluation on whatever comes back.

Defensive research, local keys only, no network I/O, no third-party target.
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

BUDGET_CAP = 5_000.0          # major units (INR)
ATTEMPTED = 750_000           # minor units (paise) = INR 7,500 -- over the cap
CURRENCY = "INR"
AUD = "https://merchant.example/checkout"
NONCE = "nonce-spike-e2e-0001"


def hr(t: str) -> None:
    print(f"\n{'=' * 72}\n{t}\n{'=' * 72}")


def key() -> JWK:
    return JWK.generate(kty="EC", crv="P-256")


def constraints_of(payload: Any) -> list[str]:
    """Constraint type-tags present in whatever the verifier handed back."""
    if isinstance(payload, dict):
        raw = payload.get("constraints") or []
        return [c.get("type", "?") if isinstance(c, dict) else str(c) for c in raw]
    raw = getattr(payload, "constraints", []) or []
    return [getattr(c, "type", type(c).__name__) for c in raw]


def main() -> int:  # noqa: PLR0915
    client = MandateClient()
    bank, sa = key(), key()

    merchant = Merchant(id="mrc_razorpay_test", name="Test Merchant")
    open_m = OpenPaymentMandate(
        constraints=[
            Budget(max=BUDGET_CAP, currency=CURRENCY),
            AllowedPayees(allowed=[merchant]),
        ],
        cnf={"jwk": sa.export_public(as_dict=True)},
    )
    closed_m = PaymentMandate(
        transaction_id="txn-spike-e2e",
        payee=merchant,
        payment_amount=Amount(currency=CURRENCY, amount=ATTEMPTED),
        payment_instrument=PaymentInstrument(id="pi_test_upi", type="upi"),
    )

    # Issuer marks BOTH constraint entries selectively disclosable -- the
    # privacy-motivated configuration described in stage 1.
    sd = DisclosureMetadata(
        children={"constraints": DisclosureMetadata(sd_array_indices=[0, 1])}
    )
    root = client.create([open_m], bank, sd=sd)

    hr("SETUP")
    print(f"cap            : INR {BUDGET_CAP:,.0f}  ({int(BUDGET_CAP * 100):,} paise)")
    print(f"charge         : {ATTEMPTED:,} paise  (INR {ATTEMPTED / 100:,.0f})")
    print(f"root SD-JWT    : {len(root)} chars, {root.count('~')} tilde segments")

    results: dict[str, Any] = {}

    for label, disclose in (
        ("FULL  (both constraints disclosed)", None),
        ("REDACTED (Budget withheld)", {"constraints": {1: {}}}),
    ):
        hr(label)
        try:
            presentation = client.present(
                sa,
                root,
                [closed_m],
                claims_to_disclose=disclose,
                nonce=NONCE,
                aud=AUD,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"present() failed: {type(exc).__name__}: {exc}")
            results[label] = ("present-failed", None, None)
            continue

        print(f"presentation   : {len(presentation)} chars, "
              f"{presentation.count('~')} tilde segments")

        try:
            # chain.verify_chain wants a resolver (ParsedToken -> JWK). The
            # root hop is issuer-signed; later hops are resolved via `cnf`.
            verified = client.verify(
                presentation,
                lambda _parsed: bank,
                expected_aud=AUD,
                expected_nonce=NONCE,
            )
            chain_ok = True
        except Exception as exc:  # noqa: BLE001
            print(f"VERIFY FAILED  : {type(exc).__name__}: {exc}")
            results[label] = ("verify-failed", False, None)
            continue

        payloads = verified if isinstance(verified, list) else [verified]
        seen: list[str] = []
        for p in payloads:
            seen.extend(constraints_of(p))
        print(f"chain verifies : {chain_ok}")
        print(f"constraints visible to verifier: {seen or '(none)'}")

        # Re-parse the root payload and run AP2's own evaluation on it.
        root_payload = payloads[0] if payloads else {}
        violations: list[str] = []
        try:
            reparsed = (
                OpenPaymentMandate.model_validate(root_payload)
                if isinstance(root_payload, dict)
                else root_payload
            )
            ctx = MandateContext(total_amount=0, total_uses=0)
            for c in reparsed.constraints:
                violations.extend(
                    create_payment_evaluator(c, ctx).evaluate(closed_m)
                )
            print(f"violations     : {violations or '[]'}")
        except Exception as exc:  # noqa: BLE001
            print(f"re-parse failed: {type(exc).__name__}: {exc}")
            violations = ["<reparse-error>"]

        results[label] = (
            "ok",
            chain_ok,
            bool(violations) and violations != ["<reparse-error>"],
        )
        print(f"\n=> over-cap payment "
              f"{'BLOCKED' if results[label][2] else 'ALLOWED'}")

    hr("RESULT")
    for label, (state, chain_ok, blocked) in results.items():
        print(f"  {label:38} state={state:14} chain_ok={chain_ok} blocked={blocked}")

    full = results.get("FULL  (both constraints disclosed)")
    red = results.get("REDACTED (Budget withheld)")
    print()
    if full and red and full[2] is True and red[1] is True and red[2] is False:
        print("  CONFIRMED END-TO-END: chain verifies with the cap withheld,")
        print("  and the over-cap payment is allowed.")
        return 0
    print("  Not confirmed end-to-end in this configuration. Read the")
    print("  per-stage output above before making any claim.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
