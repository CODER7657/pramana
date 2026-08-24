"""Mint a real AP2 delegation chain, locally, for the demo and its tests.

This is **demonstration scaffolding, not a production path**. It issues its own
keys, signs its own mandate and presents it to itself, so `pramana chain` shows
the finding end-to-end on a laptop with no network and no third party. Nothing
in the gate imports it.

It exists because the alternative -- a hand-written verdict that *illustrates*
the finding -- is what the README had to apologise for. A demo that constructs
its own conclusion proves nothing about the code. This one constructs a real
SD-JWT chain, withholds a real disclosure, and lets
:mod:`pramana.adapters.ap2` and the kernel reach their own conclusion.

Why the cap is the only selectively-disclosable entry
-----------------------------------------------------

``DisclosureMetadata(sd_array_indices=[0])`` marks **only** ``Budget`` as
selectively disclosable; ``AllowedPayees`` stays in the base payload. That is
deliberate, and it is what makes the demo sharp rather than merely true: the
withheld presentation still discloses ``payment.allowed_payees``, so what a
verifier sees is a chain that is complete-looking and one constraint short --
not an obviously empty one.

It is also forced. Passing any non-``None`` ``claims_to_disclose`` makes
``MandateClient.present`` drop **every** array-element disclosure that lacks a
``vct``, so per-index selection of constraints is not reachable through that
API at ``e1ea56db``. Marking one index is how you withhold exactly one thing.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Final

from pramana.adapters.ap2 import IssuerKeyResolver, Presentation
from pramana.kernel.verdict import Obligation, ObligationSource, ObligationStatus

AUDIENCE: Final = "https://merchant.example/checkout"

CAP_MAJOR: Final = 5_000.0
"""INR 5,000. AP2's ``Budget.max`` is in MAJOR units -- its sibling
``AmountRange.max`` is in minor ones, which is upstream finding #2."""

CAP_PAISE: Final = int(CAP_MAJOR * 100)
ATTEMPTED_PAISE: Final = 750_000
"""INR 7,500 against an INR 5,000 cap. Over by design."""


@dataclass(frozen=True, slots=True)
class MintedChain:
    """A signed presentation plus everything needed to judge it."""

    presentation: Presentation
    resolve_issuer_key: IssuerKeyResolver
    closed_mandate: Any
    withheld: bool
    cap_paise: int = CAP_PAISE
    amount_paise: int = ATTEMPTED_PAISE

    @property
    def segments(self) -> int:
        return self.presentation.token.count("~")

    @property
    def length(self) -> int:
        return len(self.presentation.token)


def mint(
    *,
    withhold_budget: bool,
    amount_paise: int = ATTEMPTED_PAISE,
    nonce: str | None = None,
) -> MintedChain:
    """Issue a root mandate and present it, with or without the cap disclosed.

    Raises whatever AP2 raises. This is demo scaffolding run before any
    decision exists, so there is no verdict to fail closed into -- unlike the
    adapter, where a raise would take a live decision with it.
    """
    from ap2.sdk.disclosure_metadata import DisclosureMetadata  # noqa: PLC0415
    from ap2.sdk.generated.open_payment_mandate import (  # noqa: PLC0415
        AllowedPayees,
        Budget,
        OpenPaymentMandate,
    )
    from ap2.sdk.generated.payment_mandate import PaymentMandate  # noqa: PLC0415
    from ap2.sdk.generated.types.amount import Amount  # noqa: PLC0415
    from ap2.sdk.generated.types.merchant import Merchant  # noqa: PLC0415
    from ap2.sdk.generated.types.payment_instrument import (  # noqa: PLC0415
        PaymentInstrument,
    )
    from ap2.sdk.mandate import MandateClient  # noqa: PLC0415
    from jwcrypto.jwk import JWK  # noqa: PLC0415

    # A fresh nonce per presentation, so SeenNonces answers a real question
    # rather than one whose answer was fixed by a constant.
    nonce = nonce or f"nonce-pramana-{secrets.token_hex(8)}"
    client = MandateClient()
    issuer_key = JWK.generate(kty="EC", crv="P-256")
    agent_key = JWK.generate(kty="EC", crv="P-256")

    merchant = Merchant(id="mrc_demo_grocer", name="Demo Grocer")
    open_mandate = OpenPaymentMandate(
        constraints=[
            Budget(max=CAP_MAJOR, currency="INR"),
            AllowedPayees(allowed=[merchant]),
        ],
        cnf={"jwk": agent_key.export_public(as_dict=True)},
    )
    closed_mandate = PaymentMandate(
        transaction_id="txn-pramana-demo",
        payee=merchant,
        payment_amount=Amount(currency="INR", amount=amount_paise),
        payment_instrument=PaymentInstrument(id="pi_demo_upi", type="upi"),
    )

    root = client.create(
        [open_mandate],
        issuer_key,
        sd=DisclosureMetadata(
            children={"constraints": DisclosureMetadata(sd_array_indices=[0])}
        ),
    )
    token = client.present(
        agent_key,
        root,
        [closed_mandate],
        # {} keeps every non-selectively-disclosable claim and drops the
        # Budget disclosure. None discloses everything.
        claims_to_disclose={} if withhold_budget else None,
        nonce=nonce,
        aud=AUDIENCE,
    )

    return MintedChain(
        presentation=Presentation(
            token=token, expected_aud=AUDIENCE, expected_nonce=nonce
        ),
        resolve_issuer_key=lambda _parsed: issuer_key,
        closed_mandate=closed_mandate,
        withheld=withhold_budget,
        amount_paise=amount_paise,
    )


def backend_obligations(
    payloads: tuple[Any, ...], closed_mandate: Any
) -> tuple[Obligation, ...]:
    """What a correct merchant backend would report, derived from AP2 itself.

    This is the honest simulation of the trusted caller, and the sharpest part
    of the demo. ``mandate.budget`` is **not** hand-set: it is whatever AP2's
    own evaluators conclude over the presented payload. Which means that in the
    withheld case the backend reports ``SATISFIED`` -- correctly, by upstream
    semantics, because there is no cap left to exceed and an empty violation
    list is compliance.

    So the withheld run is not PRAMANA disagreeing with a careless integrator.
    It is PRAMANA rejecting a payment that the protocol's own reference
    evaluator affirmatively passed.

    The remaining three are flat ``SATISFIED``: they need the persisted
    ``MandateContext`` that AP2 defines and never stores, so a demo cannot
    compute them and does not pretend to. ``chain.nonce_fresh`` is *not* in
    this list -- :class:`SeenNonces` computes it, because that state is the
    verifier's to hold.
    """
    violations = ap2_violations(payloads, closed_mandate)
    budget_ok = not violations
    return (
        Obligation(
            id="mandate.budget",
            status=(
                ObligationStatus.SATISFIED if budget_ok else ObligationStatus.VIOLATED
            ),
            source=ObligationSource.MANDATE,
            detail=(
                "AP2's own constraint evaluators reported no violation over the "
                "presented payload."
                if budget_ok
                else f"AP2's own constraint evaluators reported: {violations[0]}"
            ),
            observed={"ap2_violations": list(violations)},
            expected="within the mandated cap",
        ),
        Obligation(
            id="mandate.payee_in_scope",
            status=ObligationStatus.SATISFIED,
            source=ObligationSource.MANDATE,
            detail="Payee is in the mandate's allowed-payee list.",
            expected="payee in scope",
        ),
        Obligation(
            id="mandate.not_expired",
            status=ObligationStatus.SATISFIED,
            source=ObligationSource.MANDATE,
            detail="Execution date is inside the mandate's validity window.",
            expected="within validity",
        ),
        Obligation(
            id="merchant.category_allowed",
            status=ObligationStatus.SATISFIED,
            source=ObligationSource.MERCHANT,
            detail="Groceries are accepted from agents by this merchant.",
            expected="an accepted category",
        ),
    )


class SeenNonces:
    """A replay detector holding exactly the state AP2 declines to hold.

    **Process-local, and that is the whole caveat.** A real deployment needs
    this shared across every gate instance and expired on the policy's
    ``window_seconds``; a set in one process is not that. What it is, honestly,
    is enough to *compute* ``chain.nonce_fresh`` instead of accepting it from
    the caller -- and enough to show a replayed presentation being refused by
    the same code path that let the first one through.

    An unseen nonce is SATISFIED rather than NOT_APPLICABLE because this store
    genuinely answered the question for its own lifetime. Claiming more than
    that would be the vacuous-pass mistake in a new costume, which is why the
    scope is stated here rather than in a footnote.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def check(self, nonce: str | None) -> Obligation:
        if not nonce:
            return Obligation(
                id="chain.nonce_fresh",
                status=ObligationStatus.INDETERMINATE,
                source=ObligationSource.PROTOCOL,
                detail=(
                    "The presentation carried no nonce, so replay cannot be "
                    "ruled out. A check that could not run is not a check "
                    "that passed."
                ),
                expected="a nonce not seen before",
            )
        replayed = nonce in self._seen
        self._seen.add(nonce)
        return Obligation(
            id="chain.nonce_fresh",
            status=(
                ObligationStatus.VIOLATED if replayed else ObligationStatus.SATISFIED
            ),
            source=ObligationSource.PROTOCOL,
            detail=(
                "This nonce has already been presented to this gate. A second "
                "presentation of the same authorisation is a replay."
                if replayed
                else "This nonce has not been presented to this gate before."
            ),
            observed={"replayed": replayed, "seen_count": len(self._seen)},
            expected="a nonce not seen before",
        )


def ap2_violations(payloads: tuple[Any, ...], closed_mandate: Any) -> list[str]:
    """Run **AP2's own** constraint evaluators over what was disclosed.

    This is the baseline column, computed live rather than modelled: it is the
    upstream behaviour the whole project is a response to. With the cap
    disclosed it returns a budget violation. With the cap withheld it returns
    an empty list -- not because the payment is within the cap, but because
    there is no cap left to evaluate, and an empty violation list is what a
    presence-driven verifier reads as compliance.
    """
    from ap2.sdk.constraints import (  # noqa: PLC0415
        MandateContext,
        create_payment_evaluator,
    )
    from ap2.sdk.generated.open_payment_mandate import (  # noqa: PLC0415
        OpenPaymentMandate,
    )

    if not payloads:
        return []
    root = payloads[0]
    parsed = (
        OpenPaymentMandate.model_validate(root) if isinstance(root, dict) else root
    )
    context = MandateContext(total_amount=0, total_uses=0)
    violations: list[str] = []
    for constraint in getattr(parsed, "constraints", ()) or ():
        violations.extend(
            create_payment_evaluator(constraint, context).evaluate(closed_mandate)
        )
    return violations
