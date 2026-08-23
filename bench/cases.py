"""The frozen attack benchmark.

**Defence only.** Every case here is a fixed, enumerated scenario that runs
against locally constructed mandates and locally generated state. Nothing in
this module performs network I/O, targets a third-party system, or generates a
novel attack. It is a regression suite, not a tool. See SECURITY.md.

Structure
---------

Cases are aligned to the root-cause taxonomy in *Protocol-Level Attacks on
Agentic Commerce Platforms* (Louck, arXiv:2607.21824, 23 July 2026), which
defines six classes: RC-1 through RC-5 are **structural** -- model-independent
and deterministically exploitable -- and RC-6 is **semantic**, meaning its
success depends on the model and is therefore probabilistic.

We align to that taxonomy so our numbers are comparable to a published
baseline rather than to a test set we wrote for ourselves. We have **not** run
AIP-Bench itself: the authors state full artifacts are released on 2026-10-04.
These are our own cases, mapped to their classes, and the README says so.

What each case measures
-----------------------

Every case is evaluated twice:

* **Baseline** -- a verifier using presence-driven evaluation, i.e. one that
  checks the constraints it can see and reports violations. This is the
  behaviour of the AP2 reference implementation used as-is, and it is what our
  spike measured directly.
* **PRAMANA** -- the same request through the full kernel, where policy
  declares what must be present and absence is INDETERMINATE.

The suite contains legitimate traffic as well as attacks. An attack-success
rate reported without a false-positive rate is not a result; it is half of one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final

from pramana.kernel.risk.signals import RiskAdapter
from pramana.kernel.verdict import Obligation, ObligationSource, ObligationStatus
from pramana.kernel.verify.rbi import PaymentFacts

#: Fixed evaluation instant. The suite must not drift with the wall clock.
BENCH_NOW: Final = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)

RC_CLASSES: Final[dict[str, str]] = {
    "RC-1": "Registry/marketplace content accepted without integrity verification",
    "RC-2": "Payment destination taken from untrusted source without DID binding",
    "RC-3": "Authentication credential transmitted via observable channel",
    "RC-4": "Non-atomic check-then-execute in payment state (TOCTOU)",
    "RC-5": "Authentication exists but authorization scope not enforced",
    "RC-6": "Behavioral manipulation via poisoned agent descriptions (IPI)",
}

SEMANTIC_CLASSES: Final = frozenset({"RC-6"})
"""RC-6 is model-dependent. Its ASR is a distribution, not a constant, which is
why the report separates it from the structural classes rather than averaging
them together."""


def _ref(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _ob(
    ident: str,
    status: ObligationStatus,
    source: ObligationSource,
    detail: str = "",
) -> Obligation:
    return Obligation(
        id=ident,
        status=status,
        source=source,
        detail=detail or f"{ident} evaluated",
    )


def _clean_facts(**overrides: object) -> PaymentFacts:
    base: dict[str, object] = {
        "amount_paise": 500_000,
        "currency": "INR",
        "category": "groceries",
        "afa_performed": False,
        "afa_at_registration": True,
        "pre_debit_notice_at": BENCH_NOW - timedelta(hours=30),
        "execution_at": BENCH_NOW,
        "mandate_valid_from": BENCH_NOW - timedelta(days=30),
        "mandate_valid_until": BENCH_NOW + timedelta(days=30),
    }
    base.update(overrides)
    return PaymentFacts(**base)  # type: ignore[arg-type]


ALL_PROTOCOL: Final = (
    "chain.verified",
    "chain.nonce_fresh",
    "chain.disclosures_pinned",
)
ALL_MANDATE: Final = ("mandate.budget", "mandate.payee_in_scope", "mandate.not_expired")
ALL_MERCHANT: Final = ("merchant.category_allowed",)


@dataclass(frozen=True, slots=True)
class BenchCase:
    """One frozen scenario.

    ``observed_*`` is what a presence-driven verifier can actually evaluate.
    An obligation absent from these tuples is one the verifier never sees --
    which is the entire mechanism under test. A baseline verifier finds no
    violation for a check it never ran.
    """

    id: str
    rc_class: str
    title: str
    description: str
    is_attack: bool
    facts: PaymentFacts
    observed_protocol: tuple[Obligation, ...] = field(default_factory=tuple)
    observed_mandate: tuple[Obligation, ...] = field(default_factory=tuple)
    observed_merchant: tuple[Obligation, ...] = field(default_factory=tuple)
    risk_adapters: tuple[RiskAdapter, ...] = field(default_factory=tuple)
    notes: str = ""

    def __post_init__(self) -> None:
        if self.rc_class not in RC_CLASSES:
            raise ValueError(f"{self.id}: unknown class {self.rc_class!r}")
        if not self.description:
            raise ValueError(f"{self.id}: description is required")

    @property
    def mandate_ref(self) -> str:
        return _ref(self.id)

    @property
    def is_semantic(self) -> bool:
        return self.rc_class in SEMANTIC_CLASSES

    @property
    def observed_ids(self) -> frozenset[str]:
        """What a presence-driven verifier can evaluate for this case."""
        return frozenset(
            o.id
            for group in (
                self.observed_protocol,
                self.observed_mandate,
                self.observed_merchant,
            )
            for o in group
        )


def _all_satisfied(
    ids: tuple[str, ...], source: ObligationSource
) -> tuple[Obligation, ...]:
    return tuple(_ob(i, ObligationStatus.SATISFIED, source) for i in ids)


def _full_protocol() -> tuple[Obligation, ...]:
    return _all_satisfied(ALL_PROTOCOL, ObligationSource.PROTOCOL)


def _full_mandate() -> tuple[Obligation, ...]:
    return _all_satisfied(ALL_MANDATE, ObligationSource.MANDATE)


def _full_merchant() -> tuple[Obligation, ...]:
    return _all_satisfied(ALL_MERCHANT, ObligationSource.MERCHANT)


def _without(obligations: tuple[Obligation, ...], *drop: str) -> tuple[Obligation, ...]:
    """Simulate a constraint being withheld from the presentation."""
    return tuple(o for o in obligations if o.id not in drop)


# ---------------------------------------------------------------------------
# The cases
# ---------------------------------------------------------------------------


def attack_cases() -> tuple[BenchCase, ...]:
    """Frozen adversarial scenarios. Each SHOULD be rejected."""
    return (
        # -- RC-5: the finding ------------------------------------------
        BenchCase(
            id="rc5-budget-withheld",
            rc_class="RC-5",
            title="Spending cap withheld from the presentation",
            description=(
                "The chain authenticates and every visible constraint is "
                "satisfied, but the budget constraint was never disclosed. A "
                "presence-driven verifier finds no violation because there is "
                "nothing left to evaluate."
            ),
            is_attack=True,
            facts=_clean_facts(),
            observed_protocol=_full_protocol(),
            observed_mandate=_without(_full_mandate(), "mandate.budget"),
            observed_merchant=_full_merchant(),
            notes="Reproduced end-to-end against AP2 e1ea56db. See ADR-0003.",
        ),
        BenchCase(
            id="rc5-all-constraints-withheld",
            rc_class="RC-5",
            title="Entire constraints array withheld",
            description=(
                "Selective disclosure removes every mandate constraint at "
                "once. The chain still verifies; authority is unbounded."
            ),
            is_attack=True,
            facts=_clean_facts(),
            observed_protocol=_full_protocol(),
            observed_mandate=(),
            observed_merchant=_full_merchant(),
        ),
        BenchCase(
            id="rc5-scope-not-enforced",
            rc_class="RC-5",
            title="Authenticated agent acting outside its category scope",
            description=(
                "Authentication succeeds and the merchant scope check is "
                "simply absent from the presentation, so no authorization "
                "boundary is applied."
            ),
            is_attack=True,
            facts=_clean_facts(),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=(),
        ),
        # -- RC-2: payout destination -----------------------------------
        BenchCase(
            id="rc2-payee-unbound",
            rc_class="RC-2",
            title="Payout destination not bound to the mandate",
            description=(
                "The payee constraint is withheld, so the destination is "
                "taken from the request rather than from the signed mandate."
            ),
            is_attack=True,
            facts=_clean_facts(),
            observed_protocol=_full_protocol(),
            observed_mandate=_without(_full_mandate(), "mandate.payee_in_scope"),
            observed_merchant=_full_merchant(),
        ),
        BenchCase(
            id="rc2-payee-violated",
            rc_class="RC-2",
            title="Payout destination outside the allowed list",
            description=(
                "The payee constraint IS present and fails. A baseline "
                "verifier catches this one -- included so the suite is not "
                "stacked to only contain cases the baseline misses."
            ),
            is_attack=True,
            facts=_clean_facts(),
            observed_protocol=_full_protocol(),
            observed_mandate=(
                _ob("mandate.budget", ObligationStatus.SATISFIED,
                    ObligationSource.MANDATE),
                _ob(
                    "mandate.payee_in_scope",
                    ObligationStatus.VIOLATED,
                    ObligationSource.MANDATE,
                    "payee not in the allowed list",
                ),
                _ob("mandate.not_expired", ObligationStatus.SATISFIED,
                    ObligationSource.MANDATE),
            ),
            observed_merchant=_full_merchant(),
        ),
        # -- RC-4: TOCTOU / replay --------------------------------------
        BenchCase(
            id="rc4-nonce-replay",
            rc_class="RC-4",
            title="Presentation replayed with a reused nonce",
            description=(
                "The same presentation is submitted twice. Detecting this "
                "requires persisted state that AP2 defines (MandateContext) "
                "but never stores, so a stateless verifier cannot see it."
            ),
            is_attack=True,
            facts=_clean_facts(),
            observed_protocol=_without(_full_protocol(), "chain.nonce_fresh"),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        BenchCase(
            id="rc4-cumulative-budget-race",
            rc_class="RC-4",
            title="Concurrent debits each individually within cap",
            description=(
                "Two debits each pass an isolated amount check but breach the "
                "cumulative budget. Requires stateful spend accounting; "
                "without it the budget obligation cannot be evaluated at all."
            ),
            is_attack=True,
            facts=_clean_facts(amount_paise=400_000),
            observed_protocol=_full_protocol(),
            observed_mandate=_without(_full_mandate(), "mandate.budget"),
            observed_merchant=_full_merchant(),
        ),
        # -- RC-1: catalogue / registry integrity -----------------------
        BenchCase(
            id="rc1-unverified-catalogue",
            rc_class="RC-1",
            title="Merchant catalogue accepted without integrity verification",
            description=(
                "Marketplace content is trusted without an integrity check. "
                "PRAMANA does not yet ship a catalogue scanner, so this case "
                "is expected to be caught only via the merchant policy "
                "obligation, and is reported honestly either way."
            ),
            is_attack=True,
            facts=_clean_facts(category="gambling"),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=(
                _ob(
                    "merchant.category_allowed",
                    ObligationStatus.VIOLATED,
                    ObligationSource.MERCHANT,
                    "category blocked by merchant policy",
                ),
            ),
        ),
        # -- RC-3: observable credential channel ------------------------
        BenchCase(
            id="rc3-disclosures-unpinned",
            rc_class="RC-3",
            title="Disclosure set not pinned by the verifier",
            description=(
                "The verifier does not assert which disclosures must be "
                "present, so a delegate may vary them between presentations. "
                "This is the class PCAT reduces to warn-only; PRAMANA's "
                "control is the disclosures_pinned obligation."
            ),
            is_attack=True,
            facts=_clean_facts(),
            observed_protocol=_without(_full_protocol(), "chain.disclosures_pinned"),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        # -- regulatory ---------------------------------------------------
        BenchCase(
            id="rbi-afa-breach",
            rc_class="RC-5",
            title="Debit above the AFA ceiling without authentication",
            description=(
                "INR 20,000 debited without AFA. Above the RBI AFA-free "
                "ceiling of INR 15,000 this is outside the framework "
                "regardless of what the mandate permits."
            ),
            is_attack=True,
            facts=_clean_facts(amount_paise=2_000_000, afa_performed=False),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        BenchCase(
            id="rbi-expired-mandate",
            rc_class="RC-5",
            title="Debit after the mandate's validity period expired",
            description=(
                "The e-mandate's specified validity period has passed, so the "
                "debit is unauthorised under the RBI framework."
            ),
            is_attack=True,
            facts=_clean_facts(
                mandate_valid_until=BENCH_NOW - timedelta(days=1)
            ),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        BenchCase(
            id="rbi-no-pre-debit-notice",
            rc_class="RC-5",
            title="Debit without the required 24-hour notice",
            description=(
                "Notice given 2 hours before the debit, against a 24-hour "
                "requirement."
            ),
            is_attack=True,
            facts=_clean_facts(
                pre_debit_notice_at=BENCH_NOW - timedelta(hours=2)
            ),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
    )


def legitimate_cases() -> tuple[BenchCase, ...]:
    """Well-formed traffic. Each SHOULD be allowed.

    Without these the attack-success rate is meaningless: a gate that rejects
    everything scores a perfect ASR and is worthless. These measure the cost.
    """
    return (
        BenchCase(
            id="ok-small-purchase",
            rc_class="RC-5",
            title="Ordinary in-envelope purchase",
            description="INR 5,000 groceries, everything disclosed and within scope.",
            is_attack=False,
            facts=_clean_facts(),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        BenchCase(
            id="ok-at-afa-ceiling",
            rc_class="RC-5",
            title="Exactly at the AFA-free ceiling",
            description=(
                "INR 15,000 exactly. Boundary conditions on money must not "
                "produce false positives."
            ),
            is_attack=False,
            facts=_clean_facts(amount_paise=1_500_000),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        BenchCase(
            id="ok-above-ceiling-with-afa",
            rc_class="RC-5",
            title="Above the ceiling, but AFA was performed",
            description="INR 20,000 with AFA. Permitted under the framework.",
            is_attack=False,
            facts=_clean_facts(amount_paise=2_000_000, afa_performed=True),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        BenchCase(
            id="ok-enhanced-category",
            rc_class="RC-5",
            title="Insurance premium under the enhanced ceiling",
            description=(
                "INR 50,000 insurance premium. Breaches the standard ceiling "
                "but is within the enhanced one for specified categories."
            ),
            is_attack=False,
            facts=_clean_facts(
                amount_paise=5_000_000, category="insurance", afa_performed=True
            ),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        BenchCase(
            id="ok-exact-24h-notice",
            rc_class="RC-5",
            title="Notice given exactly 24 hours before the debit",
            description="The boundary of the notification requirement.",
            is_attack=False,
            facts=_clean_facts(
                pre_debit_notice_at=BENCH_NOW - timedelta(hours=24)
            ),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        BenchCase(
            id="ok-last-day-of-validity",
            rc_class="RC-5",
            title="Debit on the final day of the validity period",
            description="Inside the window, at its edge.",
            is_attack=False,
            facts=_clean_facts(
                mandate_valid_until=BENCH_NOW + timedelta(minutes=1)
            ),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
    )


def all_cases() -> tuple[BenchCase, ...]:
    return attack_cases() + legitimate_cases()
