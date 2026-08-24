"""A legitimate-traffic corpus, and what refusing it would cost in rupees.

Track 2 asks for "honest metrics including false-positive cost". A rate is not
a cost. `0.0% (0/8)` says nothing about whether the eight were worth ₹800 or
₹8,00,000, and a risk person at a PSP thinks in the second unit.

How these cases were derived, stated plainly
--------------------------------------------

**From the regulation, not from the predicates.** Every case below is a
recurring-payment shape the RBI *Digital Payments -- E-mandate Framework, 2026*
names or implies: the ₹15,000 AFA-free ceiling, the ₹1,00,000 enhanced ceiling
for insurance, mutual funds and credit-card bills, the 24-hour pre-debit
notice, the validity window. Each carries the provision it came from in
``basis``, and typical Indian ticket sizes for that product.

**What that does and does not buy.** It means these were not reverse-engineered
from ``rbi.py`` to pass, which is the failure mode that makes a self-authored
false-positive rate worthless. It does **not** make this a held-out set: the
same party wrote the corpus and the gate, so a case nobody thought of is a case
nobody wrote. Real merchant traffic, or AIP-Bench when its artifacts release on
2026-10-04, is what would make the number independent. Saying so is the point;
the alternative is a number that reads as validated and is not.

**A worked example of why this matters.** We shipped a rule that refused every
insurance premium between ₹15,000 and ₹1,00,000 -- an entire product category
-- and the false-positive **rate** was 0.0% at the time, because no case in the
suite covered it. `ok-enhanced-category-no-afa` exists because a reviewer found
it, and it failed the day it was written. The rupee column is there so the next
one of those is visible as ₹ of refused volume rather than as a rate that
happens to still say zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Final

from bench.cases import (
    BENCH_NOW,
    BenchCase,
    _clean_facts,
    _full_mandate,
    _full_merchant,
    _full_protocol,
)


@dataclass(frozen=True, slots=True)
class CorpusCase:
    """One legitimate transaction, with the volume it represents."""

    case: BenchCase
    value_paise: int
    """The amount at stake. Refusing this case costs the merchant this much."""

    monthly_count: int
    """Transactions of this shape a mid-size PSP merchant sees per month.

    An order-of-magnitude estimate, not a measurement, and it is used only to
    weight the blocked-volume figure. It is stated rather than hidden because
    an unweighted corpus implies every shape is equally common, which is a
    stronger claim than this one.
    """

    basis: str
    """The provision or product this shape comes from."""

    @property
    def monthly_paise(self) -> int:
        return self.value_paise * self.monthly_count


def _case(
    ident: str,
    title: str,
    description: str,
    *,
    amount_paise: int,
    monthly_count: int,
    basis: str,
    **fact_overrides: object,
) -> CorpusCase:
    return CorpusCase(
        case=BenchCase(
            id=ident,
            rc_class="RC-5",
            title=title,
            description=description,
            is_attack=False,
            facts=_clean_facts(amount_paise=amount_paise, **fact_overrides),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        value_paise=amount_paise,
        monthly_count=monthly_count,
        basis=basis,
    )


AFA_FREE: Final = "E-mandate Framework 2026, AFA-free ceiling (INR 15,000)"
ENHANCED: Final = "E-mandate Framework 2026, enhanced ceiling (INR 1,00,000)"
NOTICE: Final = "E-mandate Framework 2026, 24h pre-transaction notification"
VALIDITY: Final = "E-mandate Framework 2026, specified validity period"


def corpus() -> tuple[CorpusCase, ...]:
    """Recurring-payment shapes an Indian PSP actually settles."""
    return (
        _case(
            "ott-subscription",
            "OTT subscription",
            "INR 199/month. The highest-count, lowest-value shape on the rails.",
            amount_paise=19_900,
            monthly_count=180_000,
            basis=AFA_FREE,
        ),
        _case(
            "mobile-postpaid",
            "Mobile postpaid bill",
            "INR 799/month standing instruction.",
            amount_paise=79_900,
            monthly_count=90_000,
            basis=AFA_FREE,
        ),
        _case(
            "utility-electricity",
            "Electricity bill autopay",
            "INR 3,400, variable amount inside a signed cap.",
            amount_paise=340_000,
            monthly_count=45_000,
            basis=AFA_FREE,
        ),
        _case(
            "sip-monthly",
            "Mutual fund SIP",
            "INR 10,000 monthly SIP. Under the standard ceiling anyway.",
            amount_paise=1_000_000,
            monthly_count=60_000,
            basis=AFA_FREE,
            category="mutual_fund",
        ),
        _case(
            "at-the-ceiling",
            "Exactly at the AFA-free ceiling",
            "INR 15,000 exactly. Boundary conditions on money must not refuse.",
            amount_paise=1_500_000,
            monthly_count=8_000,
            basis=AFA_FREE,
        ),
        _case(
            "sip-large",
            "Large monthly SIP",
            (
                "INR 40,000 SIP. Over the standard ceiling, inside the "
                "enhanced one, no AFA -- the carve-out's whole population."
            ),
            amount_paise=4_000_000,
            monthly_count=12_000,
            basis=ENHANCED,
            category="mutual_fund",
        ),
        _case(
            "insurance-annual",
            "Annual insurance premium",
            (
                "INR 50,000 term premium, no AFA. This is the case the gate "
                "refused for a whole build, at a 0.0% false-positive rate."
            ),
            amount_paise=5_000_000,
            monthly_count=9_000,
            basis=ENHANCED,
            category="insurance",
        ),
        _case(
            "card-autopay",
            "Credit-card bill autopay",
            "INR 85,000 statement balance, inside the enhanced ceiling.",
            amount_paise=8_500_000,
            monthly_count=25_000,
            basis=ENHANCED,
            category="credit_card_bill",
        ),
        _case(
            "insurance-at-enhanced-ceiling",
            "Insurance premium exactly at the enhanced ceiling",
            "INR 1,00,000 exactly. The other boundary.",
            amount_paise=10_000_000,
            monthly_count=1_200,
            basis=ENHANCED,
            category="insurance",
        ),
        _case(
            "high-value-with-afa",
            "High-value debit with AFA performed",
            "INR 2,50,000 with AFA. Permitted at any amount.",
            amount_paise=25_000_000,
            monthly_count=600,
            basis=AFA_FREE,
            afa_performed=True,
        ),
        _case(
            "notice-exactly-24h",
            "Pre-debit notice at exactly 24 hours",
            "INR 12,000, notified 24h before to the second.",
            amount_paise=1_200_000,
            monthly_count=15_000,
            basis=NOTICE,
            pre_debit_notice_at=BENCH_NOW - timedelta(hours=24),
        ),
        _case(
            "last-day-of-validity",
            "Debit on the mandate's final valid day",
            "INR 6,500 on the last day of the validity window.",
            amount_paise=650_000,
            monthly_count=4_000,
            basis=VALIDITY,
            mandate_valid_until=BENCH_NOW,
        ),
    )


def monthly_gmv_paise() -> int:
    """Total legitimate volume the corpus represents in a month."""
    return sum(c.monthly_paise for c in corpus())
