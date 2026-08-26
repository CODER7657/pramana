"""A pre-registered test set: cases and expectations, sealed before execution.

**STATUS AT THIS COMMIT: SEALED. NOT YET RUN.**

Track 2 asks for precision and recall on a *held-out* test set. We do not have
one and cannot honestly manufacture one alone: the same party wrote the gate and
every case it has been measured against, so a case nobody thought of is a case
nobody wrote. AIP-Bench's artifacts release 2026-10-04, after the deadline.

This is the closest honest substitute, and it is a **method** rather than a
number. Every case below was written from the Reserve Bank of India's *Digital
Payments -- E-mandate Framework, 2026* by reading the provisions and asking what
the regulation requires -- not by reading `rbi.py` and asking what it does. Each
one records the provision it came from and the outcome the **regulation**
demands, decided before any of them were executed.

The protocol, which is the part that matters
--------------------------------------------

1. This file is committed **with no runner and no results**, in a commit that
   does not execute it. Git history is the evidence of that ordering, and it is
   checkable by anyone with `git log --follow`.
2. Only then is the runner written and the set executed.
3. Whatever comes out is published **unedited**, including failures, and a
   failure means the gate disagrees with our own reading of the regulation.
   Either the gate is wrong or the reading was -- and both are worth knowing.

What this is not
----------------

It is **not blind**. The author of these cases has read the implementation
before, and no amount of good intention undoes that. Pre-registration fixes the
*ordering* problem -- it makes it impossible to quietly tune expectations to
whatever the code happened to produce -- but it does not fix the *authorship*
problem. A genuinely held-out set has to come from someone else, or from
production traffic, and neither is available here.

Saying exactly that is the point. A number presented as validated when it is not
is worth less than a smaller claim that is true.
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

SEALED_AT: Final = "2026-08-26"
"""The date these expectations were fixed. Before any of them were run."""

# -- provisions, quoted from the notification ------------------------------

AFA_CEILING: Final = (
    "AFA exemption ceiling for recurring transactions: AFA is required above "
    "INR 15,000."
)
ENHANCED_CEILING: Final = (
    "Enhanced ceiling of INR 1,00,000 for insurance premiums, mutual fund "
    "subscriptions and credit-card bill payments."
)
PRE_DEBIT_NOTICE: Final = (
    "The customer must receive a pre-transaction notification at least 24 "
    "hours before the debit."
)
REGISTRATION_AFA: Final = (
    "Registration, modification and withdrawal of an e-mandate each require AFA."
)
VALIDITY_PERIOD: Final = (
    "The e-mandate carries a specified validity period; a debit outside it is "
    "unauthorised."
)


@dataclass(frozen=True, slots=True)
class PreregCase:
    """One case, its expected outcome, and the provision that decides it."""

    case: BenchCase
    should_allow: bool
    """What the REGULATION requires. Fixed before execution, never edited after."""

    provision: str
    reasoning: str
    """Why the regulation gives that answer. Written to be checkable by a
    reader who has the notification and has never seen this codebase."""


def _c(
    ident: str,
    description: str,
    *,
    should_allow: bool,
    provision: str,
    reasoning: str,
    **facts: object,
) -> PreregCase:
    return PreregCase(
        case=BenchCase(
            id=ident,
            rc_class="RC-5",
            title=ident.replace("-", " "),
            description=description,
            is_attack=not should_allow,
            facts=_clean_facts(**facts),
            observed_protocol=_full_protocol(),
            observed_mandate=_full_mandate(),
            observed_merchant=_full_merchant(),
        ),
        should_allow=should_allow,
        provision=provision,
        reasoning=reasoning,
    )


def prereg_cases() -> tuple[PreregCase, ...]:
    """Seventeen cases derived from the notification. Sealed 2026-08-26."""
    return (
        # -- the standard AFA-free ceiling --------------------------------
        _c(
            "pr-under-ceiling-no-afa",
            "INR 4,999 grocery mandate, no AFA performed.",
            should_allow=True,
            provision=AFA_CEILING,
            reasoning="Below INR 15,000, so AFA is not required at all.",
            amount_paise=499_900,
            category="groceries",
            afa_performed=False,
        ),
        _c(
            "pr-exactly-at-ceiling-no-afa",
            "INR 15,000 exactly, no AFA. The boundary the rule names.",
            should_allow=True,
            provision=AFA_CEILING,
            reasoning=(
                "The ceiling is an exemption limit. AFA is required *above* "
                "INR 15,000, so a debit of exactly INR 15,000 is exempt."
            ),
            amount_paise=1_500_000,
            category="groceries",
            afa_performed=False,
        ),
        _c(
            "pr-one-rupee-over-ceiling-no-afa",
            "INR 15,001, no AFA. One rupee past the exemption.",
            should_allow=False,
            provision=AFA_CEILING,
            reasoning="Above INR 15,000 without AFA is outside the framework.",
            amount_paise=1_500_100,
            category="groceries",
            afa_performed=False,
        ),
        _c(
            "pr-over-ceiling-with-afa",
            "INR 40,000 with AFA performed.",
            should_allow=True,
            provision=AFA_CEILING,
            reasoning="Above the ceiling but AFA was performed, which is what "
            "the provision asks for.",
            amount_paise=4_000_000,
            category="groceries",
            afa_performed=True,
        ),
        # -- the enhanced-category ceiling --------------------------------
        _c(
            "pr-insurance-50k-no-afa",
            "INR 50,000 insurance premium, no AFA.",
            should_allow=True,
            provision=ENHANCED_CEILING,
            reasoning=(
                "Insurance carries the INR 1,00,000 ceiling, and 50,000 is "
                "inside it, so no AFA is required."
            ),
            amount_paise=5_000_000,
            category="insurance",
            afa_performed=False,
        ),
        _c(
            "pr-insurance-exactly-1lakh-no-afa",
            "INR 1,00,000 insurance premium exactly, no AFA.",
            should_allow=True,
            provision=ENHANCED_CEILING,
            reasoning="At the enhanced ceiling, not above it, so still exempt.",
            amount_paise=10_000_000,
            category="insurance",
            afa_performed=False,
        ),
        _c(
            "pr-insurance-over-1lakh-no-afa",
            "INR 1,50,000 insurance premium, no AFA.",
            should_allow=False,
            provision=ENHANCED_CEILING,
            reasoning="Above even the enhanced ceiling, so AFA is required.",
            amount_paise=15_000_000,
            category="insurance",
            afa_performed=False,
        ),
        _c(
            "pr-mutual-fund-sip-25k-no-afa",
            "INR 25,000 mutual fund SIP, no AFA.",
            should_allow=True,
            provision=ENHANCED_CEILING,
            reasoning="Mutual funds are a specified category; 25,000 is inside "
            "the enhanced ceiling.",
            amount_paise=2_500_000,
            category="mutual_fund",
            afa_performed=False,
        ),
        _c(
            "pr-credit-card-bill-80k-no-afa",
            "INR 80,000 credit-card bill autopay, no AFA.",
            should_allow=True,
            provision=ENHANCED_CEILING,
            reasoning="Credit-card bill payments are a specified category.",
            amount_paise=8_000_000,
            category="credit_card_bill",
            afa_performed=False,
        ),
        _c(
            "pr-groceries-20k-no-afa",
            "INR 20,000 groceries, no AFA. NOT a specified category.",
            should_allow=False,
            provision=ENHANCED_CEILING,
            reasoning=(
                "The enhanced ceiling is limited to the named categories. "
                "Groceries fall under the standard INR 15,000 ceiling, so "
                "20,000 without AFA is outside the framework."
            ),
            amount_paise=2_000_000,
            category="groceries",
            afa_performed=False,
        ),
        # -- pre-debit notification ---------------------------------------
        _c(
            "pr-notice-exactly-24h",
            "Pre-debit notice sent exactly 24 hours before the debit.",
            should_allow=True,
            provision=PRE_DEBIT_NOTICE,
            reasoning="The provision says 'at least 24 hours'. Exactly 24 "
            "satisfies it.",
            amount_paise=500_000,
            pre_debit_notice_at=BENCH_NOW - timedelta(hours=24),
        ),
        _c(
            "pr-notice-23h",
            "Pre-debit notice sent 23 hours before the debit.",
            should_allow=False,
            provision=PRE_DEBIT_NOTICE,
            reasoning="Less than the required 24 hours.",
            amount_paise=500_000,
            pre_debit_notice_at=BENCH_NOW - timedelta(hours=23),
        ),
        _c(
            "pr-notice-week-early",
            "Pre-debit notice sent 7 days before the debit.",
            should_allow=True,
            provision=PRE_DEBIT_NOTICE,
            reasoning="Comfortably more than 24 hours.",
            amount_paise=500_000,
            pre_debit_notice_at=BENCH_NOW - timedelta(days=7),
        ),
        # -- AFA at registration ------------------------------------------
        _c(
            "pr-no-afa-at-registration",
            "Mandate presented with no evidence of AFA at registration.",
            should_allow=False,
            provision=REGISTRATION_AFA,
            reasoning=(
                "A mandate registered without AFA is not a valid basis for "
                "any agent-initiated debit, regardless of amount."
            ),
            amount_paise=100_000,
            afa_at_registration=False,
        ),
        # -- validity window ----------------------------------------------
        _c(
            "pr-last-day-of-validity",
            "Debit on the final day the mandate is valid.",
            should_allow=True,
            provision=VALIDITY_PERIOD,
            reasoning="Inside the specified period, at its edge.",
            amount_paise=500_000,
            mandate_valid_until=BENCH_NOW + timedelta(hours=1),
        ),
        _c(
            "pr-after-expiry",
            "Debit one day after the mandate expired.",
            should_allow=False,
            provision=VALIDITY_PERIOD,
            reasoning="Outside the specified validity period, so unauthorised.",
            amount_paise=500_000,
            mandate_valid_until=BENCH_NOW - timedelta(days=1),
        ),
        _c(
            "pr-before-validity-starts",
            "Debit attempted before the mandate's validity period begins.",
            should_allow=False,
            provision=VALIDITY_PERIOD,
            reasoning=(
                "A validity period has two edges. A debit before it starts is "
                "as unauthorised as one after it ends."
            ),
            amount_paise=500_000,
            mandate_valid_from=BENCH_NOW + timedelta(days=1),
            mandate_valid_until=BENCH_NOW + timedelta(days=30),
        ),
    )
