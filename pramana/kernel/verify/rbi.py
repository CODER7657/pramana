"""RBI e-mandate predicates.

The Reserve Bank of India notified the *Digital Payments - E-mandate Framework,
2026* on 21 April 2026, consolidating the earlier e-mandate circulars. It is not
a set of principles; it is a set of testable conditions. Compliance therefore
becomes a test suite, which is the entire reason this layer can be deterministic.

Two rules govern everything here.

**Amounts are in paise.** AP2's ``Amount.amount`` is in minor units, and so is
every threshold in the policy file. AP2's own ``Budget.max`` is in *major* units
while its sibling ``AmountRange.max`` is in minor units; conflating them yields a
cap that is wrong by a factor of one hundred. We hit that bug ourselves. Nothing
in this module accepts a rupee figure.

**Missing evidence is INDETERMINATE, never SATISFIED.** If a predicate cannot
see whether AFA was performed, it does not get to assume it was. Every predicate
here returns a status; none returns a bare boolean, so "we could not tell" is
representable and rejects (ADR-0003).

Thresholds live in the policy document, not in this file. That keeps the rule
and its citation together, and makes a jurisdiction a file rather than a fork.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from pramana.kernel.verdict import Obligation, ObligationStatus
from pramana.kernel.verify.policy import ObligationSpec

SECONDS_PER_HOUR: Final = 3600


@dataclass(frozen=True, slots=True)
class PaymentFacts:
    """Everything the RBI predicates need, already extracted and typed.

    A predicate never reaches into an AP2 object. Extraction happens once, at
    the edge, so a shape change upstream breaks in one place rather than eight.

    Every field is ``None``-able on purpose. ``None`` means *we do not know*,
    which is materially different from a value, and each predicate is required
    to treat it as INDETERMINATE rather than assume.
    """

    amount_paise: int | None = None
    currency: str | None = None
    category: str | None = None
    afa_performed: bool | None = None
    afa_at_registration: bool | None = None
    pre_debit_notice_at: datetime | None = None
    execution_at: datetime | None = None
    mandate_valid_from: datetime | None = None
    mandate_valid_until: datetime | None = None

    def __post_init__(self) -> None:
        if self.amount_paise is not None and self.amount_paise < 0:
            raise ValueError("amount_paise must be non-negative")
        for name in ("pre_debit_notice_at", "execution_at",
                     "mandate_valid_from", "mandate_valid_until"):
            value: datetime | None = getattr(self, name)
            if value is not None and value.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware")


def _rupees(paise: int) -> str:
    return f"INR {paise / 100:,.2f}"


def _obligation(
    spec: ObligationSpec,
    status: ObligationStatus,
    detail: str,
    *,
    observed: Any = None,
    expected: Any = None,
) -> Obligation:
    return Obligation(
        id=spec.id,
        status=status,
        source=spec.source,
        detail=detail,
        observed=observed,
        expected=expected,
        citation=spec.citation,
    )


def _unknown(spec: ObligationSpec, what: str) -> Obligation:
    """The standard INDETERMINATE result. Absence is never compliance."""
    return _obligation(
        spec,
        ObligationStatus.INDETERMINATE,
        f"Cannot evaluate: {what} was not supplied. Absence of evidence is not "
        f"evidence of compliance.",
        expected="evidence supplied",
    )


# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------


def afa_threshold(spec: ObligationSpec, facts: PaymentFacts) -> Obligation:
    """Above the AFA-free ceiling, AFA evidence is required.

    The enhanced ceiling for specified categories is handled by
    :func:`category_ceiling`; this predicate applies the standard one.
    """
    ceiling = int(spec.require("ceiling_paise"))
    if facts.amount_paise is None:
        return _unknown(spec, "transaction amount")

    if facts.amount_paise <= ceiling:
        return _obligation(
            spec,
            ObligationStatus.SATISFIED,
            f"{_rupees(facts.amount_paise)} is within the AFA-free ceiling of "
            f"{_rupees(ceiling)}.",
            observed={"amount_paise": facts.amount_paise},
            expected={"ceiling_paise": ceiling},
        )

    if facts.afa_performed is None:
        return _obligation(
            spec,
            ObligationStatus.INDETERMINATE,
            f"{_rupees(facts.amount_paise)} exceeds the AFA-free ceiling of "
            f"{_rupees(ceiling)} and no AFA evidence was supplied.",
            observed={"amount_paise": facts.amount_paise, "afa_performed": None},
            expected={"ceiling_paise": ceiling, "afa_performed": True},
        )

    if facts.afa_performed:
        return _obligation(
            spec,
            ObligationStatus.SATISFIED,
            f"{_rupees(facts.amount_paise)} exceeds the AFA-free ceiling but AFA "
            f"was performed.",
            observed={"amount_paise": facts.amount_paise, "afa_performed": True},
            expected={"ceiling_paise": ceiling},
        )

    return _obligation(
        spec,
        ObligationStatus.VIOLATED,
        f"{_rupees(facts.amount_paise)} exceeds the AFA-free ceiling of "
        f"{_rupees(ceiling)} and AFA was not performed.",
        observed={"amount_paise": facts.amount_paise, "afa_performed": False},
        expected={"ceiling_paise": ceiling, "afa_performed": True},
    )


def category_ceiling(spec: ObligationSpec, facts: PaymentFacts) -> Obligation:
    """Specified categories carry an enhanced AFA-free ceiling."""
    enhanced = int(spec.require("enhanced_ceiling_paise"))
    categories = {str(c) for c in spec.require("enhanced_categories")}

    if facts.category is None:
        return _unknown(spec, "transaction category")
    if facts.category not in categories:
        return _obligation(
            spec,
            ObligationStatus.NOT_APPLICABLE,
            f"Category {facts.category!r} is not one of the specified categories "
            f"carrying an enhanced ceiling.",
            observed={"category": facts.category},
            expected={"enhanced_categories": sorted(categories)},
        )
    if facts.amount_paise is None:
        return _unknown(spec, "transaction amount")

    if facts.amount_paise <= enhanced:
        return _obligation(
            spec,
            ObligationStatus.SATISFIED,
            f"{_rupees(facts.amount_paise)} is within the enhanced ceiling of "
            f"{_rupees(enhanced)} for category {facts.category!r}.",
            observed={"amount_paise": facts.amount_paise, "category": facts.category},
            expected={"enhanced_ceiling_paise": enhanced},
        )

    if facts.afa_performed:
        return _obligation(
            spec,
            ObligationStatus.SATISFIED,
            f"{_rupees(facts.amount_paise)} exceeds the enhanced ceiling but AFA "
            f"was performed.",
            observed={"amount_paise": facts.amount_paise, "afa_performed": True},
            expected={"enhanced_ceiling_paise": enhanced},
        )

    return _obligation(
        spec,
        ObligationStatus.VIOLATED,
        f"{_rupees(facts.amount_paise)} exceeds the enhanced ceiling of "
        f"{_rupees(enhanced)} for category {facts.category!r} without AFA.",
        observed={"amount_paise": facts.amount_paise, "category": facts.category},
        expected={"enhanced_ceiling_paise": enhanced, "afa_performed": True},
    )


def pre_debit_notice(spec: ObligationSpec, facts: PaymentFacts) -> Obligation:
    """A pre-transaction notification must precede the debit by 24 hours."""
    minimum_hours = float(spec.require("minimum_notice_hours"))

    if facts.pre_debit_notice_at is None:
        return _unknown(spec, "pre-debit notification timestamp")
    if facts.execution_at is None:
        return _unknown(spec, "execution timestamp")

    delta_hours = (
        facts.execution_at - facts.pre_debit_notice_at
    ).total_seconds() / SECONDS_PER_HOUR
    observed = {
        "notice_at": facts.pre_debit_notice_at.astimezone(UTC).isoformat(),
        "execution_at": facts.execution_at.astimezone(UTC).isoformat(),
        "notice_hours": round(delta_hours, 2),
    }

    if delta_hours < 0:
        return _obligation(
            spec,
            ObligationStatus.VIOLATED,
            "The pre-debit notification is timestamped after the debit.",
            observed=observed,
            expected={"minimum_notice_hours": minimum_hours},
        )
    if delta_hours + 1e-9 < minimum_hours:
        return _obligation(
            spec,
            ObligationStatus.VIOLATED,
            f"Notice given {delta_hours:.1f}h before the debit; the framework "
            f"requires at least {minimum_hours:.0f}h.",
            observed=observed,
            expected={"minimum_notice_hours": minimum_hours},
        )
    return _obligation(
        spec,
        ObligationStatus.SATISFIED,
        f"Notice given {delta_hours:.1f}h before the debit, meeting the "
        f"{minimum_hours:.0f}h requirement.",
        observed=observed,
        expected={"minimum_notice_hours": minimum_hours},
    )


def mandate_registered_with_afa(
    spec: ObligationSpec, facts: PaymentFacts
) -> Obligation:
    """Registration of the e-mandate itself required AFA."""
    if facts.afa_at_registration is None:
        return _unknown(spec, "AFA-at-registration evidence")
    if facts.afa_at_registration:
        return _obligation(
            spec,
            ObligationStatus.SATISFIED,
            "The e-mandate was registered with Additional Factor Authentication.",
            observed={"afa_at_registration": True},
        )
    return _obligation(
        spec,
        ObligationStatus.VIOLATED,
        "The e-mandate was not registered with AFA, so it is not a valid basis "
        "for an agent-initiated debit.",
        observed={"afa_at_registration": False},
        expected={"afa_at_registration": True},
    )


def validity_window(spec: ObligationSpec, facts: PaymentFacts) -> Obligation:
    """The debit must fall inside the mandate's specified validity period."""
    if facts.execution_at is None:
        return _unknown(spec, "execution timestamp")
    if facts.mandate_valid_from is None or facts.mandate_valid_until is None:
        return _unknown(spec, "mandate validity window")

    observed = {
        "execution_at": facts.execution_at.astimezone(UTC).isoformat(),
        "valid_from": facts.mandate_valid_from.astimezone(UTC).isoformat(),
        "valid_until": facts.mandate_valid_until.astimezone(UTC).isoformat(),
    }
    if facts.mandate_valid_until < facts.mandate_valid_from:
        return _obligation(
            spec,
            ObligationStatus.VIOLATED,
            "The mandate's validity window is inverted; it cannot authorise "
            "anything.",
            observed=observed,
        )
    if facts.execution_at < facts.mandate_valid_from:
        return _obligation(
            spec,
            ObligationStatus.VIOLATED,
            "The debit precedes the start of the mandate's validity period.",
            observed=observed,
        )
    if facts.execution_at > facts.mandate_valid_until:
        return _obligation(
            spec,
            ObligationStatus.VIOLATED,
            "The debit falls after the mandate's validity period expired.",
            observed=observed,
        )
    return _obligation(
        spec,
        ObligationStatus.SATISFIED,
        "The debit falls inside the mandate's specified validity period.",
        observed=observed,
    )


#: Predicate registry, keyed by obligation id. The policy declares which run.
PREDICATES: Final[dict[str, Any]] = {
    "rbi.afa_threshold": afa_threshold,
    "rbi.category_ceiling": category_ceiling,
    "rbi.pre_debit_notice": pre_debit_notice,
    "rbi.mandate_registered_with_afa": mandate_registered_with_afa,
    "rbi.validity_window": validity_window,
}


def evaluate(
    specs: tuple[ObligationSpec, ...], facts: PaymentFacts
) -> tuple[Obligation, ...]:
    """Run every declared RBI predicate.

    A declared obligation with no registered predicate yields INDETERMINATE
    rather than being skipped -- a policy naming a rule the engine cannot
    evaluate is a gap, and gaps reject.
    """
    results: list[Obligation] = []
    for spec in specs:
        predicate = PREDICATES.get(spec.id)
        if predicate is None:
            results.append(
                _obligation(
                    spec,
                    ObligationStatus.INDETERMINATE,
                    f"Policy declares {spec.id!r} but no predicate is registered "
                    f"to evaluate it.",
                    expected="a registered predicate",
                )
            )
            continue
        results.append(predicate(spec, facts))
    return tuple(results)
