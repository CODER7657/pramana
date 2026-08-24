"""A **mock** Vulcan-class scorer. Named for what it is.

Razorpay's Vulcan is a payments foundation model -- ~3 trillion data points,
~3,000 signals per transaction. This is not that, is not connected to that, and
returns a band this module decided. It exists to make one architectural claim
visible in fifteen seconds instead of readable in three paragraphs:

    **An advisory risk signal can subtract authority. It can never add any.**

A mock presented as an integration would be fatal to a submission positioned on
checkable claims, so the file is called ``vulcan_mock``, the provider string is
``vulcan-mock``, and every rationale it emits says so. The *integration
contract* it implements -- :class:`~pramana.kernel.risk.signals.RiskAdapter` --
is real, and a genuine scorer swaps in by satisfying the same protocol.

What the demo shows
-------------------

The interesting direction is the one nobody tests. Anyone can show a fraud
model blocking a payment. This shows a scorer returning ``LOW`` -- confidently,
with a plausible rationale, on a transaction that is genuinely unremarkable --
and the payment being **refused anyway**, because a deterministic obligation
failed and no score can rescue it.

That is the withheld-cap attack's actual profile: known agent, familiar
merchant, amount inside its own historical range. There is no anomaly to find.
A scorer is *right* to say LOW, and it is still not authorisation.

``to_obligation`` enforces this structurally rather than by convention: it has
exactly two reachable statuses and ``SATISFIED`` is not one of them, so there is
no value this adapter can return that contributes to an ALLOW.
"""

from __future__ import annotations

from typing import Any, Final

from pramana.kernel.risk.signals import RiskBand, RiskSignal

PROVIDER: Final = "vulcan-mock"


class MockVulcanAdapter:
    """Returns a band chosen at construction. Deterministic, offline, honest."""

    name = PROVIDER

    def __init__(
        self,
        band: RiskBand = RiskBand.LOW,
        *,
        score: float | None = None,
        rationale: str | None = None,
        unavailable: bool = False,
    ) -> None:
        # The score defaults to one that agrees with the band. It did not, at
        # first: every band carried 0.02, so a HIGH signal scored 0.02 and
        # to_obligation correctly declined to block on it. A mock whose band
        # and score contradict each other tests nothing, and would have shown
        # a judge a HIGH risk signal sailing through.
        self._band = band
        self._score = _SCORES[band] if score is None else score
        self._rationale = rationale
        self._unavailable = unavailable

    def assess(self, context: dict[str, Any]) -> RiskSignal:
        if self._unavailable:
            # A scorer that is down must not become an outage on checkout.
            return RiskSignal.unavailable(PROVIDER, "mock scorer set unavailable")
        return RiskSignal(
            provider=PROVIDER,
            band=self._band,
            rationale=self._rationale or _RATIONALES[self._band],
            score=self._score,
            signals_considered=2_987,
        )


_SCORES: Final[dict[RiskBand, float | None]] = {
    RiskBand.LOW: 0.02,
    RiskBand.ELEVATED: 0.45,
    RiskBand.HIGH: 0.93,
    RiskBand.UNKNOWN: None,
}

_RATIONALES: Final[dict[RiskBand, str]] = {
    RiskBand.LOW: (
        "MOCK: known agent, familiar merchant, amount inside its own "
        "historical range. Nothing anomalous to report."
    ),
    RiskBand.ELEVATED: (
        "MOCK: velocity above this agent's baseline. Advisory only."
    ),
    RiskBand.HIGH: (
        "MOCK: destination account first seen 40 minutes ago and shares a "
        "device fingerprint with three chargebacks."
    ),
    RiskBand.UNKNOWN: "MOCK: no assessment produced.",
}
