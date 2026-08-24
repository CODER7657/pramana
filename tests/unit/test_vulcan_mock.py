"""The one-way property, exercised through a scorer rather than described.

The claim: an advisory risk signal can subtract authority, never add any. The
interesting direction is the one nobody demonstrates -- not a fraud model
blocking a payment, but a fraud model saying **LOW**, confidently and
correctly, on a payment that is refused anyway.

That is the withheld-cap attack's real profile. Known agent, familiar merchant,
amount inside its own historical range: there is no anomaly to find, so a scorer
is *right* to return LOW. It is still not authorisation.
"""

from __future__ import annotations

from pramana.adapters.vulcan_mock import PROVIDER, MockVulcanAdapter
from pramana.kernel.risk.signals import (
    RiskAdapter,
    RiskBand,
    advisory_obligations,
    to_obligation,
)
from pramana.kernel.verdict import ObligationStatus


class TestItIsARealAdapter:
    def test_it_satisfies_the_published_protocol(self) -> None:
        """A genuine scorer swaps in by satisfying the same protocol."""
        assert isinstance(MockVulcanAdapter(), RiskAdapter)

    def test_it_never_raises_when_unavailable(self) -> None:
        signal = MockVulcanAdapter(unavailable=True).assess({})
        assert signal.band is RiskBand.UNKNOWN


class TestItIsHonestlyLabelled:
    def test_the_provider_string_says_mock(self) -> None:
        """A mock presented as an integration would be fatal. This one isn't."""
        assert "mock" in PROVIDER
        assert MockVulcanAdapter().assess({}).provider == PROVIDER

    def test_every_rationale_says_mock(self) -> None:
        for band in (RiskBand.LOW, RiskBand.ELEVATED, RiskBand.HIGH):
            assert MockVulcanAdapter(band).assess({}).rationale.startswith("MOCK")


class TestItCanOnlySubtractAuthority:
    def test_low_is_not_applicable_never_satisfied(self) -> None:
        """The whole invariant, in one assertion."""
        obligation = to_obligation(MockVulcanAdapter(RiskBand.LOW).assess({}))
        assert obligation.status is ObligationStatus.NOT_APPLICABLE
        assert obligation.status is not ObligationStatus.SATISFIED

    def test_no_band_it_can_return_produces_a_satisfied(self) -> None:
        """Swept exhaustively: there is no input that contributes to an ALLOW."""
        for band in RiskBand:
            signal = MockVulcanAdapter(band).assess({})
            assert to_obligation(signal).status is not ObligationStatus.SATISFIED

    def test_high_blocks(self) -> None:
        obligation = to_obligation(MockVulcanAdapter(RiskBand.HIGH).assess({}))
        assert obligation.status.is_blocking

    def test_the_score_agrees_with_the_band(self) -> None:
        """Every band carried 0.02 at first, so HIGH scored 0.02 and did not
        block -- to_obligation was right and the mock was incoherent. A judge
        would have watched a HIGH risk signal sail through."""
        low = MockVulcanAdapter(RiskBand.LOW).assess({})
        high = MockVulcanAdapter(RiskBand.HIGH).assess({})
        assert low.score is not None and high.score is not None
        assert low.score < high.score

    def test_an_unreachable_scorer_does_not_block(self) -> None:
        """A fraud model must not become an outage on checkout."""
        signal = MockVulcanAdapter(unavailable=True).assess({})
        assert not to_obligation(signal).status.is_blocking

    def test_a_low_signal_adds_nothing_to_an_obligation_set(self) -> None:
        obligations = advisory_obligations((MockVulcanAdapter(RiskBand.LOW),), {})
        assert all(
            o.status is not ObligationStatus.SATISFIED for o in obligations
        )
        assert not any(o.status.is_blocking for o in obligations)
