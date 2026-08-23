"""Advisory risk signals and the one-way property.

The property under test: **an advisory signal can subtract authority but never
add it.** If any input to `to_obligation` ever produces SATISFIED, an external
model could authorise a payment, and the whole determinism argument collapses.

`TestOneWayProperty` sweeps the full input space to prove it cannot.
"""

from __future__ import annotations

import hashlib
import itertools
from typing import Any

import pytest

from pramana.kernel.risk.signals import (
    ADVISORY_PREFIX,
    DEFAULT_BLOCK_THRESHOLD,
    NullRiskAdapter,
    RiskBand,
    RiskSignal,
    advisory_obligations,
    assess_safely,
    to_obligation,
)
from pramana.kernel.verdict import (
    Decision,
    Obligation,
    ObligationSource,
    ObligationStatus,
    build_verdict,
)

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
REF = hashlib.sha256(b"m").hexdigest()


def signal(
    band: RiskBand = RiskBand.LOW,
    score: float | None = None,
    provider: str = "vulcan",
) -> RiskSignal:
    return RiskSignal(
        provider=provider, band=band, rationale="test rationale", score=score
    )


class FixedAdapter:
    def __init__(self, result: Any, name: str = "fixed") -> None:
        self.name = name
        self._result = result

    def assess(self, context: dict[str, Any]) -> Any:
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


# ---------------------------------------------------------------------------
# THE ONE-WAY PROPERTY
# ---------------------------------------------------------------------------


class TestOneWayProperty:
    @pytest.mark.parametrize(
        ("band", "score"),
        list(
            itertools.product(
                list(RiskBand),
                [None, 0.0, 0.01, 0.5, 0.89, 0.9, 0.95, 0.999, 1.0],
            )
        ),
    )
    def test_no_input_ever_produces_satisfied(
        self, band: RiskBand, score: float | None
    ) -> None:
        """Swept exhaustively. SATISFIED must be unreachable."""
        obligation = to_obligation(signal(band, score))
        assert obligation.status is not ObligationStatus.SATISFIED
        assert obligation.status in (
            ObligationStatus.VIOLATED,
            ObligationStatus.NOT_APPLICABLE,
        )

    def test_low_risk_does_not_authorise_anything(self) -> None:
        """A confident 'this is fine' must not satisfy an obligation."""
        obligation = to_obligation(signal(RiskBand.LOW, 0.0))
        assert obligation.status is ObligationStatus.NOT_APPLICABLE
        assert "never grant authority" in obligation.detail

    def test_a_captured_scorer_cannot_authorise_a_payment(self) -> None:
        """Adversary controls the model and returns LOW for everything."""
        deterministic_failure = Obligation(
            id="mandate.budget",
            status=ObligationStatus.VIOLATED,
            source=ObligationSource.MANDATE,
            detail="over cap",
        )
        verdict = build_verdict(
            [
                Obligation(
                    id="chain.verified",
                    status=ObligationStatus.SATISFIED,
                    source=ObligationSource.PROTOCOL,
                    detail="ok",
                ),
                deterministic_failure,
                to_obligation(signal(RiskBand.LOW, 0.0)),
            ],
            policy_version="p@1",
            declared_obligations=("chain.verified", "mandate.budget"),
            trace_id=TRACE,
            mandate_ref=REF,
        )
        assert verdict.decision is Decision.REJECT

    def test_high_risk_can_block_an_otherwise_clean_payment(self) -> None:
        """Subtraction works, which is the whole point of integrating at all."""
        verdict = build_verdict(
            [
                Obligation(
                    id="chain.verified",
                    status=ObligationStatus.SATISFIED,
                    source=ObligationSource.PROTOCOL,
                    detail="ok",
                ),
                to_obligation(signal(RiskBand.HIGH, 0.97)),
            ],
            policy_version="p@1",
            declared_obligations=("chain.verified",),
            trace_id=TRACE,
            mandate_ref=REF,
        )
        assert verdict.decision is Decision.REJECT
        assert verdict.blocking[0].source is ObligationSource.RISK


# ---------------------------------------------------------------------------
# Banding and thresholds
# ---------------------------------------------------------------------------


class TestBanding:
    def test_high_above_threshold_blocks(self) -> None:
        assert (
            to_obligation(signal(RiskBand.HIGH, 0.95)).status
            is ObligationStatus.VIOLATED
        )

    def test_high_below_threshold_does_not_block(self) -> None:
        """Band alone is not enough when the provider gave us a score."""
        assert (
            to_obligation(signal(RiskBand.HIGH, 0.5)).status
            is ObligationStatus.NOT_APPLICABLE
        )

    def test_high_at_exactly_the_threshold_blocks(self) -> None:
        assert (
            to_obligation(signal(RiskBand.HIGH, DEFAULT_BLOCK_THRESHOLD)).status
            is ObligationStatus.VIOLATED
        )

    def test_high_without_a_score_blocks(self) -> None:
        """A provider that bands but does not score is taken at its word."""
        assert (
            to_obligation(signal(RiskBand.HIGH, None)).status
            is ObligationStatus.VIOLATED
        )

    @pytest.mark.parametrize("band", [RiskBand.LOW, RiskBand.ELEVATED])
    def test_non_high_bands_never_block_regardless_of_score(
        self, band: RiskBand
    ) -> None:
        assert (
            to_obligation(signal(band, 0.999)).status
            is ObligationStatus.NOT_APPLICABLE
        )

    def test_custom_threshold_is_respected(self) -> None:
        assert (
            to_obligation(signal(RiskBand.HIGH, 0.6), block_threshold=0.5).status
            is ObligationStatus.VIOLATED
        )

    def test_default_threshold_is_conservative(self) -> None:
        """A false positive here is blocked legitimate GMV."""
        assert DEFAULT_BLOCK_THRESHOLD >= 0.9


# ---------------------------------------------------------------------------
# Unavailability must not block -- the asymmetry with the money path
# ---------------------------------------------------------------------------


class TestUnavailability:
    def test_unknown_band_does_not_block(self) -> None:
        """Advisory absence subtracts nothing, so it cannot reject."""
        obligation = to_obligation(RiskSignal.unavailable("vulcan", "timeout"))
        assert obligation.status is ObligationStatus.NOT_APPLICABLE
        assert obligation.status.is_blocking is False

    def test_unknown_is_not_indeterminate(self) -> None:
        """The deliberate asymmetry: a *required* obligation that cannot be
        evaluated is INDETERMINATE and rejects. An *advisory* one is not."""
        obligation = to_obligation(RiskSignal.unavailable("vulcan", "down"))
        assert obligation.status is not ObligationStatus.INDETERMINATE

    def test_adapter_exception_becomes_unknown_not_a_crash(self) -> None:
        result = assess_safely(
            FixedAdapter(RuntimeError("scorer exploded")), {}
        )
        assert result.band is RiskBand.UNKNOWN
        assert "RuntimeError" in result.rationale

    def test_adapter_returning_garbage_becomes_unknown(self) -> None:
        result = assess_safely(FixedAdapter("not a signal"), {})
        assert result.band is RiskBand.UNKNOWN
        assert "non-signal" in result.rationale

    def test_a_throwing_scorer_cannot_block_a_payment(self) -> None:
        """A broken model must not become a denial-of-service on checkout."""
        obligations = advisory_obligations(
            (FixedAdapter(RuntimeError("boom"), name="vulcan"),), {}
        )
        assert all(not o.status.is_blocking for o in obligations)

    def test_null_adapter_never_blocks(self) -> None:
        obligation = to_obligation(assess_safely(NullRiskAdapter(), {}))
        assert obligation.status is ObligationStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# Multiple adapters
# ---------------------------------------------------------------------------


class TestMultipleAdapters:
    def test_each_adapter_produces_its_own_obligation(self) -> None:
        obligations = advisory_obligations(
            (
                FixedAdapter(signal(RiskBand.LOW, provider="vulcan")),
                FixedAdapter(signal(RiskBand.HIGH, 0.99, provider="internal")),
            ),
            {},
        )
        assert [o.id for o in obligations] == ["risk.vulcan", "risk.internal"]

    def test_one_failing_adapter_does_not_stop_the_others(self) -> None:
        obligations = advisory_obligations(
            (
                FixedAdapter(RuntimeError("down"), name="vulcan"),
                FixedAdapter(signal(RiskBand.HIGH, 0.99, provider="internal")),
            ),
            {},
        )
        assert len(obligations) == 2
        assert obligations[1].status is ObligationStatus.VIOLATED

    def test_no_adapters_yields_no_obligations(self) -> None:
        assert advisory_obligations((), {}) == ()


# ---------------------------------------------------------------------------
# Namespacing and provenance
# ---------------------------------------------------------------------------


class TestNamespacing:
    def test_ids_are_namespaced(self) -> None:
        assert to_obligation(signal(provider="vulcan")).id == "risk.vulcan"

    def test_non_advisory_id_is_rejected(self) -> None:
        """An advisory signal must not be able to masquerade as a mandate check."""
        with pytest.raises(ValueError, match="must start with"):
            to_obligation(signal(), obligation_id="mandate.budget")

    def test_prefix_constant_matches(self) -> None:
        assert to_obligation(signal()).id.startswith(ADVISORY_PREFIX)

    def test_source_is_always_risk(self) -> None:
        for band in RiskBand:
            assert to_obligation(signal(band, 0.99)).source is ObligationSource.RISK

    def test_provenance_is_recorded_for_the_audit_trail(self) -> None:
        obligation = to_obligation(
            RiskSignal(
                provider="vulcan",
                band=RiskBand.HIGH,
                rationale="cross-merchant velocity anomaly",
                score=0.94,
                signals_considered=3000,
            )
        )
        assert obligation.observed == {
            "provider": "vulcan",
            "band": "high",
            "score": 0.94,
            "signals_considered": 3000,
        }
        assert "cross-merchant velocity anomaly" in obligation.detail


# ---------------------------------------------------------------------------
# Signal validation
# ---------------------------------------------------------------------------


class TestSignalValidation:
    @pytest.mark.parametrize("score", [-0.1, 1.1, 2.0, -1.0])
    def test_out_of_range_score_rejected(self, score: float) -> None:
        with pytest.raises(ValueError, match=r"within \[0.0, 1.0\]"):
            RiskSignal(provider="p", band=RiskBand.LOW, rationale="r", score=score)

    def test_provider_required(self) -> None:
        with pytest.raises(ValueError, match="provider"):
            RiskSignal(provider="", band=RiskBand.LOW, rationale="r")

    def test_rationale_required(self) -> None:
        """An unexplained block is not actionable for a merchant."""
        with pytest.raises(ValueError, match="rationale"):
            RiskSignal(provider="p", band=RiskBand.LOW, rationale="")

    def test_signal_is_frozen(self) -> None:
        s = signal()
        with pytest.raises((AttributeError, TypeError)):
            s.band = RiskBand.HIGH  # type: ignore[misc]

    def test_score_is_optional(self) -> None:
        assert RiskSignal(provider="p", band=RiskBand.LOW, rationale="r").score is None
