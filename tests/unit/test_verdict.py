"""Invariants of the canonical verdict types.

These tests are deliberately adversarial about the fail-closed properties.
The upstream failure mode we are defending against is subtle: a system that
finds "no violations" because it never evaluated anything. Several tests
below exist purely to make that state unrepresentable.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from pramana.kernel.verdict import (
    Decision,
    Obligation,
    ObligationSource,
    ObligationStatus,
    Verdict,
)

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
POLICY = "test-policy@1"


def _ob(
    status: ObligationStatus,
    ident: str = "test.check",
    source: ObligationSource = ObligationSource.MANDATE,
) -> Obligation:
    return Obligation(id=ident, status=status, source=source, detail="test detail")


def _verdict(*obligations: Obligation) -> Verdict:
    return Verdict(
        obligations=list(obligations), policy_version=POLICY, trace_id=TRACE
    )


# ---------------------------------------------------------------------------
# Fail-closed: the core safety property
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_all_satisfied_allows(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"), _ob(ObligationStatus.SATISFIED, "b")
        )
        assert v.decision is Decision.ALLOW
        assert v.is_allowed

    def test_single_violation_rejects(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"), _ob(ObligationStatus.VIOLATED, "b")
        )
        assert v.decision is Decision.REJECT

    def test_indeterminate_rejects_exactly_as_hard_as_violated(self) -> None:
        """The central claim of ADR-0003.

        An obligation we could not evaluate must block. If this ever passes
        as ALLOW, a stripped constraint disclosure becomes an accepted payment.
        """
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"),
            _ob(ObligationStatus.INDETERMINATE, "b"),
        )
        assert v.decision is Decision.REJECT

    def test_not_applicable_does_not_block(self) -> None:
        """NOT_APPLICABLE is a genuine 'this rule does not govern this case',
        which is different from 'we could not tell'."""
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"),
            _ob(ObligationStatus.NOT_APPLICABLE, "b"),
        )
        assert v.decision is Decision.ALLOW

    def test_empty_obligation_set_is_unrepresentable(self) -> None:
        """A verdict that checked nothing must not be constructible.

        Without this guard, `all(...)` over an empty sequence returns True and
        an unchecked payment would be ALLOWed.
        """
        with pytest.raises(ValueError, match="at least one obligation"):
            Verdict(obligations=[], policy_version=POLICY, trace_id=TRACE)

    def test_decision_cannot_be_assigned(self) -> None:
        """ALLOW must be earned from the obligation set, never asserted."""
        v = _verdict(_ob(ObligationStatus.VIOLATED))
        with pytest.raises((AttributeError, TypeError)):
            v.decision = Decision.ALLOW  # type: ignore[misc]

    @pytest.mark.parametrize(
        ("status", "blocking"),
        [
            (ObligationStatus.SATISFIED, False),
            (ObligationStatus.NOT_APPLICABLE, False),
            (ObligationStatus.VIOLATED, True),
            (ObligationStatus.INDETERMINATE, True),
        ],
    )
    def test_is_blocking_matrix(
        self, status: ObligationStatus, blocking: bool
    ) -> None:
        assert status.is_blocking is blocking


# ---------------------------------------------------------------------------
# Immutability -- verdicts are hash-chained, so mutation would break the ledger
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_verdict_is_frozen(self) -> None:
        v = _verdict(_ob(ObligationStatus.SATISFIED))
        with pytest.raises((AttributeError, TypeError)):
            v.policy_version = "tampered"  # type: ignore[misc]

    def test_obligation_is_frozen(self) -> None:
        o = _ob(ObligationStatus.SATISFIED)
        with pytest.raises((AttributeError, TypeError)):
            o.status = ObligationStatus.VIOLATED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Required fields -- an unattributable verdict is not evidence
# ---------------------------------------------------------------------------


class TestRequiredFields:
    def test_policy_version_required(self) -> None:
        with pytest.raises(ValueError, match="policy_version"):
            Verdict(
                obligations=[_ob(ObligationStatus.SATISFIED)],
                policy_version="",
                trace_id=TRACE,
            )

    def test_trace_id_required(self) -> None:
        with pytest.raises(ValueError, match="trace_id"):
            Verdict(
                obligations=[_ob(ObligationStatus.SATISFIED)],
                policy_version=POLICY,
                trace_id="",
            )

    def test_naive_datetime_rejected(self) -> None:
        """Timezone-naive timestamps are ambiguous in an audit record."""
        with pytest.raises(ValueError, match="timezone-aware"):
            Verdict(
                obligations=[_ob(ObligationStatus.SATISFIED)],
                policy_version=POLICY,
                trace_id=TRACE,
                evaluated_at=datetime(2026, 8, 23, 12, 0, 0),  # noqa: DTZ001
            )

    def test_obligation_requires_id_and_detail(self) -> None:
        with pytest.raises(ValueError, match="id must be non-empty"):
            Obligation(
                id="",
                status=ObligationStatus.SATISFIED,
                source=ObligationSource.MANDATE,
                detail="x",
            )
        with pytest.raises(ValueError, match="detail string"):
            Obligation(
                id="a.b",
                status=ObligationStatus.SATISFIED,
                source=ObligationSource.MANDATE,
                detail="",
            )


# ---------------------------------------------------------------------------
# Canonical serialization -- third parties must be able to re-verify the chain
# ---------------------------------------------------------------------------


class TestCanonicalSerialization:
    def test_is_deterministic(self) -> None:
        ts = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
        args = {
            "obligations": [_ob(ObligationStatus.SATISFIED)],
            "policy_version": POLICY,
            "trace_id": TRACE,
            "evaluated_at": ts,
        }
        assert Verdict(**args).canonical_bytes() == Verdict(**args).canonical_bytes()  # type: ignore[arg-type]

    def test_keys_are_sorted_and_compact(self) -> None:
        v = _verdict(_ob(ObligationStatus.SATISFIED))
        raw = v.canonical_bytes().decode()
        assert ", " not in raw and '": ' not in raw, "must be compact"
        parsed = json.loads(raw)
        assert list(parsed) == sorted(parsed), "keys must be sorted"

    def test_content_hash_changes_when_status_changes(self) -> None:
        ts = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
        base = Verdict(
            obligations=[_ob(ObligationStatus.SATISFIED)],
            policy_version=POLICY,
            trace_id=TRACE,
            evaluated_at=ts,
        )
        tampered = Verdict(
            obligations=[_ob(ObligationStatus.VIOLATED)],
            policy_version=POLICY,
            trace_id=TRACE,
            evaluated_at=ts,
        )
        assert base.content_hash() != tampered.content_hash()

    def test_content_hash_is_sha256_hex(self) -> None:
        h = _verdict(_ob(ObligationStatus.SATISFIED)).content_hash()
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# Blocking-obligation reporting -- the demo prints this
# ---------------------------------------------------------------------------


class TestBlockingReport:
    def test_blocking_preserves_evaluation_order(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.VIOLATED, "first"),
            _ob(ObligationStatus.SATISFIED, "second"),
            _ob(ObligationStatus.INDETERMINATE, "third"),
        )
        assert [o.id for o in v.blocking] == ["first", "third"]

    def test_blocking_empty_when_allowed(self) -> None:
        assert _verdict(_ob(ObligationStatus.SATISFIED)).blocking == ()

    def test_source_is_recorded_per_obligation(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.VIOLATED, "r", ObligationSource.REGULATORY),
        )
        assert v.blocking[0].source is ObligationSource.REGULATORY
