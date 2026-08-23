"""The kernel facade: one entry point, full trace, evidence or no decision.

Three properties matter here and each has its own section:

* **Centralisation.** There is no way to obtain a verdict without also
  producing its trace and its ledger record.
* **Traceability.** An inbound W3C traceparent is continued, not discarded, and
  every pipeline step appears as a span under the same trace id.
* **Fail closed everywhere.** A crashing predicate group and an unwritable
  ledger both reject. Neither can produce an allow.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from pramana.kernel.gate import (
    LEDGER_OBLIGATION_ID,
    Kernel,
    PaymentRequest,
)
from pramana.kernel.ledger.chain_log import (
    EvidenceLedger,
    JsonlStore,
    LedgerStore,
    MemoryStore,
)
from pramana.kernel.risk.signals import RiskBand, RiskSignal
from pramana.kernel.verdict import (
    Decision,
    Obligation,
    ObligationSource,
    ObligationStatus,
)
from pramana.kernel.verify.policy import builtin_policy
from pramana.kernel.verify.rbi import PaymentFacts

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
REF = hashlib.sha256(b"mandate").hexdigest()
INBOUND = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

POLICY = builtin_policy()


def ob(
    ident: str,
    status: ObligationStatus = ObligationStatus.SATISFIED,
    source: ObligationSource = ObligationSource.PROTOCOL,
) -> Obligation:
    return Obligation(id=ident, status=status, source=source, detail=f"{ident} ran")


def good_facts(**overrides: Any) -> PaymentFacts:
    base: dict[str, Any] = {
        "amount_paise": 500_000,
        "category": "groceries",
        "afa_performed": False,
        "afa_at_registration": True,
        "pre_debit_notice_at": NOW - timedelta(hours=30),
        "execution_at": NOW,
        "mandate_valid_from": NOW - timedelta(days=30),
        "mandate_valid_until": NOW + timedelta(days=30),
    }
    base.update(overrides)
    return PaymentFacts(**base)


def request(**overrides: Any) -> PaymentRequest:
    base: dict[str, Any] = {
        "mandate_ref": REF,
        "facts": good_facts(),
        "protocol_results": tuple(
            ob(i)
            for i in (
                "chain.verified",
                "chain.nonce_fresh",
                "chain.disclosures_pinned",
            )
        ),
        "mandate_results": tuple(
            ob(i, source=ObligationSource.MANDATE)
            for i in ("mandate.budget", "mandate.payee_in_scope", "mandate.not_expired")
        ),
        "merchant_results": (
            ob("merchant.category_allowed", source=ObligationSource.MERCHANT),
        ),
    }
    base.update(overrides)
    return PaymentRequest(**base)


def kernel(**kw: Any) -> Kernel:
    kw.setdefault("ledger", EvidenceLedger(MemoryStore()))
    return Kernel(POLICY, **kw)


class BoomStore:
    """A ledger store that cannot be written."""

    def append(self, record: Any) -> None:
        raise OSError("disk full")

    def read_all(self) -> Any:
        return iter(())

    def last(self) -> None:
        return None

    def count(self) -> int:
        return 0


class FixedRisk:
    def __init__(self, band: RiskBand, name: str = "vulcan") -> None:
        self.name = name
        self._band = band

    def assess(self, context: dict[str, Any]) -> RiskSignal:
        return RiskSignal(provider=self.name, band=self._band, rationale="test")


class ExplodingRisk:
    name = "broken"

    def assess(self, context: dict[str, Any]) -> RiskSignal:
        raise RuntimeError("scorer down")


# ---------------------------------------------------------------------------
# Centralisation
# ---------------------------------------------------------------------------


class TestCentralisation:
    def test_a_clean_request_is_allowed(self) -> None:
        assert kernel().evaluate(request()).verdict.decision is Decision.ALLOW

    def test_every_decision_carries_a_verdict_trace_and_record(self) -> None:
        """There is no path to a decision without its evidence."""
        result = kernel().evaluate(request())
        assert result.verdict is not None
        assert result.trace.trace_id
        assert result.record is not None
        assert result.spans

    def test_coverage_is_enforced_against_the_policy(self) -> None:
        """Drop one protocol result; the policy still declared it."""
        result = kernel().evaluate(
            request(protocol_results=(ob("chain.verified"),))
        )
        assert result.verdict.decision is Decision.REJECT
        missing = {o.id for o in result.verdict.blocking}
        assert "chain.nonce_fresh" in missing
        assert "chain.disclosures_pinned" in missing

    def test_policy_version_is_stamped(self) -> None:
        assert kernel().evaluate(request()).verdict.policy_version == "rbi-in@1"

    def test_result_serialises_whole(self) -> None:
        payload = json.loads(json.dumps(kernel().evaluate(request()).to_dict()))
        assert payload["verdict"]["decision"] == "allow"
        assert payload["record_hash"]
        assert payload["spans"]


# ---------------------------------------------------------------------------
# Traceability
# ---------------------------------------------------------------------------


class TestTraceability:
    def test_inbound_traceparent_is_continued_not_discarded(self) -> None:
        result = kernel().evaluate(request(traceparent=INBOUND))
        assert result.trace.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert result.trace.parent_span_id == "00f067aa0ba902b7"

    def test_verdict_and_record_share_the_inbound_trace_id(self) -> None:
        result = kernel().evaluate(request(traceparent=INBOUND))
        assert result.verdict.trace_id == result.trace.trace_id
        assert result.record is not None
        assert result.record.trace_id == result.trace.trace_id

    def test_a_malformed_traceparent_starts_a_fresh_trace(self) -> None:
        """Losing correlation is bad; refusing a payment over it is worse."""
        result = kernel().evaluate(request(traceparent="garbage"))
        assert result.verdict.decision is Decision.ALLOW
        assert len(result.trace.trace_id) == 32

    def test_no_traceparent_starts_a_fresh_trace(self) -> None:
        result = kernel().evaluate(request())
        assert len(result.trace.trace_id) == 32
        assert result.trace.parent_span_id is None

    def test_every_pipeline_step_is_a_span_under_one_trace(self) -> None:
        result = kernel().evaluate(request(traceparent=INBOUND))
        operations = [s["operation"] for s in result.spans]
        assert operations == [
            "predicates:protocol",
            "predicates:mandate",
            "predicates:merchant",
            "predicates:regulatory",
            "predicates:risk.advisory",
            "ledger.append",
        ]
        assert {s["trace_id"] for s in result.spans} == {result.trace.trace_id}

    def test_spans_are_children_of_the_root(self) -> None:
        result = kernel().evaluate(request())
        assert all(
            s["parent_span_id"] == result.trace.span_id for s in result.spans
        )

    def test_spans_carry_latency(self) -> None:
        result = kernel().evaluate(request())
        assert all(s["duration_ms"] >= 0 for s in result.spans)
        assert result.elapsed_ms >= 0

    def test_blocking_steps_are_marked_in_the_span_outcome(self) -> None:
        result = kernel().evaluate(
            request(facts=good_facts(amount_paise=2_000_000))
        )
        regulatory = next(
            s for s in result.spans if s["operation"] == "predicates:regulatory"
        )
        assert regulatory["outcome"] == "blocked"


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_a_ledger_write_failure_rejects(self) -> None:
        """An authorisation that cannot be evidenced is not granted."""
        store: LedgerStore = BoomStore()  # type: ignore[assignment]
        result = Kernel(POLICY, ledger=EvidenceLedger(store)).evaluate(request())
        assert result.verdict.decision is Decision.REJECT
        blocked = {o.id for o in result.verdict.blocking}
        assert LEDGER_OBLIGATION_ID in blocked
        assert result.record is None

    def test_the_ledger_failure_is_indeterminate_not_violated(self) -> None:
        store: LedgerStore = BoomStore()  # type: ignore[assignment]
        result = Kernel(POLICY, ledger=EvidenceLedger(store)).evaluate(request())
        ledger_ob = next(
            o for o in result.verdict.obligations if o.id == LEDGER_OBLIGATION_ID
        )
        assert ledger_ob.status is ObligationStatus.INDETERMINATE

    def test_a_crashing_predicate_group_rejects(self) -> None:
        class Exploding(tuple):  # type: ignore[type-arg]
            def __iter__(self) -> Any:
                raise RuntimeError("predicate blew up")

        result = kernel().evaluate(request(protocol_results=Exploding()))
        assert result.verdict.decision is Decision.REJECT

    def test_regulatory_violation_rejects(self) -> None:
        result = kernel().evaluate(
            request(facts=good_facts(amount_paise=2_000_000))
        )
        assert result.verdict.decision is Decision.REJECT
        assert "rbi.afa_threshold" in {o.id for o in result.verdict.blocking}

    def test_missing_evidence_rejects(self) -> None:
        result = kernel().evaluate(request(facts=PaymentFacts()))
        assert result.verdict.decision is Decision.REJECT
        assert all(
            o.status is ObligationStatus.INDETERMINATE
            for o in result.verdict.blocking
            if o.id.startswith("rbi.")
        )

    def test_a_rejected_decision_is_still_recorded(self) -> None:
        """Rejections are evidence too."""
        ledger = EvidenceLedger(MemoryStore())
        Kernel(POLICY, ledger=ledger).evaluate(
            request(facts=good_facts(amount_paise=2_000_000))
        )
        assert len(ledger) == 1

    def test_running_without_a_ledger_still_decides(self) -> None:
        result = Kernel(POLICY, ledger=None).evaluate(request())
        assert result.verdict.decision is Decision.ALLOW
        assert result.record is None


# ---------------------------------------------------------------------------
# Advisory risk composition
# ---------------------------------------------------------------------------


class TestAdvisoryRisk:
    def test_low_risk_does_not_authorise_a_failing_payment(self) -> None:
        result = Kernel(
            POLICY,
            ledger=EvidenceLedger(MemoryStore()),
            risk_adapters=(FixedRisk(RiskBand.LOW),),
        ).evaluate(request(facts=good_facts(amount_paise=2_000_000)))
        assert result.verdict.decision is Decision.REJECT

    def test_high_risk_blocks_an_otherwise_clean_payment(self) -> None:
        result = Kernel(
            POLICY,
            ledger=EvidenceLedger(MemoryStore()),
            risk_adapters=(FixedRisk(RiskBand.HIGH),),
        ).evaluate(request())
        assert result.verdict.decision is Decision.REJECT
        assert any(
            o.source is ObligationSource.RISK for o in result.verdict.blocking
        )

    def test_a_broken_scorer_does_not_block(self) -> None:
        """A fraud model must not become an outage on checkout."""
        result = Kernel(
            POLICY,
            ledger=EvidenceLedger(MemoryStore()),
            risk_adapters=(ExplodingRisk(),),
        ).evaluate(request())
        assert result.verdict.decision is Decision.ALLOW

    def test_advisory_ids_are_not_part_of_declared_coverage(self) -> None:
        result = Kernel(
            POLICY,
            ledger=EvidenceLedger(MemoryStore()),
            risk_adapters=(FixedRisk(RiskBand.LOW),),
        ).evaluate(request())
        assert result.verdict.coverage == 1.0


# ---------------------------------------------------------------------------
# Persistence across restarts
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_chain_survives_a_reopen_and_verifies(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        k = Kernel(POLICY, ledger=EvidenceLedger(JsonlStore(path)))
        k.evaluate(request())
        k.evaluate(request(facts=good_facts(amount_paise=2_000_000)))

        reopened = EvidenceLedger(JsonlStore(path))
        assert reopened.verify() == 2
        assert [r.decision for r in reopened.records()] == ["allow", "reject"]

    def test_records_are_queryable_by_mandate(self, tmp_path: Path) -> None:
        ledger = EvidenceLedger(JsonlStore(tmp_path / "l.jsonl"))
        Kernel(POLICY, ledger=ledger).evaluate(request())
        assert len(ledger.for_mandate(REF)) == 1


# ---------------------------------------------------------------------------
# Latency -- a dimension where determinism wins outright
# ---------------------------------------------------------------------------


class TestLatency:
    def test_regulatory_predicates_are_sub_millisecond(self) -> None:
        result = Kernel(POLICY, ledger=None).evaluate(request())
        regulatory = next(
            s for s in result.spans if s["operation"] == "predicates:regulatory"
        )
        assert regulatory["duration_ms"] < 5.0

    @pytest.mark.parametrize("_run", range(3))
    def test_whole_decision_without_a_ledger_is_fast(self, _run: int) -> None:
        result = Kernel(POLICY, ledger=None).evaluate(request())
        assert result.elapsed_ms < 25.0
