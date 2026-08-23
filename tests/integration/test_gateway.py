"""The HTTP gate.

The property that matters most here is the status-code mapping: an integrator
who checks only ``response.ok`` and never reads the body must still fail
closed. Several tests below exist purely to pin that.

The rest verify that the gate contains no decision logic of its own -- the same
request through the API and through the kernel must produce the same verdict.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from pramana.gateway.app import create_app
from pramana.kernel.gate import Kernel, PaymentRequest
from pramana.kernel.ledger.chain_log import EvidenceLedger, MemoryStore
from pramana.kernel.risk.signals import RiskBand, RiskSignal
from pramana.kernel.verify.policy import builtin_policy
from pramana.kernel.verify.rbi import PaymentFacts

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
REF = hashlib.sha256(b"mandate").hexdigest()
INBOUND = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
POLICY = builtin_policy()


class FixedRisk:
    def __init__(self, band: RiskBand) -> None:
        self.name = "vulcan"
        self._band = band

    def assess(self, context: dict[str, Any]) -> RiskSignal:
        return RiskSignal(provider=self.name, band=self._band, rationale="test")


def client(**kw: Any) -> TestClient:
    kw.setdefault("ledger", EvidenceLedger(MemoryStore()))
    return TestClient(create_app(Kernel(POLICY, **kw)), raise_server_exceptions=False)


def ob(ident: str, source: str, status: str = "satisfied") -> dict[str, Any]:
    return {
        "id": ident,
        "status": status,
        "source": source,
        "detail": f"{ident} evaluated",
    }


def body(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "mandate_ref": REF,
        "facts": {
            "amount_paise": 500_000,
            "currency": "INR",
            "category": "groceries",
            "afa_performed": False,
            "afa_at_registration": True,
            "pre_debit_notice_at": (NOW - timedelta(hours=30)).isoformat(),
            "execution_at": NOW.isoformat(),
            "mandate_valid_from": (NOW - timedelta(days=30)).isoformat(),
            "mandate_valid_until": (NOW + timedelta(days=30)).isoformat(),
        },
        "protocol_obligations": [
            ob(i, "protocol")
            for i in ("chain.verified", "chain.nonce_fresh", "chain.disclosures_pinned")
        ],
        "mandate_obligations": [
            ob(i, "mandate")
            for i in ("mandate.budget", "mandate.payee_in_scope", "mandate.not_expired")
        ],
        "merchant_obligations": [ob("merchant.category_allowed", "merchant")],
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# Status codes fail closed -- the point of the design
# ---------------------------------------------------------------------------


class TestFailClosedStatusCodes:
    def test_allow_is_200(self) -> None:
        assert client().post("/v1/evaluate", json=body()).status_code == 200

    def test_reject_is_403_not_200(self) -> None:
        """A status-only integration must not read a rejection as success."""
        response = client().post(
            "/v1/evaluate",
            json=body(facts={**body()["facts"], "amount_paise": 2_000_000}),
        )
        assert response.status_code == 403
        assert response.json()["decision"] == "reject"

    def test_response_ok_tracks_the_decision_exactly(self) -> None:
        c = client()
        allowed = c.post("/v1/evaluate", json=body())
        rejected = c.post(
            "/v1/evaluate",
            json=body(mandate_obligations=[ob("mandate.budget", "mandate")]),
        )
        # httpx exposes is_success, not requests-style .ok
        assert allowed.is_success is True
        assert rejected.is_success is False

    def test_malformed_request_carries_no_decision_field(self) -> None:
        """Nothing for a careless caller to misread as permission."""
        response = client().post("/v1/evaluate", json={"mandate_ref": "not-a-hash"})
        assert response.status_code == 400
        assert "decision" not in response.json()

    def test_internal_error_carries_no_decision_field(self) -> None:
        class Exploding:
            policy = POLICY
            ledger = None
            risk_adapters = ()

            def evaluate(self, _request: PaymentRequest) -> Any:
                raise RuntimeError("kernel exploded")

        app = create_app(Exploding())  # type: ignore[arg-type]
        response = TestClient(app, raise_server_exceptions=False).post(
            "/v1/evaluate", json=body()
        )
        assert response.status_code == 500
        assert "decision" not in response.json()

    def test_internal_error_does_not_leak_the_exception(self) -> None:
        class Exploding:
            policy = POLICY
            ledger = None
            risk_adapters = ()

            def evaluate(self, _request: PaymentRequest) -> Any:
                raise RuntimeError("secret internal detail")

        app = create_app(Exploding())  # type: ignore[arg-type]
        payload = TestClient(app, raise_server_exceptions=False).post(
            "/v1/evaluate", json=body()
        ).json()
        assert "secret internal detail" not in str(payload)
        assert "Incident" in payload["detail"]


# ---------------------------------------------------------------------------
# The gate holds no decision logic of its own
# ---------------------------------------------------------------------------


class TestNoDuplicateLogic:
    def test_api_and_kernel_agree(self) -> None:
        ledger = EvidenceLedger(MemoryStore())
        kernel = Kernel(POLICY, ledger=ledger)
        direct = kernel.evaluate(
            PaymentRequest(
                mandate_ref=REF,
                facts=PaymentFacts(
                    amount_paise=2_000_000,
                    category="groceries",
                    afa_performed=False,
                    afa_at_registration=True,
                    pre_debit_notice_at=NOW - timedelta(hours=30),
                    execution_at=NOW,
                    mandate_valid_from=NOW - timedelta(days=30),
                    mandate_valid_until=NOW + timedelta(days=30),
                ),
            )
        )
        via_http = client().post(
            "/v1/evaluate",
            json=body(
                facts={**body()["facts"], "amount_paise": 2_000_000},
                protocol_obligations=[],
                mandate_obligations=[],
                merchant_obligations=[],
            ),
        ).json()
        assert str(direct.verdict.decision) == via_http["decision"]
        assert set(via_http["blocking"]) == {o.id for o in direct.verdict.blocking}

    def test_coverage_is_enforced_over_http(self) -> None:
        response = client().post(
            "/v1/evaluate", json=body(protocol_obligations=[])
        )
        assert response.status_code == 403
        assert "chain.verified" in response.json()["blocking"]

    def test_regulatory_citation_survives_the_wire(self) -> None:
        payload = client().post("/v1/evaluate", json=body()).json()
        cited = [
            o for o in payload["obligations"] if o["id"] == "rbi.afa_threshold"
        ]
        assert cited[0]["citation"]["authority"] == "RBI"
        assert cited[0]["citation"]["effective_from"] == "2026-04-21"

    def test_verdict_hash_is_returned_for_reverification(self) -> None:
        payload = client().post("/v1/evaluate", json=body()).json()
        assert len(payload["verdict_hash"]) == 64
        assert len(payload["record_hash"]) == 64


# ---------------------------------------------------------------------------
# Callers cannot smuggle in an advisory signal
# ---------------------------------------------------------------------------


class TestAdvisoryIsNotCallerSupplied:
    def test_risk_source_is_rejected_at_the_edge(self) -> None:
        """Otherwise a caller could hand us a risk.* obligation of its choosing."""
        response = client().post(
            "/v1/evaluate",
            json=body(
                merchant_obligations=[
                    ob("merchant.category_allowed", "merchant"),
                    ob("risk.vulcan", "risk"),
                ]
            ),
        )
        assert response.status_code == 400

    def test_configured_adapter_can_still_block(self) -> None:
        response = client(risk_adapters=(FixedRisk(RiskBand.HIGH),)).post(
            "/v1/evaluate", json=body()
        )
        assert response.status_code == 403

    def test_low_risk_adapter_does_not_authorise(self) -> None:
        response = client(risk_adapters=(FixedRisk(RiskBand.LOW),)).post(
            "/v1/evaluate", json=body(protocol_obligations=[])
        )
        assert response.status_code == 403


# ---------------------------------------------------------------------------
# Traceability across the wire
# ---------------------------------------------------------------------------


class TestTracePropagation:
    def test_inbound_traceparent_is_continued(self) -> None:
        payload = client().post(
            "/v1/evaluate", json=body(), headers={"traceparent": INBOUND}
        ).json()
        assert payload["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_traceparent_is_echoed_in_the_response_header(self) -> None:
        response = client().post(
            "/v1/evaluate", json=body(), headers={"traceparent": INBOUND}
        )
        assert "4bf92f3577b34da6a3ce929d0e0e4736" in response.headers["traceparent"]

    def test_malformed_traceparent_does_not_fail_the_payment(self) -> None:
        response = client().post(
            "/v1/evaluate", json=body(), headers={"traceparent": "garbage"}
        )
        assert response.status_code == 200
        assert len(response.json()["trace_id"]) == 32

    def test_decision_and_policy_are_exposed_as_headers(self) -> None:
        response = client().post("/v1/evaluate", json=body())
        assert response.headers["x-pramana-decision"] == "allow"
        assert response.headers["x-pramana-policy-version"] == "rbi-in@1"
        assert float(response.headers["x-pramana-elapsed-ms"]) >= 0


# ---------------------------------------------------------------------------
# Validation at the edge
# ---------------------------------------------------------------------------


class TestValidation:
    @pytest.mark.parametrize(
        "bad_ref", ["", "short", "A" * 64, "z" * 64, "not-a-hash"]
    )
    def test_mandate_ref_must_be_a_sha256(self, bad_ref: str) -> None:
        assert client().post(
            "/v1/evaluate", json=body(mandate_ref=bad_ref)
        ).status_code == 400

    def test_naive_timestamp_is_rejected(self) -> None:
        response = client().post(
            "/v1/evaluate",
            json=body(facts={"execution_at": "2026-08-23T12:00:00"}),
        )
        assert response.status_code == 400
        assert "timezone-aware" in response.json()["detail"]

    def test_negative_amount_is_rejected(self) -> None:
        assert client().post(
            "/v1/evaluate", json=body(facts={"amount_paise": -1})
        ).status_code == 400

    def test_unknown_field_is_rejected(self) -> None:
        """extra='forbid' -- a typo must not silently skip a check."""
        assert client().post(
            "/v1/evaluate", json=body(amount_paise=500)
        ).status_code == 400

    def test_omitted_facts_reject_rather_than_skip(self) -> None:
        """Absence is not a way to bypass the regulatory checks."""
        response = client().post("/v1/evaluate", json=body(facts={}))
        assert response.status_code == 403
        assert any(b.startswith("rbi.") for b in response.json()["blocking"])


# ---------------------------------------------------------------------------
# Operational surface
# ---------------------------------------------------------------------------


class TestOperational:
    def test_health_reports_the_policy_in_force(self) -> None:
        payload = client().get("/health").json()
        assert payload["status"] == "ok"
        assert payload["policy_version"] == "rbi-in@1"
        assert payload["declared_obligations"] == 12

    def test_health_counts_ledger_records(self) -> None:
        c = client()
        c.post("/v1/evaluate", json=body())
        assert c.get("/health").json()["ledger_records"] == 1

    def test_policy_is_publicly_readable(self) -> None:
        """A merchant is entitled to read the rules it is held to."""
        payload = client().get("/v1/policy").json()
        assert payload["version"] == "rbi-in@1"
        cited = [
            o for o in payload["obligations"] if o["id"] == "rbi.afa_threshold"
        ]
        assert cited[0]["citation"]["reference"].startswith("Digital Payments")

    def test_openapi_documents_the_403(self) -> None:
        spec = client().get("/openapi.json").json()
        responses = spec["paths"]["/v1/evaluate"]["post"]["responses"]
        assert "403" in responses
