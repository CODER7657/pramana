"""Wire types for the HTTP gate.

These are the *edge*. They parse and validate what arrives on the network and
convert it into a :class:`~pramana.kernel.gate.PaymentRequest`. The kernel never
sees a Pydantic model and never parses a wire format, so a protocol change
touches this file and nothing else.

Amounts are in **paise** on the wire, matching AP2's ``Amount.amount``. The
field is named ``amount_paise`` rather than ``amount`` on purpose: the unit
ambiguity between AP2's own ``Budget.max`` and ``AmountRange.max`` is the second
finding we reported, and a field called ``amount`` invites exactly that mistake.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from pramana.kernel.gate import GateResult
from pramana.kernel.verdict import Obligation, ObligationSource, ObligationStatus

Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ObligationIn(BaseModel):
    """A check the caller performed at the protocol or mandate layer.

    The caller reports what it evaluated; it does not get to report a decision.
    Statuses are constrained to the enum, so a caller cannot invent one, and
    ``NOT_APPLICABLE`` is accepted but cannot on its own produce an ALLOW --
    the kernel requires at least one ``SATISFIED``.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    status: ObligationStatus
    source: ObligationSource
    detail: str = Field(min_length=1, max_length=1024)
    observed: Any = None
    expected: Any = None

    @field_validator("source")
    @classmethod
    def _reject_advisory(cls, value: ObligationSource) -> ObligationSource:
        """A caller may not submit an advisory risk obligation.

        Advisory signals come from configured adapters inside the kernel, where
        the one-way property is enforced (ADR-0005). Accepting one over the wire
        would let a caller hand us a `risk.*` obligation of its own choosing.
        """
        if value is ObligationSource.RISK:
            raise ValueError(
                "source 'risk' is not accepted over the wire; advisory signals "
                "are produced by configured adapters, not supplied by callers"
            )
        return value

    def to_obligation(self) -> Obligation:
        return Obligation(
            id=self.id,
            status=self.status,
            source=self.source,
            detail=self.detail,
            observed=self.observed,
            expected=self.expected,
        )


class FactsIn(BaseModel):
    """Regulatory facts. Every field optional -- absence means *unknown*.

    Omitting a field is not a way to skip a check. An unknown fact yields
    ``INDETERMINATE``, which rejects.
    """

    model_config = ConfigDict(extra="forbid")

    amount_paise: int | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    category: str | None = Field(default=None, max_length=64)
    afa_performed: bool | None = None
    afa_at_registration: bool | None = None
    pre_debit_notice_at: datetime | None = None
    execution_at: datetime | None = None
    mandate_valid_from: datetime | None = None
    mandate_valid_until: datetime | None = None

    @field_validator(
        "pre_debit_notice_at",
        "execution_at",
        "mandate_valid_from",
        "mandate_valid_until",
    )
    @classmethod
    def _require_tz(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError(
                "timestamps must be timezone-aware; a naive timestamp is "
                "ambiguous in an audit record"
            )
        return value


class EvaluateRequest(BaseModel):
    """One authorisation decision."""

    model_config = ConfigDict(extra="forbid")

    mandate_ref: Sha256Hex = Field(
        description="sha256 of the closed mandate JWT -- the AP2 receipt anchor"
    )
    facts: FactsIn = Field(default_factory=FactsIn)
    protocol_obligations: list[ObligationIn] = Field(default_factory=list)
    mandate_obligations: list[ObligationIn] = Field(default_factory=list)
    merchant_obligations: list[ObligationIn] = Field(default_factory=list)
    risk_context: dict[str, Any] = Field(default_factory=dict)


class ObligationOut(BaseModel):
    id: str
    status: str
    source: str
    detail: str
    observed: Any = None
    expected: Any = None
    citation: dict[str, Any] | None = None


class EvaluateResponse(BaseModel):
    """The verdict, plus everything needed to explain and re-verify it.

    ``decision`` is authoritative. The HTTP status also encodes it -- 200 for
    allow, 403 for reject -- specifically so that an integrator who checks only
    the status code fails **closed**. See the note in ``gateway.app``.
    """

    decision: Literal["allow", "reject"]
    policy_version: str
    coverage: float
    trace_id: str
    mandate_ref: str
    evaluated_at: str
    verdict_hash: str
    obligations: list[ObligationOut]
    blocking: list[str]
    ledger_sequence: int | None = None
    record_hash: str | None = None
    elapsed_ms: float

    @classmethod
    def from_result(cls, result: GateResult) -> EvaluateResponse:
        verdict = result.verdict
        payload = verdict.to_dict()
        return cls(
            decision=str(verdict.decision),  # type: ignore[arg-type]
            policy_version=verdict.policy_version,
            coverage=round(verdict.coverage, 4),
            trace_id=verdict.trace_id,
            mandate_ref=verdict.mandate_ref,
            evaluated_at=str(payload["evaluated_at"]),
            verdict_hash=verdict.content_hash(),
            obligations=[
                ObligationOut(**o)  # type: ignore[arg-type]
                for o in payload["obligations"]  # type: ignore[union-attr]
            ],
            blocking=[o.id for o in verdict.blocking],
            ledger_sequence=result.record.sequence if result.record else None,
            record_hash=result.record.record_hash() if result.record else None,
            elapsed_ms=round(result.elapsed_ms, 3),
        )


class ErrorResponse(BaseModel):
    """A failure to evaluate. Never carries a decision.

    A malformed request has no verdict, so the response deliberately has no
    ``decision`` field at all -- there is nothing for a careless integrator to
    misread as an allow.
    """

    error: str
    detail: str
    trace_id: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str
    policy_version: str
    declared_obligations: int
    ledger_records: int | None = None
    risk_adapters: list[str]
