"""W3C Trace Context propagation.

Traceability is not monitoring. Monitoring says the system is healthy now;
traceability lets you reconstruct, after the fact, exactly why one decision was
made -- which is what a regulator, an auditor, and a disputing customer each
need, and what a probabilistic scorer cannot provide.

Every operation in PRAMANA carries a :class:`TraceContext`. It is created once
at ingestion, propagated through policy evaluation, every predicate, the
ledger write, and every downstream AI call, and it is stamped onto the
:class:`~pramana.kernel.verdict.Verdict` and the ledger record. Given a trace
id you can recover the complete causal history of a payment decision.

The format is W3C Trace Context (``traceparent``), so the ids interoperate with
OpenTelemetry, and with whatever the merchant already runs, rather than being a
private scheme nobody else can read.

    traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
                 ^^ ^------------ trace-id ------^ ^-- span-id --^ ^^
                 version                                           flags
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

TRACEPARENT_VERSION: Final = "00"
_TRACE_ID_RE: Final = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE: Final = re.compile(r"^[0-9a-f]{16}$")
_TRACEPARENT_RE: Final = re.compile(
    r"^(?P<version>[0-9a-f]{2})-"
    r"(?P<trace_id>[0-9a-f]{32})-"
    r"(?P<span_id>[0-9a-f]{16})-"
    r"(?P<flags>[0-9a-f]{2})$"
)
_ALL_ZERO_TRACE: Final = "0" * 32
_ALL_ZERO_SPAN: Final = "0" * 16

FLAG_SAMPLED: Final = "01"
FLAG_NOT_SAMPLED: Final = "00"


def new_trace_id() -> str:
    """A random, non-zero 16-byte trace id."""
    while (candidate := secrets.token_hex(16)) == _ALL_ZERO_TRACE:  # pragma: no cover
        continue
    return candidate


def new_span_id() -> str:
    """A random, non-zero 8-byte span id."""
    while (candidate := secrets.token_hex(8)) == _ALL_ZERO_SPAN:  # pragma: no cover
        continue
    return candidate


@dataclass(frozen=True, slots=True)
class TraceContext:
    """One point in a causal chain.

    Immutable. :meth:`child` derives a new span rather than mutating, so a
    context handed to a subsystem cannot be altered by it.
    """

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    sampled: bool = True
    operation: str = ""
    """Human name for the span, e.g. ``"predicate:rbi.afa_threshold"``."""

    baggage: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    """Immutable key/value pairs carried alongside, e.g. merchant id."""

    def __post_init__(self) -> None:
        if not _TRACE_ID_RE.match(self.trace_id) or self.trace_id == _ALL_ZERO_TRACE:
            raise ValueError(
                f"trace_id must be 32 lowercase hex chars and non-zero, "
                f"got {self.trace_id!r}"
            )
        if not _SPAN_ID_RE.match(self.span_id) or self.span_id == _ALL_ZERO_SPAN:
            raise ValueError(
                f"span_id must be 16 lowercase hex chars and non-zero, "
                f"got {self.span_id!r}"
            )
        if self.parent_span_id is not None and not _SPAN_ID_RE.match(
            self.parent_span_id
        ):
            raise ValueError(f"parent_span_id malformed: {self.parent_span_id!r}")

    @classmethod
    def start(cls, operation: str = "", **baggage: str) -> TraceContext:
        """Begin a new trace at ingestion."""
        return cls(
            trace_id=new_trace_id(),
            span_id=new_span_id(),
            operation=operation,
            baggage=tuple(sorted(baggage.items())),
        )

    @classmethod
    def parse(cls, traceparent: str, operation: str = "") -> TraceContext | None:
        """Continue an inbound trace. ``None`` if the header is malformed.

        A malformed header must not fail the request -- we start a fresh trace
        instead. Losing correlation is bad; refusing a payment because an
        upstream service sent a bad header would be worse.
        """
        match = _TRACEPARENT_RE.match(traceparent.strip())
        if match is None:
            return None
        trace_id = match.group("trace_id")
        span_id = match.group("span_id")
        if trace_id == _ALL_ZERO_TRACE or span_id == _ALL_ZERO_SPAN:
            return None
        return cls(
            trace_id=trace_id,
            span_id=new_span_id(),
            parent_span_id=span_id,
            sampled=match.group("flags") == FLAG_SAMPLED,
            operation=operation,
        )

    @classmethod
    def continue_or_start(
        cls, traceparent: str | None, operation: str = ""
    ) -> TraceContext:
        """Continue an inbound trace, or start one if there is nothing usable."""
        if traceparent:
            parsed = cls.parse(traceparent, operation)
            if parsed is not None:
                return parsed
        return cls.start(operation)

    def child(self, operation: str) -> TraceContext:
        """Derive a child span under the same trace."""
        return TraceContext(
            trace_id=self.trace_id,
            span_id=new_span_id(),
            parent_span_id=self.span_id,
            sampled=self.sampled,
            operation=operation,
            baggage=self.baggage,
        )

    def with_baggage(self, **items: str) -> TraceContext:
        """Return a copy carrying additional baggage."""
        merged = dict(self.baggage)
        merged.update(items)
        return TraceContext(
            trace_id=self.trace_id,
            span_id=self.span_id,
            parent_span_id=self.parent_span_id,
            sampled=self.sampled,
            operation=self.operation,
            baggage=tuple(sorted(merged.items())),
        )

    def traceparent(self) -> str:
        """Render the W3C header for an outbound call."""
        flags = FLAG_SAMPLED if self.sampled else FLAG_NOT_SAMPLED
        return f"{TRACEPARENT_VERSION}-{self.trace_id}-{self.span_id}-{flags}"

    def headers(self) -> dict[str, str]:
        """Headers to attach to any outbound HTTP request."""
        out = {"traceparent": self.traceparent()}
        if self.baggage:
            out["baggage"] = ",".join(f"{k}={v}" for k, v in self.baggage)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "sampled": self.sampled,
            "operation": self.operation,
            "baggage": dict(self.baggage),
        }


@dataclass(frozen=True, slots=True)
class Span:
    """A completed unit of work, for the decision-lineage record."""

    context: TraceContext
    started_at: datetime
    ended_at: datetime
    outcome: str
    detail: str = ""

    @property
    def duration_ms(self) -> float:
        return (self.ended_at - self.started_at).total_seconds() * 1000.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.context.trace_id,
            "span_id": self.context.span_id,
            "parent_span_id": self.context.parent_span_id,
            "operation": self.context.operation,
            "started_at": self.started_at.astimezone(UTC).isoformat(),
            "ended_at": self.ended_at.astimezone(UTC).isoformat(),
            "duration_ms": round(self.duration_ms, 3),
            "outcome": self.outcome,
            "detail": self.detail,
        }


class SpanRecorder:
    """Collects spans for one decision. Not a metrics system.

    Deliberately in-memory and per-request: this exists to explain a single
    decision, not to aggregate across them. Aggregation belongs in whatever
    OTel collector the merchant already runs, which is why the ids are W3C.
    """

    def __init__(self, clock: Any = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._spans: list[Span] = []

    def record(
        self,
        context: TraceContext,
        started_at: datetime,
        outcome: str,
        detail: str = "",
    ) -> Span:
        span = Span(
            context=context,
            started_at=started_at,
            ended_at=self._clock(),
            outcome=outcome,
            detail=detail,
        )
        self._spans.append(span)
        return span

    def now(self) -> datetime:
        return self._clock()

    @property
    def spans(self) -> tuple[Span, ...]:
        return tuple(self._spans)

    def total_ms(self) -> float:
        return sum(s.duration_ms for s in self._spans)

    def to_list(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self._spans]
