"""The canonical verdict types.

Every decision PRAMANA makes -- from the HTTP gate, the CLI, the benchmark
runner, or a library caller -- is expressed as exactly one :class:`Verdict`.
There is no second decision type and no path that returns a bare boolean.
That is what makes the system centralized rather than merely modular.

Two invariants are enforced structurally rather than by convention:

1. **Fail closed.** :meth:`Verdict.decision` is *derived*, never assigned.
   Anything other than a fully satisfied obligation set yields ``REJECT``.

2. **Absence is not consent.** :attr:`ObligationStatus.INDETERMINATE` exists
   because upstream AP2 constraint evaluation is presence-driven: a constraint
   that is not disclosed produces no evaluator and therefore no violation.
   A stripped spending cap reads as "no violations found". Here, an obligation
   we could not evaluate is ``INDETERMINATE``, and ``INDETERMINATE`` rejects.
   See docs/adr/0003-absent-constraint-is-not-consent.md
"""

from __future__ import annotations

import enum
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


class Decision(enum.StrEnum):
    """The only two outcomes. There is no soft path and no 'review' state."""

    ALLOW = "allow"
    REJECT = "reject"


class ObligationStatus(enum.StrEnum):
    """Outcome of a single proof obligation.

    ``INDETERMINATE`` is the load-bearing member. It is returned when a
    predicate could not reach a conclusion -- a required disclosure was
    absent, a state store was unreachable, a constraint the policy demanded
    was simply not present in the mandate. It is *not* a soft failure: it
    rejects exactly as hard as ``VIOLATED``. The two are distinguished only
    so the evidence record can say which happened.
    """

    SATISFIED = "satisfied"
    VIOLATED = "violated"
    INDETERMINATE = "indeterminate"
    NOT_APPLICABLE = "not_applicable"

    @property
    def is_blocking(self) -> bool:
        """Whether this status prevents an ``ALLOW``."""
        return self in (ObligationStatus.VIOLATED, ObligationStatus.INDETERMINATE)


class ObligationSource(enum.StrEnum):
    """Which authority imposed an obligation.

    Recorded per-obligation because the distinction is legally meaningful in
    a dispute: a mandate-derived limit was chosen by the user, a regulatory
    one was not, and a merchant one binds even when the mandate is permissive.
    """

    MANDATE = "mandate"
    """Derived from constraints carried in the AP2 mandate itself."""

    REGULATORY = "regulatory"
    """Imposed by the jurisdiction (e.g. RBI E-mandate Framework, 2026)."""

    MERCHANT = "merchant"
    """Imposed by merchant policy. A mandate cannot weaken these."""

    PROTOCOL = "protocol"
    """Structural integrity of the AP2 chain itself."""


@dataclass(frozen=True, slots=True)
class Obligation:
    """One machine-checked proof obligation and its result.

    Immutable: obligations are hash-chained into the evidence ledger, so a
    verdict must never be mutated after construction.
    """

    id: str
    """Stable identifier, e.g. ``rbi.afa_threshold``. Never renamed once shipped."""

    status: ObligationStatus
    source: ObligationSource
    detail: str
    """Human-readable reason. Shown to the merchant and in the dispute pack."""

    observed: Any = None
    """What the predicate actually saw. Kept for the evidence record."""

    expected: Any = None
    """What policy required."""

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Obligation.id must be non-empty")
        if not self.detail:
            raise ValueError(f"Obligation {self.id!r} must carry a detail string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": str(self.status),
            "source": str(self.source),
            "detail": self.detail,
            "observed": self.observed,
            "expected": self.expected,
        }


@dataclass(frozen=True, slots=True)
class Verdict:
    """The single, canonical output of the PRAMANA kernel.

    ``decision`` is deliberately a derived property. There is no constructor
    argument that lets a caller assert ``ALLOW`` -- an allow can only be
    *earned* by presenting an obligation set in which nothing blocks.
    """

    obligations: Sequence[Obligation]
    policy_version: str
    """Version of the policy document evaluated. Stamped for reproducibility."""

    trace_id: str
    """W3C Trace-Context trace id, propagated from ingestion."""

    mandate_ref: str | None = None
    """``sha256(get_closed_mandate_jwt(chain))`` -- the AP2 canonical receipt
    reference. Stable across chain depth and disclosure choices, which makes it
    the correct primary key for the evidence ledger."""

    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not self.policy_version:
            raise ValueError("Verdict.policy_version is required")
        if not self.trace_id:
            raise ValueError("Verdict.trace_id is required")
        if self.evaluated_at.tzinfo is None:
            raise ValueError("Verdict.evaluated_at must be timezone-aware")
        if not self.obligations:
            # An empty obligation set means nothing was checked. That must
            # never read as success.
            raise ValueError(
                "Verdict requires at least one obligation; an empty set would "
                "otherwise evaluate to ALLOW without any check having run"
            )

    @property
    def decision(self) -> Decision:
        """Derived, never assigned. Any blocking obligation rejects."""
        if any(o.status.is_blocking for o in self.obligations):
            return Decision.REJECT
        return Decision.ALLOW

    @property
    def blocking(self) -> tuple[Obligation, ...]:
        """The obligations responsible for a ``REJECT``, in evaluation order."""
        return tuple(o for o in self.obligations if o.status.is_blocking)

    @property
    def is_allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": str(self.decision),
            "policy_version": self.policy_version,
            "trace_id": self.trace_id,
            "mandate_ref": self.mandate_ref,
            "evaluated_at": self.evaluated_at.isoformat(),
            "obligations": [o.to_dict() for o in self.obligations],
        }

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization for hash chaining.

        Sorted keys, no insignificant whitespace, UTF-8. Two verdicts with
        identical content must produce byte-identical output on any platform
        or the evidence chain is not verifiable by a third party.
        """
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")

    def content_hash(self) -> str:
        """SHA-256 of :meth:`canonical_bytes`, hex-encoded."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()
