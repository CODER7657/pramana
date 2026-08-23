"""The canonical verdict types.

Every decision PRAMANA makes -- from the HTTP gate, the CLI, the benchmark
runner, or a library caller -- is expressed as exactly one :class:`Verdict`.
There is no second decision type and no path that returns a bare boolean.

Four invariants are enforced structurally rather than by convention. Each one
exists because its absence was a live defect, not because it seemed tidy.

1. **Fail closed.** :attr:`Verdict.decision` is *derived*, never assigned.
   Anything other than a fully satisfied obligation set yields ``REJECT``.

2. **Absence is not consent.** :attr:`ObligationStatus.INDETERMINATE` exists
   because upstream AP2 constraint evaluation is presence-driven: a constraint
   that is not disclosed produces no evaluator and therefore no violation, so a
   stripped spending cap reads as "no violations found".
   See docs/adr/0003-absent-constraint-is-not-consent.md

3. **Coverage is structural.** A verdict carries the obligation ids the policy
   *declared*. Any declared id missing from the results is materialised as an
   ``INDETERMINATE`` obligation at construction time. Without this, the kernel
   reproduces the exact failure it was built to prevent -- inability to
   distinguish "checked and passed" from "never checked".

4. **An authorisation must affirm something.** At least one obligation must be
   ``SATISFIED``. A verdict in which every obligation is ``NOT_APPLICABLE``
   checked nothing and must not read as permission.

Verdicts are hash-chained into the evidence ledger, so they are deeply
immutable and canonicalised with RFC 8785 (JCS) -- not ``json.dumps``, which
is neither cross-language canonical nor safe against non-JSON payloads.
"""

from __future__ import annotations

import enum
import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TypeAlias

import rfc8785

# Sequence/Mapping rather than list/dict: list is invariant, so list[str] would
# not satisfy list[JsonValue] and every concrete evidence value would need a cast.
JsonValue: TypeAlias = (
    "str | int | float | bool | Sequence[JsonValue] | Mapping[str, JsonValue] | None"
)

_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_ALL_ZERO_TRACE_ID = "0" * 32
_MANDATE_REF_RE = re.compile(r"^[0-9a-f]{64}$")


class Decision(enum.StrEnum):
    """The only two outcomes. There is no soft path and no 'review' state."""

    ALLOW = "allow"
    REJECT = "reject"


class ObligationStatus(enum.StrEnum):
    """Outcome of a single proof obligation."""

    SATISFIED = "satisfied"
    """The predicate ran and the condition held."""

    VIOLATED = "violated"
    """The predicate ran and the condition failed."""

    INDETERMINATE = "indeterminate"
    """The predicate could not reach a conclusion -- a required disclosure was
    absent, a state store was unreachable, a declared obligation never ran.
    Not a soft failure: it rejects exactly as hard as ``VIOLATED``. The two are
    distinguished only so the evidence record can say which happened."""

    NOT_APPLICABLE = "not_applicable"
    """The rule genuinely does not govern this transaction -- e.g. an
    insurance-category limit on a groceries purchase. This is a positive
    finding about scope, *not* an inability to evaluate. Because it does not
    block, invariant 4 exists to stop an all-``NOT_APPLICABLE`` verdict from
    reading as permission."""

    @property
    def is_blocking(self) -> bool:
        """Whether this status prevents an ``ALLOW``."""
        return self in (ObligationStatus.VIOLATED, ObligationStatus.INDETERMINATE)


class ObligationSource(enum.StrEnum):
    """Which authority imposed an obligation.

    Recorded per-obligation because the distinction is legally meaningful in a
    dispute: a mandate-derived limit was chosen by the user, a regulatory one
    was not, and a merchant one binds even when the mandate is permissive.
    """

    MANDATE = "mandate"
    REGULATORY = "regulatory"
    MERCHANT = "merchant"
    PROTOCOL = "protocol"

    RISK = "risk"
    """An advisory signal from an external scorer -- e.g. a Vulcan-class fraud
    model. Advisory obligations can only ever block; they never contribute to
    an ALLOW. See pramana.kernel.risk.signals and ADR-0005."""


def _assert_json_safe(value: object, path: str) -> None:
    """Reject anything RFC 8785 cannot canonicalise deterministically.

    ``observed``/``expected`` were previously typed ``Any`` and serialised with
    ``default=str``, which rendered arbitrary objects via ``repr`` -- memory
    addresses and all. That silently destroyed the determinism the evidence
    chain depends on.
    """
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, float):
        # JCS defines float serialisation, but NaN/Inf have no JSON form.
        if value != value or value in (float("inf"), float("-inf")):  # noqa: PLR0124
            raise ValueError(f"{path}: NaN and Infinity are not serialisable")
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _assert_json_safe(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(
                    f"{path}: dict keys must be str, got {type(k).__name__}"
                )
            _assert_json_safe(v, f"{path}.{k}")
        return
    raise ValueError(
        f"{path}: {type(value).__name__} is not JSON-safe. Evidence fields must "
        "be canonicalisable; convert to a primitive before recording."
    )


@dataclass(frozen=True, slots=True)
class Citation:
    """The authority that imposed an obligation.

    This is what makes a verdict a *compliance artifact* rather than a
    decision. A probabilistic scorer can tell a merchant a transaction looked
    risky; it cannot name the provision that forbade it. A regulator, an
    auditor, and a disputing customer all need the provision.

    Every ``REGULATORY`` obligation must carry one -- enforced in
    :meth:`Obligation.__post_init__`. You cannot claim a rule rejected a
    payment without saying which rule.
    """

    authority: str
    """Who imposed it, e.g. ``"RBI"``, ``"AP2"``, ``"merchant"``."""

    reference: str
    """The instrument, e.g. ``"Digital Payments - E-mandate Framework, 2026"``."""

    clause: str | None = None
    """The specific provision, where one is identifiable."""

    effective_from: str | None = None
    """ISO date the provision took effect. A rule cannot bind a transaction
    that predates it, and a dispute may turn on exactly that."""

    url: str | None = None

    def __post_init__(self) -> None:
        if not self.authority:
            raise ValueError("Citation.authority must be non-empty")
        if not self.reference:
            raise ValueError("Citation.reference must be non-empty")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "authority": self.authority,
            "reference": self.reference,
            "clause": self.clause,
            "effective_from": self.effective_from,
            "url": self.url,
        }

    def render(self) -> str:
        """One-line human form, for the dispute pack and the CLI."""
        parts = [self.authority, self.reference]
        if self.clause:
            parts.append(self.clause)
        return " / ".join(parts)


@dataclass(frozen=True, slots=True)
class Obligation:
    """One machine-checked proof obligation and its result."""

    id: str
    """Stable identifier, e.g. ``rbi.afa_threshold``. Never renamed once shipped."""

    status: ObligationStatus
    source: ObligationSource
    detail: str
    """Human-readable reason. Shown to the merchant and in the dispute pack."""

    observed: JsonValue = None
    """What the predicate actually saw. JSON-safe only."""

    expected: JsonValue = None
    """What policy required. JSON-safe only."""

    citation: Citation | None = None
    """The authority behind this obligation. Required for REGULATORY."""

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Obligation.id must be non-empty")
        if not self.detail:
            raise ValueError(f"Obligation {self.id!r} must carry a detail string")
        _assert_json_safe(self.observed, f"{self.id}.observed")
        _assert_json_safe(self.expected, f"{self.id}.expected")
        if self.source is ObligationSource.REGULATORY and self.citation is None:
            raise ValueError(
                f"Obligation {self.id!r} has source REGULATORY but no citation. "
                "A regulatory rejection must name the provision it rests on."
            )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "id": self.id,
            "status": str(self.status),
            "source": str(self.source),
            "detail": self.detail,
            "observed": self.observed,
            "expected": self.expected,
            "citation": self.citation.to_dict() if self.citation else None,
        }


@dataclass(frozen=True, slots=True)
class Verdict:
    """The single, canonical output of the PRAMANA kernel."""

    obligations: tuple[Obligation, ...]
    """Coerced to a tuple at construction. A caller's list would otherwise stay
    mutable through the frozen binding, letting an already-ledgered verdict be
    flipped from ALLOW to REJECT after the fact."""

    policy_version: str
    """Version of the policy document evaluated. Stamped for reproducibility."""

    declared_obligations: frozenset[str]
    """Obligation ids the policy required. Drives the coverage invariant."""

    trace_id: str
    """W3C Trace-Context trace-id: 32 lowercase hex, not all zeroes."""

    mandate_ref: str
    """``sha256(get_closed_mandate_jwt(chain))`` -- the AP2 canonical receipt
    reference. Required: an evidence record with no protocol anchor is not
    evidence."""

    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    declared_meta: Mapping[str, tuple[ObligationSource, Citation | None]] = field(
        default_factory=dict
    )
    """Optional ``id -> (source, citation)`` for declared obligations.

    Used when synthesising a missing obligation so it is attributed to the
    authority that declared it. Without this every synthesised obligation was
    recorded as ``MERCHANT`` with no citation -- including missing ``rbi.*``
    checks, in a system where ADR-0006 makes a citation mandatory for
    regulatory obligations."""


    def __post_init__(self) -> None:
        if not self.policy_version:
            raise ValueError("Verdict.policy_version is required")
        if not _TRACE_ID_RE.match(self.trace_id) or self.trace_id == _ALL_ZERO_TRACE_ID:
            raise ValueError(
                f"Verdict.trace_id must be 32 lowercase hex chars and non-zero, "
                f"got {self.trace_id!r}"
            )
        if not _MANDATE_REF_RE.match(self.mandate_ref):
            raise ValueError(
                f"Verdict.mandate_ref must be a sha256 hex digest, "
                f"got {self.mandate_ref!r}"
            )
        if self.evaluated_at.tzinfo is None:
            raise ValueError("Verdict.evaluated_at must be timezone-aware")
        if not self.declared_obligations:
            raise ValueError(
                "Verdict.declared_obligations is required; a policy that declares "
                "nothing cannot authorise anything"
            )

        object.__setattr__(self, "obligations", tuple(self.obligations))
        object.__setattr__(
            self, "declared_obligations", frozenset(self.declared_obligations)
        )

        duplicates = self._duplicate_ids()
        if duplicates:
            raise ValueError(
                f"Verdict contains duplicate obligation ids: {sorted(duplicates)}"
            )

        self._enforce_coverage()

        self._require_an_affirmation()

    def _require_an_affirmation(self) -> None:
        """An ALLOW must affirm something the policy actually asked for.

        Scoped two ways, both from review findings:

        * Only an ``ALLOW`` needs an affirmation. A ``REJECT`` is a refusal, not
          permission, so it does not need to have satisfied anything -- and
          requiring it made a malformed request crash the gate instead of
          rejecting it.
        * The satisfied obligation must be one the policy **declared**.
          Otherwise bookkeeping satisfies the invariant: an all-NOT_APPLICABLE
          policy result reached ALLOW whenever a ledger write succeeded, which
          reopened the hole this invariant exists to close, one layer down.
        """
        if any(o.status.is_blocking for o in self.obligations):
            return
        affirmed = {
            o.id
            for o in self.obligations
            if o.status is ObligationStatus.SATISFIED
        } & self.declared_obligations
        if not affirmed:
            raise ValueError(
                "Verdict would ALLOW without any policy-declared obligation "
                "being SATISFIED. Nothing the policy asked for was affirmed, so "
                "this is not an authorisation."
            )

    def _duplicate_ids(self) -> set[str]:
        seen: set[str] = set()
        dupes: set[str] = set()
        for o in self.obligations:
            if o.id in seen:
                dupes.add(o.id)
            seen.add(o.id)
        return dupes

    def _enforce_coverage(self) -> None:
        """Materialise any declared-but-unevaluated obligation as INDETERMINATE.

        Synthesising rather than raising is deliberate: the resulting verdict is
        self-documenting evidence that policy required a check the evaluator
        never ran. An exception would let a caller swallow that fact.
        """
        evaluated = {o.id for o in self.obligations}
        missing = self.declared_obligations - evaluated
        if not missing:
            return
        synthesized = tuple(
            Obligation(
                id=oid,
                status=ObligationStatus.INDETERMINATE,
                source=self.declared_meta.get(
                    oid, (ObligationSource.MERCHANT, None)
                )[0],
                detail=(
                    "Policy declared this obligation but no predicate reported a "
                    "result for it. Absence of a result is not compliance."
                ),
                expected="evaluated",
                observed=None,
                citation=self.declared_meta.get(oid, (None, None))[1],
            )
            for oid in sorted(missing)
        )
        object.__setattr__(self, "obligations", self.obligations + synthesized)

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

    @property
    def coverage(self) -> float:
        """Fraction of declared obligations that produced a real result."""
        conclusive = {
            o.id
            for o in self.obligations
            if o.status is not ObligationStatus.INDETERMINATE
        }
        return len(self.declared_obligations & conclusive) / len(
            self.declared_obligations
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "decision": str(self.decision),
            "policy_version": self.policy_version,
            "declared_obligations": sorted(self.declared_obligations),
            "trace_id": self.trace_id,
            "mandate_ref": self.mandate_ref,
            "evaluated_at": self.evaluated_at.astimezone(UTC).isoformat(),
            "obligations": [o.to_dict() for o in self.obligations],
        }

    def canonical_bytes(self) -> bytes:
        """RFC 8785 (JCS) canonicalisation.

        A third party in a dispute must be able to recompute this hash from the
        same facts in a different language. ``json.dumps`` does not provide
        that guarantee; JCS does.
        """
        return rfc8785.dumps(self.to_dict())

    def content_hash(self) -> str:
        """SHA-256 of :meth:`canonical_bytes`, hex-encoded."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def __hash__(self) -> int:
        return hash(self.content_hash())


def build_verdict(
    obligations: Iterable[Obligation],
    *,
    policy_version: str,
    declared_obligations: Iterable[str],
    trace_id: str,
    mandate_ref: str,
    evaluated_at: datetime | None = None,
    declared_meta: Mapping[str, tuple[ObligationSource, Citation | None]] | None = None,
) -> Verdict:
    """Preferred constructor. Accepts any iterable and normalises it."""
    return Verdict(
        obligations=tuple(obligations),
        policy_version=policy_version,
        declared_obligations=frozenset(declared_obligations),
        trace_id=trace_id,
        mandate_ref=mandate_ref,
        evaluated_at=evaluated_at or datetime.now(UTC),
        declared_meta=dict(declared_meta or {}),
    )
