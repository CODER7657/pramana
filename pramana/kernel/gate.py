"""The kernel facade. One entry point, one verdict, one evidence record.

Everything that decides a payment goes through :meth:`Kernel.evaluate` -- the
HTTP gate, the CLI, the benchmark runner, a library caller. There is no second
path, no shortcut for "internal" callers, and no way to obtain a decision
without also producing its trace and its ledger record. That is what makes this
a centralized product rather than a collection of modules that happen to agree.

The pipeline, in order:

    1. protocol obligations      chain verified, nonce fresh, disclosures pinned
    2. mandate obligations       budget, payee scope, expiry
    3. merchant obligations      policy the mandate cannot weaken
    4. regulatory obligations    the RBI envelope (ADR-0006, cited)
    5. advisory risk signals     one-way; can subtract, never add (ADR-0005)
    6. verdict                   coverage enforced against the policy (ADR-0003)
    7. ledger                    hash-chained; a write failure REJECTS

Every step runs under a child :class:`~pramana.kernel.trace.TraceContext` and is
recorded as a span, so a single trace id reconstructs the complete causal
history of a decision -- which predicate ran, in what order, how long it took,
and what it concluded.

Step 7 is the one people get wrong. An authorisation we cannot evidence is not
an authorisation, so a ledger failure produces an ``INDETERMINATE`` obligation
rather than an allow-and-alert. Availability is never traded for authority.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pramana.kernel.ledger.chain_log import EvidenceLedger, LedgerRecord
from pramana.kernel.risk.signals import RiskAdapter, advisory_obligations
from pramana.kernel.trace import SpanRecorder, TraceContext
from pramana.kernel.verdict import (
    Citation,
    Obligation,
    ObligationSource,
    ObligationStatus,
    Verdict,
    build_verdict,
)
from pramana.kernel.verify import rbi
from pramana.kernel.verify.policy import ObligationSpec, Policy

logger = logging.getLogger(__name__)

LEDGER_OBLIGATION_ID = "evidence.recorded"

#: A predicate group: given the declared specs and the request, return results.
PredicateGroup = Callable[
    [tuple[ObligationSpec, ...], "PaymentRequest"], tuple[Obligation, ...]
]


@dataclass(frozen=True, slots=True)
class PaymentRequest:
    """Everything the kernel needs, already extracted from the wire format.

    Extraction happens at the edge. The kernel never parses an AP2 object, so a
    protocol version bump changes one adapter rather than every predicate.
    """

    mandate_ref: str
    facts: rbi.PaymentFacts
    protocol_results: tuple[Obligation, ...] = field(default_factory=tuple)
    mandate_results: tuple[Obligation, ...] = field(default_factory=tuple)
    merchant_results: tuple[Obligation, ...] = field(default_factory=tuple)
    risk_context: Mapping[str, Any] = field(default_factory=dict)
    traceparent: str | None = None
    """Inbound W3C header, if the caller supplied one."""


@dataclass(frozen=True, slots=True)
class GateResult:
    """A decision plus everything needed to explain and defend it."""

    verdict: Verdict
    trace: TraceContext
    spans: tuple[dict[str, Any], ...]
    record: LedgerRecord | None
    elapsed_ms: float

    @property
    def is_allowed(self) -> bool:
        return self.verdict.is_allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.to_dict(),
            "trace": self.trace.to_dict(),
            "spans": list(self.spans),
            "ledger_sequence": self.record.sequence if self.record else None,
            "record_hash": self.record.record_hash() if self.record else None,
            "elapsed_ms": round(self.elapsed_ms, 3),
        }


class Kernel:
    """The single decision path."""

    def __init__(
        self,
        policy: Policy,
        *,
        ledger: EvidenceLedger | None = None,
        risk_adapters: Sequence[RiskAdapter] = (),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.policy = policy
        self.ledger = ledger
        self.risk_adapters = tuple(risk_adapters)
        self._clock = clock or (lambda: datetime.now(UTC))

    # -- pipeline ----------------------------------------------------------

    def evaluate(self, request: PaymentRequest) -> GateResult:
        """Decide. Never raises; every failure becomes a blocking obligation."""
        root = TraceContext.continue_or_start(request.traceparent, "gate.evaluate")
        recorder = SpanRecorder(self._clock)
        started = recorder.now()

        supplied: list[Obligation] = []
        supplied.extend(
            self._span(recorder, root, "protocol", lambda: request.protocol_results)
        )
        supplied.extend(
            self._span(recorder, root, "mandate", lambda: request.mandate_results)
        )
        supplied.extend(
            self._span(recorder, root, "merchant", lambda: request.merchant_results)
        )
        obligations: list[Obligation] = list(self._only_declared(supplied))
        obligations.extend(
            self._span(
                recorder,
                root,
                "regulatory",
                lambda: rbi.evaluate(
                    self.policy.by_source(ObligationSource.REGULATORY), request.facts
                ),
            )
        )
        obligations.extend(
            self._span(
                recorder,
                root,
                "risk.advisory",
                lambda: advisory_obligations(
                    self.risk_adapters, dict(request.risk_context)
                ),
            )
        )

        verdict = self._build_or_reject(obligations, root, request, started)

        # The ledgered verdict must BE the returned verdict. Previously a
        # *provisional* verdict was written and the returned one differed, so
        # nothing bound the evidence record to the decision the merchant acted
        # on -- which, for a dispute artifact, is the entire point.
        record = self._record_evidence(recorder, root, verdict)

        if self.ledger is not None and record is None:
            # Could not evidence it. That blocks, so rebuild with the failure
            # recorded. The returned verdict is deliberately in no ledger.
            obligations.append(
                Obligation(
                    id=LEDGER_OBLIGATION_ID,
                    status=ObligationStatus.INDETERMINATE,
                    source=ObligationSource.MERCHANT,
                    detail=(
                        "The decision could not be written to the evidence "
                        "ledger. An authorisation that cannot be evidenced is "
                        "not granted."
                    ),
                    expected="evidence recorded",
                )
            )
            verdict = self._build_or_reject(obligations, root, request, started)
        elapsed = (recorder.now() - started).total_seconds() * 1000.0
        return GateResult(
            verdict=verdict,
            trace=root,
            spans=tuple(recorder.to_list()),
            record=record,
            elapsed_ms=elapsed,
        )

    # -- steps -------------------------------------------------------------

    def _only_declared(
        self, supplied: Sequence[Obligation]
    ) -> tuple[Obligation, ...]:
        """Caller-supplied results may only name obligations the policy declared.

        The caller reports what it evaluated; it does not get to extend the
        policy. An undeclared id cannot authorise anything on its own -- the
        affirmation invariant counts only declared ids -- but it *was* being
        written into the evidence ledger, where it reads exactly like a check
        somebody required and somebody performed. An evidence record that
        contains checks nobody asked for is not evidence of anything.

        So an undeclared id is dropped and the request rejects, rather than the
        id being silently ignored. Ignoring it would leave the caller believing
        a check it reported was taken into account.

        ``internal.*`` ids are exempt: those are ours, minted by :meth:`_span`
        when a predicate group crashes, and they are never caller input.
        """
        declared = self.policy.declared_ids
        undeclared = sorted(
            {
                o.id
                for o in supplied
                if o.id not in declared and not o.id.startswith("internal.")
            }
        )
        kept = tuple(o for o in supplied if o.id not in undeclared)
        if not undeclared:
            return kept
        logger.warning("caller reported undeclared obligations: %s", undeclared)
        return (
            *kept,
            Obligation(
                id="internal.undeclared_obligation",
                status=ObligationStatus.VIOLATED,
                source=ObligationSource.MERCHANT,
                detail=(
                    f"The caller reported {len(undeclared)} obligation(s) this "
                    f"policy does not declare: {', '.join(undeclared)}. A caller "
                    f"reports what it evaluated; it does not get to extend the "
                    f"policy, and evidence may not record checks nobody required."
                ),
                expected="only policy-declared obligation ids",
            ),
        )

    def _declared_meta(
        self,
    ) -> dict[str, tuple[ObligationSource, Citation | None]]:
        """Authority and citation per declared id, for coverage synthesis."""
        return {
            spec.id: (spec.source, spec.citation) for spec in self.policy.enabled
        }

    def _build_or_reject(
        self,
        obligations: Sequence[Obligation],
        root: TraceContext,
        request: PaymentRequest,
        started: datetime,
    ) -> Verdict:
        """Construct the verdict, or a REJECT explaining why it could not be.

        ``evaluate`` documents that it never raises. It did: a request with
        duplicate obligation ids reached ``build_verdict``, which correctly
        refused to build, and the exception escaped to the caller as a 500 on
        an unauthenticated endpoint. A verdict we cannot construct is a
        decision we cannot justify, which is a rejection -- not a crash.
        """
        common = {
            "policy_version": self.policy.version,
            "declared_obligations": self.policy.declared_ids,
            "trace_id": root.trace_id,
            "mandate_ref": request.mandate_ref,
            "evaluated_at": started,
            "declared_meta": self._declared_meta(),
        }
        try:
            return build_verdict(obligations, **common)  # type: ignore[arg-type]
        except ValueError as exc:
            logger.warning("verdict construction failed, rejecting: %s", exc)

        # Rebuild from a sanitised set: first occurrence of each id wins, plus
        # an explicit blocking obligation naming the malformation.
        seen: set[str] = set()
        sanitised: list[Obligation] = []
        for o in obligations:
            if o.id not in seen:
                seen.add(o.id)
                sanitised.append(o)
        sanitised.append(
            Obligation(
                id="internal.request_wellformed",
                status=ObligationStatus.VIOLATED,
                source=ObligationSource.MERCHANT,
                detail=(
                    "The submitted obligation set could not form a valid "
                    "verdict, so no authorisation can be justified from it."
                ),
                expected="a well-formed obligation set",
            )
        )
        return build_verdict(sanitised, **common)  # type: ignore[arg-type]

    def _span(
        self,
        recorder: SpanRecorder,
        parent: TraceContext,
        name: str,
        run: Callable[[], tuple[Obligation, ...]],
    ) -> tuple[Obligation, ...]:
        """Run one predicate group under its own span.

        A group that raises does not take down the decision: it becomes an
        INDETERMINATE obligation, which rejects. A crashing predicate must
        never be able to produce an allow.
        """
        context = parent.child(f"predicates:{name}")
        started = recorder.now()
        try:
            # tuple() inside the guard on purpose: a group that raises while
            # being *iterated* (not while being called) must be caught too.
            results = tuple(run())
        except Exception as exc:
            logger.exception("predicate group %r failed", name)
            recorder.record(context, started, "error", f"{type(exc).__name__}: {exc}")
            return (
                Obligation(
                    id=f"internal.{name}",
                    status=ObligationStatus.INDETERMINATE,
                    source=ObligationSource.MERCHANT,
                    detail=(
                        f"The {name} predicate group raised "
                        f"{type(exc).__name__} and produced no result. A check "
                        f"that could not run is not a check that passed."
                    ),
                    expected="evaluated",
                ),
            )
        blocking = sum(1 for o in results if o.status.is_blocking)
        recorder.record(
            context,
            started,
            "blocked" if blocking else "clear",
            f"{len(results)} obligation(s), {blocking} blocking",
        )
        return tuple(results)

    def _record_evidence(
        self,
        recorder: SpanRecorder,
        parent: TraceContext,
        verdict: Verdict,
    ) -> LedgerRecord | None:
        """Append the **final** verdict. ``None`` if it could not be written.

        No obligation is emitted on success, for two reasons. Emitting one
        would change the verdict being recorded, so the ledgered artifact would
        again differ from the returned one. And a ``SATISFIED`` bookkeeping
        obligation used to satisfy the affirmation invariant on its own, so an
        all-``NOT_APPLICABLE`` policy result reached ``ALLOW`` whenever the
        ledger happened to be up.

        On success the record's existence is the evidence. On failure the
        caller adds a blocking obligation and rebuilds.
        """
        if self.ledger is None:
            return None

        context = parent.child("ledger.append")
        started = recorder.now()
        try:
            record = self.ledger.append(verdict)
        except Exception as exc:
            # Deliberately broad. LedgerStore is a plugin point; a third-party
            # backend may raise anything, and none of it may reach the caller
            # as a crash. A ledger we cannot write is a decision we cannot
            # evidence, which rejects.
            logger.warning("evidence write failed: %s", exc)
            recorder.record(context, started, "error", str(exc))
            return None

        recorder.record(context, started, "clear", f"sequence {record.sequence}")
        return record
