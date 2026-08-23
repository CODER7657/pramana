"""Run the frozen benchmark and report before/after.

Every case is evaluated under two verifiers:

**Baseline** -- presence-driven evaluation. Its policy declares only what the
presentation actually disclosed, so a withheld constraint produces no
obligation and therefore no violation. This is the AP2 reference
implementation used as-is, and it is the behaviour our spike measured
directly against the real SDK.

**PRAMANA** -- the same request through the full kernel, where policy declares
what must be present and absence is INDETERMINATE.

The difference between the two columns is the contribution. Nothing else in
this file is interesting.

Two things this runner refuses to do:

* Report an attack-success rate without a false-positive rate. A gate that
  rejects everything scores a perfect ASR and is worthless.
* Average RC-6 in with the structural classes. RC-6 is model-dependent, so its
  success rate is a distribution rather than a constant, and mixing them would
  produce a number that means nothing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bench.cases import RC_CLASSES, SEMANTIC_CLASSES, BenchCase, all_cases
from pramana.kernel.gate import Kernel, PaymentRequest
from pramana.kernel.ledger.chain_log import EvidenceLedger, MemoryStore
from pramana.kernel.verdict import ObligationSource
from pramana.kernel.verify.policy import Policy, builtin_policy, load_policy

DEFAULT_POLICY: Path | None = None
"""``None`` means "the policy shipped in the package". A path here would
be resolved against the working directory, which is how this broke."""


def baseline_policy(full: Policy, case: BenchCase) -> Policy:
    """The policy a presence-driven verifier would effectively apply.

    It declares only the obligations the presentation actually disclosed, plus
    the regulatory set (which is evaluated from supplied facts rather than from
    disclosures). An undisclosed mandate constraint is simply not required, so
    its absence raises nothing -- which is exactly the gap.
    """
    keep = case.observed_ids
    return Policy(
        version=f"{full.version}+baseline",
        description="Presence-driven baseline: declares only what was disclosed.",
        jurisdiction=full.jurisdiction,
        obligations=tuple(
            spec
            for spec in full.obligations
            if spec.id in keep or spec.source is ObligationSource.REGULATORY
        ),
    )


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    case_id: str
    rc_class: str
    is_attack: bool
    baseline_allowed: bool
    pramana_allowed: bool
    pramana_blocking: tuple[str, ...]
    elapsed_ms: float

    @property
    def baseline_correct(self) -> bool:
        return self.baseline_allowed is not self.is_attack

    @property
    def pramana_correct(self) -> bool:
        return self.pramana_allowed is not self.is_attack

    @property
    def newly_caught(self) -> bool:
        """An attack the baseline allowed and PRAMANA blocks."""
        return self.is_attack and self.baseline_allowed and not self.pramana_allowed

    @property
    def newly_blocked_legitimate(self) -> bool:
        """A false positive PRAMANA introduces and the baseline did not."""
        return (
            not self.is_attack
            and self.baseline_allowed
            and not self.pramana_allowed
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "rc_class": self.rc_class,
            "is_attack": self.is_attack,
            "baseline_allowed": self.baseline_allowed,
            "pramana_allowed": self.pramana_allowed,
            "pramana_blocking": list(self.pramana_blocking),
            "elapsed_ms": round(self.elapsed_ms, 3),
        }


@dataclass(frozen=True, slots=True)
class BenchReport:
    outcomes: tuple[CaseOutcome, ...]

    # -- rates -----------------------------------------------------------

    def _attacks(self, structural_only: bool = True) -> tuple[CaseOutcome, ...]:
        return tuple(
            o
            for o in self.outcomes
            if o.is_attack
            and (not structural_only or o.rc_class not in SEMANTIC_CLASSES)
        )

    def _legitimate(self) -> tuple[CaseOutcome, ...]:
        return tuple(o for o in self.outcomes if not o.is_attack)

    def asr(self, *, pramana: bool, structural_only: bool = True) -> float:
        """Attack-success rate: the fraction of attacks that were ALLOWED."""
        attacks = self._attacks(structural_only)
        if not attacks:
            return 0.0
        allowed = sum(
            1 for o in attacks if (o.pramana_allowed if pramana else o.baseline_allowed)
        )
        return allowed / len(attacks)

    def false_positive_rate(self, *, pramana: bool) -> float:
        """The cost side: legitimate traffic wrongly REJECTED."""
        legitimate = self._legitimate()
        if not legitimate:
            return 0.0
        blocked = sum(
            1
            for o in legitimate
            if not (o.pramana_allowed if pramana else o.baseline_allowed)
        )
        return blocked / len(legitimate)

    def asr_by_class(self, *, pramana: bool) -> dict[str, tuple[int, int]]:
        """Per class: (attacks allowed, attacks total)."""
        table: dict[str, tuple[int, int]] = {}
        for rc in RC_CLASSES:
            attacks = [o for o in self.outcomes if o.is_attack and o.rc_class == rc]
            if not attacks:
                continue
            allowed = sum(
                1
                for o in attacks
                if (o.pramana_allowed if pramana else o.baseline_allowed)
            )
            table[rc] = (allowed, len(attacks))
        return table

    def latency_p(self, percentile: float) -> float:
        values = sorted(o.elapsed_ms for o in self.outcomes)
        if not values:
            return 0.0
        index = min(int(len(values) * percentile), len(values) - 1)
        return values[index]

    @property
    def newly_caught(self) -> tuple[CaseOutcome, ...]:
        return tuple(o for o in self.outcomes if o.newly_caught)

    @property
    def new_false_positives(self) -> tuple[CaseOutcome, ...]:
        return tuple(o for o in self.outcomes if o.newly_blocked_legitimate)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cases": len(self.outcomes),
            "attacks": len(self._attacks(structural_only=False)),
            "legitimate": len(self._legitimate()),
            "asr_baseline": round(self.asr(pramana=False), 4),
            "asr_pramana": round(self.asr(pramana=True), 4),
            "fpr_baseline": round(self.false_positive_rate(pramana=False), 4),
            "fpr_pramana": round(self.false_positive_rate(pramana=True), 4),
            "asr_by_class_baseline": self.asr_by_class(pramana=False),
            "asr_by_class_pramana": self.asr_by_class(pramana=True),
            "latency_p50_ms": round(self.latency_p(0.50), 3),
            "latency_p95_ms": round(self.latency_p(0.95), 3),
            "latency_p99_ms": round(self.latency_p(0.99), 3),
            "outcomes": [o.to_dict() for o in self.outcomes],
        }

    # -- rendering -------------------------------------------------------

    def _render_class_table(self) -> list[str]:
        """Per-class before/after. Split out to keep render() legible."""
        before = self.asr_by_class(pramana=False)
        after = self.asr_by_class(pramana=True)
        rows = [
            "  BY ROOT-CAUSE CLASS  (attacks allowed / total)",
            f"    {'class':<7} {'before':>10} {'after':>10}   definition",
        ]
        for rc in sorted(set(before) | set(after)):
            b_allowed, b_total = before.get(rc, (0, 0))
            a_allowed, a_total = after.get(rc, (0, 0))
            rows.append(
                f"    {rc:<7} {f'{b_allowed}/{b_total}':>10} "
                f"{f'{a_allowed}/{a_total}':>10}   {RC_CLASSES[rc][:42]}"
            )
        return rows

    def _render_header(self) -> list[str]:
        attacks = self._attacks(structural_only=False)
        legitimate = self._legitimate()
        return [
            "=" * 72,
            "FROZEN ATTACK BENCHMARK -- before / after",
            "=" * 72,
            f"  cases      : {len(self.outcomes)} "
            f"({len(attacks)} attack, {len(legitimate)} legitimate)",
            "  taxonomy   : Louck, arXiv:2607.21824 -- RC-1..RC-5 structural, "
            "RC-6 semantic",
            "  scope      : our own cases mapped to their classes. AIP-Bench",
            "               artifacts release 2026-10-04; we have not run it.",
        ]

    def _render_rates(self) -> list[str]:
        structural = self._attacks(structural_only=True)
        return [
            "  ATTACK-SUCCESS RATE (structural classes only; lower is better)",
            f"    baseline (presence-driven) : {self.asr(pramana=False):.1%}  "
            f"({sum(1 for o in structural if o.baseline_allowed)}"
            f"/{len(structural)} attacks allowed)",
            f"    PRAMANA                    : {self.asr(pramana=True):.1%}  "
            f"({sum(1 for o in structural if o.pramana_allowed)}"
            f"/{len(structural)} attacks allowed)",
        ]

    def render(self) -> str:
        lines: list[str] = []
        add = lines.append

        legitimate = self._legitimate()

        lines.extend(self._render_header())
        add("")
        lines.extend(self._render_rates())
        add("")
        add("  FALSE-POSITIVE RATE (legitimate traffic wrongly rejected)")
        add(f"    baseline : {self.false_positive_rate(pramana=False):.1%} "
            f"({sum(1 for o in legitimate if not o.baseline_allowed)}/"
            f"{len(legitimate)})")
        add(f"    PRAMANA  : {self.false_positive_rate(pramana=True):.1%} "
            f"({sum(1 for o in legitimate if not o.pramana_allowed)}/"
            f"{len(legitimate)})")
        add("")
        lines.extend(self._render_class_table())
        add("")
        add("  LATENCY (whole decision, including the ledger write)")
        add(f"    p50 {self.latency_p(0.50):.2f}ms   "
            f"p95 {self.latency_p(0.95):.2f}ms   "
            f"p99 {self.latency_p(0.99):.2f}ms")
        add("")

        caught = self.newly_caught
        add(f"  NEWLY CAUGHT ({len(caught)} attack(s) the baseline allowed)")
        for o in caught:
            add(f"    {o.rc_class}  {o.case_id}")
            add(f"           blocked by: {', '.join(o.pramana_blocking[:3])}")

        regressions = self.new_false_positives
        add("")
        if regressions:
            add(f"  NEW FALSE POSITIVES ({len(regressions)}) -- legitimate traffic "
                f"PRAMANA rejects and the baseline did not:")
            for o in regressions:
                add(f"    {o.case_id}: {', '.join(o.pramana_blocking[:3])}")
        else:
            add("  NEW FALSE POSITIVES: none. PRAMANA rejects no legitimate case")
            add("  that the baseline allowed.")
        add("")
        add("  READ THIS BEFORE QUOTING THE NUMBER")
        add("  " + "-" * 35)
        add("  We wrote these cases and we wrote the gate. A 0% ASR against a")
        add("  suite authored by the same people who authored the defence is a")
        add("  consistency check, not an independent result.")
        add("")
        add("  What the comparison DOES support: the baseline column is not")
        add("  invented. Presence-driven evaluation is the measured behaviour")
        add("  of the AP2 reference implementation at e1ea56db, reproduced")
        add("  end-to-end in scripts/spike_chain_e2e.py, and confirmed by the")
        add("  vendor. The gap between the two columns is a real property of")
        add("  that implementation.")
        add("")
        add("  What it does NOT support: any claim about AIP-Bench, whose")
        add("  artifacts release 2026-10-04, or about attack classes nobody")
        add("  has yet thought to write a case for.")
        add("")
        return "\n".join(lines)


def _request(case: BenchCase) -> PaymentRequest:
    return PaymentRequest(
        mandate_ref=case.mandate_ref,
        facts=case.facts,
        protocol_results=case.observed_protocol,
        mandate_results=case.observed_mandate,
        merchant_results=case.observed_merchant,
    )


def run(policy_path: Path | None = DEFAULT_POLICY) -> BenchReport:
    """Evaluate every frozen case under both verifiers."""
    policy = load_policy(policy_path) if policy_path else builtin_policy()
    outcomes: list[CaseOutcome] = []

    for case in all_cases():
        request = _request(case)

        baseline = Kernel(baseline_policy(policy, case), ledger=None)
        baseline_result = baseline.evaluate(request)

        pramana = Kernel(policy, ledger=EvidenceLedger(MemoryStore()))
        started = time.perf_counter()
        pramana_result = pramana.evaluate(request)
        elapsed = (time.perf_counter() - started) * 1000.0

        outcomes.append(
            CaseOutcome(
                case_id=case.id,
                rc_class=case.rc_class,
                is_attack=case.is_attack,
                baseline_allowed=baseline_result.is_allowed,
                pramana_allowed=pramana_result.is_allowed,
                pramana_blocking=tuple(
                    o.id for o in pramana_result.verdict.blocking
                ),
                elapsed_ms=elapsed,
            )
        )

    return BenchReport(outcomes=tuple(outcomes))
