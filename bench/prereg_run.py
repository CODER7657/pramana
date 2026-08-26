"""Execute the sealed pre-registered set and report it unedited.

The cases and their expected outcomes were committed in `9d0994a`, in a commit
containing no runner. This file is the runner. `git log --follow bench/prereg.py`
shows the ordering, which is the only thing that makes the result mean anything
more than the self-authored numbers already in `pramana bench`.

Nothing here may edit an expectation. If a case fails, it is reported as a
failure and the disagreement is written up. That is the deal that was made when
the set was sealed, and the value of the exercise is entirely in keeping it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from bench.prereg import SEALED_AT, PreregCase, prereg_cases
from pramana.kernel.gate import Kernel, PaymentRequest
from pramana.kernel.verify.policy import builtin_policy


@dataclass(frozen=True, slots=True)
class PreregOutcome:
    case: PreregCase
    allowed: bool
    blocking: tuple[str, ...]

    @property
    def agrees(self) -> bool:
        return self.allowed is self.case.should_allow

    @property
    def kind(self) -> str:
        """Which way a disagreement went, in the regulation's terms."""
        if self.agrees:
            return "agrees"
        return "refused-what-the-rule-permits" if self.case.should_allow else (
            "permitted-what-the-rule-refuses"
        )


def run_prereg() -> tuple[PreregOutcome, ...]:
    policy = builtin_policy()
    kernel = Kernel(policy, ledger=None)
    outcomes: list[PreregOutcome] = []
    for pre in prereg_cases():
        case = pre.case
        result = kernel.evaluate(
            PaymentRequest(
                mandate_ref=hashlib.sha256(case.id.encode()).hexdigest(),
                facts=case.facts,
                protocol_results=case.observed_protocol,
                mandate_results=case.observed_mandate,
                merchant_results=case.observed_merchant,
            )
        )
        outcomes.append(
            PreregOutcome(
                case=pre,
                allowed=result.verdict.is_allowed,
                blocking=tuple(o.id for o in result.verdict.blocking),
            )
        )
    return tuple(outcomes)


def summary(outcomes: tuple[PreregOutcome, ...]) -> dict[str, Any]:
    agreed = [o for o in outcomes if o.agrees]
    tp = sum(1 for o in outcomes if not o.case.should_allow and not o.allowed)
    fn = sum(1 for o in outcomes if not o.case.should_allow and o.allowed)
    fp = sum(1 for o in outcomes if o.case.should_allow and not o.allowed)
    tn = sum(1 for o in outcomes if o.case.should_allow and o.allowed)
    return {
        "sealed_at": SEALED_AT,
        "cases": len(outcomes),
        "agreed": len(agreed),
        "disagreed": len(outcomes) - len(agreed),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "disagreements": [
            {
                "case_id": o.case.case.id,
                "expected": "allow" if o.case.should_allow else "reject",
                "got": "allow" if o.allowed else "reject",
                "kind": o.kind,
                "provision": o.case.provision,
                "reasoning": o.case.reasoning,
                "blocking": list(o.blocking),
            }
            for o in outcomes
            if not o.agrees
        ],
    }


def render(outcomes: tuple[PreregOutcome, ...]) -> str:
    s = summary(outcomes)
    lines = [
        "=" * 72,
        "PRE-REGISTERED TEST SET -- sealed " + str(s["sealed_at"]) + ", run after",
        "=" * 72,
        "  Cases written from the RBI E-mandate Framework 2026 and committed",
        "  with no runner, in 9d0994a. Expectations were fixed before any of",
        "  them had been executed. Results below are unedited.",
        "",
        f"  cases      : {s['cases']}",
        f"  agreed     : {s['agreed']}",
        f"  disagreed  : {s['disagreed']}",
        "",
        "  PRECISION / RECALL on this set (positive class = the regulation",
        "  requires refusal)",
        f"    TP {s['tp']}   FP {s['fp']}   FN {s['fn']}   TN {s['tn']}",
        f"    precision {s['precision']:.3f}   recall {s['recall']:.3f}",
        "",
    ]

    for o in outcomes:
        mark = "  ok  " if o.agrees else " DIFF "
        want = "allow" if o.case.should_allow else "reject"
        got = "allow" if o.allowed else "reject"
        lines.append(f"  [{mark}] {o.case.case.id:<34} want {want:<6} got {got}")

    if s["disagreements"]:
        lines += ["", "  DISAGREEMENTS", "  " + "-" * 30]
        for d in s["disagreements"]:
            lines += [
                f"  {d['case_id']}  ({d['kind']})",
                f"    provision : {d['provision']}",
                f"    we read it as: {d['reasoning']}",
                f"    the gate  : {d['got']}"
                + (f"  blocking={d['blocking']}" if d["blocking"] else ""),
                "",
            ]
        lines += [
            "  A disagreement means the gate and our reading of the",
            "  regulation differ. One of them is wrong. Neither is edited",
            "  away here; see POSTMORTEM.md for which it turned out to be.",
        ]
    else:
        lines += [
            "",
            "  No disagreements. Every case decided the way the regulation",
            "  reads. Note what this does and does not establish: the",
            "  expectations were fixed before execution, which rules out",
            "  tuning them to the result -- but the same person wrote the",
            "  cases and the gate, so this is pre-registration, not blinding.",
        ]

    lines += [
        "",
        "  A genuinely held-out set needs a different author or production",
        "  traffic. AIP-Bench releases 2026-10-04. Neither is available yet,",
        "  and this is not a substitute for either.",
    ]
    return "\n".join(lines)
