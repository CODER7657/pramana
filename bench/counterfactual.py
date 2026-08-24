"""Blast-radius analysis: what a policy change would have done, before shipping it.

You have an immutable record of decisions, a versioned policy, and a kernel that
is deterministic. Those three facts compose into something a probabilistic
scorer structurally cannot offer: **re-decide the past under a candidate rule
and see exactly what moves.**

    12 would flip REJECT -> ALLOW   (INR 1,84,000 of previously-refused volume)
     3 would flip ALLOW  -> REJECT  (INR 47,500 -- review these before shipping)

This is the thing you actually need before touching a production policy, and it
is the natural home for the false-positive cost Track 2 asks for: a candidate
policy's cost is not a rate, it is the rupees of legitimate volume it starts
refusing.

What it replays, and why not the ledger
---------------------------------------

It replays a **corpus of requests** -- the frozen attack cases and the
legitimate corpus -- not the evidence ledger, and that is a real limitation
stated rather than papered over.

Re-deciding a ledgered verdict under a different policy requires the *facts*
that produced it, and ``LedgerRecord`` stores the verdict, not the request. It
was designed as evidence of a decision rather than as a replay log. Persisting
the facts alongside would make this run over real history, and it would mean
extending what the record hash commits to; until that ships, replaying the
corpus is what the data supports. A version that claimed to replay production
history while actually replaying twelve authored cases would be exactly the
kind of claim this project exists to refuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bench.cases import BenchCase, all_cases
from bench.corpus import CorpusCase, corpus
from bench.runner import _request
from pramana.kernel.gate import Kernel
from pramana.kernel.verify.policy import Policy, builtin_policy, load_policy

RUPEE = 100
"""Paise per rupee. Named because a bare 100 in money code is how units rot."""


@dataclass(frozen=True, slots=True)
class Flip:
    """One case that decides differently under the candidate policy."""

    case_id: str
    title: str
    was_allowed: bool
    now_allowed: bool
    value_paise: int
    monthly_count: int
    is_attack: bool
    blocking_now: tuple[str, ...]

    @property
    def direction(self) -> str:
        return "REJECT -> ALLOW" if self.now_allowed else "ALLOW -> REJECT"

    @property
    def monthly_paise(self) -> int:
        return self.value_paise * self.monthly_count

    @property
    def weighted(self) -> bool:
        """Whether this case carries a volume. Attack cases do not.

        Rendering an unweighted case as "INR 0" would read as "this change is
        free", which is the opposite of what a missing weight means.
        """
        return self.value_paise > 0

    @property
    def money(self) -> str:
        return _inr(self.monthly_paise) if self.weighted else "(unweighted)"


@dataclass(frozen=True, slots=True)
class Counterfactual:
    """Every difference between two policies over the same requests."""

    baseline_version: str
    candidate_version: str
    flips: tuple[Flip, ...]
    cases_replayed: int
    legitimate_gmv_paise: int

    @property
    def loosened(self) -> tuple[Flip, ...]:
        return tuple(f for f in self.flips if f.now_allowed)

    @property
    def tightened(self) -> tuple[Flip, ...]:
        return tuple(f for f in self.flips if not f.now_allowed)

    @property
    def newly_refused_paise(self) -> int:
        """Legitimate volume the candidate starts refusing. The cost."""
        return sum(f.monthly_paise for f in self.tightened if not f.is_attack)

    @property
    def newly_allowed_attacks(self) -> tuple[Flip, ...]:
        """Attacks the candidate starts letting through. The risk."""
        return tuple(f for f in self.loosened if f.is_attack)

    @property
    def newly_allowed_paise(self) -> int:
        return sum(f.monthly_paise for f in self.loosened if not f.is_attack)

    def render(self) -> str:
        rows: list[str] = []
        add = rows.append
        add("=" * 72)
        add("COUNTERFACTUAL POLICY REPLAY")
        add("=" * 72)
        add(f"  baseline    : {self.baseline_version}")
        add(f"  candidate   : {self.candidate_version}")
        add(f"  replayed    : {self.cases_replayed} requests "
            f"(frozen attack cases + legitimate corpus)")
        add(f"  monthly GMV : {_inr(self.legitimate_gmv_paise)} of legitimate "
            f"volume represented")
        add("")

        if not self.flips:
            add("  No decision changes. The candidate policy is behaviourally")
            add("  identical to the baseline over this corpus.")
            add("")
        else:
            add(f"  {len(self.loosened)} would flip REJECT -> ALLOW"
                f"   ({_inr(self.newly_allowed_paise)}/month of previously-"
                f"refused legitimate volume)")
            for flip in self.loosened:
                marker = "  ** ATTACK **" if flip.is_attack else ""
                add(f"      {flip.case_id:<32} {flip.money:>16}{marker}")
            add("")
            add(f"  {len(self.tightened)} would flip ALLOW -> REJECT"
                f"   ({_inr(self.newly_refused_paise)}/month of legitimate "
                f"volume newly refused)")
            for flip in self.tightened:
                add(f"      {flip.case_id:<32} {flip.money:>16}")
                add(f"        blocked by: {', '.join(flip.blocking_now[:3])}")
            add("")

        rows.extend(self._verdict_lines())
        return "\n".join(rows)

    def _verdict_lines(self) -> list[str]:
        """The line a reviewer needs before approving a policy change."""
        rows: list[str] = []
        add = rows.append
        add("  BEFORE SHIPPING THIS POLICY")
        add("  " + "-" * 27)
        if self.newly_allowed_attacks:
            add("  *** This candidate ALLOWS attacks the baseline blocked: ***")
            for flip in self.newly_allowed_attacks:
                add(f"      {flip.case_id}")
        elif self.newly_refused_paise:
            add(f"  Costs {_inr(self.newly_refused_paise)}/month in refused")
            add("  legitimate volume. That is the false-positive cost, in the")
            add("  unit a risk team budgets in.")
        else:
            add("  No new attack is allowed and no legitimate volume is newly")
            add("  refused over this corpus.")
        add("")
        add("  Scope: this replays an authored corpus, not production history.")
        add("  The evidence ledger stores verdicts, not the request facts that")
        add("  produced them, so real history cannot be re-decided until those")
        add("  are persisted. See bench/counterfactual.py.")
        return rows


def _inr(paise: int) -> str:
    return f"INR {paise / RUPEE:,.0f}"


def _decide(policy: Policy, case: BenchCase) -> tuple[bool, tuple[str, ...]]:
    result = Kernel(policy).evaluate(_request(case))
    return result.is_allowed, tuple(o.id for o in result.verdict.blocking)


def _weighted() -> dict[str, CorpusCase]:
    return {c.case.id: c for c in corpus()}


def compare(candidate: Policy, baseline: Policy | None = None) -> Counterfactual:
    """Re-decide every case under both policies and report the differences."""
    base = baseline or builtin_policy()
    weights = _weighted()
    cases = list(all_cases()) + [c.case for c in corpus()]

    flips: list[Flip] = []
    for case in cases:
        was_allowed, _ = _decide(base, case)
        now_allowed, blocking_now = _decide(candidate, case)
        if was_allowed == now_allowed:
            continue
        weighted = weights.get(case.id)
        flips.append(
            Flip(
                case_id=case.id,
                title=case.title,
                was_allowed=was_allowed,
                now_allowed=now_allowed,
                value_paise=weighted.value_paise if weighted else 0,
                monthly_count=weighted.monthly_count if weighted else 1,
                is_attack=case.is_attack,
                blocking_now=blocking_now,
            )
        )

    return Counterfactual(
        baseline_version=base.version,
        candidate_version=candidate.version,
        flips=tuple(flips),
        cases_replayed=len(cases),
        legitimate_gmv_paise=sum(c.monthly_paise for c in corpus()),
    )


def compare_path(path: Path | str, baseline: Policy | None = None) -> Counterfactual:
    """Load a candidate policy from disk and compare it to the shipped one."""
    return compare(load_policy(Path(path)), baseline)
