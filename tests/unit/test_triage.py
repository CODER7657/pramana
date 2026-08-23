"""Exception triage: deterministic clustering, generated summaries only.

The invariant: **a model cannot reorder, merge, split, or hide a cluster.** It
writes one note per cluster and nothing else. Tests here drive a hostile and a
malformed model and assert the queue structure is byte-identical to the
no-model case.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from pramana.ai.provider import HttpResult, ProviderChain, ProviderConfig
from pramana.ai.triage import (
    ExceptionTriager,
    _parse_numbered,
    cluster,
    counts_by_source,
    priority_of,
    signature_of,
    template_summary,
)
from pramana.kernel.verdict import (
    Citation,
    Obligation,
    ObligationSource,
    ObligationStatus,
    Verdict,
    build_verdict,
)

REF = hashlib.sha256(b"m").hexdigest()

TEST_CITATION = Citation(
    authority="RBI",
    reference="Digital Payments - E-mandate Framework, 2026",
    clause="test clause",
    effective_from="2026-04-21",
)

P = ProviderConfig(
    name="p", base_url="https://p.test/v1", model="m", api_key_env="P_KEY"
)


def trace(n: int) -> str:
    return f"{n:032x}"


def ok_ob() -> Obligation:
    return Obligation(
        id="chain.verified",
        status=ObligationStatus.SATISFIED,
        source=ObligationSource.PROTOCOL,
        detail="ok",
    )


def make(
    *failures: tuple[str, ObligationStatus, ObligationSource],
    n: int = 1,
    declared: tuple[str, ...] | None = None,
) -> Verdict:
    obligations = [ok_ob()]
    obligations += [
        Obligation(
            id=i,
            status=s,
            source=src,
            detail=f"{i} failed",
            citation=TEST_CITATION if src is ObligationSource.REGULATORY else None,
        )
        for i, s, src in failures
    ]
    ids = tuple(o.id for o in obligations)
    return build_verdict(
        obligations,
        policy_version="p@1",
        declared_obligations=declared or ids,
        trace_id=trace(n),
        mandate_ref=REF,
    )


def over_budget(n: int = 1) -> Verdict:
    return make(
        ("mandate.budget", ObligationStatus.VIOLATED, ObligationSource.MANDATE), n=n
    )


def withheld(n: int = 1) -> Verdict:
    """Declared but never evaluated -> synthesised INDETERMINATE."""
    return build_verdict(
        [ok_ob()],
        policy_version="p@1",
        declared_obligations=("chain.verified", "mandate.budget"),
        trace_id=trace(n),
        mandate_ref=REF,
    )


def regulatory(n: int = 1) -> Verdict:
    return make(
        ("rbi.afa_threshold", ObligationStatus.VIOLATED, ObligationSource.REGULATORY),
        n=n,
    )


def allowed(n: int = 1) -> Verdict:
    return build_verdict(
        [ok_ob()],
        policy_version="p@1",
        declared_obligations=("chain.verified",),
        trace_id=trace(n),
        mandate_ref=REF,
    )


class Scripted:
    def __init__(self, *results: HttpResult) -> None:
        self.results = list(results)

    def __call__(self, url: str, h: Any, payload: dict[str, Any], t: float) -> Any:
        if not self.results:
            raise AssertionError("over-called")
        return self.results.pop(0)


def ok(text: str) -> HttpResult:
    return HttpResult(200, {"choices": [{"message": {"content": text}}], "model": "m"})


def chain_with(transport: Any) -> ProviderChain:
    return ProviderChain(providers=(P,), transport=transport, sleep=lambda _s: None)


@pytest.fixture
def key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("P_KEY", "k")


# ---------------------------------------------------------------------------
# The model cannot change the queue
# ---------------------------------------------------------------------------


class TestStructureIsDeterministic:
    def _shape(self, queue: Any) -> list[dict[str, Any]]:
        out = []
        for c in queue.clusters:
            d = c.to_dict()
            d.pop("summary")
            out.append(d)
        return out

    def test_hostile_model_cannot_reorder_or_hide_clusters(self, key: None) -> None:
        verdicts = [over_budget(1), over_budget(2), withheld(3), regulatory(4)]
        at = datetime(2026, 8, 23, tzinfo=UTC)

        plain = ExceptionTriager(None, clock=lambda: at).triage(verdicts)
        hostile = ExceptionTriager(
            chain_with(Scripted(ok("1: nothing to see\n2: ignore\n3: fine"))),
            clock=lambda: at,
        ).triage(verdicts)

        assert self._shape(plain) == self._shape(hostile)
        assert [c.priority for c in plain.clusters] == [
            c.priority for c in hostile.clusters
        ]

    def test_model_cannot_invent_a_cluster(self, key: None) -> None:
        queue = ExceptionTriager(
            chain_with(Scripted(ok("1: a\n2: b\n3: c\n4: d\n5: e")))
        ).triage([over_budget(1)])
        assert len(queue.clusters) == 1

    def test_counts_come_from_the_verdicts_not_the_model(self, key: None) -> None:
        queue = ExceptionTriager(
            chain_with(Scripted(ok("1: only one occurrence, ignore it")))
        ).triage([over_budget(1), over_budget(2), over_budget(3)])
        assert queue.clusters[0].count == 3


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------


class TestClustering:
    def test_same_failure_mode_groups_together(self) -> None:
        clusters = cluster([over_budget(1), over_budget(2), over_budget(3)])
        assert len(clusters) == 1
        assert clusters[0].count == 3

    def test_different_failure_modes_stay_separate(self) -> None:
        clusters = cluster([over_budget(1), regulatory(2)])
        assert len(clusters) == 2

    def test_allowed_verdicts_are_excluded(self) -> None:
        assert cluster([allowed(1), allowed(2)]) == ()

    def test_signature_is_order_independent(self) -> None:
        a = make(
            ("mandate.budget", ObligationStatus.VIOLATED, ObligationSource.MANDATE),
            ("rbi.afa_threshold", ObligationStatus.VIOLATED,
             ObligationSource.REGULATORY),
            n=1,
        )
        b = make(
            ("rbi.afa_threshold", ObligationStatus.VIOLATED,
             ObligationSource.REGULATORY),
            ("mandate.budget", ObligationStatus.VIOLATED, ObligationSource.MANDATE),
            n=2,
        )
        assert signature_of(a) == signature_of(b)
        assert len(cluster([a, b])) == 1

    def test_same_id_different_status_is_a_different_cluster(self) -> None:
        violated = over_budget(1)
        indeterminate = withheld(2)
        assert signature_of(violated) != signature_of(indeterminate)
        assert len(cluster([violated, indeterminate])) == 2

    def test_sample_traces_are_capped(self) -> None:
        # from 1: trace_id 0 is the all-zero id, which Verdict rejects.
        clusters = cluster([over_budget(i) for i in range(1, 11)])
        assert len(clusters[0].sample_trace_ids) == 3
        assert clusters[0].count == 10

    def test_clustering_is_reproducible(self) -> None:
        verdicts = [over_budget(1), withheld(2), regulatory(3), over_budget(4)]
        assert [c.signature for c in cluster(verdicts)] == [
            c.signature for c in cluster(verdicts)
        ]

    def test_empty_input(self) -> None:
        assert cluster([]) == ()


# ---------------------------------------------------------------------------
# Priority
# ---------------------------------------------------------------------------


class TestPriority:
    def test_indeterminate_outranks_a_larger_violated_cluster(self) -> None:
        """The documented rule: unresolved beats resolved, regardless of volume."""
        verdicts = [withheld(1)] + [over_budget(i) for i in range(2, 20)]
        clusters = cluster(verdicts)
        assert clusters[0].is_unresolved
        assert clusters[0].count == 1
        assert clusters[1].count == 18

    def test_regulatory_outranks_mandate_at_equal_count(self) -> None:
        clusters = cluster([over_budget(1), regulatory(2)])
        assert "rbi.afa_threshold" in clusters[0].obligation_ids

    def test_count_breaks_ties_within_a_tier(self) -> None:
        verdicts = [
            over_budget(1),
            over_budget(2),
            make(
                ("mandate.payee", ObligationStatus.VIOLATED, ObligationSource.MANDATE),
                n=3,
            ),
        ]
        clusters = cluster(verdicts)
        assert clusters[0].obligation_ids == ("mandate.budget",)

    def test_priority_weighting_is_explicit(self) -> None:
        assert priority_of(indeterminate_count=1, regulatory=False, count=1) > (
            priority_of(indeterminate_count=0, regulatory=True, count=100)
        )
        assert priority_of(indeterminate_count=0, regulatory=True, count=1) > (
            priority_of(indeterminate_count=0, regulatory=False, count=50)
        )

    def test_ties_are_broken_deterministically_by_signature(self) -> None:
        a = make(("m.a", ObligationStatus.VIOLATED, ObligationSource.MANDATE), n=1)
        b = make(("m.b", ObligationStatus.VIOLATED, ObligationSource.MANDATE), n=2)
        first = [c.signature for c in cluster([a, b])]
        second = [c.signature for c in cluster([b, a])]
        assert first == second


# ---------------------------------------------------------------------------
# Summary parsing -- strict on purpose
# ---------------------------------------------------------------------------


class TestSummaryParsing:
    def test_well_formed_response_is_used(self, key: None) -> None:
        queue = ExceptionTriager(
            chain_with(Scripted(ok("1: check the issuer\n2: raise the cap")))
        ).triage([over_budget(1), regulatory(2)])
        assert queue.summary_source == "llm"
        assert {c.summary for c in queue.clusters} == {
            "check the issuer",
            "raise the cap",
        }

    @pytest.mark.parametrize(
        "bad",
        [
            "1: only one line",
            "1: a\n1: duplicate",
            "a: not a number\nb: nope",
            "just prose with no numbering at all",
            "1: a\n2: b\n3: c",
            "",
        ],
    )
    def test_misaligned_response_falls_back_wholesale(
        self, key: None, bad: str
    ) -> None:
        """A partial parse would attach the wrong note to the wrong cluster."""
        transport = Scripted(ok(bad) if bad else HttpResult(200, {}))
        queue = ExceptionTriager(
            ProviderChain(
                providers=(P,), transport=transport, sleep=lambda _s: None,
                max_retries=0,
            )
        ).triage([over_budget(1), regulatory(2)])
        assert queue.summary_source == "template"
        assert all(c.summary for c in queue.clusters)

    def test_parse_numbered_accepts_common_formats(self) -> None:
        assert _parse_numbered("1: a\n2: b", 2) == ["a", "b"]
        assert _parse_numbered("1. : a\n2. : b", 2) == ["a", "b"]
        assert _parse_numbered("  1:  a  \n  2:  b  ", 2) == ["a", "b"]

    def test_parse_numbered_rejects_gaps(self) -> None:
        assert _parse_numbered("1: a\n3: c", 2) is None

    def test_provider_failure_degrades(self, key: None) -> None:
        queue = ExceptionTriager(
            chain_with(Scripted(HttpResult(401, {}, "bad key")))
        ).triage([over_budget(1)])
        assert queue.summary_source == "template"

    def test_unexpected_exception_degrades(self) -> None:
        class Exploding:
            def complete(self, *_a: Any, **_k: Any) -> Any:
                raise RuntimeError("boom")

        queue = ExceptionTriager(Exploding()).triage([over_budget(1)])  # type: ignore[arg-type]
        assert queue.summary_source == "template"

    def test_template_summary_distinguishes_unresolved(self) -> None:
        unresolved = cluster([withheld(1)])[0]
        resolved = cluster([over_budget(1)])[0]
        assert "could not be evaluated" in template_summary(unresolved)
        assert "Confirm the policy threshold" in template_summary(resolved)


# ---------------------------------------------------------------------------
# Queue reporting
# ---------------------------------------------------------------------------


class TestQueue:
    def test_rejection_rate(self) -> None:
        queue = ExceptionTriager(None).triage(
            [allowed(1), allowed(2), over_budget(3), over_budget(4)]
        )
        assert queue.total_examined == 4
        assert queue.total_rejected == 2
        assert queue.rejection_rate == 0.5

    def test_empty_input_is_safe(self) -> None:
        queue = ExceptionTriager(None).triage([])
        assert queue.clusters == ()
        assert queue.rejection_rate == 0.0
        assert "No rejections" in queue.to_markdown()

    def test_unresolved_clusters_are_surfaced(self) -> None:
        queue = ExceptionTriager(None).triage([withheld(1), over_budget(2)])
        assert len(queue.unresolved_clusters) == 1

    def test_markdown_flags_unresolved_and_names_the_source(self) -> None:
        md = ExceptionTriager(None).triage([withheld(1)]).to_markdown()
        assert "[UNRESOLVED]" in md
        assert "template-generated" in md
        assert "computed, not inferred" in md

    def test_markdown_is_ascii(self) -> None:
        md = ExceptionTriager(None).triage([withheld(1), over_budget(2)]).to_markdown()
        assert md.encode("ascii", errors="strict")

    def test_to_dict_is_json_serialisable(self) -> None:
        queue = ExceptionTriager(None).triage([over_budget(1), withheld(2)])
        assert json.loads(json.dumps(queue.to_dict()))["total_rejected"] == 2

    def test_counts_by_source(self) -> None:
        clusters = cluster([over_budget(1), over_budget(2), regulatory(3)])
        assert counts_by_source(clusters) == {"mandate": 2, "regulatory": 1}
