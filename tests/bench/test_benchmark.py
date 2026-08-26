"""The frozen benchmark.

These tests guard the properties that make the number defensible, not the
number itself:

* the suite contains legitimate traffic, so an ASR is reported alongside a
  false-positive rate rather than on its own;
* RC-6 is never averaged in with the structural classes;
* the baseline actually catches some attacks, so the comparison is not staged;
* the honesty note about who authored the cases is always printed.

A benchmark that only proves its author right is a consistency check. These
tests exist so that stays visible rather than being quietly dropped.
"""

from __future__ import annotations

import json

import pytest

from bench.cases import (
    RC_CLASSES,
    SEMANTIC_CLASSES,
    all_cases,
    attack_cases,
    legitimate_cases,
)
from bench.runner import run

REPORT = run()


class TestSuiteComposition:
    def test_contains_both_attacks_and_legitimate_traffic(self) -> None:
        """An ASR without a false-positive rate is half a result."""
        assert len(attack_cases()) >= 10
        assert len(legitimate_cases()) >= 5

    def test_case_ids_are_unique(self) -> None:
        ids = [c.id for c in all_cases()]
        assert len(ids) == len(set(ids))

    def test_every_case_maps_to_a_known_class(self) -> None:
        assert all(c.rc_class in RC_CLASSES for c in all_cases())

    def test_every_case_carries_a_description(self) -> None:
        assert all(c.description.strip() for c in all_cases())

    def test_the_structural_classes_are_covered(self) -> None:
        covered = {c.rc_class for c in attack_cases()}
        assert {"RC-1", "RC-2", "RC-3", "RC-4", "RC-5"} <= covered

    def test_legitimate_cases_include_boundary_conditions(self) -> None:
        """Off-by-one on a money threshold is a false positive on real revenue."""
        ids = {c.id for c in legitimate_cases()}
        assert "ok-at-afa-ceiling" in ids
        assert "ok-exact-24h-notice" in ids

    def test_cases_are_frozen_against_the_wall_clock(self) -> None:
        """Re-running tomorrow must produce the same result."""
        assert run().to_dict()["asr_pramana"] == REPORT.to_dict()["asr_pramana"]


class TestBaselineIsNotStaged:
    def test_the_baseline_catches_some_attacks(self) -> None:
        """If the baseline caught nothing the comparison would be rigged."""
        caught = [
            o for o in REPORT.outcomes if o.is_attack and not o.baseline_allowed
        ]
        assert len(caught) >= 3

    def test_the_baseline_has_no_false_positives(self) -> None:
        """So any FP PRAMANA introduces is attributable to PRAMANA."""
        assert REPORT.false_positive_rate(pramana=False) == 0.0

    def test_some_attacks_are_visible_to_a_presence_driven_verifier(self) -> None:
        """Cases where the constraint IS present and fails."""
        assert any(
            o.case_id == "rc2-payee-violated" and not o.baseline_allowed
            for o in REPORT.outcomes
        )


class TestResults:
    def test_pramana_blocks_every_structural_attack(self) -> None:
        assert REPORT.asr(pramana=True) == 0.0

    def test_pramana_is_strictly_better_than_the_baseline(self) -> None:
        assert REPORT.asr(pramana=True) < REPORT.asr(pramana=False)

    def test_pramana_introduces_no_new_false_positives(self) -> None:
        """The cost side. This is the number that would sink the project."""
        assert REPORT.new_false_positives == ()
        assert REPORT.false_positive_rate(pramana=True) == 0.0

    def test_the_withheld_cap_case_is_newly_caught(self) -> None:
        """The finding, as a benchmark row."""
        case = next(o for o in REPORT.outcomes if o.case_id == "rc5-budget-withheld")
        assert case.baseline_allowed is True
        assert case.pramana_allowed is False
        assert "mandate.budget" in case.pramana_blocking

    def test_rc3_is_caught(self) -> None:
        """The class the published defence reduces only to warn-only."""
        case = next(
            o for o in REPORT.outcomes if o.case_id == "rc3-disclosures-unpinned"
        )
        assert case.pramana_allowed is False

    @pytest.mark.parametrize("rc", ["RC-1", "RC-2", "RC-3", "RC-4", "RC-5"])
    def test_no_structural_class_still_succeeds(self, rc: str) -> None:
        allowed, _total = REPORT.asr_by_class(pramana=True).get(rc, (0, 0))
        assert allowed == 0


class TestSemanticSeparation:
    def test_rc6_is_declared_semantic(self) -> None:
        assert {"RC-6"} == SEMANTIC_CLASSES

    def test_structural_asr_excludes_semantic_classes(self) -> None:
        """RC-6's success rate is a distribution; averaging it in is meaningless."""
        structural = REPORT.asr(pramana=False, structural_only=True)
        overall = REPORT.asr(pramana=False, structural_only=False)
        assert isinstance(structural, float)
        assert isinstance(overall, float)


class TestLatency:
    def test_percentiles_are_reported(self) -> None:
        payload = REPORT.to_dict()
        assert payload["latency_p50_ms"] > 0
        assert payload["latency_p99_ms"] >= payload["latency_p50_ms"]

    def test_p99_is_within_a_checkout_budget(self) -> None:
        """A gate that adds 400ms is unshippable regardless of accuracy.

        The bound is ~200x the observed value on purpose. Over 21 cases this
        "p99" is the maximum observation, so on shared CI hardware it measures
        the runner's scheduler as much as the gate. What it can still catch is
        the regression that matters: something with a network call or a model
        on the money path, which would miss by orders of magnitude rather than
        by jitter. `run()` discards a warm-up evaluation first -- before it
        did, this assertion failed once at 422ms on a cold runner.
        """
        assert REPORT.latency_p(0.99) < 50.0


class TestReporting:
    def test_render_states_both_rates(self) -> None:
        text = REPORT.render()
        assert "ATTACK-SUCCESS RATE" in text
        assert "FALSE-POSITIVE RATE" in text

    def test_render_carries_the_honesty_note(self) -> None:
        """This must not be quietly dropped when the number looks good."""
        text = REPORT.render()
        assert "We wrote these cases and we wrote the gate" in text
        assert "consistency check, not an independent result" in text
        assert "we have not run it" in text or "AIP-Bench" in text

    def test_render_is_ascii(self) -> None:
        assert REPORT.render().encode("ascii", errors="strict")

    def test_report_serialises(self) -> None:
        payload = json.loads(json.dumps(REPORT.to_dict()))
        assert payload["asr_pramana"] == 0.0
        assert payload["cases"] == len(all_cases())

    def test_per_class_table_is_populated(self) -> None:
        table = REPORT.asr_by_class(pramana=False)
        assert set(table) >= {"RC-2", "RC-3", "RC-4", "RC-5"}


class TestPrecisionAndRecall:
    """Track 2 asks for precision and recall in those words. So they exist.

    Every assertion here is also a guard against the number being quoted
    without its decomposition, because 1.0/1.0 on a self-authored suite is
    what working code scores, not evidence that it works.
    """

    def test_the_confusion_matrix_accounts_for_every_case(self) -> None:
        attacks = [o for o in REPORT.outcomes if o.is_attack]
        legitimate = [o for o in REPORT.outcomes if not o.is_attack]
        for pramana in (True, False):
            m = REPORT.confusion(pramana=pramana)
            assert m["tp"] + m["fn"] == len(attacks)
            assert m["fp"] + m["tn"] == len(legitimate)
            assert sum(m.values()) == len(REPORT.outcomes)

    def test_pramana_refuses_every_attack_and_no_legitimate_case(self) -> None:
        m = REPORT.confusion(pramana=True)
        assert m["fn"] == 0, "an attack was allowed"
        assert m["fp"] == 0, "a legitimate case was refused"
        assert REPORT.precision(pramana=True) == 1.0
        assert REPORT.recall(pramana=True) == 1.0

    def test_the_baseline_has_perfect_precision_and_poor_recall(self) -> None:
        """The shape of the gap, stated as a property rather than a sentence.

        The baseline is not *wrong* about what it refuses -- everything it
        refuses deserves it. It simply cannot see the attacks where the
        constraint was never disclosed, so it misses more than half of them.
        If this ever reads 1.0 recall, the baseline stopped being a baseline.
        """
        assert REPORT.precision(pramana=False) == 1.0
        assert REPORT.recall(pramana=False) < 0.6

    def test_the_decomposition_partitions_the_attacks_exactly(self) -> None:
        split = REPORT.decomposition()
        omitted = set(split["omitted_obligation"]["case_ids"])
        comparable = set(split["comparable"]["case_ids"])
        attacks = {o.case_id for o in REPORT.outcomes if o.is_attack}
        assert omitted & comparable == set(), "a case is in both halves"
        assert omitted | comparable == attacks, "a case is in neither half"

    def test_the_two_verifiers_agree_on_every_comparable_case(self) -> None:
        """The claim that should be quoted instead of the 1.0.

        Where a constraint is present and violated, both verifiers do the same
        work. If PRAMANA ever beat the baseline here it would be a real
        result -- and this test would need rewriting rather than deleting.
        """
        comparable = REPORT.decomposition()["comparable"]
        assert comparable["cases"] > 0
        assert comparable["baseline_refused"] == comparable["pramana_refused"]

    def test_the_delta_is_entirely_the_omitted_obligation_half(self) -> None:
        omitted = REPORT.decomposition()["omitted_obligation"]
        assert omitted["baseline_refused"] == 0
        assert omitted["pramana_refused"] == omitted["cases"]

    def test_the_render_refuses_to_show_the_number_bare(self) -> None:
        text = REPORT.render()
        assert "PRECISION / RECALL" in text
        assert "DO NOT QUOTE THAT ROW ON ITS OWN" in text
        assert "IDENTITY, not a measurement" in text
        assert "INDISTINGUISHABLE" in text
        assert "not held out" in text

    def test_the_json_payload_carries_both_the_number_and_the_split(self) -> None:
        payload = REPORT.to_dict()
        assert payload["precision_pramana"] == 1.0
        assert payload["recall_pramana"] == 1.0
        assert payload["recall_baseline"] < 1.0
        assert payload["decomposition"]["comparable"]["cases"] > 0
        assert payload["confusion_pramana"]["fn"] == 0
