"""Blast-radius analysis, and the corpus that gives it a unit.

The point of both is that a rate hides the thing a risk team needs. We shipped
a rule that refused every insurance premium between INR 15,000 and INR 1,00,000
while the false-positive rate read 0.0%, because no case covered it. These
tests hold the rupee column honest and check that a policy change cannot loosen
a control quietly.
"""

from __future__ import annotations

import dataclasses

from bench.corpus import corpus, monthly_gmv_paise
from bench.counterfactual import compare
from bench.runner import _request
from pramana.kernel.gate import Kernel
from pramana.kernel.verify.policy import ObligationSpec, Policy, builtin_policy

BASE = builtin_policy()


def _with_param(policy: Policy, obligation_id: str, **params: object) -> Policy:
    specs: list[ObligationSpec] = []
    for spec in policy.obligations:
        if spec.id != obligation_id:
            specs.append(spec)
            continue
        merged = dict(spec.params)
        merged.update(params)
        specs.append(dataclasses.replace(spec, params=merged))
    return dataclasses.replace(
        policy, version=f"{policy.version}-candidate", obligations=tuple(specs)
    )


class TestTheCorpusIsLegitimateTraffic:
    def test_the_shipped_policy_refuses_none_of_it(self) -> None:
        kernel = Kernel(BASE)
        refused = [
            entry.case.id
            for entry in corpus()
            if not kernel.evaluate(_request(entry.case)).is_allowed
        ]
        assert refused == []

    def test_every_case_carries_a_value_and_a_provenance(self) -> None:
        """A case with no basis is a case somebody invented to pass."""
        for entry in corpus():
            assert entry.value_paise > 0, entry.case.id
            assert entry.monthly_count > 0, entry.case.id
            assert "E-mandate Framework 2026" in entry.basis, entry.case.id

    def test_it_covers_both_ceilings_and_both_boundaries(self) -> None:
        amounts = {entry.value_paise for entry in corpus()}
        assert 1_500_000 in amounts, "the AFA-free ceiling, exactly"
        assert 10_000_000 in amounts, "the enhanced ceiling, exactly"

    def test_it_includes_the_category_we_once_refused_wholesale(self) -> None:
        """INR 50,000 insurance, no AFA. The bug that a 0.0% rate hid."""
        entry = next(e for e in corpus() if e.case.id == "insurance-annual")
        assert entry.case.facts.category == "insurance"
        assert entry.case.facts.afa_performed is False
        assert entry.value_paise == 5_000_000

    def test_the_monthly_volume_is_the_sum_of_its_parts(self) -> None:
        assert monthly_gmv_paise() == sum(e.monthly_paise for e in corpus())


class TestCounterfactual:
    def test_an_identical_policy_moves_nothing(self) -> None:
        report = compare(BASE, BASE)
        assert report.flips == ()
        assert report.newly_refused_paise == 0

    def test_tightening_a_ceiling_costs_measurable_rupees(self) -> None:
        """The false-positive cost of a policy change, in the unit that matters."""
        candidate = _with_param(BASE, "rbi.afa_threshold", ceiling_paise=500_000)
        report = compare(candidate)
        assert report.tightened, "a lower ceiling must refuse something"
        assert report.newly_refused_paise > 0
        assert report.newly_allowed_attacks == ()

    def test_loosening_a_ceiling_is_reported_as_allowing_an_attack(self) -> None:
        candidate = _with_param(
            BASE, "rbi.afa_threshold", ceiling_paise=100_000_000
        )
        report = compare(candidate)
        allowed = {f.case_id for f in report.newly_allowed_attacks}
        assert "rbi-afa-breach" in allowed

    def test_an_unweighted_case_is_not_rendered_as_free(self) -> None:
        """"INR 0" would read as "this change costs nothing", which inverts it."""
        candidate = _with_param(
            BASE, "rbi.afa_threshold", ceiling_paise=100_000_000
        )
        flip = next(iter(compare(candidate).newly_allowed_attacks))
        assert not flip.weighted
        assert flip.money == "(unweighted)"

    def test_it_replays_both_corpora(self) -> None:
        report = compare(BASE, BASE)
        assert report.cases_replayed == 21 + len(corpus())

    def test_the_render_states_its_own_scope_limit(self) -> None:
        """The ledger cannot be replayed, and the output has to say so."""
        text = compare(BASE, BASE).render()
        assert "not production history" in text
        assert "stores verdicts, not the request facts" in text
