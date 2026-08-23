"""Policy loading, and the RBI predicates it drives.

Two themes run through this file:

* A policy cannot assert a legal requirement without citing it, and cannot
  declare an advisory signal. Both are load-time errors.
* Every predicate treats missing evidence as INDETERMINATE. A predicate that
  cannot see whether AFA happened does not get to assume it did.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pramana.kernel.verdict import ObligationSource, ObligationStatus
from pramana.kernel.verify.policy import (
    ObligationSpec,
    Policy,
    PolicyError,
    load_policy,
)
from pramana.kernel.verify.rbi import PaymentFacts, evaluate

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
POLICY_PATH = Path("policies/rbi-in.yaml")

MINIMAL = """
version: "t@1"
obligations:
  - id: chain.verified
    source: protocol
    description: d
"""


def spec_for(obligation_id: str) -> ObligationSpec:
    policy = load_policy(POLICY_PATH)
    found = policy.spec(obligation_id)
    assert found is not None, obligation_id
    return found


def compliant(**overrides: object) -> PaymentFacts:
    base = {
        "amount_paise": 500_000,
        "currency": "INR",
        "category": "groceries",
        "afa_performed": False,
        "afa_at_registration": True,
        "pre_debit_notice_at": NOW - timedelta(hours=30),
        "execution_at": NOW,
        "mandate_valid_from": NOW - timedelta(days=30),
        "mandate_valid_until": NOW + timedelta(days=30),
    }
    base.update(overrides)
    return PaymentFacts(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


class TestLoading:
    def test_shipped_policy_loads(self) -> None:
        policy = load_policy(POLICY_PATH)
        assert policy.version == "rbi-in@1"
        assert policy.jurisdiction == "IN"
        assert len(policy.declared_ids) == 12

    def test_every_regulatory_obligation_cites_the_notification(self) -> None:
        """The regulatory-credibility play depends on this being true."""
        for s in load_policy(POLICY_PATH).by_source(ObligationSource.REGULATORY):
            assert s.citation is not None, s.id
            assert s.citation.authority == "RBI"
            assert "E-mandate Framework, 2026" in s.citation.reference
            assert s.citation.effective_from == "2026-04-21"

    def test_regulatory_without_citation_is_a_load_error(self) -> None:
        with pytest.raises(PolicyError, match="declares no citation"):
            load_policy(
                'version: "t@1"\nobligations:\n'
                "  - id: rbi.x\n    source: regulatory\n    description: d\n"
            )

    def test_risk_source_cannot_be_declared(self) -> None:
        """Declaring demands a result; advisory signals are proceed-without."""
        with pytest.raises(PolicyError, match="must never be declared"):
            load_policy(
                'version: "t@1"\nobligations:\n'
                "  - id: risk.vulcan\n    source: risk\n    description: d\n"
            )

    def test_yaml_string_and_path_both_work(self) -> None:
        assert load_policy(MINIMAL).version == "t@1"
        assert load_policy(POLICY_PATH).version == "rbi-in@1"

    @pytest.mark.parametrize(
        ("doc", "match"),
        [
            ("[]", "must be a mapping"),
            ('version: "t@1"', "non-empty 'obligations'"),
            ('version: "t@1"\nobligations: []', "non-empty 'obligations'"),
            ('version: ""\nobligations:\n  - id: a\n    source: protocol', "version"),
            ("version: t\nobligations:\n  - id: a\n    source: nope", "unknown source"),
            ("version: t\nobligations:\n  - id: ''\n    source: protocol", "id is req"),
            ("version: t\nbogus: 1\nobligations:\n  - id: a\n    source: protocol",
             "unknown top-level"),
            ("version: t\nobligations:\n  - id: a\n    source: protocol\n    zzz: 1",
             "unknown keys"),
            ("version: t\nobligations:\n  - id: a\n    source: protocol\n"
             "    params: notamap", "params must be a mapping"),
            ("::: not yaml :::", "not valid YAML"),
        ],
    )
    def test_malformed_documents_are_rejected(self, doc: str, match: str) -> None:
        with pytest.raises(PolicyError, match=match):
            load_policy(doc)

    def test_duplicate_ids_rejected(self) -> None:
        with pytest.raises(PolicyError, match="duplicate obligation ids"):
            load_policy(
                "version: t\nobligations:\n"
                "  - id: a\n    source: protocol\n"
                "  - id: a\n    source: protocol\n"
            )

    def test_policy_enabling_nothing_is_rejected(self) -> None:
        """It could only ever produce an unchecked ALLOW."""
        with pytest.raises(PolicyError, match="enables no obligations"):
            load_policy(
                "version: t\nobligations:\n"
                "  - id: a\n    source: protocol\n    enabled: false\n"
            )

    def test_disabled_obligations_are_not_declared(self) -> None:
        policy = load_policy(
            "version: t\nobligations:\n"
            "  - id: a\n    source: protocol\n"
            "  - id: b\n    source: protocol\n    enabled: false\n"
        )
        assert policy.declared_ids == frozenset({"a"})

    def test_unknown_citation_key_rejected(self) -> None:
        with pytest.raises(PolicyError, match="unknown citation keys"):
            load_policy(
                "version: t\nobligations:\n  - id: rbi.x\n    source: regulatory\n"
                "    citation:\n      authority: RBI\n      reference: r\n"
                "      bogus: 1\n"
            )

    def test_missing_required_param_is_an_error_not_a_default(self) -> None:
        spec = ObligationSpec(
            id="x", source=ObligationSource.PROTOCOL, description="d"
        )
        with pytest.raises(PolicyError, match="missing required parameter"):
            spec.require("ceiling_paise")


# ---------------------------------------------------------------------------
# AFA threshold
# ---------------------------------------------------------------------------


class TestAfaThreshold:
    def test_below_ceiling_is_satisfied(self) -> None:
        obs = evaluate((spec_for("rbi.afa_threshold"),), compliant())
        assert obs[0].status is ObligationStatus.SATISFIED

    def test_exactly_at_the_ceiling_is_satisfied(self) -> None:
        """INR 15,000 exactly. Boundary conditions on money are load-bearing."""
        obs = evaluate(
            (spec_for("rbi.afa_threshold"),), compliant(amount_paise=1_500_000)
        )
        assert obs[0].status is ObligationStatus.SATISFIED

    def test_one_paisa_over_without_afa_is_violated(self) -> None:
        obs = evaluate(
            (spec_for("rbi.afa_threshold"),), compliant(amount_paise=1_500_001)
        )
        assert obs[0].status is ObligationStatus.VIOLATED

    def test_over_ceiling_with_afa_is_satisfied(self) -> None:
        obs = evaluate(
            (spec_for("rbi.afa_threshold"),),
            compliant(amount_paise=2_000_000, afa_performed=True),
        )
        assert obs[0].status is ObligationStatus.SATISFIED

    def test_over_ceiling_with_unknown_afa_is_indeterminate(self) -> None:
        """Not knowing whether AFA happened is not the same as it happening."""
        obs = evaluate(
            (spec_for("rbi.afa_threshold"),),
            compliant(amount_paise=2_000_000, afa_performed=None),
        )
        assert obs[0].status is ObligationStatus.INDETERMINATE

    def test_unknown_amount_is_indeterminate(self) -> None:
        obs = evaluate((spec_for("rbi.afa_threshold"),), compliant(amount_paise=None))
        assert obs[0].status is ObligationStatus.INDETERMINATE

    def test_the_citation_travels_with_the_result(self) -> None:
        obs = evaluate((spec_for("rbi.afa_threshold"),), compliant())
        assert obs[0].citation is not None
        assert obs[0].citation.authority == "RBI"

    def test_detail_is_stated_in_rupees_for_a_human(self) -> None:
        obs = evaluate(
            (spec_for("rbi.afa_threshold"),), compliant(amount_paise=2_000_000)
        )
        assert "INR 20,000.00" in obs[0].detail
        assert "INR 15,000.00" in obs[0].detail


# ---------------------------------------------------------------------------
# Category ceiling
# ---------------------------------------------------------------------------


class TestCategoryCeiling:
    def test_non_specified_category_is_not_applicable(self) -> None:
        obs = evaluate((spec_for("rbi.category_ceiling"),), compliant())
        assert obs[0].status is ObligationStatus.NOT_APPLICABLE

    @pytest.mark.parametrize(
        "category", ["insurance", "mutual_fund", "credit_card_bill"]
    )
    def test_specified_categories_get_the_enhanced_ceiling(
        self, category: str
    ) -> None:
        """INR 50,000 would breach the standard ceiling but not the enhanced one."""
        obs = evaluate(
            (spec_for("rbi.category_ceiling"),),
            compliant(category=category, amount_paise=5_000_000),
        )
        assert obs[0].status is ObligationStatus.SATISFIED

    def test_above_the_enhanced_ceiling_without_afa_is_violated(self) -> None:
        obs = evaluate(
            (spec_for("rbi.category_ceiling"),),
            compliant(category="insurance", amount_paise=10_000_001),
        )
        assert obs[0].status is ObligationStatus.VIOLATED

    def test_exactly_at_the_enhanced_ceiling_is_satisfied(self) -> None:
        obs = evaluate(
            (spec_for("rbi.category_ceiling"),),
            compliant(category="insurance", amount_paise=10_000_000),
        )
        assert obs[0].status is ObligationStatus.SATISFIED

    def test_unknown_category_is_indeterminate(self) -> None:
        obs = evaluate((spec_for("rbi.category_ceiling"),), compliant(category=None))
        assert obs[0].status is ObligationStatus.INDETERMINATE


# ---------------------------------------------------------------------------
# Pre-debit notice
# ---------------------------------------------------------------------------


class TestPreDebitNotice:
    def test_thirty_hours_notice_is_satisfied(self) -> None:
        obs = evaluate((spec_for("rbi.pre_debit_notice"),), compliant())
        assert obs[0].status is ObligationStatus.SATISFIED

    def test_exactly_twenty_four_hours_is_satisfied(self) -> None:
        obs = evaluate(
            (spec_for("rbi.pre_debit_notice"),),
            compliant(pre_debit_notice_at=NOW - timedelta(hours=24)),
        )
        assert obs[0].status is ObligationStatus.SATISFIED

    def test_twenty_three_hours_is_violated(self) -> None:
        obs = evaluate(
            (spec_for("rbi.pre_debit_notice"),),
            compliant(pre_debit_notice_at=NOW - timedelta(hours=23)),
        )
        assert obs[0].status is ObligationStatus.VIOLATED
        assert "23.0h" in obs[0].detail

    def test_notice_after_the_debit_is_violated(self) -> None:
        obs = evaluate(
            (spec_for("rbi.pre_debit_notice"),),
            compliant(pre_debit_notice_at=NOW + timedelta(hours=1)),
        )
        assert obs[0].status is ObligationStatus.VIOLATED
        assert "after the debit" in obs[0].detail

    @pytest.mark.parametrize(
        "missing", ["pre_debit_notice_at", "execution_at"]
    )
    def test_missing_timestamps_are_indeterminate(self, missing: str) -> None:
        obs = evaluate(
            (spec_for("rbi.pre_debit_notice"),), compliant(**{missing: None})
        )
        assert obs[0].status is ObligationStatus.INDETERMINATE


# ---------------------------------------------------------------------------
# Registration AFA and validity window
# ---------------------------------------------------------------------------


class TestRegistrationAndValidity:
    def test_registration_with_afa_is_satisfied(self) -> None:
        obs = evaluate((spec_for("rbi.mandate_registered_with_afa"),), compliant())
        assert obs[0].status is ObligationStatus.SATISFIED

    def test_registration_without_afa_is_violated(self) -> None:
        obs = evaluate(
            (spec_for("rbi.mandate_registered_with_afa"),),
            compliant(afa_at_registration=False),
        )
        assert obs[0].status is ObligationStatus.VIOLATED

    def test_unknown_registration_afa_is_indeterminate(self) -> None:
        obs = evaluate(
            (spec_for("rbi.mandate_registered_with_afa"),),
            compliant(afa_at_registration=None),
        )
        assert obs[0].status is ObligationStatus.INDETERMINATE

    def test_debit_inside_the_window_is_satisfied(self) -> None:
        obs = evaluate((spec_for("rbi.validity_window"),), compliant())
        assert obs[0].status is ObligationStatus.SATISFIED

    def test_debit_before_the_window_is_violated(self) -> None:
        obs = evaluate(
            (spec_for("rbi.validity_window"),),
            compliant(mandate_valid_from=NOW + timedelta(days=1)),
        )
        assert obs[0].status is ObligationStatus.VIOLATED
        assert "precedes" in obs[0].detail

    def test_expired_mandate_is_violated(self) -> None:
        obs = evaluate(
            (spec_for("rbi.validity_window"),),
            compliant(mandate_valid_until=NOW - timedelta(days=1)),
        )
        assert obs[0].status is ObligationStatus.VIOLATED
        assert "expired" in obs[0].detail

    def test_inverted_window_is_violated(self) -> None:
        obs = evaluate(
            (spec_for("rbi.validity_window"),),
            compliant(
                mandate_valid_from=NOW + timedelta(days=10),
                mandate_valid_until=NOW - timedelta(days=10),
            ),
        )
        assert obs[0].status is ObligationStatus.VIOLATED
        assert "inverted" in obs[0].detail


# ---------------------------------------------------------------------------
# Fail-closed behaviour of the whole regulatory set
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_no_evidence_yields_all_indeterminate(self) -> None:
        specs = load_policy(POLICY_PATH).by_source(ObligationSource.REGULATORY)
        obs = evaluate(specs, PaymentFacts())
        assert len(obs) == 5
        assert all(o.status is ObligationStatus.INDETERMINATE for o in obs)

    def test_a_declared_rule_with_no_predicate_is_indeterminate(self) -> None:
        """A policy naming a rule the engine cannot evaluate is a gap."""
        policy = load_policy(
            'version: "t@1"\nobligations:\n'
            "  - id: rbi.not_implemented_yet\n    source: regulatory\n"
            "    description: d\n"
            "    citation:\n      authority: RBI\n      reference: r\n"
        )
        obs = evaluate(policy.enabled, compliant())
        assert obs[0].status is ObligationStatus.INDETERMINATE
        assert "no predicate is registered" in obs[0].detail

    def test_compliant_payment_passes_every_regulatory_check(self) -> None:
        specs = load_policy(POLICY_PATH).by_source(ObligationSource.REGULATORY)
        obs = evaluate(specs, compliant())
        assert not any(o.status.is_blocking for o in obs)


class TestPaymentFacts:
    def test_negative_amount_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            PaymentFacts(amount_paise=-1)

    def test_naive_datetime_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            PaymentFacts(execution_at=datetime(2026, 8, 23))  # noqa: DTZ001

    def test_everything_defaults_to_unknown(self) -> None:
        facts = PaymentFacts()
        assert facts.amount_paise is None
        assert facts.afa_performed is None


class TestPolicySerialisation:
    def test_round_trips_to_a_dict(self) -> None:
        payload = load_policy(POLICY_PATH).to_dict()
        assert payload["version"] == "rbi-in@1"
        cited = [
            o for o in payload["obligations"] if o["id"] == "rbi.afa_threshold"
        ]
        assert cited[0]["citation"]["effective_from"] == "2026-04-21"
        assert cited[0]["params"]["ceiling_paise"] == 1_500_000

    def test_policy_requires_a_version(self) -> None:
        with pytest.raises(PolicyError, match="version is required"):
            Policy(version="", description="", obligations=())
