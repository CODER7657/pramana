"""Invariants of the canonical verdict types.

Several tests here are regressions for defects found in review on 2026-08-23.
They are marked with their finding id so they cannot be silently deleted:

* S3a -- an all-NOT_APPLICABLE verdict returned ALLOW
* S3b -- a frozen Verdict was mutable via the caller's list, flipping its hash
* S3c -- canonical_bytes() rendered arbitrary objects via repr, memory
         addresses included, destroying determinism
* S3d -- mandate_ref defaulted to None and trace_id accepted "x"
* S4  -- nothing forced the obligation set to cover what policy declared
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime

import pytest

from pramana.kernel.verdict import (
    Citation,
    Decision,
    Obligation,
    ObligationSource,
    ObligationStatus,
    Verdict,
    build_verdict,
)

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
REF = hashlib.sha256(b"closed-mandate-jwt").hexdigest()
POLICY = "test-policy@1"

TEST_CITATION = Citation(
    authority="RBI",
    reference="Digital Payments - E-mandate Framework, 2026",
    clause="test clause",
    effective_from="2026-04-21",
)



def _ob(
    status: ObligationStatus,
    ident: str = "test.check",
    source: ObligationSource = ObligationSource.MANDATE,
) -> Obligation:
    return Obligation(
        id=ident,
        status=status,
        source=source,
        detail="test detail",
        citation=TEST_CITATION if source is ObligationSource.REGULATORY else None,
    )


def _verdict(
    *obligations: Obligation, declared: tuple[str, ...] | None = None
) -> Verdict:
    return build_verdict(
        obligations,
        policy_version=POLICY,
        declared_obligations=declared or tuple(o.id for o in obligations),
        trace_id=TRACE,
        mandate_ref=REF,
    )


# ---------------------------------------------------------------------------
# Fail-closed: the core safety property
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_all_satisfied_allows(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"), _ob(ObligationStatus.SATISFIED, "b")
        )
        assert v.decision is Decision.ALLOW

    def test_single_violation_rejects(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"), _ob(ObligationStatus.VIOLATED, "b")
        )
        assert v.decision is Decision.REJECT

    def test_indeterminate_rejects_exactly_as_hard_as_violated(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"),
            _ob(ObligationStatus.INDETERMINATE, "b"),
        )
        assert v.decision is Decision.REJECT

    def test_not_applicable_alone_does_not_block(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"),
            _ob(ObligationStatus.NOT_APPLICABLE, "b"),
        )
        assert v.decision is Decision.ALLOW

    def test_empty_obligation_set_is_unrepresentable(self) -> None:
        msg = r"declares nothing|policy-declared obligation"
        with pytest.raises(ValueError, match=msg):
            build_verdict(
                [],
                policy_version=POLICY,
                declared_obligations=[],
                trace_id=TRACE,
                mandate_ref=REF,
            )

    def test_decision_cannot_be_assigned(self) -> None:
        v = _verdict(_ob(ObligationStatus.SATISFIED))
        with pytest.raises((AttributeError, TypeError)):
            v.decision = Decision.ALLOW  # type: ignore[misc]

    @pytest.mark.parametrize(
        ("status", "blocking"),
        [
            (ObligationStatus.SATISFIED, False),
            (ObligationStatus.NOT_APPLICABLE, False),
            (ObligationStatus.VIOLATED, True),
            (ObligationStatus.INDETERMINATE, True),
        ],
    )
    def test_is_blocking_matrix(self, status: ObligationStatus, blocking: bool) -> None:
        assert status.is_blocking is blocking


# ---------------------------------------------------------------------------
# S3a regression -- a verdict that affirms nothing is not permission
# ---------------------------------------------------------------------------


class TestMustAffirmSomething:
    def test_all_not_applicable_is_unconstructible(self) -> None:
        """S3a. Previously returned ALLOW, having checked nothing."""
        with pytest.raises(ValueError, match="policy-declared obligation"):
            _verdict(
                _ob(ObligationStatus.NOT_APPLICABLE, "a"),
                _ob(ObligationStatus.NOT_APPLICABLE, "b"),
            )

    def test_not_applicable_still_usable_alongside_a_real_check(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "chain.verified"),
            _ob(ObligationStatus.NOT_APPLICABLE, "rbi.insurance_category_limit"),
        )
        assert v.decision is Decision.ALLOW


# ---------------------------------------------------------------------------
# S4 -- coverage of policy-declared obligations is structural
# ---------------------------------------------------------------------------


class TestCoverage:
    def test_undeclared_obligation_becomes_indeterminate_and_rejects(self) -> None:
        """S4. Policy declared three checks; the evaluator reported two."""
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"),
            _ob(ObligationStatus.SATISFIED, "b"),
            declared=("a", "b", "rbi.afa_threshold"),
        )
        assert v.decision is Decision.REJECT
        missing = [o for o in v.blocking if o.id == "rbi.afa_threshold"]
        assert len(missing) == 1
        assert missing[0].status is ObligationStatus.INDETERMINATE
        assert "not compliance" in missing[0].detail

    def test_full_coverage_allows(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"),
            _ob(ObligationStatus.SATISFIED, "b"),
            declared=("a", "b"),
        )
        assert v.decision is Decision.ALLOW
        assert v.coverage == 1.0

    def test_coverage_ratio_reported(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"),
            declared=("a", "b", "c", "d"),
        )
        assert v.coverage == 0.25

    def test_extra_undeclared_obligations_are_permitted(self) -> None:
        """Protocol-level checks always run, whether policy names them or not."""
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "a"),
            _ob(
                ObligationStatus.SATISFIED,
                "chain.verified",
                ObligationSource.PROTOCOL,
            ),
            declared=("a",),
        )
        assert v.decision is Decision.ALLOW

    def test_declared_obligations_required(self) -> None:
        with pytest.raises(ValueError, match="declares nothing"):
            build_verdict(
                [_ob(ObligationStatus.SATISFIED)],
                policy_version=POLICY,
                declared_obligations=[],
                trace_id=TRACE,
                mandate_ref=REF,
            )

    def test_duplicate_obligation_ids_rejected(self) -> None:
        with pytest.raises(ValueError, match="duplicate obligation ids"):
            _verdict(
                _ob(ObligationStatus.SATISFIED, "a"),
                _ob(ObligationStatus.VIOLATED, "a"),
            )


# ---------------------------------------------------------------------------
# S3b regression -- deep immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_caller_list_mutation_cannot_alter_verdict(self) -> None:
        """S3b. Previously flipped ALLOW -> REJECT and changed content_hash."""
        obs = [_ob(ObligationStatus.SATISFIED, "a")]
        v = build_verdict(
            obs,
            policy_version=POLICY,
            declared_obligations=("a",),
            trace_id=TRACE,
            mandate_ref=REF,
        )
        before_decision, before_hash = v.decision, v.content_hash()
        obs.append(_ob(ObligationStatus.VIOLATED, "injected"))
        assert v.decision is before_decision
        assert v.content_hash() == before_hash
        assert isinstance(v.obligations, tuple)

    def test_verdict_is_hashable(self) -> None:
        """S3b. hash() raised 'unhashable type: list' when obligations was a list."""
        assert isinstance(hash(_verdict(_ob(ObligationStatus.SATISFIED))), int)

    def test_verdict_is_frozen(self) -> None:
        v = _verdict(_ob(ObligationStatus.SATISFIED))
        with pytest.raises((AttributeError, TypeError)):
            v.policy_version = "tampered"  # type: ignore[misc]

    def test_obligation_is_frozen(self) -> None:
        o = _ob(ObligationStatus.SATISFIED)
        with pytest.raises((AttributeError, TypeError)):
            o.status = ObligationStatus.VIOLATED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# S3d regression -- an unanchored record is not evidence
# ---------------------------------------------------------------------------


class TestRequiredFields:
    @pytest.mark.parametrize(
        "bad", ["x", "", "0" * 32, "4BF92F3577B34DA6A3CE929D0E0E4736", "abc123"]
    )
    def test_invalid_trace_id_rejected(self, bad: str) -> None:
        """S3d. trace_id='x' was previously accepted."""
        with pytest.raises(ValueError, match="trace_id"):
            build_verdict(
                [_ob(ObligationStatus.SATISFIED)],
                policy_version=POLICY,
                declared_obligations=("test.check",),
                trace_id=bad,
                mandate_ref=REF,
            )

    @pytest.mark.parametrize("bad", ["", "not-a-hash", "a" * 63, "A" * 64])
    def test_invalid_mandate_ref_rejected(self, bad: str) -> None:
        """S3d. mandate_ref previously defaulted to None."""
        with pytest.raises(ValueError, match="mandate_ref"):
            build_verdict(
                [_ob(ObligationStatus.SATISFIED)],
                policy_version=POLICY,
                declared_obligations=("test.check",),
                trace_id=TRACE,
                mandate_ref=bad,
            )

    def test_policy_version_required(self) -> None:
        with pytest.raises(ValueError, match="policy_version"):
            build_verdict(
                [_ob(ObligationStatus.SATISFIED)],
                policy_version="",
                declared_obligations=("test.check",),
                trace_id=TRACE,
                mandate_ref=REF,
            )

    def test_naive_datetime_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            build_verdict(
                [_ob(ObligationStatus.SATISFIED)],
                policy_version=POLICY,
                declared_obligations=("test.check",),
                trace_id=TRACE,
                mandate_ref=REF,
                evaluated_at=datetime(2026, 8, 23, 12, 0, 0),  # noqa: DTZ001
            )

    def test_obligation_requires_id_and_detail(self) -> None:
        with pytest.raises(ValueError, match="id must be non-empty"):
            Obligation(
                id="",
                status=ObligationStatus.SATISFIED,
                source=ObligationSource.MANDATE,
                detail="x",
            )
        with pytest.raises(ValueError, match="detail string"):
            Obligation(
                id="a.b",
                status=ObligationStatus.SATISFIED,
                source=ObligationSource.MANDATE,
                detail="",
            )


# ---------------------------------------------------------------------------
# S3c regression -- canonical serialisation
# ---------------------------------------------------------------------------


class TestCanonicalSerialization:
    def test_non_json_safe_evidence_is_rejected(self) -> None:
        """S3c. Previously serialised as '<object at 0x...>' via default=str."""

        class Opaque:
            pass

        with pytest.raises(ValueError, match="not JSON-safe"):
            Obligation(
                id="a.b",
                status=ObligationStatus.SATISFIED,
                source=ObligationSource.MANDATE,
                detail="d",
                observed=Opaque(),  # type: ignore[arg-type]
            )

    def test_nested_non_json_safe_is_rejected(self) -> None:
        with pytest.raises(ValueError, match=re.escape("observed.k[0]")):
            Obligation(
                id="a.b",
                status=ObligationStatus.SATISFIED,
                source=ObligationSource.MANDATE,
                detail="d",
                observed={"k": [object()]},  # type: ignore[list-item]
            )

    def test_nan_and_infinity_rejected(self) -> None:
        for bad in (float("nan"), float("inf")):
            with pytest.raises(ValueError, match="NaN and Infinity"):
                Obligation(
                    id="a.b",
                    status=ObligationStatus.SATISFIED,
                    source=ObligationSource.MANDATE,
                    detail="d",
                    observed=bad,
                )

    def test_json_safe_evidence_accepted(self) -> None:
        o = Obligation(
            id="a.b",
            status=ObligationStatus.SATISFIED,
            source=ObligationSource.MANDATE,
            detail="d",
            observed={"amount": 750000, "currency": "INR", "ok": True, "tags": ["x"]},
            expected={"max": 500000},
        )
        assert o.observed is not None

    def test_is_deterministic(self) -> None:
        ts = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)

        def make() -> Verdict:
            return build_verdict(
                [_ob(ObligationStatus.SATISFIED)],
                policy_version=POLICY,
                declared_obligations=("test.check",),
                trace_id=TRACE,
                mandate_ref=REF,
                evaluated_at=ts,
            )

        assert make().canonical_bytes() == make().canonical_bytes()

    def test_jcs_sorts_keys(self) -> None:
        raw = _verdict(_ob(ObligationStatus.SATISFIED)).canonical_bytes().decode()
        assert raw.index('"decision"') < raw.index('"evaluated_at"')
        assert raw.index('"obligations"') < raw.index('"policy_version"')

    def test_content_hash_changes_when_status_changes(self) -> None:
        ts = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
        common = {
            "policy_version": POLICY,
            "declared_obligations": ("test.check",),
            "trace_id": TRACE,
            "mandate_ref": REF,
            "evaluated_at": ts,
        }
        a = build_verdict([_ob(ObligationStatus.SATISFIED)], **common)  # type: ignore[arg-type]
        b = build_verdict(
            [_ob(ObligationStatus.SATISFIED), _ob(ObligationStatus.VIOLATED, "z")],
            **common,  # type: ignore[arg-type]
        )
        assert a.content_hash() != b.content_hash()

    def test_content_hash_is_sha256_hex(self) -> None:
        h = _verdict(_ob(ObligationStatus.SATISFIED)).content_hash()
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# Blocking-obligation reporting -- the demo prints this
# ---------------------------------------------------------------------------


class TestBlockingReport:
    def test_blocking_preserves_evaluation_order(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.VIOLATED, "first"),
            _ob(ObligationStatus.SATISFIED, "second"),
            _ob(ObligationStatus.INDETERMINATE, "third"),
        )
        assert [o.id for o in v.blocking] == ["first", "third"]

    def test_blocking_empty_when_allowed(self) -> None:
        assert _verdict(_ob(ObligationStatus.SATISFIED)).blocking == ()

    def test_source_is_recorded_per_obligation(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "ok"),
            _ob(ObligationStatus.VIOLATED, "r", ObligationSource.REGULATORY),
        )
        assert v.blocking[0].source is ObligationSource.REGULATORY


# ---------------------------------------------------------------------------
# Citation -- what makes a verdict a compliance artifact rather than a score
# ---------------------------------------------------------------------------


class TestCitation:
    def test_regulatory_obligation_requires_a_citation(self) -> None:
        """You cannot claim a rule rejected a payment without naming the rule."""
        with pytest.raises(ValueError, match="REGULATORY but no citation"):
            Obligation(
                id="rbi.afa_threshold",
                status=ObligationStatus.VIOLATED,
                source=ObligationSource.REGULATORY,
                detail="AFA required",
            )

    @pytest.mark.parametrize(
        "source",
        [
            ObligationSource.MANDATE,
            ObligationSource.MERCHANT,
            ObligationSource.PROTOCOL,
            ObligationSource.RISK,
        ],
    )
    def test_non_regulatory_sources_do_not_require_one(
        self, source: ObligationSource
    ) -> None:
        assert (
            Obligation(
                id="x.y",
                status=ObligationStatus.SATISFIED,
                source=source,
                detail="d",
            ).citation
            is None
        )

    def test_citation_requires_authority_and_reference(self) -> None:
        with pytest.raises(ValueError, match="authority"):
            Citation(authority="", reference="r")
        with pytest.raises(ValueError, match="reference"):
            Citation(authority="RBI", reference="")

    def test_render_is_human_readable(self) -> None:
        assert (
            Citation(
                authority="RBI", reference="E-mandate Framework, 2026", clause="AFA"
            ).render()
            == "RBI / E-mandate Framework, 2026 / AFA"
        )

    def test_render_without_a_clause(self) -> None:
        assert Citation(authority="AP2", reference="v0.2").render() == "AP2 / v0.2"

    def test_citation_is_serialised_into_the_verdict(self) -> None:
        v = _verdict(
            _ob(ObligationStatus.SATISFIED, "ok"),
            _ob(ObligationStatus.VIOLATED, "rbi.x", ObligationSource.REGULATORY),
        )
        payload = v.to_dict()
        cited = [o for o in payload["obligations"] if o["id"] == "rbi.x"]  # type: ignore[index,union-attr]
        assert cited[0]["citation"]["authority"] == "RBI"  # type: ignore[index]

    def test_citation_changes_the_content_hash(self) -> None:
        """A verdict citing a different provision is a different record."""
        base = Obligation(
            id="rbi.x",
            status=ObligationStatus.VIOLATED,
            source=ObligationSource.REGULATORY,
            detail="d",
            citation=Citation(authority="RBI", reference="A"),
        )
        other = Obligation(
            id="rbi.x",
            status=ObligationStatus.VIOLATED,
            source=ObligationSource.REGULATORY,
            detail="d",
            citation=Citation(authority="RBI", reference="B"),
        )
        common = {
            "policy_version": POLICY,
            "declared_obligations": ("ok", "rbi.x"),
            "trace_id": TRACE,
            "mandate_ref": REF,
            "evaluated_at": datetime(2026, 8, 23, tzinfo=UTC),
        }
        a = build_verdict([_ob(ObligationStatus.SATISFIED, "ok"), base], **common)  # type: ignore[arg-type]
        b = build_verdict([_ob(ObligationStatus.SATISFIED, "ok"), other], **common)  # type: ignore[arg-type]
        assert a.content_hash() != b.content_hash()

    def test_citation_is_frozen(self) -> None:
        c = Citation(authority="RBI", reference="r")
        with pytest.raises((AttributeError, TypeError)):
            c.authority = "tampered"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Invariant 4, scoped. Both halves are review findings.
# ---------------------------------------------------------------------------


class TestAffirmationIsScoped:
    def test_a_reject_does_not_need_an_affirmation(self) -> None:
        """A refusal is not permission, so it need not have satisfied anything.

        Requiring it made a malformed request crash the gate with a ValueError
        instead of rejecting it.
        """
        v = build_verdict(
            [_ob(ObligationStatus.INDETERMINATE, "a")],
            policy_version=POLICY,
            declared_obligations=("a",),
            trace_id=TRACE,
            mandate_ref=REF,
        )
        assert v.decision is Decision.REJECT

    def test_an_all_indeterminate_verdict_is_constructible(self) -> None:
        v = build_verdict(
            [],
            policy_version=POLICY,
            declared_obligations=("a", "b", "c"),
            trace_id=TRACE,
            mandate_ref=REF,
        )
        assert v.decision is Decision.REJECT
        assert len(v.blocking) == 3

    def test_bookkeeping_cannot_satisfy_the_invariant(self) -> None:
        """An undeclared SATISFIED obligation must not earn an ALLOW.

        Previously the ledger's own `evidence.recorded` obligation met this,
        so an all-NOT_APPLICABLE policy result reached ALLOW whenever the
        ledger happened to be up.
        """
        with pytest.raises(ValueError, match="policy-declared obligation"):
            build_verdict(
                [
                    _ob(ObligationStatus.NOT_APPLICABLE, "declared.rule"),
                    _ob(ObligationStatus.SATISFIED, "evidence.recorded"),
                ],
                policy_version=POLICY,
                declared_obligations=("declared.rule",),
                trace_id=TRACE,
                mandate_ref=REF,
            )

    def test_a_declared_satisfied_obligation_does_earn_an_allow(self) -> None:
        v = build_verdict(
            [
                _ob(ObligationStatus.SATISFIED, "declared.rule"),
                _ob(ObligationStatus.NOT_APPLICABLE, "declared.other"),
            ],
            policy_version=POLICY,
            declared_obligations=("declared.rule", "declared.other"),
            trace_id=TRACE,
            mandate_ref=REF,
        )
        assert v.decision is Decision.ALLOW


class TestSynthesisAttribution:
    def test_a_missing_regulatory_check_is_attributed_to_its_authority(self) -> None:
        """Synthesised obligations previously claimed MERCHANT with no citation,
        including missing rbi.* checks, in a system where ADR-0006 makes a
        citation mandatory for regulatory obligations."""
        citation = Citation(
            authority="RBI", reference="E-mandate Framework, 2026", clause="AFA"
        )
        v = build_verdict(
            [_ob(ObligationStatus.SATISFIED, "ok")],
            policy_version=POLICY,
            declared_obligations=("ok", "rbi.pre_debit_notice"),
            trace_id=TRACE,
            mandate_ref=REF,
            declared_meta={
                "rbi.pre_debit_notice": (ObligationSource.REGULATORY, citation)
            },
        )
        synth = next(o for o in v.obligations if o.id == "rbi.pre_debit_notice")
        assert synth.source is ObligationSource.REGULATORY
        assert synth.citation is citation

    def test_without_metadata_it_still_synthesises_and_blocks(self) -> None:
        v = build_verdict(
            [_ob(ObligationStatus.SATISFIED, "ok")],
            policy_version=POLICY,
            declared_obligations=("ok", "unknown.rule"),
            trace_id=TRACE,
            mandate_ref=REF,
        )
        assert v.decision is Decision.REJECT
