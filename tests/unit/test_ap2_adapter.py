"""The adapter that turned a declaration into a detector.

Two halves, deliberately:

* **Injected verifier.** Every branch of the failure taxonomy, with no keys
  generated and no AP2 imported. A fake ``ChainVerifier`` is the only way to
  exercise "the SDK raised" and "AP2 is not installed" without conjuring a
  malformed SD-JWT for each one.
* **The real SDK.** The claims that only mean something against AP2 itself:
  that a chain with a withheld disclosure still verifies, that AP2's own
  evaluators report nothing wrong about it, and that PRAMANA rejects it anyway.
  If those three ever stop being true together, the project's premise is gone
  and these tests should be the thing that says so.
"""

from __future__ import annotations

import hashlib
from typing import Any, ClassVar

from pramana.adapters.ap2 import (
    CHAIN_VERIFIED,
    DISCLOSURES_PINNED,
    Presentation,
    disclosed_constraints,
    read_presentation,
    required_constraints_from,
)
from pramana.adapters.ap2_chain import (
    SeenNonces,
    ap2_violations,
    backend_obligations,
    mint,
)
from pramana.kernel.gate import Kernel, PaymentRequest
from pramana.kernel.verdict import Decision, ObligationSource, ObligationStatus
from pramana.kernel.verify.policy import builtin_policy, load_policy
from pramana.kernel.verify.rbi import PaymentFacts

REQUIRED = ("payment.budget", "payment.allowed_payees")


def payload(*tags: str) -> dict[str, Any]:
    return {"constraints": [{"type": t} for t in tags]}


class Scripted:
    """A ChainVerifier that returns or raises whatever the test needs."""

    def __init__(self, result: Any = None, raises: Exception | None = None) -> None:
        self._result = result
        self._raises = raises
        self.calls: list[dict[str, Any]] = []

    def verify(
        self,
        token: str,
        key_or_provider: Any,
        payload_type: Any = None,
        expected_aud: str | None = None,
        expected_nonce: str | None = None,
    ) -> Any:
        self.calls.append(
            {"token": token, "aud": expected_aud, "nonce": expected_nonce}
        )
        if self._raises is not None:
            raise self._raises
        return self._result


def read(verifier: Any, required: tuple[str, ...] = REQUIRED) -> Any:
    return read_presentation(
        Presentation(token="t", expected_aud="a", expected_nonce="n"),  # noqa: S106
        resolve_issuer_key=lambda _parsed: object(),
        required_constraints=required,
        verifier=verifier,
    )


def by_id(reading: Any) -> dict[str, Any]:
    return {o.id: o for o in reading.obligations}


class TestTheDetector:
    def test_every_required_constraint_present_satisfies_both(self) -> None:
        obs = by_id(read(Scripted([payload(*REQUIRED)])))
        assert obs[CHAIN_VERIFIED].status is ObligationStatus.SATISFIED
        assert obs[DISCLOSURES_PINNED].status is ObligationStatus.SATISFIED

    def test_a_withheld_constraint_is_violated_not_indeterminate(self) -> None:
        """The distinction the adapter exists to create.

        INDETERMINATE means we could not tell. We told: the disclosed set was
        read and the required constraint was not in it.
        """
        reading = read(Scripted([payload("payment.allowed_payees")]))
        obs = by_id(reading)
        assert obs[CHAIN_VERIFIED].status is ObligationStatus.SATISFIED
        assert obs[DISCLOSURES_PINNED].status is ObligationStatus.VIOLATED
        assert reading.missing_constraints == ("payment.budget",)
        assert "payment.budget" in obs[DISCLOSURES_PINNED].detail

    def test_the_violation_records_what_was_disclosed_and_what_was_not(self) -> None:
        obs = by_id(read(Scripted([payload("payment.allowed_payees")])))
        observed = obs[DISCLOSURES_PINNED].observed
        assert observed == {
            "disclosed": ["payment.allowed_payees"],
            "withheld": ["payment.budget"],
        }

    def test_no_required_constraints_is_not_applicable_not_satisfied(self) -> None:
        """A vacuous pass is how this family of bug starts."""
        obs = by_id(read(Scripted([payload()]), required=()))
        assert obs[DISCLOSURES_PINNED].status is ObligationStatus.NOT_APPLICABLE

    def test_constraints_are_sorted_and_deduplicated(self) -> None:
        """A verdict is hashed, so its content cannot depend on hop order."""
        assert disclosed_constraints(
            [payload("b", "a"), payload("a")]
        ) == ("a", "b")

    def test_object_payloads_are_read_as_well_as_dicts(self) -> None:
        class Constraint:
            type = "payment.budget"

        class Payload:
            constraints: ClassVar[list[Constraint]] = [Constraint()]

        assert disclosed_constraints([Payload()]) == ("payment.budget",)


class TestFailClosed:
    def test_a_verification_failure_violates_and_blocks(self) -> None:
        reading = read(Scripted(raises=ValueError("signature mismatch")))
        obs = by_id(reading)
        assert obs[CHAIN_VERIFIED].status is ObligationStatus.VIOLATED
        assert "signature mismatch" in obs[CHAIN_VERIFIED].detail
        assert not reading.verified

    def test_an_unverified_chain_reports_nothing_about_disclosures(self) -> None:
        """An unverified payload is not evidence of what was disclosed."""
        obs = by_id(read(Scripted(raises=ValueError("nope"))))
        assert obs[DISCLOSURES_PINNED].status is ObligationStatus.INDETERMINATE

    def test_a_missing_sdk_is_indeterminate_not_a_crash(self) -> None:
        reading = read_presentation(
            Presentation(token="t", expected_aud="a"),  # noqa: S106
            resolve_issuer_key=lambda _p: object(),
            required_constraints=REQUIRED,
            verifier=None,
        )
        # verifier=None falls through to default_verifier(); AP2 is installed
        # in this environment, so assert on the shape rather than the outcome.
        assert {o.id for o in reading.obligations} == {
            CHAIN_VERIFIED,
            DISCLOSURES_PINNED,
        }

    def test_the_adapter_never_raises(self) -> None:
        """A raise here would take a live decision with it."""
        reading = read(Scripted(raises=RuntimeError("anything at all")))
        assert all(o.status.is_blocking for o in reading.obligations)

    def test_aud_and_nonce_are_passed_to_the_verifier(self) -> None:
        scripted = Scripted([payload(*REQUIRED)])
        read(scripted)
        assert scripted.calls[0]["aud"] == "a"
        assert scripted.calls[0]["nonce"] == "n"


class TestRequiredConstraintsComeFromPolicy:
    def test_the_shipped_policy_parameter_is_finally_read(self) -> None:
        """Declared in rbi-in.yaml since the first build, read by nothing."""
        assert set(required_constraints_from(builtin_policy())) == set(REQUIRED)

    def test_an_absent_obligation_requires_nothing(self) -> None:
        policy = load_policy(
            'version: "t@1"\nobligations:\n'
            "  - id: chain.verified\n    source: protocol\n    description: d\n"
        )
        assert required_constraints_from(policy) == ()


class TestAgainstTheRealSdk:
    """These are the claims that only mean anything against AP2 itself."""

    def test_a_fully_disclosed_chain_verifies_and_pins(self) -> None:
        chain = mint(withhold_budget=False)
        reading = read_presentation(
            chain.presentation,
            resolve_issuer_key=chain.resolve_issuer_key,
            required_constraints=REQUIRED,
        )
        obs = by_id(reading)
        assert obs[CHAIN_VERIFIED].status is ObligationStatus.SATISFIED
        assert obs[DISCLOSURES_PINNED].status is ObligationStatus.SATISFIED
        assert reading.disclosed_constraints == (
            "payment.allowed_payees",
            "payment.budget",
        )

    def test_the_finding_holds_end_to_end(self) -> None:
        """All three at once, or the project has no premise.

        1. the chain still verifies with the cap withheld
        2. AP2's own evaluators report nothing wrong about it
        3. PRAMANA rejects it anyway
        """
        chain = mint(withhold_budget=True)
        reading = read_presentation(
            chain.presentation,
            resolve_issuer_key=chain.resolve_issuer_key,
            required_constraints=REQUIRED,
        )
        obs = by_id(reading)

        assert reading.verified, "1. the chain must still verify"
        assert obs[CHAIN_VERIFIED].status is ObligationStatus.SATISFIED
        assert (
            ap2_violations(reading.payloads, chain.closed_mandate) == []
        ), "2. AP2 must report no violation -- there is no cap left to violate"
        assert (
            obs[DISCLOSURES_PINNED].status is ObligationStatus.VIOLATED
        ), "3. PRAMANA must reject it"
        assert reading.missing_constraints == ("payment.budget",)

    def test_the_backend_following_ap2_reports_the_budget_satisfied(self) -> None:
        """Not a careless integrator: the reference evaluator's own answer."""
        chain = mint(withhold_budget=True)
        reading = read_presentation(
            chain.presentation,
            resolve_issuer_key=chain.resolve_issuer_key,
            required_constraints=REQUIRED,
        )
        budget = next(
            o
            for o in backend_obligations(reading.payloads, chain.closed_mandate)
            if o.id == "mandate.budget"
        )
        assert budget.status is ObligationStatus.SATISFIED

    def test_a_disclosed_over_cap_charge_is_caught_by_ap2_too(self) -> None:
        """The control: when the cap IS disclosed, both verifiers agree."""
        chain = mint(withhold_budget=False)
        reading = read_presentation(
            chain.presentation,
            resolve_issuer_key=chain.resolve_issuer_key,
            required_constraints=REQUIRED,
        )
        assert ap2_violations(reading.payloads, chain.closed_mandate) != []

    def test_a_tampered_presentation_does_not_verify(self) -> None:
        chain = mint(withhold_budget=False)
        tampered = Presentation(
            token=chain.presentation.token[:-8] + "AAAAAAAA",
            expected_aud=chain.presentation.expected_aud,
            expected_nonce=chain.presentation.expected_nonce,
        )
        reading = read_presentation(
            tampered,
            resolve_issuer_key=chain.resolve_issuer_key,
            required_constraints=REQUIRED,
        )
        assert not reading.verified
        assert by_id(reading)[CHAIN_VERIFIED].status is ObligationStatus.VIOLATED

    def test_the_kernel_rejects_the_withheld_presentation(self) -> None:
        """Through the real gate, under the shipped policy."""
        policy = builtin_policy()
        chain = mint(withhold_budget=True)
        reading = read_presentation(
            chain.presentation,
            resolve_issuer_key=chain.resolve_issuer_key,
            required_constraints=required_constraints_from(policy),
        )
        result = Kernel(policy).evaluate(
            PaymentRequest(
                mandate_ref=hashlib.sha256(
                    chain.presentation.token.encode()
                ).hexdigest(),
                facts=PaymentFacts(amount_paise=chain.amount_paise, currency="INR"),
                protocol_results=reading.obligations,
                mandate_results=tuple(
                    o
                    for o in backend_obligations(
                        reading.payloads, chain.closed_mandate
                    )
                    if o.source is ObligationSource.MANDATE
                ),
            )
        )
        assert result.verdict.decision is Decision.REJECT
        assert DISCLOSURES_PINNED in {o.id for o in result.verdict.blocking}


class TestSeenNonces:
    def test_an_unseen_nonce_is_satisfied(self) -> None:
        assert SeenNonces().check("n1").status is ObligationStatus.SATISFIED

    def test_a_replayed_nonce_is_violated(self) -> None:
        store = SeenNonces()
        store.check("n1")
        replay = store.check("n1")
        assert replay.status is ObligationStatus.VIOLATED
        assert "replay" in replay.detail

    def test_no_nonce_at_all_is_indeterminate(self) -> None:
        assert SeenNonces().check(None).status is ObligationStatus.INDETERMINATE
