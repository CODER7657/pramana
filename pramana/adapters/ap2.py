"""AP2 presentation -> protocol obligations. The one module that imports AP2.

Until this existed, ``chain.verified`` and ``chain.disclosures_pinned`` were
*declared* by policy and *supplied* by the caller. The gate required them to be
present, not to be true. That is coverage enforcement, and it fails closed, but
it is not detection -- and the README said so in as many words.

This module computes both. The difference it makes is one sentence:

    before  the cap was withheld, nothing reported a result for a declared
            obligation, and the coverage invariant rejected
    after   PRAMANA enumerated the constraints actually disclosed in the
            presentation, found ``payment.budget`` absent where policy
            required it, and rejected -- while AP2's own evaluator, run over
            the same presentation, reported zero violations

Scope, stated precisely, because the precision is the point
-----------------------------------------------------------

**What we verify.** ``chain.verified`` is the real result of
``MandateClient.verify`` over the presented chain: every hop's signature, the
key-binding JWT on the terminal hop, and ``aud``/``nonce`` when the presentation
carries a KB-JWT.

**Whose ``cnf`` walking.** AP2's. ``verify_chain`` resolves hop *i* with hop
*i-1*'s ``cnf.jwk`` internally; the resolver this module takes supplies only the
**root issuer** key. Calling that "a cnf-following resolver" would claim credit
for the SDK's work, so it is named :data:`IssuerKeyResolver` instead.

**What stays caller-supplied.** ``mandate.budget``, ``mandate.payee_in_scope``
and ``mandate.not_expired``. Those need the persisted ``MandateContext`` that
AP2 defines and never stores; the merchant's backend has it and we do not.
``chain.nonce_fresh`` needs a seen-nonce store, which is state this process does
not hold. All four remain declared, so their absence still rejects.

Failure taxonomy
----------------

Every branch below fails closed, and the *reason* is preserved because a
dispute needs to know which one happened:

===============================  ==================  ========================
situation                        ``chain.verified``  ``disclosures_pinned``
===============================  ==================  ========================
signatures verify, all required
constraints disclosed            SATISFIED           SATISFIED
signatures verify, a required
constraint is absent             SATISFIED           **VIOLATED**
verification raises              **VIOLATED**        INDETERMINATE
AP2 unavailable / payload
shape unreadable                 INDETERMINATE       INDETERMINATE
===============================  ==================  ========================

The second row is the whole point, and it is ``VIOLATED`` rather than
``INDETERMINATE`` on purpose. ``INDETERMINATE`` means *we could not tell*. We
told: we read the disclosed constraint set and the required one was not in it.
Both block identically, so nothing about the decision changes -- but a verdict
that says "we checked and it was missing" is a different artifact in a dispute
from one that says "nobody looked".
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol

from pramana.kernel.verdict import Obligation, ObligationSource, ObligationStatus

logger = logging.getLogger(__name__)

CHAIN_VERIFIED: Final = "chain.verified"
DISCLOSURES_PINNED: Final = "chain.disclosures_pinned"

IssuerKeyResolver = Callable[[Any], Any]
"""``(ParsedToken) -> JWK`` for the **root** hop only. AP2 walks ``cnf`` itself."""


class ChainVerifier(Protocol):
    """The single AP2 call this module depends on.

    Declared as a Protocol so the failure branches can be tested without
    conjuring a malformed SD-JWT for each one, and so the adapter's own logic
    is exercised with no key generation at all.
    """

    def verify(
        self,
        token: str,
        key_or_provider: Any,
        payload_type: Any = None,
        expected_aud: str | None = None,
        expected_nonce: str | None = None,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class Presentation:
    """An AP2 presentation as it arrives at the gate."""

    token: str
    expected_aud: str
    expected_nonce: str | None = None


@dataclass(frozen=True, slots=True)
class PresentationReading:
    """What the adapter made of a presentation.

    ``obligations`` is what the kernel consumes. The rest is kept for the
    explainer and the dispute pack, which need to say *what was disclosed*
    rather than only *that something was missing*.
    """

    obligations: tuple[Obligation, ...]
    disclosed_constraints: tuple[str, ...]
    missing_constraints: tuple[str, ...]
    verified: bool
    payloads: tuple[Any, ...] = ()


def required_constraints_from(policy: Any) -> tuple[str, ...]:
    """Read ``chain.disclosures_pinned``'s ``required_constraints`` parameter.

    That parameter was declared in the shipped policy and **read by nothing**
    for the whole of the first build. It named the control for the headline
    finding, and no code consumed it. This is the line that makes it live.

    Returns empty when the obligation is absent or disabled, which
    :func:`_pin` renders as NOT_APPLICABLE rather than a vacuous pass.
    """
    spec = policy.spec(DISCLOSURES_PINNED)
    if spec is None or not spec.enabled:
        return ()
    return tuple(str(c) for c in spec.param("required_constraints", ()) or ())


def _ob(
    ident: str,
    status: ObligationStatus,
    detail: str,
    *,
    observed: Any = None,
    expected: Any = None,
) -> Obligation:
    return Obligation(
        id=ident,
        status=status,
        source=ObligationSource.PROTOCOL,
        detail=detail,
        observed=observed,
        expected=expected,
    )


def default_verifier() -> ChainVerifier | None:
    """AP2's ``MandateClient``, or ``None`` if AP2 is not importable.

    Imported lazily so that the kernel, the policy engine and the whole test
    suite remain usable without the git-installed dependency present. A missing
    AP2 does not crash a decision; it produces INDETERMINATE, which rejects.
    """
    try:
        from ap2.sdk.mandate import MandateClient  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover - exercised by injection
        logger.warning("AP2 SDK unavailable: %s", exc)
        return None
    client: ChainVerifier = MandateClient()
    return client


def disclosed_constraints(payloads: Sequence[Any]) -> tuple[str, ...]:
    """Constraint type-tags actually present in the verified payloads.

    A withheld selective disclosure simply is not here -- that is the entire
    mechanism. AP2 tags each constraint with a ``type`` (``payment.budget``,
    ``payment.allowed_payees``), which is what the policy's
    ``required_constraints`` names, so no translation table is needed and none
    can drift.
    """
    seen: list[str] = []
    for payload in payloads:
        raw = (
            payload.get("constraints")
            if isinstance(payload, dict)
            else getattr(payload, "constraints", None)
        )
        for constraint in raw or ():
            if isinstance(constraint, dict):
                tag = constraint.get("type")
            else:
                tag = getattr(constraint, "type", None)
            if tag:
                seen.append(str(tag))
    # Sorted and de-duplicated: a verdict is hashed, so its content must not
    # depend on the order hops happened to be walked in.
    return tuple(sorted(set(seen)))


def read_presentation(
    presentation: Presentation,
    *,
    resolve_issuer_key: IssuerKeyResolver,
    required_constraints: Sequence[str] = (),
    verifier: ChainVerifier | None = None,
) -> PresentationReading:
    """Verify a presentation and report what it actually disclosed.

    Never raises. Every failure becomes a blocking obligation, because an
    adapter that throws would take the decision with it -- and a decision we
    could not reach is a rejection, not a crash.
    """
    client = verifier if verifier is not None else default_verifier()
    if client is None:
        reason = (
            "The AP2 SDK is not available in this process, so the delegation "
            "chain could not be verified at all."
        )
        return PresentationReading(
            obligations=(
                _ob(CHAIN_VERIFIED, ObligationStatus.INDETERMINATE, reason,
                    expected="a verifiable AP2 presentation"),
                _ob(DISCLOSURES_PINNED, ObligationStatus.INDETERMINATE, reason,
                    expected=sorted(required_constraints)),
            ),
            disclosed_constraints=(),
            missing_constraints=tuple(sorted(required_constraints)),
            verified=False,
        )

    try:
        verified = client.verify(
            presentation.token,
            resolve_issuer_key,
            expected_aud=presentation.expected_aud,
            expected_nonce=presentation.expected_nonce,
        )
    except Exception as exc:
        # Deliberately broad: a signature failure, a malformed token, an
        # audience mismatch and a bug in the SDK are all "this presentation
        # did not verify", and none of them may reach the caller as a crash.
        logger.warning("AP2 chain verification failed: %s", exc)
        detail = f"The delegation chain did not verify: {type(exc).__name__}: {exc}"
        return PresentationReading(
            obligations=(
                _ob(CHAIN_VERIFIED, ObligationStatus.VIOLATED, detail,
                    expected="every hop's signature valid, aud and nonce bound"),
                _ob(
                    DISCLOSURES_PINNED,
                    ObligationStatus.INDETERMINATE,
                    "The chain did not verify, so its disclosed constraints "
                    "were never read. An unverified payload is not evidence "
                    "of what was disclosed.",
                    expected=sorted(required_constraints),
                ),
            ),
            disclosed_constraints=(),
            missing_constraints=tuple(sorted(required_constraints)),
            verified=False,
        )

    payloads = tuple(verified) if isinstance(verified, list) else (verified,)
    chain_ok = _ob(
        CHAIN_VERIFIED,
        ObligationStatus.SATISFIED,
        f"The delegation chain verified across {len(payloads)} hop(s): every "
        f"signature valid, key binding intact, audience and nonce as expected.",
        observed={"hops": len(payloads)},
        expected="every hop's signature valid, aud and nonce bound",
    )
    return PresentationReading(
        obligations=(chain_ok, _pin(payloads, required_constraints)),
        disclosed_constraints=disclosed_constraints(payloads),
        missing_constraints=_missing(payloads, required_constraints),
        verified=True,
        payloads=payloads,
    )


def _missing(payloads: Sequence[Any], required: Sequence[str]) -> tuple[str, ...]:
    present = set(disclosed_constraints(payloads))
    return tuple(sorted(set(required) - present))


def _pin(payloads: Sequence[Any], required: Sequence[str]) -> Obligation:
    """The detector. Enumerate what was disclosed; require what policy named."""
    if not required:
        # Vacuous truth is how this family of bug starts. A policy that
        # requires no constraint has not had this check pass -- it has not
        # asked for it.
        return _ob(
            DISCLOSURES_PINNED,
            ObligationStatus.NOT_APPLICABLE,
            "Policy names no required constraints, so there is nothing to pin.",
            observed={"disclosed": list(disclosed_constraints(payloads))},
        )

    present = disclosed_constraints(payloads)
    missing = _missing(payloads, required)
    if not missing:
        return _ob(
            DISCLOSURES_PINNED,
            ObligationStatus.SATISFIED,
            f"Every constraint policy requires is present in the presentation: "
            f"{', '.join(sorted(required))}.",
            observed={"disclosed": list(present)},
            expected={"required": sorted(required)},
        )
    return _ob(
        DISCLOSURES_PINNED,
        ObligationStatus.VIOLATED,
        f"{len(missing)} constraint(s) policy requires were withheld from this "
        f"presentation: {', '.join(missing)}. The chain is cryptographically "
        f"valid and reports no violation for them, because they were never "
        f"disclosed -- which is the whole finding. Absence is not consent.",
        observed={"disclosed": list(present), "withheld": list(missing)},
        expected={"required": sorted(required)},
    )
