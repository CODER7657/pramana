"""Advisory risk signals, and the one-way property that makes them safe.

PRAMANA is not a fraud model and does not try to be. Razorpay's Vulcan is a
transformer trained on roughly three trillion data points across four billion
payments, using ~3,000 signals per transaction. Competing with that would be
absurd; ignoring it would be worse.

This module is the integration contract instead.

**Risk and authority are different questions.**

    Vulcan-class scorer:  "Is this transaction likely to be fraudulent?"
    PRAMANA:              "Was this agent permitted to make it?"

The first is correctly probabilistic -- it optimises expected value against a
tunable threshold, and a good model beats a bad one. The second is binary and
cryptographic. There is no threshold at which "probably authorised" is an
acceptable answer, which is why no model sits on that path (ADR-0001).

**The one-way property.**

An advisory signal can only ever *subtract* authority. Concretely:

* A HIGH risk band may emit a ``VIOLATED`` obligation, which blocks.
* A LOW risk band emits ``NOT_APPLICABLE``. It never emits ``SATISFIED``.
* An unavailable scorer emits ``NOT_APPLICABLE``. It never blocks.

So plugging in an external model can *tighten* the gate and can never loosen
it. A scorer that is compromised, degraded, mis-thresholded, or adversarially
manipulated into returning "low risk" for everything changes nothing: the
deterministic obligations still have to pass on their own.

Note the deliberate asymmetry with the money path. A *required* obligation that
cannot be evaluated is ``INDETERMINATE`` and rejects, because its absence hides
whether authority existed. An *advisory* signal that cannot be evaluated is
``NOT_APPLICABLE`` and does not reject, because it could never have granted
authority in the first place. Absence only matters where presence would have
mattered.

See docs/adr/0005-advisory-risk-signals.md
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from typing import Any, Final, Protocol, cast, runtime_checkable

from pramana.kernel.verdict import Obligation, ObligationSource, ObligationStatus

logger = logging.getLogger(__name__)

ADVISORY_PREFIX: Final = "risk."
"""Every advisory obligation id is namespaced. Policy must not *declare* one --
declaring it would demand a result, and an advisory signal is by definition
one we are willing to proceed without."""

DEFAULT_BLOCK_THRESHOLD: Final = 0.90
"""Score at or above which an advisory signal is allowed to block. Deliberately
high: a false positive here is blocked legitimate GMV, and the deterministic
obligations are the primary control."""


class RiskBand(enum.StrEnum):
    """Coarse bands, so a policy is not written against a provider's raw scale."""

    LOW = "low"
    ELEVATED = "elevated"
    HIGH = "high"
    UNKNOWN = "unknown"
    """The scorer was unreachable, timed out, or returned nothing usable."""


@dataclass(frozen=True, slots=True)
class RiskSignal:
    """One external assessment. Advisory by construction."""

    provider: str
    """Who produced it, e.g. ``"vulcan"``. Recorded in the evidence trail."""

    band: RiskBand
    rationale: str
    score: float | None = None
    """Normalised 0.0-1.0 where the provider exposes one. ``None`` is fine."""

    signals_considered: int | None = None
    """Provider-reported feature count, purely for the audit record."""

    def __post_init__(self) -> None:
        if not self.provider:
            raise ValueError("RiskSignal.provider must be non-empty")
        if not self.rationale:
            raise ValueError("RiskSignal.rationale must be non-empty")
        if self.score is not None and not 0.0 <= self.score <= 1.0:
            raise ValueError(
                f"RiskSignal.score must be within [0.0, 1.0], got {self.score}"
            )

    @classmethod
    def unavailable(cls, provider: str, reason: str) -> RiskSignal:
        """Construct the signal for a scorer we could not reach."""
        return cls(
            provider=provider,
            band=RiskBand.UNKNOWN,
            rationale=f"Risk signal unavailable: {reason}",
        )


@runtime_checkable
class RiskAdapter(Protocol):
    """An external scorer. Implement this to plug Vulcan, or anything else, in.

    Implementations must not raise; return
    :meth:`RiskSignal.unavailable` instead. :func:`assess_safely` enforces this
    for adapters that misbehave.
    """

    name: str

    def assess(self, context: dict[str, Any]) -> RiskSignal: ...


class NullRiskAdapter:
    """No scorer configured. Always UNKNOWN, which never blocks."""

    name = "none"

    def assess(self, context: dict[str, Any]) -> RiskSignal:
        return RiskSignal.unavailable("none", "no risk adapter configured")


def assess_safely(
    adapter: RiskAdapter, context: dict[str, Any]
) -> RiskSignal:
    """Call an adapter, converting any failure into an UNKNOWN signal.

    A misbehaving risk model must not be able to take down the gate, and must
    not be able to block a payment by throwing either.
    """
    signal: object
    try:
        # Deliberately typed as `object`: the Protocol *declares* RiskSignal,
        # but a third-party adapter is not obliged to honour it and mypy would
        # otherwise prove the isinstance check below unreachable.
        signal = cast(object, adapter.assess(context))
    except Exception as exc:  # a third-party scorer is not trusted to behave
        logger.info("risk adapter %r failed: %s", getattr(adapter, "name", "?"), exc)
        return RiskSignal.unavailable(
            getattr(adapter, "name", "unknown"), f"{type(exc).__name__}: {exc}"
        )
    if not isinstance(signal, RiskSignal):
        logger.warning("risk adapter returned %r, not a RiskSignal", type(signal))
        return RiskSignal.unavailable(
            getattr(adapter, "name", "unknown"), "adapter returned a non-signal"
        )
    return signal


def to_obligation(
    signal: RiskSignal,
    *,
    block_threshold: float = DEFAULT_BLOCK_THRESHOLD,
    obligation_id: str | None = None,
) -> Obligation:
    """Convert an advisory signal into an obligation.

    The one-way property lives here, and it is enforced by construction: this
    function has exactly two possible statuses in its output, and
    ``SATISFIED`` is not one of them.

    * ``HIGH`` band, and a score at or above ``block_threshold`` (or no score
      at all) -> ``VIOLATED``. Blocks.
    * Everything else, including ``LOW`` and ``UNKNOWN`` -> ``NOT_APPLICABLE``.
      Does not block, and does not contribute to an ``ALLOW``.
    """
    ident = obligation_id or f"{ADVISORY_PREFIX}{signal.provider}"
    if not ident.startswith(ADVISORY_PREFIX):
        raise ValueError(
            f"advisory obligation id must start with {ADVISORY_PREFIX!r}, "
            f"got {ident!r}"
        )

    observed: dict[str, Any] = {
        "provider": signal.provider,
        "band": str(signal.band),
    }
    if signal.score is not None:
        observed["score"] = signal.score
    if signal.signals_considered is not None:
        observed["signals_considered"] = signal.signals_considered

    blocks = signal.band is RiskBand.HIGH and (
        signal.score is None or signal.score >= block_threshold
    )

    if blocks:
        return Obligation(
            id=ident,
            status=ObligationStatus.VIOLATED,
            source=ObligationSource.RISK,
            detail=(
                f"Advisory risk signal from {signal.provider} is HIGH: "
                f"{signal.rationale}"
            ),
            observed=observed,
            expected={"band_below": str(RiskBand.HIGH)},
        )

    return Obligation(
        id=ident,
        status=ObligationStatus.NOT_APPLICABLE,
        source=ObligationSource.RISK,
        detail=(
            f"Advisory risk signal from {signal.provider} did not block "
            f"({signal.band}): {signal.rationale}. Advisory signals never "
            f"grant authority."
        ),
        observed=observed,
    )


def advisory_obligations(
    adapters: tuple[RiskAdapter, ...],
    context: dict[str, Any],
    *,
    block_threshold: float = DEFAULT_BLOCK_THRESHOLD,
) -> tuple[Obligation, ...]:
    """Run every configured adapter and convert the results.

    Adapters are independent: one failing does not prevent the others running,
    and none of them can cause an ``ALLOW``.
    """
    return tuple(
        to_obligation(
            assess_safely(adapter, context), block_threshold=block_threshold
        )
        for adapter in adapters
    )
