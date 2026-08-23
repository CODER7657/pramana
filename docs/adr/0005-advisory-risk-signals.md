# ADR-0005: Advisory risk signals are one-way

* Status: Accepted
* Date: 2026-08-23
* Extends: [ADR-0001](0001-deterministic-money-path.md), [ADR-0004](0004-ai-boundary.md)
* Evidence: `tests/unit/test_risk_signals.py::TestOneWayProperty`

## Context

On 18 August 2026 Razorpay launched **Vulcan**, a transformer foundation model
for payments: ~3 trillion data points across 4 billion payments, ~3,000 signals
per transaction, reported 8-10% uplift in payment success and up to 8x more
international card fraud detected. Its four named capabilities are
hyper-precision routing, network-level fraud detection, RTO risk intelligence,
and predictive checkout personalisation.

Two questions follow. Does it overlap PRAMANA? And what should PRAMANA do
about it?

## Analysis

**No overlap, because they answer different questions.**

| | Vulcan-class scorer | PRAMANA |
| --- | --- | --- |
| Question | "Is this transaction likely fraudulent?" | "Was this agent permitted to make it?" |
| Method | Probabilistic, learned from history | Deterministic, cryptographic |
| Output | A score against a tunable threshold | A binary verdict with named obligations |
| Improves with | More data, better architecture | Nothing -- it is already exact |
| Correct to be a model | Yes | No |

Neither of Razorpay's public Vulcan materials -- the launch press release or the
capability list -- mentions agentic payments, AI agent authorisation, mandates,
or cryptographic verification. Vulcan is a risk layer. It is not a mandate
verifier, and nothing suggests it is meant to be.

**The withheld-constraint case shows why the gap is structural.** A compromised
agent presenting a chain with the spending cap withheld produces a transaction
that is statistically unremarkable: known agent, valid chain, amount inside its
own historical range, familiar merchant. There is no anomaly to detect. This is
the distinction the project rests on -- semantic attacks weaken as models
improve, structural ones do not.

**Two consequences.**

First, the behavioural risk scorer originally planned as C3 is cancelled
permanently. Building one would mean shipping a worse model than Vulcan to the
people who built Vulcan, trained on synthetic data we generated ourselves. It
was already the weakest component; this settles it.

Second, we should *integrate* rather than ignore. A merchant running both should
get the union of their protection, not a choice between them.

## Decision

Introduce `ObligationSource.RISK` and a small adapter contract for external
scorers, governed by a single invariant:

> **An advisory signal can subtract authority. It can never add any.**

* `HIGH` band at or above the block threshold -> `VIOLATED`, which blocks.
* Every other band, including `LOW` -> `NOT_APPLICABLE`. Never `SATISFIED`.
* An unreachable, throwing, or malformed scorer -> `NOT_APPLICABLE`. Never blocks.

`to_obligation` has exactly two reachable statuses and `SATISFIED` is not one of
them. `TestOneWayProperty` sweeps every band against nine score values,
including the boundaries, and asserts `SATISFIED` is unreachable.

## Why this composition is safe

A risk model integrated this way can be wrong, degraded, mis-thresholded, or
fully attacker-controlled and still cannot authorise a payment. If it returns
"low risk" for everything, the deterministic obligations must each still pass on
their own merits. The worst an adversary achieves by capturing the scorer is
losing a control they did not have before.

Conversely a throwing scorer cannot deny service: failure yields `UNKNOWN`,
which does not block. A fraud model must not become an outage on checkout.

## The asymmetry with the money path, stated deliberately

ADR-0003 requires that a policy-declared obligation which could not be evaluated
becomes `INDETERMINATE` and rejects. Advisory unavailability does the opposite.

That is not an inconsistency. A required obligation's absence hides whether
authority existed -- absence there is exactly the failure mode we exist to catch.
An advisory signal's absence hides nothing, because its presence could never
have granted authority. **Absence only matters where presence would have
mattered.**

For this reason advisory ids are namespaced `risk.*` and policy must never
*declare* one. Declaring it would demand a result, which contradicts calling it
advisory.

## Consequences

* PRAMANA has a defined integration point for Vulcan and any comparable scorer.
* We make no claim to do fraud detection, and the README says so.
* The pitch position is complementary, not competitive: *Vulcan scores, PRAMANA
  verifies, and a merchant should run both.*
* If Razorpay's stated roadmap -- "every payment decision, from authentication
  to routing to fraud to lending, powered by one continuously learning model" --
  ever extends to agent authorisation, this ADR is the place to revisit. Our
  position is not that models are bad, but that authority is not a prediction.
