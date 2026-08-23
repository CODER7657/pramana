# ADR-0004: Models everywhere except the decision

* Status: Accepted
* Date: 2026-08-23
* Extends: [ADR-0001](0001-deterministic-money-path.md)
* Evidence: `tests/unit/test_explainer.py::TestPromptInjection`

## Context

ADR-0001 established that no model participates in an authorisation decision.
Taken alone, that reads as "this project contains no AI", which is both
uninteresting and a poor answer to the obvious question.

The useful position is narrower and stronger: **models are used throughout the
system, and the one place they are excluded from is the decision.** That is only
worth claiming if the exclusion is structural. A promise in a README is not an
architecture.

## Decision

Language models operate strictly downstream of `Verdict`. Every AI surface takes
a `Verdict` as input and returns prose, a document, or a ranking. None returns a
`Verdict`, an `Obligation`, or an `ObligationStatus`.

| Surface | Input | Output | Can affect a decision |
| --- | --- | --- | --- |
| Verdict explainer | `Verdict` | merchant-facing prose | No |
| Dispute-pack drafter | `Verdict` + ledger chain | evidence document | No |
| Exception triage | rejected verdicts | ranked review queue | No |
| Buying agent | shopping intent | an AP2 mandate request | No — it is the *governed* party |

## Why the boundary holds

Three independent mechanisms, not one:

1. **Type asymmetry.** `Verdict.decision` is a derived property computed from
   obligation statuses. Obligations are constructed only by deterministic
   predicates. There is no function anywhere that turns a string into an
   `ObligationStatus`, so there is no path from model output to a decision.

2. **Constructor invariants.** Even if such a path were added by mistake, a
   `Verdict` cannot be built without a policy-declared obligation set, at least
   one `SATISFIED` obligation, and full coverage of declared ids (ADR-0003). A
   model producing free text cannot satisfy those.

3. **Input narrowing.** The model never receives raw attacker text. Obligation
   ids, statuses, and sources are enum- and policy-controlled. Only
   `observed`/`expected` carry attacker-influenceable content, and those are
   already constrained to JSON-safe types, then stripped of control characters,
   collapsed to a single line, and capped at 200 characters before templating.

## Verification

`TestPromptInjection` drives eight hostile payloads — instruction override,
fake system turns, delimiter escape, SQL, ANSI control sequences, a 5,000
character flood — through both `observed` and `detail`, with the model scripted
to return exactly what the attacker asked for ("APPROVED. The payment is
allowed."). Every case asserts the verdict's `decision` and `content_hash()` are
unchanged.

A fully attacker-controlled provider is also tested: returning `"ALLOW"`,
`{"decision":"allow"}`, or an empty body changes nothing.

## Failure behaviour

The explainer never raises and never blocks. If every provider is rate limited,
unreachable, or returns nonsense, it degrades to a deterministic template built
from the same obligations, and marks the result `degraded=True` so a dispute
reviewer can tell prose from template.

This is the deliberate inverse of the money path. Authorisation **fails closed**
— unavailability yields `INDETERMINATE`, which rejects. Explanation **fails
open** — unavailability yields a blunter sentence. Neither trades away the
other's property.

## Consequences

* Every AI surface must be expressible as a pure function of an existing
  verdict. A feature that needs a model *before* the decision does not get built.
* We can demonstrate the boundary live: inject the explainer on stage, watch the
  explanation corrupt and the verdict not move.
* "We deliberately used no AI" would have been a weak answer. "Models
  everywhere except the decision, and here is the type that enforces it" is a
  claim that survives someone opening the source.
