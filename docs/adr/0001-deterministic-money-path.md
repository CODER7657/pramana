# ADR-0001: No model on the money path

* Status: Accepted
* Date: 2026-08-23

## Context

PRAMANA decides whether an agent-initiated payment is authorised. The obvious
temptation in an AI hackathon is to put a model in that decision.

The competing project in this space, `internet-court/internet-court-skill`
(4,484 stars), adjudicates *natural-language* mandates with an LLM.

## Decision

No model participates in an authorisation decision. The kernel is deterministic
code evaluating signed constraints against a declarative policy. Models may be
used off the money path (catalogue triage, report drafting) but never to produce
or influence a `Verdict`.

## Rationale

The distinction the project rests on is **structural** versus **semantic**
attacks. Semantic attacks weaken as models improve; structural attacks succeed
deterministically regardless of model quality. A model in the decision path
*reintroduces* a semantic attack surface into the one place we claim not to have
one -- and anything that can be argued out of a decision does not belong on a
money path.

It also makes the system testable: a deterministic gate has a reproducible
attack-success rate. A model-mediated one has a distribution.

## Consequences

* Every check must be expressible as a predicate over signed data.
* Cases that cannot be decided deterministically resolve to `INDETERMINATE`,
  which rejects (ADR-0003). We accept false positives over false negatives.
* We must report false-positive cost honestly, in blocked legitimate GMV.
