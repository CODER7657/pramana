# ADR-0006: Every regulatory decision cites its authority

* Status: Accepted
* Date: 2026-08-23
* Extends: [ADR-0005](0005-advisory-risk-signals.md)
* Evidence: `tests/unit/test_verdict.py::TestCitation`

## Context

ADR-0005 established that PRAMANA does not compete with a fraud model. That is
correct but incomplete: "we do something different" is a weaker position than
"we do something they structurally cannot".

A learned scorer has four limits that more data does not fix:

1. **It produces a score, not a reason.** A probability is not evidence. In a
   dispute, "the model returned 0.94" is not a defence anyone can examine.
2. **It cannot be replayed.** Vulcan is described as improving with every
   transaction. Weights move, so a decision from eight months ago is not
   reproducible even in principle.
3. **It cannot cite a provision.** RBI compliance is demonstrable conformance to
   a written rule. A black box cannot demonstrate conformance to anything.
4. **A merchant cannot run or audit it.** It is proprietary and hosted.

Those are the dimensions where PRAMANA can be better rather than merely
different, so the architecture should make them explicit rather than implied.

## Decision

**A verdict is a compliance artifact, not a decision record.**

Two changes make that structural:

### 1. `Citation` is a first-class type, and regulatory obligations require one

`Obligation` gains an optional `citation: Citation | None`, carrying the
authority, instrument, clause, effective date and URL. `__post_init__` rejects
any obligation whose source is `REGULATORY` and whose citation is `None`:

> You cannot claim a rule rejected a payment without naming the rule.

The citation is inside the canonicalised payload, so it is committed to by the
verdict hash and by the ledger chain. A verdict citing a different provision is
a different record. `effective_from` is carried because a provision cannot bind
a transaction that predates it, and a dispute may turn on exactly that.

### 2. Replay is a first-class operation

`pramana replay` recomputes each stored verdict's digest from its body and shows
the result is byte-identical. The computation is SHA-256 over RFC 8785, so a
third party can perform it without this codebase, in another language, years
later.

## Consequences

* Every rejection is answerable to a named authority. `mandate.*` obligations
  point at the user's own signed constraints; `rbi.*` at the notification;
  `merchant.*` at merchant policy.
* Adding a regulatory predicate now requires sourcing it. That is friction we
  want -- a wrong threshold quoted confidently is worse than no threshold.
* The comparison a reviewer can make is concrete rather than rhetorical:

  | | Learned scorer | PRAMANA |
  | --- | --- | --- |
  | Output | score | named obligation + provision |
  | Reproducible in 8 months | no -- weights moved | yes, byte-identical |
  | Verifiable by a third party | no | yes, without our code |
  | Cites a regulation | no | required |

* This does **not** claim PRAMANA is better at detecting fraud. It is not, it
  does not try to be, and ADR-0005 says so. It claims that authority decisions
  should be provable, and that a probabilistic system cannot make them provable
  no matter how good it gets.
