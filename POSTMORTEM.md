# Postmortem

Written during the build, not after it. Every defect below was found while the
project was live and is recorded with what actually happened rather than what
was intended.

Measurements are from this machine (Windows 11, Python 3.13.2) on 2026-08-23 and
are reproducible with `pramana bench` and the commands quoted in each section.

---

## Numbers

### Latency

500 evaluations after 50 warm-up runs, one full decision each:

| Path | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- |
| Decision only | **0.062 ms** | 0.081 ms | 0.120 ms | 0.380 ms |
| Decision + hash-chained ledger write | **0.262 ms** | 0.381 ms | **0.637 ms** | 0.771 ms |

The stated budget was: *a checkout gate that adds 400 ms is not shippable
regardless of accuracy.* The p99 including a tamper-evident write is **0.637 ms**,
about 600x inside that budget. This was never in doubt — deterministic predicate
evaluation is cheap — but the budget was set before measuring, so the number
means something.

### Cost per decision

**Zero.** The authorisation path makes no network calls and no model calls, so a
decision costs CPU and nothing else. That is a property of the architecture
(ADR-0001), not a cost optimisation.

The AI layer, which sits strictly downstream of the decision, does cost
something. Measured against Groq's free tier:

| | prompt | completion | latency |
| --- | --- | --- | --- |
| Verdict explanation | 76 tok | 45 tok | 633 ms |
| Dispute narrative | 289 tok | 220 tok | 1094 ms |

At free-tier limits (Groq ~1,000 req/day, Cerebras ~1M tok/day) the AI layer
costs **₹0** at any volume this project will see. If it were paid, an explanation
is ~120 tokens round trip.

Two things follow. The AI layer is ~10,000x slower than the decision it
describes, which is precisely why it is not on the money path. And because it is
downstream, a provider outage costs an explanation, not a payment.

### Tests and coverage

| | |
| --- | --- |
| Tests | 559 |
| Statement coverage | **95%** |
| `pramana/kernel/gate.py` | 100% |
| `pramana/kernel/verdict.py` | 99% |
| `pramana/kernel/risk/signals.py` | 99% |
| Lowest module | `kernel/trace.py`, 84% |

### Benchmark

| | baseline | PRAMANA |
| --- | --- | --- |
| Attack-success rate (structural) | 58.3% (7/12) | **0.0%** (0/12) |
| False-positive rate | 0.0% (0/6) | **0.0%** (0/6) |

Read the caveat in `pramana bench` output before quoting the 0%. We wrote the
cases and we wrote the gate.

---

## What broke

Fifteen defects, grouped by how they were found. The pattern worth noting: **not
one of these came from writing more code. Every one came from running something
against reality.**

### Found by external review (4)

An adversarial review of the kernel found four defects in `verdict.py`, all of
which contradicted its own docstring. Each was reproduced before being fixed.

| | Defect | Why it mattered |
| --- | --- | --- |
| S3a | A verdict where every obligation was `NOT_APPLICABLE` returned **ALLOW** | The empty obligation set was unrepresentable; the *semantically* empty one was not. The same bug wearing a different hat. |
| S3b | `frozen=True` froze the binding, not the caller's list | A verdict already written to the evidence ledger could be flipped ALLOW→REJECT afterwards, changing its `content_hash`. |
| S3c | `canonical_bytes()` used `json.dumps(default=str)` | Arbitrary objects serialised via `repr`, **memory addresses included**. The "deterministic" hash was not. |
| S3d | `mandate_ref` defaulted to `None`; `trace_id` accepted `"x"` | An evidence record with no protocol anchor is not evidence. |

The review also proposed the **coverage invariant** now in ADR-0003: a verdict
carries the obligation ids its policy declared, and any declared id with no
reported result becomes `INDETERMINATE`. Without it the kernel reproduced the
exact failure it was built to catch — inability to distinguish *checked and
passed* from *never checked*. That was the single most valuable change in the
codebase and it came from someone else reading it.

### Found by running against a live provider (3)

None of these are reachable with mocks. All three appeared within minutes of the
first real API key.

1. **Model IDs were wrong.** `llama-3.3-70b` and `llama-3.3-70b-versatile` both
   404. They came from search results rather than the providers' `/models`
   endpoints. Corrected to `gpt-oss-120b` and `openai/gpt-oss-120b`, and dated,
   because they will move again.

2. **Reasoning models starve small token budgets.** `gpt-oss-120b` emits
   chain-of-thought into a separate `reasoning` field billed against
   `max_tokens`. At `max_tokens=16`, reasoning consumed 35 of 45 tokens and
   `content` came back empty. The adapter now adds `reasoning_overhead_tokens`
   and reports the specific cause instead of a generic "empty completion".

3. **A model crashed the CLI with a space.** A live explanation contained U+202F
   (narrow no-break space). The cp1252 console could not encode it and `print`
   raised `UnicodeEncodeError` mid-output. **This would have been a hard crash on
   stage.** Fixing our own strings does not help — model output is not ours — so
   it is handled at the render boundary: streams reconfigured to
   `utf-8/errors=replace`, plus transliteration of the punctuation models
   actually emit.

   *Footnote, added while writing this file:* the script verifying this
   document was ASCII-clean crashed with `UnicodeEncodeError` on the rupee
   sign it contains. Same bug class, three sections later, in the tooling
   checking for it. The distinction that resolves it is worth stating: **CLI
   output must be ASCII** because a cp1252 console will kill the process;
   **markdown may be UTF-8** because a browser renders it. `console.py`
   enforces the first. This file is the second.

### Found by the fresh-clone test (2)

Cloning the repo into a clean directory and following the README exactly. Both
would have hit a judge within minutes.

1. **`pytest` from `tests/` produced 34 failures.** The policy was loaded via
   `Path("policies/rbi-in.yaml")`, resolved against the working directory. The
   suite only passed when the process happened to start in the repo root.

2. **`pramana bench` from any other directory raised `ModuleNotFoundError`.**
   `packages.find` included only `pramana*`, so `bench` was never installed.

Both fixed by shipping the default policy as package data resolved through
`importlib.resources`, and packaging `bench`.

### Found by publishing (3)

1. **The `.gitignore` was itself the leak.** It listed the strategy documents by
   name under a comment describing them as containing "competitive positioning,
   judge analysis, and scope tactics". That comment was tracked. A public repo
   would have shipped a signed statement that such a document exists. Fixed in
   HEAD **and purged from history** before the first push.

2. **`SECURITY.md` made a promise the repo broke.** It stated reproduction
   details were "withheld from this repository" while both reproduction scripts
   were tracked *in that repository*. Nothing leaked — there was no remote — but
   the statement was false as written and contradicted an embargo commitment
   about to be made in writing to a vendor.

3. **Our own upstream PR failed spellcheck.** The `budget.max` description used
   "paise", not in AP2's cspell dictionary. Rewritten currency-neutral, which is
   better for an international protocol anyway. The same run flagged
   `pisp`/`pisps` — words already appearing nine times on their `main`, surfaced
   only because the job scans changed files.

### Found by our own tests, in our own tests (3)

Recorded because it would be dishonest to list only the code defects.

- A tamper-detection test set `decision = "allow"` on a verdict that was
  **already** `allow`, then asserted the hash changed. It did not. The test was
  wrong; the hash function was correct.
- A benchmark test used `range(10)`, producing `trace_id` `0`, which `Verdict`
  correctly rejects as the all-zero W3C trace id.
- A gateway test used `response.ok`, a `requests` idiom. httpx exposes
  `is_success`.

In each case the first instinct was that the code was broken. Verifying before
"fixing" saved three regressions.

---

## The bug we shipped to a vendor, having hit it ourselves

The strongest evidence for the `Budget.max` unit finding is that **we made the
error first**.

The initial spike set a cap of `5000.0` against a charge of `47500` and observed
no violation. The hypothesis looked disproved. It was not: `BudgetEvaluator`
computes `int(constraint.max * 100)`, so `Budget.max` is in major units while its
sibling `AmountRange.max` is documented in minor units. The charge was ₹475
against a ₹5,000 cap — correctly allowed.

An issuer following the schema descriptions gets a cap **100x larger than
intended**, and enforcement appears to work throughout. That experience is quoted
in the upstream report, because "I made this mistake using your documentation" is
a stronger argument than "someone might".

---

## What we would fix with more time

Ordered by what we would do first, not by how impressive it sounds.

1. **Tail-truncation detection in the ledger.** `verify()` catches modification,
   deletion, reordering and broken links. It does **not** catch records removed
   from the *end* — that leaves a shorter but internally valid chain. This is
   asserted in a test named for the limitation rather than left implied. Fixing
   it needs an external anchor: a countersigned head, or a published checkpoint.

2. **The three-hop `issuer_jwt_hash` case.** We demonstrated presence-driven
   evaluation with a single hop, default `sd_hash`, and a holder-chosen
   redaction. The SDK README describes `issuer_jwt_hash` as letting a downstream
   delegate drop disclosures without breaking chain integrity. If that is
   adversarially reachable it is a materially stronger finding. We asked the
   vendor and said plainly in the report that we had not shown it.

3. **Real AP2 objects at the gate boundary.** `PaymentRequest` takes already-
   extracted facts. The adapter that turns a live AP2 presentation into those
   facts is the one piece the benchmark simulates rather than exercises.

4. **A legitimate-traffic corpus we did not author.** The false-positive rate is
   0/6 against six boundary cases we wrote. Six is not a corpus, and we wrote
   them. Real traffic, or AIP-Bench's cases when they release on 2026-10-04,
   would make the number mean something.

5. **`kernel/trace.py` to 95%.** Lowest-covered module at 84%. The gaps are the
   `secrets` collision retry loops, which are hard to exercise honestly.

6. **Catalogue integrity (RC-1).** Currently caught only through merchant policy.
   A real content-integrity scanner is unbuilt and the benchmark says so.

---

## What we would do differently

**Run the fresh-clone test on day one, not day three.** Both packaging bugs
existed from the first commit. They cost nothing to fix and would have cost the
demo everything.

**Get a live API key before writing the adapter, not after.** All three provider
bugs were invisible to a test suite with an injected transport — which was
otherwise the right design, and still is.

**Write the security posture and the repository together.** `SECURITY.md` made a
claim about the repository that the repository contradicted, because they were
written at different times and never checked against each other. A statement
about what a repo contains should be tested like anything else.

**Verify a review's claims before acting on them.** The external review was
largely correct and its central proposal was excellent. It was also wrong about
`pip install -e .` failing. Reproducing each claim took minutes and prevented a
"fix" for a problem that did not exist.

---

## What held up

Recorded because a postmortem that only lists failures is not an honest account
of the build either.

- **Fail-closed as a type, not a convention.** `Verdict.decision` is derived and
  cannot be assigned. Every attempt to produce an unearned ALLOW — an empty
  obligation set, an all-`NOT_APPLICABLE` set, a missing declared obligation, a
  crashed predicate group, an unwritable ledger — is a construction error or a
  rejection. Several of those were found *because* the invariant existed to
  violate.

- **The injected transport.** Every provider test runs with no network and no
  credential. Failover, exponential backoff, rate limiting, malformed responses
  and offline mode are all genuinely exercised. It is also why the three live
  bugs were invisible; both halves of that trade-off are real.

- **The AI boundary.** Sixteen injection payloads through a model scripted to
  return exactly what the attacker asked for. The verdict's decision and content
  hash are byte-identical every time, because nothing in the codebase converts a
  string into an `ObligationStatus`.

- **Deciding the honest framing before knowing the outcome.** The benchmark
  prints "we wrote these cases and we wrote the gate" unconditionally, with a
  test asserting it cannot be dropped. That was written before the result was
  0.0%. It would have been much harder to add afterwards.
