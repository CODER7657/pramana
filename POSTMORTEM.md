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
| Tests | 670 |
| Statement coverage | **95%** |
| `pramana/kernel/gate.py` | 100% |
| `pramana/kernel/verdict.py` | 99% |
| `pramana/kernel/risk/signals.py` | 99% |
| Lowest module | `pramana/config.py`, 50% — then `kernel/trace.py`, 84% |

### Benchmark

| | baseline | PRAMANA |
| --- | --- | --- |
| Attack-success rate (structural) | 53.8% (7/13) | **0.0%** (0/13) |
| False-positive rate | 0.0% (0/8) | **0.0%** (0/8) |

Read the caveat in `pramana bench` output before quoting the 0%. We wrote the
cases and we wrote the gate.

---

## What broke

Twenty-seven defects, grouped by how they were found. The pattern worth noting: **not
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

### Found by a second external review (7)

A second adversarial pass, after the build was "finished", found seven more.
Every one was a place where **a document outran the code** — which is the
dangerous failure mode for a submission positioned on checkable claims.

| | Defect |
| --- | --- |
| Ledger | `verify()` skipped the body check when the hash could not be recomputed. Appending an out-of-domain integer made rfc8785 raise, the error was swallowed, and a rejection rewritten as an allow **passed verification**. The project's own thesis — absence of a result is not compliance — violated inside the function that detects tampering. |
| RBI | The ₹1,00,000 enhanced ceiling was **unreachable**. `afa_threshold` applied the ₹15,000 standard ceiling to every category, and since any blocking obligation rejects, `category_ceiling` returning SATISFIED could never rescue it. Every insurance premium, SIP and card autopay between the two ceilings was wrongly refused. |
| Gate | `evaluate()` documented that it never raises. Duplicate obligation ids escaped as a **500 on an unauthenticated endpoint**. |
| Invariant 4 | Satisfied by bookkeeping. `evidence.recorded` was SATISFIED on every ledger append, so an all-`NOT_APPLICABLE` policy result reached ALLOW whenever the ledger was up — the hole we closed, reopened one layer down. |
| Ledger | The **ledgered verdict was not the returned verdict**. A provisional one was written; nothing bound the evidence to the decision acted on. |
| Coverage | Synthesised obligations hardcoded `MERCHANT`, so a missing `rbi.*` check was attributed to merchant policy with no citation — in a system where ADR-0006 makes citations mandatory for regulatory obligations. |
| Benchmark | The baseline is a **derived configuration of the same kernel**, so for omitted-obligation cases the delta is an identity measuring the coverage invariant, not a measurement. |

The RBI one is the most instructive. Our test suite had a passing test for the
enhanced ceiling — it evaluated `category_ceiling` **in isolation**, never
against the full regulatory set, so it never saw `afa_threshold` blocking
alongside it. A green test asserted the opposite of the truth. The benchmark
now carries the ₹50,000 insurance premium as a case, and that case failed when
it was written.

### Found by a third external review (5)

The third pass verified every fix from the second and then broke the fix itself.

**The carve-out fix opened a fail-open.** Closing the ₹1,00,000 ceiling defect
left `rbi.afa_threshold` deferring the enhanced categories to
`rbi.category_ceiling` — and both obligations carried **their own copy of the
category list**. Deleting one word from one copy:

```
INR 50,00,000 insurance premium, no AFA, everything else clean
  policy as shipped                         -> 403  blocking=['rbi.category_ceiling']
  one word dropped from enhanced_categories -> 200  blocking=[]   coverage=1.0
```

An unauthenticated debit of fifty times the enhanced ceiling, authorised, with
coverage reporting 1.0. **No verdict-level invariant could see it.** Both
obligations reported a result, so coverage was satisfied. Both said
`NOT_APPLICABLE`, so nothing blocked. Each predicate was individually correct,
because each had been told the other one held the case.

That is the same family as the empty obligation set and the all-`NOT_APPLICABLE`
verdict, appearing a third time one layer up: *responsibility transferred, and
nobody receiving it.* A handoff with no receiver is absence wearing a
delegation. The fix is therefore an invariant rather than a patch —
`Policy._resolve_handoffs` reads the list **from the receiver** so no second copy
exists to drift, and refuses to load a policy whose handoff receiver is absent,
disabled, or empty. Disabling the receiver used to silently drop the rule; it is
now a load error that says so.

The other four, all claims-outrunning-code:

| | Defect |
| --- | --- |
| Benchmark | The README's "The number" block was **five numbers stale** — 58.3% (7/12) and 0/6 legitimate, three commits after the suite grew to 13 and 8. The test count was guarded by a test; the expensive number was not. Now every rate line and per-class row is compared against a live run. |
| Evidence | An obligation id the policy **never declared** was accepted from the wire and written to the ledger. It could not authorise anything, but in an evidence record it reads exactly like a check somebody required and somebody performed. The caller reports what it evaluated; it does not get to extend the policy. |
| Benchmark | The latency line said "including the ledger write" while the runner used `MemoryStore`. The only durable backend shipped, `JsonlStore`, costs 22 ms at depth 2000. The output now names the store, and the sample size. |
| README | The component table claimed the benchmark covered **RC-1..RC-6**. There are no RC-6 cases. RC-6 is semantic — it belongs to the model, not the gate — and is now listed as out of scope, which is the true statement and the better one. |

One review claim did **not** reproduce: coverage was reported as 96% against a
95% badge. Measured at `--precision=1` it is **95.1%**, so the badge was right
and the correction was wrong. Verifying before acting has now caught two of
these across three reviews, which is the entire reason for the habit.

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

1. **Signing the ledger head.** `verify()` catches modification, deletion,
   reordering, broken links, and — since a second review — bodies that cannot be
   recomputed at all. It does **not** catch records removed from the *end*, which
   leaves a shorter but internally valid chain, and it cannot prove *we* produced
   the chain rather than someone who recomputed it wholesale. Both need the same
   thing: an Ed25519 signature over the head hash. That turns "tamper-evident to
   us" into "non-repudiable to a third party".

   The *recomputation* half of that claim is now an artifact rather than an
   assertion: `tools/verify.mjs` is 40 lines of dependency-free Node that
   re-implements RFC 8785 and the chain rules from the spec, and a test
   requires it to agree with the Python on the same bytes -- including on the
   truncated tail that neither can catch. The comparison table now says
   "recomputable" rather than "verifiable", which is the word the code
   supports.

2. **The three-hop `issuer_jwt_hash` case.** We demonstrated presence-driven
   evaluation with a single hop, default `sd_hash`, and a holder-chosen
   redaction. The SDK README describes `issuer_jwt_hash` as letting a downstream
   delegate drop disclosures without breaking chain integrity. If that is
   adversarially reachable it is a materially stronger finding. We asked the
   vendor and said plainly in the report that we had not shown it.

3. ~~**Real AP2 objects at the gate boundary.**~~ **Shipped.**
   `pramana/adapters/ap2.py` verifies a real presentation and enumerates the
   constraints it actually disclosed, so `chain.disclosures_pinned` is a
   detector rather than a declaration. `pramana chain` runs it end to end
   against the SDK at the pinned SHA. The benchmark still simulates the
   protocol layer, and `mandate.*` is still caller-supplied.

4. **A legitimate-traffic corpus we did not author.** Partly addressed and
   still open. `bench/corpus.py` now carries twelve recurring-payment shapes
   derived from the RBI framework's own parameters rather than from the
   predicates, each naming its provision, each weighted with a ticket size so
   `pramana cost` can report refused volume in rupees rather than as a rate.
   What has *not* changed is who wrote them. A shape nobody thought of is a
   shape nobody wrote, so real merchant traffic -- or AIP-Bench when its
   artifacts release on 2026-10-04 -- is still what would make the number
   independent.

5. **`pramana/config.py` and `kernel/trace.py`.** The two lowest-covered modules,
   at 50% and 84%. `config.py`'s gap is the `.env` parse loop, which is trivial to
   cover and simply was not; `trace.py`'s is the `secrets` collision retry loops,
   which are hard to exercise honestly. Neither is on the decision path — `gate.py`
   is at 100% and `verdict.py` at 99% — but "lowest module" naming `trace.py` was
   wrong once `config.py` landed, which is exactly the drift this file exists to
   record.

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

- **The AI boundary.** Eight injection payloads through both attacker-reachable
  fields — sixteen cases — against a model scripted to return exactly what the
  attacker asked for. The verdict's decision and content hash are byte-identical
  every time, because nothing in the codebase converts a string into an
  `ObligationStatus`.

- **Deciding the honest framing before knowing the outcome.** The benchmark
  prints "we wrote these cases and we wrote the gate" unconditionally, with a
  test asserting it cannot be dropped. That was written before the result was
  0.0%. It would have been much harder to add afterwards.
