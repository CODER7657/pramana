# PRAMANA

**A deterministic verification gate for agent-initiated payments. No model on the money path.**

PRAMANA sits between an AI buying agent and merchant checkout. It re-verifies the signed
[AP2](https://github.com/google-agentic-commerce/AP2) authorisation chain server-side,
enforces the RBI E-mandate envelope as executable predicates, and writes a hash-chained
evidence record for every verdict.

The substrate is **agent-native payments (AP2 / SD-JWT delegation chains)**, hardened with
**policy-as-code**. Language models are used throughout the system — to shop, to explain a
decision, to draft a dispute pack — but never to *make* one. That boundary is enforced by
the type system, not by convention. See [ADR-0001](docs/adr/0001-deterministic-money-path.md).

> **Defence only.** PRAMANA is a verification and policy layer. Its attack cases are a
> fixed, closed regression suite that runs exclusively against its own local sandbox. It
> contains nothing that generates novel attacks and nothing that targets a third-party
> system. See [SECURITY.md](SECURITY.md).

---

## The problem, in one screen

```bash
pramana demo
```

```
====================================================================
2. SPENDING CAP WITHHELD FROM THE PRESENTATION
====================================================================
decision : REJECT
coverage : 67% of policy-declared obligations

obligations:
  [  ok  ] chain.verified                     (protocol)
  [  ok  ] rbi.afa_threshold                  (regulatory)
  [ ???? ] mandate.budget                     (merchant)
           Policy declared this obligation but no predicate reported a
           result for it. Absence of a result is not compliance.
```

That second chain is **cryptographically valid**. Its signature verifies. Its delegation
chain verifies. And it reports **zero constraint violations** — because the spending cap
was never presented, so there was nothing left to evaluate.

We measured this end-to-end against the AP2 reference implementation: a ₹7,500 charge
cleared against a ₹5,000 cap. Reproduction in
[`scripts/spike_chain_e2e.py`](scripts/spike_chain_e2e.py), analysis in
[ADR-0003](docs/adr/0003-absent-constraint-is-not-consent.md).

A verifier that cannot distinguish *"checked and passed"* from *"never checked"* is not a
verifier. That distinction is what PRAMANA adds.

---

## Quickstart

```bash
git clone <repo-url> && cd pramana
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pramana demo
```

On Windows, use `.venv\Scripts\` in place of `.venv/bin/`. Requires Python 3.11+.

```bash
pytest              # the invariant suite
pramana verify --withhold | jq .   # canonical JSON verdict
```

> **Supply-chain note.** Google has not published AP2 to PyPI. The name `ap2` there
> belongs to an unrelated publisher and `ap2-sdk` is an empty placeholder. This project
> installs AP2 from upstream git at a **pinned commit SHA** — never a tag, never a branch.
> If you are integrating AP2 in Python, read
> [ADR-0002](docs/adr/0002-pin-ap2-by-commit-sha.md) before you `pip install` anything.

---

## What PRAMANA adds over AP2

AP2's SDK already evaluates mandate constraints — `BudgetEvaluator`,
`AllowedPayeeEvaluator`, `PaymentReferenceEvaluator` and others. PRAMANA does **not**
reimplement them. It supplies the enforcement layer AP2 deliberately leaves to the verifier:

| | What AP2 provides | What PRAMANA adds |
| --- | --- | --- |
| **Constraint presence** | Evaluates constraints that are present | Requires policy-declared constraints to *be* present; absence is `INDETERMINATE`, which rejects |
| **Mandate context** | Defines `MandateContext`, never persists it | The state store that makes `Budget` and `AgentRecurrence` enforceable at all |
| **Jurisdiction** | Neutral by design | RBI E-mandate Framework, 2026, as executable predicates |
| **Policy source** | Constraints come *from* the mandate | Merchant policy a mandate cannot weaken |
| **Audit** | Signed receipts | Hash-chained evidence ledger anchored on the receipt reference |

---

## Design

Every decision — from the HTTP gate, the CLI, the benchmark runner, or a library caller —
is exactly one `Verdict`. Four invariants are enforced structurally, each because its
absence was a live defect caught in review:

1. **Fail closed.** `Verdict.decision` is a derived property. No caller can assert `ALLOW`;
   it can only be earned from an obligation set in which nothing blocks.
2. **Absence is not consent.** `INDETERMINATE` blocks exactly as hard as `VIOLATED`.
3. **Coverage is structural.** A verdict carries the obligation ids its policy *declared*.
   Any declared id with no reported result is materialised as `INDETERMINATE` at
   construction time — so the kernel cannot commit the sin it accuses AP2 of.
4. **An authorisation must affirm something.** At least one obligation must be `SATISFIED`.
   A verdict where everything is `NOT_APPLICABLE` checked nothing and is not permission.

Verdicts are deeply immutable and canonicalised with **RFC 8785 (JCS)**, so a third party
in a dispute can recompute the hash from the same facts in a different language.

---

## Status

Honest, and updated as it changes. This is **Day 2 of a 13-day build**.

| Component | State |
| --- | --- |
| Verdict kernel — invariants, JCS canonicalisation | **Built**, 45 tests |
| CLI | **Built** |
| AP2 chain verification spike | **Built**, reproduces the finding |
| Policy engine + predicate framework | Not started |
| RBI envelope predicates | Not started |
| Evidence ledger (C5) | Not started |
| FastAPI gate | Not started |
| Attack benchmark (RC-1..RC-5) | Not started |
| AI layer — explainer, dispute drafter, triage, buying agent | Not started |

Nothing above is claimed as working that is not. Where a number appears in this README, it
was measured; where a design is described but unbuilt, it says so.

---

## Findings

Two issues found in the AP2 reference implementation at commit `e1ea56db` while building
against it.

**Disclosure status: report drafted, not yet submitted.** It will be submitted to Google
via [g.co/vulnz](https://g.co/vulnz), whose stated response window is 5 working days.
Reproduction details are withheld from this repository until that process concludes. This
line will be updated with the actual submission date.

1. **Presence-driven constraint evaluation** — a withheld constraint is indistinguishable
   from a satisfied one. ([ADR-0003](docs/adr/0003-absent-constraint-is-not-consent.md))
2. **Undocumented unit mismatch between `Budget.max` and `AmountRange.max`** — an issuer
   following the SDK's own documentation can create a spending cap 100× larger than
   intended.

---

## Licence

Apache-2.0. See [LICENSE](LICENSE).

AP2 is a trademark of its respective owners. This project is an independent
implementation and is not affiliated with or endorsed by Google, the FIDO Alliance, NPCI,
or Razorpay.
