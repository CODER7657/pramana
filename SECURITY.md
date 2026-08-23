# Security Policy

## Posture: defence only

PRAMANA is a verification and policy layer. It exists to *reject* payments that fall
outside a signed authorisation. It contains no offensive capability, and that is a
deliberate constraint on what this repository will ever accept.

Concretely:

* **The attack cases are a fixed, closed regression suite.** They live in `bench/cases.py`,
  are enumerated in advance, and are never generated at runtime.
* **They run only against this project's own local sandbox** — locally generated keys,
  locally constructed mandates. No test in this repository performs network I/O against a
  third-party system, and none ever will.
* **Nothing here generates novel attacks.** There is no fuzzer, no mutation engine, no
  payload synthesiser. A case is added by a human writing it down, with a rationale.
* **No credentials, keys, or live endpoints** are committed. Test keys are generated at
  runtime and are throwaway.

Contributions that add offensive capability will be declined regardless of quality.

## Reporting a vulnerability in PRAMANA

Email **killerff479@gmail.com** with `[PRAMANA SECURITY]` in the subject.

Please include a description, affected version or commit, and reproduction steps. We will
acknowledge within 5 working days. Please do not open a public issue for a security report.

## Findings in upstream dependencies

While building against the AP2 reference implementation we identified two issues in its
constraint layer at commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`.

We follow coordinated disclosure. AP2's own `SECURITY.md` directs reports to
[g.co/vulnz](https://g.co/vulnz), with a stated 5-working-day response window and
coordination through GitHub Security Advisory.

| Stage | Status |
| --- | --- |
| Findings identified | 2026-08-23 |
| Reports drafted | 2026-08-23 |
| Submitted to Google OSS VRP | 2026-08-23 |
| Tracking | [551304805](https://issuetracker.google.com/issues/551304805), [551303152](https://issuetracker.google.com/issues/551303152) |
| **Vendor response** | **2026-08-23 - closed "Won't Fix (Intended Behavior)"** |
| Embargo | Lifted. The vendor invited a public issue. |

### What the vendor said

Google acknowledged the mechanism directly:

> "You've clearly identified a mechanism where a selectively withheld constraint
> could lead to a permissions bypass, potentially allowing reported over-cap
> payments."

They declined a monetary reward because AP2 falls outside the tiered scope of
the OSS VRP -- a **reward-eligibility** determination, not a judgement that the
finding is wrong -- closed the reports as *Won't Fix (Intended Behavior)*, and
encouraged a public issue or pull request on the repository instead.

We take that at face value and report it without spin:

* The mechanism is **confirmed**, in writing, by the vendor.
* It is **not going to be fixed** upstream, because it is considered intended
  behaviour of the protocol.
* Public disclosure is **invited**, so the embargo no longer applies.

The third point is why reproduction scripts are now in this repository. The
second is why this project exists: a verifier that reads an empty violation
list as compliance will keep authorising uncapped payments, and no upstream fix
is coming to stop it.

## Scope of our claims

We are deliberate about the difference between what was measured and what was inferred:

* Our findings concern **verifier semantics and documentation**, not cryptography. We have
  not identified any signature forgery or delegation-chain integrity break, and we do not
  claim one.
* Where a reproduction exercises a documented API in a sanctioned way, we say so rather
  than describing it as an attack.
* Any claim in this repository that is a projection rather than a measurement is labelled
  as a projection.

## Threat model

PRAMANA assumes:

* The buying agent may be **fully compromised**. It is the untrusted party.
* The AP2 chain may be **validly signed and still not authorise the transaction** — that
  is the primary case the system is built for.
* Language models in the system may be **prompt-injected**. They sit strictly downstream
  of `Verdict` and cannot construct one, so a compromised model can degrade an explanation
  but cannot change a decision. See
  [ADR-0001](docs/adr/0001-deterministic-money-path.md).
* State stores may be **unavailable**. Unavailability yields `INDETERMINATE`, which
  rejects. Availability is never traded for authorisation.
