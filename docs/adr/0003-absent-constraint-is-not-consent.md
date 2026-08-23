# ADR-0003: An absent constraint is not consent

* Status: Accepted
* Date: 2026-08-23
* Disclosed: reported to Google OSS VRP 2026-08-23 (issues 551304805, 551303152)
* Evidence: reproduction scripts held outside the repository pending
  coordinated disclosure. See SECURITY.md.

## Context

AP2 constraint evaluation is **presence-driven**. In `ap2/sdk/constraints.py`,
`create_payment_evaluator()` is invoked once per constraint *found in the open
mandate*. `check_preset_payment_claims()` documents the same shape explicitly:
"If a field is set in the open mandate, the closed mandate must contain an
identical value." A field that is not set is not checked.

Separately, selective disclosure is a first-class AP2 privacy feature.
`DisclosureMetadata` accepts arbitrary `sd_array_indices`, so an issuer may mark
entries of the `constraints` array selectively disclosable. A bank plausibly
would: not revealing a customer's total budget to a merchant is precisely the
privacy motivation SD-JWT exists for.

These two facts compose badly.

## Measured result

the held reproduction, run against locally generated keys:

| Presentation | chain verifies | constraints visible | violations | outcome |
| --- | --- | --- | --- | --- |
| Full disclosure | yes | `payment.budget`, `payment.allowed_payees` | 1 | blocked |
| Budget withheld | **yes** | **none** | **0** | **allowed** |

A charge of INR 7,500 cleared against a INR 5,000 cap. The chain verified. The
signature was valid. AP2's own evaluator reported no violations -- correctly,
because there was nothing left to evaluate.

*Precision:* in this configuration the withheld disclosure removed the entire
constraints array rather than the `Budget` entry alone. Withholding exactly one
constraint while retaining others is a refinement not yet confirmed. The
security claim does not depend on it.

## Decision

The kernel distinguishes "this constraint was satisfied" from "this constraint
was not evaluated", and treats the latter as blocking.

* `ObligationStatus.INDETERMINATE` is a first-class status.
* `INDETERMINATE` is `is_blocking`, exactly like `VIOLATED`.
* `Verdict.decision` is a derived property. No caller can assert `ALLOW`.
* A `Verdict` with an empty obligation set is unconstructible -- otherwise
  `all()` over an empty sequence would allow an unchecked payment.
* Policy declares which constraints must be **present**. Absence of a required
  constraint yields `INDETERMINATE`, not silence.

## Consequences

* PRAMANA rejects some presentations that AP2 alone would allow. That is the
  point, and it must be reported honestly as false-positive cost.
* Merchants operating a privacy-preserving disclosure posture must declare which
  constraints they require, rather than inferring safety from "no violations".
* This is the RC-3-adjacent contribution: the gap is not a broken signature, it
  is a verifier that cannot tell absence from compliance.
