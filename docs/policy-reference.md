# Policy reference: `rbi-in@1`

Generated from [`pramana/policies/rbi-in.yaml`](../pramana/policies/rbi-in.yaml) by `scripts/gen_policy_reference.py`;
do not edit by hand. Every obligation below is evaluated on every payment.
One with no result is `INDETERMINATE`, which rejects.

> Deterministic envelope for agent-initiated payments under Indian rails. Protocol integrity, mandate conformance, and the RBI e-mandate framework.

## Protocol integrity

The AP2 delegation chain itself.

### `chain.verified`

The AP2 delegation chain verifies: every hop's signature is valid, cnf binding holds, and the presentation matches the expected audience.

- **Evaluated by:** [`ap2 adapter`](../pramana/adapters/ap2.py#L222)

### `chain.nonce_fresh`

The presentation nonce has not been seen before. Requires state AP2 deliberately does not hold; without it, replay is unenforceable.

- **window_seconds:** 900
- **Evaluated by:** [`ap2_chain adapter`](../pramana/adapters/ap2_chain.py#L264)

### `chain.disclosures_pinned`

Every constraint the policy requires is actually PRESENT in the presented mandate. This is the control for the withheld-constraint finding: AP2 evaluates what is disclosed, so an absent cap yields no violation. Absence here is INDETERMINATE, which rejects.

- **required_constraints:** payment.budget, payment.allowed_payees
- **Evaluated by:** [`ap2 adapter`](../pramana/adapters/ap2.py#L224)

## Mandate conformance

Limits the user chose and signed.

### `mandate.budget`

Cumulative spend against the user's signed cap. Requires the persisted MandateContext that AP2 defines but never stores.

- **Evaluated by:** [`ap2_chain adapter`](../pramana/adapters/ap2_chain.py#L204)

### `mandate.payee_in_scope`

The payee appears in the mandate's allowed-payee list.

- **Evaluated by:** [`ap2_chain adapter`](../pramana/adapters/ap2_chain.py#L219)

### `mandate.not_expired`

The mandate's validity window covers the execution date.

- **Evaluated by:** [`ap2_chain adapter`](../pramana/adapters/ap2_chain.py#L226)

## Merchant rules

Rules that bind even when the mandate allows more.

### `merchant.category_allowed`

The purchase category is one this merchant accepts from agents. Merchant policy binds even where the mandate is permissive.

- **blocked_categories:** gambling, crypto
- **Evaluated by:** [`ap2_chain adapter`](../pramana/adapters/ap2_chain.py#L233)

## RBI e-mandate framework

Rules no mandate can waive.

### `rbi.afa_threshold`

Recurring transactions above INR 15,000 require Additional Factor of Authentication. An agent-initiated debit above the ceiling without AFA evidence is outside the framework.

- **ceiling_paise:** 1,500,000 paise (INR 15,000)
- **defers_to:** {"obligation": "rbi.category_ceiling", "when_category_in": "enhanced_categories"}
- **deferred_categories:** insurance, mutual_fund, credit_card_bill
- **Evaluated by:** [`rbi.afa_threshold()`](../pramana/kernel/verify/rbi.py#L108)
- **Source:** RBI, Digital Payments - E-mandate Framework, 2026, AFA exemption ceiling for recurring transactions (effective 2026-04-21)

### `rbi.category_ceiling`

Specified categories carry an enhanced AFA-free ceiling of INR 1,00,000: insurance premiums, mutual fund subscriptions, and credit card bill payments. Outside those categories the standard ceiling applies.

- **enhanced_ceiling_paise:** 10,000,000 paise (INR 100,000)
- **enhanced_categories:** insurance, mutual_fund, credit_card_bill
- **Evaluated by:** [`rbi.category_ceiling()`](../pramana/kernel/verify/rbi.py#L178)
- **Source:** RBI, Digital Payments - E-mandate Framework, 2026, Enhanced ceiling for specified categories (effective 2026-04-21)

### `rbi.pre_debit_notice`

The customer must receive a pre-transaction notification at least 24 hours before the debit, with an opt-out path.

- **minimum_notice_hours:** 24
- **Evaluated by:** [`rbi.pre_debit_notice()`](../pramana/kernel/verify/rbi.py#L227)
- **Source:** RBI, Digital Payments - E-mandate Framework, 2026, Pre-transaction notification requirement (effective 2026-04-21)

### `rbi.mandate_registered_with_afa`

Registration, modification and withdrawal of an e-mandate each require AFA. A mandate presented without evidence of AFA at registration is not a valid basis for an agent-initiated debit.

- **Evaluated by:** [`rbi.mandate_registered_with_afa()`](../pramana/kernel/verify/rbi.py#L272)
- **Source:** RBI, Digital Payments - E-mandate Framework, 2026, AFA on registration, modification and withdrawal (effective 2026-04-21)

### `rbi.validity_window`

The e-mandate carries a specified validity period the customer can modify or withdraw. A debit outside that window is unauthorised.

- **Evaluated by:** [`rbi.validity_window()`](../pramana/kernel/verify/rbi.py#L295)
- **Source:** RBI, Digital Payments - E-mandate Framework, 2026, Specified validity period (effective 2026-04-21)
