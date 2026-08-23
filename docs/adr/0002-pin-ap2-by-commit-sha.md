# ADR-0002: Pin the AP2 SDK by commit SHA, never by name or tag

* Status: Accepted
* Date: 2026-08-23

## Context

PRAMANA depends on Google's AP2 reference implementation. While wiring the
dependency we checked PyPI:

* `ap2` on PyPI is published by an unrelated author ("whill"). It is **not**
  Google's AP2.
* `ap2-sdk` on PyPI has an empty author, empty description, and no license.
* `ap2-protocol` does not exist.

Google has **not** published AP2 to PyPI. The upstream `pyproject.toml`
declares `name = "ap2"` but the project is distributed via git only.

`pip install ap2` or `pip install ap2-sdk` would therefore install
attacker-controllable or unrelated code into the trusted path of a payment
verification system.

## Decision

Install from the upstream git repository at a **pinned commit SHA**:

    ap2 @ git+https://github.com/google-agentic-commerce/AP2@e1ea56db72a6385bce3e5c1112b3a56ce60acb43

Not a branch. Not a tag. Tags are mutable; branches move.

Pinned commit: `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` (2026-04-29,
"fix: remove uvlock (#246)"), which is `v0.2.0` plus one commit and the current
head of `main`.

## Consequences

* Upgrades are deliberate: change the SHA, re-run the benchmark, review the diff.
* CI must not be allowed to silently resolve a different revision.
* This is itself a finding worth stating in the README: a supply-chain trap sits
  directly in front of anyone integrating AP2 in Python today.
* Upstream pins `pytest==9.0.2` as a *runtime* dependency and carries a bare
  `"py"` dependency. We tolerate this rather than fork, but it is noted.
