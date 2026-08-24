"""SPIKE: is the three-hop `issuer_jwt_hash` redaction reachable? (Answer: no.)

We reported one finding to Google and, in the same report, said plainly that we
had **not** shown a second, worse one. This script is us going back and
checking, because an open item you flagged yourself and never tested is a claim
with a hole in it.

The question
------------

AP2's ``MandateClient.present`` takes a ``hash_mode``:

    sd_hash          commits to the preceding hop's exact disclosures.
                     "Next delegate cannot further redact them."
    issuer_jwt_hash  commits only to the preceding issuer-signed JWT,
                     "allowing the next delegate to drop disclosures from it"
                     (draft-gco-oauth-delegate-sd-jwt-00 5.1.4)

If ``issuer_jwt_hash`` is adversarially reachable, it is materially worse than
the finding we shipped. Ours is holder-side: the party presenting a mandate
withholds its own constraint. This one would be **downstream**: an agent
discloses its spending cap honestly, and a delegate further along the chain
removes it before checkout, with the chain still verifying. The honest party
would be the one whose cap disappears.

The answer
----------

Not reachable through the SDK's public API, because a three-hop chain cannot be
built with it at all::

    hop1 (2 hops) built and verified   : 2 payloads
    common.parse_token(chain)          : ValueError, empty disclosure segment
    present(chain, ...)                : ValueError, empty disclosure segment

``present`` parses its ``mandate_token`` argument with ``parse_token``, which
splits on ``~`` and rejects the empty segment produced by the ``~~`` chain
separator. So ``present`` appends a hop to a *token*, never to a *chain*, and
the third hop cannot be constructed. The same applies to ``claims_to_disclose``
on a chain: the redaction helper rebuilds ``jwt_part + '~' + disclosures`` from
``split('~', maxsplit=1)[0]``, which on a chain is the first hop's JWT only, and
the result no longer parses.

Both fail **closed** -- a ValueError, not a silent acceptance -- so neither is a
security defect. What they are is a limit on where the delegation story
currently goes: two hops, not N.

What this does and does not license us to say
---------------------------------------------

We may say: we tested it, and via the documented API it does not reproduce.

We may **not** say it is impossible. Hand-assembling hops beneath ``present``
with ``kb_sd_jwt.create`` was not attempted, and an attacker writing raw SD-JWT
is not using this API surface anyway. What that changes is the threat model:
the shipped finding needs only a well-formed SDK call, while this one would
need an attacker already operating below the SDK -- which is a different and
weaker claim than the one we would have been making.

Local keys, no network, no third-party system. See SECURITY.md.
"""

from __future__ import annotations

import sys

from ap2.sdk.disclosure_metadata import DisclosureMetadata
from ap2.sdk.generated.open_payment_mandate import (
    AllowedPayees,
    Budget,
    OpenPaymentMandate,
)
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.mandate import MandateClient
from ap2.sdk.sdjwt import common
from jwcrypto.jwk import JWK

AUD = "https://merchant.example/checkout"
NONCE = "nonce-three-hop-0001"


def key() -> JWK:
    return JWK.generate(kty="EC", crv="P-256")


def main() -> int:
    client = MandateClient()
    bank, agent, delegate = key(), key(), key()
    merchant = Merchant(id="mrc_grocer", name="Grocer")

    print("=" * 72)
    print("THREE-HOP DELEGATION -- is downstream redaction reachable?")
    print("=" * 72)

    # hop 0: the bank issues to the agent, cap selectively disclosable.
    root = client.create(
        [
            OpenPaymentMandate(
                constraints=[
                    Budget(max=5_000.0, currency="INR"),
                    AllowedPayees(allowed=[merchant]),
                ],
                cnf={"jwk": agent.export_public(as_dict=True)},
            )
        ],
        bank,
        sd=DisclosureMetadata(
            children={"constraints": DisclosureMetadata(sd_array_indices=[0])}
        ),
    )

    # hop 1: the agent delegates onward, disclosing everything. Honest party.
    hop1 = client.present(
        agent,
        root,
        [
            OpenPaymentMandate(
                constraints=[], cnf={"jwk": delegate.export_public(as_dict=True)}
            )
        ],
        nonce=NONCE,
        aud=AUD,
    )
    payloads = client.verify(
        hop1, lambda _t: bank, expected_aud=AUD, expected_nonce=NONCE
    )
    print(f"  two-hop chain builds and verifies : {len(payloads)} payloads")
    print(f"  chain separators (~~)             : {hop1.count('~~')}")

    # The third hop is where it stops.
    for label, call in (
        ("parse_token(chain)", lambda: common.parse_token(hop1)),
        (
            "present(chain, ...)",
            lambda: client.present(
                delegate,
                hop1,
                [
                    OpenPaymentMandate(
                        constraints=[],
                        cnf={"jwk": key().export_public(as_dict=True)},
                    )
                ],
                nonce=NONCE,
                aud=AUD,
                hash_mode="issuer_jwt_hash",
            ),
        ),
    ):
        try:
            call()
        except ValueError as exc:
            print(f"  {label:<34}: {type(exc).__name__}: {exc}")
        else:
            print(f"  {label:<34}: SUCCEEDED -- re-read this spike's docstring")
            return 1

    print()
    print("  present() appends a hop to a TOKEN, never to a CHAIN: it parses")
    print("  its input with parse_token, which rejects the empty segment the")
    print("  ~~ separator produces. The third hop cannot be built through the")
    print("  documented API, so the downstream-redaction case does not")
    print("  reproduce here. It fails CLOSED -- a ValueError, not a silent")
    print("  acceptance -- so this is a limit, not a defect.")
    print()
    print("  NOT the same as impossible. Hand-assembling hops beneath")
    print("  present() with kb_sd_jwt.create was not attempted, and would be a")
    print("  weaker claim anyway: an attacker already writing raw SD-JWT is")
    print("  not using this API surface at all.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
