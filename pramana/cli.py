"""PRAMANA command line interface.

Deliberately small. The CLI exists so that a fresh clone can demonstrate the
kernel's safety properties in under two minutes without reading any source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence

from pramana import __version__
from pramana.kernel.verdict import (
    Obligation,
    ObligationSource,
    ObligationStatus,
    Verdict,
    build_verdict,
)

_DEMO_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
_DEMO_REF = hashlib.sha256(b"demo-closed-mandate-jwt").hexdigest()
_POLICY = "demo-policy@1"


def _ob(
    ident: str,
    status: ObligationStatus,
    source: ObligationSource,
    detail: str,
    *,
    observed: object = None,
    expected: object = None,
) -> Obligation:
    return Obligation(
        id=ident,
        status=status,
        source=source,
        detail=detail,
        observed=observed,  # type: ignore[arg-type]
        expected=expected,  # type: ignore[arg-type]
    )


def _render(title: str, verdict: Verdict) -> None:
    bar = "=" * 68
    print(f"\n{bar}\n{title}\n{bar}")
    print(f"decision : {str(verdict.decision).upper()}")
    print(f"coverage : {verdict.coverage:.0%} of policy-declared obligations")
    print(f"anchor   : {verdict.mandate_ref[:16]}...")
    print(f"hash     : {verdict.content_hash()[:16]}...")
    print("\nobligations:")
    for o in verdict.obligations:
        mark = {
            ObligationStatus.SATISFIED: "  ok  ",
            ObligationStatus.VIOLATED: " FAIL ",
            ObligationStatus.INDETERMINATE: " ???? ",
            ObligationStatus.NOT_APPLICABLE: "  --  ",
        }[o.status]
        print(f"  [{mark}] {o.id:<34} ({o.source})")
        if o.status.is_blocking:
            print(f"           {o.detail}")


def _legitimate() -> Verdict:
    """A well-formed presentation: every declared obligation evaluated and met."""
    return build_verdict(
        [
            _ob(
                "chain.verified",
                ObligationStatus.SATISFIED,
                ObligationSource.PROTOCOL,
                "AP2 delegation chain verified.",
            ),
            _ob(
                "mandate.budget",
                ObligationStatus.SATISFIED,
                ObligationSource.MANDATE,
                "Amount within the mandated cap.",
                observed={"amount": 250_000, "currency": "INR"},
                expected={"max": 500_000, "currency": "INR"},
            ),
            _ob(
                "rbi.afa_threshold",
                ObligationStatus.SATISFIED,
                ObligationSource.REGULATORY,
                "Below the AFA-free ceiling for this category.",
                observed={"amount_paise": 250_000},
                expected={"ceiling_paise": 1_500_000},
            ),
            _ob(
                "rbi.insurance_category_limit",
                ObligationStatus.NOT_APPLICABLE,
                ObligationSource.REGULATORY,
                "Transaction is not in a specified category.",
            ),
        ],
        policy_version=_POLICY,
        declared_obligations=(
            "chain.verified",
            "mandate.budget",
            "rbi.afa_threshold",
            "rbi.insurance_category_limit",
        ),
        trace_id=_DEMO_TRACE,
        mandate_ref=_DEMO_REF,
    )


def _withheld_constraint() -> Verdict:
    """The finding, expressed as a verdict.

    The chain verifies and no constraint reports a violation -- because the
    spending cap was never presented. Policy declared ``mandate.budget``, so
    its absence is materialised as INDETERMINATE rather than passing silently.
    """
    return build_verdict(
        [
            _ob(
                "chain.verified",
                ObligationStatus.SATISFIED,
                ObligationSource.PROTOCOL,
                "AP2 delegation chain verified -- signature is valid.",
            ),
            _ob(
                "rbi.afa_threshold",
                ObligationStatus.SATISFIED,
                ObligationSource.REGULATORY,
                "Below the AFA-free ceiling for this category.",
            ),
        ],
        policy_version=_POLICY,
        declared_obligations=("chain.verified", "mandate.budget", "rbi.afa_threshold"),
        trace_id=_DEMO_TRACE,
        mandate_ref=_DEMO_REF,
    )


def cmd_demo(_: argparse.Namespace) -> int:
    """Show the contrast the whole project exists for."""
    _render("1. LEGITIMATE PRESENTATION", _legitimate())
    _render("2. SPENDING CAP WITHHELD FROM THE PRESENTATION", _withheld_constraint())
    print(
        "\nThe second chain is cryptographically valid and reports no constraint\n"
        "violation, because the cap was never presented. Upstream evaluation would\n"
        "return an empty violation list. PRAMANA rejects it: policy declared the\n"
        "obligation, nothing reported on it, and absence is not compliance.\n"
    )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Emit a verdict as canonical JSON, for piping into other tools."""
    verdict = _withheld_constraint() if args.withhold else _legitimate()
    print(json.dumps(verdict.to_dict(), indent=2))
    return 0 if verdict.is_allowed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pramana",
        description="Deterministic verification gate for agent-initiated payments.",
    )
    parser.add_argument("--version", action="version", version=f"pramana {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="show a legitimate and a withheld-cap verdict")
    demo.set_defaults(func=cmd_demo)

    verify = sub.add_parser("verify", help="emit a verdict as canonical JSON")
    verify.add_argument(
        "--withhold",
        action="store_true",
        help="simulate a presentation with the spending cap withheld",
    )
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
