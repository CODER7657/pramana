"""Two implementations, one hash, or the claim is false.

The README says a third party in a dispute can recompute a verdict's hash from
the same facts **in a different language**. That was an assertion about RFC 8785
rather than a demonstrated property, and an assertion is not evidence.

`tools/verify.mjs` is one Node file with no dependencies and no import from
this project. These tests run it against a ledger this project wrote and require
that it agree -- on the digests, on the chain, and on what counts as tampering.
If the two ever disagree, one of them is wrong and the claim was never true.

Skipped when Node is absent, which keeps the suite runnable on a machine with
no JavaScript toolchain. GitHub's ubuntu runners ship Node, so CI does run it.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pramana.kernel.gate import Kernel, PaymentRequest
from pramana.kernel.ledger.chain_log import EvidenceLedger, JsonlStore
from pramana.kernel.verdict import Obligation, ObligationSource, ObligationStatus
from pramana.kernel.verify.policy import builtin_policy
from pramana.kernel.verify.rbi import PaymentFacts

VERIFIER = Path(__file__).resolve().parents[2] / "tools" / "verify.mjs"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def _facts(amount_paise: int) -> PaymentFacts:
    return PaymentFacts(
        amount_paise=amount_paise,
        currency="INR",
        category="groceries",
        afa_performed=False,
        afa_at_registration=True,
        pre_debit_notice_at=NOW.replace(hour=6),
        execution_at=NOW,
        mandate_valid_from=NOW.replace(day=1),
        mandate_valid_until=NOW.replace(day=28),
    )


def _supplied(policy: object) -> dict[str, tuple[Obligation, ...]]:
    groups: dict[str, tuple[Obligation, ...]] = {}
    for source, key in (
        (ObligationSource.PROTOCOL, "protocol_results"),
        (ObligationSource.MANDATE, "mandate_results"),
        (ObligationSource.MERCHANT, "merchant_results"),
    ):
        groups[key] = tuple(
            Obligation(
                id=spec.id,
                status=ObligationStatus.SATISFIED,
                source=source,
                detail="supplied by the merchant backend",
                expected="ok",
            )
            for spec in policy.by_source(source)  # type: ignore[attr-defined]
        )
    return groups


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    """A real JSONL ledger with three records, written by the kernel."""
    policy = builtin_policy()
    path = tmp_path / "ledger.jsonl"
    kernel = Kernel(policy, ledger=EvidenceLedger(JsonlStore(path)))
    for i, amount in enumerate((250_000, 750_000, 5_000_000)):
        kernel.evaluate(
            PaymentRequest(
                mandate_ref=hashlib.sha256(f"mandate-{i}".encode()).hexdigest(),
                facts=_facts(amount),
                **_supplied(policy),  # type: ignore[arg-type]
            )
        )
    return path


def run_verifier(path: Path) -> subprocess.CompletedProcess[str]:
    assert NODE is not None
    # S603: the executable is shutil.which("node") and both arguments are
    # paths this test constructed. No part of it comes from input.
    return subprocess.run(  # noqa: S603
        [NODE, str(VERIFIER), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


def rewrite(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )


def read(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class TestItAgrees:
    def test_an_untouched_ledger_verifies(self, ledger_path: Path) -> None:
        result = run_verifier(ledger_path)
        assert result.returncode == 0, result.stderr
        assert "3 record(s) verified" in result.stdout

    def test_node_recomputes_the_same_digests_python_wrote(
        self, ledger_path: Path
    ) -> None:
        """The actual claim: same facts, different language, same hash."""
        result = run_verifier(ledger_path)
        for record in read(ledger_path):
            assert str(record["verdict_hash"])[:16] in result.stdout

    def test_node_agrees_with_the_python_verifier_on_the_head(
        self, ledger_path: Path
    ) -> None:
        expected = read(ledger_path)[-1]["record_hash"]
        assert f"head {expected}" in run_verifier(ledger_path).stdout


class TestItAgreesOnTampering:
    def test_a_flipped_decision_is_caught(self, ledger_path: Path) -> None:
        records = read(ledger_path)
        records[1]["verdict"]["decision"] = "allow"  # type: ignore[index]
        rewrite(ledger_path, records)
        result = run_verifier(ledger_path)
        assert result.returncode == 1
        assert "BROKEN at record 1" in result.stderr

    def test_a_missing_verdict_body_is_a_failure_not_a_pass(
        self, ledger_path: Path
    ) -> None:
        """The defect the Python verifier shipped with, not repeated here."""
        records = read(ledger_path)
        records[1].pop("verdict")
        rewrite(ledger_path, records)
        result = run_verifier(ledger_path)
        assert result.returncode == 1
        assert "cannot be recomputed" in result.stderr

    def test_a_broken_link_is_caught(self, ledger_path: Path) -> None:
        records = read(ledger_path)
        records[2]["prev_hash"] = "0" * 64
        rewrite(ledger_path, records)
        assert "broken link" in run_verifier(ledger_path).stderr

    def test_a_reordered_chain_is_caught(self, ledger_path: Path) -> None:
        records = read(ledger_path)
        rewrite(ledger_path, [records[1], records[0], records[2]])
        assert run_verifier(ledger_path).returncode == 1

    def test_tail_truncation_is_undetected_by_both(self, ledger_path: Path) -> None:
        """Named for the limitation, so it cannot be quietly forgotten.

        A shorter chain is still internally valid. Both implementations say OK,
        because neither can do otherwise without a signature over the head.
        That is the one word the Vulcan comparison table still overstates, and
        it is recorded in POSTMORTEM.md as the next thing to build.
        """
        rewrite(ledger_path, read(ledger_path)[:-1])
        result = run_verifier(ledger_path)
        assert result.returncode == 0
        assert "2 record(s) verified" in result.stdout
