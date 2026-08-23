"""Evidence ledger: chain integrity and tamper detection.

The tamper tests are the point. A hash chain that does not actually detect
modification is decoration, so each test mutates a stored record in a specific
way and asserts verification fails at the right sequence number.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pramana.kernel.ledger.chain_log import (
    GENESIS_HASH,
    EvidenceLedger,
    JsonlStore,
    LedgerIntegrityError,
    LedgerRecord,
    LedgerStore,
    LedgerUnavailableError,
    MemoryStore,
)
from pramana.kernel.verdict import (
    Obligation,
    ObligationSource,
    ObligationStatus,
    Verdict,
    build_verdict,
)

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


def ref(seed: bytes = b"m") -> str:
    return hashlib.sha256(seed).hexdigest()


def verdict(
    *,
    status: ObligationStatus = ObligationStatus.SATISFIED,
    mandate_ref: str | None = None,
    policy: str = "p@1",
) -> Verdict:
    obligations = [
        Obligation(
            id="chain.verified",
            status=ObligationStatus.SATISFIED,
            source=ObligationSource.PROTOCOL,
            detail="ok",
        )
    ]
    if status is not ObligationStatus.SATISFIED:
        obligations.append(
            Obligation(
                id="mandate.budget",
                status=status,
                source=ObligationSource.MANDATE,
                detail="over cap",
            )
        )
    return build_verdict(
        obligations,
        policy_version=policy,
        declared_obligations=tuple(o.id for o in obligations),
        trace_id=TRACE,
        mandate_ref=mandate_ref or ref(),
    )


def fixed_clock(n: int = 0):
    base = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
    return lambda: base.replace(second=n % 60)


# ---------------------------------------------------------------------------
# Chain construction
# ---------------------------------------------------------------------------


class TestChain:
    def test_first_record_links_to_genesis(self) -> None:
        ledger = EvidenceLedger(MemoryStore())
        record = ledger.append(verdict())
        assert record.sequence == 0
        assert record.prev_hash == GENESIS_HASH

    def test_records_link_to_their_predecessor(self) -> None:
        ledger = EvidenceLedger(MemoryStore())
        first = ledger.append(verdict())
        second = ledger.append(verdict())
        assert second.sequence == 1
        assert second.prev_hash == first.record_hash()

    def test_verify_walks_a_clean_chain(self) -> None:
        ledger = EvidenceLedger(MemoryStore())
        for _ in range(20):
            ledger.append(verdict())
        assert ledger.verify() == 20
        assert len(ledger) == 20

    def test_empty_ledger_verifies(self) -> None:
        assert EvidenceLedger(MemoryStore()).verify() == 0

    def test_record_binds_the_verdict_hash(self) -> None:
        v = verdict()
        record = EvidenceLedger(MemoryStore()).append(v)
        assert record.verdict_hash == v.content_hash()

    def test_decision_and_anchor_are_denormalised(self) -> None:
        v = verdict(status=ObligationStatus.VIOLATED, mandate_ref=ref(b"x"))
        record = EvidenceLedger(MemoryStore()).append(v)
        assert record.decision == "reject"
        assert record.mandate_ref == ref(b"x")
        assert record.trace_id == TRACE

    def test_record_hash_is_deterministic(self) -> None:
        record = EvidenceLedger(MemoryStore(), clock=fixed_clock()).append(verdict())
        assert record.record_hash() == record.record_hash()
        assert len(record.record_hash()) == 64

    def test_verdict_hash_is_independent_of_ledger_position(self) -> None:
        """The same decision must hash identically wherever it lands."""
        ledger = EvidenceLedger(MemoryStore())
        v = verdict()
        first = ledger.append(v)
        for _ in range(5):
            ledger.append(verdict())
        later = ledger.append(v)
        assert first.verdict_hash == later.verdict_hash
        assert first.record_hash() != later.record_hash()


# ---------------------------------------------------------------------------
# Tamper detection -- the reason the chain exists
# ---------------------------------------------------------------------------


class TestTamperDetection:
    def _seed(self, store: LedgerStore, n: int = 3) -> EvidenceLedger:
        ledger = EvidenceLedger(store)
        for _ in range(n):
            ledger.append(verdict())
        assert ledger.verify() == n
        return ledger

    def test_altered_verdict_body_is_detected(self) -> None:
        store = MemoryStore()
        ledger = EvidenceLedger(store)
        ledger.append(verdict())
        ledger.append(verdict(status=ObligationStatus.VIOLATED))  # a real REJECT
        ledger.append(verdict())
        assert ledger.verify() == 3
        original = store._records[1]
        assert original.decision == "reject"
        tampered = dict(original.verdict)
        tampered["decision"] = "allow"
        store._records[1] = LedgerRecord(
            sequence=original.sequence,
            verdict_hash=original.verdict_hash,
            prev_hash=original.prev_hash,
            recorded_at=original.recorded_at,
            mandate_ref=original.mandate_ref,
            trace_id=original.trace_id,
            decision="allow",
            verdict=tampered,
        )
        with pytest.raises(LedgerIntegrityError, match="does not match its recorded"):
            ledger.verify()

    def test_deleted_record_is_detected(self) -> None:
        store = MemoryStore()
        ledger = self._seed(store, 4)
        del store._records[2]
        with pytest.raises(LedgerIntegrityError) as exc:
            ledger.verify()
        assert exc.value.sequence == 3

    def test_reordered_records_are_detected(self) -> None:
        store = MemoryStore()
        ledger = self._seed(store, 4)
        store._records[1], store._records[2] = (
            store._records[2],
            store._records[1],
        )
        with pytest.raises(LedgerIntegrityError):
            ledger.verify()

    def test_broken_link_is_detected(self) -> None:
        store = MemoryStore()
        ledger = self._seed(store)
        original = store._records[2]
        store._records[2] = LedgerRecord(
            sequence=original.sequence,
            verdict_hash=original.verdict_hash,
            prev_hash=GENESIS_HASH,  # re-point at genesis
            recorded_at=original.recorded_at,
            mandate_ref=original.mandate_ref,
            trace_id=original.trace_id,
            decision=original.decision,
            verdict=original.verdict,
        )
        with pytest.raises(LedgerIntegrityError, match="broken link"):
            ledger.verify()

    def test_truncation_at_the_tail_is_not_detectable_by_the_chain_alone(self) -> None:
        """Honest limitation, asserted so it is not mistaken for a guarantee.

        Removing records from the *end* leaves a shorter but internally valid
        chain. Detecting that needs an external anchor -- a countersigned head,
        or a published checkpoint. Not yet implemented; stated in the README.
        """
        store = MemoryStore()
        ledger = self._seed(store, 5)
        del store._records[4]
        assert ledger.verify() == 4  # still verifies -- this is the limitation


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class TestJsonlStore:
    def test_roundtrip_through_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        ledger = EvidenceLedger(JsonlStore(path))
        for _ in range(5):
            ledger.append(verdict())
        reopened = EvidenceLedger(JsonlStore(path))
        assert reopened.verify() == 5
        assert len(reopened) == 5

    def test_one_json_object_per_line(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        ledger = EvidenceLedger(JsonlStore(path))
        for _ in range(3):
            ledger.append(verdict())
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            assert json.loads(line)["record_hash"]

    def test_appends_do_not_rewrite_history(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        ledger = EvidenceLedger(JsonlStore(path))
        ledger.append(verdict())
        first_line = path.read_text(encoding="utf-8").split("\n")[0]
        ledger.append(verdict())
        assert path.read_text(encoding="utf-8").split("\n")[0] == first_line

    def test_on_disk_tampering_is_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        ledger = EvidenceLedger(JsonlStore(path))
        ledger.append(verdict())
        ledger.append(verdict(status=ObligationStatus.VIOLATED))  # a real REJECT
        ledger.append(verdict())
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        row = json.loads(lines[1])
        assert row["verdict"]["decision"] == "reject"
        row["verdict"]["decision"] = "allow"
        lines[1] = json.dumps(row, sort_keys=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with pytest.raises(LedgerIntegrityError):
            EvidenceLedger(JsonlStore(path)).verify()

    def test_corrupt_line_raises_integrity_error(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        path.write_text('{"not": "a record"}\n', encoding="utf-8")
        with pytest.raises(LedgerIntegrityError, match="unparseable"):
            EvidenceLedger(JsonlStore(path)).verify()

    def test_blank_lines_are_tolerated(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        ledger = EvidenceLedger(JsonlStore(path))
        ledger.append(verdict())
        with path.open("a", encoding="utf-8") as fh:
            fh.write("\n\n")
        assert EvidenceLedger(JsonlStore(path)).verify() == 1

    def test_missing_file_reads_as_empty(self, tmp_path: Path) -> None:
        assert EvidenceLedger(JsonlStore(tmp_path / "absent.jsonl")).verify() == 0

    def test_unwritable_path_raises_unavailable_not_silent_success(
        self, tmp_path: Path
    ) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("i am a file", encoding="utf-8")
        ledger = EvidenceLedger(JsonlStore(blocker / "nested" / "ledger.jsonl"))
        with pytest.raises(LedgerUnavailableError):
            ledger.append(verdict())


# ---------------------------------------------------------------------------
# Querying for a dispute
# ---------------------------------------------------------------------------


class TestQuery:
    def test_for_mandate_selects_only_that_anchor(self) -> None:
        ledger = EvidenceLedger(MemoryStore())
        target = ref(b"target")
        ledger.append(verdict(mandate_ref=target))
        ledger.append(verdict(mandate_ref=ref(b"other")))
        ledger.append(verdict(mandate_ref=target, status=ObligationStatus.VIOLATED))
        selected = ledger.for_mandate(target)
        assert len(selected) == 2
        assert {r.decision for r in selected} == {"allow", "reject"}

    def test_for_mandate_preserves_chain_order(self) -> None:
        ledger = EvidenceLedger(MemoryStore())
        target = ref(b"t")
        for _ in range(4):
            ledger.append(verdict(mandate_ref=target))
        assert [r.sequence for r in ledger.for_mandate(target)] == [0, 1, 2, 3]

    def test_unknown_mandate_returns_empty(self) -> None:
        ledger = EvidenceLedger(MemoryStore())
        ledger.append(verdict())
        assert ledger.for_mandate(ref(b"nope")) == []


# ---------------------------------------------------------------------------
# Record validation
# ---------------------------------------------------------------------------


class TestRecordValidation:
    @pytest.mark.parametrize("bad", ["", "xyz", "A" * 64, "a" * 63])
    def test_invalid_digests_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError, match="hex digest"):
            LedgerRecord(
                sequence=0,
                verdict_hash=bad,
                prev_hash=GENESIS_HASH,
                recorded_at=datetime.now(UTC),
                mandate_ref=ref(),
                trace_id=TRACE,
                decision="allow",
                verdict={},
            )

    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            LedgerRecord(
                sequence=0,
                verdict_hash=ref(),
                prev_hash=GENESIS_HASH,
                recorded_at=datetime(2026, 8, 23),  # noqa: DTZ001
                mandate_ref=ref(),
                trace_id=TRACE,
                decision="allow",
                verdict={},
            )

    def test_negative_sequence_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            LedgerRecord(
                sequence=-1,
                verdict_hash=ref(),
                prev_hash=GENESIS_HASH,
                recorded_at=datetime.now(UTC),
                mandate_ref=ref(),
                trace_id=TRACE,
                decision="allow",
                verdict={},
            )

    def test_record_is_frozen(self) -> None:
        record = EvidenceLedger(MemoryStore()).append(verdict())
        with pytest.raises((AttributeError, TypeError)):
            record.decision = "allow"  # type: ignore[misc]
