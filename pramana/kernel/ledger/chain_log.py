"""Hash-chained, append-only evidence ledger.

Every verdict the kernel produces is appended here as a linked record. The
chain is the non-repudiation artifact: it answers, after the fact, who
authorised what, within which limits, and who exceeded them.

Two design decisions worth stating explicitly.

**The chain lives in the ledger row, not on the Verdict.** A verdict's
``content_hash()`` must be a function of the decision alone, so the same
decision hashes identically whether it is record 1 or record 100,000. Putting
``prev_hash`` on the verdict would make an authorisation's identity depend on
when it happened to be logged. :class:`LedgerRecord` wraps a verdict instead.

**Storage is append-only JSONL, one record per line.** A third party in a
dispute must be able to verify the chain without running our code. JSONL plus
RFC 8785 canonicalisation means the verification algorithm is a paragraph of
prose, not a dependency.

A ledger write failure is *not* recoverable on the money path. An authorisation
we cannot evidence is an authorisation we do not grant -- see
:class:`LedgerUnavailableError` and the threat model in SECURITY.md.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable

import rfc8785

from pramana.kernel.verdict import Verdict

logger = logging.getLogger(__name__)

GENESIS_HASH: Final = "0" * 64
"""``prev_hash`` of the first record. Not a real digest -- a chain terminator."""

_HEX64 = 64


class LedgerError(Exception):
    """Base class for ledger failures."""


class LedgerIntegrityError(LedgerError):
    """The chain does not verify. Something was altered, removed, or reordered."""

    def __init__(self, sequence: int, reason: str) -> None:
        self.sequence = sequence
        self.reason = reason
        super().__init__(f"record {sequence}: {reason}")


class LedgerUnavailableError(LedgerError):
    """The ledger could not be written.

    Callers on the money path must translate this into an ``INDETERMINATE``
    obligation, which rejects. An authorisation that cannot be evidenced is not
    an authorisation.
    """


@dataclass(frozen=True, slots=True)
class LedgerRecord:
    """One link in the chain: a verdict, its position, and its binding."""

    sequence: int
    verdict_hash: str
    """``Verdict.content_hash()`` -- binds this record to a specific decision."""

    prev_hash: str
    """The previous record's :meth:`record_hash`, or :data:`GENESIS_HASH`."""

    recorded_at: datetime
    mandate_ref: str
    """AP2 canonical receipt reference. The protocol-level anchor, denormalised
    onto the record so a dispute can be located without replaying the chain."""

    trace_id: str
    decision: str
    verdict: dict[str, Any]
    """The full verdict payload, so the record is self-contained evidence."""

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("sequence must be non-negative")
        for name, value in (
            ("verdict_hash", self.verdict_hash),
            ("prev_hash", self.prev_hash),
        ):
            if len(value) != _HEX64 or not all(c in "0123456789abcdef" for c in value):
                raise ValueError(f"{name} must be a 64-char lowercase hex digest")
        if self.recorded_at.tzinfo is None:
            raise ValueError("recorded_at must be timezone-aware")

    def linking_payload(self) -> dict[str, Any]:
        """Exactly the fields the record hash commits to.

        The verdict body is committed *by reference* through ``verdict_hash``,
        which is itself a JCS digest of the verdict. Hashing the body again
        here would be redundant and would couple the chain to verdict
        serialisation details.
        """
        return {
            "sequence": self.sequence,
            "verdict_hash": self.verdict_hash,
            "prev_hash": self.prev_hash,
            "recorded_at": self.recorded_at.astimezone(UTC).isoformat(),
            "mandate_ref": self.mandate_ref,
            "trace_id": self.trace_id,
            "decision": self.decision,
        }

    def record_hash(self) -> str:
        return hashlib.sha256(rfc8785.dumps(self.linking_payload())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        payload = self.linking_payload()
        payload["record_hash"] = self.record_hash()
        payload["verdict"] = self.verdict
        return payload

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> LedgerRecord:
        return cls(
            sequence=int(raw["sequence"]),
            verdict_hash=raw["verdict_hash"],
            prev_hash=raw["prev_hash"],
            recorded_at=datetime.fromisoformat(raw["recorded_at"]),
            mandate_ref=raw["mandate_ref"],
            trace_id=raw["trace_id"],
            decision=raw["decision"],
            verdict=raw.get("verdict", {}),
        )


@runtime_checkable
class LedgerStore(Protocol):
    """Storage backend. Swappable without touching chain logic."""

    def append(self, record: LedgerRecord) -> None: ...
    def read_all(self) -> Iterator[LedgerRecord]: ...
    def last(self) -> LedgerRecord | None: ...
    def count(self) -> int: ...


class JsonlStore:
    """Append-only JSONL. One record per line, newest last."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def append(self, record: LedgerRecord) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(record.to_dict(), sort_keys=True, ensure_ascii=False)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
        except OSError as exc:
            raise LedgerUnavailableError(
                f"cannot append to {self.path}: {exc}"
            ) from exc

    def read_all(self) -> Iterator[LedgerRecord]:
        if not self.path.is_file():
            return
        try:
            with self.path.open(encoding="utf-8") as fh:
                for lineno, line in enumerate(fh):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        yield LedgerRecord.from_dict(json.loads(stripped))
                    except (ValueError, KeyError) as exc:
                        raise LedgerIntegrityError(
                            lineno, f"unparseable record: {exc}"
                        ) from exc
        except OSError as exc:
            raise LedgerUnavailableError(f"cannot read {self.path}: {exc}") from exc

    def last(self) -> LedgerRecord | None:
        record = None
        for record in self.read_all():  # noqa: B007 -- we want the final value
            pass
        return record

    def count(self) -> int:
        return sum(1 for _ in self.read_all())


class MemoryStore:
    """In-memory backend, for tests and ephemeral runs."""

    def __init__(self) -> None:
        self._records: list[LedgerRecord] = []

    def append(self, record: LedgerRecord) -> None:
        self._records.append(record)

    def read_all(self) -> Iterator[LedgerRecord]:
        yield from self._records

    def last(self) -> LedgerRecord | None:
        return self._records[-1] if self._records else None

    def count(self) -> int:
        return len(self._records)


class EvidenceLedger:
    """Appends verdicts as a verifiable chain and detects tampering."""

    def __init__(
        self,
        store: LedgerStore,
        *,
        clock: Any = None,
    ) -> None:
        self.store = store
        self._clock = clock or (lambda: datetime.now(UTC))

    def append(self, verdict: Verdict) -> LedgerRecord:
        """Append a verdict. Raises :class:`LedgerUnavailableError` on failure."""
        previous = self.store.last()
        record = LedgerRecord(
            sequence=0 if previous is None else previous.sequence + 1,
            verdict_hash=verdict.content_hash(),
            prev_hash=GENESIS_HASH if previous is None else previous.record_hash(),
            recorded_at=self._clock(),
            mandate_ref=verdict.mandate_ref,
            trace_id=verdict.trace_id,
            decision=str(verdict.decision),
            verdict=dict(verdict.to_dict()),
        )
        self.store.append(record)
        return record

    def verify(self) -> int:
        """Walk the whole chain. Returns the number of records verified.

        Raises :class:`LedgerIntegrityError` at the first inconsistency, naming
        the sequence number, so a dispute can point at a specific record.
        """
        expected_prev = GENESIS_HASH
        count = 0

        for expected_seq, record in enumerate(self.store.read_all()):
            if record.sequence != expected_seq:
                raise LedgerIntegrityError(
                    record.sequence,
                    f"out-of-order or missing record: expected sequence "
                    f"{expected_seq}",
                )
            if record.prev_hash != expected_prev:
                raise LedgerIntegrityError(
                    record.sequence,
                    "broken link: prev_hash does not match the preceding "
                    "record's hash",
                )
            recomputed = _verdict_hash_of(record.verdict)
            if recomputed is not None and recomputed != record.verdict_hash:
                raise LedgerIntegrityError(
                    record.sequence,
                    "verdict body does not match its recorded hash",
                )
            expected_prev = record.record_hash()
            count += 1

        return count

    def records(self) -> list[LedgerRecord]:
        return list(self.store.read_all())

    def for_mandate(self, mandate_ref: str) -> list[LedgerRecord]:
        """Every record anchored to one AP2 mandate. The dispute's raw material."""
        return [r for r in self.store.read_all() if r.mandate_ref == mandate_ref]

    def __len__(self) -> int:
        return self.store.count()


def _verdict_hash_of(body: dict[str, Any]) -> str | None:
    """Recompute a stored verdict body's digest, or None if it is absent.

    Mirrors ``Verdict.content_hash()``: JCS over the same dict. A record whose
    body was edited will not reproduce its ``verdict_hash``.
    """
    if not body:
        return None
    try:
        return hashlib.sha256(rfc8785.dumps(body)).hexdigest()
    except (TypeError, ValueError):
        return None
