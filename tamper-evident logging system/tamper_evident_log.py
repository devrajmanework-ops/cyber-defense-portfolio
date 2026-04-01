"""
tamper_evident_log.py
─────────────────────
Core engine for the Tamper-Evident Logging System.

Classes:
    LogEntry          – Immutable record with HMAC-SHA256 integrity tag.
    TamperEvidentLog  – In-memory chain manager; creates & links entries.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Constants ─────────────────────────────────────────────────────────────────

GENESIS_HASH: str = "0" * 64   # Sentinel previous_hash for the first entry


# ── LogEntry ──────────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    """
    A single immutable audit-log record.

    Fields
    ------
    id            : UUID4 – unique identifier
    sequence      : int   – zero-based position in the chain
    timestamp     : str   – ISO-8601 UTC creation time
    event_type    : str   – short label  (e.g. "LOGIN_ATTEMPT")
    description   : str   – human-readable event summary
    data          : dict  – arbitrary metadata payload
    previous_hash : str   – entry_hash of the preceding entry (64-hex)
    entry_hash    : str   – HMAC-SHA256 over all other fields  (64-hex)
    """

    id: str
    sequence: int
    timestamp: str
    event_type: str
    description: str
    data: Dict[str, Any]
    previous_hash: str
    entry_hash: str

    # ── Serialisation ──────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict (JSON-serialisable)."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LogEntry":
        """Reconstruct a LogEntry from a plain dict."""
        return cls(
            id=d["id"],
            sequence=d["sequence"],
            timestamp=d["timestamp"],
            event_type=d["event_type"],
            description=d["description"],
            data=d["data"],
            previous_hash=d["previous_hash"],
            entry_hash=d["entry_hash"],
        )

    # ── Payload helper (used by verifier too) ──────────────────────────────

    def payload_dict(self) -> Dict[str, Any]:
        """
        Return the dict that is hashed: everything except entry_hash itself.
        Keys are sorted for canonical / deterministic JSON serialisation.
        """
        return {
            "id": self.id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "data": self.data,
            "previous_hash": self.previous_hash,
        }


# ── Hash helpers ──────────────────────────────────────────────────────────────

def _canonical_json(obj: Any) -> bytes:
    """
    Deterministic JSON serialisation.
    - Keys sorted recursively.
    - No extra whitespace.
    Guarantees the same byte sequence across platforms / Python versions.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def compute_hmac(secret_key: str, payload: Dict[str, Any]) -> str:
    """
    Return HMAC-SHA256(secret_key, canonical_json(payload)) as a 64-char
    lowercase hex string.
    """
    key_bytes = secret_key.encode("utf-8")
    msg_bytes = _canonical_json(payload)
    digest = hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()
    return digest


# ── TamperEvidentLog ──────────────────────────────────────────────────────────

class TamperEvidentLog:
    """
    In-memory hash-chained audit log.

    Parameters
    ----------
    secret_key : str
        The HMAC secret.  Must remain confidential; the same key must be
        supplied to LogVerifier to pass integrity checks.
    """

    def __init__(self, secret_key: str) -> None:
        self._secret_key: str = secret_key
        self._entries: List[LogEntry] = []

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def entries(self) -> List[LogEntry]:
        """Read-only view of the entry list."""
        return list(self._entries)

    @property
    def size(self) -> int:
        return len(self._entries)

    # ── Chain management ───────────────────────────────────────────────────

    def _last_hash(self) -> str:
        """entry_hash of the tail entry, or GENESIS_HASH for an empty log."""
        if self._entries:
            return self._entries[-1].entry_hash
        return GENESIS_HASH

    def add_entry(
        self,
        event_type: str,
        description: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> LogEntry:
        """
        Create a new LogEntry, append it to the chain, and return it.

        Parameters
        ----------
        event_type  : str  – e.g. "LOGIN_ATTEMPT", "TRANSACTION"
        description : str  – human-readable summary
        data        : dict – optional metadata (IP, amounts, usernames …)

        Returns
        -------
        LogEntry – the newly created (and appended) entry
        """
        if data is None:
            data = {}

        entry_id = str(uuid.uuid4())
        sequence = len(self._entries)
        timestamp = datetime.now(tz=timezone.utc).isoformat()
        previous_hash = self._last_hash()

        # Build the payload dict (everything except entry_hash)
        payload: Dict[str, Any] = {
            "id": entry_id,
            "sequence": sequence,
            "timestamp": timestamp,
            "event_type": event_type,
            "description": description,
            "data": data,
            "previous_hash": previous_hash,
        }

        entry_hash = compute_hmac(self._secret_key, payload)

        entry = LogEntry(
            id=entry_id,
            sequence=sequence,
            timestamp=timestamp,
            event_type=event_type,
            description=description,
            data=data,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )

        self._entries.append(entry)
        return entry

    # ── Serialisation helpers ──────────────────────────────────────────────

    def to_list(self) -> List[Dict[str, Any]]:
        """Serialise all entries to a list of dicts."""
        return [e.to_dict() for e in self._entries]

    def load_from_list(self, records: List[Dict[str, Any]]) -> None:
        """
        Replace in-memory entries with those from *records*.
        Does NOT verify integrity – call LogVerifier.verify() separately.
        """
        self._entries = [LogEntry.from_dict(r) for r in records]

    # ── Dunder helpers ─────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"TamperEvidentLog(entries={len(self._entries)})"
