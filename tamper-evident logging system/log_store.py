"""
log_store.py
────────────
Persistence layer for TamperEvidentLog.

Writes the chain to a JSON file using atomic rename so a crash mid-write
cannot corrupt the log.  On POSIX systems os.replace() is fully atomic;
on Windows it is best-effort (atomic within the same filesystem volume).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from tamper_evident_log import TamperEvidentLog


class LogStore:
    """
    Thin wrapper around TamperEvidentLog that adds load / save.

    Parameters
    ----------
    filepath   : str | Path  – path to the JSON log file
    secret_key : str         – HMAC secret forwarded to TamperEvidentLog
    """

    def __init__(self, filepath: str | Path, secret_key: str) -> None:
        self._filepath = Path(filepath)
        self._secret_key = secret_key
        self.log = TamperEvidentLog(secret_key)

    # ── Load ───────────────────────────────────────────────────────────────

    def load(self) -> None:
        """
        Load entries from *filepath* into the in-memory log.

        If the file does not exist the log is left empty (fresh start).
        Raises json.JSONDecodeError if the file is malformed.
        """
        if not self._filepath.exists():
            return  # fresh log

        with self._filepath.open("r", encoding="utf-8") as fh:
            records: List[Dict[str, Any]] = json.load(fh)

        self.log.load_from_list(records)

    # ── Save ───────────────────────────────────────────────────────────────

    def save(self) -> None:
        """
        Atomically write all entries to *filepath*.

        Strategy
        --------
        1. Serialise to JSON in memory.
        2. Write to a sibling temp file in the same directory.
        3. os.replace() the temp file over the target path.

        This guarantees the on-disk log is never in a half-written state.
        """
        data = self.log.to_list()
        json_bytes = json.dumps(data, indent=2, ensure_ascii=True).encode("utf-8")

        dir_path = self._filepath.parent
        dir_path.mkdir(parents=True, exist_ok=True)

        # Write to a temp file in the same directory (same filesystem)
        fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
        try:
            os.write(fd, json_bytes)
            os.fsync(fd)           # flush kernel buffers → disk
        finally:
            os.close(fd)

        os.replace(tmp_path, self._filepath)  # atomic rename

    # ── Convenience ────────────────────────────────────────────────────────

    def add_and_save(
        self,
        event_type: str,
        description: str,
        data: Optional[Dict[str, Any]] = None,
    ):
        """Add a new entry *and* immediately persist the chain."""
        entry = self.log.add_entry(event_type, description, data)
        self.save()
        return entry

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def filepath(self) -> Path:
        return self._filepath

    def __repr__(self) -> str:
        return (
            f"LogStore(file={self._filepath!s}, "
            f"entries={self.log.size})"
        )
