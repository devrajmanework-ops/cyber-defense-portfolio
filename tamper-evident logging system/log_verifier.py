"""
log_verifier.py
───────────────
Integrity verifier for TamperEvidentLog.

Performs three independent checks on every entry:

  1. Sequence continuity  – detects insertions, deletions, reordering.
  2. Hash-chain linkage   – detects deletions and reordering.
  3. HMAC recomputation   – detects field-level modifications.

A single pass is O(n) in the number of entries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional

from tamper_evident_log import (
    GENESIS_HASH,
    LogEntry,
    TamperEvidentLog,
    compute_hmac,
)


# ── Violation types ───────────────────────────────────────────────────────────

class ViolationType(Enum):
    SEQUENCE_MISMATCH  = auto()   # sequence number is wrong
    HASH_CHAIN_BROKEN  = auto()   # previous_hash does not match predecessor
    HMAC_MISMATCH      = auto()   # HMAC recomputation failed (field modified)


@dataclass
class Violation:
    """Describes a single detected integrity violation."""
    sequence_index: int           # position (0-based) in the chain
    violation_type: ViolationType
    reason: str                   # human-readable explanation

    def __str__(self) -> str:
        tag = self.violation_type.name
        return f"[seq {self.sequence_index}] {tag}: {self.reason}"


# ── Verification result ───────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    """Aggregated result from a full-chain verification pass."""
    passed: bool
    total_entries: int
    violations: List[Violation] = field(default_factory=list)

    @property
    def first_tamper_index(self) -> Optional[int]:
        """Sequence index of the earliest violation, or None if clean."""
        if self.violations:
            return min(v.sequence_index for v in self.violations)
        return None

    def summary(self) -> str:
        if self.passed:
            return (
                f"✅  Chain INTACT — {self.total_entries} "
                f"entr{'y' if self.total_entries == 1 else 'ies'} verified."
            )
        v_count = len(self.violations)
        return (
            f"❌  Chain COMPROMISED — {v_count} "
            f"violation{'s' if v_count != 1 else ''} detected "
            f"(first at sequence index {self.first_tamper_index})."
        )

    def __str__(self) -> str:
        lines = [self.summary()]
        for v in self.violations:
            lines.append(f"    {v}")
        return "\n".join(lines)


# ── Verifier ──────────────────────────────────────────────────────────────────

class LogVerifier:
    """
    Stateless verifier.  Instantiate once, call verify() as many times
    as needed (e.g. after every append, or on a schedule).

    Parameters
    ----------
    secret_key : str
        Must be the same key that was used to *create* the entries.
        A different key will cause every HMAC check to fail.
    """

    def __init__(self, secret_key: str) -> None:
        self._secret_key = secret_key

    # ── Public API ─────────────────────────────────────────────────────────

    def verify(self, log: TamperEvidentLog) -> VerificationResult:
        """
        Walk the entire chain and return a VerificationResult.

        Algorithm (O(n))
        ----------------
        expected_previous = GENESIS_HASH

        for i, entry in enumerate(entries):
            check  entry.sequence == i
            check  entry.previous_hash == expected_previous
            check  HMAC(payload) == entry.entry_hash
            expected_previous = entry.entry_hash
        """
        entries = log.entries
        violations: List[Violation] = []
        expected_previous_hash = GENESIS_HASH

        for i, entry in enumerate(entries):

            # ── 1. Sequence continuity ──────────────────────────────────
            if entry.sequence != i:
                violations.append(Violation(
                    sequence_index=i,
                    violation_type=ViolationType.SEQUENCE_MISMATCH,
                    reason=(
                        f"expected sequence {i}, "
                        f"found {entry.sequence}"
                    ),
                ))

            # ── 2. Hash-chain linkage ───────────────────────────────────
            if entry.previous_hash != expected_previous_hash:
                violations.append(Violation(
                    sequence_index=i,
                    violation_type=ViolationType.HASH_CHAIN_BROKEN,
                    reason=(
                        f"previous_hash mismatch — "
                        f"expected {expected_previous_hash[:16]}…, "
                        f"found    {entry.previous_hash[:16]}…"
                    ),
                ))

            # ── 3. HMAC field integrity ─────────────────────────────────
            recomputed = compute_hmac(self._secret_key, entry.payload_dict())
            if recomputed != entry.entry_hash:
                violations.append(Violation(
                    sequence_index=i,
                    violation_type=ViolationType.HMAC_MISMATCH,
                    reason=(
                        f"recomputed HMAC {recomputed[:16]}… "
                        f"≠ stored {entry.entry_hash[:16]}…"
                    ),
                ))

            # Advance the expected pointer regardless of violations so we
            # keep checking downstream entries independently.
            expected_previous_hash = entry.entry_hash

        passed = len(violations) == 0
        return VerificationResult(
            passed=passed,
            total_entries=len(entries),
            violations=violations,
        )

    # ── Convenience ────────────────────────────────────────────────────────

    def verify_entry(
        self,
        entry: LogEntry,
        expected_sequence: int,
        expected_previous_hash: str,
    ) -> List[Violation]:
        """
        Verify a single entry in isolation.
        Useful when streaming entries one-by-one from a large log.
        """
        violations: List[Violation] = []

        if entry.sequence != expected_sequence:
            violations.append(Violation(
                sequence_index=expected_sequence,
                violation_type=ViolationType.SEQUENCE_MISMATCH,
                reason=(
                    f"expected sequence {expected_sequence}, "
                    f"found {entry.sequence}"
                ),
            ))

        if entry.previous_hash != expected_previous_hash:
            violations.append(Violation(
                sequence_index=entry.sequence,
                violation_type=ViolationType.HASH_CHAIN_BROKEN,
                reason=(
                    f"previous_hash mismatch at sequence {entry.sequence}"
                ),
            ))

        recomputed = compute_hmac(self._secret_key, entry.payload_dict())
        if recomputed != entry.entry_hash:
            violations.append(Violation(
                sequence_index=entry.sequence,
                violation_type=ViolationType.HMAC_MISMATCH,
                reason=(
                    f"HMAC mismatch at sequence {entry.sequence}"
                ),
            ))

        return violations
