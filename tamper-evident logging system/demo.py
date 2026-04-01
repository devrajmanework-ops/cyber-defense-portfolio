"""
demo.py
───────
End-to-end demonstration of the Tamper-Evident Logging System.

Phases
──────
  1. Build a clean 7-entry log chain
  2. Verify the clean chain (should PASS)
  3a. Attack: modify a field in entry [seq 4]
  3b. Attack: delete entry [seq 2]
  3c. Attack: swap entries [seq 0] and [seq 1]
  4.  Reset and verify persistence round-trip

Run:  python demo.py
"""

import copy
import json
import os
import tempfile

from tamper_evident_log import TamperEvidentLog
from log_store import LogStore
from log_verifier import LogVerifier

SECRET = "demo-secret-key-do-not-share"

SEP_WIDE  = "=" * 66
SEP_THIN  = "-" * 66


# ── Pretty helpers ────────────────────────────────────────────────────────────

def banner(title: str) -> None:
    print(f"\n{SEP_WIDE}")
    print(f"  {title}")
    print(SEP_WIDE)


def print_entry(entry, label: str = "") -> None:
    tag = f"  {label}" if label else ""
    print(
        f"  [seq {entry.sequence}]{tag}"
        f"  {entry.event_type:<22}"
        f"  →  {entry.entry_hash[:16]}…"
    )


def print_result(result) -> None:
    print(f"\n  {result.summary()}")
    if not result.passed:
        print(f"  First tamper detected at sequence index: "
              f"{result.first_tamper_index}")
        print()
        for v in result.violations:
            print(f"    {v}")


# ── Phase 1: Build clean log ──────────────────────────────────────────────────

def phase1_build() -> TamperEvidentLog:
    banner("PHASE 1: Building a clean log chain")

    log = TamperEvidentLog(SECRET)
    events = [
        ("SYSTEM_START",    "Audit service initialised",       {"version": "1.0"}),
        ("LOGIN_ATTEMPT",   "alice logged in successfully",     {"user": "alice", "ip": "10.0.0.1"}),
        ("DATA_ACCESS",     "alice read report Q1-2025",        {"resource": "report_q1"}),
        ("PRIVILEGE_CHANGE","alice granted admin role",         {"granted_by": "root"}),
        ("TRANSACTION",     "Wire transfer $10,000 to Bob",     {"amount": 10000, "currency": "USD"}),
        ("DATA_MODIFY",     "alice updated customer record 42", {"record_id": 42}),
        ("LOGOUT",          "alice session ended",              {"duration_s": 482}),
    ]

    for event_type, desc, data in events:
        entry = log.add_entry(event_type, desc, data)
        print_entry(entry)

    print(f"\n  Total entries written: {log.size}")
    return log


# ── Phase 2: Verify clean chain ───────────────────────────────────────────────

def phase2_verify_clean(log: TamperEvidentLog) -> None:
    banner("PHASE 2: Verifying clean chain integrity")
    verifier = LogVerifier(SECRET)
    result = verifier.verify(log)
    print_result(result)
    assert result.passed, "Clean chain should PASS verification!"


# ── Attack helpers ────────────────────────────────────────────────────────────

def _clone_entries(log: TamperEvidentLog) -> list:
    """Deep-copy the raw entry list."""
    return copy.deepcopy(log.entries)


def _make_tampered_log(entries: list) -> TamperEvidentLog:
    """Build a TamperEvidentLog from a (possibly modified) entry list."""
    tampered = TamperEvidentLog(SECRET)
    tampered.load_from_list([e.to_dict() for e in entries])
    return tampered


# ── Phase 3a: Modify a field ──────────────────────────────────────────────────

def phase3a_modify(log: TamperEvidentLog) -> None:
    banner("PHASE 3a: Attack — Modify entry [seq 4] (transaction amount)")

    entries = _clone_entries(log)
    original_amount = entries[4].data.get("amount")
    entries[4].data["amount"] = 1          # attacker changes $10,000 → $1
    print(f"  ✏️  entries[4].data['amount']  {original_amount} → 1")

    tampered = _make_tampered_log(entries)
    result = LogVerifier(SECRET).verify(tampered)
    print_result(result)
    assert not result.passed, "Modification should be detected!"


# ── Phase 3b: Delete an entry ─────────────────────────────────────────────────

def phase3b_delete(log: TamperEvidentLog) -> None:
    banner("PHASE 3b: Attack — Delete entry [seq 2]")

    entries = _clone_entries(log)
    deleted = entries.pop(2)
    print(f"  🗑️  Removed entry [seq 2]: {deleted.event_type}")

    tampered = _make_tampered_log(entries)
    result = LogVerifier(SECRET).verify(tampered)
    print_result(result)
    assert not result.passed, "Deletion should be detected!"


# ── Phase 3c: Swap / reorder entries ─────────────────────────────────────────

def phase3c_swap(log: TamperEvidentLog) -> None:
    banner("PHASE 3c: Attack — Swap entries [seq 0] and [seq 1]")

    entries = _clone_entries(log)
    entries[0], entries[1] = entries[1], entries[0]
    print(f"  🔀  entries[0] ↔ entries[1]")

    tampered = _make_tampered_log(entries)
    result = LogVerifier(SECRET).verify(tampered)
    print_result(result)
    assert not result.passed, "Reordering should be detected!"


# ── Phase 4: Persistence round-trip ──────────────────────────────────────────

def phase4_persistence() -> None:
    banner("PHASE 4: Persistence round-trip (save → load → verify)")

    # Use a temp path that does NOT exist yet so LogStore starts fresh
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, "test_audit.json")

    try:
        # Write
        store = LogStore(tmp_path, SECRET)
        store.load()
        store.add_and_save("SESSION_START", "Bob opened a session",  {"user": "bob"})
        store.add_and_save("TRANSACTION",   "Bob paid invoice #99",  {"amount": 250})
        store.add_and_save("SESSION_END",   "Bob session closed",    {"user": "bob"})
        print(f"  Saved {store.log.size} entries → {tmp_path}")

        # Reload from disk
        store2 = LogStore(tmp_path, SECRET)
        store2.load()
        print(f"  Loaded {store2.log.size} entries from disk")

        result = LogVerifier(SECRET).verify(store2.log)
        print_result(result)
        assert result.passed, "Persisted chain should verify cleanly!"

        # Verify file is valid JSON
        with open(tmp_path) as fh:
            records = json.load(fh)
        print(f"  JSON file contains {len(records)} records ✅")

    finally:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ── Phase 5: Wrong-key rejection ─────────────────────────────────────────────

def phase5_wrong_key(log: TamperEvidentLog) -> None:
    banner("PHASE 5: Wrong HMAC key → all entries appear invalid")

    verifier = LogVerifier("COMPLETELY-WRONG-KEY")
    result = verifier.verify(log)
    print_result(result)
    assert not result.passed, "Wrong key should fail every HMAC check!"
    print(f"\n  All {len(result.violations)} entries flagged as invalid "
          f"(correct behaviour).")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("\n" + SEP_WIDE)
    print("  TAMPER-EVIDENT LOGGING SYSTEM — Full Demo")
    print(SEP_WIDE)

    log = phase1_build()
    phase2_verify_clean(log)
    phase3a_modify(log)
    phase3b_delete(log)
    phase3c_swap(log)
    phase4_persistence()
    phase5_wrong_key(log)

    print(f"\n{SEP_WIDE}")
    print("  All phases completed.  System working as expected. ✅")
    print(f"{SEP_WIDE}\n")


if __name__ == "__main__":
    main()
