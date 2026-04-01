"""
cli.py  —  Tamper-Evident Logging System CLI
PowerShell-friendly: --data accepts key=value pairs
"""

import argparse
import json
import os
import sys

from log_store import LogStore
from log_verifier import LogVerifier


def _get_secret(args):
    secret = getattr(args, "secret", "") or os.environ.get("LOG_HMAC_SECRET", "")
    if not secret:
        sys.exit("Error: supply a secret via --secret or LOG_HMAC_SECRET env variable.")
    return secret


def _load_store(args, secret):
    store = LogStore(args.log, secret)
    store.load()
    return store


def _parse_data(data_tokens):
    if not data_tokens:
        return {}
    combined = " ".join(data_tokens).strip()
    if combined.startswith("{"):
        try:
            return json.loads(combined)
        except json.JSONDecodeError as e:
            sys.exit(f"Error: --data JSON is invalid — {e}")
    result = {}
    for token in data_tokens:
        if "=" not in token:
            sys.exit(f"Error: --data token '{token}' must be key=value format")
        k, v = token.split("=", 1)
        try:
            v = int(v)
        except ValueError:
            try:
                v = float(v)
            except ValueError:
                pass
        result[k.strip()] = v
    return result


def cmd_add(args):
    secret = _get_secret(args)
    store = _load_store(args, secret)
    data = _parse_data(args.data)
    entry = store.add_and_save(args.type, args.desc, data)
    print(f"Entry added  [seq {entry.sequence}]  {entry.event_type}  ->  {entry.entry_hash[:16]}...")


def cmd_verify(args):
    secret = _get_secret(args)
    store = _load_store(args, secret)
    result = LogVerifier(secret).verify(store.log)
    print(result)
    if not result.passed:
        sys.exit(2)


def cmd_list(args):
    secret = _get_secret(args)
    store = _load_store(args, secret)
    entries = store.log.entries
    if not entries:
        print("(log is empty)")
        return
    print(f"\n{'SEQ':<5} {'EVENT TYPE':<20} {'DESCRIPTION':<35} {'HASH PREFIX'}")
    print("-" * 85)
    for e in entries:
        desc = (e.description[:32] + "...") if len(e.description) > 32 else e.description
        print(f"{e.sequence:<5} {e.event_type:<20} {desc:<35} {e.entry_hash[:16]}...")
    print(f"\nTotal: {len(entries)} entries\n")


def cmd_export(args):
    secret = _get_secret(args)
    store = _load_store(args, secret)
    out_path = args.out if args.out else args.log.replace(".json", "_report.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(store.log.to_list(), fh, indent=2)
    print(f"Exported {store.log.size} entries -> {out_path}")


def build_parser():
    parser = argparse.ArgumentParser(prog="cli.py", description="Tamper-Evident Logging System")
    parser.add_argument("--log",    required=True)
    parser.add_argument("--secret", default="")

    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add")
    p_add.add_argument("--type", required=True)
    p_add.add_argument("--desc", required=True)
    p_add.add_argument("--data", nargs="*", default=[])
    p_add.set_defaults(func=cmd_add)

    p_verify = sub.add_parser("verify")
    p_verify.set_defaults(func=cmd_verify)

    p_list = sub.add_parser("list")
    p_list.set_defaults(func=cmd_list)

    p_export = sub.add_parser("export")
    p_export.add_argument("--out", default="")
    p_export.set_defaults(func=cmd_export)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
