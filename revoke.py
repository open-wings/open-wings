#!/usr/bin/env python3
"""
Slice 6 — Issuer-level revocation.

Closes a trusted issuer's window by setting their valid_until in the allowlist.
Because the verifier already enforces [valid_from, valid_until] against each
credential's issue_date (slice 4), this is the only action revocation needs:

  - credentials issued ON OR BEFORE valid_until stay valid (trust is
    time-relative — they were issued while the CFI was trusted);
  - credentials issued AFTER valid_until are rejected.

Per-credential status-list revocation is out of scope for v1.

Usage:
  python3 revoke.py <did> [--date YYYY-MM-DD] [--allowlist allowlist.json]
    --date defaults to today (revoke as of now).

Exits 0 on success, 1 if the issuer is not found.
"""

import argparse
import json
import sys
from datetime import date
from pathlib import Path

DEFAULT_ALLOWLIST_PATH = Path("allowlist.json")


def revoke_issuer(allowlist: dict, did: str, as_of: str) -> tuple[bool, str]:
    """Set the issuer's valid_until to as_of. Returns (changed, message)."""
    entry = next(
        (e for e in allowlist.get("trusted_issuers", []) if e.get("did") == did),
        None,
    )
    if entry is None:
        return False, f"Issuer not found in allowlist: {did}"

    previous = entry.get("valid_until")
    entry["valid_until"] = as_of
    return True, (
        f"Revoked {entry.get('name', '(unnamed)')} ({did})\n"
        f"    valid_until: {previous if previous else 'null (active)'} -> {as_of}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Revoke a trusted issuer (issuer-level)")
    parser.add_argument("did", help="The issuer did:key to revoke")
    parser.add_argument(
        "--date",
        default=date.today().isoformat(),
        help="valid_until to set, YYYY-MM-DD (default: today / now).",
    )
    parser.add_argument(
        "--allowlist",
        default=str(DEFAULT_ALLOWLIST_PATH),
        help=f"Path to the allowlist (default: {DEFAULT_ALLOWLIST_PATH}).",
    )
    args = parser.parse_args()

    # Validate the date format up front.
    try:
        date.fromisoformat(args.date)
    except ValueError:
        print(f"Invalid --date {args.date!r}; expected YYYY-MM-DD.")
        sys.exit(1)

    path = Path(args.allowlist)
    allowlist = json.loads(path.read_text())

    changed, message = revoke_issuer(allowlist, args.did, args.date)
    print(message)
    if not changed:
        sys.exit(1)

    path.write_text(json.dumps(allowlist, indent=2) + "\n")
    print(f"    Wrote {path}")


if __name__ == "__main__":
    main()
