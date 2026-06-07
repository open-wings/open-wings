#!/usr/bin/env python3
"""
Verify a ClubAircraftCheckout SD-JWT VC.

Check 1 (slice 3) — Signature: resolve the issuer did:key from 'iss' to an
  Ed25519 public key and verify the JWT signature.
Check 2 (slice 4) — Allowlist + temporal: the issuer did:key must be in the
  allowlist AND the credential's issue_date must fall within that issuer's
  [valid_from, valid_until] window (null valid_until = still active). Trust is
  time-relative: a credential issued while the CFI was trusted stays valid even
  after valid_until has passed or the CFI is removed.

Usage:
  python3 verify.py <sd_jwt> [--allowlist allowlist.json]
  python3 verify.py                (reads SD-JWT from stdin)

Exits 0 if all checks pass, 1 otherwise.
(The FAA cross-check comes in a later slice.)
"""

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Optional

import base58
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_ED25519_MULTICODEC = bytes([0xED, 0x01])
DEFAULT_ALLOWLIST_PATH = Path("allowlist.json")


def did_key_to_ed25519_pubkey(did: str) -> Ed25519PublicKey:
    """Resolve a did:key (Ed25519) to an Ed25519PublicKey."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"Not a base58btc did:key: {did!r}")
    raw = base58.b58decode(did[len("did:key:z"):])
    if raw[:2] != _ED25519_MULTICODEC:
        raise ValueError(f"Not an Ed25519 did:key (unexpected multicodec prefix): {did!r}")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def check_signature(sd_jwt: str) -> tuple[bool, str, Optional[dict]]:
    """
    Verify the SD-JWT signature against the issuer's did:key.
    Returns (passed, message, claims_or_none).
    """
    jwt_part = sd_jwt.split("~")[0]

    try:
        unverified = pyjwt.decode(jwt_part, options={"verify_signature": False})
    except Exception as exc:
        return False, f"Malformed JWT: {exc}", None

    iss = unverified.get("iss")
    if not iss:
        return False, "Missing 'iss' claim", None

    try:
        pub_key = did_key_to_ed25519_pubkey(iss)
    except ValueError as exc:
        return False, str(exc), None

    try:
        claims = pyjwt.decode(jwt_part, pub_key, algorithms=["EdDSA"])
        return True, f"Signed by {iss}", claims
    except pyjwt.exceptions.InvalidSignatureError:
        return False, "Signature INVALID — payload has been tampered with or key does not match", None
    except Exception as exc:
        return False, f"Verification error: {exc}", None


def check_allowlist_temporal(claims: dict, allowlist: dict) -> tuple[bool, str]:
    """
    Check 2 — the issuer must be allowlisted AND the credential's issue_date
    must fall within that issuer's [valid_from, valid_until] window.

    Trust is time-relative: we compare issue_date against the window, never the
    current date. A null valid_until means "still active"; a past valid_until
    still trusts credentials that were issued before it.
    """
    iss = claims.get("iss")
    issue_date_str = claims.get("issue_date")
    if not issue_date_str:
        return False, "Credential has no issue_date claim"

    entry = next(
        (e for e in allowlist.get("trusted_issuers", []) if e.get("did") == iss),
        None,
    )
    if entry is None:
        return False, f"Issuer not in allowlist: {iss}"

    try:
        issue_date = date.fromisoformat(issue_date_str)
        valid_from = date.fromisoformat(entry["valid_from"])
        valid_until = date.fromisoformat(entry["valid_until"]) if entry.get("valid_until") else None
    except (ValueError, KeyError) as exc:
        return False, f"Bad date in credential or allowlist: {exc}"

    window = f"[{valid_from}, {valid_until if valid_until else 'active'}]"

    if issue_date < valid_from:
        return False, f"issue_date {issue_date} is before issuer's valid_from {valid_from}"
    if valid_until is not None and issue_date > valid_until:
        return False, f"issue_date {issue_date} is after issuer's valid_until {valid_until} {window}"

    return True, f"Issuer allowlisted; issue_date {issue_date} within window {window}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a ClubAircraftCheckout SD-JWT VC")
    parser.add_argument("sd_jwt", nargs="?", help="SD-JWT VC string (or pass on stdin)")
    parser.add_argument(
        "--allowlist",
        default=str(DEFAULT_ALLOWLIST_PATH),
        help=f"Path to trusted-issuer allowlist (default: {DEFAULT_ALLOWLIST_PATH}).",
    )
    args = parser.parse_args()

    sd_jwt = (args.sd_jwt or sys.stdin.read()).strip()
    if not sd_jwt:
        print("No SD-JWT provided.")
        sys.exit(1)

    # Check 1 — signature.
    sig_ok, sig_msg, claims = check_signature(sd_jwt)
    print(f"[1] Signature         : {'PASS' if sig_ok else 'FAIL'}")
    print(f"    {sig_msg}")

    # Check 2 — allowlist + temporal. Only meaningful once the signature is
    # trusted, so it is skipped (and counts as not passing) if check 1 fails.
    if sig_ok:
        try:
            allowlist = json.loads(Path(args.allowlist).read_text())
        except FileNotFoundError:
            print(f"[2] Allowlist+temporal: FAIL")
            print(f"    Allowlist file not found: {args.allowlist}")
            sys.exit(1)
        allow_ok, allow_msg = check_allowlist_temporal(claims, allowlist)
        print(f"[2] Allowlist+temporal: {'PASS' if allow_ok else 'FAIL'}")
        print(f"    {allow_msg}")
    else:
        allow_ok = False
        print(f"[2] Allowlist+temporal: SKIPPED (signature did not pass)")

    all_pass = sig_ok and allow_ok
    print()
    print(f"RESULT: {'TRUSTED' if all_pass else 'REJECTED'}  (slice 4: 2 of 2 checks; FAA check still to come)")

    if claims:
        print()
        print("Claims:")
        print(json.dumps(claims, indent=2))

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
