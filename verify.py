#!/usr/bin/env python3
"""
Slice 3 — Verify the signature on a ClubAircraftCheckout SD-JWT VC.

Extracts the issuer did:key from the 'iss' claim, resolves it to an
Ed25519 public key, and checks the JWT signature.

Usage:
  python3 verify.py <sd_jwt>
  python3 verify.py          (reads from stdin)

Exits 0 on pass, 1 on failure.
(Allowlist + temporal and FAA checks come in later slices.)
"""

import argparse
import json
import sys
from typing import Optional

import base58
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_ED25519_MULTICODEC = bytes([0xED, 0x01])


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


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a ClubAircraftCheckout SD-JWT VC")
    parser.add_argument("sd_jwt", nargs="?", help="SD-JWT VC string (or pass on stdin)")
    args = parser.parse_args()

    sd_jwt = (args.sd_jwt or sys.stdin.read()).strip()
    if not sd_jwt:
        print("No SD-JWT provided.")
        sys.exit(1)

    passed, message, claims = check_signature(sd_jwt)

    print(f"[1] Signature : {'PASS' if passed else 'FAIL'}")
    print(f"    {message}")

    if claims:
        print()
        print("Claims:")
        print(json.dumps(claims, indent=2))

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
