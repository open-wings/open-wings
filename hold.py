#!/usr/bin/env python3
"""
Slice 2 — Pilot wallet (holder).

Commands:
  init                       Generate a pilot identity and create wallet.json
  receive <sd_jwt>           Save a credential to the wallet
  receive                    Read SD-JWT from stdin and save it
  show                       Display all held credentials
"""

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import base58
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

WALLET_PATH = Path("wallet.json")
_ED25519_MULTICODEC = bytes([0xED, 0x01])


def _key_to_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.private_bytes_raw()).decode()


def _key_from_b64(b64: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(b64))


def _did_from_key(key: Ed25519PrivateKey) -> str:
    pub_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    encoded = base58.b58encode(_ED25519_MULTICODEC + pub_bytes).decode()
    return f"did:key:z{encoded}"


def _decode_claims(sd_jwt: str) -> dict:
    """Decode JWT claims without verifying the signature (verification is slice 3)."""
    jwt_part = sd_jwt.split("~")[0]
    return pyjwt.decode(jwt_part, options={"verify_signature": False})


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(_args) -> None:
    if WALLET_PATH.exists():
        print(f"Wallet already exists at {WALLET_PATH}. Delete it first to reinitialise.")
        sys.exit(1)

    key = Ed25519PrivateKey.generate()
    did = _did_from_key(key)

    wallet = {
        "did": did,
        "private_key_b64": _key_to_b64(key),
        "credentials": [],
    }
    WALLET_PATH.write_text(json.dumps(wallet, indent=2) + "\n")

    print(f"Wallet created : {WALLET_PATH}")
    print(f"Pilot DID      : {did}")


def cmd_receive(args) -> None:
    if not WALLET_PATH.exists():
        print("No wallet found. Run:  python3 hold.py init")
        sys.exit(1)

    sd_jwt = (args.sd_jwt or sys.stdin.read()).strip()
    if not sd_jwt:
        print("No SD-JWT provided.")
        sys.exit(1)

    claims = _decode_claims(sd_jwt)

    wallet = json.loads(WALLET_PATH.read_text())
    wallet["credentials"].append({
        "sd_jwt": sd_jwt,
        "vct": claims.get("vct"),
        "iss": claims.get("iss"),
        "issue_date": claims.get("issue_date"),
        "received_at": datetime.now(timezone.utc).isoformat(),
    })
    WALLET_PATH.write_text(json.dumps(wallet, indent=2) + "\n")

    n = len(wallet["credentials"])
    print(f"Stored. Wallet now holds {n} credential(s).")
    print(f"  Type      : {claims.get('vct')}")
    print(f"  Issuer    : {claims.get('iss')}")
    print(f"  Aircraft  : {claims.get('aircraft')}")
    print(f"  Issue date: {claims.get('issue_date')}")


def cmd_show(_args) -> None:
    if not WALLET_PATH.exists():
        print("No wallet found. Run:  python3 hold.py init")
        sys.exit(1)

    wallet = json.loads(WALLET_PATH.read_text())
    print(f"Pilot DID        : {wallet['did']}")
    print(f"Credentials held : {len(wallet['credentials'])}")

    for i, entry in enumerate(wallet["credentials"], 1):
        print(f"\n{'─' * 50}")
        print(f"Credential {i}")
        print(f"{'─' * 50}")
        claims = _decode_claims(entry["sd_jwt"])
        print(json.dumps(claims, indent=2))
        print(f"\nReceived at : {entry['received_at']}")
        print(f"SD-JWT      : {entry['sd_jwt']}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Open Wings pilot wallet")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Create a wallet with a new pilot identity")

    rx = sub.add_parser("receive", help="Save a credential to the wallet")
    rx.add_argument("sd_jwt", nargs="?", help="SD-JWT VC string (or pass on stdin)")

    sub.add_parser("show", help="Display all held credentials")

    args = parser.parse_args()
    {"init": cmd_init, "receive": cmd_receive, "show": cmd_show}[args.command](args)


if __name__ == "__main__":
    main()
