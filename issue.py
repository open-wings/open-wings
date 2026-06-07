#!/usr/bin/env python3
"""
Slice 1 — Issue a ClubAircraftCheckout SD-JWT VC.

Generates a did:key (Ed25519) for a CFI, a did:key for a pilot, builds the
credential payload, signs it as an SD-JWT VC (no selective disclosures in v1),
and prints everything.

Usage:
  python3 issue.py                        # generate a fresh pilot DID
  python3 issue.py --pilot-did did:key:z…  # issue to the holder's wallet DID
"""

import argparse
import json
import time
from datetime import date

import base58
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_ED25519_MULTICODEC = bytes([0xED, 0x01])


def generate_did_key() -> tuple[Ed25519PrivateKey, str]:
    """Return (private_key, did:key string) for a fresh Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    encoded = base58.b58encode(_ED25519_MULTICODEC + pub_bytes).decode()
    return private_key, f"did:key:z{encoded}"


def issue_sd_jwt_vc(private_key: Ed25519PrivateKey, payload: dict) -> str:
    """Sign payload with EdDSA and wrap as SD-JWT with no disclosures (<JWT>~)."""
    token = jwt.encode(payload, private_key, algorithm="EdDSA")
    return token + "~"


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a ClubAircraftCheckout SD-JWT VC")
    parser.add_argument(
        "--pilot-did",
        help="Pilot's did:key from their wallet. Omit to generate a throwaway identity.",
    )
    args = parser.parse_args()

    cfi_key, cfi_did = generate_did_key()
    if args.pilot_did:
        pilot_did = args.pilot_did
    else:
        _, pilot_did = generate_did_key()

    print(f"CFI DID  : {cfi_did}")
    print(f"Pilot DID: {pilot_did}")
    print()

    payload = {
        "vct": "ClubAircraftCheckout",
        "iss": cfi_did,
        "sub": pilot_did,
        "iat": int(time.time()),
        "cfi_name": "Jane Smith",
        "cfi_faa_cert": "1234567",
        "pilot_name": "John Doe",
        "aircraft": "N12345",
        "club_id": "BVAC",
        "issue_date": date.today().isoformat(),
    }

    sd_jwt = issue_sd_jwt_vc(cfi_key, payload)

    print("SD-JWT VC:")
    print(sd_jwt)
    print()
    print("Decoded claims:")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
