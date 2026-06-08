#!/usr/bin/env python3
"""
Slice 1 — Issue a ClubAircraftCheckout SD-JWT VC.

Generates a did:key (Ed25519) for a CFI, a did:key for a pilot, builds the
credential payload, signs it as an SD-JWT VC (no selective disclosures in v1),
and prints everything.

Usage:
  python3 issue.py                            # persistent CFI key, fresh pilot DID, issued today
  python3 issue.py --pilot-did did:key:z…     # issue to the holder's wallet DID
  python3 issue.py --issue-date 2023-06-01    # backdate the issue_date (for testing)
  python3 issue.py --cfi-key other_cfi.json   # use a different CFI identity file
"""

import argparse
import base64
import json
import time
from datetime import date
from pathlib import Path

import base58
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_ED25519_MULTICODEC = bytes([0xED, 0x01])
DEFAULT_CFI_KEY_PATH = Path("cfi_key.json")


def _did_from_key(private_key: Ed25519PrivateKey) -> str:
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    encoded = base58.b58encode(_ED25519_MULTICODEC + pub_bytes).decode()
    return f"did:key:z{encoded}"


def generate_did_key() -> tuple[Ed25519PrivateKey, str]:
    """Return (private_key, did:key string) for a fresh Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, _did_from_key(private_key)


def load_or_create_cfi_key(path: Path) -> tuple[Ed25519PrivateKey, str]:
    """Load the CFI's persistent Ed25519 key, creating it on first use.

    A CFI has one stable did:key identity (the one listed in the allowlist),
    so unlike the throwaway pilot DID it must persist across runs.
    """
    if path.exists():
        data = json.loads(path.read_text())
        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(data["private_key_b64"]))
        return key, _did_from_key(key)

    key, did = generate_did_key()
    path.write_text(
        json.dumps({"private_key_b64": base64.b64encode(key.private_bytes_raw()).decode()}, indent=2)
        + "\n"
    )
    return key, did


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
    parser.add_argument(
        "--cfi-key",
        default=str(DEFAULT_CFI_KEY_PATH),
        help=f"Path to the CFI's persistent key file (default: {DEFAULT_CFI_KEY_PATH}).",
    )
    parser.add_argument(
        "--issue-date",
        default=date.today().isoformat(),
        help="issue_date as YYYY-MM-DD (default: today). Useful for testing temporal rules.",
    )
    parser.add_argument("--cfi-name", default="Jane Smith", help="CFI name claim.")
    parser.add_argument(
        "--cfi-cert",
        default="1234567",
        help="CFI's FAA airman ID claim (matched against the FAA airmen database).",
    )
    args = parser.parse_args()

    cfi_key, cfi_did = load_or_create_cfi_key(Path(args.cfi_key))
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
        "cfi_name": args.cfi_name,
        "cfi_faa_cert": args.cfi_cert,
        "pilot_name": "John Doe",
        "aircraft": "N12345",
        "club_id": "BVAC",
        "issue_date": args.issue_date,
    }

    sd_jwt = issue_sd_jwt_vc(cfi_key, payload)

    print("SD-JWT VC:")
    print(sd_jwt)
    print()
    print("Decoded claims:")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
