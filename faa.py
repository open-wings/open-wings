#!/usr/bin/env python3
"""
FAA airmen cross-check (verifier check 3).

Confirms the CFI named in a credential is a real, active certified flight
instructor by looking them up in the FAA Releasable Airmen Database, matched by
FAA airman ID (cfi_faa_cert) + name.

Data source — the FAA Releasable Airmen Database (public record):
  https://www.faa.gov/licenses_certificates/airmen_certification/releasable_airmen_download
The comma-delimited download (CS<MMYYYY>.zip) contains PILOT_CERT.csv. Flight
instructors are the rows with TYPE='F'; their EXPIRE DATE (MMDDYYYY) is the
flight-instructor certificate expiry. We treat a CFI as ACTIVE if that expiry
is today or later.

  cfi_faa_cert  -> PILOT_CERT.csv "UNIQUE ID" (the FAA airman ID, e.g. A0000098)
  cfi_name      -> "FIRST NAME" + "LAST NAME" (credential name must be a subset)

Set up the data once:
  python3 fetch_faa.py            # downloads + extracts into faa_data/
  python3 faa.py build-index      # (optional) pre-builds the fast CFI index

The public interface is unchanged so verify.py is untouched:
  check_faa(cfi_name, faa_cert) -> (passed, message)

Stub mode (for testing, behind a flag): set OPENWINGS_FAA_STUB=pass or =fail to
bypass the database entirely.
"""

import csv
import os
import re
import sys
from datetime import date
from pathlib import Path
from typing import Optional, Tuple

DATA_DIR = Path(os.environ.get("OPENWINGS_FAA_DATA", "faa_data"))
CERT_CSV = DATA_DIR / "PILOT_CERT.csv"
INDEX_PATH = DATA_DIR / "cfi_index.csv"  # compact, derived flight-instructor index

_FLIGHT_INSTRUCTOR_TYPE = "F"
_index_cache: Optional[dict] = None


# ---------------------------------------------------------------------------
# Building / loading the flight-instructor index
# ---------------------------------------------------------------------------

def build_index() -> dict:
    """Scan PILOT_CERT.csv once and return {airman_id: {"name", "expire"}}.

    Only the flight-instructor rows (TYPE='F') are kept. The full file is ~120MB
    with 100+ columns, but we only need the first six fields, so we split each
    line lazily rather than parsing every column.
    """
    if not CERT_CSV.exists():
        raise FileNotFoundError(CERT_CSV)

    index: dict = {}
    with CERT_CSV.open(encoding="latin-1") as f:
        next(f, None)  # header
        for line in f:
            parts = line.split(",", 6)  # UNIQUE ID,FIRST,LAST,TYPE,LEVEL,EXPIRE,<rest>
            if len(parts) < 6 or parts[3].strip() != _FLIGHT_INSTRUCTOR_TYPE:
                continue
            airman_id = parts[0].strip().upper()
            name = f"{parts[1].strip()} {parts[2].strip()}".strip()
            index[airman_id] = {"name": name, "expire": parts[5].strip()}
    return index


def _write_index(index: dict, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["airman_id", "name", "expire"])
        for airman_id, rec in index.items():
            writer.writerow([airman_id, rec["name"], rec["expire"]])


def _load_index_file(path: Path) -> dict:
    index: dict = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            index[row["airman_id"]] = {"name": row["name"], "expire": row["expire"]}
    return index


def _get_index() -> dict:
    """Return the flight-instructor index, building and caching it on first use."""
    global _index_cache
    if _index_cache is not None:
        return _index_cache

    if INDEX_PATH.exists():
        _index_cache = _load_index_file(INDEX_PATH)
    else:
        _index_cache = build_index()
        try:
            _write_index(_index_cache, INDEX_PATH)
        except OSError:
            pass  # index is an optimisation; fall back to in-memory only
    return _index_cache


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

def _tokens(name: str) -> set:
    return {t for t in re.split(r"[^A-Za-z0-9]+", (name or "").upper()) if t}


def _name_matches(credential_name: str, db_name: str) -> bool:
    """The credential's name tokens must all appear in the FAA record's name.

    Lets "Kevin McGrady" match the database's "KEVIN PATRICK MCGRADY" while
    still rejecting an unrelated name.
    """
    cred = _tokens(credential_name)
    return bool(cred) and cred.issubset(_tokens(db_name))


def _parse_expiry(mmddyyyy: str) -> Optional[date]:
    if not re.fullmatch(r"\d{8}", mmddyyyy or ""):
        return None
    mm, dd, yyyy = int(mmddyyyy[0:2]), int(mmddyyyy[2:4]), int(mmddyyyy[4:8])
    try:
        return date(yyyy, mm, dd)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def check_faa(cfi_name: str, faa_cert: str) -> Tuple[bool, str]:
    """Return (passed, message) for the FAA cross-check.

    Looks the CFI up in the FAA Releasable Airmen Database by airman ID + name
    and confirms an active (unexpired) flight-instructor certificate.

    Stub mode (behind a flag, for testing): OPENWINGS_FAA_STUB=pass|fail bypasses
    the database lookup entirely.
    """
    stub = os.environ.get("OPENWINGS_FAA_STUB")
    if stub is not None:
        if stub.lower() == "fail":
            return False, f"(stub) No active FAA CFI match for {cfi_name} / cert {faa_cert}"
        return True, f"(stub) {cfi_name} / cert {faa_cert} — assumed active CFI (stub mode)"

    if not cfi_name or not faa_cert:
        return False, "Missing cfi_name or cfi_faa_cert in credential"

    try:
        index = _get_index()
    except FileNotFoundError:
        return False, (
            "FAA airmen database not found in faa_data/. Run 'python3 fetch_faa.py' "
            "to download the FAA Releasable Airmen Database first."
        )

    rec = index.get(faa_cert.strip().upper())
    if rec is None:
        return False, f"No flight-instructor certificate on file for FAA airman ID {faa_cert!r}"

    if not _name_matches(cfi_name, rec["name"]):
        return False, (
            f"Name {cfi_name!r} does not match the FAA record for {faa_cert} "
            f"(on file: {rec['name'].title()})"
        )

    expiry = _parse_expiry(rec["expire"])
    if expiry is None:
        return False, f"FAA record for {faa_cert} has no readable certificate expiry"
    if expiry < date.today():
        return False, (
            f"{rec['name'].title()} ({faa_cert}) — flight-instructor certificate "
            f"EXPIRED {expiry.isoformat()}; not an active CFI"
        )

    return True, (
        f"{rec['name'].title()} ({faa_cert}) — active CFI in FAA airmen data; "
        f"flight-instructor certificate valid through {expiry.isoformat()}"
    )


def _main(argv) -> int:
    if len(argv) >= 1 and argv[0] == "build-index":
        index = build_index()
        _write_index(index, INDEX_PATH)
        print(f"Indexed {len(index)} flight instructors -> {INDEX_PATH}")
        return 0
    if len(argv) == 3 and argv[0] == "check":
        ok, msg = check_faa(argv[1], argv[2])
        print(f"{'PASS' if ok else 'FAIL'}: {msg}")
        return 0 if ok else 1
    print("Usage:\n  python3 faa.py build-index\n  python3 faa.py check \"<cfi name>\" \"<faa id>\"")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
