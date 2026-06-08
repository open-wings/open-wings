#!/usr/bin/env python3
"""
Download + extract the FAA Releasable Airmen Database (comma-delimited) into
faa_data/, ready for faa.check_faa().

The FAA publishes a monthly ZIP named CS<MMYYYY>.zip (e.g. CS062026.zip). This
script tries the current month and walks back a few months to find the latest
available file. The registry host requires browser-like headers, so we send
them. The data (and the extracted CSVs) are large and are gitignored.

Usage:
  python3 fetch_faa.py
"""

import io
import sys
import urllib.request
import zipfile
from datetime import date
from pathlib import Path

DATA_DIR = Path("faa_data")
BASE = "https://registry.faa.gov/database/CS{mmyyyy}.zip"
REFERER = "https://www.faa.gov/licenses_certificates/airmen_certification/releasable_airmen_download"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                  "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Accept": "*/*",
    "Referer": REFERER,
}


def _candidate_months(n=6):
    y, m = date.today().year, date.today().month
    for _ in range(n):
        yield f"{m:02d}{y:04d}"
        m -= 1
        if m == 0:
            m, y = 12, y - 1


def main() -> int:
    DATA_DIR.mkdir(exist_ok=True)
    for mmyyyy in _candidate_months():
        url = BASE.format(mmyyyy=mmyyyy)
        try:
            print(f"Trying {url} ...")
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = resp.read()
        except Exception as exc:  # noqa: BLE001 - try the next month
            print(f"  not available ({exc})")
            continue

        zip_path = DATA_DIR / f"CS{mmyyyy}.zip"
        zip_path.write_bytes(data)
        print(f"  downloaded {len(data) / 1048576:.1f} MB -> {zip_path}")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(DATA_DIR)
        print(f"  extracted into {DATA_DIR}/")
        print("Done. Next: python3 faa.py build-index (optional) or just run the verifier.")
        return 0

    print("Could not download the FAA database from any recent month.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
