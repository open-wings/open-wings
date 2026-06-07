#!/usr/bin/env python3
"""
FAA airmen cross-check (verifier check 3).

Confirms the CFI named in the credential is an active certified flight
instructor in FAA airmen data, matched by name + certificate number.

v1 is a STUB that returns pass. The real implementation will load the
downloadable FAA airmen database and perform the lookup inside check_faa(),
WITHOUT any change to verify.py — the verifier depends only on this function's
signature: check_faa(cfi_name, faa_cert) -> (passed, message).
"""

import os
from typing import Tuple


def check_faa(cfi_name: str, faa_cert: str) -> Tuple[bool, str]:
    """Return (passed, message) for the FAA cross-check.

    Stub behaviour: passes as long as both fields are present.

    Slice-5 test hook: setting the env var OPENWINGS_FAA_STUB=fail forces a
    failure, so we can prove the check is wired into the verifier's decision.
    The real FAA-database lookup will replace this body and ignore the env var.
    """
    if not cfi_name or not faa_cert:
        return False, "Missing cfi_name or cfi_faa_cert in credential"

    if os.environ.get("OPENWINGS_FAA_STUB", "pass").lower() == "fail":
        return False, f"(stub) No active FAA CFI match for {cfi_name} / cert {faa_cert}"

    return True, (
        f"(stub) {cfi_name} / cert {faa_cert} — assumed active CFI "
        "(real FAA database lookup not wired yet)"
    )
