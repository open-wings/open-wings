# Open Wings — v1 Project Context

## What this is
Open Wings is an open-source system for verifiable flight credentials. A flight instructor (CFI) issues a digitally signed credential to a pilot; the pilot holds it on their phone; a verifier (a flying club's checkout desk) confirms it is genuine. v1 targets a single flying club.

## Fixed architecture (do not change without asking)
- Credential format: SD-JWT VC.
- Issuer (CFI) and holder (pilot) identity: did:key (self-contained, Ed25519). No central issuer domain.
- Verifier: our own lightweight web app.
- Trust comes from three things, not a central server: a signature, a trusted-issuer allowlist, and an FAA cross-check.

## v1 credential
Type: ClubAircraftCheckout. Claims: issuer (CFI did:key, the signer), cfi_name, cfi_faa_cert, subject (pilot did:key), pilot_name, aircraft (tail or make/model/class), club_id, issue_date, optional expiry.

## Three verifier checks, in order
1. Signature: verify the SD-JWT VC against the issuer's did:key.
2. Allowlist + temporal: the issuer did:key must be in the allowlist AND the credential's issue_date must fall within that issuer's [valid_from, valid_until] window (null valid_until = still active). Trust holds even if valid_until is now past, as long as issue_date was inside the window. Reject if issued outside it.
3. FAA cross-check: cfi_name + cfi_faa_cert match an active CFI in FAA airmen data. Stub as "pass" first; wire in the downloadable FAA database later.
Trust only if all three pass; show each result.

## Allowlist (one JSON file)
{ "trusted_issuers": [ { "did": "...", "name": "...", "faa_cert": "...", "valid_from": "YYYY-MM-DD", "valid_until": null } ] }

## Key rule
Trust is time-relative: always check issuer authority as of the credential's issue_date against validity windows, never a simple current on/off.

## v1 definition of done
An allowlisted CFI issues one ClubAircraftCheckout to a pilot's holder; the pilot holds it; the web verifier shows the three checks passing; revocation works (remove the key → its NEW credentials rejected); temporal validity works (a credential issued while the CFI was trusted still verifies after the CFI is removed).

## Out of scope for v1
No full logbook, no second credential type, no SHACL, no application ontology, no live FAA API (stub it), no selective disclosure, no app-store release, no goal/data-store features, no production key management.

## How we work
Thin slices, one at a time, testing each: (1) issue one credential and print it; (2) hold it; (3) verify the signature; (4) allowlist+temporal check; (5) FAA cross-check (stub first); (6) revocation. Keep it simple; prefer well-maintained libraries.
