#!/usr/bin/env python3
"""
Open Wings — web verifier (checkout-desk UI).

A thin web wrapper over verify.verify_credential. It does NOT reimplement any
check: it takes a presented credential (pasted or uploaded), calls the same
verification logic the CLI uses, and shows each of the three results plus the
overall TRUSTED / REJECTED verdict in plain language.

Run:
  .venv/bin/python3 app.py
  then open http://127.0.0.1:5000
"""

from flask import Flask, render_template_string, request

from verify import DEFAULT_ALLOWLIST_PATH, verify_credential

app = Flask(__name__)

# Plain-language explanation of what each check answers, for a non-technical
# user at the desk. Keyed by the check names returned by verify_credential.
CHECK_HELP = {
    "Signature": "Is the credential genuine and unaltered?",
    "Allowlist + temporal": "Was the instructor authorized by the club when they issued it?",
    "FAA cross-check": "Is the instructor a real, active FAA-certified CFI?",
}

# Friendly labels for the credential's claims.
CLAIM_LABELS = [
    ("pilot_name", "Pilot"),
    ("aircraft", "Aircraft"),
    ("cfi_name", "Instructor (CFI)"),
    ("cfi_faa_cert", "CFI certificate"),
    ("club_id", "Club"),
    ("issue_date", "Issued"),
    ("exp", "Expires"),
]

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Open Wings — Credential Verifier</title>
  <style>
    :root { --green:#1a7f37; --red:#b42318; --grey:#6b7280; --line:#e5e7eb; }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
           max-width: 720px; margin: 0 auto; padding: 32px 20px 64px; color: #111827;
           background: #f9fafb; }
    h1 { font-size: 1.5rem; margin: 0 0 4px; }
    .sub { color: var(--grey); margin: 0 0 28px; }
    .card { background: #fff; border: 1px solid var(--line); border-radius: 12px;
            padding: 20px; margin-bottom: 20px; }
    label { font-weight: 600; display: block; margin-bottom: 8px; }
    textarea { width: 100%; min-height: 130px; padding: 12px; font-family: ui-monospace, monospace;
               font-size: 0.85rem; border: 1px solid var(--line); border-radius: 8px; resize: vertical; }
    .or { text-align: center; color: var(--grey); margin: 12px 0; font-size: 0.9rem; }
    input[type=file] { font-size: 0.9rem; }
    button { margin-top: 16px; background: #111827; color: #fff; border: 0; border-radius: 8px;
             padding: 12px 22px; font-size: 1rem; font-weight: 600; cursor: pointer; }
    button:hover { background: #000; }
    .verdict { border-radius: 12px; padding: 22px; text-align: center; color: #fff;
               font-size: 1.6rem; font-weight: 700; letter-spacing: 0.5px; margin-bottom: 20px; }
    .verdict.trusted { background: var(--green); }
    .verdict.rejected { background: var(--red); }
    .verdict small { display: block; font-size: 0.85rem; font-weight: 500; opacity: 0.9; margin-top: 4px;
                     letter-spacing: 0; }
    .check { display: flex; gap: 14px; padding: 14px 0; border-bottom: 1px solid var(--line); }
    .check:last-child { border-bottom: 0; }
    .icon { font-size: 1.3rem; line-height: 1.4; width: 24px; text-align: center; flex-shrink: 0; }
    .pass .icon { color: var(--green); }
    .fail .icon { color: var(--red); }
    .skip .icon { color: var(--grey); }
    .check .name { font-weight: 600; }
    .check .help { color: var(--grey); font-size: 0.9rem; margin: 2px 0 4px; }
    .check .msg { font-size: 0.85rem; color: #374151; font-family: ui-monospace, monospace;
                  word-break: break-word; }
    .details { margin-top: 4px; }
    .details h2 { font-size: 1rem; margin: 0 0 12px; }
    .row { display: flex; padding: 6px 0; border-bottom: 1px solid var(--line); font-size: 0.95rem; }
    .row:last-child { border-bottom: 0; }
    .row .k { width: 150px; color: var(--grey); flex-shrink: 0; }
    .row .v { font-weight: 600; }
    .empty { color: var(--red); margin-bottom: 20px; }
  </style>
</head>
<body>
  <h1>✈️ Open Wings — Credential Verifier</h1>
  <p class="sub">Paste or upload the pilot's credential to check it is genuine and current.</p>

  {% if error %}<div class="card empty">{{ error }}</div>{% endif %}

  {% if result %}
    <div class="verdict {{ 'trusted' if result.trusted else 'rejected' }}">
      {{ 'TRUSTED' if result.trusted else 'REJECTED' }}
      <small>{{ 'All three checks passed.' if result.trusted else 'One or more checks did not pass — do not accept this credential.' }}</small>
    </div>

    <div class="card">
      {% for c in result.checks %}
        <div class="check {{ c.status }}">
          <div class="icon">{{ '✓' if c.status == 'pass' else ('✗' if c.status == 'fail' else '–') }}</div>
          <div>
            <div class="name">{{ c.name }}
              — {{ 'Pass' if c.status == 'pass' else ('Fail' if c.status == 'fail' else 'Not checked') }}</div>
            <div class="help">{{ check_help.get(c.name, '') }}</div>
            <div class="msg">{{ c.message }}</div>
          </div>
        </div>
      {% endfor %}
    </div>

    {% if result.claims %}
      <div class="card details">
        <h2>Credential details</h2>
        {% for key, label in claim_labels %}
          {% if result.claims.get(key) %}
            <div class="row"><div class="k">{{ label }}</div><div class="v">{{ result.claims.get(key) }}</div></div>
          {% endif %}
        {% endfor %}
      </div>
    {% endif %}
  {% endif %}

  <div class="card">
    <form method="post" enctype="multipart/form-data">
      <label for="credential">Presented credential</label>
      <textarea id="credential" name="credential" placeholder="Paste the credential here (a long string ending in ~)">{{ submitted or '' }}</textarea>
      <div class="or">— or —</div>
      <label for="credential_file">Upload a credential file</label>
      <input id="credential_file" type="file" name="credential_file">
      <div><button type="submit">Verify credential</button></div>
    </form>
  </div>
</body>
</html>
"""


def _read_submitted() -> str:
    """Get the SD-JWT from the uploaded file if present, else the textarea."""
    upload = request.files.get("credential_file")
    if upload and upload.filename:
        return upload.read().decode("utf-8", errors="replace").strip()
    return (request.form.get("credential") or "").strip()


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    submitted = ""

    if request.method == "POST":
        submitted = _read_submitted()
        if not submitted:
            error = "Please paste a credential or choose a file to verify."
        else:
            result = verify_credential(submitted, str(DEFAULT_ALLOWLIST_PATH))

    return render_template_string(
        PAGE,
        result=result,
        error=error,
        submitted=submitted,
        check_help=CHECK_HELP,
        claim_labels=CLAIM_LABELS,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
