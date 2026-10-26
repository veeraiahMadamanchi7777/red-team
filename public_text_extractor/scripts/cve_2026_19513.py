#!/usr/bin/env python3
"""
CVE-2026-19513 — Gravity Forms Unauthenticated Arbitrary File Upload
=====================================================================

CVE ID      : CVE-2026-19513
CVSS Score  : 8.1 (HIGH)
CVSS Vector : CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
Affected    : Gravity Forms <= 3.0.2
Patched     : 3.0.3+
Published   : September 2026
Component   : GFAsyncUpload::upload()

Description
-----------
Gravity Forms accepts chunked multi-file uploads via an unauthenticated AJAX
action (?action=gf_upload_temp_file or admin-ajax.php?action=gf_upload_temp_file).

The vulnerability exists in two weaknesses in GFAsyncUpload::upload():

  1. STATE HASH CONFUSION — The function uses a "state hash" derived from the
     public form URL to authorise chunk continuation. A public form's state hash
     can be reused as a chunk-continuation hash for a completely different upload
     request, bypassing the intended session binding.

  2. FILENAME INJECTION — Attacker-controlled filenames are accepted and written
     to the Gravity Forms temporary upload directory BEFORE sanitisation occurs.
     This allows a filename like "shell.php" or "shell.php.png" to land on disk
     under the attacker-chosen name.

Combined, these allow an unauthenticated attacker who can identify:
  (a) a public Gravity Forms page, and
  (b) a form with a File Upload field with "Allow Multiple Files" enabled

...to upload a file with an attacker-controlled filename to:
  wp-content/uploads/gravity_forms/tmp/<attacker-filename>

If PHP execution is not blocked in that directory (no .htaccess), this achieves
Remote Code Execution. If PHP execution IS blocked, a .html file can still
deliver stored XSS in same-origin context.

Attack Surface
--------------
- WordPress sites running Gravity Forms <= 3.0.2
- Must have at least one public form with a File Upload field
- "Allow Multiple Files" (chunked upload mode) must be enabled on that field
- RCE requires PHP execution not blocked in uploads/gravity_forms/tmp/

Detection Methodology (READ-ONLY — no files written)
------------------------------------------------------
This script performs PASSIVE detection only. It does NOT upload any files.

Step 1 — Confirm Gravity Forms is present
  - Check for gravityforms assets in page HTML (ver= strings, /gravityforms/ paths)
  - Confirm via /wp-json/gf/v2/ REST namespace (returns 401 if GF present)

Step 2 — Locate public forms with file upload fields
  - Fetch candidate pages (homepage, /contact, /book, /register, etc.)
  - Parse HTML for <input type="file"> inside a <form> with gform_ class markers
  - Look for data-max-files or data-allow-multiple attributes (chunked upload indicator)

Step 3 — Probe the async upload endpoint reachability
  - Send a minimal malformed POST to admin-ajax.php?action=gf_upload_temp_file
  - A response of {"error":...} or {"status":...} confirms endpoint is live and
    reachable without authentication
  - A 400/200 JSON response = endpoint exposed; 403/404 = blocked or patched

Step 4 — Version confirmation
  - Check gravityforms asset URLs for ver= query param
  - Compare against affected range (<= 3.0.2)

The script does NOT:
  - Upload any file (benign or otherwise)
  - Send a valid form nonce
  - Write anything to the target server

Remediation
-----------
- Upgrade Gravity Forms to >= 3.0.3
- Block PHP execution in wp-content/uploads/ via .htaccess:
    <FilesMatch "\.php$">
      Deny from all
    </FilesMatch>
- Restrict File Upload fields to authenticated users where possible
- Disable "Allow Multiple Files" on public-facing forms until patched

References
----------
- https://www.rapid7.com/db/vulnerabilities/cve-2026-19513/
- https://www.sentinelone.com/vulnerability-database/cve-2026-19513/
- https://zeropath.com/blog/gravity-forms-cve-2025-12352-summary
- https://hol.org/guard/security/cves/CVE-2026-19513-gravity-forms-302-unauthenticated-arbitrary-file
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


# ── Constants ──────────────────────────────────────────────────────────────────

UA = "GravityForms-CVE-Detector/1.0 (passive security check; no files uploaded)"

# Pages commonly containing contact/booking forms
FORM_CANDIDATE_PATHS = [
    "/",
    "/contact",
    "/contact-us",
    "/book",
    "/booking",
    "/register",
    "/sign-up",
    "/get-a-quote",
    "/request",
    "/apply",
    "/reservations",
    "/groups",
    "/gift-cards",
    "/trip-builder",
    "/text-consent",
]

# Gravity Forms HTML markers
GF_FORM_PATTERN       = re.compile(r'class=["\'][^"\']*gform', re.I)
GF_FILE_INPUT_PATTERN = re.compile(r'<input[^>]+type=["\']file["\'][^>]*>', re.I | re.S)
GF_MULTI_PATTERN      = re.compile(r'(data-max-files|gf_multi_upload|allow_multiple|gform_multifile)', re.I)
GF_ASSET_VER_PATTERN  = re.compile(r'/gravityforms/[^"\'?]*\?[^"\']*ver=([0-9][^"\'&\s]+)', re.I)
GF_NONCE_PATTERN      = re.compile(r'"nonce"\s*:\s*"([a-f0-9]{10})"', re.I)
GFORM_ID_PATTERN      = re.compile(r'gform_ajax_frame_(\d+)|id=["\']gform_(\d+)["\']', re.I)


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass
class FormFinding:
    url: str
    form_ids: list[str]
    has_file_input: bool
    has_multi_upload: bool
    nonce: str | None


@dataclass
class ScanResult:
    target: str
    gf_detected: bool = False
    gf_version: str | None = None
    version_affected: bool | None = None   # None = unknown
    rest_api_exposed: bool = False
    upload_endpoint_reachable: bool = False
    upload_endpoint_status: int | None = None
    upload_endpoint_response: str = ""
    forms_found: list[FormFinding] = field(default_factory=list)
    public_file_upload_forms: list[FormFinding] = field(default_factory=list)
    verdict: str = "UNKNOWN"
    evidence: list[str] = field(default_factory=list)


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def get(url: str, timeout: int = 12) -> tuple[int, str, dict[str, str]]:
    """GET url → (status, body, headers). Never raises on HTTP errors."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(500_000).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in r.headers.items()}
            return r.status, body, headers
    except urllib.error.HTTPError as e:
        try:
            body = e.read(10_000).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, body, headers
    except Exception as e:
        return 0, str(e), {}


def post_minimal(url: str, data: dict[str, str], timeout: int = 12) -> tuple[int, str]:
    """POST minimal form data → (status, body). For endpoint reachability probe only."""
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url,
        data=encoded,
        headers={
            "User-Agent": UA,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json, */*",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(5_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(5_000).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return 0, str(e)


# ── Detection steps ────────────────────────────────────────────────────────────

def detect_gf_version(html: str) -> str | None:
    """Extract Gravity Forms version from asset URL ver= params."""
    matches = GF_ASSET_VER_PATTERN.findall(html)
    if matches:
        # Return the first non-hash version string
        for m in matches:
            if re.match(r"^\d+\.\d+", m):
                return m
    return None


def version_is_affected(version: str) -> bool:
    """Return True if version <= 3.0.2."""
    try:
        parts = [int(x) for x in version.split(".")[:3]]
        affected = [3, 0, 2]
        return parts <= affected
    except ValueError:
        return False  # can't parse — be conservative


def parse_forms(html: str, url: str) -> list[FormFinding]:
    """Find Gravity Forms on a page and check for file upload fields."""
    findings: list[FormFinding] = []
    if not GF_FORM_PATTERN.search(html):
        return findings

    # Extract form IDs
    form_ids = list({
        m.group(1) or m.group(2)
        for m in GFORM_ID_PATTERN.finditer(html)
    })

    has_file = bool(GF_FILE_INPUT_PATTERN.search(html))
    has_multi = bool(GF_MULTI_PATTERN.search(html))
    nonce_match = GF_NONCE_PATTERN.search(html)
    nonce = nonce_match.group(1) if nonce_match else None

    findings.append(FormFinding(
        url=url,
        form_ids=form_ids,
        has_file_input=has_file,
        has_multi_upload=has_multi,
        nonce=nonce,
    ))
    return findings


def probe_upload_endpoint(base: str, timeout: int) -> tuple[int, str]:
    """
    Send a deliberately malformed minimal POST to the GF async upload endpoint.

    We send an empty/invalid payload. The goal is to confirm the endpoint
    is reachable and responds with a Gravity Forms JSON error — NOT to upload
    anything. A GF JSON error response proves the endpoint is live and
    unauthenticated.

    Expected responses:
      Vulnerable/exposed : 200 {"status":"error","error":"..."}
                           400 {"status":"error","error":"invalid_nonce"}
      Blocked/patched    : 403, 404, or non-JSON HTML
    """
    ajax_url = base.rstrip("/") + "/wp-admin/admin-ajax.php"
    status, body = post_minimal(
        ajax_url,
        {
            "action": "gf_upload_temp_file",
            # Deliberately missing nonce/form_id — we want the GF error,
            # not a successful upload
        },
        timeout=timeout,
    )
    return status, body


def check_rest_namespace(base: str, timeout: int) -> bool:
    """Check if /wp-json/ exposes the gf/v2 namespace (confirms GF installed)."""
    status, body, _ = get(base.rstrip("/") + "/wp-json/", timeout=timeout)
    if status in {200, 401} and "gf/v2" in body:
        return True
    return False


# ── Main scan ──────────────────────────────────────────────────────────────────

def scan(target: str, timeout: int, verbose: bool) -> ScanResult:
    result = ScanResult(target=target)
    base = target.rstrip("/")

    print(f"\n[CVE-2026-19513] Gravity Forms Unauthenticated File Upload Detector")
    print(f"Target  : {target}")
    print(f"Mode    : PASSIVE — no files uploaded, no writes to target server")
    print("-" * 65)

    # ── Step 1: Confirm Gravity Forms presence ─────────────────────────
    print("\n[1/4] Checking for Gravity Forms...")

    status, body, _ = get(base + "/", timeout=timeout)
    version = detect_gf_version(body)

    if version:
        result.gf_detected = True
        result.gf_version = version
        affected = version_is_affected(version)
        result.version_affected = affected
        result.evidence.append(f"Gravity Forms version {version} detected in asset URLs")
        print(f"  ✓ Gravity Forms v{version} detected in HTML asset URLs")
        print(f"  {'✗ AFFECTED version (<= 3.0.2)' if affected else '✓ Version appears patched (> 3.0.2)'}")
    elif GF_FORM_PATTERN.search(body) or "/gravityforms/" in body:
        result.gf_detected = True
        result.evidence.append("Gravity Forms detected (version not extractable from assets)")
        print("  ✓ Gravity Forms detected (version hidden in asset URLs)")
    else:
        print("  – Gravity Forms not detected in homepage HTML")

    # Check REST API namespace
    rest = check_rest_namespace(base, timeout)
    if rest:
        result.rest_api_exposed = True
        result.gf_detected = True
        result.evidence.append("gf/v2 REST namespace confirmed via /wp-json/")
        print("  ✓ gf/v2 REST namespace confirmed — Gravity Forms installed")

    if not result.gf_detected:
        print("\n  Gravity Forms not detected. Stopping scan.")
        result.verdict = "NOT_APPLICABLE"
        return result

    # ── Step 2: Find public forms with file upload fields ──────────────
    print(f"\n[2/4] Scanning {len(FORM_CANDIDATE_PATHS)} candidate pages for public file upload forms...")

    for path in FORM_CANDIDATE_PATHS:
        url = base + path
        status, html, _ = get(url, timeout=timeout)
        if status not in {200, 301, 302}:
            continue

        forms = parse_forms(html, url)
        for f in forms:
            result.forms_found.append(f)
            if f.has_file_input:
                result.public_file_upload_forms.append(f)
                multi = " + multi-file (chunked)" if f.has_multi_upload else ""
                print(f"  ✓ {path}  — GF form with file upload field{multi}  (form IDs: {f.form_ids})")
                result.evidence.append(
                    f"Public form with file upload at {url} "
                    f"(multi={f.has_multi_upload}, ids={f.form_ids})"
                )
            elif forms:
                if verbose:
                    print(f"  – {path}  — GF form (no file upload field)")

    if not result.public_file_upload_forms:
        print("  – No public Gravity Forms with file upload fields found in candidate pages")
        print("    (Forms may exist on other pages or require authentication to view)")

    # ── Step 3: Probe upload endpoint reachability ─────────────────────
    print(f"\n[3/4] Probing upload endpoint (no file sent)...")

    ep_status, ep_body = probe_upload_endpoint(base, timeout)
    result.upload_endpoint_status = ep_status
    result.upload_endpoint_response = ep_body[:200]

    # Interpret the response
    is_gf_response = False
    try:
        parsed: Any = json.loads(ep_body)
        # GF returns {"status":"error","error":"..."} or -1 (invalid nonce as plain text)
        if isinstance(parsed, dict) and ("error" in parsed or "status" in parsed):
            is_gf_response = True
    except (json.JSONDecodeError, ValueError):
        if ep_body.strip() in {"-1", "0"}:
            # WordPress AJAX no-priv returns -1 for unregistered/blocked actions
            is_gf_response = False
        elif "nonce" in ep_body.lower() or "invalid" in ep_body.lower():
            is_gf_response = True

    result.upload_endpoint_reachable = is_gf_response or ep_status == 200

    if is_gf_response:
        print(f"  ✓ Upload endpoint LIVE — responded with GF JSON  HTTP {ep_status}")
        print(f"    Response: {ep_body.strip()[:120]}")
        result.evidence.append(
            f"admin-ajax.php?action=gf_upload_temp_file responded with GF JSON "
            f"(HTTP {ep_status}) — endpoint reachable unauthenticated"
        )
    elif ep_status == 200 and ep_body.strip() == "-1":
        print(f"  – Endpoint returned -1 (action not registered or blocked)  HTTP {ep_status}")
        print(f"    This may indicate the upload action is restricted.")
    elif ep_status in {403, 404}:
        print(f"  – Upload endpoint blocked  HTTP {ep_status}")
        print(f"    Firewall/WAF or Kinsta may be blocking direct admin-ajax access.")
    else:
        print(f"  ? Endpoint response unclear  HTTP {ep_status}: {ep_body.strip()[:80]}")

    # ── Step 4: Version-based verdict ─────────────────────────────────
    print(f"\n[4/4] Determining verdict...")

    if not result.gf_detected:
        result.verdict = "NOT_APPLICABLE"
    elif result.version_affected is True and result.upload_endpoint_reachable:
        if result.public_file_upload_forms:
            result.verdict = "LIKELY_VULNERABLE"
        else:
            result.verdict = "POSSIBLY_VULNERABLE"
    elif result.version_affected is True and not result.upload_endpoint_reachable:
        result.verdict = "POSSIBLY_MITIGATED"
    elif result.version_affected is False:
        result.verdict = "PATCHED"
    elif result.version_affected is None:
        result.verdict = "INCONCLUSIVE"
    else:
        result.verdict = "INCONCLUSIVE"

    return result


# ── Output ─────────────────────────────────────────────────────────────────────

def print_result(result: ScanResult) -> None:
    verdict_icons = {
        "LIKELY_VULNERABLE":   "✗ LIKELY VULNERABLE",
        "POSSIBLY_VULNERABLE": "? POSSIBLY VULNERABLE",
        "POSSIBLY_MITIGATED":  "~ POSSIBLY MITIGATED",
        "PATCHED":             "✓ PATCHED",
        "NOT_APPLICABLE":      "– NOT APPLICABLE",
        "INCONCLUSIVE":        "? INCONCLUSIVE",
    }

    print("\n" + "=" * 65)
    print(f"VERDICT : {verdict_icons.get(result.verdict, result.verdict)}")
    print("=" * 65)

    if result.gf_version:
        print(f"\nGravity Forms version : {result.gf_version}")
        print(f"Affected range        : <= 3.0.2")
        print(f"Version is affected   : {result.version_affected}")

    if result.evidence:
        print("\nEvidence:")
        for e in result.evidence:
            print(f"  • {e}")

    if result.public_file_upload_forms:
        print(f"\nPublic file upload forms found: {len(result.public_file_upload_forms)}")
        for f in result.public_file_upload_forms:
            multi = "YES (chunked mode — directly exploitable)" if f.has_multi_upload else "NO (single-file — lower risk)"
            print(f"  URL   : {f.url}")
            print(f"  Multi : {multi}")
            print(f"  IDs   : {f.form_ids}")

    print(f"\nUpload endpoint status : HTTP {result.upload_endpoint_status}")
    print(f"Endpoint reachable     : {result.upload_endpoint_reachable}")

    if result.verdict == "LIKELY_VULNERABLE":
        print("""
Impact:
  An unauthenticated attacker can upload a file with an attacker-controlled
  filename to wp-content/uploads/gravity_forms/tmp/. If PHP execution is not
  blocked in that directory, this leads to Remote Code Execution.

Immediate actions:
  1. Upgrade Gravity Forms to >= 3.0.3
  2. Add to wp-content/uploads/.htaccess:
       <FilesMatch "\\.php$">
         Deny from all
       </FilesMatch>
  3. Disable multi-file upload on public forms until patched
""")
    elif result.verdict in {"PATCHED", "POSSIBLY_MITIGATED"}:
        print("\nNo immediate action required for this CVE.")
    elif result.verdict == "INCONCLUSIVE":
        print("\nManual verification recommended — version could not be confirmed.")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Passive detector for CVE-2026-19513 (Gravity Forms unauth file upload)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", default="https://royalgorgerafting.net",
                        help="Target WordPress base URL (default: https://royalgorgerafting.net)")
    parser.add_argument("--timeout", type=int, default=12, help="Per-request timeout in seconds")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all probe results")
    args = parser.parse_args()

    result = scan(args.target, args.timeout, args.verbose)
    print_result(result)

    return 0 if result.verdict in {"PATCHED", "NOT_APPLICABLE", "POSSIBLY_MITIGATED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
