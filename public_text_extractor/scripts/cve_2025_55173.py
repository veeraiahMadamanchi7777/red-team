#!/usr/bin/env python3
"""
CVE-2025-55173 — Next.js Information Disclosure via Error Responses
===================================================================

CVE ID      : CVE-2025-55173
GHSA        : GHSA-7hqr-r82j-3w29 (placeholder — verify at time of use)
CVSS Score  : 4.3 (MEDIUM)
CVSS Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N
Affected    : Next.js >= 13.0.0, < 14.2.31
Patched     : 14.2.31
Published   : 2025-06 (est.)

Description
-----------
In affected versions, Next.js may include internal implementation details in
error responses sent to clients in certain conditions — even in production
builds. This can include:
  - Stack traces referencing internal Node.js module paths
  - Internal Next.js configuration values
  - Server-side environment variable names (not values) in error output
  - Internal request routing metadata in 500 responses

These disclosures reduce the effort required for targeted attacks by revealing
the application's internal structure.

Attack Surface
--------------
- Any publicly accessible Next.js application
- Paths that trigger 500 errors (malformed RSC requests, invalid API inputs)
- The `/_next/` prefix with malformed sub-paths

Test Methodology
---------------
1. Trigger 4xx/5xx error responses via malformed requests.
2. Check response bodies for internal path disclosures, stack traces,
   environment variable names, or Next.js internal metadata.
3. Probe paths known to trigger Next.js internal error handling.

Remediation
-----------
Upgrade Next.js to >= 14.2.31.
Additionally, configure a custom error page (app/error.tsx or pages/_error.js)
that does not leak internal details.

References
----------
- https://nvd.nist.gov/vuln/detail/CVE-2025-55173
"""

from __future__ import annotations

import argparse
import re
import urllib.error
import urllib.request

ERROR_TRIGGER_PATHS = [
    "/_next/image",                         # Missing required params → error
    "/_next/data/BUILD_ID/[invalid].json",  # Invalid build ID
    "/api/__nextjs_original-stack-frame",   # Internal dev tool probed in prod
    "/__nextjs_error",                      # Error boundary test
    "/[...catchall]/[malformed",            # Malformed dynamic route
]

DISCLOSURE_PATTERNS = [
    (r"at\s+\w+\s+\(/.+?\.js:\d+:\d+\)", "Stack trace with file paths"),
    (r"/\.next/server/", "Server build directory path"),
    (r"node_modules/next/dist/", "Next.js internal module path"),
    (r"process\.env\.\w+", "Environment variable name in error"),
    (r"NEXT_PUBLIC_\w+", "Public env var name disclosed"),
    (r'"nextConfig":\s*\{', "Next.js config object in response"),
    (r'"buildId":\s*"[^"]+"', "Build ID disclosed in error"),
    (r"Error: Cannot find module", "Module resolution error"),
    (r"SyntaxError:", "Syntax error details"),
    (r"TypeError:", "Type error details"),
]


def fetch(url: str, headers: dict[str, str] | None = None, timeout: int = 10) -> tuple[int, str]:
    h = {"User-Agent": "NextJS-CVE-Tester/1.0", "Accept": "text/html,application/json,*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(32768).decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read(8192).decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc)) from exc


def run(target: str, timeout: int, verbose: bool) -> int:
    print(f"\n[CVE-2025-55173] Next.js Information Disclosure via Errors")
    print(f"Target : {target}")
    print("-" * 60)

    findings: list[tuple[str, int, str, str]] = []

    for path in ERROR_TRIGGER_PATHS:
        url = target.rstrip("/") + path
        try:
            status, body = fetch(url, timeout=timeout)
        except ConnectionError as exc:
            if verbose:
                print(f"  {path}: connection error ({exc})")
            continue

        if verbose:
            print(f"  {path}: status={status}")

        for pattern, description in DISCLOSURE_PATTERNS:
            matches = re.findall(pattern, body)
            for match in matches[:2]:  # Limit to first 2 matches per pattern per path
                findings.append((path, status, description, match[:100]))

    print()
    if findings:
        print("VERDICT : LIKELY VULNERABLE — Internal details disclosed in error responses")
        print()
        print("Disclosures found:")
        seen = set()
        for path, status, description, match in findings:
            key = (path, description)
            if key in seen:
                continue
            seen.add(key)
            print(f"  Path : {path} (HTTP {status})")
            print(f"  Type : {description}")
            print(f"  Match: {match!r}")
            print()
        print("Fix: Upgrade Next.js to >= 14.2.31")
        return 1
    else:
        print("VERDICT : NO DISCLOSURES DETECTED")
        print()
        print("Error responses did not contain internal implementation details.")
        print("Either patched or error pages are properly sanitized.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Test CVE-2025-55173 Next.js error disclosure")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    return run(args.target, args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
