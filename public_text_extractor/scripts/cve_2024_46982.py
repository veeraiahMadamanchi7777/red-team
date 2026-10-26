#!/usr/bin/env python3
"""
CVE-2024-46982 — Next.js Cache Poisoning via Crafted HTTP Request
=================================================================

CVE ID      : CVE-2024-46982
GHSA        : GHSA-gp8f-8m3g-qvj9
CVSS Score  : 7.5 (HIGH)
CVSS Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N
Affected    : Next.js < 14.2.10, < 13.5.7
Patched     : 14.2.10, 13.5.7
Published   : 2024-09-17

Description
-----------
Next.js's built-in cache (used by the App Router's `fetch()` with default
revalidation) could be poisoned by crafting a specific sequence of HTTP
requests. An attacker who can send requests to the Next.js server before a
legitimate user can cause the cache to store a malicious or incorrect response,
which is then served to subsequent users.

This affects the server-side fetch cache, not the HTTP response cache at the
CDN layer. The vulnerability is in how Next.js processes cache keys when
incoming requests contain certain headers or body content that influences
which cached response is returned.

Attack Surface
--------------
- Applications using Next.js App Router with cached `fetch()` calls (default
  or explicit `{ cache: 'force-cache' }`)
- Self-hosted Next.js deployments (not Vercel, which patched this server-side)
- The attacker needs the ability to send HTTP requests to the origin server

Test Methodology
---------------
1. Fetch a cacheable page/endpoint twice with identical parameters → expect
   same response (establishes baseline).
2. Send a crafted request with a header that may act as an undocumented cache
   key (e.g., x-invoke-path, x-nextjs-data, x-matched-path).
3. Fetch the original URL again without the special header → check if the
   response changed unexpectedly.

Note: Full exploitation requires knowing the exact cache key manipulation
vector, which depends on Next.js internals. This script performs a
passive detection by checking version signals and cache-related headers.

Remediation
-----------
Upgrade Next.js to >= 14.2.10.
If upgrade is not possible, disable server-side fetch caching by using
`{ cache: 'no-store' }` on sensitive fetch calls.

References
----------
- https://github.com/advisories/GHSA-gp8f-8m3g-qvj9
- https://nvd.nist.gov/vuln/detail/CVE-2024-46982
"""

from __future__ import annotations

import argparse
import urllib.error
import urllib.request

CACHE_PROBE_HEADERS = [
    "x-invoke-path",
    "x-nextjs-data",
    "x-matched-path",
    "x-middleware-invoke",
]


def fetch(url: str, headers: dict[str, str] | None = None, timeout: int = 10) -> tuple[int, dict[str, str]]:
    h = {"User-Agent": "NextJS-CVE-Tester/1.0", "Accept": "text/html,application/json,*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_headers
    except urllib.error.HTTPError as exc:
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, resp_headers
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc)) from exc


def detect_nextjs_version(target: str, timeout: int) -> str | None:
    """Attempt to read Next.js version from /_next/static headers or HTML."""
    try:
        _, headers = fetch(target, timeout=timeout)
        # Next.js sometimes exposes version in X-Powered-By
        xpb = headers.get("x-powered-by", "")
        if "Next.js" in xpb:
            parts = xpb.split("/")
            if len(parts) == 2:
                return parts[1].strip()
    except ConnectionError:
        pass
    return None


def version_before(ver: str | None, cutoff: tuple[int, int, int]) -> bool | None:
    if not ver:
        return None
    try:
        parts = tuple(int(x) for x in ver.split(".")[:3])
        return parts < cutoff
    except ValueError:
        return None


def run(target: str, timeout: int, verbose: bool) -> int:
    print(f"\n[CVE-2024-46982] Next.js Cache Poisoning")
    print(f"Target : {target}")
    print("-" * 60)

    version = detect_nextjs_version(target, timeout)
    if verbose:
        print(f"  Detected version: {version or 'unknown'}")

    vuln = version_before(version, (14, 2, 10))

    # Also check if cache-control headers suggest server-side caching is active
    try:
        _, headers = fetch(target, timeout=timeout)
        cache_header = headers.get("x-nextjs-cache", headers.get("cache-control", ""))
        if verbose:
            print(f"  Cache-Control: {cache_header or '(not present)'}")
            print(f"  x-nextjs-cache: {headers.get('x-nextjs-cache', '(not present)')}")
    except ConnectionError as exc:
        print(f"  Connection error: {exc}")
        print("\nVERDICT : INCONCLUSIVE (connection failed)")
        return 2

    print()
    if vuln is True:
        print("VERDICT : LIKELY VULNERABLE")
        print(f"\nDetected Next.js {version} which is < 14.2.10 (patched version).")
        print("Cache poisoning may be possible if App Router server-side fetch caching is in use.")
        print("Fix: Upgrade Next.js to >= 14.2.10")
        return 1
    elif vuln is False:
        print("VERDICT : PATCHED")
        print(f"\nDetected Next.js {version} which is >= 14.2.10.")
        return 0
    else:
        print("VERDICT : INCONCLUSIVE")
        print("\nCould not determine Next.js version from response headers.")
        print("Manual inspection required: check package.json or /_next/static/ chunk filenames.")
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Test CVE-2024-46982 Next.js cache poisoning")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    return run(args.target, args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
