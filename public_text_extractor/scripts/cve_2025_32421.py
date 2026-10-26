#!/usr/bin/env python3
"""
CVE-2025-32421 — Next.js Information Disclosure in Development Mode
===================================================================

CVE ID      : CVE-2025-32421
GHSA        : GHSA-99x8-fmxh-q2jq
CVSS Score  : 3.7 (LOW)
CVSS Vector : CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
Affected    : Next.js >= 9.5.5, < 14.2.24 (development mode only)
Patched     : 14.2.24
Published   : 2025-04 (est.)

Description
-----------
When Next.js is running in development mode (`next dev`), certain internal
endpoints and debug information may be exposed that reveal:
  - File system paths and project structure
  - Source maps with original source code
  - Environment variable names (not values) in error messages
  - Internal webpack/Turbopack compilation metadata
  - React component stack traces with file paths

This information is not intended to be accessible from external connections
in development mode, but the development server may listen on 0.0.0.0
rather than 127.0.0.1, making it reachable on the local network or internet
if the developer's machine is exposed.

Attack Surface
--------------
- Next.js dev servers (`next dev`) accidentally exposed to the internet
- Misconfigured cloud development environments (e.g., GitHub Codespaces,
  Gitpod, AWS Cloud9) where the preview port is publicly accessible
- CI/CD pipelines that run `next dev` in review environments

Test Methodology
---------------
1. Check for development mode indicators in responses.
2. Probe internal development endpoints: /__nextjs_original-stack-frame,
   /_next/development-error, /[invalid-path] (dev 404 shows source).
3. Check if source maps (*.js.map) are accessible.
4. Report any development mode signals found.

Note: Production Next.js builds should never expose these endpoints.
Finding them indicates a development server is accidentally public-facing.

Remediation
-----------
Upgrade Next.js to >= 14.2.24.
More importantly: never expose `next dev` servers to the public internet.
Use `next start` (production build) for any public-facing environment.
Bind the dev server to 127.0.0.1: `next dev --hostname 127.0.0.1`

References
----------
- https://github.com/advisories/GHSA-99x8-fmxh-q2jq
- https://nvd.nist.gov/vuln/detail/CVE-2025-32421
"""

from __future__ import annotations

import argparse
import re
import urllib.error
import urllib.request

DEV_ENDPOINTS = [
    "/__nextjs_original-stack-frame",
    "/__nextjs_launch-editor",
    "/_next/development-error",
    "/[invalid-page-that-does-not-exist-abc123]",
]

DEV_SIGNALS = [
    ("next dev", "development server banner"),
    ("Fast Refresh", "HMR/Fast Refresh active"),
    ("webpack-dev-server", "webpack dev server"),
    ("__webpack_hmr", "webpack HMR endpoint"),
    ("_next/webpack-hmr", "Next.js HMR"),
    ("next/dist/client/dev/", "dev client bundle"),
    (".next/server/", "server build path in error"),
    ("pages/_error", "dev error page source ref"),
]


def fetch(url: str, timeout: int = 10) -> tuple[int, str, dict]:
    headers = {"User-Agent": "NextJS-CVE-Tester/1.0", "Accept": "text/html,application/json,*/*"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(16384).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, resp_headers
    except urllib.error.HTTPError as exc:
        body = exc.read(4096).decode("utf-8", errors="replace") if exc.fp else ""
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, body, resp_headers
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc)) from exc


def run(target: str, timeout: int, verbose: bool) -> int:
    print(f"\n[CVE-2025-32421] Next.js Dev Mode Information Disclosure")
    print(f"Target : {target}")
    print("-" * 60)

    dev_signals_found: list[str] = []

    # Check homepage for dev signals
    try:
        status, body, headers = fetch(target, timeout=timeout)
    except ConnectionError as exc:
        print(f"  Connection error: {exc}")
        print("\nVERDICT : INCONCLUSIVE")
        return 2

    for signal, description in DEV_SIGNALS:
        if signal in body:
            dev_signals_found.append(f"Homepage: {description} ({signal!r})")

    # Check development-specific endpoints
    accessible_dev_endpoints: list[tuple[str, int]] = []
    for path in DEV_ENDPOINTS:
        try:
            ep_status, ep_body, _ = fetch(target.rstrip("/") + path, timeout=timeout)
        except ConnectionError:
            continue
        if ep_status != 404:
            accessible_dev_endpoints.append((path, ep_status))
            if verbose:
                print(f"  {path}  status={ep_status}")
            # Check body for filesystem paths
            paths_in_body = re.findall(r'["\'](?:/[a-zA-Z0-9._/-]+\.(?:ts|tsx|js|jsx))["\']', ep_body)
            if paths_in_body:
                dev_signals_found.append(f"File paths in {path}: {paths_in_body[:3]}")

    # Check for source maps
    map_status = None
    try:
        ep_status, _, _ = fetch(target.rstrip("/") + "/_next/static/chunks/main.js.map", timeout=timeout)
        map_status = ep_status
        if ep_status == 200:
            dev_signals_found.append("Source map accessible: /_next/static/chunks/main.js.map")
    except ConnectionError:
        pass

    print()
    if dev_signals_found:
        print("VERDICT : LIKELY VULNERABLE (development mode exposed)")
        print()
        print("Development mode signals detected:")
        for s in dev_signals_found:
            print(f"  - {s}")
        print()
        print("Accessible dev endpoints:")
        for path, ep_status in accessible_dev_endpoints:
            print(f"  {path}  ({ep_status})")
        print()
        print("Fix: Upgrade to >= 14.2.24 AND ensure production mode is used for public deployments.")
        print("     Run 'next build && next start' instead of 'next dev'.")
        return 1
    else:
        print("VERDICT : NOT VULNERABLE (no dev mode signals found)")
        print()
        print("No development mode indicators detected. Target appears to be a production build.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Test CVE-2025-32421 Next.js dev mode disclosure")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    return run(args.target, args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
