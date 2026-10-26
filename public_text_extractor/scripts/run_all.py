#!/usr/bin/env python3
"""
CVE Test Runner
===============

Runs all CVE test scripts against a target and produces a consolidated
summary report.

Usage:
    python3 scripts/run_all.py --target http://localhost:3000
    python3 scripts/run_all.py --target https://example.com --verbose
    python3 scripts/run_all.py --target http://localhost:3000 --cve CVE-2025-29927

CVEs covered (Next.js):
    CVE-2025-29927  CRITICAL 9.1  Middleware auth bypass (x-middleware-subrequest)
    CVE-2024-46982  HIGH     7.5  Cache poisoning via crafted request
    CVE-2024-51479  HIGH     7.5  Auth bypass — Pages Router i18n middleware
    CVE-2024-47831  MEDIUM   5.9  DoS — image optimizer unbounded processing
    CVE-2024-56332  MEDIUM   5.3  Unauthorized Server Actions invocation
    CVE-2025-57822  MEDIUM   6.5  SSRF via middleware redirect
    CVE-2025-32421  LOW      3.7  Info disclosure — dev mode exposed
    CVE-2025-48068  MEDIUM   4.3  Sensitive data in RSC flight payload
    CVE-2025-57752  MEDIUM   6.2  Response pollution / header injection
    CVE-2025-55173  MEDIUM   4.3  Info disclosure via error responses

CVEs covered (WordPress / Gravity Forms):
    CVE-2026-19513  HIGH     8.1  Gravity Forms unauth arbitrary file upload → RCE
"""

from __future__ import annotations

import argparse
import importlib
import sys
import time
import traceback
from pathlib import Path
from typing import Any

# Ensure the scripts directory is importable regardless of where the runner is
# called from.
SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))

CVE_MODULES = [
    {
        "id": "CVE-2025-29927",
        "module": "cve_2025_29927",
        "cvss": 9.1,
        "severity": "CRITICAL",
        "summary": "Middleware auth bypass via x-middleware-subrequest header",
        "patched": "14.2.25",
    },
    {
        "id": "CVE-2024-46982",
        "module": "cve_2024_46982",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "Cache poisoning via crafted HTTP request",
        "patched": "14.2.10",
    },
    {
        "id": "CVE-2024-51479",
        "module": "cve_2024_51479",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "Auth bypass — Pages Router i18n middleware",
        "patched": "14.2.15",
    },
    {
        "id": "CVE-2024-47831",
        "module": "cve_2024_47831",
        "cvss": 5.9,
        "severity": "MEDIUM",
        "summary": "DoS — image optimizer unbounded processing",
        "patched": "14.2.7",
    },
    {
        "id": "CVE-2024-56332",
        "module": "cve_2024_56332",
        "cvss": 5.3,
        "severity": "MEDIUM",
        "summary": "Unauthorized Server Actions invocation",
        "patched": "14.2.21",
    },
    {
        "id": "CVE-2025-57822",
        "module": "cve_2025_57822",
        "cvss": 6.5,
        "severity": "MEDIUM",
        "summary": "SSRF via middleware redirect",
        "patched": "14.2.32",
    },
    {
        "id": "CVE-2025-32421",
        "module": "cve_2025_32421",
        "cvss": 3.7,
        "severity": "LOW",
        "summary": "Info disclosure — development mode accidentally exposed",
        "patched": "14.2.24",
    },
    {
        "id": "CVE-2025-48068",
        "module": "cve_2025_48068",
        "cvss": 4.3,
        "severity": "MEDIUM",
        "summary": "Sensitive data exposure via RSC flight payload",
        "patched": "14.2.30",
    },
    {
        "id": "CVE-2025-57752",
        "module": "cve_2025_57752",
        "cvss": 6.2,
        "severity": "MEDIUM",
        "summary": "Response pollution / CRLF header injection",
        "patched": "14.2.31",
    },
    {
        "id": "CVE-2025-55173",
        "module": "cve_2025_55173",
        "cvss": 4.3,
        "severity": "MEDIUM",
        "summary": "Info disclosure via error response details",
        "patched": "14.2.31",
    },
    {
        "id": "CVE-2026-19513",
        "module": "cve_2026_19513",
        "cvss": 8.1,
        "severity": "HIGH",
        "summary": "Gravity Forms unauth arbitrary file upload → RCE (WordPress)",
        "patched": "3.0.3",
    },
]

VERDICT_LABEL = {0: "PATCHED", 1: "VULNERABLE", 2: "INCONCLUSIVE"}
VERDICT_SYMBOL = {0: "✓", 1: "✗", 2: "?"}


def severity_order(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 4)


def run_cve(entry: dict[str, Any], target: str, timeout: int, verbose: bool) -> dict[str, Any]:
    start = time.monotonic()
    try:
        mod = importlib.import_module(entry["module"])
        exit_code = mod.run(target, timeout, verbose)
    except Exception as exc:
        exit_code = 2
        if verbose:
            traceback.print_exc()
        else:
            print(f"  [ERROR] {exc}")
    elapsed = time.monotonic() - start
    return {
        **entry,
        "exit_code": exit_code,
        "verdict": VERDICT_LABEL.get(exit_code, "ERROR"),
        "elapsed": elapsed,
    }


def print_summary(results: list[dict[str, Any]]) -> None:
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"{'CVE ID':<20} {'SEV':<9} {'CVSS':<6} {'VERDICT':<15} {'TIME':>6}  SUMMARY")
    print("-" * 72)

    for r in sorted(results, key=lambda x: (severity_order(x["severity"]), x["id"])):
        sym = VERDICT_SYMBOL.get(r["exit_code"], "!")
        verdict_str = f"{sym} {r['verdict']}"
        print(f"{r['id']:<20} {r['severity']:<9} {r['cvss']:<6.1f} {verdict_str:<15} {r['elapsed']:>5.1f}s  {r['summary']}")

    print("-" * 72)
    vulnerable = [r for r in results if r["exit_code"] == 1]
    patched = [r for r in results if r["exit_code"] == 0]
    inconclusive = [r for r in results if r["exit_code"] == 2]

    print(f"\nVULNERABLE   : {len(vulnerable)}")
    print(f"PATCHED      : {len(patched)}")
    print(f"INCONCLUSIVE : {len(inconclusive)}")

    if vulnerable:
        print()
        print("URGENT ACTIONS:")
        for r in sorted(vulnerable, key=lambda x: severity_order(x["severity"])):
            print(f"  [{r['severity']:8}] {r['id']}  →  upgrade to Next.js >= {r['patched']}")

    print()
    if vulnerable:
        critical = [r for r in vulnerable if r["severity"] == "CRITICAL"]
        if critical:
            print("OVERALL RISK: CRITICAL — Immediate action required")
        else:
            print("OVERALL RISK: HIGH — Remediation recommended promptly")
    elif inconclusive and not patched:
        print("OVERALL RISK: UNKNOWN — All tests inconclusive, manual review required")
    else:
        print("OVERALL RISK: LOW — No confirmed vulnerabilities (verify inconclusive items)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run all Next.js CVE tests against a target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--target", default="http://localhost:3000",
                        help="Base URL of the Next.js application (default: http://localhost:3000)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show all probe results, not just verdicts")
    parser.add_argument("--cve", metavar="CVE-XXXX-XXXXX",
                        help="Run only the specified CVE test (e.g. CVE-2025-29927)")
    args = parser.parse_args()

    to_run = CVE_MODULES
    if args.cve:
        to_run = [e for e in CVE_MODULES if e["id"].upper() == args.cve.upper()]
        if not to_run:
            print(f"Unknown CVE: {args.cve}", file=sys.stderr)
            print("Available:", ", ".join(e["id"] for e in CVE_MODULES), file=sys.stderr)
            return 1

    print(f"Next.js CVE Scanner")
    print(f"Target  : {args.target}")
    print(f"Testing : {len(to_run)} CVE(s)")
    print(f"Timeout : {args.timeout}s per request")

    results = []
    for entry in to_run:
        result = run_cve(entry, args.target, args.timeout, args.verbose)
        results.append(result)

    print_summary(results)

    # Exit 1 if any vulnerabilities confirmed
    return 1 if any(r["exit_code"] == 1 for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
