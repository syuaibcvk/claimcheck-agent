#!/usr/bin/env python3
"""
ClaimCheck demo — runs the agent against local fixtures (no network)
and prints example reports.

Usage: python3 demo.py
"""

import json

import app

CLEAN_ANNOUNCEMENT = """Official claim announcement — Example Protocol.
The claim window opens on November 30, 2026. Connect your wallet on our
official website to check eligibility. We will never ask for your seed
phrase or private key. Contract: 0x4Fe7E22267bFc3fB5113C42Ea9E93265Dc8F1C03
"""


def summarise(report):
    lines = [
        f"risk_level : {report['risk_level']}",
        f"report id  : {report['id']}",
        f"sha256     : {report['evidence_sha256']}",
        f"addresses  : {report['extracted']['evm_addresses']}",
        f"dates      : {report['extracted']['dates']}",
        "findings   :",
    ]
    if report["findings"]:
        for finding in report["findings"]:
            lines.append(
                f"  - [{finding['severity']}] {finding['rule']}: "
                f"{finding['evidence']}"
            )
    else:
        lines.append("  (none)")
    return "\n".join(lines)


def main():
    print("=" * 72)
    print("DEMO 1 — built-in scam fixture (same as GET /demo)")
    print("=" * 72)
    scam_report = app.analyze(
        app.DEMO_HTML.encode("utf-8"), "demo", "built-in fixture")
    print(summarise(scam_report))

    print()
    print("=" * 72)
    print("DEMO 2 — a clean announcement (text mode)")
    print("=" * 72)
    clean_report = app.analyze_text(CLEAN_ANNOUNCEMENT)
    print(summarise(clean_report))

    print()
    print("Full JSON of demo 1:")
    print(json.dumps(scam_report, indent=2))
    print()
    print("To serve the agent over HTTP:  python3 app.py   "
          "(then open http://localhost:8000/)")


if __name__ == "__main__":
    main()
