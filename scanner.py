#!/usr/bin/env python3
"""
CORS Misconfiguration Scanner

Actively probes a web server's CORS policy with a battery of crafted
Origin headers - not just reading one response's headers, but asking
the specific questions that distinguish a correct allowlist from a
broken one: does it reflect any origin back? Does it trust Origin:
null? Does a naive string check accept "evilexample.com" as a
subdomain of "example.com"? Does it accept the plain-HTTP version of
an HTTPS-only trusted origin?

Only scan servers you own or are authorized to test.

Usage:
    python3 scanner.py https://api.example.com/some/endpoint
    python3 scanner.py https://api.example.com/endpoint --trusted-origin https://app.example.com
    python3 scanner.py https://api.example.com/endpoint --json report.json
"""

import sys
import json
import argparse

import requests

from probes import run_all_probes

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def print_report(url, findings):
    print(f"\n{url}")
    real_findings = [f for f in findings if f.severity != "INFO"]
    if not real_findings:
        print("  No CORS misconfigurations found by this probe battery.")
    for f in sorted(real_findings, key=lambda f: -SEVERITY_RANK[f.severity]):
        print(f"\n  [{f.severity}] {f.probe_name}")
        print(f"      {f.message}")
        if f.origin_sent:
            print(f"      Origin sent: {f.origin_sent}")
        if f.acao_received is not None:
            print(f"      Access-Control-Allow-Origin received: {f.acao_received}")
        if f.acac_received:
            print(f"      Access-Control-Allow-Credentials received: {f.acac_received}")

    info_findings = [f for f in findings if f.severity == "INFO"]
    for f in info_findings:
        print(f"\n  [INFO] {f.probe_name}: {f.message}")


def main():
    parser = argparse.ArgumentParser(description="Actively probe a server's CORS configuration for common misconfigurations.")
    parser.add_argument("url", help="Target URL to probe (any endpoint that sets CORS headers)")
    parser.add_argument("--trusted-origin", help="The site's real expected origin, e.g. https://app.example.com - enables scheme-downgrade and substring-match bypass probes")
    parser.add_argument("--timeout", type=float, default=10, help="Per-request timeout in seconds")
    parser.add_argument("--json", metavar="FILE", help="Also write a JSON report to FILE")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "any", "none"], default="high",
                         help="Minimum severity that causes a non-zero exit code (default: high)")
    args = parser.parse_args()

    try:
        findings = run_all_probes(args.url, trusted_origin_hint=args.trusted_origin, timeout=args.timeout)
    except requests.RequestException as e:
        print(f"Error: could not reach {args.url}: {e}", file=sys.stderr)
        sys.exit(2)

    print_report(args.url, findings)

    if args.json:
        with open(args.json, "w") as f:
            json.dump([{
                "severity": fd.severity, "probe": fd.probe_name, "message": fd.message,
                "origin_sent": fd.origin_sent, "acao_received": fd.acao_received, "acac_received": fd.acac_received,
            } for fd in findings], f, indent=2)
        print(f"\nJSON report written to {args.json}")

    real_findings = [f for f in findings if f.severity != "INFO"]
    if args.fail_on == "none":
        sys.exit(0)
    if args.fail_on == "any":
        sys.exit(1 if real_findings else 0)
    threshold = SEVERITY_RANK[args.fail_on.upper()]
    worst = max((SEVERITY_RANK[f.severity] for f in real_findings), default=0)
    sys.exit(1 if worst >= threshold else 0)


if __name__ == "__main__":
    main()
