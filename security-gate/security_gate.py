
import argparse
import json
import sys
from pathlib import Path


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read {path}: {exc}")


def add_count(summary, severity, count=1):
    severity = severity.lower()

    if severity not in summary:
        severity = "info"

    summary[severity] += count


def scan_npm_audit(path, summary):
    report = load_json(path)

    vulnerabilities = (
        report.get("metadata", {}).get("vulnerabilities")
    )

    if not isinstance(vulnerabilities, dict):
        raise ValueError("Invalid npm audit vulnerability metadata")

    for severity in ("critical", "high", "moderate", "low", "info"):
        add_count(
            summary,
            severity,
            int(vulnerabilities.get(severity, 0))
        )


def scan_semgrep(path, summary):
    report = load_json(path)
    results = report.get("results")

    if not isinstance(results, list):
        raise ValueError("Invalid Semgrep report: missing results")

    severity_map = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low"
    }

    for finding in results:
        severity = (
            finding.get("extra", {}).get("severity", "INFO")
        ).upper()

        add_count(summary, severity_map.get(severity, "info"))


def scan_zap(path, summary):
    report = load_json(path)
    sites = report.get("site")

    if not isinstance(sites, list):
        raise ValueError("Invalid ZAP report: missing site data")

    risk_map = {
        "3": "high",
        "2": "medium",
        "1": "low",
        "0": "info"
    }

    for site in sites:
        for alert in site.get("alerts", []):
            riskcode = alert.get("riskcode")

            if riskcode is not None:
                severity = risk_map.get(str(riskcode), "info")
            else:
                riskdesc = alert.get("riskdesc", "Informational")
                severity = riskdesc.split("(")[0].strip().lower()

            try:
                count = int(alert.get("count", 1))
            except (TypeError, ValueError):
                count = 1

            add_count(summary, severity, max(count, 1))


def main():
    parser = argparse.ArgumentParser(
        description="Centralized DevSecOps security gate"
    )

    parser.add_argument("--npm-audit", required=True)
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--zap-baseline", required=True)
    parser.add_argument("--zap-full")

    parser.add_argument("--max-critical", type=int, default=0)
    parser.add_argument("--max-high", type=int, default=0)

    args = parser.parse_args()

    reports = {
        "npm audit": args.npm_audit,
        "Semgrep": args.semgrep,
        "ZAP Baseline": args.zap_baseline
    }

    if args.zap_full:
        reports["ZAP Full Scan"] = args.zap_full

    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    print("\n========== DEVSECOPS SECURITY GATE ==========\n")

    try:
        for scanner, path in reports.items():
            if not Path(path).is_file():
                raise ValueError(f"{scanner} report not found: {path}")

        scan_npm_audit(args.npm_audit, summary)
        scan_semgrep(args.semgrep, summary)
        scan_zap(args.zap_baseline, summary)

        if args.zap_full:
            scan_zap(args.zap_full, summary)

    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 2

    print("Vulnerability summary:")

    for severity, count in summary.items():
        print(f"{severity.upper():12}: {count}")

    print("\nSecurity policy:")
    print(f"Maximum Critical: {args.max_critical}")
    print(f"Maximum High:     {args.max_high}")

    failed = (
        summary["critical"] > args.max_critical
        or summary["high"] > args.max_high
    )

    print("\n============================================")

    if failed:
        print("SECURITY GATE: FAILED")
        print("Build blocked due to policy violations.")
        return 1

    print("SECURITY GATE: PASSED")
    print("No Critical or High findings exceeded the thresholds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
