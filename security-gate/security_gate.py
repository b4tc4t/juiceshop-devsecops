
#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

SEVERITIES = ["critical", "high", "moderate", "low", "info"]


def load_report(report_path):
    """Load an npm audit JSON report."""
    path = Path(report_path)

    if not path.is_file():
        raise FileNotFoundError(f"Report not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def evaluate_report(report, max_critical, max_high):
    """Evaluate vulnerability counts against security thresholds."""

    metadata = report.get("metadata", {})
    vulnerabilities = metadata.get("vulnerabilities")

    if not isinstance(vulnerabilities, dict):
        raise ValueError(
            "Invalid npm audit report: vulnerability metadata missing."
        )

    counts = {}

    for severity in SEVERITIES:
        value = vulnerabilities.get(severity, 0)

        if not isinstance(value, int) or value < 0:
            raise ValueError(f"Invalid count for severity: {severity}")

        counts[severity] = value

    blocking = []

    if counts["critical"] > max_critical:
        blocking.append("Critical")

    if counts["high"] > max_high:
        blocking.append("High")

    return counts, blocking


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate npm audit findings against security thresholds."
    )

    parser.add_argument(
        "--report",
        required=True,
        help="Path to npm audit JSON report"
    )

    parser.add_argument(
        "--max-critical",
        type=int,
        default=0,
        help="Maximum allowed Critical vulnerabilities (default: 0)"
    )

    parser.add_argument(
        "--max-high",
        type=int,
        default=0,
        help="Maximum allowed High vulnerabilities (default: 0)"
    )

    args = parser.parse_args()

    if args.max_critical < 0 or args.max_high < 0:
        parser.error("Thresholds cannot be negative.")

    try:
        report = load_report(args.report)

        counts, blocking = evaluate_report(
            report,
            args.max_critical,
            args.max_high
        )

        print("\n========== SECURITY GATE REPORT ==========\n")

        for severity in SEVERITIES:
            print(f"{severity.capitalize():<12}: {counts[severity]}")

        print("\n------------------------------------------")

        if blocking:
            print("RESULT: FAILED")
            print("Blocking severity: " + ", ".join(blocking))
            print("Build must be stopped.")
            return 1

        print("RESULT: PASSED")
        print("No vulnerabilities exceeded configured thresholds.")
        return 0

    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
