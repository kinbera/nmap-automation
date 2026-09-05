"""Renders comparison findings between two scans as a terminal report."""
import sys
from collections import Counter

from netscan.models import ScanResult
from netscan.rules.base import Finding

SEVERITY_ORDER = ("high", "medium", "low")
SEVERITY_COLOR = {
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
}
BOLD = "\033[1m"
RESET = "\033[0m"


def _colors_enabled() -> bool:
    return sys.stdout.isatty()


def _severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)


def render(findings: list[Finding], baseline: ScanResult, current: ScanResult) -> None:
    use_color = _colors_enabled()
    bold = BOLD if use_color else ""
    reset = RESET if use_color else ""

    print(f"{bold}== Compare: {current.target} =={reset}")
    print(f"  Baseline: {baseline.timestamp}")
    print(f"  Current:  {current.timestamp}")

    if not findings:
        print("\n  No differences found.\n")
        return

    by_severity = Counter(f.severity for f in findings)
    print(f"\n{bold}Summary{reset}")
    print(f"  Total findings: {len(findings)}")
    for severity in SEVERITY_ORDER:
        if by_severity[severity]:
            color = SEVERITY_COLOR.get(severity, "") if use_color else ""
            print(f"  {color}{severity.upper():<7}{reset} {by_severity[severity]}")

    print(f"\n{bold}Findings{reset}")
    for finding in sorted(findings, key=lambda f: (_severity_rank(f.severity), f.host, f.port or 0)):
        color = SEVERITY_COLOR.get(finding.severity, "") if use_color else ""
        print(f"  [{color}{finding.severity.upper():<6}{reset}] {finding.rule:<20} {finding.message}")
    print()
