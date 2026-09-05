"""nmap automation CLI: run a scan, save the result, and show a terminal report."""
import argparse
import os

from intel.storage.ioc_store import init_db as init_threat_intel_db

from netscan.dashboard.cli_diff import render as render_diff
from netscan.dashboard.cli_report import render
from netscan.parsers.nmap_parser import parse_string
from netscan.rules.new_open_port import NewOpenPortRule
from netscan.rules.new_service_version import NewServiceVersionRule
from netscan.runner.nmap_runner import run_scan
from netscan.storage.scan_store import list_scans, load_scan, save_scan

DEFAULT_SCAN_DIR = "scans"


def cmd_scan(args):
    xml_text = run_scan(args.target, ports=args.ports, nmap_path=args.nmap_path)
    result = parse_string(xml_text)
    path = save_scan(result, base_dir=args.out)
    print(f"Saved scan to {path}")
    render(result)


def cmd_compare(args):
    paths = list_scans(args.target, base_dir=args.dir)
    if len(paths) < 2:
        print(f"Need at least 2 saved scans for {args.target!r} to compare (found {len(paths)}).")
        return

    baseline = load_scan(paths[-2])
    current = load_scan(paths[-1])

    # Only touch the threat-intel store if the integration is actually
    # configured — otherwise this would silently create an empty data/iocs.db
    # in whatever directory the CLI happens to run from.
    threat_intel_conn = init_threat_intel_db() if os.environ.get("THREAT_INTEL_DB") else None
    try:
        rules = [NewOpenPortRule(threat_intel_conn=threat_intel_conn), NewServiceVersionRule()]
        findings = [finding for rule in rules for finding in rule.compare(baseline, current)]
        render_diff(findings, baseline=baseline, current=current)
    finally:
        if threat_intel_conn is not None:
            threat_intel_conn.close()


def main():
    parser = argparse.ArgumentParser(description="Simple nmap automation tool")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run an nmap scan and report the results")
    scan.add_argument("target", help="IP, hostname, or subnet to scan")
    scan.add_argument("--ports", default=None, help="Port range/list, e.g. 22,80,443 or 1-1000")
    scan.add_argument("--out", default=DEFAULT_SCAN_DIR, help="Directory to save scan JSON results")
    scan.add_argument("--nmap-path", default="nmap", help="Path to the nmap binary")
    scan.set_defaults(func=cmd_scan)

    compare = sub.add_parser("compare", help="Compare the two most recent saved scans for a target")
    compare.add_argument("target", help="Target to compare (must match a previous scan's target)")
    compare.add_argument("--dir", default=DEFAULT_SCAN_DIR, help="Directory holding saved scan JSON results")
    compare.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
