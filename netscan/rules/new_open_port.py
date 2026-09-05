"""Flags ports that are open in the current scan but weren't in the baseline.

Severity escalates to "high" when the host's IP also matches a known-bad IOC
in the threat-intel-aggregator local store (see README: Threat intel enrichment).
"""
import sqlite3

from intel.lookup.checker import check_ip as check_known_bad_ip

from netscan.models import ScanResult
from netscan.rules.base import Finding, Rule


class NewOpenPortRule(Rule):
    name = "new_open_port"

    def __init__(self, threat_intel_conn: sqlite3.Connection | None = None):
        self.threat_intel_conn = threat_intel_conn

    def compare(self, baseline: ScanResult, current: ScanResult) -> list[Finding]:
        baseline_open = {
            (host.ip, port.number)
            for host in baseline.hosts
            for port in host.ports
            if port.state == "open"
        }

        findings = []
        for host in current.hosts:
            for port in host.ports:
                if port.state != "open":
                    continue
                if (host.ip, port.number) in baseline_open:
                    continue

                severity = "medium"
                message = (
                    f"New open port {port.number}/{port.protocol} "
                    f"({port.service or 'unknown service'}) on {host.ip}"
                )
                if self.threat_intel_conn is not None and check_known_bad_ip(self.threat_intel_conn, host.ip):
                    severity = "high"
                    message += " — host IP is a known-bad IOC"

                findings.append(
                    Finding(
                        rule=self.name,
                        severity=severity,
                        message=message,
                        host=host.ip,
                        port=port.number,
                    )
                )
        return findings
