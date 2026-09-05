"""Flags ports that are open in the current scan but weren't in the baseline."""
from netscan.models import ScanResult
from netscan.rules.base import Finding, Rule


class NewOpenPortRule(Rule):
    name = "new_open_port"

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
                findings.append(
                    Finding(
                        rule=self.name,
                        severity="medium",
                        message=(
                            f"New open port {port.number}/{port.protocol} "
                            f"({port.service or 'unknown service'}) on {host.ip}"
                        ),
                        host=host.ip,
                        port=port.number,
                    )
                )
        return findings
