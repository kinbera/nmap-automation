"""Flags ports where the service is unchanged but its reported version differs."""
from netscan.models import ScanResult
from netscan.rules.base import Finding, Rule


class NewServiceVersionRule(Rule):
    name = "new_service_version"

    def compare(self, baseline: ScanResult, current: ScanResult) -> list[Finding]:
        baseline_ports = {
            (host.ip, port.number): port
            for host in baseline.hosts
            for port in host.ports
            if port.state == "open"
        }

        findings = []
        for host in current.hosts:
            for port in host.ports:
                if port.state != "open":
                    continue
                old = baseline_ports.get((host.ip, port.number))
                if old is None or old.service != port.service:
                    continue
                if old.version == port.version:
                    continue
                findings.append(
                    Finding(
                        rule=self.name,
                        severity="low",
                        message=(
                            f"{port.service} on {host.ip}:{port.number} version changed: "
                            f"{old.version or 'unknown'} -> {port.version or 'unknown'}"
                        ),
                        host=host.ip,
                        port=port.number,
                    )
                )
        return findings
