import unittest

from netscan.models import Host, Port, ScanResult
from netscan.rules.new_open_port import NewOpenPortRule


def _scan(ports):
    return ScanResult(target="10.0.0.5", timestamp="t", hosts=[Host(ip="10.0.0.5", ports=ports)])


class TestNewOpenPortRule(unittest.TestCase):
    def test_flags_newly_opened_port(self):
        baseline = _scan([Port(number=22, protocol="tcp", state="open", service="ssh")])
        current = _scan(
            [
                Port(number=22, protocol="tcp", state="open", service="ssh"),
                Port(number=8080, protocol="tcp", state="open", service="http"),
            ]
        )
        findings = NewOpenPortRule().compare(baseline, current)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].host, "10.0.0.5")
        self.assertEqual(findings[0].port, 8080)

    def test_no_findings_when_ports_unchanged(self):
        baseline = _scan([Port(number=22, protocol="tcp", state="open", service="ssh")])
        current = _scan([Port(number=22, protocol="tcp", state="open", service="ssh")])
        self.assertEqual(NewOpenPortRule().compare(baseline, current), [])

    def test_ignores_non_open_ports_in_current(self):
        baseline = _scan([])
        current = _scan([Port(number=443, protocol="tcp", state="filtered", service="https")])
        self.assertEqual(NewOpenPortRule().compare(baseline, current), [])


if __name__ == "__main__":
    unittest.main()
