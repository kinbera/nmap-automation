import unittest

from intel.models import IOC
from intel.storage.ioc_store import init_db, upsert_iocs

from netscan.models import Host, Port, ScanResult
from netscan.rules.new_open_port import NewOpenPortRule


def _scan(ports, ip="10.0.0.5"):
    return ScanResult(target=ip, timestamp="t", hosts=[Host(ip=ip, ports=ports)])


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

    def test_defaults_to_medium_severity_without_threat_intel(self):
        baseline = _scan([])
        current = _scan([Port(number=8080, protocol="tcp", state="open", service="http")])
        findings = NewOpenPortRule().compare(baseline, current)
        self.assertEqual(findings[0].severity, "medium")


class TestNewOpenPortRuleThreatIntel(unittest.TestCase):
    def setUp(self):
        self.conn = init_db(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_escalates_to_high_when_host_ip_is_a_known_bad_ioc(self):
        upsert_iocs(self.conn, [
            IOC(type="ip", value="203.0.113.5", source="urlhaus", threat="malware_download"),
        ])
        baseline = _scan([], ip="203.0.113.5")
        current = _scan([Port(number=8080, protocol="tcp", state="open", service="http")], ip="203.0.113.5")

        findings = NewOpenPortRule(threat_intel_conn=self.conn).compare(baseline, current)

        self.assertEqual(findings[0].severity, "high")
        self.assertIn("known-bad IOC", findings[0].message)

    def test_stays_medium_when_host_ip_is_not_a_known_bad_ioc(self):
        baseline = _scan([])
        current = _scan([Port(number=8080, protocol="tcp", state="open", service="http")])

        findings = NewOpenPortRule(threat_intel_conn=self.conn).compare(baseline, current)

        self.assertEqual(findings[0].severity, "medium")

    def test_unchanged_port_still_produces_no_finding_even_if_ip_is_a_known_bad_ioc(self):
        upsert_iocs(self.conn, [
            IOC(type="ip", value="203.0.113.5", source="urlhaus", threat="malware_download"),
        ])
        baseline = _scan([Port(number=22, protocol="tcp", state="open", service="ssh")], ip="203.0.113.5")
        current = _scan([Port(number=22, protocol="tcp", state="open", service="ssh")], ip="203.0.113.5")

        findings = NewOpenPortRule(threat_intel_conn=self.conn).compare(baseline, current)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
