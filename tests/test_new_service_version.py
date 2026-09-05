import unittest

from netscan.models import Host, Port, ScanResult
from netscan.rules.new_service_version import NewServiceVersionRule


def _scan(ports):
    return ScanResult(target="10.0.0.5", timestamp="t", hosts=[Host(ip="10.0.0.5", ports=ports)])


class TestNewServiceVersionRule(unittest.TestCase):
    def test_flags_version_change_same_service(self):
        baseline = _scan(
            [Port(number=22, protocol="tcp", state="open", service="ssh", product="OpenSSH", version="8.9p1")]
        )
        current = _scan(
            [Port(number=22, protocol="tcp", state="open", service="ssh", product="OpenSSH", version="10.2p1")]
        )
        findings = NewServiceVersionRule().compare(baseline, current)
        self.assertEqual(len(findings), 1)
        self.assertIn("8.9p1", findings[0].message)
        self.assertIn("10.2p1", findings[0].message)

    def test_no_finding_when_version_unchanged(self):
        baseline = _scan([Port(number=22, protocol="tcp", state="open", service="ssh", version="10.2p1")])
        current = _scan([Port(number=22, protocol="tcp", state="open", service="ssh", version="10.2p1")])
        self.assertEqual(NewServiceVersionRule().compare(baseline, current), [])

    def test_no_finding_when_service_itself_changed(self):
        baseline = _scan([Port(number=8080, protocol="tcp", state="open", service="http", version="1.0")])
        current = _scan([Port(number=8080, protocol="tcp", state="open", service="rtsp", version="2.0")])
        self.assertEqual(NewServiceVersionRule().compare(baseline, current), [])

    def test_no_finding_for_port_missing_from_baseline(self):
        baseline = _scan([])
        current = _scan([Port(number=22, protocol="tcp", state="open", service="ssh", version="10.2p1")])
        self.assertEqual(NewServiceVersionRule().compare(baseline, current), [])


if __name__ == "__main__":
    unittest.main()
