import os
import unittest

from netscan.parsers.nmap_parser import parse_file

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_scan.xml")


class TestNmapParser(unittest.TestCase):
    def test_parses_target_and_timestamp(self):
        result = parse_file(FIXTURE)
        self.assertEqual(result.target, "localhost")
        self.assertTrue(result.timestamp)

    def test_parses_host(self):
        result = parse_file(FIXTURE)
        self.assertEqual(len(result.hosts), 1)
        host = result.hosts[0]
        self.assertEqual(host.ip, "127.0.0.1")
        self.assertEqual(host.status, "up")
        self.assertIn("localhost", host.hostnames)

    def test_parses_open_port_with_service(self):
        result = parse_file(FIXTURE)
        host = result.hosts[0]
        self.assertEqual(len(host.ports), 1)
        port = host.ports[0]
        self.assertEqual(port.number, 22)
        self.assertEqual(port.protocol, "tcp")
        self.assertEqual(port.state, "open")
        self.assertEqual(port.service, "ssh")
        self.assertEqual(port.product, "OpenSSH")
        self.assertEqual(port.version, "10.2p1 Debian 5")


if __name__ == "__main__":
    unittest.main()
