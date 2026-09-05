import argparse
import io
import tempfile
import unittest
from contextlib import redirect_stdout

import main as cli
from netscan.models import Host, Port, ScanResult
from netscan.storage.scan_store import save_scan


def _scan(target, ports):
    return ScanResult(target=target, timestamp="t", hosts=[Host(ip="10.0.0.5", ports=ports)])


class TestCmdCompare(unittest.TestCase):
    def test_reports_not_enough_scans(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(target="10.0.0.5", dir=tmpdir)
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli.cmd_compare(args)
            self.assertIn("Need at least 2 saved scans", buf.getvalue())

    def test_compares_two_saved_scans_and_reports_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = _scan(
                "10.0.0.5", [Port(number=22, protocol="tcp", state="open", service="ssh", version="8.9p1")]
            )
            current = _scan(
                "10.0.0.5",
                [
                    Port(number=22, protocol="tcp", state="open", service="ssh", version="10.2p1"),
                    Port(number=8080, protocol="tcp", state="open", service="http"),
                ],
            )
            save_scan(baseline, base_dir=tmpdir)
            save_scan(current, base_dir=tmpdir)

            args = argparse.Namespace(target="10.0.0.5", dir=tmpdir)
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli.cmd_compare(args)
            output = buf.getvalue()

            self.assertIn("new_open_port", output)
            self.assertIn("8080", output)
            self.assertIn("new_service_version", output)
            self.assertIn("8.9p1", output)
            self.assertIn("10.2p1", output)

    def test_only_compares_the_two_most_recent_scans(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            oldest = _scan("10.0.0.5", [])
            middle = _scan("10.0.0.5", [Port(number=22, protocol="tcp", state="open", service="ssh")])
            newest = _scan("10.0.0.5", [Port(number=22, protocol="tcp", state="open", service="ssh")])
            for result in (oldest, middle, newest):
                save_scan(result, base_dir=tmpdir)

            args = argparse.Namespace(target="10.0.0.5", dir=tmpdir)
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli.cmd_compare(args)
            # port 22 already existed in the middle scan, so comparing
            # middle -> newest should find no new port, not "oldest -> newest".
            self.assertIn("No differences found", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
