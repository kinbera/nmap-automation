import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import main as cli

FIXTURE = Path(__file__).parent / "fixtures" / "sample_scan.xml"


class TestCmdScan(unittest.TestCase):
    @patch("main.run_scan")
    def test_scan_saves_json_and_prints_report(self, mock_run_scan):
        mock_run_scan.return_value = FIXTURE.read_text()

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                target="localhost", ports=None, out=tmpdir, nmap_path="nmap"
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli.cmd_scan(args)
            output = buf.getvalue()

            mock_run_scan.assert_called_once_with(
                "localhost", ports=None, nmap_path="nmap"
            )
            self.assertIn("Saved scan to", output)
            self.assertIn("127.0.0.1", output)
            self.assertIn("ssh", output)

            saved_files = list(Path(tmpdir).glob("*.json"))
            self.assertEqual(len(saved_files), 1)
            data = json.loads(saved_files[0].read_text())
            self.assertEqual(data["target"], "localhost")
            self.assertEqual(data["hosts"][0]["ports"][0]["number"], 22)


if __name__ == "__main__":
    unittest.main()
