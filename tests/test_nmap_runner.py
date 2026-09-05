import subprocess
import unittest
from unittest.mock import patch

from netscan.runner.nmap_runner import run_scan


class TestNmapRunner(unittest.TestCase):
    def test_rejects_target_starting_with_dash(self):
        with self.assertRaises(ValueError):
            run_scan("--script=whatever")

    @patch("netscan.runner.nmap_runner.subprocess.run")
    def test_builds_expected_command_and_returns_stdout(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="<xml/>", stderr=""
        )
        output = run_scan("localhost", ports="22,80")
        self.assertEqual(output, "<xml/>")
        cmd = mock_run.call_args.args[0]
        self.assertEqual(cmd, ["nmap", "-sV", "-oX", "-", "-p", "22,80", "localhost"])

    @patch("netscan.runner.nmap_runner.subprocess.run")
    def test_raises_on_nonzero_exit(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="nmap: some error"
        )
        with self.assertRaises(RuntimeError):
            run_scan("localhost")

    @patch("netscan.runner.nmap_runner.subprocess.run", side_effect=FileNotFoundError())
    def test_raises_when_nmap_missing(self, mock_run):
        with self.assertRaises(RuntimeError):
            run_scan("localhost")


if __name__ == "__main__":
    unittest.main()
