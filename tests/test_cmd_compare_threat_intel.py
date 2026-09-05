import argparse
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import main as cli
from intel.storage.ioc_store import init_db as init_intel_db
from netscan.models import Host, Port, ScanResult
from netscan.storage.scan_store import save_scan


def _scan(ports):
    return ScanResult(target="10.0.0.5", timestamp="t", hosts=[Host(ip="10.0.0.5", ports=ports)])


class TestCmdCompareThreatIntelGating(unittest.TestCase):
    def _seed_two_scans(self, tmpdir):
        save_scan(_scan([]), base_dir=tmpdir)
        save_scan(_scan([Port(number=8080, protocol="tcp", state="open", service="http")]), base_dir=tmpdir)

    @patch("main.init_threat_intel_db")
    def test_does_not_open_threat_intel_conn_when_env_var_unset(self, mock_init_db):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._seed_two_scans(tmpdir)
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("THREAT_INTEL_DB", None)
                args = argparse.Namespace(target="10.0.0.5", dir=tmpdir)
                cli.cmd_compare(args)

        mock_init_db.assert_not_called()

    @patch("main.init_threat_intel_db")
    def test_opens_and_closes_threat_intel_conn_when_env_var_set(self, mock_init_db):
        # A real (empty) in-memory store, so check_ip() inside the rule runs
        # against genuine SQL — a bare MagicMock can't stand in for a
        # sqlite3.Connection. close() can't be mocked either (C extension
        # type), so we confirm it was closed by trying to use it afterward.
        real_conn = init_intel_db(":memory:")
        mock_init_db.return_value = real_conn

        with tempfile.TemporaryDirectory() as tmpdir:
            self._seed_two_scans(tmpdir)
            with patch.dict(os.environ, {"THREAT_INTEL_DB": "/tmp/whatever.db"}):
                args = argparse.Namespace(target="10.0.0.5", dir=tmpdir)
                cli.cmd_compare(args)

        mock_init_db.assert_called_once()
        with self.assertRaises(sqlite3.ProgrammingError):
            real_conn.execute("SELECT 1")

    @patch("main.init_threat_intel_db")
    def test_does_not_open_threat_intel_conn_when_env_var_is_empty_string(self, mock_init_db):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._seed_two_scans(tmpdir)
            with patch.dict(os.environ, {"THREAT_INTEL_DB": ""}):
                args = argparse.Namespace(target="10.0.0.5", dir=tmpdir)
                cli.cmd_compare(args)

        mock_init_db.assert_not_called()


if __name__ == "__main__":
    unittest.main()
