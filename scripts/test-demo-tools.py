#!/usr/bin/env python3
"""Offline validation of the current monitor, route audit and kiosk helpers."""
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kiosk = load("demo-kiosk")
monitor = load("monitor-demo")
route_audit = load("audit-routes")


def create_database(path):
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE sessions (id, demo)")
        db.execute("INSERT INTO sessions VALUES ('demo', true)")
        db.execute("CREATE TABLE destinations (id)")
        for table in ("traffic_chunks", "capture_intervals", "activity_blocks"):
            db.execute("CREATE TABLE " + table + " (session)")
            db.execute("INSERT INTO " + table + " VALUES ('demo')")
        db.execute("CREATE TABLE route_evidence (session, kind, attempt_id, revision, binding_key, network_epoch, measured_ms, valid_until_ms, hops, fingerprint, evidence_bytes)")
        db.execute("INSERT INTO route_evidence VALUES ('demo','path','run',1,'9.9.9.9|tcp|443','epoch',100,200,'[{\"ttl\":3,\"address\":\"1.1.1.1\"}]','fingerprint',500)")
        db.execute("CREATE TABLE probe_runs (session, manual, status, class)")
        db.execute("INSERT INTO probe_runs VALUES ('deleted-session',false,'interrupted','indeterminate')")


class DemoToolsTest(unittest.TestCase):
    def test_monitor_uses_core_collections_and_optional_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "data.db"
            create_database(database)
            with patch.object(monitor.urllib.request, "urlopen", side_effect=OSError("offline")):
                result = monitor.sample("http://example.invalid", database)
                self.assertNotIn("databaseError", result)
                self.assertEqual(result["rows"], {"traffic_chunks": 1, "capture_intervals": 1, "activity_blocks": 1, "route_evidence": 1, "probe_runs": 0})
                self.assertEqual(result["probeRunsGlobal"], 1)
                with sqlite3.connect(database) as db:
                    db.execute("CREATE TABLE flow_diagnostics (session)")
                    db.execute("INSERT INTO flow_diagnostics VALUES ('demo')")
                self.assertEqual(monitor.sample("http://example.invalid", database)["rows"]["flow_diagnostics"], 1)

    def test_audit_is_read_only_and_distinguishes_publications_from_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "data.db"
            create_database(database)
            before = database.read_bytes()
            db = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
            db.row_factory = sqlite3.Row
            try:
                result = route_audit.audit(db, "demo")
                self.assertEqual(result["useful_path_publications"], 1)
                self.assertEqual(result["admitted_attempts"], 0)
                self.assertEqual(result["global_admissions_after_session_deletion"], 1)
                self.assertEqual(result["structural_issues"], {})
                self.assertEqual(result["collections"]["probe_runs"]["global_rows"], 1)
            finally:
                db.close()
            self.assertEqual(database.read_bytes(), before)
        with sqlite3.connect(":memory:") as db:
            with self.assertRaisesRegex(ValueError, "requires the current schema"):
                route_audit.audit(db)

    def test_gateway_failure_is_recoverable_and_kiosk_has_dedicated_profile(self):
        with patch.object(kiosk.urllib.request, "urlopen", side_effect=OSError("offline")):
            self.assertFalse(kiosk.gateway_ready("http://example.invalid"))
        command = kiosk.browser_command("chromium", Path("/tmp/demo-profile"), "http://gateway/")
        self.assertIn("--kiosk", command)
        self.assertIn("--user-data-dir=/tmp/demo-profile", command)
        self.assertEqual(command[-1], "http://gateway/demo")
        with patch.object(monitor.urllib.request, "urlopen", side_effect=OSError("offline")):
            self.assertIn("error", monitor.sample("http://example.invalid"))


if __name__ == "__main__":
    unittest.main()
