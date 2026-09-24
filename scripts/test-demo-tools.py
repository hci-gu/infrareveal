#!/usr/bin/env python3
"""Offline validation of the local demo export, monitor, and kiosk helpers."""
import csv
import importlib.util
import json
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


exporter = load("export-domain-catalogue")
kiosk = load("demo-kiosk")
monitor = load("monitor-demo")


class DemoToolsTest(unittest.TestCase):
    def test_exports_preserve_examples_without_identifiers_and_keep_previous_on_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "data.db"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE domain_catalogue (" + ",".join(exporter.FIELDS) + ",client_ip)")
                row = ["example.com", "first", "last", 4, 0, 2, 0, '["www.example.com"]', '[]', "pending", "", "review, later"]
                connection.execute("INSERT INTO domain_catalogue VALUES (" + ",".join("?" for _ in row + [""]) + ")", row + ["10.0.0.50"])
            output = root / "snapshot.json"
            self.assertEqual(exporter.export(database, output), 1)
            snapshot = output.read_text()
            self.assertNotIn("10.0.0.50", snapshot)
            self.assertEqual(json.loads(snapshot)["domains"][0]["hostnames"], ["www.example.com"])
            csv_output = root / "snapshot.csv"
            exporter.export(database, csv_output)
            with csv_output.open() as source:
                self.assertEqual(list(csv.DictReader(source))[0]["notes"], "review, later")
            with self.assertRaises(sqlite3.OperationalError):
                exporter.export(root / "missing.db", output)
            self.assertEqual(output.read_text(), snapshot)

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
