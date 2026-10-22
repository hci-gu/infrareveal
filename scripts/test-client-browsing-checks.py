#!/usr/bin/env python3
"""Offline checks that the E2E verifier rejects misleading success evidence."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("check", Path(__file__).with_name("check-client-browsing.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def fixture():
    ip = "10.0.0.106"
    visits = [{"label": label, "service": service, "start_ms": start, "end_ms": start + 1000, "pages": [{"status": 200, "end_ms": start + 1000}]} for label, service, start in [("first", "svt.se", 2000), ("other", "wikipedia.org", 5000), ("return", "svt.se", 80000)]]
    run = {"errors": [], "started_ms": 1000, "ended_ms": 82000, "network": {"client_ip": ip, "interface": "wlan0", "links": [{"ifname": "lo"}, {"ifname": "wlan0"}], "route": {"gateway": "10.0.0.1"}}, "visits": visits}
    manifest = {"capture": {"running": True, "error": ""}, "retained_from_ms": 0}
    window = {"coverage": [{"start_ms": 1000, "end_ms": 82000, "quality": "complete", "dropped": 0}], "series": [{"client_ip": ip, "service_key": v["service"], "start_ms": v["start_ms"], "destination_id": "destination", "destination_ip": "198.51.100.1", "samples": [[0, 100, 8192, 50, 8000, 1, 6]]} for v in visits], "destinations": [{"id": "destination", "country_code": "SE"}]}
    blocks = {"items": [{"id": str(i), "client_ip": ip, "service_key": v["service"], "start_ms": v["start_ms"], "end_ms": v["end_ms"], "active_ms": 50} for i, v in enumerate(visits)]}
    return run, manifest, window, blocks


class BrowsingChecks(unittest.TestCase):
    def test_baseline_uses_the_active_session_without_demo_mode(self):
        manifest = {"id": "active", "active": True, "capture": {"running": True, "error": "", "epoch": "first"}}
        with patch.object(check, "get", side_effect=[{"items": [{"id": "closed", "active": False}, manifest]}, manifest]) as request:
            self.assertEqual(check.active_manifest("http://gateway"), manifest)
        self.assertEqual([call.args[0] for call in request.call_args_list], [
            "http://gateway/api/infrareveal/sessions",
            "http://gateway/api/infrareveal/sessions/active/manifest",
        ])
        for change in [dict(id="other"), dict(active=False), dict(capture={"running": True, "error": "", "epoch": "restarted"})]:
            with self.subTest(change=change), self.assertRaises(AssertionError):
                check.validate_session(manifest, dict(manifest, **change))
        with patch.object(check, "get", return_value={"items": []}), self.assertRaisesRegex(AssertionError, "active session"):
            check.active_manifest("http://gateway")

    def test_map_pagination_keeps_destinations_from_every_page(self):
        common = {"session_id": "active", "revision": 3, "coverage": []}
        pages = [dict(common, series=[{"id": "a"}], destinations=[{"id": "one"}], complete=False, next_cursor="next"),
                 dict(common, series=[{"id": "b"}], destinations=[{"id": "one"}, {"id": "two"}], complete=True)]
        with patch.object(check, "get", side_effect=pages):
            window = check.pages("http://gateway", "map", "series", 0, 1000)
        self.assertEqual([c["id"] for c in window["series"]], ["a", "b"])
        self.assertEqual([d["id"] for d in window["destinations"]], ["one", "two"])
        self.assertTrue(window["complete"])

    def test_incomplete_or_changed_pagination_cannot_pass(self):
        page = {"session_id": "active", "revision": 3, "series": [], "destinations": [], "complete": False, "next_cursor": "next"}
        for last in [dict(page, next_cursor=None), dict(page, revision=4, complete=True, next_cursor=None), page]:
            with self.subTest(last=last), patch.object(check, "get", side_effect=[page, last]), self.assertRaises(AssertionError):
                check.pages("http://gateway", "map", "series", 0, 1000)

    def test_real_client_with_separate_visits_passes(self):
        result = check.validate(*fixture())
        self.assertTrue(result["passed"])
        self.assertEqual(result["chunks"], 3)

    def test_other_client_or_unclassified_traffic_cannot_pass(self):
        for field, value in [("client_ip", "10.0.0.107"), ("service_key", "unknown")]:
            args = fixture()
            for chunk in args[2]["series"]:
                chunk[field] = value
            with self.assertRaises(AssertionError):
                check.validate(*args)

    def test_failed_page_capture_gap_or_ethernet_cannot_pass(self):
        cases = [lambda a: a[0]["visits"][0]["pages"][0].update(status=403), lambda a: a[2]["coverage"][0].update(start_ms=2000), lambda a: a[2]["coverage"][0].update(dropped=1), lambda a: a[0]["network"]["links"].append({"ifname": "eth0"})]
        for change in cases:
            args = fixture()
            change(args)
            with self.assertRaises(AssertionError):
                check.validate(*args)

    def test_merged_return_visit_cannot_pass(self):
        args = fixture()
        args[3]["items"][0]["end_ms"] = 82000
        args[3]["items"].pop()
        with self.assertRaisesRegex(AssertionError, "Separate visits"):
            check.validate(*args)

    def test_shared_endpoint_requires_browser_ip_and_explicit_ambiguity(self):
        for failure in [None, "other_ip", "unknown", "not_ambiguous", "not_allowed"]:
            with self.subTest(failure=failure):
                args = fixture()
                visit, chunk, block = args[0]["visits"][1], args[2]["series"][1], args[3]["items"][1]
                visit["allow_ambiguous"] = failure != "not_allowed"
                visit["pages"][0]["remote_ip"] = "203.0.113.2" if failure == "other_ip" else "203.0.113.1"
                chunk.update(service_key="endpoint:203.0.113.1|tcp|443", destination_ip="203.0.113.1", protocol="tcp", destination_port=443, evidence={"source": "destination_ip" if failure == "unknown" else "ambiguous_dns", "ambiguous": failure != "not_ambiguous"})
                block["service_key"] = chunk["service_key"]
                if failure:
                    with self.assertRaises(AssertionError):
                        check.validate(*args)
                else:
                    self.assertEqual(check.validate(*args)["visits"][1]["ambiguous_received"], 8192)


if __name__ == "__main__":
    unittest.main()
