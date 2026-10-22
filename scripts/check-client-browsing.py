#!/usr/bin/env python3
"""Compare a real browser run with the gateway's public map/activity APIs."""
import argparse
import json
from pathlib import Path
import time
import urllib.parse
import urllib.request


def get(url):
    with urllib.request.urlopen(url, timeout=20) as response:
        return json.load(response)


def active_manifest(url):
    sessions = [s for s in get(url + "/api/infrareveal/sessions")["items"] if s["active"]]
    assert len(sessions) == 1, "Start one active session before this test"
    manifest = get(url + "/api/infrareveal/sessions/" + sessions[0]["id"] + "/manifest")
    assert manifest["active"] and manifest["capture"]["running"] and not manifest["capture"]["error"], "Active capture is unavailable"
    return manifest


def validate_session(baseline, manifest):
    assert manifest["active"] and manifest["id"] == baseline["id"], "Active session changed during the run"
    assert baseline["capture"]["epoch"] and manifest["capture"]["epoch"] == baseline["capture"]["epoch"], "Gateway capture restarted during the run"


def pages(base, kind, field, start, end):
    query = {"from": start, "to": end, "resolution": 50, "limit": 1000}
    first = None
    seen = set()
    for _ in range(100):
        page = get(base + "/" + kind + "?" + urllib.parse.urlencode(query))
        if first is None:
            first = page.copy()
            first[field] = list(page[field])
        else:
            assert (page["session_id"], page["revision"]) == (first["session_id"], first["revision"]), "Session changed during pagination"
            first[field].extend(page[field])
            if kind == "map":
                first["destinations"] = list({d["id"]: d for d in first["destinations"] + page["destinations"]}.values())
        if kind == "map":
            first["complete"] = page["complete"]
        cursor = page.get("next_cursor")
        if not cursor:
            assert kind != "map" or page["complete"], "Incomplete map window without a continuation"
            first.pop("next_cursor", None)
            return first
        assert cursor not in seen, "Repeated pagination cursor"
        seen.add(cursor)
        query["cursor"] = cursor
    raise AssertionError("Pagination exceeded 100 pages")


def validate(run, manifest, window, blocks):
    assert not run["errors"], run["errors"]
    assert run["visits"] and all(v["pages"] for v in run["visits"]), "No browser visits completed"
    assert manifest["capture"]["running"] and not manifest["capture"]["error"], "Capture is unavailable"
    assert manifest["retained_from_ms"] <= run["started_ms"], "Run has expired from the rolling window"
    client = run["network"]["client_ip"]
    assert run["network"]["route"]["gateway"] == "10.0.0.1", "Browser bypassed the gateway"
    assert {link["ifname"] for link in run["network"]["links"]} == {"lo", run["network"]["interface"]}, "An alternate interface was available"
    cursor = run["started_ms"]
    for interval in sorted(window["coverage"], key=lambda c: c["start_ms"]):
        if interval["end_ms"] <= cursor:
            continue
        assert interval["start_ms"] <= cursor and interval["quality"] == "complete" and interval["dropped"] == 0, "Missing or lossy capture during browsing"
        cursor = max(cursor, interval["end_ms"])
    assert cursor >= run["ended_ms"], "Capture did not cover the full run"
    series = [c for c in window["series"] if c["client_ip"] == client]
    client_blocks = [b for b in blocks["items"] if b["client_ip"] == client]
    assert series and client_blocks, "No traffic/blocks for this physical client"
    result = {"client_ip": client, "captured_wire_sent": sum(s[1] for c in series for s in c["samples"]), "captured_wire_received": sum(s[2] for c in series for s in c["samples"]), "chunks": len(series), "blocks": len(client_blocks), "visits": []}
    for visit in run["visits"]:
        assert all(p.get("end_ms") and p.get("status") is not None and 200 <= p["status"] < 400 for p in visit["pages"]), "A website did not load successfully"
        ips = {p.get("remote_ip") for p in visit["pages"]}
        if visit.get("allow_ambiguous"):
            assert None not in ips and "" not in ips, "Browser did not record its server IP"
        matching = []
        for chunk in series:
            if chunk["service_key"] == visit["service"]:
                matching.append(chunk)
            elif visit.get("allow_ambiguous") and chunk["destination_ip"] in ips:
                # Shared IPs must remain independent when DNS evidence conflicts.
                evidence = chunk["evidence"]
                endpoint = f'endpoint:{chunk["destination_ip"]}|{chunk["protocol"]}|{chunk["destination_port"]}'
                if chunk["service_key"] == endpoint and evidence["source"] == "ambiguous_dns" and evidence["ambiguous"]:
                    matching.append(chunk)
        samples = [(c["service_key"], s) for c in matching for s in c["samples"] if visit["start_ms"] - 2000 <= c["start_ms"] + s[0] < visit["end_ms"] + 2000]
        sent, received = sum(s[1] for _, s in samples), sum(s[2] for _, s in samples)
        assert sent > 0 and received > 4096, "Missing attributed traffic for " + visit["label"]
        services = {key for key, _ in samples}
        activity = [b for b in client_blocks if b["service_key"] in services and b["start_ms"] < visit["end_ms"] and b["end_ms"] > visit["start_ms"]]
        assert activity and all(b["active_ms"] > 0 for b in activity), "Missing activity for " + visit["label"]
        result["visits"].append({"label": visit["label"], "service": visit["service"], "sent": sent, "received": received, "ambiguous_received": sum(s[2] for key, s in samples if key != visit["service"]), "block_ids": [b["id"] for b in activity]})
    for index, visit in enumerate(result["visits"]):
        for previous in result["visits"][:index]:
            if previous["service"] == visit["service"]:
                assert set(previous["block_ids"]).isdisjoint(visit["block_ids"]), "Separate visits were merged into one activity block"
    ids = {c["destination_id"] for c in series}
    result["mapped_destinations"] = sum(d["id"] in ids and bool(d.get("country_code")) for d in window["destinations"])
    assert result["mapped_destinations"] > 0, "No destination context reached the map API"
    result["capture_complete"] = True
    result["passed"] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", action="store_true", help="Print the active session manifest before browsing")
    parser.add_argument("--browser", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--url", default="http://127.0.0.1:8090")
    parser.add_argument("--settle-seconds", type=int, default=60)
    args = parser.parse_args()
    if args.snapshot:
        print(json.dumps(active_manifest(args.url), indent=2))
        return
    if not all((args.browser, args.baseline, args.output)):
        parser.error("--browser, --baseline and --output are required unless using --snapshot")
    run, baseline = json.loads(args.browser.read_text()), json.loads(args.baseline.read_text())
    # Let the normal correction and quiet-gap timers finish; do not change policy.
    remaining = run["ended_ms"] / 1000 + args.settle_seconds - time.time()
    if remaining > 0:
        time.sleep(remaining)
    manifest = active_manifest(args.url)
    validate_session(baseline, manifest)
    base = args.url + "/api/infrareveal/sessions/" + manifest["id"]
    window = pages(base, "map", "series", run["started_ms"], run["ended_ms"])
    blocks = pages(base, "blocks", "items", run["started_ms"], run["ended_ms"])
    args.output.mkdir(parents=True, exist_ok=True)
    for name, value in [("manifest", manifest), ("map", window), ("blocks", blocks)]:
        (args.output / (name + ".json")).write_text(json.dumps(value) + "\n")
    try:
        result = validate(run, manifest, window, blocks)
    except AssertionError as error:
        (args.output / "result.json").write_text(json.dumps({"passed": False, "error": str(error)}, indent=2) + "\n")
        raise
    (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
