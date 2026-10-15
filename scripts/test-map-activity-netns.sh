#!/usr/bin/env bash
set -euo pipefail

# Run only in a disposable --privileged --network none Linux container.
# All HTTP traffic stays inside three private namespaces; no Internet probes.
# Example (from the repository):
# docker run --rm --privileged --network none --entrypoint bash \
#   -e IR_MAP_ACTIVITY_ISOLATED=1 -v "$PWD:/workspace:ro" \
#   -v "$PWD/output/pocketbase-restructuring/map-activity-netns:/results" infrareveal-gateway:map-activity \
#   /workspace/scripts/test-map-activity-netns.sh \
#   /workspace/output/pocketbase-restructuring/infrareveal-linux-arm64 /results
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" -ne 0 ] || [ "${IR_MAP_ACTIVITY_ISOLATED:-}" != 1 ]; then
  echo 'Requires an explicitly isolated root Linux container (IR_MAP_ACTIVITY_ISOLATED=1).' >&2
  exit 1
fi
for command in ip python3 curl; do command -v "$command" >/dev/null; done
if [ -n "$(ip route show default)" ]; then
  echo 'Refusing to run with an outer default route; use Docker --network none.' >&2
  exit 1
fi
BACKEND="${1:-/root/pb/infra-reveal}"
RESULTS="${2:-/tmp/map-activity-results}"
[ -x "$BACKEND" ] || { echo "Missing executable: $BACKEND" >&2; exit 1; }
mkdir -p "$RESULTS"
CLIENT="ir-map-client-$$"
GATEWAY="ir-map-gateway-$$"
UPSTREAM="ir-map-upstream-$$"
cleanup() {
  for namespace in "$CLIENT" "$GATEWAY" "$UPSTREAM"; do
    for pid in $(ip netns pids "$namespace" 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
    ip netns del "$namespace" 2>/dev/null || true
  done
}
trap cleanup EXIT
for namespace in "$CLIENT" "$GATEWAY" "$UPSTREAM"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
ip -n "$CLIENT" link add client type veth peer name ap
ip -n "$CLIENT" link set ap netns "$GATEWAY"
ip -n "$GATEWAY" link add uplink type veth peer name server
ip -n "$GATEWAY" link set server netns "$UPSTREAM"
ip -n "$CLIENT" addr add 10.0.0.100/24 dev client
ip -n "$GATEWAY" addr add 10.0.0.1/24 dev ap
ip -n "$GATEWAY" addr add 10.249.99.1/24 dev uplink
ip -n "$UPSTREAM" addr add 10.249.99.2/24 dev server
ip -n "$UPSTREAM" addr add 151.101.3.6/32 dev lo
ip -n "$CLIENT" link set client up
ip -n "$GATEWAY" link set ap up
ip -n "$GATEWAY" link set uplink up
ip -n "$UPSTREAM" link set server up
ip -n "$CLIENT" route add default via 10.0.0.1
ip -n "$GATEWAY" route add 151.101.3.6/32 via 10.249.99.2
ip -n "$UPSTREAM" route add 10.0.0.0/24 via 10.249.99.1
ip netns exec "$GATEWAY" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

ip netns exec "$GATEWAY" python3 - "$BACKEND" "$RESULTS" "$CLIENT" "$UPSTREAM" <<'PY'
import collections
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

binary, results, client, upstream = sys.argv[1:]
results = Path(results)
work = Path(tempfile.mkdtemp(prefix="ir-map-activity-"))
data_dir = work / "data"
dns_log = work / "dnsmasq.log"
dns_log.touch()
(work / "accounting").write_text("1\n")
(work / "payload").write_bytes(b"x" * (128 * 1024))
base = "http://127.0.0.1:8090"
app = server = None
log = (results / "backend.log").open("w")
server_log = (results / "http-server.log").open("w")
latencies = []
started = time.monotonic()
report = {"fixture": "isolated Linux namespaces, real AF_PACKET capture, missing conntrack", "platform": os.environ.get("IR_MAP_ACTIVITY_PLATFORM", "development Linux container"), "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(), "policy": {"bucket_ms": 50, "chunk_ms": 5000, "correction_ms": 2000, "quiet_gap_ms": 1000}, "download_payload_bytes": 0}


def stage(name):
    print(json.dumps({"stage": name, "elapsed_seconds": round(time.monotonic()-started, 2)}), flush=True)


def request(path, method="GET", body=None):
    req = urllib.request.Request(base+path, method=method, data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type": "application/json"})
    at = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            value = json.load(response)
    except urllib.error.HTTPError as error:
        raise AssertionError(f"HTTP {error.code} {path.split('?')[0]}: {error.read(1000).decode()}") from error
    latencies.append((time.monotonic()-at)*1000)
    return value


def wait_for(check, timeout=15, description="condition"):
    deadline = time.monotonic()+timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError, sqlite3.OperationalError) as error:
            last = error
        if app is not None and app.poll() is not None:
            raise AssertionError("backend exited: " + log.name)
        time.sleep(.1)
    raise AssertionError("timeout waiting for " + description + (": " + str(last) if last else ""))


def rows(sql, parameters=()):
    db = sqlite3.connect((data_dir / "data.db").as_uri()+"?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in db.execute(sql, parameters)]
    finally:
        db.close()


def manifest():
    return request("/api/infrareveal/sessions/" + session + "/manifest")


def chunk_totals(chunks):
    return [sum(sample[i] for chunk in chunks for sample in (json.loads(chunk["samples"]) if isinstance(chunk["samples"], str) else chunk["samples"])) for i in range(1, 7)]


def chunks():
    return rows("SELECT * FROM traffic_chunks WHERE session=? ORDER BY start_ms,id", (session,))


def dns_ready():
    # The follower opens and seeks to EOF before test DNS is appended.
    for entry in Path("/proc" + "/" + str(app.pid) + "/fd").iterdir():
        try:
            if os.readlink(entry) == str(dns_log):
                return True
        except FileNotFoundError:
            pass
    return False


def feed_dns():
    wait_for(dns_ready, description="dnsmasq follower file descriptor")
    time.sleep(.35)
    with dns_log.open("a") as target:
        target.write("dnsmasq[100]: 1001 10.0.0.100/53000 query[A] www.svt.se from 10.0.0.100\n")
        target.write("dnsmasq[100]: 1001 10.0.0.100/53000 reply www.svt.se is 151.101.3.6\n")
        target.flush()
    time.sleep(.4)


def start_backend():
    global app
    environment = dict(os.environ, AP_IFACE="ap", INTERNET_IFACE="uplink", CLIENT_CIDRS="10.0.0.0/24", GATEWAY_IP="10.0.0.1", PACKET_ACTIVITY_ENABLED="true", PACKET_ACTIVITY_IFACE="ap", CONNTRACK_PATH=str(work/"deliberately-absent-conntrack"), CONNTRACK_ACCOUNTING_PATH=str(work/"accounting"), DHCP_LEASE_PATH=str(work/"no-leases"), DNSMASQ_LOG_PATH=str(dns_log), ROUTE_ENGINE="off", LAB_GATE_ENABLED="false", DEBUG_TRACE_ENABLED="false", DIAGNOSTICS_ENABLED="false", DEMO_MODE="true", DEMO_RETENTION_MINUTES="30", TRAFFIC_BUCKET_MS="50", TRAFFIC_CHUNK_MS="5000", TRAFFIC_FLUSH_MS="400", TRAFFIC_CORRECTION_MS="2000", ACTIVITY_QUIET_GAP_MS="1000")
    app = subprocess.Popen([binary, "serve", "--http=127.0.0.1:8090", "--dir="+str(data_dir)], env=environment, stdout=log, stderr=subprocess.STDOUT)
    demo = wait_for(lambda: request("/api/infrareveal/demo"), description="demo API")
    found = demo["sessionId"]
    wait_for(lambda: request("/api/infrareveal/sessions/"+found+"/manifest")["capture"].get("running"), description="real packet socket readiness")
    return found


def stop_backend():
    global app
    if app is not None:
        if app.poll() is None:
            app.send_signal(signal.SIGTERM)
        try:
            app.wait(timeout=10)
        except subprocess.TimeoutExpired:
            app.kill()
            app.wait()
            raise AssertionError("backend did not drain in 10 seconds")
        app = None


def download(paced=True):
    command = ["ip", "netns", "exec", client, "curl", "--noproxy", "*", "--fail", "--silent", "--show-error", "--max-time", "10", "--resolve", "www.svt.se:80:151.101.3.6", "--output", "/dev/null"]
    if paced:
        command += ["--limit-rate", "256k"]
    command += ["http://www.svt.se/payload"]
    subprocess.run(command, check=True, timeout=12)
    report["download_payload_bytes"] += 128*1024


def process_metrics():
    status = Path("/proc/"+str(app.pid)+"/status").read_text().splitlines()
    memory = {line.split(":")[0]: int(line.split()[1]) for line in status if line.startswith(("VmRSS:", "VmHWM:"))}
    stat = Path("/proc/"+str(app.pid)+"/stat").read_text().rpartition(") ")[2].split()
    io = dict(line.split(": ") for line in Path("/proc/"+str(app.pid)+"/io").read_text().splitlines())
    return {"rss_kib": memory["VmRSS"], "peak_rss_kib": memory["VmHWM"], "cpu_seconds": (int(stat[11])+int(stat[12]))/os.sysconf("SC_CLK_TCK"), "process_write_bytes": int(io["write_bytes"])}


def storage_metrics(names):
    return {"database_bytes": (data_dir/"data.db").stat().st_size,
            "wal_bytes": (data_dir/"data.db-wal").stat().st_size if (data_dir/"data.db-wal").exists() else 0,
            "allocated_pages": rows("PRAGMA page_count")[0]["page_count"],
            "free_pages": rows("PRAGMA freelist_count")[0]["freelist_count"],
            "rows": {name: rows("SELECT count(*) n FROM "+name)[0]["n"] for name in names}}


def collection_names():
    return sorted(row["name"] for row in rows("SELECT name FROM _collections WHERE system=0 AND type='base'"))


def pages(kind, start, end, limit):
    items, responses, cursor = [], [], ""
    for _ in range(100):
        query = {"from": start, "to": end, "resolution": 50, "limit": limit}
        if cursor:
            query["cursor"] = cursor
        page = request("/api/infrareveal/sessions/"+session+"/"+kind+"?"+urllib.parse.urlencode(query))
        responses.append(page)
        items.extend(page["series" if kind == "map" else "items"])
        cursor = page.get("next_cursor")
        if not cursor:
            return items, responses
    raise AssertionError("pagination did not terminate")

try:
    stage("namespaces_ready")
    server = subprocess.Popen(["ip", "netns", "exec", upstream, "python3", "-m", "http.server", "80", "--bind", "151.101.3.6", "--directory", str(work)], stdout=server_log, stderr=subprocess.STDOUT)
    session = start_backend()
    expected = sorted(["sessions", "traffic_chunks", "capture_intervals", "activity_blocks", "destinations", "route_evidence", "probe_runs"])
    assert collection_names() == expected, collection_names()
    assert not (work/"deliberately-absent-conntrack").exists()
    assert abs(manifest()["started_ms"]-int(time.time()*1000)) < 60000, "session timestamp lost Unix-millisecond precision"
    assert all(manifest()["policy"][key] == value for key, value in report["policy"].items()), manifest()["policy"]
    baseline = storage_metrics(expected)
    feed_dns()
    stage("capture_and_dns_ready")
    for _ in range(3):
        download()
        time.sleep(.2)
    wait_for(lambda: chunks() and chunk_totals(chunks())[3] >= 3*128*1024, description="persisted download payload without conntrack")
    assert any(row["service_label"] == "svt.se" for row in chunks()), [(row["service_key"], row["evidence"]) for row in chunks()]
    report["provisional_chunk_observed"] = any(not row["sealed"] for row in chunks())
    assert report["provisional_chunk_observed"]
    wait_for(lambda: chunks() and all(row["sealed"] for row in chunks()), timeout=15, description="sealed attribution tail")
    first_health = manifest()["capture"]
    idle_totals = chunk_totals(chunks())
    time.sleep(1.3)
    after_idle = manifest()["capture"]
    assert after_idle["confirmed_ms"] > first_health["confirmed_ms"], (first_health, after_idle)
    assert chunk_totals(chunks()) == idle_totals, "idle heartbeat invented traffic"
    stage("sealed_and_idle_coverage_verified")

    # Align close to a five-second boundary so restart can split one chunk into
    # two capture epochs. The report explicitly says whether timing fit.
    wait_for(lambda: int(time.time()*1000)%5000 < 250, timeout=6, description="chunk boundary")
    before_restart = chunk_totals(chunks())
    restart_start = int(time.time()*1000)//5000*5000
    old_epoch = manifest()["capture"]["epoch"]
    download(False)
    wait_for(lambda: chunk_totals(chunks())[3] > before_restart[3], description="pre-restart chunk flush")
    first_process = process_metrics()
    stop_backend()
    first_flushes = json.loads(rows("SELECT capture FROM sessions WHERE id=?", (session,))[0]["capture"])["generation"]
    old_rows = {row["id"]: row["samples"] for row in chunks() if row["capture_epoch"] == old_epoch}
    assert start_backend() == session, "demo session changed on restart"
    assert manifest()["capture"]["epoch"] != old_epoch, "restart reused capture epoch"
    feed_dns()
    download(False)
    restart_end = int(time.time()*1000)//5000*5000
    wait_for(lambda: chunk_totals(chunks())[3] >= before_restart[3]+2*128*1024, description="post-restart bytes")
    assert {row["id"]: row["samples"] for row in chunks() if row["capture_epoch"] == old_epoch} == old_rows, "restart removed or changed previous epoch samples"
    report["restart_within_same_chunk"] = restart_start == restart_end
    if report["restart_within_same_chunk"]:
        epochs = {row["capture_epoch"] for row in chunks() if row["start_ms"] == restart_start}
        assert len(epochs) == 2, epochs
    wait_for(lambda: chunks() and all(row["sealed"] for row in chunks()), timeout=15, description="post-restart seal")
    stage("restart_preserved_capture_epochs")

    current = manifest()
    start, end = current["started_ms"], int(time.time()*1000)
    series, map_pages = pages("map", start, end, 1)
    full, full_pages = pages("map", start, end, 1000)
    assert len(map_pages) > 1, "fixture did not exercise pagination"
    assert len({row["id"] for row in series}) == len(series), "duplicate page records"
    assert chunk_totals(series) == chunk_totals(full) == chunk_totals(chunks()), (chunk_totals(series), chunk_totals(full), chunk_totals(chunks()))
    totals = chunk_totals(series)
    assert totals[0] >= totals[2] > 0 and totals[1] >= totals[3] >= report["download_payload_bytes"], totals
    blocks, block_pages = pages("blocks", start, end, 1)
    assert blocks and all(block["service_label"] == "svt.se" for block in blocks), blocks
    assert any(not block["provisional"] for block in blocks), blocks
    assert all(block["active_ms"] <= block["end_ms"]-block["start_ms"] for block in blocks), blocks
    assert sum(block["sent"] for block in blocks) <= totals[0] and sum(block["received"] for block in blocks) <= totals[1], "block allocation duplicated bytes"
    for block in blocks:
        detail = request("/api/infrareveal/sessions/"+session+"/blocks/"+block["id"])
        assert detail["id"] == block["id"]
    measured = []
    for _ in range(10):
        at = time.monotonic()
        pages("map", start, end, 1000)
        measured.append((time.monotonic()-at)*1000)
    current = manifest()
    assert current["capture"]["dropped"] == 0, current["capture"]
    process = process_metrics()
    process["peak_rss_kib"] = max(process["peak_rss_kib"], first_process["peak_rss_kib"])
    for key in ("cpu_seconds", "process_write_bytes"):
        process[key] += first_process[key]
    elapsed = time.monotonic()-started
    flushes = first_flushes+current["capture"]["generation"]
    report.update(process)
    report.update({"capture_flushes": flushes, "capture_flushes_per_second": flushes/elapsed, "cpu_percent_one_core": process["cpu_seconds"]*100/elapsed})
    report.update({"session": session, "application_collections": collection_names(), "before": baseline, "after": storage_metrics(expected), "wire_sent": totals[0], "wire_received": totals[1], "payload_sent": totals[2], "payload_received": totals[3], "packets_sent": totals[4], "packets_received": totals[5], "map_pages": len(map_pages), "block_pages": len(block_pages), "coverage_quality": dict(collections.Counter(row["quality"] for row in rows("SELECT quality FROM capture_intervals"))), "capture": current["capture"], "map_latency_ms": {"samples": len(measured), "mean": sum(measured)/len(measured), "max": max(measured)}, "elapsed_seconds": time.monotonic()-started, "limitations": "Disposable Docker fixture on the stated platform, using virtual interfaces. Does not validate physical Wi-Fi, Internet visibility, production throughput or a long retention soak. Correction/quiet-gap policy shortened to 2s/1s to exercise transitions."})
    (results/"manifest.json").write_text(json.dumps(current, indent=2)+"\n")
    (results/"map-pages.json").write_text(json.dumps(map_pages, indent=2)+"\n")
    (results/"blocks.json").write_text(json.dumps(blocks, indent=2)+"\n")
    stop_backend()
    with sqlite3.connect(data_dir/"data.db") as source, sqlite3.connect(results/"fixture.db") as target:
        source.backup(target)
    report["passed"] = True
    (results/"report.json").write_text(json.dumps(report, indent=2)+"\n")
    stage("passed")
    print(json.dumps(report, indent=2), flush=True)
except BaseException as error:
    report.update({"passed": False, "error": str(error), "elapsed_seconds": time.monotonic()-started})
    (results/"report.json").write_text(json.dumps(report, indent=2)+"\n")
    raise
finally:
    stop_backend()
    if server is not None:
        server.terminate()
        server.wait(timeout=5)
    log.close()
    # PocketBase prints a one-time bootstrap token even in this isolated fixture.
    # It is irrelevant to the evidence, so omit that line from saved logs.
    log_path = results/"backend.log"
    log_path.write_text("".join(line for line in log_path.read_text().splitlines(True) if "/pbinstall/" not in line))
    server_log.close()
PY
