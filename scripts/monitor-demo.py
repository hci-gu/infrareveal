#!/usr/bin/env python3
"""Sample demo health and optional local database/RSS metrics as JSONL."""
import argparse
import datetime as dt
import json
from pathlib import Path
import sqlite3
import subprocess
import time
import urllib.request


def sample(url, database=None, pids=()):
    result = {"at": dt.datetime.now(dt.timezone.utc).isoformat()}
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/infrareveal/demo", timeout=10) as response:
            result["demo"] = json.load(response)
    except Exception as error:
        result["error"] = str(error)
    if database:
        try:
            with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=5) as connection:
                connection.execute("BEGIN")
                session = connection.execute("SELECT id FROM sessions WHERE demo=true").fetchone()
                if session:
                    result["rows"] = {table: connection.execute("SELECT count(*) FROM " + table + " WHERE session=?", session).fetchone()[0]
                                      for table in ("flows", "dns_queries", "flow_activity_chunks", "routes", "route_evidence_updates")}
                result["catalogueDomains"] = connection.execute("SELECT count(*) FROM domain_catalogue").fetchone()[0]
                result["databasePages"] = connection.execute("PRAGMA page_count").fetchone()[0]
                result["freePages"] = connection.execute("PRAGMA freelist_count").fetchone()[0]
            result["databaseBytes"] = database.stat().st_size
            wal = Path(str(database) + "-wal")
            result["walBytes"] = wal.stat().st_size if wal.exists() else 0
        except Exception as error:
            result["databaseError"] = str(error)
    if pids:
        result["rssKiB"] = {}
        for pid in pids:
            process = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=5)
            result["rssKiB"][str(pid)] = int(process.stdout.strip()) if process.stdout.strip() else None
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://10.77.0.1")
    parser.add_argument("--database", type=Path)
    parser.add_argument("--pid", type=int, action="append", default=[])
    parser.add_argument("--interval", type=float, default=60)
    parser.add_argument("--samples", type=int, default=4320, help="4320 samples at 60 seconds is about 72 hours")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.interval < 1 or args.samples < 1:
        parser.error("interval and samples must be positive (interval >= 1 second)")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("a", encoding="utf-8") as output:
        for i in range(args.samples):
            start = time.monotonic()
            output.write(json.dumps(sample(args.url, args.database, args.pid)) + "\n")
            output.flush()
            if i + 1 < args.samples:
                time.sleep(max(0, args.interval - (time.monotonic() - start)))


if __name__ == "__main__":
    main()
