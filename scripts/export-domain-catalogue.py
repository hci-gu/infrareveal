#!/usr/bin/env python3
"""Export an atomic, identifier-free catalogue snapshot from the Pi's database."""
import argparse
import csv
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile

FIELDS = ("domain", "first_seen", "last_seen", "dns_count", "high_flow_count",
          "medium_flow_count", "low_flow_count", "hostnames", "cname_examples",
          "review_status", "proposed_group", "notes")


def export(database: Path, output: Path):
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
    connection.row_factory = sqlite3.Row
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT " + ",".join(FIELDS) + " FROM domain_catalogue ORDER BY domain")]
    finally:
        connection.close()
    for row in rows:
        for field in ("hostnames", "cname_examples"):
            row[field] = json.loads(row[field] or "[]")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=output.parent, delete=False) as target:
            temporary = Path(target.name)
            if output.suffix.lower() == ".csv":
                writer = csv.DictWriter(target, fieldnames=FIELDS)
                writer.writeheader()
                for row in rows:
                    writer.writerow({key: json.dumps(value, ensure_ascii=False) if isinstance(value, list) else value for key, value in row.items()})
            else:
                json.dump({"version": 1, "exportedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "domains": rows}, target, ensure_ascii=False, indent=2)
                target.write("\n")
        temporary.replace(output)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("data/data.db"))
    parser.add_argument("--output", type=Path, required=True, help="JSON or CSV file; replaced atomically")
    args = parser.parse_args()
    print(f"Exported {export(args.database, args.output)} domains to {args.output}")


if __name__ == "__main__":
    main()
