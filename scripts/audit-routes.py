#!/usr/bin/env python3
"""Read-only audit of the route evidence and probe admission ledger.

python3 scripts/audit-routes.py /tmp/recording-copy.db --session SESSION_ID
Requires the seven-collection schema. It never modifies the database.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import sqlite3


def parsed(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return value if isinstance(value, list) else []


def audit(db, session=None):
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required = {"sessions", "route_evidence", "probe_runs"}
    if not required <= tables:
        raise ValueError("requires the current schema; missing " + ", ".join(sorted(required - tables)))
    where, params = (" WHERE session=?", (session,)) if session else ("", ())
    evidence = [dict(row) for row in db.execute("SELECT * FROM route_evidence" + where, params)]
    runs = [dict(row) for row in db.execute("SELECT * FROM probe_runs" + where, params)]
    paths = [row for row in evidence if row["kind"] == "path"]
    attempts = Counter(row["attempt_id"] for row in paths)
    issues = Counter()
    for row in paths:
        hops = parsed(row["hops"])
        if not any(hop.get("address") or any(reply.get("address") for reply in hop.get("replies", [])) for hop in hops):
            issues["path_without_responders"] += 1
        if row["revision"] not in (1, 2):
            issues["invalid_path_revision"] += 1
        if not row["attempt_id"] or not row["binding_key"] or not row["network_epoch"]:
            issues["missing_path_identity"] += 1
        if row["valid_until_ms"] <= row["measured_ms"]:
            issues["invalid_path_expiry"] += 1
    issues["attempts_exceeding_two_publications"] = sum(count > 2 for count in attempts.values())
    collections = {}
    for name in ("route_evidence", "probe_runs"):
        count = size = 0
        for row in db.execute("SELECT * FROM " + name):
            count += 1
            size += len(json.dumps(dict(row)).encode())
        collections[name] = {"global_rows": count, "serialized_bytes": size}
    orphaned = db.execute("SELECT count(*) FROM probe_runs p WHERE NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id=p.session)").fetchone()[0]
    return {
        "session": session,
        "evidence_rows": len(evidence),
        "evidence_kinds": dict(Counter(row["kind"] for row in evidence)),
        "useful_path_publications": len(paths),
        "distinct_bindings": len({(row["session"], row["network_epoch"], row["binding_key"]) for row in paths}),
        "published_attempts": len(attempts),
        "distinct_path_fingerprints": len({row["fingerprint"] for row in paths}),
        "charged_evidence_bytes": sum(row["evidence_bytes"] for row in evidence),
        "admitted_attempts": len(runs),
        "manual_attempts": sum(bool(row["manual"]) for row in runs),
        "attempt_statuses": dict(Counter(row["status"] for row in runs)),
        "attempt_outcomes": dict(Counter(row["class"] or "pending" for row in runs)),
        "structural_issues": {key: count for key, count in issues.items() if count},
        "global_admissions_after_session_deletion": orphaned,
        "collections": collections,
        "database_allocated_bytes_including_indexes": db.execute("PRAGMA page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0],
        "limitations": "Publications are revisions, not distinct routes. Deleted-session admissions are retained deliberately for quota/cooldown enforcement. Serialized bytes differ from SQLite allocation; WAL is separate. Useful-path classification is not reconstructed by this audit.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--session")
    args = parser.parse_args()
    path = args.database.resolve(strict=True)
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        db.execute("BEGIN")
        result = audit(db, args.session)
        wal = Path(str(path) + "-wal")
        result["wal_bytes"] = wal.stat().st_size if wal.exists() else 0
        print(json.dumps(result, indent=2))
    except (ValueError, sqlite3.DatabaseError) as error:
        parser.error(str(error))
    finally:
        db.close()


if __name__ == "__main__":
    main()
