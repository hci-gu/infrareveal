#!/usr/bin/env python3
"""Read-only route audit; optional exact-duplicate compaction of an offline COPY.

python3 scripts/audit-routes.py pocketbase/pb_data/data.db --session ID
python3 scripts/audit-routes.py /tmp/copy.db --compact --backup /tmp/before.db
Never opens the input writable unless --compact and a new --backup are supplied.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import sqlite3
from collections import Counter


def parsed(value, fallback):
    if not isinstance(value, str):
        return value if value is not None else fallback
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return fallback


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def responders(hop):
    return sorted({a for a in [hop.get('address'), *[r.get('address') for r in hop.get('replies', [])]] if a})


def audit(db, session=None):
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    rows = [dict(r) for r in db.execute('SELECT * FROM routes' + (' WHERE session=?' if session else ''), (session,) if session else ())]
    classes, paths, bindings, attempts = Counter(), set(), set(), set()
    cached_fingerprints = Counter()
    zero_reply = 0
    exact, removable, retained = {}, [], []
    payload_bytes = 0
    for r in rows:
        hops = parsed(r.get('hops'), []) or []
        observed = [(h.get('ttl'), responders(h)) for h in hops if responders(h)]
        zero_reply += not observed
        intermediate = [a for _, aa in observed for a in aa if a != r.get('destination_ip')]
        reached = bool(r.get('destination_reached') or r.get('complete'))
        # Access consensus cannot be safely reconstructed from arbitrary legacy
        # rows. Count local-only and use stored v2 classifications when present.
        public = any(ipaddress.ip_address(a).is_global for a in intermediate)
        kind = r.get('evidence_class') or ('useful_candidate' if intermediate and (public or reached) else 'access_only' if intermediate else 'endpoint_only' if reached else 'no_path')
        classes[kind] += 1
        binding = tuple(r.get(k) for k in ('session', 'destination_ip', 'protocol', 'destination_port', 'network_context'))
        bindings.add(binding)
        if r.get('attempt_id'):
            attempts.add(r['attempt_id'])
        material = digest([binding, r.get('method'), reached, observed])
        paths.add(material)
        if r.get('provenance') == 'cache':
            cached_fingerprints[material] += 1
        # Preserve *all* temporal, provenance, outcome and observation fields.
        # Only duplicate physical rows with identical evidence can be removed.
        signature = digest({k: v for k, v in r.items() if k not in ('id', 'created', 'updated')})
        if signature in exact:
            removable.append(r['id'])
        else:
            exact[signature] = r['id']
            retained.append(r['id'])
        payload_bytes += len(json.dumps(r).encode())
    collections = {}
    for name in ('routes', 'route_observations', 'route_cache', 'route_outcomes', 'route_budget_state', 'route_evidence_updates'):
        if name not in tables:
            continue
        records = db.execute('SELECT * FROM "' + name + '"')
        count = size = 0
        for record in records:
            count += 1
            size += len(json.dumps(dict(record)).encode())
        collections[name] = {'global_rows': count, 'serialized_bytes': size}
    physical = db.execute('PRAGMA page_count').fetchone()[0] * db.execute('PRAGMA page_size').fetchone()[0]
    return {'session': session, 'route_rows': len(rows), 'distinct_bindings': len(bindings), 'known_attempts': len(attempts),
            'material_fingerprints': len(paths), 'zero_reply_rows': zero_reply, 'repeated_cached_copies': sum(max(0,n-1) for n in cached_fingerprints.values()), 'classes': dict(classes), 'cached_rows': sum(r.get('provenance') == 'cache' for r in rows),
            'route_serialized_bytes': payload_bytes, 'database_allocated_bytes_including_indexes': physical,
            'collections': collections, 'exact_duplicate_rows': len(removable), 'retain_ids': retained, 'remove_ids': removable,
            'limitations': 'Legacy useful_candidate is provisional: no historical access consensus. Allocated bytes do not shrink without a separate VACUUM; WAL is reported separately.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path)
    parser.add_argument('--session')
    parser.add_argument('--compact', action='store_true', help='Delete only exact duplicates from an offline database copy')
    parser.add_argument('--backup', type=Path, help='Required new SQLite backup file before compaction')
    args = parser.parse_args()
    path = args.database.resolve(strict=True)
    if args.compact and (not args.backup or args.backup.exists()):
        parser.error('--compact requires a --backup path that does not already exist')
    db = sqlite3.connect(path.as_uri() + ('?mode=rw' if args.compact else '?mode=ro'), uri=True)
    db.row_factory = sqlite3.Row
    with db:
        if args.compact:
            # Lock out concurrent writers between backup, audit and deletion.
            db.execute('BEGIN IMMEDIATE')
            backup = sqlite3.connect(args.backup)
            reader = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
            reader.backup(backup)
            reader.close()
            backup.close()
        result = audit(db, args.session)
        wal = Path(str(path) + '-wal')
        result['wal_bytes'] = wal.stat().st_size if wal.exists() else 0
        if args.compact:
            db.executemany('DELETE FROM routes WHERE id=?', [(x,) for x in result['remove_ids']])
        result['compacted'] = args.compact
    print(json.dumps(result, indent=2))
    db.close()


if __name__ == '__main__':
    main()
