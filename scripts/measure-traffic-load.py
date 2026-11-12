#!/usr/bin/env python3
"""Read-only API workload and resource evidence. Never modifies a recording."""
import argparse
import json
import time
import urllib.request
import urllib.parse
import sys
from pathlib import Path


def get(url):
    started = time.monotonic()
    with urllib.request.urlopen(url, timeout=30) as response:
        body = response.read()
    return json.loads(body), (time.monotonic() - started) * 1000, len(body)


def window(url, session, start, end, resolution, compact=True):
    cursor, pages, elapsed, size, rows = '', 0, 0, 0, 0
    totals = dict.fromkeys(['sent', 'received', 'payloadSent', 'payloadReceived', 'packetsSent', 'packetsReceived'], 0)
    while True:
        query = urllib.parse.urlencode(dict(from_=start)).replace('from_=', 'from=')
        query += '&' + urllib.parse.urlencode(dict(to=end, resolution=resolution, compact=str(compact).lower(), cursor=cursor))
        page, ms, count = get(f'{url}/api/infrareveal/sessions/{session}/map?{query}')
        pages += 1
        elapsed += ms
        size += count
        for chunk in page['series']:
            rows += 1
            for sample in chunk['samples']:
                for i, key in enumerate(totals, 1):
                    totals[key] += sample[i]
        cursor = page.get('next_cursor')
        if not cursor:
            assert page['complete'], 'incomplete response without continuation'
            return dict(pages=pages, ms=round(elapsed, 2), bytes=size, rows=rows, **totals)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8092')
    parser.add_argument('--output', required=True)
    parser.add_argument('--samples', type=int, default=1)
    parser.add_argument('--interval', type=float, default=60)
    parser.add_argument('--window-seconds', type=int, default=300)
    parser.add_argument('--resolution', type=int, default=1000)
    parser.add_argument('--pid', type=int)
    parser.add_argument('--database')
    parser.add_argument('--stop-on-ended', action='store_true')
    parser.add_argument('--source-stats', help='optional offered-load meter file from the isolated generator')
    parser.add_argument('--expected', help='workload.json for exact recorded-fixture totals')
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    failed = False
    for sample in range(args.samples):
        row = dict(sample=sample, at=time.time())
        try:
            sessions, _, _ = get(args.url + '/api/infrareveal/sessions')
            session = next(s for s in sessions['items'] if s['name'].startswith('Load fixture'))
            manifest, _, _ = get(f"{args.url}/api/infrareveal/sessions/{session['id']}/manifest")
            end = manifest['capture']['confirmed_ms'] if manifest['active'] else manifest['ended_ms']
            start = max(manifest['retained_from_ms'], end - args.window_seconds * 1000)
            row.update(capture=manifest['capture'], lag_ms=manifest['server_ms']-end, retained_from_ms=manifest['retained_from_ms'])
            if end > start:
                row['window'] = window(args.url, session['id'], start, end, args.resolution)
                if args.expected:
                    expected = json.loads(Path(args.expected).read_text())
                    assert start == expected['start_ms'] and end == expected['end_ms']
                    for key in ['sent', 'received', 'payloadSent', 'payloadReceived', 'packetsSent', 'packetsReceived']:
                        if key in expected:
                            assert row['window'][key] == expected[key], (key, row)
            if args.source_stats:
                row['source'] = json.loads(Path(args.source_stats).read_text())
            if args.pid:
                status = Path(f'/proc/{args.pid}/status').read_text().splitlines()
                row['memory'] = {line.split(':')[0]: line.split(':')[1].strip() for line in status if line.startswith(('VmRSS:', 'VmHWM:'))}
                row['cpu'] = Path(f'/proc/{args.pid}/stat').read_text().split()[13:15]
            if args.database:
                row['storage'] = {suffix or 'db': Path(args.database+suffix).stat().st_size if Path(args.database+suffix).exists() else 0 for suffix in ['', '-wal', '-shm']}
        except Exception as error:
            row['error'] = str(error)
            failed = True
        with open(args.output, 'a') as output:
            output.write(json.dumps(row) + '\n')
        print(json.dumps(row), flush=True)
        if args.stop_on_ended and not row.get('capture', {}).get('running', True) and row.get('source', {}).get('ended_ms', 0):
            break
        if sample + 1 < args.samples:
            time.sleep(args.interval)
    if failed:
        sys.exit(1)


if __name__ == '__main__':
    main()
