#!/usr/bin/env python3
"""Wait for USB radios, detect runtime loss, and check complete gateway health."""
import argparse
import json
import os
import re
import subprocess
import sys
import time


def command(*args):
    return subprocess.check_output(args, text=True, timeout=2)


def radios():
    return {
        os.environ.get('AP_IFACE', 'wlan0'): os.environ.get('AP_PREFIX', '10.0.0') + '.1',
        os.environ.get('ADMIN_IFACE', 'wlan1'): os.environ.get('ADMIN_PREFIX', '10.77.0') + '.1',
    }


def snapshot(require_addresses=True):
    interfaces = {item['ifname']: item for item in json.loads(command('ip', '-j', 'address', 'show'))}
    result = {}
    for name, address in radios().items():
        interface = interfaces.get(name)
        if interface is None:
            raise ValueError(f'Missing Wi-Fi interface {name}; check the USB adapter')
        if require_addresses:
            if 'UP' not in interface.get('flags', []):
                raise ValueError(f'Wi-Fi interface {name} is down')
            if not any(item.get('family') == 'inet' and item.get('local') == address
                       and item.get('prefixlen') == 24 for item in interface.get('addr_info', [])):
                raise ValueError(f'Wi-Fi interface {name} is missing {address}/24')
        result[name] = interface['ifindex']
    return result


def wait_for_radios(interval):
    previous_error = None
    while True:
        try:
            snapshot(require_addresses=False)
            return
        except ValueError as error:
            # Do not fill container logs while an adapter is unplugged for days.
            if str(error) != previous_error:
                print(f'Waiting for radios: {error}', flush=True)
                previous_error = str(error)
        time.sleep(interval)


def watch(interval):
    original = snapshot()
    print('Monitoring gateway Wi-Fi interfaces and addresses.', flush=True)
    while True:
        time.sleep(interval)
        current = snapshot()
        # Catch a remove/reinsert between polls, even with the same interface name.
        if current != original:
            raise ValueError('Wi-Fi interface was replaced; reinitializing the gateway')


def health():
    snapshot()
    interface = None
    access_points = set()
    for line in command('iw', 'dev').splitlines():
        match = re.match(r'\s*Interface (\S+)', line)
        if match:
            interface = match.group(1)
        elif line.strip() == 'type AP':
            access_points.add(interface)
    for name in radios():
        if name not in access_points:
            raise ValueError(f'Wi-Fi interface {name} is not an access point')
    command('curl', '--fail', '--silent', '--show-error', '--max-time', '2',
            'http://127.0.0.1:8090/api/health')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('wait', 'watch', 'health'))
    parser.add_argument('--interval', type=float, default=2)
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error('--interval must be positive')
    try:
        if args.mode == 'wait':
            wait_for_radios(args.interval)
        elif args.mode == 'watch':
            watch(args.interval)
        else:
            health()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f'Gateway network unavailable: {error}', file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
