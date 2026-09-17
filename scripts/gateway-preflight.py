#!/usr/bin/env python3
"""Validate before touching interfaces; reject overlapping uplink routes."""
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def validate(env, routes):
    interfaces = [env[key] for key in ('AP_IFACE', 'ADMIN_IFACE', 'INTERNET_IFACE')]
    if len(set(interfaces)) != 3 or any(not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', i) for i in interfaces):
        raise ValueError('AP_IFACE, ADMIN_IFACE and INTERNET_IFACE must be distinct interface names')
    networks = [ipaddress.IPv4Network(env[key] + '.0/24') for key in ('AP_PREFIX', 'ADMIN_PREFIX')]
    private = [ipaddress.IPv4Network(c) for c in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if any(not any(n.subnet_of(p) for p in private) for n in networks):
        raise ValueError('Use private IPv4 /24 prefixes for AP_PREFIX and ADMIN_PREFIX')
    if networks[0].overlaps(networks[1]):
        raise ValueError('Participant and admin subnets must differ')
    for route in routes:
        if route.get('dev') in interfaces[:2] or route.get('dst', 'default') == 'default':
            continue
        routed = ipaddress.ip_network(route['dst'], strict=False)
        if any(n.overlaps(routed) for n in networks):
            raise ValueError(f"Local subnet overlaps route {route['dst']} on {route.get('dev')}; change AP_PREFIX or ADMIN_PREFIX in .env")
    for key in ('SSID', 'ADMIN_SSID'):
        value = env[key]
        if not 1 <= len(value.encode()) <= 32 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(f'{key} must be 1–32 bytes without control characters')
    if not re.fullmatch('[A-Z]{2}', env['WIFI_COUNTRY']):
        raise ValueError('WIFI_COUNTRY must be a two-letter uppercase country code')
    for key in ('AP_CHANNEL', 'ADMIN_CHANNEL'):
        if env[key] not in [str(i) for i in range(1, 12)]:
            raise ValueError(f'{key} must be a 2.4 GHz channel from 1 through 11')


def main():
    env = os.environ
    routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'main']))
    validate(env, routes)
    for key in ('AP_IFACE', 'ADMIN_IFACE', 'INTERNET_IFACE'):
        if not Path('/sys/class/net', env[key]).exists():
            raise ValueError(f"Missing {key}={env[key]}; check the USB adapter and interface names")
    mac = env.get('ADMIN_WIFI_MAC', '')
    if mac and Path('/sys/class/net', env['ADMIN_IFACE'], 'address').read_text().strip().lower() != mac.lower():
        raise ValueError('ADMIN_IFACE does not match ADMIN_WIFI_MAC; check interface naming')
    password = Path(env['ADMIN_WIFI_PASSWORD_FILE']).read_text().removesuffix('\n')
    if not 8 <= len(password) <= 63 or any(ord(c) < 32 or ord(c) > 126 for c in password):
        raise ValueError('Admin Wi-Fi password must contain 8–63 printable ASCII characters on one line')
    phys = [Path('/sys/class/net', env[key], 'phy80211').resolve().name
            for key in ('AP_IFACE', 'ADMIN_IFACE')]
    if len(set(phys)) != 2:
        raise ValueError('This deployment requires two separate Wi-Fi radios')
    for key in ('AP_IFACE', 'ADMIN_IFACE'):
        iface = env[key]
        phy = Path('/sys/class/net', iface, 'phy80211').resolve().name
        capabilities = subprocess.check_output(['iw', 'phy', phy, 'info'], text=True)
        if not re.search(r'^\s*\* AP\s*$', capabilities, re.M):
            raise ValueError(f'{iface} does not advertise AP support')
    print('Gateway preflight passed: separate APs and non-overlapping subnets.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'Gateway preflight failed: {error}', file=sys.stderr)
        sys.exit(1)
