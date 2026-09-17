#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('preflight', Path(__file__).with_name('gateway-preflight.py'))
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.env = dict(AP_IFACE='wlan0', ADMIN_IFACE='wlan1', INTERNET_IFACE='eth0',
                        AP_PREFIX='10.0.0', ADMIN_PREFIX='10.77.0', SSID='Infrareveal',
                        ADMIN_SSID='Infrareveal-admin', WIFI_COUNTRY='SE', AP_CHANNEL='1', ADMIN_CHANNEL='6')

    def test_dhcp_uplink_and_existing_ap_routes_are_accepted(self):
        preflight.validate(self.env, [dict(dst='default', dev='eth0'),
                                     dict(dst='192.168.10.0/24', dev='eth0'),
                                     dict(dst='10.0.0.0/24', dev='wlan0'),
                                     dict(dst='10.77.0.0/24', dev='wlan1')])

    def test_uplink_collision_including_broader_routes_is_rejected(self):
        for prefix in ('10.0.0.0/24', '10.77.0.0/24', '10.0.0.0/8'):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, 'overlaps route'):
                preflight.validate(self.env, [dict(dst=prefix, dev='eth0')])

    def test_bad_settings_are_rejected(self):
        for key, value in [('ADMIN_PREFIX', '10.0.0'), ('AP_PREFIX', '8.8.8'),
                           ('ADMIN_IFACE', 'eth0'), ('SSID', 'name\nwpa=0'),
                           ('ADMIN_CHANNEL', '0'), ('WIFI_COUNTRY', 'SE\n')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                preflight.validate(dict(self.env, **{key: value}), [])


if __name__ == '__main__':
    unittest.main()
