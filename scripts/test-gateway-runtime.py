#!/usr/bin/env python3
"""Exercise the runtime processes against a changing, simulated Linux network."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name('gateway-runtime.py')


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / 'state.json'
        for name in ('ip', 'iw', 'curl', 'wget'):
            path = self.root / name
            path.write_text(f'#!{sys.executable}\n' + '''
import json, os, pathlib, sys
state = json.loads(pathlib.Path(os.environ['NETWORK_STATE']).read_text())
name = pathlib.Path(sys.argv[0]).name
if name == 'ip':
    if sys.argv[1] == '-j':
        print(json.dumps(state['interfaces']))
    elif sys.argv[1:4] == ['-4', 'addr', 'flush']:
        for item in state['interfaces']:
            if item['ifname'] == sys.argv[-1]:
                item['addr_info'] = []
    elif sys.argv[1:3] == ['addr', 'add']:
        for item in state['interfaces']:
            if item['ifname'] == sys.argv[-1]:
                address, prefix = sys.argv[3].split('/')
                item['addr_info'] = [dict(family='inet', local=address, prefixlen=int(prefix))]
    if sys.argv[1] != '-j':
        path = pathlib.Path(os.environ['NETWORK_STATE'])
        temp = path.with_suffix('.ip.tmp')
        temp.write_text(json.dumps(state))
        temp.replace(path)
elif name == 'iw':
    print(state.get('iw', 'Interface wlan0\\n type AP\\nInterface wlan1\\n type AP'))
elif name in ('curl', 'wget'):
    sys.exit(state.get('api_exit', 0))
''')
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                        NETWORK_STATE=str(self.state), AP_IFACE='wlan0', ADMIN_IFACE='wlan1',
                        AP_PREFIX='10.0.0', ADMIN_PREFIX='10.77.0')
        self.interfaces = [self.interface('wlan0', 3, '10.0.0.1'),
                           self.interface('wlan1', 4, '10.77.0.1')]
        self.save()

    @staticmethod
    def interface(name, index, address):
        return dict(ifname=name, ifindex=index, flags=['UP'],
                    addr_info=[dict(family='inet', local=address, prefixlen=24)])

    def save(self, **extra):
        temp = self.state.with_suffix('.tmp')
        temp.write_text(json.dumps(dict(interfaces=self.interfaces, **extra)))
        temp.replace(self.state)

    def start(self, mode):
        process = subprocess.Popen([sys.executable, str(SCRIPT), mode, '--interval', '0.05'],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True)
        self.addCleanup(self.stop, process)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=3)

    def ready(self, process, marker):
        # A bounded read lets failures terminate the test rather than hang CI.
        import selectors
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(3), 'runtime did not report its state')
            self.assertIn(marker, process.stdout.readline())

    def test_late_insertion_after_startup(self):
        adapter = self.interfaces.pop()
        self.save()
        process = self.start('wait')
        self.ready(process, 'Waiting')
        time.sleep(0.15)
        self.assertIsNone(process.poll())
        self.interfaces.append(adapter)
        self.save()
        self.assertEqual(process.wait(timeout=3), 0)

    def test_removal_triggers_recovery_even_when_api_is_healthy(self):
        process = self.start('watch')
        self.ready(process, 'Monitoring')
        self.interfaces.pop()
        self.save()
        self.assertEqual(process.wait(timeout=3), 1)
        self.assertIn('wlan1', process.stdout.read())
        self.assertEqual(self.start('health').wait(timeout=3), 1)

    def test_rapid_replug_with_same_name_triggers_recovery(self):
        process = self.start('watch')
        self.ready(process, 'Monitoring')
        self.interfaces[1]['ifindex'] = 8
        self.save()
        self.assertEqual(process.wait(timeout=3), 1)

    def test_address_loss_triggers_recovery(self):
        process = self.start('watch')
        self.ready(process, 'Monitoring')
        self.interfaces[1]['addr_info'] = []
        self.save()
        self.assertEqual(process.wait(timeout=3), 1)

    def test_health_requires_both_access_points_and_api(self):
        self.assertEqual(self.start('health').wait(timeout=3), 0)
        self.save(iw='Interface wlan0\n type AP\nInterface wlan1\n type managed')
        self.assertEqual(self.start('health').wait(timeout=3), 1)
        self.save(api_exit=7)
        self.assertEqual(self.start('health').wait(timeout=3), 1)

    def test_shutdown_while_waiting(self):
        self.interfaces.pop()
        self.save()
        process = self.start('wait')
        self.ready(process, 'Waiting')
        process.terminate()
        self.assertEqual(process.wait(timeout=3), -15)

    def entrypoint_fixture(self):
        # Run the real shell supervisor. Only host paths and hardware/daemon
        # commands are substituted; wait, traps, child PIDs and exits are real.
        repo = SCRIPT.parent.parent
        scripts = self.root / 'scripts'
        scripts.mkdir()
        shutil.copy(SCRIPT, scripts / SCRIPT.name)
        (scripts / 'gateway-preflight.py').write_text('pass\n')
        (scripts / 'gateway-network.sh').write_text('''
network_defaults() { export CONFIG_DIR="$FIXTURE_ROOT/config"; }
write_network_configs() { :; }
configure_firewall() { :; }
remove_legacy_rules() { :; }
''')
        for name in ('iptables', 'ipset'):
            command = self.root / name
            command.write_text('#!/bin/sh\nexit 1\n')
            command.chmod(0o755)
        (self.root / 'pb').mkdir()
        for name in ('hostapd', 'dnsmasq', 'pb/infra-reveal'):
            command = self.root / name
            command.write_text(f'#!{sys.executable}\n' + '''
import os, pathlib, signal, time
path = pathlib.Path(os.environ['FIXTURE_ROOT']) / ('daemon-' + str(os.getpid()))
path.write_text('running')
def stop(*args):
    path.write_text('stopped')
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
while True: time.sleep(0.05)
''')
            command.chmod(0o755)
        self.entrypoint = self.root / 'entrypoint.sh'
        self.entrypoint.write_text(repo.joinpath('entrypoint.sh').read_text()
                                  .replace('/root/', str(self.root) + '/')
                                  .replace('/proc/sys/net/ipv4/ip_forward', str(self.root / 'ip_forward')))

    def start_entrypoint(self):
        process = subprocess.Popen(['bash', str(self.entrypoint)],
                                   env=dict(self.env, FIXTURE_ROOT=str(self.root)),
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.addCleanup(self.stop, process)
        return process

    def await_daemons(self, count):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            running = [p for p in self.root.glob('daemon-*') if p.read_text() == 'running']
            if len(running) == count:
                return running
            time.sleep(0.05)
        self.fail(f'Expected {count} running daemons, got {len(running)}')

    def test_supervisor_recovers_after_removal_and_late_reinsertion(self):
        self.entrypoint_fixture()
        process = self.start_entrypoint()
        self.await_daemons(4)
        adapter = self.interfaces.pop()
        self.save()
        self.assertEqual(process.wait(timeout=5), 1)
        self.await_daemons(0)
        # Emulate restart: always. A missing USB device must wait rather than
        # repeatedly exit, and replugging must reconfigure its missing address.
        process = self.start_entrypoint()
        self.ready(process, 'Waiting')
        self.assertIsNone(process.poll())
        adapter['ifindex'] = 9
        adapter['addr_info'] = []
        self.interfaces.append(adapter)
        self.save()
        self.await_daemons(4)
        self.assertEqual(self.start('health').wait(timeout=3), 0)
        process.terminate()
        self.assertEqual(process.wait(timeout=3), 0)
        self.await_daemons(0)

    def test_supervisor_stops_cleanly_while_usb_is_missing(self):
        self.entrypoint_fixture()
        self.interfaces.pop()
        self.save()
        process = self.start_entrypoint()
        self.ready(process, 'Waiting')
        process.terminate()
        self.assertEqual(process.wait(timeout=3), 0)
        self.await_daemons(0)

    def test_dashboard_waits_until_gateway_is_ready(self):
        self.save(api_exit=7)
        process = subprocess.Popen(['sh', str(SCRIPT.with_name('wait-for-gateway.sh'))],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True)
        self.addCleanup(self.stop, process)
        self.ready(process, 'Waiting for gateway networking')
        time.sleep(0.15)
        self.assertIsNone(process.poll())
        self.save(api_exit=0)
        self.assertEqual(process.wait(timeout=5), 0)


if __name__ == '__main__':
    unittest.main()
