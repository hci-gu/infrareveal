# Proxy Lab Raspberry Pi Validation

Run this on the minimum supported 64-bit Raspberry Pi with dedicated clients and controlled traffic. Local/macOS results are development evidence only; do not check the target-Pi acceptance box until the completed measurement table is attached to a release.

## Automated preflight

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm build
pnpm lint

(cd pocketbase && go test -count=1 ./...)
(cd pocketbase && go test -race ./debugtrace ./labgate ./netmeta)
./scripts/test-entrypoint.sh
sudo ./scripts/test-lab-gate-netns.sh
docker compose build proxy dashboard debug-dashboard
```

The namespace script proves baseline/queue-bypass forwarding, delayed accept, explicit drop, listener-kill recovery, and repeatable cleanup without touching the physical AP. Run it before every Pi trial. `shellcheck` is used automatically when installed.

## Capability and privacy preflight

Record:

```bash
uname -a
docker version
docker compose version
lsmod | grep -E 'nfnetlink_queue|nf_conntrack'
iptables --version
ipset --version
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max
```

Start with `LAB_GATE_ENABLED=false`; verify normal forwarding and that no `INFRAREVEAL_LAB*` chain/set remains. Enable support with an empty client set; verify status separately reports supported/listener/rules/off. Search the database export and logs for a unique marker sent only in a controlled HTTP body; it must not occur. Search browser history, logs, screenshots, `gate_events`, and exports for the control token; it must not occur. Confirm unauthenticated and wrong-origin control mutations return 401/403.

## Thirty-client, 60-minute matrix

Use up to 30 controlled/consented devices or reproducible network-namespace clients. Warm up for five minutes, then run 60 minutes with a mix of browsing, video, messaging, background, idle, DNS, and QUIC traffic.

Repeat four scenarios:

1. Passive metadata with debug trace disabled.
2. Passive trace enabled with no debug viewer.
3. Passive trace with one then several viewers.
4. Flow gate armed for one client while the other 29 bypass.

Sample once per minute:

```bash
docker stats --no-stream proxy dashboard debug-dashboard
curl -sS http://127.0.0.1:8090/api/infrareveal/debug-trace/status
curl -sS http://127.0.0.1:8090/api/infrareveal/lab-gate/status
du -b data/data.db
```

| Pi/OS/build | Scenario | CPU avg/peak | RSS warm/peak/end | RTT p50/p95 | Throughput | Trace/audit/kernel drops | DB growth/hour |
|---|---|---:|---:|---:|---:|---:|---:|
| _record_ | trace off | | | | | | |
| _record_ | trace/no viewer | | | | | | |
| _record_ | trace/viewers | | | | | | |
| _record_ | one gated/29 bypass | | | | | | |

Accept only if buffers remain within configured bounds, RSS plateaus after warm-up, passive capture introduces no forwarding wait, bypass clients show no material regression, and every drop creates an incomplete/gap/audit warning.

## Gate failure matrix

For each case record status before/during/after and a simultaneous request from an ungated client:

- Reach pending-flow cap; the next new flow must accept and increment overflow.
- Reach held-packet cap; the next packet must accept and increment overflow.
- Leave decisions untouched; watchdog must accept them as `expired`, not `approved`.
- Close all viewers; watchdogs remain independent of the UI.
- Kill the Go process; `--queue-bypass` preserves forwarding.
- Send SIGTERM to the container; held packets drain and both jumps/chains/set disappear.
- Make PocketBase persistence unavailable; verdicts continue and audit loss is visible.
- Rename/remove the AP interface before arming; the controller must not leave partial membership.
- End the active session; it automatically drains/disarms.
- Reboot after unclean power loss; startup removes stale rules before recreating empty chains.
- Run cleanup twice; the second pass succeeds without remaining resources.

## Mode/client matrix

Test Chromium desktop, Firefox desktop, Safari desktop/iOS, Android Chromium, and a Linux CLI using `curl`, `dig`, and the controlled page at `/controlled-client`. For each, record visible three-second flow pause, resolver retries, QUIC fallback, Happy Eyeballs alternate connections, application timeout, and connection pooling. Use an HTTP IP target with QUIC disabled for strict TCP mechanics; use a hostname for DNS. Holds beyond ordinary client patience belong only to the controlled CLI/client.

Strict acceptance requires exact tuple rules to catch both directions and no neighbouring tuple; individual retransmissions remain separate; 500 ms watchdog prevents retention; FIN/RST disarms. DNS acceptance requires selected UDP and TCP/53 to wait/release/reach dnsmasq while another client, DHCP, dashboard, and control API remain unaffected.

| Client/build | 3 s flow pause | DNS retry | QUIC fallback | Happy Eyeballs | Observed timeout/deviation |
|---|---|---|---|---|---|
| Chromium desktop | | | | | |
| Firefox desktop | | | | | |
| Safari/iOS | | | | | |
| Android Chromium | | | | | |
| Linux CLI | | | n/a | configurable | |

## Final acceptance

- All automated suites and namespace tests pass on the candidate commit.
- Target Pi completes every 60-minute scenario without monotonic memory growth or hidden loss.
- Controller/browser/storage/process failure cannot strand selected or bypass traffic.
- No content-bearing payload or bearer token is persisted or logged.
- Recorded and live rendering agree at the same timestamp; rate changes do not change event existence.
- Production dashboard remains green and contains no Proxy Lab controls.
- Completed tables, logs, configuration, and deviations are attached to the release evidence.
