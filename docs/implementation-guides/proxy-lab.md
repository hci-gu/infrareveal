# Proxy Lab Implementation and Operator Guide

## Status and boundaries

Implemented in the debug dashboard and PocketBase proxy. The regular dashboard consumes the shared session state, including durable gate events, but contains no traffic-control UI. The gate is disabled by default, IPv4-only, metadata-only, and intended for consented lab demonstrations.

Two independent planes share timestamps and canonical flow keys:

```text
data plane:        client -> optional NFQUEUE gate -> FORWARD/NAT or local dnsmasq -> remote
observation plane: AF_PACKET/conntrack/dnsmasq -> bounded trace hub + PocketBase -> shared state -> Remotion
```

Remotion is a deterministic view of the shared millisecond session cursor. Recorded PocketBase events and bounded live SSE events project into the same `PipelineEvent` contract. Scrubbing changes only the visualization; it never rewinds the current gate controller. “Go live” returns the shared clock to the latest observed edge.

## Runtime components

- `pocketbase/debugtrace`: non-blocking event/burst ingress, coalescing, sequence IDs, time/count-bounded ring, per-subscriber buffers, gap messages, and SSE reconnect.
- `pocketbase/netmeta`: bounded IPv4/TCP/UDP header parsing, canonical tuple, and direction.
- `pocketbase/labgate`: serialized policy controller, three NFQUEUE adapters behind a virtual-ID multiplexer, idempotent firewall manager, watchdogs, bounded audit writer, and authenticated routes.
- `packages/session-state`: shared PocketBase transport, normalized entities, temporal indexes, bounded detail-page cache, realtime reconciliation, and one playback clock for both dashboards.
- `debug-dashboard/src/experiments/proxy-lab`: recorded/live merge, deterministic scene projection, Remotion player, health, arming, and current approval queue.
- `/controlled-client`: browser probe for comparing queue wait with application-visible completion/failure.

No stored record contains packet payload contents or the control token. Strict events contain only tuple, direction, wire/payload byte counts, flags, timing, and verdict. The parser may receive a maximum 256-byte prefix from NFQUEUE and releases that reference after synchronous classification.

## Control lifecycle and APIs

`OFF -> ARMING -> ACTIVE -> DRAINING -> OFF`; listener failure enters `DEGRADED` and fails open. Pause accepts new arrivals while existing decisions remain. Drain accepts existing decisions and remains armed/paused. Disarm drains, empties the client set, and enters OFF. Session deactivation automatically disarms.

Public health:

```text
GET /api/infrareveal/lab-gate/status
```

Bearer-authenticated controls:

```text
GET  /api/infrareveal/lab-gate/pending
POST /api/infrareveal/lab-gate/arm
POST /api/infrareveal/lab-gate/pause
POST /api/infrareveal/lab-gate/resume
POST /api/infrareveal/lab-gate/drain
POST /api/infrareveal/lab-gate/disarm
POST /api/infrareveal/lab-gate/decisions/:decisionID
POST /api/infrareveal/lab-gate/approve-all
POST /api/infrareveal/lab-gate/strict/accept-next
```

Mutations require JSON, reject unknown fields and oversized bodies, are rate-limited, and return a request ID. Repeating a terminal decision returns HTTP 409 with the terminal result so the UI can reconcile. Status includes listener/rule readiness, queue/drop/bypass/watchdog/audit counters, effective deadlines, and read-only target-kernel settings.

## Mode semantics

### Flow gate

Queue 42 matches selected AP-to-uplink TCP/UDP in conntrack NEW state. A TCP packet must be SYN to create a decision. UDP and retransmissions group by protocol, client IP/port, and remote IP/port. Approve/drop applies to all attached packet IDs; overflow and watchdog accept are visibly `bypassed`/`expired`, never operator approvals.

Suggested preset: **Visible pause**. Use the default ten-second safety watchdog and decide around three seconds. This provides a visible client delay without claiming a universal application timeout.

### Strict packet gate

Queue 43 requires exactly one client and complete protocol/client-port/remote-IP/remote-port tuple. Exact rules match both AP-to-uplink and uplink-to-AP directions. Each packet remains a separate decision, including retransmissions. Use approve/drop, Accept next N, or Drain held. TCP FIN/RST terminal handling automatically disarms once no packet remains. Default safety watchdog is 500 ms.

Suggested presets: **Strict handshake** for a controlled HTTP/TCP target, or **Retry demonstration** with the controlled client. Disable QUIC and use one address family when the lesson depends on TCP timing. Do not extend global defaults to compensate for one browser.

### DNS gate

Queue 44 matches selected AP INPUT UDP/53 and NEW TCP/53 before local dnsmasq. The gate never parses the DNS payload; after approval, the normal dnsmasq record can provide the query label. DHCP, dashboard/control traffic, and unrelated forwarding do not match.

Suggested preset: **DNS retry**. Use a hostname in the controlled client and release before the two-second watchdog. OS/browser resolver caches and encrypted DNS can bypass the visible query; document that observation instead of presenting it as failure.

## Safe first run

1. Run the automated and Linux namespace suites in the validation guide.
2. Generate a token without putting it in shell history where possible:

   ```bash
   install -m 600 /dev/null data/lab-gate.token
   openssl rand -base64 48 > data/lab-gate.token
   ```

3. Mount that file read-only at `/run/secrets/infrareveal-lab-token` and set:

   ```text
   DEBUG_TRACE_ENABLED=true
   LAB_GATE_ENABLED=true
   LAB_GATE_FAIL_OPEN=true
   LAB_GATE_CONTROL_TOKEN_FILE=/run/secrets/infrareveal-lab-token
   LAB_GATE_ALLOWED_ORIGINS=http://PI_ADDRESS:8081
   ```

   Add the mount to a local Compose override (do not commit the token):

   ```yaml
   services:
     proxy:
       volumes:
         - ./data/lab-gate.token:/run/secrets/infrareveal-lab-token:ro
   ```

4. Start the proxy and debug dashboard. Confirm status is `off`, `supported`, `listenerReady`, `rulesReady`, fail-open, zero clients, and normal browsing still works.
5. Start one active session. Open `/proxy-lab/SESSION_ID`, select Turn based, enter the token, select exactly one controlled client, acknowledge the warning, and arm.
6. Generate one request from that client. Approve it before the watchdog, verify the client continues, then Drain and Emergency disarm.
7. Confirm normal browsing, an empty `infrareveal_lab_clients` set, and a durable `gate_events` record.

Enabling passive tracing alone requires only `DEBUG_TRACE_ENABLED=true`. Enabling gate support without arming uses `LAB_GATE_ENABLED=true`; queue listeners and empty return-only chains are ready, but no IP is in the set and no client packet is queued.

## Command-line controls

Use the token in an environment variable read from the file, never in a URL:

```bash
LAB_TOKEN="$(<data/lab-gate.token)"
BASE=http://127.0.0.1:8090/api/infrareveal/lab-gate
curl -sS "$BASE/status"
curl -sS -H "Authorization: Bearer $LAB_TOKEN" "$BASE/pending"
curl -sS -X POST -H "Authorization: Bearer $LAB_TOKEN" -H 'Content-Type: application/json' "$BASE/drain" -d '{"actor":"cli"}'
curl -sS -X POST -H "Authorization: Bearer $LAB_TOKEN" -H 'Content-Type: application/json' "$BASE/disarm" -d '{"actor":"cli"}'
unset LAB_TOKEN
```

Interpret counters conservatively: queue/held/pending are current pressure; kernel/user drops mean netlink loss; overflow is immediate fail-open due to bounds; watchdog is safety expiry; parse bypass is an unsupported/malformed header accepted immediately; audit drops mean the durable trail is incomplete; trace gaps affect visualization only.

## Emergency recovery

If the UI is unavailable, call `drain` then `disarm` with curl. If the controller is unavailable, stop the proxy; every NFQUEUE rule has `--queue-bypass`. The entrypoint removes stale resources at both startup and shutdown. Manual cleanup is idempotent:

```bash
while iptables -w -C FORWARD -j INFRAREVEAL_LAB 2>/dev/null; do iptables -w -D FORWARD -j INFRAREVEAL_LAB; done
while iptables -w -C INPUT -j INFRAREVEAL_LAB_DNS 2>/dev/null; do iptables -w -D INPUT -j INFRAREVEAL_LAB_DNS; done
iptables -w -F INFRAREVEAL_LAB 2>/dev/null || true
iptables -w -X INFRAREVEAL_LAB 2>/dev/null || true
iptables -w -F INFRAREVEAL_LAB_DNS 2>/dev/null || true
iptables -w -X INFRAREVEAL_LAB_DNS 2>/dev/null || true
ipset flush infrareveal_lab_clients 2>/dev/null || true
ipset destroy infrareveal_lab_clients 2>/dev/null || true
```

Then verify `iptables -S FORWARD`, `iptables -S INPUT`, `ipset list`, normal DNS, and a new HTTP request from the controlled client. Do not reboot as the first recovery action; retaining logs/counters helps explain the failure.

## Privacy and limitations

Use consented, dedicated devices and controlled targets. Do not paste tokens into URLs, screenshots, logs, PocketBase, or issue reports. The debug trace and gate can reveal IPs, ports, DNS-derived hostnames, byte timing, and operator decisions. They cannot see encrypted URLs/content, reliably identify an HTTP resource, freeze client-side timers, prevent retries, or guarantee identical behaviour across Chromium, Firefox, Safari/iOS, Android, or native apps.

Any trace drop, audit loss, unknown capture period, fail-open bypass, timeout, resolver deviation, QUIC fallback, or Happy Eyeballs alternate flow must remain visible in results and exported session interpretation.
