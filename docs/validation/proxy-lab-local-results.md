# Proxy Lab implementation validation — 2026-09-03

This record captures the validation completed in the implementation workspace. It is evidence for the code handoff, not a substitute for the physical Raspberry Pi and client-matrix procedure in [proxy-lab-raspberry-pi.md](proxy-lab-raspberry-pi.md).

## Automated suites

All of these commands completed successfully from a clean invocation after the final implementation edits:

```text
pnpm test
  session-state: 20 tests passed
  debug-dashboard: 62 tests passed
  dashboard: 3 tests passed

pnpm build
pnpm lint

cd pocketbase
go test ./...
go test -race ./debugtrace ./labgate ./netmeta
go vet ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...

scripts/test-entrypoint.sh
scripts/check-proxy-lab-privacy.sh
shellcheck -x entrypoint.sh scripts/*.sh

docker compose config --quiet
docker compose build proxy dashboard debug-dashboard
```

The two Vite builds report their existing large-chunk advisory; it is non-fatal and does not affect the experiment contract.

## Linux NFQUEUE integration

`scripts/test-lab-gate-netns.sh` passed in a disposable privileged Linux container using the Docker host kernel. The suite creates isolated client, gateway, and upstream namespaces and verifies:

- normal forwarding with queue bypass and no listener;
- a TCP connection remains held until the configured release;
- a drop verdict fails the selected connection;
- closing the queue listener while a packet is held restores forwarding;
- queue pressure remains fail-open;
- forwarding recovers after the controller exits;
- repeated namespace cleanup succeeds.

The platform-independent suite separately covers TCP/UDP grouping, exact strict tuples in both directions, DNS isolation, watchdogs, caps, verdict errors, session-end disarm, audit ordering/loss, authentication, CORS, and HTTP error mapping.

## PocketBase migration smoke

A copy of the existing `pocketbase/pb_data` was migrated and served on an isolated port with `--dev=false`. Health, `sessions`, and `gate_events` collection requests succeeded. The original data directory was not modified.

## Browser review

The debug dashboard was exercised with a real Chromium browser at 1440×1000 and 390×844:

- deterministic replay, frame controls, queue fixture, and graph topology rendered;
- replay, live-observe, flow, strict, and DNS modes were reachable;
- strict mode exposed exactly one-client selection and a complete tuple form;
- DNS mode showed its isolated traffic/safety explanation;
- the controlled-client route completed a local timed probe and reported its duration;
- the narrow layout retained an inspectable fixed graph and moved controls below it;
- two consecutive 1440×1000 fixture captures were byte-identical (`sha256 4a59340e…`);
- the browser console reported zero errors and zero warnings.

## Deployment validation still required

The following checks require hardware and client environments not present in this workspace and therefore remain deliberately unchecked in the implementation plan:

- the 30-client, 60-minute Raspberry Pi soak and resource baseline;
- real AP/uplink interface hook-order confirmation on the target image;
- physical bypass-client and unclean-reboot drills;
- end-to-end DNS approve/reject against the target dnsmasq instance;
- Chromium, Firefox, Safari/iOS, Android, and controlled CLI client timing comparisons.

Use [proxy-lab-raspberry-pi.md](proxy-lab-raspberry-pi.md) for the exact runbook and evidence table. Lab gating must remain disabled by default until that target validation is signed off.
