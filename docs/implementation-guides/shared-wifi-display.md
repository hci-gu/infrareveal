# Shared Wi-Fi and visiting display devices

The portable appliance runs the gateway and main dashboard on one Pi. Its
built-in Wi-Fi broadcasts `Infrareveal`; Ethernet supplies internet. Both the
display and participants join that Wi-Fi. Open `http://infrareveal.home.arpa`
(fallback `http://10.0.0.1`) and choose **Use this device as display**. The live
session opens at `/display`, or the most recent recording if none is active.
Ordinary dashboard visitors remain observable participants.

## Deployment

Use the normal host preparation/build/release procedure in
[Pi deployment](pi-deployment.md). This change has no database migration and
does not require fresh application data on an existing current-schema release.
Build updated gateway and dashboard images on the deployment/build machine;
the new gateway includes `pocketbase/displaymode`. Preserve data/GeoIP mounts.

For the existing Pi's stable interface name, set:

```dotenv
AP_IFACE=ir-ap
ADMIN_WIFI_ENABLED=false
DASHBOARD_ON_AP=true
COMPOSE_FILE=docker-compose.yml:compose.shared-wifi.yml
```

If using `compose.release.yml`, place it between those files and update its image
references to the newly built release. Replace the old `compose.proxy-only.yml`
entry. The shared override also resets old dashboard profiles if both overrides
are inadvertently present. Keep `COMPOSE_PROFILES=debug` only if the debug UI is
wanted. `docker compose up -d --no-build` then starts the gateway and dashboard.
Their restart policies restore services after a Pi reboot.

The Pi assigns its own AP address and local DNS record independently of the
venue's DHCP address. The firewall permits ports 80/8081 to the AP address on
the AP interface. Direct backend port 8090 remains inaccessible from Wi-Fi;
nginx forwards same-origin API requests and overwrites `X-Real-IP` with the
actual client address. The backend trusts that header only from loopback.
The existing Ethernet API allowance is unchanged. Optional admin Wi-Fi and
proxy-only modes remain available through explicit configuration.

The venue must provide usable Ethernet internet. Upstream authentication and
overlapping private subnets still need handling; preflight reports a subnet
collision rather than silently routing incorrectly. `AP_PREFIX` can be changed;
the local hostname follows it. IPv6 Wi-Fi forwarding remains disabled by the
existing firewall policy.

## Role lifecycle and observations

- Start resolves the HTTP client's current DHCP lease and registers its IP and
  Wi-Fi MAC. No permanent identity, fixed address or prior device list is needed.
- A per-tab session-storage token survives refresh. Multiple tabs explicitly
  choosing display mode share the device role. Renewal runs every 20 seconds;
  grace is three minutes, bounded by the DHCP lease expiry. The response includes
  a relative validity duration so browser/gateway clock differences do not
  create a false active status.
- Packet filtering checks the actual client MAC in both directions. DNS and
  conntrack sources check the current DHCP lease, so a replacement device cannot
  inherit an excluded IP. Renewal can follow an IP change for the same Wi-Fi MAC.
  A changed/private MAC requires choosing display mode again.
- Registration completes before `/display` mounts the map. Refresh also waits
  for renewal before mounting map resources. A temporary outage retains the
  exclusion through the grace period; after validity expires the UI removes the
  map and reports that exclusion could not be renewed.
- Stop invalidates the shared device token immediately, including other tabs'
  renewals. Closing a tab sends no stop request, because that would also fire on
  refresh; the role expires when all renewing tabs close. Roles are bounded to
  32 devices and stored only in memory. After expiry or a gateway restart the
  browser asks the operator to choose display mode again.
- The whole device's new traffic is excluded before counters, attribution,
  diagnostics, passive tracing and new traffic-driven route admissions. NAT and
  DNS service keep working. Earlier observations remain; probes already admitted
  for earlier participant traffic can finish. The bounded dnsmasq spool still
  receives resolver logs, but display queries do not enter observation records.
- Lab gate arming rejects display devices. Entering display mode releases that
  device's pending decisions and removes its kernel selection, leaving other
  participants selected. Previously held traffic retains its required terminal
  audit record. Stopping display mode does not automatically re-arm a device.

The role applies to the whole laptop, including other tabs and background apps.
It is therefore a deliberate choice, not an automatic consequence of viewing a
dashboard. No additional login is introduced for this local workflow.

## Verification

Local Go tests cover DHCP expiry/reassignment, reconnects, role renewal/stop,
request identity, capture/DNS/conntrack exclusion, route inputs and held gate
packets. Frontend tests cover refresh, reconnect/expiry and stale request races.
The existing network namespace script supports shared, proxy-only and separate
admin configurations; run it in a disposable privileged Linux environment with
the scripts mounted at `/root/scripts` and the required networking tools:

```sh
ADMIN_WIFI_ENABLED=false DASHBOARD_ON_AP=true bash /root/scripts/test-gateway-network.sh
ADMIN_WIFI_ENABLED=false DASHBOARD_ON_AP=false bash /root/scripts/test-gateway-network.sh
ADMIN_WIFI_ENABLED=true DASHBOARD_ON_AP=false bash /root/scripts/test-gateway-network.sh
```

Each invocation needs a fresh namespace/container. The script checks AP dashboard
access, continued internet NAT, backend-port rules and local hostname resolution.

Physical acceptance after deployment:

1. Remove the USB radio, reboot and verify the shared SSID and local dashboard.
2. Join with two devices. Designate one display; browse on both and verify only
   the participant produces new traffic/DNS observations and route admissions.
3. Refresh the display and briefly interrupt its Wi-Fi. Confirm renewal and no
   dashboard/map downloads entering observation while the role remains valid.
4. Stop display mode and confirm new laptop traffic becomes observable. Repeat
   by closing all display tabs and waiting over three minutes.
5. Reassign the display's old IP to the other device and confirm it is observed.
6. Repeat after reboot and at another DHCP Ethernet network; select the visiting
   display again. Check hostname access without learning the Ethernet address.

Physical radio stability, real NFQUEUE behavior and venue-network acceptance
must be checked on the Pi; local tests do not establish those properties.
