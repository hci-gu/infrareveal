# Passive round-trip time on the Raspberry Pi

Checks that `traffic_chunks.rtt_us` matches active measurements from the gateway.

1. **Namespace test (any Linux host):** `scripts/test-map-activity-netns.sh`
   asserts sub-10 ms veth handshakes, then adds `netem delay 40ms` upstream and
   expects a 38–60 ms round trip (`report.netem_rtt_us`). Without the `sch_netem`
   module the report records why the delay step was skipped.
2. **Pi comparison:** from a participant device, open a few sites with known
   placement (a nearby CDN, Frankfurt, US East, Asia). On the gateway, run
   `ping -c 10` and `curl -so /dev/null -w '%{time_connect}\n' https://host` to
   the same addresses. Then read:

   ```sh
   sqlite3 "file:data-map-activity/data.db?mode=ro" \
     "SELECT destination_ip, rtt_source, MIN(rtt_us)/1000.0 FROM traffic_chunks
      WHERE rtt_us > 0 GROUP BY destination_ip, rtt_source ORDER BY 3"
   ```

   TCP values should sit within a few ms of `time_connect` and ping minimums.
   UDP values may be higher (first-reply upper bounds).
3. **Jitter:** repeat under dense traffic. Kernel timestamps should keep the
   minimum stable; record the spread between repeated minimums.
4. **Gate:** arm the Proxy Lab gate for one client and confirm that client's
   chunks carry no `rtt_us` while armed.
5. **Middleboxes:** if nearly every destination measures below 2 ms, an upstream
   transparent proxy is answering handshakes and the latency view is not
   meaningful on that network.
