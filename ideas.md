# Map visualization ideas

Alternative ways to show overall traffic on the map dashboard. The current view
draws gateway → destination arcs on an Equal Earth projection, with traffic
volume animated along each arc. Each idea below answers a different question
than that view does.

## Ranked suggestions

### 1. Latency cartogram: "how far away is the internet, really?" — *implemented as the Latency layout*
Place each destination by measured round-trip time instead of geography. Needs
passive latency evidence first. Full plan: **Plan: passive latency and the
latency view** at the end of this document.

### 2. Route-bundled flow tree — *tried and removed*
Built as a Routes layout, then removed: `route_evidence` is too rarely available
for it to differ from the direct view. Revisit if route measurement becomes reliable.
Replace independent great-circle arcs with a flow tree from the gateway
following hops in `route_evidence`. Paths that share upstream hops merge into
thicker trunks and fan out near destinations (spiral trees / Sankey-like flow
maps).

- **Insight:** shared chokepoints: one uplink → a couple of transit providers →
  fan-out. A truer picture of "the route" than a straight line through the sky.
- **Data:** already collected. Keep the "approximate path" framing visible.
- **Prior art:** Buchin et al. spiral trees; swarm-based edge bundling
  (Polisciuc & Machado); obstacle-aware bundling (Pupyrev et al.).

### 3. Physical layer: submarine cables — *implemented as the Cables layout (v1)*
Route evidence turned out to be unreliable, so v1 infers **sea crossings** from IP
geography alone and highlights the real cables (TeleGeography geometry) that
connect the regions, instead of matching traceroute hops to a single cable. See
`docs/implementation-guides/map-dashboard.md` → Flow layouts. Original idea:
overlay submarine cable data and highlight the cable a transoceanic hop most
likely used.

- **Insight:** makes "the cloud" physical, e.g. this video crossed a specific
  Atlantic cable.
- **Caveat:** hop → cable attribution is uncertain, so label it "likely cable"
  using the existing confidence vocabulary.
- **Prior art:** Calypso (SIGCOMM '25 / IMC '26), UCI Nautilus, APNIC cable
  tagging.

### 4. Ownership lens
Same traffic, grouped by owner (ASN/service: Google, Amazon, Cloudflare,
Meta…). On the map, each location dot becomes a pie or stack by owner. Off the
map: a treemap of client → owning company → service.

- **Insight:** concentration. Often 70–90% of bytes go to 3–4 companies,
  wherever the servers physically are.
- **Data:** already available (service attribution + GeoLite2 ASN fallback).
- **Prior art:** Tactical Tech *Trackography*, Columbia/Brown *Mapping Data
  Flows*. These work from policies or crawled data; nothing found combines live
  captured traffic with company ownership.

### 5. Traffic cartogram
Dorling circles or countries resized by bytes, animated over the session.

- **Insight:** readable from across a room (display mode). "Your internet's map
  of the world."

### 6. Tile grid map with sparklines
One equal-size tile per country, arranged roughly geographically, each with a
sent/received sparkline.

- **Insight:** when each country is active (periodic background polling vs.
  user bursts). Small data-centre countries (IE, NL) become legible.
- **Data:** per-location series (`LocationTraffic.series`).
- **Prior art:** Slingsby 2018 gridmaps, PolicyViz, Flourish.

### 7. Per-device OD map / small multiples
A small map per connected client (Wood/Dykes/Slingsby OD maps), or plain small
multiples with a shared scale.

- **Insight:** device footprints differ sharply (phone vs. laptop vs. smart TV).

### Honourable mention: sonification
Ambient sound in display mode from the 50 ms directional samples: pitch by
distance, stereo pan by sent/received. Prior art: *PacketWeather*.

## Plan: passive latency and the latency view (idea #1 + latency evidence)

Two parts that ship in order: the gateway first learns how far away each
destination really is (round-trip time), then the dashboard uses it, mainly for
a latency view, but also to check the Cables inference.

### Goals

- Measure round-trip time (RTT) from the gateway to each destination **without
  probes**, from traffic the gateway already captures. Route evidence has proven
  unreliable; this must not depend on it.
- Show a **latency view**: gateway in the centre, each destination at its true
  compass direction but at a distance set by RTT.
- Use RTT as **evidence**: an address too fast for its IP location was served
  nearby (geolocation or anycast); a slow one is consistent with a far location.

### Part A: passive handshake RTT (Go, `pocketbase/observer`)

**What is measured.** The gateway sits between clients and servers, so the time
from a connection's opening packet passing the gateway to the server's first reply
is the gateway↔server RTT. The client's Wi-Fi hop is excluded.

- **TCP:** client SYN → server SYN-ACK. `PacketActivityEvent` already carries
  `TCPFlags`, and `aggregate.packet` already tracks per-connection state
  (`connection`, SYN detection). Add `synAt` and set an RTT on the first
  SYN-ACK in the other direction.
- **Retransmissions (Karn's rule):** if the SYN is seen twice, or the SYN-ACK
  arrives without a SYN on record, the sample is ambiguous; discard it.
- **QUIC/UDP:** first client packet → first server packet of a new UDP flow, with
  no payload inspection. Servers may answer late (Retry, 0-RTT), so these are
  upper bounds; store them separately (`rtt_source: udp`) and only use them when
  no TCP sample exists for that destination.
- **Timestamps:** today `ObservedAt` is `time.Now()` after `recvmsg`, which adds
  user-space jitter on a loaded Pi. Enable `SO_TIMESTAMPNS` on the `AF_PACKET`
  socket and read the kernel receive time from the control message already
  parsed for `PACKET_AUXDATA`. Measure the jitter on the Pi before and after;
  keep `time.Now()` as fallback.
- **Proxy Lab gate:** when the opt-in NFQUEUE gate (ADR 0002) is armed, it can
  hold packets for selected clients and would inflate RTT. Don't record samples
  for gated flows (or while armed).

**Storage.** Add two optional fields to `traffic_chunks`: `rtt_ms` (lowest
handshake RTT among connections opened in that chunk's binding) and `rtt_source`
(`tcp` | `udp`). Chunks are already per destination binding and 5 s, already
flow to the dashboard in `MapWindow.series`, and already obey retention. No new
collection or API, just one migration. Lowest wins because queueing only ever
adds delay.

**Privacy.** RTT to a server is network metadata of the same kind as byte
counts; no payload is read, including for QUIC. Document it in the flow-activity
guide.

**Also update:**
- **Synthetic data:** `cmd/dev-data` and the simulation, so they produce
  plausible RTTs derived from destination distance and stay realistic.

**Tests and validation:**
- **Unit tests:** SYN/SYN-ACK pairing, Karn rejection, port reuse, a SYN-ACK
  with no SYN, UDP first-reply timing, and keeping the lowest value per chunk.
- **Network-namespace test:** extend `scripts/test-map-activity-netns.sh` to add
  known delay with `tc qdisc … netem delay 40ms` and assert measured RTT ≈ 40 ms
  ± a few ms.
- **Pi check:** compare `rtt_ms` against `ping`/`tcping` from the gateway to a
  handful of hosts (nearby CDN, Frankfurt, US East, Asia). Record the procedure
  in `docs/validation/`.

### Part B: latency in the dashboard data

- **Types:** `TrafficChunk.rtt_ms?` and `rtt_source?` in `@infrareveal/session-state`.
- **Projection:** `projectWorkspace` gives each series a `rttMs` (lowest in
  the history window, preferring TCP) and each location a byte-weighted
  representative, the lowest across its series.
- **Physical floor:** light in fibre needs about 1 ms of RTT per 100 km of
  great-circle distance (real paths are longer). For each located destination
  compute `floorMs = distanceKm / 100` from the gateway. If
  `rttMs < 0.8 × floorMs`, the IP location is **physically impossible**: the
  address was served nearby. Mark it (`placement: 'contradicted'`).

### Part C: the latency view

A new layout, **Geography | Latency**, built in the shared deck.gl renderer like
the Equal Earth projection.

- **Layout:**
  - **Gateway:** at the centre.
  - **Direction:** each destination keeps its true initial compass bearing from
    the gateway.
  - **Distance:** set by RTT on a square-root scale (separates 1–20 ms locals
    while still fitting 300 ms intercontinental).
  - **Rings:** concentric at 10 / 25 / 50 / 100 / 200 ms, with labels.
- **Positions:** computed per destination in the composition and passed into the
  same arc, column and label layers. The basemap (land, borders, tiles) is hidden,
  because geography has no meaning in this space. A faint compass rose gives
  orientation.
- **Transition:** positions animate between geographic and latency layouts
  (deck.gl attribute transitions on position accessors, about 1.2 s). Watching a
  "United States" column slide in next to the gateway is the core insight.
- **Ghosts (optional):** a faint dot at each destination's geographic distance on
  the same bearing, joined to its latency position. Long ghost lines mean "much
  closer than it looks"; contradicted placements are highlighted.
- **Without RTT:** destinations with no RTT (no new connection in the window,
  UDP-only with no reply) sit on an outer "no measurement" ring and are counted
  in the footer.
- **Tooltip:** RTT, source (TCP handshake / UDP first reply), number of samples,
  physical floor for the IP location, and a plain verdict ("served from within
  ~X km", "consistent with its location").
- **Insights → Latency:** traffic share by RTT band (<10, 10–50, 50–150, >150
  ms), and the share of bytes whose IP location was contradicted by physics.

### Part D: feed RTT into Cables

In `seaCrossings.classifySeries`, when a series has `rttMs`:
- **Too fast for the crossing:** if `rttMs` is below the floor for the inferred
  crossing (gateway → destination distance / 100 × 0.8), the claimed crossing
  is impossible. Classify as `nearby` (served locally), whatever the ASN.
- **Consistent with the crossing:** label it "measured" (e.g. "required ·
  consistent with 92 ms RTT").
- **No RTT:** keep the anycast/CDN ASN list as the fallback for series without RTT.

### Phases

1. **A1:** kernel timestamps, TCP handshake RTT, chunk fields and migration,
   unit tests, netem namespace test.
2. **A2:** UDP first-reply RTT, gate exclusion, dev-data/simulation, Pi
   validation doc.
3. **B:** types, workspace projection, physical floor, tests.
4. **C:** latency layout, rings, transition, tooltip, Insights section.
5. **D:** Cables integration, docs (`map-dashboard.md`,
   `flow-activity-bursts.md`).

Parts A and B are worth having even without C: RTT immediately improves the
Cables inference and the location inspector ("12 ms away").

### Decisions to make

1. **Storage:** fields on `traffic_chunks` (recommended) or a separate
   per-destination latency collection.
2. **UDP/QUIC:** include first-reply upper bounds (recommended, labelled), or TCP only.
3. **Placement of the view:** a third option in the projection setting, or its
   own Geography | Latency toggle in the map toolbar (recommended).
4. **Radius scale:** square root (recommended), logarithmic, or linear.
5. **Ghost lines:** in v1, or later.

### Risks

- **Coverage:** only connections *opened* within the history window produce
  samples. Long-lived connections (streaming, push) may have none in a 5-minute
  window. Mitigation: show the last known RTT per destination for the session,
  marked as older.
- **Pi timestamp jitter:** if kernel timestamps aren't available or are still
  noisy, use only the lowest of several samples and suppress single samples
  under 1 ms.
- **Middleboxes:** a transparent proxy upstream of the gateway (hotel or
  enterprise networks) would answer SYNs itself and show ~1 ms everywhere. Detect
  it: most destinations below 2 ms means the RTT isn't meaningful on this
  network; show a warning.

## Recommendation
Start with #2 and #4, which reuse existing data and fit the deck.gl stack. #1
surprises viewers most, if RTT data is available.

## Sources
- [Caidagram (RIPE Labs)](https://labs.ripe.net/author/csquarce/caidagram-visualising-geographically-annotated-internet-measurements/)
- [Matisse: latencies as manifolds](https://arxiv.org/pdf/2509.08097)
- [Semiotic DistanceCartogram](https://semiotic.nteract.io/charts/distance-cartogram)
- [Many-to-many geographically-embedded flow visualisation](https://arxiv.org/pdf/1908.02052)
- [Swarm-based edge bundling for flow maps](https://cdv.dei.uc.pt/wp-content/uploads/2017/11/pepmsw2017.pdf)
- [From Origins to Destinations: flow map survey](https://services.informatik.hs-mannheim.de/~nagel/publication/from-origins-to-destinations/)
- [Calypso, SIGCOMM '25](https://aqualab.cs.northwestern.edu/publication/2025/cwang-sigcomm25/)
- [UCI Nautilus](https://nautilus.ics.uci.edu/)
- [APNIC: untangling undersea cables](https://blog.apnic.net/2019/04/05/untangling-the-worldwide-mesh-of-undersea-cables/)
- [Tactical Tech Trackography](https://theglassroom.org/object/tactical_tech-trackography)
- [Mapping Data Flows](https://brown.columbia.edu/mapping-data-flows)
- [Wood et al., OD maps (2010)](https://openaccess.city.ac.uk/id/eprint/537/1/wood_visualization_2010.pdf)
- [Slingsby tilemaps (2018)](https://openaccess.city.ac.uk/20884/1/slingsby_tilemaps_2018.pdf)
- [PacketWeather (Rhizome)](https://artbase.rhizome.org/wiki/Q4014)
