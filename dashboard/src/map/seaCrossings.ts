import countries from './data/countries.json'
import cableData from './data/cables.json'
import type { GatewayOrigin, MapPosition } from './mapModel'
import type { LocationTraffic } from './mapWorkspace'
import type { ByteTotals } from './destinationVolumes'
import type { MapSeries } from './mapTracks'
import { hasMapCoordinates } from './mapCoordinates'
import { fibreFloorMs, formatRtt, placement } from './latency'

/**
 * Sea crossings inferred from IP geography, drawn on real cable geometry.
 *
 * No path measurement is used. The gateway and each destination are placed in
 * coarse regions. Regions are linked overland (costed links) and by every
 * submarine cable that lands in both (TeleGeography geometry, landing countries
 * derived from line ends). The cheapest region path decides whether a crossing
 * is `required` (no overland path exists) or `possible` (the sea is the usual
 * way). For each crossing, every cable connecting the two regions is a
 * candidate: traffic used one or more of them, and which one is never observed.
 */

type Region = { id: string; label: string; hub: MapPosition; countries: string[] }
export type Landing = { position: MapPosition; country: string }
/** `distances[i][j]`: km along the cable between landings i and j, null when the source lines do not connect them. */
export type Cable = { id: string; name: string; color: string; lines: MapPosition[][]; landings: Landing[]; distances: (number | null)[][]; joins?: [MapPosition, MapPosition][] }
/** A cable that can carry a crossing, between its best-placed landing on each side. */
export type CableCandidate = { cable: Cable; from: MapPosition; to: MapPosition; cost: number }
/** One sea crossing between two regions, with every cable that connects them. */
export type SeaHop = { id: string; from: string; to: string; candidates: CableCandidate[] }
export type CrossingConfidence = 'required' | 'possible'
/** `nearby`: a measured round trip too fast for the IP location, so no crossing happened. */
export type CrossingClass = 'none' | CrossingConfidence | 'nearby' | 'edge' | 'unknown'
/** `measuredMs`: a round trip that is consistent with the crossing (it does not prove the cable). */
export type Crossing = { kind: CrossingClass; hops: SeaHop[]; reason: string; measuredMs?: number }
const emptyTotals = (): Record<CrossingClass, number> => ({ none: 0, possible: 0, required: 0, nearby: 0, edge: 0, unknown: 0 })

const REGIONS: Region[] = [
  { id: 'nordic', label: 'Scandinavia', hub: [11, 58.5], countries: ['SE', 'NO', 'DK'] },
  { id: 'finland', label: 'Finland', hub: [24.9, 60.2], countries: ['FI'] },
  { id: 'baltics', label: 'Baltic states', hub: [24.1, 56.9], countries: ['EE', 'LV', 'LT'] },
  { id: 'europe', label: 'Continental Europe', hub: [8.7, 50.1], countries: ['DE', 'NL', 'BE', 'LU', 'FR', 'CH', 'AT', 'LI', 'PL', 'CZ', 'SK', 'HU', 'SI', 'HR', 'IT', 'SM', 'VA', 'MC', 'ES', 'PT', 'AD', 'GI', 'RO', 'BG', 'RS', 'BA', 'ME', 'MK', 'AL', 'XK', 'GR', 'MD', 'UA', 'BY'] },
  { id: 'british_isles', label: 'Britain & Ireland', hub: [-1.5, 52.5], countries: ['GB', 'IE', 'IM', 'JE', 'GG'] },
  { id: 'iceland', label: 'Iceland & Faroe Islands', hub: [-21.9, 64.1], countries: ['IS', 'FO'] },
  { id: 'greenland', label: 'Greenland', hub: [-51.7, 64.2], countries: ['GL'] },
  { id: 'russia', label: 'Russia', hub: [37.6, 55.8], countries: ['RU'] },
  // Landings only: Russian landings east of the Urals, which Moscow cannot plausibly backhaul.
  { id: 'russia_far_east', label: 'Russian Far East', hub: [131.9, 43.1], countries: [] },
  { id: 'turkey', label: 'Turkey & Caucasus', hub: [29, 41], countries: ['TR', 'GE', 'AM', 'AZ'] },
  { id: 'middle_east', label: 'Middle East', hub: [46.7, 24.7], countries: ['SA', 'AE', 'QA', 'BH', 'KW', 'OM', 'YE', 'IQ', 'IR', 'JO', 'IL', 'PS', 'LB', 'SY'] },
  { id: 'north_africa', label: 'North-West Africa', hub: [10.2, 36.8], countries: ['LY', 'TN', 'DZ', 'MA', 'EH'] },
  { id: 'egypt', label: 'Egypt & Sudan', hub: [31.2, 30], countries: ['EG', 'SD'] },
  { id: 'west_africa', label: 'West & Central Africa', hub: [3.4, 6.5], countries: ['SN', 'GM', 'GW', 'GN', 'SL', 'LR', 'CI', 'GH', 'TG', 'BJ', 'NG', 'CM', 'GQ', 'GA', 'CG', 'CD', 'AO', 'ML', 'BF', 'NE', 'TD', 'CF', 'CV', 'MR', 'ST'] },
  { id: 'east_africa', label: 'East Africa', hub: [39.7, -4], countries: ['DJ', 'ER', 'ET', 'SO', 'KE', 'TZ', 'UG', 'RW', 'BI', 'SS', 'MZ', 'MW', 'ZM', 'MG', 'KM', 'SC', 'MU', 'RE'] },
  { id: 'southern_africa', label: 'Southern Africa', hub: [18.4, -33.9], countries: ['ZA', 'NA', 'BW', 'ZW', 'LS', 'SZ'] },
  { id: 'south_asia', label: 'South Asia', hub: [72.9, 19.1], countries: ['IN', 'PK', 'BD', 'LK', 'NP', 'BT', 'MV', 'AF'] },
  { id: 'central_asia', label: 'Central Asia', hub: [76.9, 43.2], countries: ['KZ', 'UZ', 'TM', 'KG', 'TJ', 'MN'] },
  { id: 'east_asia', label: 'China & Korea', hub: [114.2, 22.3], countries: ['CN', 'HK', 'MO', 'KR', 'KP'] },
  { id: 'japan', label: 'Japan', hub: [139.7, 35.7], countries: ['JP'] },
  { id: 'taiwan', label: 'Taiwan', hub: [121.5, 25], countries: ['TW'] },
  { id: 'se_asia', label: 'South-East Asia', hub: [103.8, 1.35], countries: ['SG', 'MY', 'TH', 'VN', 'LA', 'KH', 'MM', 'BN'] },
  { id: 'se_asia_islands', label: 'Indonesia & Philippines', hub: [106.8, -6.2], countries: ['ID', 'PH', 'TL'] },
  { id: 'oceania', label: 'Oceania', hub: [151.2, -33.9], countries: ['AU', 'NZ', 'PG', 'FJ', 'NC', 'PF', 'WS', 'TO', 'VU', 'SB'] },
  { id: 'north_america', label: 'North & Central America', hub: [-77.5, 39], countries: ['US', 'CA', 'MX', 'GT', 'BZ', 'SV', 'HN', 'NI', 'CR', 'PA'] },
  { id: 'caribbean', label: 'Caribbean', hub: [-66.1, 18.4], countries: ['CU', 'JM', 'HT', 'DO', 'PR', 'BS', 'TT', 'BB', 'KY', 'VI', 'AG', 'DM', 'LC', 'VC', 'GD', 'AW', 'CW', 'BQ', 'SX', 'MQ', 'GP'] },
  { id: 'south_america', label: 'South America', hub: [-46.6, -23.5], countries: ['BR', 'AR', 'CL', 'UY', 'PY', 'BO', 'PE', 'EC', 'CO', 'VE', 'GY', 'SR', 'GF'] },
]

/**
 * Overland links with an effective cost in km. Long multi-country terrestrial
 * paths are penalised: intercontinental traffic overwhelmingly rides cables.
 * Britain–continent is a land link because fibre runs through the Channel Tunnel.
 */
const LAND_LINKS: [string, string, number][] = [
  ['nordic', 'europe', 450], ['nordic', 'finland', 1500], ['finland', 'russia', 400], ['baltics', 'europe', 1200], ['baltics', 'russia', 800],
  ['europe', 'russia', 1900], ['europe', 'turkey', 3000], ['europe', 'british_isles', 1500], ['turkey', 'middle_east', 8000],
  ['middle_east', 'egypt', 3500], ['north_africa', 'egypt', 3500], ['middle_east', 'south_asia', 6000], ['russia', 'central_asia', 7000],
  ['central_asia', 'east_asia', 12000], ['russia', 'east_asia', 20000], ['south_asia', 'east_asia', 8000], ['se_asia', 'east_asia', 4500],
  ['south_asia', 'se_asia', 6000], ['north_africa', 'west_africa', 9000], ['egypt', 'east_africa', 8000],
  ['west_africa', 'southern_africa', 7000], ['east_africa', 'southern_africa', 6000], ['west_africa', 'east_africa', 5000],
  ['russia', 'russia_far_east', 18000], ['russia_far_east', 'east_asia', 2500],
]

/**
 * Anycast and CDN networks whose addresses are routinely geolocated to a
 * headquarters country while being served from a nearby edge. Placing them
 * would invent ocean crossings, so they are reported, not drawn.
 */
export const EDGE_NETWORK_ASNS = new Map<number, string>([
  [13335, 'Cloudflare'], [209242, 'Cloudflare'], [15169, 'Google'], [396982, 'Google'], [19527, 'Google'], [36040, 'Google'], [43515, 'Google'],
  [20940, 'Akamai'], [16625, 'Akamai'], [16702, 'Akamai'], [21342, 'Akamai'], [32787, 'Akamai'], [12222, 'Akamai'], [34164, 'Akamai'],
  [54113, 'Fastly'], [8075, 'Microsoft'], [8068, 'Microsoft'], [714, 'Apple'], [6185, 'Apple'], [32934, 'Meta'], [2906, 'Netflix'], [40027, 'Netflix'],
  [15133, 'Edgio'], [22822, 'Edgio'], [60068, 'CDN77'], [200325, 'Bunny'], [13414, 'X'], [46489, 'Twitch'], [14618, 'Amazon CloudFront'],
])

/**
 * Cables in the geometry export that are not carrying traffic. The export has
 * no in-service dates, so planned systems that would distort inferred paths are
 * listed by hand. Polar Express (Murmansk–Vladivostok) is under construction.
 */
const NOT_IN_SERVICE = new Set(['polar-express'])
export const CABLES = (cableData.cables as unknown as Cable[]).filter(cable => !NOT_IN_SERVICE.has(cable.id))
export const CABLE_SOURCE = { label: 'TeleGeography Submarine Cable Map', short: 'TeleGeography' }

const regionByCountry = new Map(REGIONS.flatMap(region => region.countries.map(code => [code, region])))
export const regionOf = (countryCode: string | null | undefined) => countryCode ? regionByCountry.get(countryCode.toUpperCase()) : undefined
const regionById = new Map(REGIONS.map(region => [region.id, region]))
export const regionLabel = (id: string) => regionById.get(id)?.label ?? id
const hub = (id: string) => regionById.get(id)!.hub

/**
 * Every link, overland or sea, adds a fixed handover cost, so a path through
 * fewer regions wins over one that hops between neighbours.
 */
const LINK_OVERHEAD_KM = 1500
const hopId = (a: string, b: string) => a < b ? `${a}~${b}` : `${b}~${a}`

/** Lines that do not connect (often a terrestrial stretch missing from the data) are costed as a detour. */
const UNCONNECTED_FACTOR = 1.5
const URALS_LONGITUDE = 60
const landingRegion = (landing: Landing) => landing.country === 'RU' && landing.position[0] > URALS_LONGITUDE ? regionById.get('russia_far_east') : regionOf(landing.country)

/** Cables landing in both regions of an ordered pair, with their landing indices on each side. */
const cablesByPair = new Map<string, { cable: Cable; from: number[]; to: number[] }[]>()
for (const cable of CABLES) {
  const byRegion = new Map<string, number[]>()
  cable.landings.forEach((landing, index) => {
    const region = landingRegion(landing)
    if (region) byRegion.set(region.id, [...byRegion.get(region.id) ?? [], index])
  })
  for (const [a, from] of byRegion) for (const [b, to] of byRegion) {
    if (a !== b) cablesByPair.set(`${a}>${b}`, [...cablesByPair.get(`${a}>${b}`) ?? [], { cable, from, to }])
  }
}

const candidateCache = new Map<string, CableCandidate[]>()
/**
 * Candidate cables for crossing from one region to another, ranked by cost:
 * overland backhaul from `start` to the landing, the length along the cable,
 * and backhaul from the far landing to `end`. `start`/`end` default to the
 * region hubs; the gateway and destination pass their own positions so the
 * landings nearest to them are chosen. Costs only rank plausibility.
 */
export function cablesBetween(fromRegion: string, toRegion: string, start = hub(fromRegion), end = hub(toRegion)): CableCandidate[] {
  const key = `${fromRegion}>${toRegion}|${start.map(v => v.toFixed(1))}|${end.map(v => v.toFixed(1))}`
  const cached = candidateCache.get(key)
  if (cached) return cached
  const candidates = (cablesByPair.get(`${fromRegion}>${toRegion}`) ?? []).map(({ cable, from, to }) => {
    let best: CableCandidate | null = null
    for (const i of from) for (const j of to) {
      const a = cable.landings[i].position, b = cable.landings[j].position
      const along = cable.distances[i]?.[j] ?? distanceKm(a, b) * UNCONNECTED_FACTOR
      const cost = distanceKm(start, a) + along + distanceKm(b, end) + LINK_OVERHEAD_KM
      if (!best || cost < best.cost) best = { cable, from: a, to: b, cost }
    }
    return best!
  }).sort((x, y) => x.cost - y.cost || x.cable.name.localeCompare(y.cable.name))
  candidateCache.set(key, candidates)
  return candidates
}

type GraphEdge = { to: string; cost: number; sea: boolean }
const graph = new Map<string, GraphEdge[]>()
const addEdge = (from: string, edge: GraphEdge) => graph.set(from, [...graph.get(from) ?? [], edge])
for (const [a, b, km] of LAND_LINKS) { const cost = km + LINK_OVERHEAD_KM; addEdge(a, { to: b, cost, sea: false }); addEdge(b, { to: a, cost, sea: false }) }
for (const key of cablesByPair.keys()) { const [a, b] = key.split('>'); addEdge(a, { to: b, cost: cablesBetween(a, b)[0].cost, sea: true }) }

function cheapest(from: string, to: string, landOnly: boolean): GraphEdge[] | null {
  const cost = new Map([[from, 0]]), previous = new Map<string, [string, GraphEdge]>(), done = new Set<string>()
  while (true) {
    let node: string | null = null
    for (const [id, value] of cost) if (!done.has(id) && (node === null || value < cost.get(node)!)) node = id
    if (node === null) return null
    if (node === to) break
    done.add(node)
    for (const edge of graph.get(node) ?? []) {
      if (landOnly && edge.sea) continue
      const next = cost.get(node)! + edge.cost
      if (next < (cost.get(edge.to) ?? Infinity)) { cost.set(edge.to, next); previous.set(edge.to, [node, edge]) }
    }
  }
  const edges: [string, GraphEdge][] = []
  for (let node = to; node !== from;) { const [prior, edge] = previous.get(node)!; edges.unshift([prior, edge]); node = prior }
  return edges.map(([, edge]) => edge).map((edge, i, all) => ({ ...edge, from: i ? all[i - 1].to : from })) as (GraphEdge & { from: string })[]
}

const crossingCache = new Map<string, Crossing>()
/** The cheapest plausible region-to-region path, and whether its sea legs are avoidable. */
export function regionCrossing(fromRegion: string, toRegion: string): Crossing {
  const key = `${fromRegion}>${toRegion}`
  const cached = crossingCache.get(key)
  if (cached) return cached
  const from = regionLabel(fromRegion), to = regionLabel(toRegion)
  let result: Crossing
  if (fromRegion === toRegion) result = { kind: 'none', hops: [], reason: `${to} is in the same region as the gateway.` }
  else {
    const path = cheapest(fromRegion, toRegion, false) as (GraphEdge & { from: string })[] | null
    const hops = (path ?? []).filter(edge => edge.sea).map(edge => ({ id: hopId(edge.from, edge.to), from: edge.from, to: edge.to, candidates: cablesBetween(edge.from, edge.to) }))
    if (!path) result = { kind: 'unknown', hops: [], reason: `No cable or overland link connects ${from} and ${to} in the data.` }
    else if (!hops.length) result = { kind: 'none', hops, reason: `${to} is reachable overland from ${from}.` }
    else if (cheapest(fromRegion, toRegion, true)) result = { kind: 'possible', hops, reason: `${to} can be reached overland, but the usual route from ${from} runs under the sea.` }
    else result = { kind: 'required', hops, reason: `No overland route connects ${from} and ${to}; traffic must cross the sea.` }
  }
  crossingCache.set(key, result)
  return result
}

/**
 * A measured round trip decides first: answering faster than light allows from
 * the IP location means the traffic was served nearby, so no crossing is
 * claimed; a consistent one is noted. Without a measurement, edge networks veto
 * a crossing: a nearby location is consistent with edge serving and stays
 * overland, while a far-away one is likely a headquarters geolocation of an
 * address that was served locally.
 */
export function classifySeries(series: Pick<MapSeries, 'countryCode' | 'asn' | 'rttMs'>, gatewayRegion: string | undefined, context?: { origin: GatewayOrigin; position?: MapPosition }): Crossing {
  const region = regionOf(series.countryCode)
  if (!gatewayRegion || !region) return { kind: 'unknown', hops: [], reason: 'The destination country is unknown or outside the modelled regions.' }
  const crossing = regionCrossing(gatewayRegion, region.id)
  if (series.rttMs !== undefined && context && (crossing.kind === 'required' || crossing.kind === 'possible')) {
    const floor = fibreFloorMs(context.origin, context.position ?? region.hub)
    if (placement(series.rttMs, floor) === 'contradicted') {
      return { kind: 'nearby', hops: [], reason: `Answered in ${formatRtt(series.rttMs)}, faster than light allows from its IP location (at least ${formatRtt(floor)}); it was served from nearby.` }
    }
    return { ...crossing, measuredMs: series.rttMs, reason: `${crossing.reason} Consistent with the measured ${formatRtt(series.rttMs)} round trip.` }
  }
  const edge = series.asn ? EDGE_NETWORK_ASNS.get(series.asn) : undefined
  if (edge && (crossing.kind === 'required' || crossing.kind === 'possible')) return { kind: 'edge', hops: [], reason: `${edge} serves traffic from nearby edge locations; its IP location does not show where it was served from.` }
  return crossing
}

/** Gateway country by point-in-polygon on the bundled Natural Earth outlines. */
export function countryAt([lon, lat]: MapPosition): string | undefined {
  for (const country of countries as unknown as { code: string; polygons: MapPosition[][][] }[]) {
    for (const polygon of country.polygons) {
      if (insideRing(polygon[0], lon, lat) && !polygon.slice(1).some(hole => insideRing(hole, lon, lat))) return country.code
    }
  }
  return undefined
}
function insideRing(ring: MapPosition[], x: number, y: number) {
  let inside = false
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const [xi, yi] = ring[i], [xj, yj] = ring[j]
    if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) inside = !inside
  }
  return inside
}
const gatewayRegionCache = new Map<string, string | undefined>()
export function gatewayRegion(origin: GatewayOrigin): string | undefined {
  const key = `${origin.longitude},${origin.latitude}`
  if (!gatewayRegionCache.has(key)) {
    // Coastal gateways can fall just outside a simplified outline; nudge inland before giving up.
    const probes: MapPosition[] = [[origin.longitude, origin.latitude], ...[[.2, 0], [-.2, 0], [0, .2], [0, -.2]].map(([dx, dy]) => [origin.longitude + dx, origin.latitude + dy] as MapPosition)]
    const code = probes.map(countryAt).find(Boolean)
    gatewayRegionCache.set(key, regionOf(code)?.id)
  }
  return gatewayRegionCache.get(key)
}

export function distanceKm([lon1, lat1]: MapPosition, [lon2, lat2]: MapPosition) {
  const rad = Math.PI / 180, dLat = (lat2 - lat1) * rad, dLon = (lon2 - lon1) * rad
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) ** 2
  return 12_742 * Math.asin(Math.min(1, Math.sqrt(h)))
}

/** Vertices shared by several lines join them; ±180° is one meridian. */
const vertexKey = ([lon, lat]: MapPosition) => `${Math.abs(lon) > 179.9999 ? 180 : lon.toFixed(4)},${lat.toFixed(4)}`
const cableGraphs = new Map<string, { points: Map<string, MapPosition>; links: Map<string, [string, number][]> }>()
function cableGraph(cable: Cable) {
  let graph = cableGraphs.get(cable.id)
  if (!graph) {
    const points = new Map<string, MapPosition>(), links = new Map<string, [string, number][]>()
    for (const line of cable.lines) for (let i = 0; i < line.length; i++) {
      const key = vertexKey(line[i])
      if (!points.has(key)) points.set(key, line[i])
      if (!i) continue
      const prior = vertexKey(line[i - 1]), length = distanceKm(line[i - 1], line[i])
      links.set(key, [...links.get(key) ?? [], [prior, length]])
      links.set(prior, [...links.get(prior) ?? [], [key, length]])
    }
    // Branch snaps and bridges between pieces, computed at import time.
    for (const [a, b] of cable.joins ?? []) {
      const from = vertexKey(a), to = vertexKey(b), length = distanceKm(a, b)
      for (const [key, point] of [[from, a], [to, b]] as const) if (!points.has(key)) points.set(key, point)
      links.set(from, [...links.get(from) ?? [], [to, length]])
      links.set(to, [...links.get(to) ?? [], [from, length]])
    }
    graph = { points, links }
    cableGraphs.set(cable.id, graph)
  }
  return graph
}
const sectionCache = new Map<string, MapPosition[][]>()
/** Distances from one vertex to every vertex it connects to (Dijkstra with a binary heap). */
function reach(links: Map<string, [string, number][]>, start: string) {
  const cost = new Map([[start, 0]]), previous = new Map<string, string>(), heap: [number, string][] = [[0, start]]
  const swap = (i: number, j: number) => { [heap[i], heap[j]] = [heap[j], heap[i]] }
  while (heap.length) {
    const [distance, node] = heap[0], last = heap.pop()!
    if (heap.length) {
      heap[0] = last
      for (let i = 0; ;) { const l = 2 * i + 1, r = l + 1; let m = i; if (l < heap.length && heap[l][0] < heap[m][0]) m = l; if (r < heap.length && heap[r][0] < heap[m][0]) m = r; if (m === i) break; swap(m, i); i = m }
    }
    if (distance > cost.get(node)!) continue
    for (const [next, length] of links.get(node) ?? []) {
      if (distance + length >= (cost.get(next) ?? Infinity)) continue
      cost.set(next, distance + length); previous.set(next, node); heap.push([distance + length, next])
      for (let i = heap.length - 1; i > 0;) { const p = (i - 1) >> 1; if (heap[p][0] <= heap[i][0]) break; swap(p, i); i = p }
    }
  }
  return { cost, previous }
}
function trace(previous: Map<string, string>, points: Map<string, MapPosition>, goal: string) {
  const path: MapPosition[] = []
  for (let node: string | undefined = goal; node; node = previous.get(node)) path.unshift(points.get(node)!)
  return path
}
/**
 * The stretch of a cable between two of its landings, following its own
 * geometry through branching units. When the source lines do not connect the
 * landings (often a terrestrial stretch), each side is drawn as far as it goes
 * towards the other and the gap is left visible.
 */
export function cableSection(cable: Cable, from: MapPosition, to: MapPosition): MapPosition[][] {
  const key = `${cable.id}|${vertexKey(from)}|${vertexKey(to)}`
  const cached = sectionCache.get(key)
  if (cached) return cached
  const { points, links } = cableGraph(cable)
  const start = vertexKey(from), goal = vertexKey(to)
  const forward = reach(links, start)
  let sections: MapPosition[][]
  if (forward.cost.has(goal)) sections = [trace(forward.previous, points, goal)]
  else {
    const closest = (reached: Map<string, number>, target: MapPosition) => [...reached.keys()].reduce((best, node) => distanceKm(points.get(node)!, target) < distanceKm(points.get(best)!, target) ? node : best)
    const backward = reach(links, goal)
    sections = [trace(forward.previous, points, closest(forward.cost, to)), trace(backward.previous, points, closest(backward.cost, from))]
  }
  sections = sections.filter(section => section.length > 1)
  sectionCache.set(key, sections)
  return sections
}

/** At most this many cables are drawn per crossing; the tooltip names them all. */
export const DRAWN_CANDIDATES = 6

export type SeaEdge = {
  id: string
  /** `sea`: a candidate cable section. `land`: a straight connector to a landing or to an overland destination. */
  kind: 'sea' | 'land'
  path: MapPosition[]
  received: number
  sent: number
  confidence: CrossingConfidence | null
  cableId?: string
  hopId?: string
  /** Candidate cables for this edge's crossing; traffic used one or more of them. */
  candidates?: number
  locationIds: string[]
  trackIds: string[]
  /** Traffic series on this edge, for live rates. */
  seriesIds: string[]
}
/** `measuredMs`: the lowest consistent round trip among the series using this crossing. */
export type SeaHopTotal = { hop: SeaHop; received: number; sent: number; confidence: CrossingConfidence; measuredMs?: number }
/**
 * The drawn edges one series can travel: `fixed` edges always carry it; for each
 * sea crossing, `hops[h][c]` are the edges (connectors and cable sections) of
 * its c-th candidate cable. Animation sends each burst along one candidate.
 */
export type SeriesRoute = { fixed: string[]; hops: string[][][] }
export type SeaNetwork = { edges: SeaEdge[]; hops: SeaHopTotal[]; landings: { id: string; position: MapPosition }[]; peak: number; totals: Record<CrossingClass, number>; edgeNetworks: string[]; routes: Map<string, SeriesRoute> }

/** Bursts within one window take the same cable; long enough for a pulse to travel a path. */
export const ROUTE_CHOICE_WINDOW_MS = 4000

/**
 * Which candidate cable a burst of a series takes on one crossing. Seeded by the
 * series, the crossing and the data time of the burst, so playback, seeking and
 * replays always pick the same cable for the same traffic.
 */
export function routeChoice(seriesId: string, hopIndex: number, atMs: number, candidates: number) {
  if (candidates <= 1) return 0
  // FNV-1a over the seed, then a final avalanche so neighbouring windows decorrelate.
  let hash = 0x811c9dc5
  for (const char of `${seriesId}|${hopIndex}|${Math.floor(atMs / ROUTE_CHOICE_WINDOW_MS)}`) hash = Math.imul(hash ^ char.charCodeAt(0), 0x01000193)
  hash ^= hash >>> 16; hash = Math.imul(hash, 0x85ebca6b); hash ^= hash >>> 13
  return (hash >>> 0) % candidates
}

const CONNECTOR_MIN_KM = 40
const rank = (value: CrossingConfidence | null) => value === 'required' ? 2 : value === 'possible' ? 1 : 0
const wrapPosition = ([lon, lat]: MapPosition): MapPosition => [((lon + 540) % 360) - 180, lat]

/**
 * Merge every destination's inferred crossings into one flow network. Each
 * crossing draws its candidate cables' sections (between the landings closest
 * to the two regions); connectors join the gateway, landings and destination.
 */
export function buildSeaNetwork(locations: LocationTraffic[], origin: GatewayOrigin, volumeBySeries: Map<string, ByteTotals>): SeaNetwork {
  const home = gatewayRegion(origin)
  const gateway: MapPosition = [origin.longitude, origin.latitude]
  const edges = new Map<string, SeaEdge & { locations: Set<string>; tracks: Set<string>; series: Set<string> }>()
  const hops = new Map<string, SeaHopTotal>()
  const landings = new Map<string, MapPosition>()
  const routes = new Map<string, SeriesRoute>()
  const totals = emptyTotals()
  const edgeNetworks = new Set<string>()
  const add = (edge: Omit<SeaEdge, 'received' | 'sent' | 'locationIds' | 'trackIds' | 'seriesIds'>, volume: ByteTotals, locationId: string, trackId: string, seriesId: string) => {
    const entry = edges.get(edge.id) ?? { ...edge, received: 0, sent: 0, locationIds: [], trackIds: [], seriesIds: [], locations: new Set(), tracks: new Set(), series: new Set() }
    entry.received += volume.received; entry.sent += volume.sent
    if (rank(edge.confidence) > rank(entry.confidence)) entry.confidence = edge.confidence
    entry.locations.add(locationId); entry.tracks.add(trackId); entry.series.add(seriesId)
    edges.set(edge.id, entry)
    return edge.id
  }
  for (const location of locations) {
    for (const series of location.series) {
      const volume = volumeBySeries.get(series.id)
      if (!volume || volume.received + volume.sent <= 0) continue
      const crossing = classifySeries(series, home, { origin, position: location.position })
      totals[crossing.kind] += volume.received + volume.sent
      if (crossing.kind === 'edge' && series.asn) edgeNetworks.add(EDGE_NETWORK_ASNS.get(series.asn)!)
      if (!location.position || !hasMapCoordinates(location.position[1], location.position[0])) continue
      if (crossing.kind !== 'none' && crossing.kind !== 'possible' && crossing.kind !== 'required') continue
      const confidence = crossing.kind === 'none' ? null : crossing.kind
      const route: SeriesRoute = { fixed: [], hops: [] }
      routes.set(series.id, route)
      // Each end remembers which candidates of the last crossing reach it, so the final connector follows them.
      let ends: { key: string; position: MapPosition; owners: number[] }[] = [{ key: 'gateway', position: gateway, owners: [] }]
      for (const [index, hop] of crossing.hops.entries()) {
        // The first and last crossings choose landings near the gateway and the destination themselves.
        const candidates = cablesBetween(hop.from, hop.to, index === 0 ? gateway : undefined, index === crossing.hops.length - 1 ? location.position : undefined)
        const total = hops.get(hop.id) ?? { hop, received: 0, sent: 0, confidence: confidence! }
        total.received += volume.received; total.sent += volume.sent
        if (confidence === 'required') total.confidence = 'required'
        if (crossing.measuredMs !== undefined) total.measuredMs = Math.min(total.measuredMs ?? Infinity, crossing.measuredMs)
        hops.set(hop.id, total)
        const drawn = candidates.slice(0, DRAWN_CANDIDATES)
        const options: string[][] = drawn.map(() => [])
        route.hops.push(options)
        const next: { key: string; position: MapPosition; owners: number[] }[] = []
        for (const [choice, candidate] of drawn.entries()) {
          const from = wrapPosition(candidate.from), to = wrapPosition(candidate.to)
          const fromKey = `landing:${vertexKey(from)}`, toKey = `landing:${vertexKey(to)}`
          // Connect from the nearest point reached so far, so branching stays readable.
          const start = ends.reduce((best, end) => distanceKm(end.position, from) < distanceKm(best.position, from) ? end : best)
          if (distanceKm(start.position, from) > CONNECTOR_MIN_KM) options[choice].push(add({ id: `land:${start.key}>${fromKey}`, kind: 'land', path: [start.position, from], confidence }, volume, location.id, series.trackId, series.id))
          const [a, b] = [fromKey, toKey].sort()
          for (const path of cableSection(candidate.cable, candidate.from, candidate.to)) {
            options[choice].push(add({ id: `sea:${candidate.cable.id}:${a}~${b}:${path.length}`, kind: 'sea', path, confidence, cableId: candidate.cable.id, hopId: hop.id, candidates: hop.candidates.length }, volume, location.id, series.trackId, series.id))
          }
          landings.set(fromKey, from); landings.set(toKey, to)
          const reached = next.find(end => end.key === toKey)
          if (reached) reached.owners.push(choice)
          else next.push({ key: toKey, position: to, owners: [choice] })
        }
        ends = next
      }
      for (const end of ends) {
        const id = add({ id: `land:${end.key}>loc:${location.id}`, kind: 'land', path: [end.position, location.position], confidence }, volume, location.id, series.trackId, series.id)
        const last = route.hops[route.hops.length - 1]
        if (!last) route.fixed.push(id)
        else for (const owner of end.owners) last[owner].push(id)
      }
    }
  }
  const result = [...edges.values()].map(({ locations: locationSet, tracks, series, ...edge }) => ({ ...edge, locationIds: [...locationSet].sort(), trackIds: [...tracks].sort(), seriesIds: [...series].sort() }))
    .sort((a, b) => (b.received + b.sent) - (a.received + a.sent) || a.id.localeCompare(b.id))
  return {
    edges: result, hops: [...hops.values()].sort((a, b) => (b.received + b.sent) - (a.received + a.sent) || a.hop.id.localeCompare(b.hop.id)),
    landings: [...landings].map(([id, position]) => ({ id, position })).sort((a, b) => a.id.localeCompare(b.id)),
    peak: Math.max(0, ...result.map(edge => edge.received + edge.sent)), totals, edgeNetworks: [...edgeNetworks].sort(), routes,
  }
}

export type CrossingSummary = { totals: Record<CrossingClass, number>; total: number; hops: { hop: SeaHop; bytes: number; confidence: CrossingConfidence }[]; edgeNetworks: string[] }
/** Bytes per crossing class and per region-to-region crossing for the filtered workspace's locations. */
export function summarizeCrossings(locations: readonly LocationTraffic[], origin: GatewayOrigin): CrossingSummary {
  const home = gatewayRegion(origin)
  const totals = emptyTotals()
  const hops = new Map<string, { hop: SeaHop; bytes: number; confidence: CrossingConfidence }>()
  const edgeNetworks = new Set<string>()
  for (const item of locations.flatMap(location => location.series.map(series => ({ ...series, position: location.position })))) {
    if (item.bytes <= 0) continue
    const crossing = classifySeries(item, home, { origin, position: item.position })
    totals[crossing.kind] += item.bytes
    if (crossing.kind === 'edge' && item.asn) edgeNetworks.add(EDGE_NETWORK_ASNS.get(item.asn)!)
    if (crossing.kind !== 'required' && crossing.kind !== 'possible') continue
    for (const hop of crossing.hops) {
      const entry = hops.get(hop.id) ?? { hop, bytes: 0, confidence: crossing.kind }
      entry.bytes += item.bytes
      if (crossing.kind === 'required') entry.confidence = 'required'
      hops.set(hop.id, entry)
    }
  }
  return {
    totals, total: Object.values(totals).reduce((sum, value) => sum + value, 0), edgeNetworks: [...edgeNetworks].sort(),
    hops: [...hops.values()].sort((a, b) => b.bytes - a.bytes || a.hop.id.localeCompare(b.hop.id)),
  }
}

export const hopLabel = (hop: Pick<SeaHop, 'from' | 'to'>) => `${regionLabel(hop.from)} – ${regionLabel(hop.to)}`

/** Split a path wherever it crosses the antimeridian, after folding longitudes into ±180. */
export function splitAntimeridian(path: MapPosition[]): MapPosition[][] {
  const wrap = (lon: number) => ((lon + 540) % 360) - 180
  const parts: MapPosition[][] = [[]]
  for (let i = 0; i < path.length; i++) {
    const point: MapPosition = [wrap(path[i][0]), path[i][1]]
    const previous = i ? path[i - 1] : null
    if (previous) {
      const prior: MapPosition = [wrap(previous[0]), previous[1]]
      if (Math.abs(point[0] - prior[0]) > 180) {
        const edge = prior[0] > 0 ? 180 : -180
        const span = 360 - Math.abs(point[0] - prior[0])
        const t = span ? (edge - prior[0]) * Math.sign(edge) / span : 0
        const lat = prior[1] + (point[1] - prior[1]) * Math.abs(t)
        parts[parts.length - 1].push([edge, lat])
        parts.push([[-edge, lat]])
      }
    }
    parts[parts.length - 1].push(point)
  }
  return parts.filter(part => part.length > 1)
}
