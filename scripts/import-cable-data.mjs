#!/usr/bin/env node
// Converts TeleGeography submarine cable geometry (their cable-geo.json GeoJSON)
// into dashboard/src/map/data/cables.json.
//
// Kept: cable id, name, colour and its exact line geometry (rounded to ~10 m).
// Derived: landing points (line ends that are not branching units) and the
// country each lands in, by point-in-polygon on the bundled Natural Earth
// outlines, falling back to the nearest coastline within LANDING_MAX_KM.
// Landings without a country (mostly small islands) are dropped. For every pair
// of landings, `distances` holds the length along the cable's own geometry in
// km (null when the source lines do not connect them). `joins` lists the extra
// links (branch snaps and bridges) the dashboard adds to the cable's own lines.
//
// Usage: node scripts/import-cable-data.mjs [path/to/cables.json]
import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const DEFAULT_SOURCE = fileURLToPath(new URL('../../RED-infra-reveal-dashboard/src/components/Map/geojson/cables.json', import.meta.url))
const COUNTRIES = fileURLToPath(new URL('../dashboard/src/map/data/countries.json', import.meta.url))
const OUTPUT = fileURLToPath(new URL('../dashboard/src/map/data/cables.json', import.meta.url))
/** Natural Earth 1:110m coastlines are coarse; landings this close to a country belong to it. */
const LANDING_MAX_KM = 120
/** Branches often meet another line mid-way or a few metres off; ends this close are junctions, not landings. */
const SNAP_KM = 10
/**
 * Pieces of one cable that still do not touch are bridged at their closest
 * points when this close: separate landing stations of one system (2Africa's
 * two loops at Cape Town) or branches drawn short of the trunk (Medusa).
 */
const BRIDGE_KM = 100

const source = JSON.parse(await readFile(process.argv[2] ?? DEFAULT_SOURCE, 'utf8'))
const countries = JSON.parse(await readFile(COUNTRIES, 'utf8')).filter(country => /^[A-Z]{2}$/.test(country.code))

const round = value => Math.round(value * 1e4) / 1e4
/** Lines meet at shared vertices; ±180° is one meridian. */
const key = ([lon, lat]) => `${Math.abs(lon) > 179.9999 ? 180 : lon.toFixed(4)},${lat.toFixed(4)}`
const rad = Math.PI / 180
function km([lon1, lat1], [lon2, lat2]) {
  const h = Math.sin((lat2 - lat1) * rad / 2) ** 2 + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin((lon2 - lon1) * rad / 2) ** 2
  return 12742 * Math.asin(Math.min(1, Math.sqrt(h)))
}
function inside(ring, [x, y]) {
  let result = false
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const [xi, yi] = ring[i], [xj, yj] = ring[j]
    if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) result = !result
  }
  return result
}
function countryAt(point) {
  for (const country of countries) for (const polygon of country.polygons) if (inside(polygon[0], point) && !polygon.slice(1).some(hole => inside(hole, point))) return country.code
  let best = null, distance = LANDING_MAX_KM
  for (const country of countries) for (const polygon of country.polygons) for (const vertex of polygon[0]) {
    const d = km(point, vertex)
    if (d < distance) { distance = d; best = country.code }
  }
  return best
}

/** Closest-point links between a cable's still-separate pieces, nearest first, up to BRIDGE_KM. */
function bridges(lines, junctions) {
  const parent = lines.map((_, i) => i)
  const find = i => { while (parent[i] !== i) i = parent[i] = parent[parent[i]]; return i }
  const owner = new Map()
  lines.forEach((line, i) => line.forEach(point => { const k = key(point); if (owner.has(k)) parent[find(i)] = find(owner.get(k)); else owner.set(k, i) }))
  for (const [end, vertex] of junctions) parent[find(owner.get(key(end)))] = find(owner.get(key(vertex)))
  const added = []
  while (true) {
    const groups = new Map()
    lines.forEach((line, i) => groups.set(find(i), [...groups.get(find(i)) ?? [], i]))
    if (groups.size < 2) return added
    let best = null
    const pieces = [...groups.values()]
    for (let a = 0; a < pieces.length; a++) for (let b = a + 1; b < pieces.length; b++) {
      for (const i of pieces[a]) for (const p of lines[i]) for (const j of pieces[b]) for (const q of lines[j]) {
        const d = km(p, q)
        if (!best || d < best.d) best = { d, p, q, i, j }
      }
    }
    if (best.d > BRIDGE_KM) return added
    added.push([best.p, best.q])
    parent[find(best.i)] = find(best.j)
  }
}

/** Shortest distance along a cable's lines between each pair of landings (Dijkstra with a binary heap). */
function alongCable(lines, landings, junctions) {
  const links = new Map()
  const link = (a, b, d) => links.set(a, [...links.get(a) ?? [], [b, d]])
  for (const line of lines) for (let i = 1; i < line.length; i++) {
    const a = key(line[i - 1]), b = key(line[i]), d = km(line[i - 1], line[i])
    link(a, b, d); link(b, a, d)
  }
  for (const [end, vertex] of junctions) { const a = key(end), b = key(vertex), d = km(end, vertex); if (a !== b) { link(a, b, d); link(b, a, d) } }
  return landings.map(origin => {
    const cost = new Map([[key(origin.position), 0]]), heap = [[0, key(origin.position)]]
    const push = item => { heap.push(item); for (let i = heap.length - 1; i > 0;) { const p = (i - 1) >> 1; if (heap[p][0] <= heap[i][0]) break; [heap[p], heap[i]] = [heap[i], heap[p]]; i = p } }
    const pop = () => { const top = heap[0], last = heap.pop(); if (heap.length) { heap[0] = last; for (let i = 0; ;) { const l = 2 * i + 1, r = l + 1; let m = i; if (l < heap.length && heap[l][0] < heap[m][0]) m = l; if (r < heap.length && heap[r][0] < heap[m][0]) m = r; if (m === i) break; [heap[m], heap[i]] = [heap[i], heap[m]]; i = m } } return top }
    while (heap.length) {
      const [d, node] = pop()
      if (d > cost.get(node)) continue
      for (const [next, length] of links.get(node) ?? []) if (d + length < (cost.get(next) ?? Infinity)) { cost.set(next, d + length); push([d + length, next]) }
    }
    return landings.map(target => { const d = cost.get(key(target.position)); return d === undefined ? null : Math.round(d) })
  })
}

const cables = new Map()
for (const feature of source.features) {
  const { id, name, color } = feature.properties
  const cable = cables.get(id) ?? { id, name, color, lines: [] }
  cable.lines.push(...feature.geometry.coordinates.map(line => line.map(([lon, lat]) => [round(lon), round(lat)])))
  cables.set(id, cable)
}
const output = []
for (const cable of cables.values()) {
  const junctions = []
  const landings = new Map()
  for (const [index, line] of cable.lines.entries()) for (const end of [line[0], line[line.length - 1]]) {
    // A line end touching another line of the same cable is a branching unit; otherwise it is a landing.
    let nearest = null, distance = SNAP_KM
    for (const [other, candidate] of cable.lines.entries()) {
      if (other === index) continue
      for (const vertex of candidate) { const d = km(end, vertex); if (d <= distance) { distance = d; nearest = vertex } }
    }
    if (nearest) junctions.push([end, nearest])
    else if (!landings.has(key(end))) landings.set(key(end), { position: end, country: countryAt(end) })
  }
  const joins = [...junctions, ...bridges(cable.lines, junctions)].filter(([a, b]) => key(a) !== key(b))
  const located = [...landings.values()].filter(landing => landing.country)
  output.push({ ...cable, landings: located, distances: alongCable(cable.lines, located, joins), joins })
}
output.sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id))
await writeFile(OUTPUT, JSON.stringify({
  source: `TeleGeography Submarine Cable Map (submarinecablemap.com) cable-geo.json, imported ${new Date().toISOString().slice(0, 10)}`,
  cables: output,
}) + '\n')
const landed = output.flatMap(cable => cable.landings)
const unconnected = output.reduce((sum, cable) => sum + cable.distances.flat().filter(d => d === null).length, 0)
console.log(`Wrote ${output.length} cables with ${landed.length} located landings (${unconnected / 2} landing pairs not connected by the source lines) to ${OUTPUT}`)
