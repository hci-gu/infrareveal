import { memo, useId, useImperativeHandle, useMemo, useRef, useState } from 'react'
import type { Ref } from 'react'
import countries from './data/countries.json'
import type { MapPosition, GatewayOrigin } from './mapModel'
import { equalEarth, equalEarthPath } from './equalEarth'
import type { LocationTraffic, TrafficDirection } from './mapWorkspace'
import { formatBytes } from './format'
import { MapIcon } from './MapIcon'

const geography = countries.map(country => ({ ...country, path: country.polygons.map(polygon => polygon.map(ring => equalEarthPath(ring as MapPosition[], true)).join('')).join('') }))
const graticule = [
  ...Array.from({ length: 13 }, (_, i) => equalEarthPath(Array.from({ length: 61 }, (_, j) => [i * 30 - 180, j * 3 - 90]))),
  ...Array.from({ length: 5 }, (_, i) => equalEarthPath(Array.from({ length: 121 }, (_, j) => [j * 3 - 180, i * 30 - 60]))),
]
export type EqualEarthControls = { fit: (positions: MapPosition[]) => void }
export const EqualEarthMap = memo(function EqualEarthMap({ controlsRef, locations, origin, direction, selected, onSelect, labels, showTraffic }: {
  controlsRef: Ref<EqualEarthControls>; locations: LocationTraffic[]; origin: GatewayOrigin; direction: TrafficDirection; selected: string | null; onSelect: (id: string | null) => void; labels: boolean; showTraffic: boolean
}) {
  const id = useId().replace(/:/g, '')
  const svgRef = useRef<SVGSVGElement>(null)
  const drag = useRef<{ x: number; y: number; dx: number; dy: number; moved: boolean } | null>(null)
  const [camera, setCamera] = useState({ zoom: 1, x: 0, y: 0 })
  useImperativeHandle(controlsRef, () => ({ fit: positions => {
    if (!positions.length) return
    const points = positions.map(equalEarth), xs = points.map(p => p[0]), ys = points.map(p => p[1])
    const left = Math.min(...xs), right = Math.max(...xs), top = Math.min(...ys), bottom = Math.max(...ys)
    const zoom = Math.max(.75, Math.min(8, 800 / Math.max(40, right - left), 320 / Math.max(40, bottom - top)))
    setCamera({ zoom, x: (500 - (left + right) / 2) * zoom, y: (280 - (top + bottom) / 2) * zoom })
  } }), [])
  const [gx, gy] = equalEarth([origin.longitude, origin.latitude])
  const mapped = useMemo(() => locations.filter(location => location.position), [locations])
  const peak = Math.max(1, ...mapped.map(location => Math.max(location.received, location.sent)))
  const featured = locations.find(location => location.id === selected) ?? locations.find(location => location.bytes > 0)
  const select = (location: LocationTraffic) => { if (!drag.current?.moved) onSelect(selected === location.id ? null : location.id) }
  const fit = () => setCamera({ zoom: 1, x: 0, y: 0 })
  function zoom(delta: number) { setCamera(current => ({ ...current, zoom: Math.max(.75, Math.min(8, current.zoom * delta)) })) }
  return <div className="atlas-equal-earth" data-projection="equal-earth">
    <svg ref={svgRef} viewBox="0 0 1000 560" aria-label="Equal Earth traffic map" onWheel={event => { zoom(event.deltaY > 0 ? .9 : 1.1) }}
      onPointerDown={event => { if (event.button !== 0 || (event.target as Element).closest('[data-map-location]')) return; drag.current = { x: event.clientX, y: event.clientY, dx: camera.x, dy: camera.y, moved: false }; event.currentTarget.setPointerCapture(event.pointerId) }}
      onPointerMove={event => { if (!drag.current) return; const scale = 1000 / Math.max(1, event.currentTarget.getBoundingClientRect().width); const dx = event.clientX - drag.current.x, dy = event.clientY - drag.current.y; drag.current.moved ||= Math.abs(dx) + Math.abs(dy) > 4; setCamera(current => ({ ...current, x: drag.current!.dx + dx * scale, y: drag.current!.dy + dy * scale })) }}
      onPointerUp={event => { drag.current = null; if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId) }} onPointerCancel={() => { drag.current = null }}>
      <defs>{(['received', 'sent'] as const).map(key => <marker key={key} id={`${id}-${key}`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M1 1L9 5L1 9" fill="none" stroke={`var(--atlas-${key === 'received' ? 'down' : 'up'})`} strokeWidth="1.5" /></marker>)}</defs>
      <g transform={`translate(${500 + camera.x} ${280 + camera.y}) scale(${camera.zoom}) translate(-500 -280)`}>
        {graticule.map((d, index) => <path key={index} d={d} className="atlas-earth-grid" />)}
        {geography.map(country => <path key={`${country.code}:${country.name}`} d={country.path} className="atlas-earth-country" fillRule="evenodd" />)}
        {mapped.map(location => {
          const [x, y] = equalEarth(location.position!)
          const country = location.country
          const path = country?.polygons.map(polygon => polygon.map(ring => equalEarthPath(ring, true)).join('')).join('')
          const cy = Math.min(gy, y) - Math.max(18, Math.abs(gx - x) * .22)
          const dimmed = Boolean(selected && selected !== location.id)
          return <g key={location.id} className={dimmed ? 'is-dimmed' : ''} data-map-location={location.id} tabIndex={0} role="button" aria-pressed={selected === location.id} aria-label={`${location.label}, ${formatBytes(location.bytes)}, filter location`} onClick={() => select(location)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(selected === location.id ? null : location.id) } }}>
            <title>{`${location.label}\n↓ ${formatBytes(location.received)} downloaded\n↑ ${formatBytes(location.sent)} sent\n${location.detail}`}</title>
            {country && path && <path d={path} fillRule="evenodd" className="atlas-earth-footprint" />}
            {showTraffic && (['received', 'sent'] as const).filter(key => direction === 'both' || direction === key).map(key => {
              if (location[key] <= 0) return null
              // Country anchors are layout references, not located destination pins.
              const d = key === 'received' ? `M${x} ${y}Q${(gx + x) / 2} ${cy} ${gx} ${gy}` : `M${gx} ${gy + 4}Q${(gx + x) / 2} ${cy - 12} ${x} ${y + 4}`
              return <path key={key} className={`atlas-earth-flow ${key}${country ? ' country-estimate' : ''}`} d={d} markerEnd={`url(#${id}-${key})`} />
            })}
            {!country && <><circle cx={x} cy={y} r={10} fill="transparent" /><circle cx={x} cy={y} r={3.5} className="atlas-earth-point" />{(['received', 'sent'] as const).filter(key => direction === 'both' || direction === key).map((key, i) => <rect key={key} className={`atlas-earth-bar ${key}`} x={x + 7 + i * 6} y={y - location[key] / peak * 52} width={4} height={location[key] / peak * 52} rx={1} />)}</>}
            {country && !path && <text x={x} y={y} className="atlas-earth-location">{location.label} · country estimate</text>}
            {labels && (selected === location.id || mapped.length < 8) && <text x={x} y={y + 20} className="atlas-earth-location">{location.label}{country ? ' · country estimate' : ''}</text>}
          </g>
        })}
        <circle cx={gx} cy={gy} r={9} className="atlas-earth-gateway-ring" /><circle cx={gx} cy={gy} r={3} className="atlas-earth-gateway" />
        {labels && <text x={gx + 16} y={gy - 12} className="atlas-earth-location">{origin.label} · your devices</text>}
      </g>
    </svg>
    {featured && <div className="atlas-map-location-card" data-location-card={featured.id}><small>{selected ? 'Selected location' : 'Largest exchange'}</small><h3>{featured.label}</h3><div>{direction !== 'sent' && <span className="atlas-down">↓ {formatBytes(featured.received)}<small>Downloaded</small></span>}{direction !== 'received' && <span className="atlas-up">↑ {formatBytes(featured.sent)}<small>Sent</small></span>}</div><p>{featured.estimated ? '≈ Counter estimates · ' : featured.partial ? 'Partial capture · ' : ''}{featured.detail}</p></div>}
    <div className="atlas-map-tools" aria-label="Equal Earth map controls"><button type="button" className="atlas-icon-button" onClick={() => zoom(1.3)} aria-label="Zoom in"><MapIcon name="plus" /></button><button type="button" className="atlas-icon-button" onClick={() => zoom(1 / 1.3)} aria-label="Zoom out"><MapIcon name="minus" /></button><button type="button" className="atlas-icon-button" onClick={fit} aria-label="Fit world"><MapIcon name="expand" /></button><button type="button" className="atlas-icon-button" aria-label="Center on gateway" onClick={() => setCamera({ zoom: 2, x: (500 - gx) * 2, y: (280 - gy) * 2 })}><MapIcon name="target" /></button></div>
    <a className="atlas-earth-credit" href="https://www.naturalearthdata.com/" target="_blank" rel="noreferrer">Natural Earth</a>
  </div>
})
