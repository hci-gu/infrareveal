import { WebMercatorViewport } from '@deck.gl/core'
import type { MapViewState } from '@deck.gl/core'
import type { DestinationVolume } from './destinationVolumes'
import type { TrackColors } from './mapTracks'
import { colorCSS } from './mapTracks'
import { directionalBytes, directionLabel } from './mapWorkspace'
import type { TrafficDirection } from './mapWorkspace'
import { formatBytes } from './format'

type Props = {
  direction: TrafficDirection
  destinations: DestinationVolume[]
  viewState: MapViewState
  width: number
  height: number
  selection: string | null
  selectedCountry: string | null
  colors: TrackColors
  onCountry: (id: string | null) => void
  onTrack: (id: string) => void
}

export function CountryLabels({ direction, destinations, viewState, width, height, selection, selectedCountry, colors, onCountry, onTrack }: Props) {
  const viewport = new WebMercatorViewport({ ...viewState, width, height })
  const occupied: number[][] = []
  return <div className="atlas-country-labels" aria-label="Country-level traffic">
    {destinations.map(destination => {
      const [x, y] = viewport.project(destination.position)
      const leftEdge = 12
      const rightEdge = width - (selection && width > 1000 ? 390 : 60)
      const labelWidth = Math.min(200, rightEdge - leftEdge)
      if ((width <= 760 && selection) || x < leftEdge - 50 || x > rightEdge + 50 || y < 75 || y > height) return null
      const left = Math.max(leftEdge, Math.min(rightEdge - labelWidth, x - labelWidth / 2))
      const expanded = selectedCountry === destination.id
      const bottom = height - 95
      const detailsHeight = expanded ? Math.min(240, Math.max(70, bottom - 200)) : 0
      let top = Math.max(80, Math.min(y + 20, bottom - 112 - detailsHeight))
      while (occupied.some(([px, py]) => Math.abs(px - left) < labelWidth + 8 && Math.abs(py - top) < 120)) top -= 120
      if (top < 75) return null
      occupied.push([left, top])
      const dimmed = Boolean(selection && !destination.tracks.some(track => track.trackId === selection))
      return <div key={destination.id} className={`atlas-country-label${dimmed ? ' is-dimmed' : ''}`} style={{ left, top, width: labelWidth }} data-country-code={destination.country?.code} data-country-bytes={Math.round(directionalBytes(destination, direction))}>
        <button type="button" className="atlas-country-summary" aria-expanded={expanded} onClick={() => onCountry(expanded ? null : destination.id)}>
          <span className="atlas-country-name"><i className="atlas-country-swatch" />{destination.location}</span>
          <span className="atlas-country-precision">Country estimate · City unknown</span>
          <span className="atlas-country-total">{destination.estimated ? '≈ ' : ''}{formatBytes(directionalBytes(destination, direction))}<small>{directionLabel(direction)}</small></span>
          <span className="atlas-country-tracks" aria-hidden="true">{direction !== 'sent' && <i style={{ width: `${destination.received / Math.max(1, directionalBytes(destination, direction)) * 100}%`, background: 'var(--atlas-down)' }} />}{direction !== 'received' && <i style={{ width: `${destination.sent / Math.max(1, directionalBytes(destination, direction)) * 100}%`, background: 'var(--atlas-up)' }} />}</span>
        </button>
        {expanded && <div className="atlas-country-details" style={{ maxHeight: detailsHeight }}>
          <p>{direction !== 'sent' && <>↓ {formatBytes(destination.received)} downloaded<br /></>}{direction !== 'received' && <>↑ {formatBytes(destination.sent)} sent</>}</p>
          <p>{destination.ips.length} destinations · {destination.flowCount} connections</p>
          <p>Only destinations without a city estimate. The footprint does not indicate where within the country traffic goes.</p>
          <p>{destination.estimated ? 'Includes flow-counter estimates' : 'Captured wire bytes'}{destination.partial ? ' · Partial capture' : ''}</p>
          {destination.tracks.map(track => <button key={track.trackId} type="button" onClick={() => onTrack(track.trackId)}><i style={{ background: colorCSS(colors.get(track.trackId)) }} /><span>{track.label}</span><strong>{formatBytes(directionalBytes(track, direction))}</strong></button>)}
        </div>}
      </div>
    })}
  </div>
}
