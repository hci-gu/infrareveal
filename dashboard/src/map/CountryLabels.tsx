import type { DestinationVolume } from './destinationVolumes'
import { formatBytes } from './format'
import { leaderEnd } from './labelLayout'
import type { PlacedCountryLabel } from './labelLayout'

type Props = {
  labels: PlacedCountryLabel[]
  destinations: ReadonlyMap<string, DestinationVolume>
  selection: string | null
  selectedLocationId: string | null
  onCountry: (id: string | null) => void
}

/** Card size and position come from `layoutMapLabels`; this only renders. */
export function CountryLabels({ labels, destinations, selection, selectedLocationId, onCountry }: Props) {
  const leaders = labels.filter(label => label.leader)
  return <div className="atlas-country-labels" aria-label="Country-level traffic">
    {leaders.length > 0 && <svg className="atlas-country-leaders" aria-hidden="true">
      {leaders.map(({ id, rect, anchor }) => {
        const [x2, y2] = leaderEnd(rect, anchor)
        return <g key={id}><line x1={anchor[0]} y1={anchor[1]} x2={x2} y2={y2} /><circle cx={anchor[0]} cy={anchor[1]} r={2.5} /></g>
      })}
    </svg>}
    {labels.map(({ id, variant, rect }) => {
      const destination = destinations.get(id)
      if (!destination) return null
      const total = destination.received + destination.sent
      const selected = selectedLocationId === destination.id
      const dimmed = Boolean(selection && !destination.tracks.some(track => track.trackId === selection))
      const split = <span className="atlas-country-tracks" aria-hidden="true"><i style={{ width: `${destination.received / Math.max(1, total) * 100}%`, background: 'var(--atlas-down)' }} /><i style={{ width: `${destination.sent / Math.max(1, total) * 100}%`, background: 'var(--atlas-up)' }} /></span>
      return <div key={id} className={`atlas-country-label is-${variant}${dimmed ? ' is-dimmed' : ''}`} style={{ left: rect.left, top: rect.top, width: rect.width }} data-country-code={destination.country?.code} data-country-bytes={Math.round(total)} data-label-variant={variant}>
        <button type="button" className="atlas-country-summary" aria-pressed={selected} onClick={() => onCountry(selected ? null : destination.id)}
          title={variant === 'full' ? undefined : `${destination.location} · Country estimate, city unknown · ${formatBytes(total)} downloaded + sent`}>
          {variant === 'pill'
            ? <><span className="atlas-country-name"><i className="atlas-country-swatch" /><span>{destination.location}</span></span><span className="atlas-country-pill-total">{formatBytes(total)}</span></>
            : <>
              <span className="atlas-country-name"><i className="atlas-country-swatch" /><span>{destination.location}</span></span>
              {variant === 'full' && <span className="atlas-country-precision">Country estimate · City unknown</span>}
              <span className="atlas-country-total">{formatBytes(total)}{variant === 'full' && <small>Downloaded + sent</small>}</span>
              {split}
            </>}
        </button>
      </div>
    })}
  </div>
}
