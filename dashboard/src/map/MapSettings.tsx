import { useEffect, useRef } from 'react'
import type { MapPreferences } from './mapPreferences'
import { MapIcon } from './MapIcon'

export function MapSettings({ open, preferences, onChange, onClose }: { open: boolean; preferences: MapPreferences; onChange: (value: MapPreferences) => void; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => { if (open && !ref.current?.open) ref.current?.showModal(); else if (!open) ref.current?.close() }, [open])
  return <dialog ref={ref} className="atlas-settings" aria-labelledby="map-settings-title" onClose={onClose} onCancel={onClose} onClick={event => {
    if (event.target !== event.currentTarget) return
    const rect = event.currentTarget.getBoundingClientRect()
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) onClose()
  }}>
    <header><h2 id="map-settings-title">Display settings</h2><button type="button" className="atlas-icon-button" aria-label="Close display settings" onClick={onClose}><MapIcon name="close" /></button></header>
    <div className="atlas-settings-body">
      <label htmlFor="map-projection">Map projection</label>
      <select id="map-projection" value={preferences.projection} onChange={event => onChange({ ...preferences, projection: event.target.value as MapPreferences['projection'] })}><option value="equal-earth">Equal Earth</option><option value="mercator">Mercator</option></select>
      <p>{preferences.projection === 'equal-earth' ? 'Preserves relative land area. A flat worldwide view using bundled geography.' : 'Detailed map with perspective and approximate traceroute paths. Basemap tiles require internet.'}</p>
      <span className="atlas-setting-label">Appearance</span><div className="atlas-segmented" aria-label="Appearance">{(['dark', 'light', 'system'] as const).map(theme => <button key={theme} type="button" aria-pressed={preferences.theme === theme} onClick={() => onChange({ ...preferences, theme })}>{theme[0].toUpperCase() + theme.slice(1)}</button>)}</div>
      <label className="atlas-setting-check"><span>Show location labels</span><input type="checkbox" checked={preferences.labels} onChange={event => onChange({ ...preferences, labels: event.target.checked })} /></label>
      <p>Teal means downloaded; amber means sent. Arrows and labels identify direction in both themes.</p>
    </div><footer><span>Saved on this display</span><button type="button" onClick={onClose}>Done</button></footer>
  </dialog>
}
