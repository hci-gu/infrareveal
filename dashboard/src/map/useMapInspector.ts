import { useCallback, useMemo, useState } from 'react'
import { filterScope, scopeTracks } from './mapWorkspace'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'

/** Inspection never changes global filters. Detail lists share their projection. */
export function useMapInspector(overview: WorkspaceProjection, workspace: WorkspaceState, onWorkspace: (value: WorkspaceState) => void) {
  const scope = `${overview.scene.sessionId}:${filterScope(workspace)}`
  const [selected, setSelected] = useState<{ scope: string; trackId: string | null; locationId: string | null } | null>(null)
  if (selected && selected.scope !== scope) setSelected(null)
  const selection = selected?.scope === scope ? selected : null
  const location = overview.locations.find(location => location.id === selection?.locationId)
  const tracks = useMemo(() => location ? scopeTracks(overview.tracks, new Map(location.series.map(series => [series.id, series])), workspace.order) : overview.tracks, [location, overview.tracks, workspace.order])
  const track = tracks.find(track => track.id === selection?.trackId)
  const selectLocation = useCallback((locationId: string | null) => {
    setSelected({ scope, locationId, trackId: null })
  }, [scope])
  const selectTrack = useCallback((trackId: string | null) => {
    setSelected({ scope, trackId, locationId: selection?.locationId ?? null })
    if (!trackId && selection?.trackId) requestAnimationFrame(() => {
      const id = CSS.escape(selection.trackId!)
      const button = document.querySelector<HTMLButtonElement>(`button[data-location-track-id="${id}"]`)
        ?? document.querySelector<HTMLButtonElement>(`button[data-track-id="${id}"]`)
      button?.focus({ preventScroll: true })
    })
  }, [scope, selection])
  const closeLocation = useCallback(() => {
    selectLocation(null)
    if (location) requestAnimationFrame(() => document.querySelector<HTMLButtonElement>(`button[data-location-id="${CSS.escape(location.id)}"]`)?.focus({ preventScroll: true }))
  }, [selectLocation, location])

  return { track, location, tracks, open: Boolean(track || location), changeWorkspace: onWorkspace, selectLocation, selectTrack, closeLocation }
}
