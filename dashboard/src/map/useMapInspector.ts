import { useCallback, useState } from 'react'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'

/** Service details drill into the current location; a new location starts fresh. */
export function useMapInspector(overview: WorkspaceProjection, workspace: WorkspaceState, onWorkspace: (value: WorkspaceState) => void) {
  const [selected, setSelected] = useState<{ trackId: string; locationId: string | null } | null>(null)
  const track = selected?.locationId === workspace.locationId ? overview.tracks.find(track => track.id === selected?.trackId) : undefined
  const location = overview.locations.find(location => location.id === workspace.locationId)

  const changeWorkspace = useCallback((next: WorkspaceState) => {
    if (next.locationId !== workspace.locationId) setSelected(null)
    onWorkspace(next)
  }, [workspace.locationId, onWorkspace])
  const selectLocation = useCallback((locationId: string | null) => changeWorkspace({ ...workspace, locationId }), [workspace, changeWorkspace])
  const selectTrack = useCallback((trackId: string | null) => {
    setSelected(trackId ? { trackId, locationId: workspace.locationId } : null)
    if (!trackId && selected) requestAnimationFrame(() => {
      const id = CSS.escape(selected.trackId)
      const button = document.querySelector<HTMLButtonElement>(`button[data-location-track-id="${id}"]`)
        ?? document.querySelector<HTMLButtonElement>(`button[data-track-id="${id}"]`)
      button?.focus({ preventScroll: true })
    })
  }, [workspace.locationId, selected])
  const closeLocation = useCallback(() => {
    selectLocation(null)
    requestAnimationFrame(() => document.querySelector<HTMLButtonElement>(`button[data-location-id="${CSS.escape(workspace.locationId ?? '')}"]`)?.focus({ preventScroll: true }))
  }, [selectLocation, workspace.locationId])

  return { track, location, open: Boolean(track || location), changeWorkspace, selectLocation, selectTrack, closeLocation }
}
