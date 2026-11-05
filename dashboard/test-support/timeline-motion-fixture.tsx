// Browser-only fixture: exercise the real timeline without mutating a session.
import type { CSSProperties } from 'react'
import { createRoot } from 'react-dom/client'
import { MapTimeline } from '../src/map/MapTimeline'
import { indexDestinationVolumes } from '../src/map/destinationVolumes'
import { type CaptureInterval, type TrafficChunk, type MapWindow, type SessionManifest } from '@infrareveal/session-state'
import { projectWorkspace } from '../src/map/mapWorkspace'
import { buildMapTimelineScene } from '../src/map/mapModel'
import { buildMapTrackCatalog } from '../src/map/mapTracks'
import fixture from '../../testdata/aggregate-window-v2.json'
import '../src/map/map.css'
import '../src/map/workspace.css'

export function mountTimelineMotion(container: HTMLElement) {
  const root = createRoot(container)
  const start = fixture.window.from_ms, end = start + 600_000
  const coverage = [{ ...fixture.window.coverage[0], start_ms: start, end_ms: end + 60_000 }] as CaptureInterval[]
  const chunks = Array.from({ length: 135 }, (_, i) => ({ ...fixture.window.series[0], client_id: `client-${i}`, service_key: `service-${i}`, service_label: `Endpoint ${i}`, start_ms: start, bucket_ms: 50,
    samples: [[i === 134 ? 598_000 : i === 133 ? 595_000 : i === 132 ? 420_000 : 1000, 400, 2400, 0, 0, 1, 1]],
  })) as TrafficChunk[]
  const render = (cursorMs: number) => {
    const source = { ...fixture.window, from_ms: start, to_ms: end + 60_000, series: chunks } as MapWindow
    const scene = buildMapTimelineScene(source, fixture.manifest as SessionManifest, { latitude: 57.7, longitude: 11.9, label: 'Gateway' })
    const index = indexDestinationVolumes(chunks, start, coverage, end + 60_000)
    const state = { direction: 'both' as const, locationId: null, expanded: true, order: 'latest' as const }
    const data = projectWorkspace(buildMapTrackCatalog(source), scene, index, cursorMs, state)
    root.render(<div className="atlas-page" data-theme="dark" style={{ position: 'fixed', inset: 0, '--atlas-overview-width': '0px' } as CSSProperties}>
      <MapTimeline data={data} index={index} startMs={start} endMs={end + 60_000} cursorMs={cursorMs}
        state={state} onSeek={() => {}} onTrack={() => {}}
        loading={false} error={false} refreshing={false} live />
    </div>)
  }
  render(end)
  return {
    advance(lane: number, seconds: number) { chunks[lane].samples.push([600_000 + seconds * 1000 - 50, 400, 2400, 0, 0, 1, 1]); render(end + seconds * 1000) },
    dispose() { root.unmount() },
  }
}
