// Browser-only fixture: exercise the real timeline without mutating a session.
import type { CSSProperties } from 'react'
import { createRoot } from 'react-dom/client'
import { MapTimeline } from '../src/map/MapTimeline'
import { indexDestinationVolumes } from '../src/map/destinationVolumes'
import { seriesKey, type CaptureInterval, type TrafficChunk } from '@infrareveal/session-state'
import type { WorkspaceProjection } from '../src/map/mapWorkspace'
import type { MapSeries } from '../src/map/mapTracks'
import fixture from '../../testdata/aggregate-window-v2.json'
import '../src/map/map.css'
import '../src/map/workspace.css'

export function mountTimelineMotion(container: HTMLElement) {
  const root = createRoot(container)
  const start = fixture.window.from_ms, end = start + 600_000
  const coverage = [{ ...fixture.window.coverage[0], start_ms: start, end_ms: end + 60_000 }] as CaptureInterval[]
  const chunks = Array.from({ length: 135 }, (_, i) => ({ ...fixture.window.series[0], client_id: `client-${i}`, start_ms: start, bucket_ms: 50,
    samples: [[i === 134 ? 598_000 : i === 133 ? 595_000 : i === 132 ? 420_000 : 1000, 400, 2400, 0, 0, 1, 1]],
  })) as TrafficChunk[]
  const render = (cursorMs: number) => {
    const rows = chunks.map((chunk, i) => ({ id: seriesKey(chunk), trackId: `track-${i}`, label: `Endpoint ${i}`, client: `client-${i}`,
      endpoint: `${i}.example:443`, location: 'Test location', locationId: 'test', received: 2400, sent: 400, bytes: 2800, partial: false, lastActivityMs: start,
      series: [{ id: seriesKey(chunk), startMs: start, endMs: end + 60_000, chunks: [chunk] } as MapSeries],
    }))
    const data = { rows, scene: { sessionId: 'motion-fixture' }, locations: [] } as unknown as WorkspaceProjection
    root.render(<div className="atlas-page" data-theme="dark" style={{ position: 'fixed', inset: 0, '--atlas-overview-width': '0px' } as CSSProperties}>
      <MapTimeline data={data} index={indexDestinationVolumes(chunks, start, coverage, end + 60_000)} startMs={start} endMs={end + 60_000} cursorMs={cursorMs}
        state={{ direction: 'both', locationId: null, expanded: true }} onChange={() => {}} onSeek={() => {}} onTrack={() => {}}
        loading={false} error={false} refreshing={false} live following onFollowLive={() => {}} />
    </div>)
  }
  render(end)
  return {
    advance(lane: number, seconds: number) { chunks[lane].samples.push([600_000 + seconds * 1000 - 50, 400, 2400, 0, 0, 1, 1]); render(end + seconds * 1000) },
    dispose() { root.unmount() },
  }
}
