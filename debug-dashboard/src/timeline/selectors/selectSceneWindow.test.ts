import { describe, expect, it } from 'vitest'
import type { SessionComposition } from '../../model/sessionModel'
import { createRecordedRenderBundle, parseRecordedRenderBundle } from '../../remotion/renderBundle'
import { selectSceneWindow } from './selectSceneWindow'

const base = {
  fps: 30,
  width: 1440,
  height: 810,
  sessionStartMs: 0,
  sessionEndMs: 60_000,
  durationInFrames: 1800,
  clips: [
    { id: 'early', serviceGroupId: 'one', startMs: 0, endMs: 1000, bytes: 10, packets: 1, activity: emptyActivity() },
    { id: 'late', serviceGroupId: 'two', startMs: 50_000, endMs: 51_000, bytes: 20, packets: 2, activity: emptyActivity() },
  ],
  lanes: [
    { id: 'lane-one', serviceGroupId: 'one', clips: [{ id: 'early' }] },
    { id: 'lane-two', serviceGroupId: 'two', clips: [{ id: 'late' }] },
  ],
  serviceGroups: [{ id: 'one' }, { id: 'two' }],
  captureStatus: null,
  totals: { flowCount: 2, attributedCount: 0, routeCount: 0, byteCount: 30, packetCount: 3, trafficCountersAvailable: true },
} as unknown as SessionComposition

function emptyActivity() {
  return {
    samples: [],
    completeRanges: [],
    activeMs: 0,
    coveredMs: 0,
    idleMs: 0,
    payloadBytesOut: 0,
    payloadBytesIn: 0,
    wireBytesOut: 0,
    wireBytesIn: 0,
    packetsOut: 0,
    packetsIn: 0,
    bucketMs: null,
    droppedEvents: 0,
    captureComplete: false,
    captureAvailable: false,
  }
}

describe('selectSceneWindow', () => {
  it('materializes only records overlapping the requested scene window', () => {
    const scene = selectSceneWindow(base, {
      fromMs: 49_000,
      toMs: 52_000,
      overview: false,
      focusedServiceId: null,
      selectedClipId: null,
    })
    expect(scene.clips.map((clip) => clip.id)).toEqual(['late'])
    expect(scene.lanes.map((lane) => lane.id)).toEqual(['lane-two'])
  })

  it('creates a serializable recorded render bundle', () => {
    const scene = selectSceneWindow(base, {
      fromMs: 0,
      toMs: 60_000,
      overview: true,
      focusedServiceId: null,
      selectedClipId: null,
    })
    const bundle = createRecordedRenderBundle('session', scene, '2026-09-02T09:00:00Z')
    expect(parseRecordedRenderBundle(JSON.stringify(bundle)).sceneWindow.clips).toHaveLength(2)
  })

  it('removes raw samples and caps pre-rendered activity to screen-scale columns', () => {
    const composition = structuredClone(base)
    composition.clips[0].activity.samples = Array.from({ length: 2_000 }, (_, index) => ({
      startMs: index * 20,
      durationMs: 20,
      payloadBytesOut: 1,
      payloadBytesIn: 0,
      packetsOut: 1,
      packetsIn: 0,
      complete: true,
    }))
    const scene = selectSceneWindow(composition, {
      fromMs: 0,
      toMs: 40_000,
      overview: true,
      focusedServiceId: null,
      selectedClipId: null,
      loadedRanges: [{ fromMs: 0, toMs: 40_000, complete: true }],
    })

    expect(scene.clips[0].activityColumns.length).toBeLessThanOrEqual(1024)
    expect('samples' in scene.clips[0].activity).toBe(false)
    expect(scene.loadedRanges).toEqual([{ fromMs: 0, toMs: 40_000, complete: true }])
  })
})
