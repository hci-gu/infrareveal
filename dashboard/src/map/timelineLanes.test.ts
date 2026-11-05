import { expect, it } from 'vitest'
import { seriesKey, type TrafficChunk, type CaptureInterval } from '@infrareveal/session-state'
import fixture from '../../../testdata/aggregate-window-v2.json'
import { indexDestinationVolumes } from './destinationVolumes'
import { timelineLanes } from './timelineLanes'
import type { TimelineTrafficRow } from './mapWorkspace'

it('uses completed directional traffic in the displayed interval, excluding future samples and old totals', () => {
  const chunk = { ...fixture.window.series[0], start_ms: 0, bucket_ms: 50,
    samples: [[100, 10000, 10000, 0, 0, 1, 1], [1000, 100, 0, 0, 0, 1, 0], [1050, 0, 200, 0, 0, 0, 1], [1100, 90000, 90000, 0, 0, 1, 1]],
  } as TrafficChunk
  const index = indexDestinationVolumes([chunk], 0, fixture.window.coverage as CaptureInterval[])
  const row = { id: seriesKey(chunk), bytes: 900000, lastActivityMs: 999999, series: [{ id: seriesKey(chunk) }] } as TimelineTrafficRow
  const range = { from: 1000, to: 2000 }
  expect(timelineLanes([row], index, range, 1125, 'received')[0]).toMatchObject({ windowBytes: 200, windowLastActivityMs: 1100 })
  expect(timelineLanes([row], index, range, 1125, 'sent')[0]).toMatchObject({ windowBytes: 100, windowLastActivityMs: 1050 })
  expect(timelineLanes([row], index, range, 1025, 'both')[0]).toMatchObject({ windowBytes: 0, windowLastActivityMs: 0 })
  expect(timelineLanes([row], index, { from: 1150, to: 2000 }, 2000, 'both')[0]).toMatchObject({ windowBytes: 0, windowLastActivityMs: 0 })
})


it('fades quiet history without dropping it or fading a held window further', () => {
  const chunk = { ...fixture.window.series[0], start_ms: 0, bucket_ms: 50, samples: [[1000, 100, 200, 0, 0, 1, 1]] } as TrafficChunk
  const index = indexDestinationVolumes([chunk])
  const row = { id: seriesKey(chunk), series: [{ id: seriesKey(chunk) }] } as TimelineTrafficRow
  const project = (to: number, cursor = to) => timelineLanes([row], index, { from: 0, to }, cursor, 'both')[0]
  expect(project(5000)).toMatchObject({ recentlyActive: true, activityOpacity: 1, windowBytes: 300 })
  expect(project(16_049)).toMatchObject({ recentlyActive: true, activityOpacity: 1 })
  expect(project(16_050)).toMatchObject({ recentlyActive: false, activityOpacity: 1, windowBytes: 300 })
  expect(project(61_050)).toMatchObject({ recentlyActive: false, activityOpacity: .8125, windowBytes: 300 })
  expect(project(250_000)).toMatchObject({ recentlyActive: false, activityOpacity: .5, windowBytes: 300 })
  expect(project(5000, 250_000)).toMatchObject({ recentlyActive: true, activityOpacity: 1 })
})
