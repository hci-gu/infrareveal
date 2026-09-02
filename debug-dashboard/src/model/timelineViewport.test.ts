import { describe, expect, it } from 'vitest'
import { activityVisualMetrics, resolveTimelineViewport } from './timelineViewport'

describe('timeline viewport', () => {
  it('uses the complete selected domain lifetime for the all preset', () => {
    expect(resolveTimelineViewport({
      currentFrame: 3_000,
      durationInFrames: 18_000,
      focusBounds: { start: 600, end: 2_400 },
      followLive: true,
      zoomFrames: 'all',
    })).toEqual({ start: 600, end: 2_400 })
  })

  it('keeps a focused zoom window inside the selected domain history', () => {
    expect(resolveTimelineViewport({
      currentFrame: 10_000,
      durationInFrames: 18_000,
      focusBounds: { start: 600, end: 2_400 },
      followLive: false,
      zoomFrames: 300,
    })).toEqual({ start: 2_100, end: 2_400 })
  })

  it('gives packet activity a larger minimum mark in domain focus', () => {
    expect(activityVisualMetrics(true)).toMatchObject({
      columnWidth: 3,
      packetOnlyHeight: 3,
      maxDirectionalHeight: 25,
    })
    expect(activityVisualMetrics(false).columnWidth).toBe(1)
  })
})
