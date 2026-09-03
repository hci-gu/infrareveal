import { describe, expect, it } from 'vitest'
import type { FlowActivityStatus, FlowActivityWindow } from '@infrareveal/session-state'
import type { PipelineEvent } from '../types'
import { deriveActivityDataQuality } from './activityDataQuality'

const startMs = Date.parse('2026-09-03T10:00:00.000Z')

describe('activity data quality', () => {
  it('reports a complete closed capture window independently of replay transport', () => {
    const quality = deriveActivityDataQuality(input({ windows: [window({ capture_complete: true })] }))

    expect(quality.level).toBe('complete')
    expect(quality.capture.label).toBe('Complete')
    expect(quality.stream.label).toBe('Not used')
    expect(quality.captureIntervals).toEqual([])
  })

  it('marks dropped capture activity as a partial interval', () => {
    const quality = deriveActivityDataQuality(input({
      windows: [window({ capture_complete: false, dropped_events: 37 })],
    }))

    expect(quality.level).toBe('partial')
    expect(quality.capture).toMatchObject({ level: 'partial', label: 'Partial' })
    expect(quality.captureIntervals[0]).toMatchObject({
      startMs,
      endMs: startMs + 5_000,
      level: 'partial',
      droppedEvents: 37,
    })
  })

  it('marks a stopped or failed capture window as unavailable', () => {
    const quality = deriveActivityDataQuality(input({
      windows: [window({ capture_running: false, capture_complete: false, last_error: 'listener stopped' })],
    }))

    expect(quality.level).toBe('unavailable')
    expect(quality.capture.detail).toContain('listener stopped')
    expect(quality.captureIntervals[0].level).toBe('unavailable')
  })

  it('does not confuse browser trace loss with packet activity loss', () => {
    const quality = deriveActivityDataQuality(input({
      windows: [window({ capture_complete: true })],
      healthEvents: [healthEvent('trace-gap:12', 2_000, 12)],
      streamDropped: 12,
      traceConnection: 'gap',
      usesLiveStream: true,
    }))

    expect(quality.capture.level).toBe('complete')
    expect(quality.captureIntervals).toEqual([])
    expect(quality.stream).toMatchObject({ level: 'partial', droppedEvents: 12 })
    expect(quality.streamGapTimes).toEqual([startMs + 2_000])
    expect(quality.level).toBe('partial')
  })

  it('uses live capture status only at the live edge', () => {
    const current = deriveActivityDataQuality(input({ status: status(), atLiveEdge: true }))
    const historical = deriveActivityDataQuality(input({ status: status(), atLiveEdge: false }))

    expect(current.capture.label).toBe('Healthy now')
    expect(historical.capture.level).toBe('unknown')
  })

  it('turns a live capture-health event into quality metadata, not traffic', () => {
    const quality = deriveActivityDataQuality(input({
      cursorMs: startMs + 2_500,
      healthEvents: [healthEvent('capture-health:1', 2_000, 5)],
    }))

    expect(quality.capture.level).toBe('partial')
    expect(quality.captureIntervals).toHaveLength(1)
    expect(quality.streamGapTimes).toEqual([])
  })
})

function input(overrides: Partial<Parameters<typeof deriveActivityDataQuality>[0]> = {}) {
  return {
    cursorMs: startMs + 2_500,
    windows: [],
    status: null,
    healthEvents: [],
    streamDropped: 0,
    traceConnection: 'idle' as const,
    usesLiveStream: false,
    atLiveEdge: false,
    ...overrides,
  }
}

function window(overrides: Partial<FlowActivityWindow> = {}): FlowActivityWindow {
  return {
    id: 'window-1', session: 'session-1', window_key: 'window-1', window_start: new Date(startMs).toISOString(),
    window_ms: 5_000, capture_running: true, capture_complete: false, dropped_events: 0, last_error: '',
    ...overrides,
  }
}

function status(overrides: Partial<FlowActivityStatus> = {}): FlowActivityStatus {
  return {
    id: 'status-1', session: 'session-1', interface: 'wlan0', enabled: true, running: true,
    dropped_events: 0, last_error: '', last_event_at: new Date(startMs + 2_000).toISOString(),
    reported_at: new Date(startMs + 2_500).toISOString(), ...overrides,
  }
}

function healthEvent(id: string, offsetMs: number, droppedEvents: number): PipelineEvent {
  return {
    id, sequence: 1, sessionId: 'session-1', traceId: id, kind: 'health', stage: 'health',
    occurredAtMs: startMs + offsetMs, timing: 'observed',
    summary: { captureComplete: false, droppedEvents },
  }
}
