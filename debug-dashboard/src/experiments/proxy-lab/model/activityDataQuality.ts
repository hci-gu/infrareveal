import type { FlowActivityStatus, FlowActivityWindow } from '@infrareveal/session-state'
import type { PipelineEvent } from '../types'

const FALLBACK_WINDOW_MS = 5_000

export type DataQualityLevel = 'complete' | 'partial' | 'unavailable' | 'unknown'
export type TraceConnectionState = 'idle' | 'connecting' | 'live' | 'reconnecting' | 'gap' | 'error'

export type DataQualityState = {
  level: DataQualityLevel
  label: string
  detail: string
}

export type CaptureQualityInterval = {
  id: string
  startMs: number
  endMs: number
  level: 'partial' | 'unavailable'
  droppedEvents: number
  detail: string
}

export type ActivityDataQuality = {
  level: DataQualityLevel
  label: string
  capture: DataQualityState
  stream: DataQualityState & { droppedEvents: number }
  captureIntervals: CaptureQualityInterval[]
  streamGapTimes: number[]
}

export type ActivityDataQualityInput = {
  cursorMs: number
  windows: readonly FlowActivityWindow[]
  status?: FlowActivityStatus | null
  healthEvents: readonly PipelineEvent[]
  streamDropped: number
  traceConnection: TraceConnectionState
  usesLiveStream: boolean
  atLiveEdge: boolean
}

/** Capture completeness and browser stream delivery are separate failure domains.
 * This projection keeps that distinction while producing one compact UI status. */
export function deriveActivityDataQuality(input: ActivityDataQualityInput): ActivityDataQuality {
  const parsedWindows = input.windows
    .map(parseWindow)
    .filter((window): window is ParsedWindow => window !== null)
    .sort((left, right) => left.startMs - right.startMs)
  const captureHealthEvents = input.healthEvents.filter(isCaptureHealthEvent)
  const captureIntervals = mergeCaptureIntervals([
    ...parsedWindows.filter((window) => window.level !== 'complete').map(intervalFromWindow),
    ...captureHealthEvents
      .filter((event) => event.summary.captureComplete === false || (event.summary.droppedEvents ?? 0) > 0)
      .map(intervalFromHealthEvent),
  ])
  const matchingWindow = findAtCursor(parsedWindows, input.cursorMs)
  const matchingHealth = captureIntervals.find((interval) => input.cursorMs >= interval.startMs && input.cursorMs < interval.endMs)
  const captureAtCursor = [
    matchingWindow ? stateForWindow(matchingWindow) : null,
    matchingHealth ? stateForInterval(matchingHealth) : null,
  ].filter((state): state is DataQualityState => state !== null)
  const capture = captureAtCursor.sort((left, right) => severity(right.level) - severity(left.level))[0]
    ?? (input.atLiveEdge ? stateForLiveStatus(input.status) : unknownCaptureState())
  const streamGapEvents = input.healthEvents.filter(isStreamGapEvent)
  const streamGapTimes = streamGapEvents
    .map((event) => event.occurredAtMs)
    .filter(Number.isFinite)
    .sort((left, right) => left - right)
  const reportedGapLoss = streamGapEvents.reduce((total, event) => total + Math.max(0, event.summary.droppedEvents ?? 0), 0)
  const stream = stateForStream(input.usesLiveStream, input.traceConnection, Math.max(input.streamDropped, reportedGapLoss))
  const level = overallLevel(capture.level, stream.level, input.usesLiveStream)

  return {
    level,
    label: level === 'complete' ? 'Complete' : level === 'partial' ? 'Partial' : level === 'unavailable' ? 'Unavailable' : 'Unknown',
    capture,
    stream,
    captureIntervals,
    streamGapTimes,
  }
}

type ParsedWindow = {
  id: string
  startMs: number
  endMs: number
  level: DataQualityLevel
  droppedEvents: number
  lastError: string
  running: boolean
}

function parseWindow(window: FlowActivityWindow): ParsedWindow | null {
  const startMs = Date.parse(window.window_start)
  if (!Number.isFinite(startMs)) return null
  const droppedEvents = Math.max(0, window.dropped_events || 0)
  const lastError = window.last_error?.trim() ?? ''
  const level: DataQualityLevel = !window.capture_running || Boolean(lastError)
    ? 'unavailable'
    : !window.capture_complete || droppedEvents > 0
      ? 'partial'
      : 'complete'
  return {
    id: window.id,
    startMs,
    endMs: startMs + Math.max(1, window.window_ms || FALLBACK_WINDOW_MS),
    level,
    droppedEvents,
    lastError,
    running: window.capture_running,
  }
}

function findAtCursor(windows: readonly ParsedWindow[], cursorMs: number) {
  for (let index = windows.length - 1; index >= 0; index -= 1) {
    const window = windows[index]
    if (cursorMs >= window.startMs && cursorMs < window.endMs) return window
  }
  return null
}

function stateForWindow(window: ParsedWindow): DataQualityState {
  if (window.level === 'complete') {
    return { level: 'complete', label: 'Complete', detail: 'This capture window closed without known activity loss.' }
  }
  if (window.level === 'unavailable') {
    return {
      level: 'unavailable',
      label: 'Unavailable',
      detail: window.lastError || (window.running ? 'Activity capture reported an error.' : 'Activity capture was not running in this window.'),
    }
  }
  return {
    level: 'partial',
    label: 'Partial',
    detail: window.droppedEvents > 0
      ? `${window.droppedEvents.toLocaleString()} activity event(s) were dropped in this window.`
      : 'This activity window did not close as complete.',
  }
}

function stateForInterval(interval: CaptureQualityInterval): DataQualityState {
  return { level: interval.level, label: interval.level === 'partial' ? 'Partial' : 'Unavailable', detail: interval.detail }
}

function stateForLiveStatus(status?: FlowActivityStatus | null): DataQualityState {
  if (!status) return { level: 'unknown', label: 'Checking', detail: 'No current activity-capture status has arrived yet.' }
  const lastError = status.last_error?.trim() ?? ''
  if (!status.enabled) return { level: 'unavailable', label: 'Disabled', detail: 'Activity capture is disabled on the gateway.' }
  if (!status.running || lastError) {
    return { level: 'unavailable', label: 'Unavailable', detail: lastError || 'Activity capture is not running on the gateway.' }
  }
  const historicalLoss = Math.max(0, status.dropped_events || 0)
  return {
    level: 'complete',
    label: 'Healthy now',
    detail: historicalLoss > 0
      ? `Capture is running. ${historicalLoss.toLocaleString()} earlier dropped event(s) remain marked on completed windows.`
      : 'Capture is running with no current error; the open window is not final until it closes.',
  }
}

function unknownCaptureState(): DataQualityState {
  return {
    level: 'unknown',
    label: 'Unknown',
    detail: 'No loaded completeness window covers this time. Absence of activity must not be read as confirmed idleness.',
  }
}

function stateForStream(
  usesLiveStream: boolean,
  connection: TraceConnectionState,
  droppedEvents: number,
): ActivityDataQuality['stream'] {
  const dropped = Math.max(0, droppedEvents || 0)
  if (!usesLiveStream) {
    return { level: 'complete', label: 'Not used', detail: 'Replay reads durable PocketBase data and does not depend on the live trace stream.', droppedEvents: 0 }
  }
  if (connection === 'error') {
    return { level: 'unavailable', label: 'Unavailable', detail: 'The browser is not receiving the live trace stream.', droppedEvents: dropped }
  }
  if (connection === 'gap' || dropped > 0) {
    return {
      level: 'partial',
      label: 'Loss detected',
      detail: `${dropped.toLocaleString()} event(s) were lost from the live visualization path. Durable activity capture may still be complete.`,
      droppedEvents: dropped,
    }
  }
  if (connection === 'live') {
    return { level: 'complete', label: 'Live', detail: 'The browser trace stream is connected with no known delivery gap.', droppedEvents: 0 }
  }
  return {
    level: 'unknown',
    label: connection === 'reconnecting' ? 'Reconnecting' : connection === 'connecting' ? 'Connecting' : 'Waiting',
    detail: 'Live stream delivery has not been confirmed yet.',
    droppedEvents: dropped,
  }
}

function overallLevel(capture: DataQualityLevel, stream: DataQualityLevel, usesLiveStream: boolean): DataQualityLevel {
  if (capture === 'unavailable') return 'unavailable'
  if (capture === 'partial') return 'partial'
  if (usesLiveStream && (stream === 'partial' || stream === 'unavailable')) return capture === 'unknown' ? 'unavailable' : 'partial'
  if (capture === 'complete') return 'complete'
  return 'unknown'
}

function severity(level: DataQualityLevel) {
  if (level === 'unavailable') return 3
  if (level === 'partial') return 2
  if (level === 'unknown') return 1
  return 0
}

function isStreamGapEvent(event: PipelineEvent) {
  return event.kind === 'health' && event.id.startsWith('trace-gap:')
}

function isCaptureHealthEvent(event: PipelineEvent) {
  return event.kind === 'health' && !isStreamGapEvent(event)
}

function intervalFromWindow(window: ParsedWindow): CaptureQualityInterval {
  const detail = window.level === 'unavailable'
    ? window.lastError || 'Activity capture was not running.'
    : window.droppedEvents > 0
      ? `${window.droppedEvents.toLocaleString()} activity event(s) dropped.`
      : 'Capture window incomplete.'
  return {
    id: `capture-window:${window.id}`,
    startMs: window.startMs,
    endMs: window.endMs,
    level: window.level === 'unavailable' ? 'unavailable' : 'partial',
    droppedEvents: window.droppedEvents,
    detail,
  }
}

function intervalFromHealthEvent(event: PipelineEvent): CaptureQualityInterval {
  const droppedEvents = Math.max(0, event.summary.droppedEvents ?? 0)
  const level = droppedEvents > 0 ? 'partial' : 'unavailable'
  return {
    id: `capture-event:${event.id}`,
    startMs: event.occurredAtMs,
    endMs: event.occurredAtMs + FALLBACK_WINDOW_MS,
    level,
    droppedEvents,
    detail: droppedEvents > 0
      ? `${droppedEvents.toLocaleString()} activity event(s) dropped.`
      : 'Activity capture reported incomplete data.',
  }
}

function mergeCaptureIntervals(intervals: CaptureQualityInterval[]) {
  const sorted = intervals
    .filter((interval) => Number.isFinite(interval.startMs) && Number.isFinite(interval.endMs) && interval.endMs > interval.startMs)
    .sort((left, right) => left.startMs - right.startMs || left.endMs - right.endMs)
  const result: CaptureQualityInterval[] = []
  for (const interval of sorted) {
    const previous = result[result.length - 1]
    if (!previous || interval.startMs > previous.endMs || interval.level !== previous.level) {
      result.push({ ...interval })
      continue
    }
    previous.endMs = Math.max(previous.endMs, interval.endMs)
    previous.droppedEvents = Math.max(previous.droppedEvents, interval.droppedEvents)
    if (!previous.detail.includes(interval.detail)) previous.detail = `${previous.detail} ${interval.detail}`
  }
  return result
}
