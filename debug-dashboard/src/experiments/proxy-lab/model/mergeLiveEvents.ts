import type { PipelineEvent, PipelineStreamMessage } from '../types'
import { comparePipelineEvents } from './projectRecordedEvents'

export const LIVE_EVENT_RETENTION_MS = 30_000

/** Source IDs deduplicate actual publications. Aggregate facts and individual
 * diagnostic events remain distinct even when their timestamps overlap. */
export function mergeLiveEvents(
  durableEvents: readonly PipelineEvent[],
  ephemeralEvents: Iterable<PipelineEvent>,
  liveEdgeMs: number,
  retentionMs = LIVE_EVENT_RETENTION_MS,
) {
  const result = new Map(durableEvents.map(event => [event.id, event]))
  const seenSequences = new Set<number>()
  const cutoff = liveEdgeMs - retentionMs
  const orderedLive = Array.from(ephemeralEvents).sort(comparePipelineEvents)
  for (const event of orderedLive) {
    if (seenSequences.has(event.sequence) || event.occurredAtMs < cutoff) continue
    seenSequences.add(event.sequence)
    if (!result.has(event.id)) result.set(event.id, event)
  }

  return [...result.values()].sort(comparePipelineEvents)
}

export function gapEvent(message: PipelineStreamMessage): PipelineEvent {
  return {
    id: `trace-gap:${message.requestedSequence ?? 0}:${message.oldestSequence}`,
    sequence: message.newestSequence,
    sessionId: message.sessionId,
    traceId: `trace-gap:${message.oldestSequence}`,
    kind: 'health',
    stage: 'health',
    occurredAtMs: message.serverNowMs,
    processedAtMs: message.serverNowMs,
    timing: 'observed',
    summary: { droppedEvents: message.droppedEvents, captureComplete: false },
  }
}
