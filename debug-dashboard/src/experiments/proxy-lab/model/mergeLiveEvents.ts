import type { PipelineEvent, PipelineStreamMessage } from '../types'
import { comparePipelineEvents } from './projectRecordedEvents'

export const LIVE_EVENT_RETENTION_MS = 30_000

/** Merges the short-lived trace ring over durable reconstruction. Durable data
 * remains authoritative for labels/counters; measured live timing replaces a
 * matching derived timestamp until the durable observation catches up. */
export function mergeLiveEvents(
  durableEvents: readonly PipelineEvent[],
  ephemeralEvents: Iterable<PipelineEvent>,
  liveEdgeMs: number,
  retentionMs = LIVE_EVENT_RETENTION_MS,
) {
  const liveByIdentity = new Map<string, PipelineEvent>()
  const seenSequences = new Set<number>()
  const cutoff = liveEdgeMs - retentionMs
  const orderedLive = Array.from(ephemeralEvents).sort(comparePipelineEvents)
  for (const event of orderedLive) {
    if (seenSequences.has(event.sequence) || event.occurredAtMs < cutoff) continue
    seenSequences.add(event.sequence)
    const identity = stableEventIdentity(event)
    const previous = liveByIdentity.get(identity)
    if (!previous || comparePipelineEvents(previous, event) < 0) liveByIdentity.set(identity, event)
  }

  const result = durableEvents.map((durable) => {
    const identity = stableEventIdentity(durable)
    const live = liveByIdentity.get(identity)
    if (!live) return durable
    liveByIdentity.delete(identity)
    if (durable.timing === 'derived' && live.timing === 'observed') {
      return {
        ...durable,
        occurredAtMs: live.occurredAtMs,
        processedAtMs: live.processedAtMs,
        sequence: live.sequence,
        timing: live.timing,
        summary: { ...live.summary, ...durable.summary },
      } satisfies PipelineEvent
    }
    return durable
  })
  result.push(...liveByIdentity.values())
  return result.sort(comparePipelineEvents)
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

function stableEventIdentity(event: PipelineEvent) {
  const flowRecord = event.id.match(/^flow(?:-discovered:|:)([^:]+)(?::discovered)?$/)
  if (flowRecord) return `flow-record:${flowRecord[1]}`
  const dnsRecord = event.id.match(/^dns(?:-query:|:)([^:]+)(?::query)?$/)
  if (dnsRecord) return `dns-query:${dnsRecord[1]}`
  if (event.summary.flowKey) {
    const bucket = Math.floor(event.occurredAtMs / 50) * 50
    return `${event.kind}:${event.stage}:${event.summary.flowKey}:${event.direction ?? ''}:${bucket}`
  }
  return event.id
}
