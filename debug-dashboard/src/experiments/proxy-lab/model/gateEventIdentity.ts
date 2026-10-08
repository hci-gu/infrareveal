import type { PipelineEvent } from '../types'

export const gateEventID = (decisionId: string, phase: 'queued' | 'verdict') => `gate:${decisionId}:${phase}`

/** Older trace streams used different IDs from durable gate events. Normalize
 * only their identity; stage and verdict retain their original wire meanings. */
export function normalizeGateEvent(event: PipelineEvent): PipelineEvent {
  if (event.kind !== 'gate') return event
  const current = event.id.match(/^gate:(.+):(queued|verdict)$/)
  const legacy = event.id.match(/^gate-(waiting|verdict):(.+)$/)
  const decisionId = current?.[1] ?? legacy?.[2]
  const phase = current?.[2] ?? (legacy?.[1] === 'waiting' ? 'queued' : legacy?.[1])
  if (!decisionId || (phase !== 'queued' && phase !== 'verdict')) return event
  const id = gateEventID(decisionId, phase)
  const parentId = phase === 'verdict' ? gateEventID(decisionId, 'queued') : event.parentId
  return event.id === id && event.parentId === parentId ? event : { ...event, id, parentId }
}
