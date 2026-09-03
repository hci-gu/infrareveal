import type { PipelineEvent } from '../types'
import { nodeById, pathForEvent, type PathDefinition } from './graphLayout'

export const DEFAULT_MAX_VISIBLE_TOKENS = 180

export type SceneToken = {
  id: string
  eventIds: string[]
  path: PathDefinition
  startMs: number
  endMs: number
  color: string
  scale: number
  provenance: 'recorded-observed' | 'recorded-derived' | 'live-observed'
  selectionId: string
  clientIp?: string
  stage: PipelineEvent['stage']
  direction?: PipelineEvent['direction']
  count: number
  laneOffset: number
  queued: boolean
}

export type SceneTokenPosition = { x: number; y: number; progress: number }

export type ProxyScene = {
  cursorMs: number
  tokens: SceneToken[]
  totalActiveTokens: number
  aggregatedTokenCount: number
}

export type SceneProjectionOptions = {
  selectedId?: string | null
  maxVisibleTokens?: number
  source?: 'recorded' | 'live'
  tokenDurationMs?: number
}

export function projectProxyScene(
  events: readonly PipelineEvent[],
  cursorMs: number,
  options: SceneProjectionOptions = {},
): ProxyScene {
  const durationMs = Math.max(1, options.tokenDurationMs ?? 1_200)
  const source = options.source ?? 'recorded'
  const allTokens = events
    .map((event) => tokenForEvent(event, durationMs, source))
    .filter((token) => cursorMs >= token.startMs && cursorMs <= token.endMs)
    .sort((left, right) => left.startMs - right.startMs || left.id.localeCompare(right.id))
  const maxVisible = Math.max(1, options.maxVisibleTokens ?? DEFAULT_MAX_VISIBLE_TOKENS)
  const selectedId = options.selectedId ?? null
  const protectedTokens = allTokens.filter((token) => token.queued || token.selectionId === selectedId || token.id === selectedId)
  const protectedIds = new Set(protectedTokens.map((token) => token.id))
  const ordinary = allTokens.filter((token) => !protectedIds.has(token.id))
  const capacity = Math.max(0, maxVisible - protectedTokens.length)
  const visibleOrdinary = ordinary.length <= capacity ? ordinary : aggregateTokens(ordinary).slice(0, capacity)
  const tokens = [...protectedTokens, ...visibleOrdinary]
    .sort((left, right) => left.startMs - right.startMs || left.id.localeCompare(right.id))
  return {
    cursorMs,
    tokens,
    totalActiveTokens: allTokens.length,
    aggregatedTokenCount: tokens.reduce((total, token) => total + Math.max(0, token.count - 1), 0),
  }
}

export function positionSceneToken(token: SceneToken, cursorMs: number): SceneTokenPosition {
  const rawProgress = token.endMs === token.startMs ? 1 : (cursorMs - token.startMs) / (token.endMs - token.startMs)
  const progress = Number.isFinite(rawProgress) ? Math.min(1, Math.max(0, rawProgress)) : 0
  const nodes = token.path.nodes.map(nodeById)
  if (nodes.length === 1) return { x: nodes[0].x, y: nodes[0].y + token.laneOffset, progress }
  const scaled = progress * (nodes.length - 1)
  const segment = Math.min(nodes.length - 2, Math.floor(scaled))
  const local = scaled - segment
  const from = nodes[segment]
  const to = nodes[segment + 1]
  return {
    x: from.x + (to.x - from.x) * local,
    y: from.y + (to.y - from.y) * local + token.laneOffset,
    progress,
  }
}

function tokenForEvent(event: PipelineEvent, durationMs: number, source: 'recorded' | 'live'): SceneToken {
  const path = pathForEvent(event)
  return {
    id: `token:${event.id}`,
    eventIds: [event.id],
    path,
    startMs: event.occurredAtMs,
    endMs: event.occurredAtMs + Math.max(durationMs, (path.nodes.length - 1) * 140),
    color: colorForEvent(event),
    scale: scaleForEvent(event),
    provenance: source === 'live' && event.timing === 'observed'
      ? 'live-observed'
      : event.timing === 'derived' ? 'recorded-derived' : 'recorded-observed',
    selectionId: event.traceId,
    clientIp: event.summary.clientIp,
    stage: event.stage,
    direction: event.direction,
    count: 1,
    laneOffset: deterministicLaneOffset(event.id),
    queued: event.kind === 'gate' && event.stage === 'gate_queue' && !event.summary.verdict,
  }
}

function aggregateTokens(tokens: SceneToken[]) {
  const groups = new Map<string, SceneToken[]>()
  for (const token of tokens) {
    const bucket = Math.floor(token.startMs / 50) * 50
    const key = `${token.clientIp ?? ''}|${token.stage}|${token.direction ?? ''}|${bucket}`
    const current = groups.get(key) ?? []
    current.push(token)
    groups.set(key, current)
  }
  return Array.from(groups.entries(), ([key, group]) => {
    const first = group[0]
    return {
      ...first,
      id: `aggregate:${key}`,
      eventIds: group.flatMap((token) => token.eventIds).sort(),
      count: group.length,
      scale: Math.min(2.4, first.scale + Math.log2(group.length) * 0.18),
      laneOffset: deterministicLaneOffset(key),
    }
  }).sort((left, right) => right.count - left.count || left.id.localeCompare(right.id))
}

function colorForEvent(event: PipelineEvent) {
  if (event.kind === 'health') return '#f97316'
  if (event.kind === 'gate' && event.summary.verdict === 'rejected') return '#ef4444'
  if (event.kind === 'gate') return '#facc15'
  if (event.timing === 'derived') return '#a78bfa'
  if (event.direction === 'remote_to_client') return '#4ade80'
  return '#22d3ee'
}

function scaleForEvent(event: PipelineEvent) {
  const weight = Math.max(event.summary.packetCount ?? 0, (event.summary.payloadBytes ?? event.summary.wireBytes ?? 0) / 1200)
  return Math.min(2, 0.7 + Math.log2(1 + weight) * 0.16)
}

function deterministicLaneOffset(id: string) {
  let hash = 2_166_136_261
  for (let index = 0; index < id.length; index += 1) {
    hash ^= id.charCodeAt(index)
    hash = Math.imul(hash, 16_777_619)
  }
  return ((hash >>> 0) % 7 - 3) * 4
}
