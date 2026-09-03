export const PIPELINE_EVENT_KINDS = [
  'dns',
  'flow',
  'burst',
  'attribution',
  'destination',
  'route',
  'gate',
  'health',
] as const

export type PipelineEventKind = (typeof PIPELINE_EVENT_KINDS)[number]

export const PIPELINE_STAGES = [
  'client',
  'gateway_ingress',
  'dns',
  'conntrack',
  'header_capture',
  'gate_queue',
  'forward',
  'nat',
  'remote',
  'attribution',
  'destination',
  'route',
  'health',
] as const

export type PipelineStage = (typeof PIPELINE_STAGES)[number]
export type PipelineDirection = 'client_to_remote' | 'remote_to_client'
export type PipelineTiming = 'observed' | 'derived'

export type PipelineEventSummary = {
  protocol?: string
  clientIp?: string
  clientPort?: number
  remoteIp?: string
  remotePort?: number
  flowKey?: string
  dnsName?: string
  dnsType?: string
  hostname?: string
  confidence?: string
  wireBytes?: number
  payloadBytes?: number
  packetCount?: number
  tcpFlags?: number
  verdict?: string
  verdictSource?: string
  droppedEvents?: number
  captureComplete?: boolean
}

export type PipelineEvent = {
  id: string
  sequence: number
  sessionId: string
  traceId: string
  parentId?: string
  kind: PipelineEventKind
  stage: PipelineStage
  direction?: PipelineDirection
  occurredAtMs: number
  processedAtMs?: number
  timing: PipelineTiming
  summary: PipelineEventSummary
}

export type PipelineStreamEnvelope = {
  version: 1
  sessionId: string
  events: PipelineEvent[]
  droppedEvents: number
  serverNowMs: number
}

export type PipelineStreamMessage = {
  type: 'hello' | 'batch' | 'gap' | 'status' | 'heartbeat'
  version: 1
  sessionId: string
  events: PipelineEvent[]
  droppedEvents: number
  serverNowMs: number
  requestedSequence?: number
  oldestSequence: number
  newestSequence: number
  ingressRejected: number
  subscriberDropped: number
  burstDiscarded: number
}

export type ProxyLabMode = 'replay' | 'live-observe' | 'turn-based' | 'strict' | 'dns'

export type GateDecision = {
  id: string
  flowKey: string
  sessionId: string
  clientIp: string
  remoteIp: string
  clientPort: number
  remotePort: number
  protocol: string
  mode?: 'flow' | 'strict' | 'dns'
  direction?: PipelineDirection
  wireBytes?: number
  payloadBytes?: number
  packetCount: number
  tcpFlags: number
  queuedAtMs: number
  deadlineMs: number
  state: 'queued' | 'approved' | 'rejected' | 'expired' | 'bypassed' | 'drained'
  verdict?: 'accept' | 'drop'
  verdictSource?: 'operator' | 'watchdog' | 'overflow' | 'shutdown' | 'system'
  actor?: string
  reason?: string
  decidedAtMs?: number
  waitMs?: number
}

export type GateStatus = {
  enabled: boolean
  supported: boolean
  listenerReady: boolean
  rulesReady: boolean
  armed: boolean
  state: 'off' | 'arming' | 'active' | 'paused' | 'draining' | 'degraded' | 'error'
  mode: 'flow' | 'strict' | 'dns' | null
  sessionId: string | null
  clientIps: string[]
  paused: boolean
  failOpen: boolean
  pendingFlows: number
  heldPackets: number
  overflowCount: number
  watchdogReleases: number
  verdictErrors: number
  auditDrops: number
  oldestWaitMs: number
  parseBypassCount: number
  lastError: string | null
  flowTimeoutMs: number
  establishedTimeoutMs: number
  dnsTimeoutMs: number
  maxPendingFlows: number
  maxHeldPackets: number
  strictAutoAccept: number
  kernelSettings: Record<string, string>
  queue: {
    queueDepth: number
    kernelDrops: number
    userDrops: number
    parseBypass: number
  }
}
