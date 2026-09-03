import {
  PIPELINE_EVENT_KINDS,
  PIPELINE_STAGES,
  type PipelineDirection,
  type PipelineEvent,
  type PipelineEventKind,
  type PipelineEventSummary,
  type PipelineStage,
  type PipelineStreamMessage,
  type PipelineStreamEnvelope,
  type PipelineTiming,
} from '../types'

const STREAM_MESSAGE_TYPES = new Set(['hello', 'batch', 'gap', 'status', 'heartbeat'])
const MAX_SSE_EVENT_BYTES = 256 * 1024

const MAX_BATCH_EVENTS = 200
const MAX_ID_LENGTH = 256
const MAX_SESSION_ID_LENGTH = 128
const EVENT_KINDS = new Set<string>(PIPELINE_EVENT_KINDS)
const STAGES = new Set<string>(PIPELINE_STAGES)
const DIRECTIONS = new Set<PipelineDirection>(['client_to_remote', 'remote_to_client'])
const TIMINGS = new Set<PipelineTiming>(['observed', 'derived'])

export class PipelineDecodeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PipelineDecodeError'
  }
}

export function decodePipelineStreamEnvelope(input: unknown): PipelineStreamEnvelope {
  const envelope = record(input, 'stream envelope')
  if (envelope.version !== 1) {
    throw new PipelineDecodeError(`Unsupported trace protocol version: ${String(envelope.version)}`)
  }

  const sessionId = requiredString(envelope, 'sessionId', MAX_SESSION_ID_LENGTH)
  const rawEvents = envelope.events
  if (!Array.isArray(rawEvents) || rawEvents.length > MAX_BATCH_EVENTS) {
    throw new PipelineDecodeError(`events must be an array of at most ${MAX_BATCH_EVENTS} items`)
  }

  const events: PipelineEvent[] = []
  rawEvents.forEach((rawEvent, index) => {
    const decoded = decodePipelineEvent(rawEvent, `events[${index}]`)
    if (decoded && decoded.sessionId !== sessionId) {
      throw new PipelineDecodeError(`events[${index}] belongs to another session`)
    }
    if (decoded) events.push(decoded)
  })

  return {
    version: 1,
    sessionId,
    events,
    droppedEvents: nonNegativeInteger(envelope, 'droppedEvents'),
    serverNowMs: nonNegativeInteger(envelope, 'serverNowMs'),
  }
}

export function decodePipelineStreamMessage(input: unknown): PipelineStreamMessage | null {
  const source = record(input, 'stream message')
  if (source.version !== 1) {
    throw new PipelineDecodeError(`Unsupported trace protocol version: ${String(source.version)}`)
  }
  const type = requiredString(source, 'type', 32)
  if (!STREAM_MESSAGE_TYPES.has(type)) return null
  const sessionId = requiredString(source, 'sessionId', MAX_SESSION_ID_LENGTH)
  const droppedEvents = optionalNonNegativeInteger(source, 'droppedEvents') ?? 0
  const serverNowMs = nonNegativeInteger(source, 'serverNowMs')
  const oldestSequence = nonNegativeInteger(source, 'oldestSequence')
  const newestSequence = nonNegativeInteger(source, 'newestSequence')
  const events = type === 'batch'
    ? decodePipelineStreamEnvelope({ version: 1, sessionId, events: source.events, droppedEvents, serverNowMs }).events
    : []
  return {
    type: type as PipelineStreamMessage['type'],
    version: 1,
    sessionId,
    events,
    droppedEvents,
    serverNowMs,
    requestedSequence: optionalNonNegativeInteger(source, 'requestedSequence'),
    oldestSequence,
    newestSequence,
    ingressRejected: optionalNonNegativeInteger(source, 'ingressRejected') ?? 0,
    subscriberDropped: optionalNonNegativeInteger(source, 'subscriberDropped') ?? 0,
    burstDiscarded: optionalNonNegativeInteger(source, 'burstDiscarded') ?? 0,
  }
}

export type ParsedSSEEvent = { event: string; data: string }

/** Small incremental parser; chunks may split CRLFs, fields, or JSON bytes. */
export class SSEDecoder {
  private buffer = ''
  private event = 'message'
  private data: string[] = []

  push(chunk: string, final = false): ParsedSSEEvent[] {
    this.buffer += chunk
    const lines = this.buffer.split(/\r?\n/)
    this.buffer = final ? '' : lines.pop() ?? ''
    const events: ParsedSSEEvent[] = []
    for (const line of lines) {
      if (line === '') {
        if (this.data.length > 0) events.push({ event: this.event, data: this.data.join('\n') })
        this.event = 'message'
        this.data = []
      } else if (line.startsWith('event:')) {
        this.event = line.slice(6).trimStart()
      } else if (line.startsWith('data:')) {
        const value = line.slice(5).trimStart()
        if (this.data.reduce((size, part) => size + part.length, 0) + value.length > MAX_SSE_EVENT_BYTES) {
          throw new PipelineDecodeError('SSE event exceeds the 256 KiB limit')
        }
        this.data.push(value)
      }
    }
    if (final && (this.buffer || this.data.length)) {
      if (this.buffer.startsWith('data:')) this.data.push(this.buffer.slice(5).trimStart())
      if (this.data.length) events.push({ event: this.event, data: this.data.join('\n') })
      this.buffer = ''
      this.event = 'message'
      this.data = []
    }
    return events
  }
}

export type TraceClientHandlers = {
  onMessage: (message: PipelineStreamMessage) => void
  onState?: (state: 'connecting' | 'live' | 'reconnecting' | 'error') => void
  onError?: (error: Error) => void
}

export type TraceClientOptions = {
  sessionId: string
  token?: string
  baseUrl?: string
  fetchImpl?: typeof fetch
  minimumBackoffMs?: number
  maximumBackoffMs?: number
}

const lastSequenceBySession = new Map<string, number>()

export class TraceClient {
  private readonly fetchImpl: typeof fetch
  private controller: AbortController | null = null
  private running = false

  constructor(private readonly options: TraceClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch
  }

  start(handlers: TraceClientHandlers) {
    this.stop()
    this.running = true
    void this.run(handlers)
  }

  stop() {
    this.running = false
    this.controller?.abort()
    this.controller = null
  }

  private async run(handlers: TraceClientHandlers) {
    let backoffMs = this.options.minimumBackoffMs ?? 500
    const maximumBackoffMs = this.options.maximumBackoffMs ?? 10_000
    let attempt = 0
    while (this.running) {
      this.controller = new AbortController()
      handlers.onState?.(attempt === 0 ? 'connecting' : 'reconnecting')
      try {
        await this.consume(this.controller.signal, handlers)
        backoffMs = this.options.minimumBackoffMs ?? 500
        attempt = 0
      } catch (error) {
        if (!this.running || isAbort(error)) return
        const normalized = error instanceof Error ? error : new Error('Trace stream failed')
        handlers.onError?.(normalized)
        handlers.onState?.('error')
        attempt += 1
      }
      if (!this.running) return
      await abortableDelay(backoffMs, this.controller.signal).catch(() => undefined)
      backoffMs = Math.min(maximumBackoffMs, backoffMs * 2)
    }
  }

  private async consume(signal: AbortSignal, handlers: TraceClientHandlers) {
    const lastSequence = lastSequenceBySession.get(this.options.sessionId) ?? 0
    const baseUrl = (this.options.baseUrl ?? '').replace(/\/$/, '')
    const url = `${baseUrl}/api/infrareveal/debug/sessions/${encodeURIComponent(this.options.sessionId)}/trace?after=${lastSequence}`
    const headers = new Headers({ Accept: 'text/event-stream' })
    if (this.options.token) headers.set('Authorization', `Bearer ${this.options.token}`)
    const response = await this.fetchImpl(url, { headers, signal })
    if (!response.ok || !response.body) throw new Error(`Trace stream returned HTTP ${response.status}`)
    const reader = response.body.getReader()
    const textDecoder = new TextDecoder()
    const sse = new SSEDecoder()
    handlers.onState?.('live')
    while (this.running) {
      const chunk = await reader.read()
      const parsedEvents = sse.push(textDecoder.decode(chunk.value, { stream: !chunk.done }), chunk.done)
      for (const parsed of parsedEvents) {
        if (parsed.data.length > MAX_SSE_EVENT_BYTES) throw new PipelineDecodeError('SSE event exceeds the 256 KiB limit')
        let raw: unknown
        try {
          raw = JSON.parse(parsed.data) as unknown
        } catch {
          throw new PipelineDecodeError('SSE data is not valid JSON')
        }
        const message = decodePipelineStreamMessage(raw)
        if (!message || message.sessionId !== this.options.sessionId) continue
        handlers.onMessage(message)
        if (message.events.length) {
          lastSequenceBySession.set(this.options.sessionId, Math.max(
            lastSequenceBySession.get(this.options.sessionId) ?? 0,
            ...message.events.map((event) => event.sequence),
          ))
        }
      }
      if (chunk.done) return
    }
  }
}

function isAbort(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError'
}

function abortableDelay(milliseconds: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const timer = globalThis.setTimeout(resolve, milliseconds)
    signal.addEventListener('abort', () => {
      globalThis.clearTimeout(timer)
      reject(new DOMException('Aborted', 'AbortError'))
    }, { once: true })
  })
}

// Unknown future kinds or stages are omitted so one additive server event does
// not tear down an otherwise compatible stream. Known events stay strict.
export function decodePipelineEvent(input: unknown, path = 'event'): PipelineEvent | null {
  const event = record(input, path)
  const rawKind = requiredString(event, 'kind', 64)
  const rawStage = requiredString(event, 'stage', 64)
  if (!EVENT_KINDS.has(rawKind) || !STAGES.has(rawStage)) return null

  const direction = optionalEnum(event, 'direction', DIRECTIONS)
  const timing = requiredEnum(event, 'timing', TIMINGS)
  return {
    id: requiredString(event, 'id', MAX_ID_LENGTH),
    sequence: nonNegativeInteger(event, 'sequence'),
    sessionId: requiredString(event, 'sessionId', MAX_SESSION_ID_LENGTH),
    traceId: requiredString(event, 'traceId', MAX_ID_LENGTH),
    parentId: optionalString(event, 'parentId', MAX_ID_LENGTH),
    kind: rawKind as PipelineEventKind,
    stage: rawStage as PipelineStage,
    direction,
    occurredAtMs: nonNegativeInteger(event, 'occurredAtMs'),
    processedAtMs: optionalNonNegativeInteger(event, 'processedAtMs'),
    timing,
    summary: decodeSummary(event.summary),
  }
}

function decodeSummary(input: unknown): PipelineEventSummary {
  const summary = record(input, 'event.summary')
  return omitUndefined({
    protocol: optionalString(summary, 'protocol', 16),
    clientIp: optionalString(summary, 'clientIp', 64),
    clientPort: optionalPort(summary, 'clientPort'),
    remoteIp: optionalString(summary, 'remoteIp', 64),
    remotePort: optionalPort(summary, 'remotePort'),
    flowKey: optionalString(summary, 'flowKey', 512),
    dnsName: optionalString(summary, 'dnsName', 253),
    dnsType: optionalString(summary, 'dnsType', 32),
    hostname: optionalString(summary, 'hostname', 253),
    confidence: optionalString(summary, 'confidence', 32),
    wireBytes: optionalNonNegativeInteger(summary, 'wireBytes'),
    payloadBytes: optionalNonNegativeInteger(summary, 'payloadBytes'),
    packetCount: optionalNonNegativeInteger(summary, 'packetCount'),
    tcpFlags: optionalBoundedInteger(summary, 'tcpFlags', 0, 0x1ff),
    verdict: optionalString(summary, 'verdict', 32),
    verdictSource: optionalString(summary, 'verdictSource', 32),
    droppedEvents: optionalNonNegativeInteger(summary, 'droppedEvents'),
    captureComplete: optionalBoolean(summary, 'captureComplete'),
  })
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new PipelineDecodeError(`${path} must be an object`)
  }
  return value as Record<string, unknown>
}

function requiredString(source: Record<string, unknown>, key: string, maxLength: number): string {
  const value = source[key]
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || value.includes('\0')) {
    throw new PipelineDecodeError(`${key} must be a non-empty string of at most ${maxLength} characters`)
  }
  return value
}

function optionalString(source: Record<string, unknown>, key: string, maxLength: number): string | undefined {
  const value = source[key]
  if (value === undefined) return undefined
  if (typeof value !== 'string' || value.length > maxLength || value.includes('\0')) {
    throw new PipelineDecodeError(`${key} must be a string of at most ${maxLength} characters`)
  }
  return value
}

function nonNegativeInteger(source: Record<string, unknown>, key: string): number {
  const value = source[key]
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new PipelineDecodeError(`${key} must be a finite non-negative safe integer`)
  }
  return value
}

function optionalNonNegativeInteger(source: Record<string, unknown>, key: string): number | undefined {
  if (source[key] === undefined) return undefined
  return nonNegativeInteger(source, key)
}

function optionalBoundedInteger(source: Record<string, unknown>, key: string, min: number, max: number): number | undefined {
  const value = source[key]
  if (value === undefined) return undefined
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new PipelineDecodeError(`${key} must be an integer from ${min} to ${max}`)
  }
  return value
}

function optionalPort(source: Record<string, unknown>, key: string): number | undefined {
  return optionalBoundedInteger(source, key, 1, 65_535)
}

function optionalBoolean(source: Record<string, unknown>, key: string): boolean | undefined {
  const value = source[key]
  if (value === undefined) return undefined
  if (typeof value !== 'boolean') throw new PipelineDecodeError(`${key} must be a boolean`)
  return value
}

function requiredEnum<T extends string>(source: Record<string, unknown>, key: string, values: ReadonlySet<T>): T {
  const value = source[key]
  if (typeof value !== 'string' || !values.has(value as T)) {
    throw new PipelineDecodeError(`${key} has an unsupported value`)
  }
  return value as T
}

function optionalEnum<T extends string>(source: Record<string, unknown>, key: string, values: ReadonlySet<T>): T | undefined {
  if (source[key] === undefined) return undefined
  return requiredEnum(source, key, values)
}

function omitUndefined<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as T
}
