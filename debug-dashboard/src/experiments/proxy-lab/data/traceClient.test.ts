import { describe, expect, it } from 'vitest'
import fixture from '../../../../../testdata/pipeline-event-v1.json'
import {
  decodePipelineStreamEnvelope,
  decodePipelineStreamMessage,
  PipelineDecodeError,
  SSEDecoder,
  TraceClient,
} from './traceClient'

describe('decodePipelineStreamEnvelope', () => {
  it('decodes the fixture shared with Go exactly', () => {
    const decoded = decodePipelineStreamEnvelope(fixture)
    expect(decoded.version).toBe(1)
    expect(decoded.events).toHaveLength(1)
    expect(decoded.events[0]).toMatchObject({
      id: 'fixture-flow-1',
      sequence: 41,
      sessionId: 'fixture-session',
      traceId: 'fixture-trace-1',
      kind: 'flow',
      stage: 'gateway_ingress',
      direction: 'client_to_remote',
      occurredAtMs: 1_788_343_200_000,
      summary: {
        flowKey: 'tcp|10.42.0.18|53120|142.250.74.14|443',
        wireBytes: 1514,
        captureComplete: true,
      },
    })
  })

  it('accepts omitted optional fields and strips arbitrary metadata', () => {
    const envelope = baseEnvelope({
      ...baseEvent(),
      unknownEventField: 'not forwarded',
      summary: { protocol: 'udp', unknownSummaryField: { secret: 'not forwarded' } },
    })
    const decoded = decodePipelineStreamEnvelope(envelope)
    expect(decoded.events[0]).not.toHaveProperty('unknownEventField')
    expect(decoded.events[0]?.summary).toEqual({ protocol: 'udp' })
    expect(decoded.events[0]?.parentId).toBeUndefined()
  })

  it('ignores future event kinds and stages without losing known events', () => {
    const envelope = baseEnvelope(
      { ...baseEvent(), id: 'future-kind', kind: 'tls_handshake' },
      { ...baseEvent(), id: 'future-stage', stage: 'sidecar' },
      baseEvent(),
    )
    expect(decodePipelineStreamEnvelope(envelope).events.map((event) => event.id)).toEqual(['event-1'])
  })

  it.each([
    ['unknown version', { ...baseEnvelope(baseEvent()), version: 2 }],
    ['negative byte count', baseEnvelope({ ...baseEvent(), summary: { wireBytes: -1 } })],
    ['non-finite count', baseEnvelope({ ...baseEvent(), summary: { packetCount: Number.POSITIVE_INFINITY } })],
    ['oversized string', baseEnvelope({ ...baseEvent(), summary: { dnsName: 'x'.repeat(254) } })],
    ['oversized batch', { ...baseEnvelope(), events: Array.from({ length: 201 }, baseEvent) }],
    ['wrong session', baseEnvelope({ ...baseEvent(), sessionId: 'another-session' })],
  ])('rejects %s', (_label, value) => {
    expect(() => decodePipelineStreamEnvelope(value)).toThrow(PipelineDecodeError)
  })
})

describe('live trace transport', () => {
  it('parses SSE events split across arbitrary chunks', () => {
    const decoder = new SSEDecoder()
    expect(decoder.push('event: bat')).toEqual([])
    expect(decoder.push('ch\r\ndata: {"one":')).toEqual([])
    expect(decoder.push('1}\r\n\r\n')).toEqual([{ event: 'batch', data: '{"one":1}' }])
  })

  it('decodes typed messages and explicit gaps', () => {
    const gap = decodePipelineStreamMessage({
      type: 'gap', version: 1, sessionId: 'session-1', droppedEvents: 4,
      serverNowMs: 1000, requestedSequence: 2, oldestSequence: 7, newestSequence: 9,
    })
    expect(gap).toMatchObject({ type: 'gap', droppedEvents: 4, requestedSequence: 2 })
    expect(decodePipelineStreamMessage({
      type: 'future-message', version: 1, sessionId: 'session-1', droppedEvents: 0,
      serverNowMs: 1000, oldestSequence: 0, newestSequence: 0,
    })).toBeNull()
  })

  it('reconnects with the last accepted sequence and keeps bearer data out of the URL', async () => {
    const urls: string[] = []
    const authorizations: Array<string | null> = []
    let call = 0
    const fetchImpl: typeof fetch = async (input, init) => {
      urls.push(String(input))
      authorizations.push(new Headers(init?.headers).get('Authorization'))
      call += 1
      return streamResponse(streamMessage(call === 1 ? 3 : 4))
    }
    const client = new TraceClient({
      sessionId: 'transport-test', token: 'private-token', fetchImpl,
      minimumBackoffMs: 1, maximumBackoffMs: 2,
    })
    await new Promise<void>((resolve, reject) => {
      client.start({
        onMessage: (message) => {
          if (message.newestSequence === 4) {
            client.stop()
            resolve()
          }
        },
        onError: reject,
      })
    })
    expect(urls).toEqual([
      '/api/infrareveal/debug/sessions/transport-test/trace?after=0',
      '/api/infrareveal/debug/sessions/transport-test/trace?after=3',
    ])
    expect(urls.join(' ')).not.toContain('private-token')
    expect(authorizations).toEqual(['Bearer private-token', 'Bearer private-token'])
  })

  it('aborts an in-flight fetch immediately when stopped', async () => {
    let observedSignal: AbortSignal | undefined
    const fetchImpl: typeof fetch = async (_input, init) => {
      observedSignal = init?.signal ?? undefined
      return await new Promise<Response>((_resolve, reject) => {
        observedSignal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true })
      })
    }
    const client = new TraceClient({ sessionId: 'abort-test', fetchImpl })
    client.start({ onMessage: () => undefined })
    await new Promise((resolve) => globalThis.setTimeout(resolve, 0))
    client.stop()
    expect(observedSignal?.aborted).toBe(true)
  })

  it('reports malformed stream envelopes before state callbacks', async () => {
    const client = new TraceClient({
      sessionId: 'malformed-test',
      fetchImpl: async () => streamResponse({ ...streamMessage(1), version: 2 }),
      minimumBackoffMs: 1,
    })
    const error = await new Promise<Error>((resolve) => {
      client.start({
        onMessage: () => { throw new Error('malformed message reached state') },
        onError: (caught) => { client.stop(); resolve(caught) },
      })
    })
    expect(error).toBeInstanceOf(PipelineDecodeError)
  })
})

function baseEnvelope(...events: unknown[]) {
  return {
    version: 1,
    sessionId: 'session-1',
    events,
    droppedEvents: 0,
    serverNowMs: 1000,
  }
}

function baseEvent() {
  return {
    id: 'event-1',
    sequence: 1,
    sessionId: 'session-1',
    traceId: 'trace-1',
    kind: 'health',
    stage: 'health',
    occurredAtMs: 900,
    timing: 'observed',
    summary: {},
  }
}

function streamMessage(sequence: number) {
  return {
    type: 'batch', version: 1, sessionId: 'transport-test', droppedEvents: 0,
    serverNowMs: 1000, oldestSequence: 1, newestSequence: sequence,
    events: [{ ...baseEvent(), id: `event-${sequence}`, sessionId: 'transport-test', sequence }],
  }
}

function streamResponse(message: unknown) {
  const bytes = new TextEncoder().encode(`event: batch\ndata: ${JSON.stringify(message)}\n\n`)
  return new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(bytes.slice(0, 7))
      controller.enqueue(bytes.slice(7, 19))
      controller.enqueue(bytes.slice(19))
      controller.close()
    },
  }), { status: 200, headers: { 'Content-Type': 'text/event-stream' } })
}
