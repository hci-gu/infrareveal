import { describe, expect, it } from 'vitest'
import type { PipelineEvent } from '../types'
import { demoPipelineEvents } from '../data/demoTransport'
import { positionSceneToken, projectProxyScene } from './projectProxyScene'

describe('proxy scene projection', () => {
  it('is seek-deterministic and clamps positions outside token time', () => {
    const events = [event('one', 100, 'flow', 'conntrack')]
    const first = projectProxyScene(events, 500)
    const second = projectProxyScene(events, 500)
    expect(second).toEqual(first)
    expect(positionSceneToken(first.tokens[0], -100).progress).toBe(0)
    expect(positionSceneToken(first.tokens[0], 5000).progress).toBe(1)
    expect(Object.values(positionSceneToken(first.tokens[0], 500)).every(Number.isFinite)).toBe(true)
    const token = first.tokens[0]
    expect(positionSceneToken(token, token.startMs).progress).toBe(0)
    expect(positionSceneToken(token, token.endMs).progress).toBe(1)
  })

  it('bounds 10k active events while preserving selected and queued decisions', () => {
    const events: PipelineEvent[] = Array.from({ length: 10_000 }, (_, index) => ({
      ...event(`burst-${index}`, 100 + index % 50, 'burst', 'header_capture'),
      traceId: `trace-${index}`,
      summary: { clientIp: `10.0.0.${index % 20}`, packetCount: 1 },
    }))
    events.push({
      ...event('queued', 100, 'gate', 'gate_queue'),
      traceId: 'queued-trace',
      summary: { clientIp: '10.0.0.99' },
    })
    const selected = events[9_999]
    const started = performance.now()
    const scene = projectProxyScene(events, 500, { selectedId: selected.traceId })

    expect(scene.tokens.length).toBeLessThanOrEqual(180)
    expect(scene.tokens.some((token) => token.eventIds.includes(selected.id))).toBe(true)
    expect(scene.tokens.some((token) => token.eventIds.includes('queued'))).toBe(true)
    expect(scene.tokens.some((token) => token.count > 1)).toBe(true)
    expect(performance.now() - started).toBeLessThan(1000)
  })

  it('uses explicit observation and drop paths', () => {
    const attribution = projectProxyScene([event('attribute', 0, 'attribution', 'attribution')], 100).tokens[0]
    const rejected = projectProxyScene([{
      ...event('reject', 0, 'gate', 'gate_queue'), summary: { verdict: 'rejected' },
    }], 100).tokens[0]
    expect(attribution.path.plane).toBe('observation')
    expect(rejected.path.nodes[rejected.path.nodes.length - 1]).toBe('drop')
  })

  it('uses distinct DNS gate and inbound strict paths', () => {
    const dns = { ...event('dns-gate', 0, 'gate', 'gate_queue'), summary: { remotePort: 53 } }
    const inbound = { ...event('strict-in', 0, 'gate', 'gate_queue'), direction: 'remote_to_client' as const, summary: {} }
    expect(projectProxyScene([dns], 100).tokens[0].path.id).toBe('dns-gate-wait')
    expect(projectProxyScene([inbound], 100).tokens[0].path.id).toBe('gate-wait-in')
  })

  it('keeps capture quality events out of the animated traffic graph', () => {
    expect(projectProxyScene([event('capture-health', 0, 'health', 'health')], 100).tokens).toEqual([])
  })

  it('maps the recorded source families onto their explicit paths', () => {
    const fixtures: Array<[PipelineEvent['kind'], PipelineEvent['stage'], string]> = [
      ['flow', 'conntrack', 'flow-out'],
      ['dns', 'dns', 'dns-out'],
      ['attribution', 'attribution', 'attribution'],
      ['route', 'route', 'route'],
      ['gate', 'gate_queue', 'gate-wait'],
    ]
    expect(fixtures.map(([kind, stage]) => projectProxyScene([event(`${kind}`, 0, kind, stage)], 100).tokens[0].path.id))
      .toEqual(fixtures.map(([, , path]) => path))
    const attributionNodes = projectProxyScene([event('attribute', 0, 'attribution', 'attribution')], 100).tokens[0].path.nodes
    const dnsNodes = projectProxyScene([event('dns', 0, 'dns', 'dns')], 100).tokens[0].path.nodes
    expect(attributionNodes[attributionNodes.length - 1]).toBe('pocketbase')
    expect(dnsNodes[dnsNodes.length - 1]).toBe('pocketbase')
  })

  it('keeps a simulated ten-minute frame run finite and deterministic', () => {
    for (let frame = 0; frame < 10 * 60 * 30; frame += 1) {
      const cursorMs = demoPipelineEvents[0].occurredAtMs + frame / 30 * 1000
      const scene = projectProxyScene(demoPipelineEvents, cursorMs)
      for (const token of scene.tokens) {
        expect(Object.values(positionSceneToken(token, cursorMs)).every(Number.isFinite)).toBe(true)
      }
    }
  })
})

function event(
  id: string,
  occurredAtMs: number,
  kind: PipelineEvent['kind'],
  stage: PipelineEvent['stage'],
): PipelineEvent {
  return {
    id, sequence: 0, sessionId: 'session', traceId: `trace-${id}`, kind, stage,
    direction: 'client_to_remote', occurredAtMs, timing: 'observed', summary: {},
  }
}
