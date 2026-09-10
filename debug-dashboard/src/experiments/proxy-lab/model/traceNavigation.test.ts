import { describe, expect, it } from 'vitest'
import { buildLabTraces, preferredTraceEvent, stepTraceNode, traceEventPath } from './traceNavigation'
import type { PipelineEvent } from '../types'
const event = (patch: Partial<PipelineEvent> = {}): PipelineEvent => ({ id:'e',sequence:1,sessionId:'s',traceId:'t',kind:'flow',stage:'conntrack',occurredAtMs:100,timing:'observed',summary:{flowKey:'tcp|client|5000|remote|443',clientIp:'client',remoteIp:'remote',remotePort:443,protocol:'tcp'},...patch })
describe('Lab trace navigation', () => {
  it('groups observed and durable events by connection identity without conflating clients', () => {
    const a=event(),b=event({id:'other-event',traceId:'different-event-trace',kind:'burst'}),c=event({id:'different-client',summary:{...a.summary,flowKey:'tcp|other|5000|remote|443',clientIp:'other'}})
    const traces=buildLabTraces([c,b,a]);expect(traces).toHaveLength(2);expect(traces[0].events.map(e=>e.id)).toEqual(['e','other-event'])
  })
  it('ends a held path at the gate and requires a verdict for forwarding', () => {
    const held=event({kind:'gate',stage:'gate_queue'}),path=traceEventPath(held)!
    expect(path.nodes).toEqual(['conntrack','flow_gate'])
    expect(stepTraceNode(path,'flow_gate',1)).toBe('flow_gate')
    const accepted=event({kind:'gate',stage:'forward',summary:{...held.summary,verdict:'approved'}})
    expect(traceEventPath(accepted)?.nodes).toEqual(['flow_gate','forward','nat','remote'])
    const trace=buildLabTraces([held,{...accepted,id:'accepted',occurredAtMs:200}])[0]
    expect(preferredTraceEvent(trace,150)?.id).toBe(held.id)
    expect(preferredTraceEvent(trace,250)?.id).toBe('accepted')
  })
  it('preserves reject, DNS and inbound paths without a capture forwarding hop', () => {
    expect(traceEventPath(event({kind:'gate',summary:{verdict:'rejected'}}))?.nodes).toEqual(['flow_gate','drop'])
    expect(traceEventPath(event({kind:'gate',summary:{remotePort:53}}))?.nodes).toEqual(['client','wlan0','dns_gate'])
    expect(traceEventPath(event({kind:'gate',summary:{remotePort:53,verdict:'rejected'}}))?.nodes).toEqual(['dns_gate','drop'])
    expect(traceEventPath(event({kind:'burst',direction:'remote_to_client'}))?.nodes).toEqual(['remote','nat','forward','flow_gate','conntrack','wlan0','client'])
    expect(traceEventPath(event({kind:'burst'}))?.nodes).not.toContain('header_capture')
  })
})
