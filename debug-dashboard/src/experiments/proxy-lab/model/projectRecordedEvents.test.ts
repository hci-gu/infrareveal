import { describe, expect, it } from 'vitest'
import fixture from '../../../../../testdata/aggregate-window-v2.json'
import type { MapWindow } from '@infrareveal/session-state'
import { projectRecordedEvents } from './projectRecordedEvents'
const window=fixture.window as MapWindow
describe('aggregate laboratory events',()=>{
  it('projects actual captured directions and preserves all bytes without inventing sockets',()=>{
    const events=projectRecordedEvents(window), bursts=events.filter(event=>event.kind==='burst')
    expect(bursts.reduce((sum,event)=>sum+(event.summary.wireBytes??0),0)).toBe(3510)
    expect(bursts.some(event=>event.direction==='remote_to_client')).toBe(true)
    expect(bursts.every(event=>event.summary.clientPort===undefined&&event.summary.flowKey===undefined)).toBe(true)
    expect(events.some(event=>event.kind==='flow')).toBe(false)
    expect(events.find(event=>event.kind==='route')?.occurredAtMs).toBe(window.routes[0].available_ms)
  })
  it('keeps visits separated in time for a reused aggregate binding',()=>{
    const events=projectRecordedEvents(window).filter(event=>event.summary.hostname==='svt.se'&&event.direction==='client_to_remote')
    expect(events).toHaveLength(2)
    expect(events[0].traceId).toBe(events[1].traceId)
    expect(events[1].occurredAtMs-events[0].occurredAtMs).toBe(70000)
    expect(events.every(event=>event.summary.payloadBytes===30&&event.summary.wireBytes===150)).toBe(true)
  })
})
