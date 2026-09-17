import { describe, expect, it } from 'vitest'
import type { Route, SessionWindow } from './types'
import { emptyGatewayData } from './pocketbaseClient'
import { routeForFlowAt, routeStateLabel, routeTopology } from './routeEvidence'
import { applyRealtimeBatch, applySessionWindow, clearDetailPages, resetSessionTimeline, sessionTimelineStore } from '../timeline/store/sessionStore'

const start = Date.parse('2026-09-10T12:00:00Z')
const socket = { session: 'session', destination_ip: '9.9.9.9', destination_port: 443, protocol: 'tcp' }
function route(id: string, at: number, extra: Partial<Route> = {}): Route {
  return { ...socket, id, destination: '', method: 'tcp:443', complete: false, error: '', completed_at: '', available_at: new Date(start + at).toISOString(), valid_until: new Date(start + 60_000).toISOString(), hops: [], ...extra }
}
describe('route evidence over time', () => {
  it('applies confirmation, enrichment and network epochs only at their availability', () => {
    const at = (n: number) => new Date(start+n).toISOString()
    const r = route('sparse',100,{valid_until:at(1000),hops:[{ttl:1,address:'1.1.1.1',missing:false,timings:[]}],evidence_updates:[
      {kind:'confirmed',available_at:at(1500),value:{fresh_until:at(2500),valid_until:at(5000)}},
      {kind:'enriched',available_at:at(2000),value:{'1':{'1.1.1.1':{origin_asn:13335,source:'fixture',version:'1',available_at:at(2000),confidence:'inferred'}}}},
      {kind:'network_invalidated',available_at:at(3000),value:{}},
    ]})
    expect(routeForFlowAt(socket,[r],start+1100)).toBeNull()
    expect(routeForFlowAt(socket,[r],start+1600)?.hops?.[0].interface_evidence).toBeUndefined()
    expect(routeForFlowAt(socket,[r],start+2100)?.hops?.[0].interface_evidence?.['1.1.1.1'].origin_asn).toBe(13335)
    expect(routeForFlowAt(socket,[r],start+3100)).toBeNull()
  })
  it('keeps unlocated responders, unknown spans and unprobed tails distinct', () => {
    const r = route('topology',100,{hops:[
      {ttl:1,address:'192.168.1.1',missing:false,timings:[]},
      {ttl:2,end_ttl:12,address:'',missing:true,state:'no_reply',timings:[]},
      {ttl:13,address:'9.9.9.9',missing:false,timings:[]},
      {ttl:14,end_ttl:32,address:'',missing:true,state:'not_probed',timings:[]},
    ]})
    expect(routeTopology(r).map(h=>[h.from,h.to,h.label])).toEqual([[1,1,'192.168.1.1'],[2,12,'Unobserved segment'],[13,13,'9.9.9.9'],[14,32,'Not probed']])
  })
  it('keeps alternate probes separate and reveals them only with their revision', () => {
    const mainHops = [{ttl: 1, address: '1.1.1.1', missing: false, timings: [1]}]
    const first = route('first', 100, {hops: mainHops, provenance: 'cache', measured_at: new Date(start - 60_000).toISOString()})
    const later = route('later', 2000, {...first, id: 'later', available_at: new Date(start + 2000).toISOString(), status: 'refreshing',
      probe_details: {latest_attempt: {method: 'icmp-paris', status: 'probing', error: '', measured_at: new Date(start + 2000).toISOString(), responding_hops: 1, located_hops: 0, profile: 'coverage'}},
      alternate_routes: [{method: 'icmp-paris', measured_at: new Date(start + 2000).toISOString(), destination_reached: false, responding_hops: 1, located_hops: 0, hops: [{ttl: 1, address: '2.2.2.2', missing: false, timings: [2]}]}],
    })
    expect(routeForFlowAt(socket, [first, later], start + 1000)?.alternate_routes).toBeUndefined()
    const selected = routeForFlowAt(socket, [first, later], start + 3000)!
    expect(selected.hops).toEqual(mainHops)
    expect(selected.alternate_routes?.[0].hops?.[0].address).toBe('2.2.2.2')
    expect(routeStateLabel(selected, start + 3000)).toBe('Improving coverage · cached 1m ago')
  })
  it('shows progressive and cached evidence only when available and never resurrects invalidated paths', () => {
    const cached = route('cache', 100, {complete: true, provenance: 'cache', measured_at: new Date(start - 60_000).toISOString()})
    const partial = route('partial', 1000, {hops: [{ttl: 1, address: '1.1.1.1', missing: false, timings: [1]}]})
    const invalid = route('invalid', 2000, {status: 'invalidated'})
    expect(routeForFlowAt(socket, [cached], start)).toBeNull()
    expect(routeForFlowAt(socket, [partial, cached], start + 500)?.id).toBe('cache')
    expect(routeForFlowAt(socket, [partial, cached], start + 1500)?.hops).toHaveLength(1)
    expect(routeForFlowAt(socket, [partial, cached, invalid], start + 2500)).toBeNull()
    expect(routeForFlowAt(socket, [cached], start + 60_000)).toBeNull()
    expect(routeForFlowAt({...socket, protocol: 'udp'}, [cached], start + 500)).toBeNull()
  })
  it('bounds realtime revisions while retaining loaded history and newer before-window anchors', () => {
    resetSessionTimeline('session', [])
    const first = route('first', 100)
    const window: SessionWindow = {...emptyGatewayData(), range:{from:new Date(start + 500).toISOString(),to:new Date(start + 1000).toISOString()}, lod:'50ms', watermark:'test',nextCursor:null,routes:[first]}
    applySessionWindow(window, {key:'page',fromMs:start+500,toMs:start+1000,lod:'50ms',flowKey:'all',flowIds:new Set()})
    applyRealtimeBatch([{collection:'routes',action:'create',record:route('new-anchor',400)}])
    expect(sessionTimelineStore.getState().pages.get('page')?.ownership.routes.has('first')).toBe(false)
    expect(sessionTimelineStore.getState().pages.get('page')?.ownership.routes.has('new-anchor')).toBe(true)
    for (let i=1;i<=200;i++) applyRealtimeBatch([{collection:'routes',action:'create',record:route(`future-${i}`,1000+i)}])
    expect(sessionTimelineStore.getState().entities.routes.size).toBe(2)
    applyRealtimeBatch([{collection:'routes',action:'create',record:first}])
    expect(sessionTimelineStore.getState().entities.routes.size).toBe(2)
    clearDetailPages()
    expect([...sessionTimelineStore.getState().entities.routes.keys()]).toEqual(['future-200'])
  })
})
