import { describe, expect, it } from 'vitest'
import type { Flow, FlowActivityChunk, FlowActivityWindow, GatewayData } from '@infrareveal/session-state'
import { SessionCompositionProjector } from '../../model/sessionModel'
import { activityInWindow, buildTrafficModel, preferredActivityChunks, trafficRecords } from './trafficModel'
import { clampTime, pixelAtTime, timeAtPixel, viewportAt, rulerStep } from './trafficTime'
import { captureCoverage } from '../../shared/activity/captureCoverage'
const epoch=Date.parse('2026-09-07T10:00:00Z'),iso=(offset:number)=>new Date(epoch+offset).toISOString()
const flow=(id:string,client='client'):Flow=>({id,session:'s',created:iso(0),updated:iso(0),client_ip:client,destination_ip:'1.1.1.1',source_port:5000,destination_port:443,protocol:'udp',state:'ESTABLISHED',start:iso(125),last_seen:iso(10000),bytes_in:1000,bytes_out:100,packets_in:5,packets_out:2})
const empty=():GatewayData=>({sessions:[],selectedSession:null,flows:[],dnsQueries:[],attributions:[],activityEpisodes:[],flowAssociations:[],flowActivityChunks:[],flowActivityWindows:[],flowActivityStatuses:[],destinations:[],routes:[],gateEvents:[]})
const chunk=(id:string,bucket=1000,start=0,length=5000):FlowActivityChunk=>({id,session:'s',flow:'f',flow_key:'f',chunk_start:iso(start),bucket_ms:bucket,chunk_ms:length,samples:{version:1,bucket_ms:bucket,chunk_ms:length,samples:[[0,10,100,1,2]]},wire_bytes_out:20,wire_bytes_in:150,payload_bytes_out:10,payload_bytes_in:100,packets_out:1,packets_in:2,tcp_flags_out:0,tcp_flags_in:0,capture_complete:true,dropped_events:0,updated_at_source:iso(0)})
const window=(start=0,length=10000,patch:Partial<FlowActivityWindow>={}):FlowActivityWindow=>({id:`w${start}`,session:'s',window_key:'w',window_start:iso(start),window_ms:length,capture_running:true,capture_complete:true,dropped_events:0,last_error:'',...patch})
describe('Traffic time and evidence',()=>{
  it('round-trips source precision through pixels and clamps seeks without changing zoom anchor',()=>{
    const bounds={fromMs:epoch,toMs:epoch+60000},range=viewportAt(epoch+30000,10000,bounds),time=epoch+30123.5
    expect(timeAtPixel(pixelAtTime(time,733,range),733,range)).toBeCloseTo(time,4)
    expect(viewportAt(epoch+30000,30000,bounds)).toEqual({fromMs:epoch+15000,toMs:epoch+45000})
    expect(clampTime(epoch-500,bounds)).toBe(epoch);expect(clampTime(epoch+90000,bounds)).toBe(epoch+60000)
    expect(rulerStep(300,1200)).toBe(1000)
    expect(viewportAt(epoch,0,bounds)).toEqual(bounds)
  })
  it('uses only supported client-specific associations and preserves protocol and endpoint identity',()=>{
    const data=empty();data.flows=[flow('supported'),flow('other-client','other'),flow('low'),flow('provider')]
    data.activityEpisodes=[{id:'ep',session:'s',episode_key:'ep',client_ip:'client',site_key:'example.org',label:'Browsing',anchor_hostname:'www.example.org',start:iso(0),last_seen:iso(10000),confidence:'high',explanation:'Evidence'}]
    data.flowAssociations=data.flows.slice(0,3).map(f=>({id:`a${f.id}`,session:'s',flow:f.id,episode:'ep',parent_site_key:'example.org',parent_label:'Browsing',relationship:'first_party',confidence:f.id==='low'?'low':'high',score:.9,explanation:'Association',observed_at:iso(150)}))
    data.destinations=[{id:'d',ip:'1.1.1.1',reverse_dns:'edge.example.org',asn:123,organization:'Provider',provider_label:'Provider',city:'',country:'',lat:0,lon:0,last_seen:iso(0)}]
    const model=buildTrafficModel(data,new SessionCompositionProjector(),epoch,epoch+10000)
    expect(model.clips.find(c=>c.flowId==='supported')?.serviceGroupId).toContain('activity:ep')
    expect(model.clips.filter(c=>c.flowId!=='supported').every(c=>c.serviceGroupId.endsWith(':independent'))).toBe(true)
    expect(model.clips.every(c=>c.protocol.toLowerCase()==='udp'&&c.label==='1.1.1.1')).toBe(true)
  })
  it('retains independent DNS IDs and sorts events within the same displayed second',()=>{
    const data=empty();data.flows=[flow('z'),{...flow('a'),start:iso(100)}];data.dnsQueries=[{id:'q1',session:'s',created:iso(0),client_ip:'client',query_name:'example.org',query_type:'A',answers:['1.1.1.1'],aliases:[],timestamp:iso(110)},{id:'q2',session:'s',created:iso(0),client_ip:'client',query_name:'example.org',query_type:'A',answers:['1.1.1.1'],aliases:[],timestamp:iso(111)}]
    expect(trafficRecords(data).map(r=>r.id)).toEqual(['flow:a','dns:q1','dns:q2','flow:z'])
    const model=buildTrafficModel(data,new SessionCompositionProjector(),epoch,epoch+10000)
    expect(model.groups.find(g=>g.id==='client:dns')?.dns.map(q=>q.id)).toEqual(['q1','q2'])
  })
  it('avoids overlapping LOD totals and keeps whole coarse coverage when fine detail is partial',()=>{
    const coarse=chunk('coarse'),fine=chunk('fine',50)
    expect(preferredActivityChunks([coarse,fine]).map(c=>c.id)).toEqual(['fine'])
    expect(preferredActivityChunks([chunk('wide',1000,0,10000),fine]).map(c=>c.id)).toEqual(['wide'])
    expect(preferredActivityChunks([chunk('wide',1000,0,10000),fine,chunk('fine2',50,5000)]).map(c=>c.id)).toEqual(['fine','fine2'])
    const totals=activityInWindow([coarse,fine],[window()],epoch,epoch+10000)
    expect(totals.payloadIn).toBe(100);expect(totals.packetsOut).toBe(1);expect(totals.resolution).toEqual([50])
    expect(activityInWindow([fine],[window()],epoch+50,epoch+10000).payloadIn).toBe(0)
    expect(activityInWindow([fine],[window(20000)],epoch+20000,epoch+30000).resolution).toEqual([])
  })
  it('separates complete silence, unloaded coverage, capture loss and unavailable capture',()=>{
    const coverage=captureCoverage([window(0,5000),window(2000,1000,{capture_complete:false}),window(3000,1000,{capture_running:false})],epoch,epoch+6000)
    expect(coverage.map(c=>c.level)).toEqual(['complete','partial','unavailable','complete','unknown'])
    expect(activityInWindow([{...chunk('partial'),capture_complete:false}],[window()],epoch,epoch+10000).complete).toBe(false)
  })
})
