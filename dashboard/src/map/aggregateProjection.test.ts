import { describe, expect, it } from 'vitest'
import fixture from '../../../testdata/aggregate-window-v2.json'
import type { MapWindow, SessionManifest } from '@infrareveal/session-state'
import { buildMapTimelineScene, projectMapFrame } from './mapModel'
import { buildMapTrackCatalog } from './mapTracks'
import { indexDestinationVolumes, projectDestinationVolumes } from './destinationVolumes'
import { projectWorkspace } from './mapWorkspace'
import { directionalVolumeArcs, indexMapTraffic, projectTrafficProfiles } from './mapTraffic'
import { wireWaveform } from './wireWaveform'
const window=fixture.window as MapWindow, manifest=fixture.manifest as SessionManifest, start=manifest.started_ms
const origin={latitude:57.7,longitude:11.9,label:'Gateway'}
function project(data=window,time=start+100) {
  const scene=buildMapTimelineScene(data,manifest,origin), catalog=buildMapTrackCatalog(data,manifest), index=indexDestinationVolumes(data.series,data.from_ms,data.coverage)
  return { scene,catalog,index,view:projectWorkspace(catalog,scene,index,time,{direction:'both',locationId:null,expanded:false}) }
}
describe('captured series map projection',()=>{
  it('preserves all wire bytes once, separates shared-IP services, and includes unknown locations',()=>{
    const {view, index}=project()
    expect(view.total).toMatchObject({received:2000,sent:360,partial:false})
    expect(view.tracks.map(track=>track.label).sort()).toEqual(['203.0.113.99','news.example','svt.se'])
    expect(view.locations.find(location=>location.id==='unlocated')?.sent).toBe(60)
    const volumes=projectDestinationVolumes(view.scene,view.bySeries,index,start+100)
    expect(volumes).toHaveLength(1)
    expect(volumes[0]).toMatchObject({received:2000,sent:300,seriesCount:2})
    expect(volumes[0].tracks).toHaveLength(2)
  })
  it('does not treat a quiet gap between chunks as active traffic',()=>{
    const {view}=project(window,start+20000)
    expect(view.tracks.every(track=>track.activeCount===0)).toBe(true)
    expect(projectMapFrame(view.scene,start+20000).activeSeriesCount).toBe(0)
  })
  it('gives distinct series their own timeline lanes even at the same service and location',()=>{
    const original=window.series[0]
    const parallel={...original,id:'parallel',destination_port:8443}
    const restarted={...original,id:'restarted',capture_epoch:'capture-2'}
    const {view}=project({...window,series:[...window.series,parallel,restarted]})
    expect(view.rows).toHaveLength(view.bySeries.size)
    expect(view.rows.every(row=>row.series.length===1)).toBe(true)
    expect(view.rows.filter(row=>row.label==='svt.se')).toHaveLength(3)
    expect(view.rows.reduce((sum,row)=>sum+row.received,0)).toBe(view.total.received)
    expect(view.rows.reduce((sum,row)=>sum+row.sent,0)).toBe(view.total.sent)
  })
  it('does not move timeline lanes when another service gains traffic',()=>{
    const before=project().view.rows.map(row=>row.id)
    const changed={...window,series:window.series.map(chunk=>chunk.service_key.startsWith('endpoint:')?{...chunk,samples:chunk.samples.map(sample=>[sample[0],sample[1]*100,sample[2]*100,...sample.slice(3)] as typeof sample)}:chunk)}
    expect(project(changed).view.rows.map(row=>row.id)).toEqual(before)
  })
  it('preserves outward and return bursts independently without lifetime estimation',()=>{
    const {view}=project(window,start+500)
    const profiles=projectTrafficProfiles(view.scene,indexMapTraffic(window.series,window.coverage),start+500)
    const endpoint=view.scene.endpoints.find(endpoint=>endpoint.label==='svt.se')!
    expect(profiles.get(endpoint.id)).toMatchObject({source:'sampled',inRates:[1680,...Array(11).fill(0)],outRates:[60,...Array(11).fill(0)]})
    expect(directionalVolumeArcs([{endpointIds:[endpoint.id]}],profiles).map(arc=>arc.direction)).toEqual([1,-1])
    const absent=projectTrafficProfiles(view.scene,indexMapTraffic([],[]),start+500).get(endpoint.id)!
    expect(absent.rates.every(rate=>rate===0)).toBe(true)
    expect(absent.source).toBe('partial')
  })
  it('shows confirmed idle waveform bins while preserving capture gaps',()=>{
    const {view,index}=project(window,start+20000)
    const bins=wireWaveform([...view.bySeries.values()],index,{from:start+1000,to:start+3000},2)
    expect(bins).toEqual([{received:0,sent:0,complete:true,observed:true},{received:0,sent:0,complete:true,observed:true}])
    index.coverage=[]
    expect(wireWaveform([...view.bySeries.values()],index,{from:start+1000,to:start+3000},2).every(bin=>!bin.observed&&!bin.complete)).toBe(true)
  })
  it('uses location versions independently, never the newest location for every IP',()=>{
    const later={...window.destinations[0],id:'later',city:'Berlin',country:'Germany',lat:52.52,lon:13.4,observed_ms:start+1000}
    const changed={...window,destinations:[...window.destinations,later],series:window.series.map(chunk=>chunk.id==='news-1'?{...chunk,destination_id:'later'}:chunk)}
    const before=project(changed,start+100).view
    expect(before.locations.find(location=>location.id==='unlocated')?.received).toBe(1000)
    const after=project(changed,start+1500).view
    expect(after.locations.some(location=>location.label==='Berlin')).toBe(true)
    expect(after.locations.some(location=>location.label==='Stockholm')).toBe(true)
  })
  it('keeps route geometry as-known and falls back after expiration',()=>{
    const {view}=project(window,start+2000)
    const frame=projectMapFrame(view.scene,start+2000)
    expect(frame.arcs.some(arc=>arc.routeId==='path-1')).toBe(true)
    expect(frame.arcs.filter(arc=>arc.routeId==='path-1').some(arc=>arc.gap)).toBe(true)
    expect(projectMapFrame(view.scene,start+65000).arcs.every(arc=>!arc.routeId)).toBe(true)
    expect(frame.points.every(point=>point.position[0]!==0&&point.position[1]!==0)).toBe(true)
  })
})
