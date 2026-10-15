import { afterEach, describe, expect, it, vi } from 'vitest'
import fixture from '../../../../testdata/aggregate-window-v2.json'
import type { MapWindow, RouteEvidence, SessionManifest } from './types'
import { getMapWindow } from './client'
import { captureQuality, trafficTotals } from './traffic'
import { routeForSeriesAt } from './routeEvidence'
import { acceptManifest, sessionTimelineStore } from '../runtime'
const window = fixture.window as MapWindow, manifest = fixture.manifest as SessionManifest
const start = manifest.started_ms

afterEach(() => vi.unstubAllGlobals())
describe('aggregate product contract', () => {
  it('counts captured wire bins once, never future or invented partial-bin bytes', () => {
    expect(trafficTotals(window.series, start, start+49).sent).toBe(0)
    expect(trafficTotals(window.series, start, start+50)).toMatchObject({ sent:260, received:800 })
    expect(trafficTotals(window.series, start, start+100)).toMatchObject({ sent:360, received:2000 })
    expect(trafficTotals(window.series, start+50, start+100)).toMatchObject({ sent:100, received:1200 })
    expect(trafficTotals(window.series, start, start+90000)).toMatchObject({ sent:510, received:3000 })
  })
  it('separates confirmed silence, partial capture, and absence of evidence', () => {
    expect(captureQuality(window.coverage, start+1000,start+5000)).toBe('complete')
    expect(captureQuality([],start,start+100)).toBe('unavailable')
    expect(captureQuality([{...window.coverage[0],end_ms:start+100}],start,start+200)).toBe('partial')
    expect(captureQuality([{...window.coverage[0],dropped:1}],start,start+100)).toBe('partial')
  })
  it('uses exact protocol/port/epoch binding and never resurrects expired or invalidated routes', () => {
    const chunk=window.series[0], path=window.routes[0]
    expect(routeForSeriesAt(chunk,window.routes,start+999)).toBeNull()
    expect(routeForSeriesAt(chunk,window.routes,start+1000)?.id).toBe(path.id)
    expect(routeForSeriesAt(window.series[2],window.routes,start+1000)).toBeNull()
    const latest={...path,id:'new',revision:2,available_ms:start+2000,valid_until_ms:start+3000}
    expect(routeForSeriesAt(chunk,[path,latest],start+3500)).toBeNull()
    const invalidation={...path,id:'invalid',kind:'network_invalidated',available_ms:start+1500} as RouteEvidence
    expect(routeForSeriesAt(chunk,[path,invalidation],start+1600)).toBeNull()
    expect(routeForSeriesAt({...chunk,network_epoch:'other'},window.routes,start+1500)).toBeNull()
  })
  it('keeps paused absolute time while retention advances, then clamps only expired replay', () => {
    sessionTimelineStore.setState({selectedSessionId:manifest.id,manifest:null})
    acceptManifest({...manifest,active:true,ephemeral:true})
    sessionTimelineStore.setState({cursorMs:start+10000,playback:'paused'})
    acceptManifest({...manifest,active:true,ephemeral:true,retained_from_ms:start+5000,server_ms:start+100000})
    expect(sessionTimelineStore.getState()).toMatchObject({epochMs:start,cursorMs:start+10000,playback:'paused'})
    acceptManifest({...manifest,active:true,ephemeral:true,retained_from_ms:start+15000})
    expect(sessionTimelineStore.getState()).toMatchObject({epochMs:start,cursorMs:start+15000,playback:'paused'})
  })
  it('assembles all pages and replaces a changed revision instead of adding stale samples', async () => {
    const fetch=vi.fn().mockResolvedValueOnce(Response.json({...window,complete:false,next_cursor:'next',series:[window.series[0]]}))
      .mockResolvedValueOnce(Response.json({message:'revision changed'},{status:409}))
      .mockResolvedValueOnce(Response.json({...window,revision:4,complete:false,next_cursor:'new-next',series:[window.series[1]]}))
      .mockResolvedValueOnce(Response.json({...window,revision:4,complete:true,series:[window.series[2]]}))
    vi.stubGlobal('fetch',fetch)
    const result=await getMapWindow('session',start,start+90000)
    expect(result.revision).toBe(4)
    expect(result.series.map(chunk=>chunk.id)).toEqual(['svt-2','news-1'])
    expect(result.destinations).toHaveLength(1)
    expect(fetch).toHaveBeenCalledTimes(4)
  })
  it('rejects incomplete pagination instead of publishing misleading totals', async () => {
    vi.stubGlobal('fetch',vi.fn().mockResolvedValue(Response.json({...window,complete:false,next_cursor:''})))
    await expect(getMapWindow('session',start,start+90000)).rejects.toThrow('Invalid map pagination')
  })
})
