import { beforeEach, describe, expect, it } from 'vitest'
import { canDecide } from './useLabControl'
import { clearProxyLabRoute, proxyLabStore, resetProxyLabSession, selectLabNode, setGateStatus, setLabGateMode, setLabObservationMode, synchronizePendingDecisions } from './proxyLabStore'
import type { GateDecision, GateStatus } from '../types'
const decision: GateDecision={id:'d',flowKey:'f',sessionId:'s',clientIp:'client',remoteIp:'remote',clientPort:5000,remotePort:443,protocol:'tcp',packetCount:1,tcpFlags:2,queuedAtMs:100,deadlineMs:1000,state:'queued'}
beforeEach(()=>{clearProxyLabRoute();resetProxyLabSession('s')})
describe('independent observation and current control state',()=>{
  it('keeps armed policy, pending decisions and selected node independent of view changes',()=>{
    const status={armed:true,mode:'strict',state:'active',sessionId:'s'} as GateStatus
    setGateStatus(status);synchronizePendingDecisions([decision]);selectLabNode('nat')
    setLabObservationMode('live-observe');setLabGateMode('dns');setLabObservationMode('replay')
    expect(proxyLabStore.getState()).toMatchObject({observationMode:'replay',requestedGateMode:'dns',gateStatus:status,selectedNodeId:'nat'})
    expect(proxyLabStore.getState().pendingDecisions.get('d')).toEqual(decision)
  })
  it('disables expired, terminal, offline, other-source and in-flight decisions',()=>{
    expect(canDecide(decision,500,'s',true,new Set())).toBe(true)
    expect(canDecide(decision,1000,'s',true,new Set())).toBe(false)
    expect(canDecide({...decision,state:'approved'},500,'s',true,new Set())).toBe(false)
    expect(canDecide(decision,500,'s',false,new Set())).toBe(false)
    expect(canDecide(decision,500,'recording',true,new Set())).toBe(false)
    expect(canDecide(decision,500,'s',true,new Set(['decision:d']))).toBe(false)
  })
})
