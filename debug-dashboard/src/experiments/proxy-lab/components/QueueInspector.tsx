import { useState } from 'react'
import type { GateDecision, GateStatus, PipelineEvent } from '../types'

export function QueueInspector({ decisions, recent, events, historical, actionable, inFlight, nowMs, gateMode, onApprove, onReject, onApproveAll, onAcceptNext, onSelect }: {
  decisions: readonly GateDecision[]
  recent: readonly GateDecision[]
  events: readonly PipelineEvent[]
  historical: boolean
  actionable: boolean
  inFlight: Set<string>
  nowMs: number
  gateMode: GateStatus['mode']
  onApprove: (id: string) => void
  onReject: (id: string) => void
  onApproveAll: () => void
  onAcceptNext: (count: number) => void
  onSelect: (eventId: string | null, traceId: string) => void
}) {
  const [acceptCount, setAcceptCount] = useState(1)
  const ordered = [...decisions].sort((left, right) => left.queuedAtMs - right.queuedAtMs || left.id.localeCompare(right.id))
  const demoWaiting = events.filter((event) => event.kind === 'gate' && event.stage === 'gate_queue' && !event.summary.verdict)
  const hostnameByFlow = new Map(events
    .filter((event) => event.summary.flowKey && event.summary.hostname)
    .map((event) => [event.summary.flowKey!, { hostname: event.summary.hostname!, confidence: event.summary.confidence ?? 'inferred' }]))
  const hostnameFor = (decision: GateDecision) => {
    const attributed = hostnameByFlow.get(decision.flowKey)
    if (attributed) return attributed
    if (decision.mode !== 'dns' && decision.remotePort !== 53) return null
    const dns = [...events].reverse().find((event) => (
      event.kind === 'dns'
      && event.summary.clientIp === decision.clientIp
      && event.summary.dnsName
      && event.occurredAtMs >= decision.queuedAtMs
      && event.occurredAtMs <= decision.queuedAtMs + 10_000
    ))
    return dns?.summary.dnsName ? { hostname: dns.summary.dnsName, confidence: 'dnsmasq observed' } : null
  }
  return (
    <section aria-label="Current approval queue" className="border border-slate-800 bg-slate-900/70">
      <header className="flex items-center justify-between border-b border-slate-800 px-3 py-2">
        <div><h2 className="text-sm font-semibold text-slate-100">Approval queue</h2><p className="text-[11px] text-slate-500">Live control state, never rewound</p></div>
        <span className="bg-rose-950 px-2 py-1 font-mono text-[10px] font-bold text-rose-300">NOW · {ordered.length}</span>
      </header>
      {historical ? <p className="border-b border-amber-900 bg-amber-950/30 px-3 py-2 text-xs text-amber-200">You are viewing past time. These decisions affect current client traffic.</p> : null}
      {!actionable && ordered.length > 0 ? <p className="border-b border-rose-900 px-3 py-2 text-xs text-rose-300">Control API is unavailable. Queue items are shown but actions are disabled.</p> : null}
      {gateMode === 'strict' ? (
        <div className="m-3 flex items-center gap-2 border border-violet-900 bg-violet-950/20 p-2 text-xs text-violet-200">
          <label className="flex items-center gap-2">Accept next<input className="w-16 border border-violet-700 bg-slate-950 px-2 py-1 font-mono" max="100" min="1" onChange={(event) => setAcceptCount(Math.min(100, Math.max(1, Number(event.target.value) || 1)))} type="number" value={acceptCount} /></label>
          <button className="border border-violet-600 px-2 py-1 disabled:opacity-40" disabled={!actionable || inFlight.has('accept-next')} onClick={() => onAcceptNext(acceptCount)} type="button">Step packets</button>
        </div>
      ) : ordered.length > 1 ? <button className="m-3 border border-emerald-700 px-2 py-1 text-xs text-emerald-300 disabled:opacity-40" disabled={!actionable || inFlight.has('approve-all')} onClick={onApproveAll} type="button">Approve all {ordered.length}</button> : null}
      <div className="max-h-80 overflow-y-auto">
        {ordered.length === 0 && demoWaiting.length === 0 ? <p className="p-4 text-xs text-slate-500">No flows are currently held.</p> : null}
        {ordered.map((decision) => {
          const busy = inFlight.has(`decision:${decision.id}`)
          const elapsed = Math.max(0, nowMs - decision.queuedAtMs)
          const budget = Math.max(1, decision.deadlineMs - decision.queuedAtMs)
          const warning = elapsed / budget >= 0.8 ? 'text-rose-300' : elapsed / budget >= 0.5 ? 'text-amber-300' : 'text-slate-500'
          const hostname = hostnameFor(decision)
          return (
            <article className="border-b border-slate-800 p-3" key={decision.id}>
              <button className="block w-full text-left" onClick={() => onSelect(null, `gate:${decision.id}`)} type="button">
                <span className="font-mono text-xs text-cyan-200">{decision.protocol.toUpperCase()} {decision.clientIp}:{decision.clientPort}</span>
                <span className="mt-1 block font-mono text-[11px] text-slate-400">{decision.direction === 'remote_to_client' ? '←' : '→'} {decision.remoteIp}:{decision.remotePort}</span>
                <span className={`mt-1 block text-[11px] ${warning}`}>{hostname?.hostname || 'Hostname unknown'} · confidence {hostname?.confidence ?? 'none'} · {decision.packetCount} pkt · {decision.wireBytes ?? 0} B wire / {decision.payloadBytes ?? 0} B payload · flags 0x{decision.tcpFlags.toString(16)} · waiting {elapsed} ms · watchdog in {Math.max(0, decision.deadlineMs - nowMs)} ms</span>
              </button>
              <div className="mt-2 flex gap-2">
                <button className="border border-emerald-700 px-2 py-1 text-xs text-emerald-300 disabled:opacity-40" disabled={!actionable || busy} onClick={() => onApprove(decision.id)} type="button">{busy ? 'Working…' : 'Approve'}</button>
                <button className="border border-rose-700 px-2 py-1 text-xs text-rose-300 disabled:opacity-40" disabled={!actionable || busy} onClick={() => onReject(decision.id)} type="button">Reject</button>
              </div>
            </article>
          )
        })}
        {ordered.length === 0 ? demoWaiting.map((event) => (
          <button className="block w-full border-b border-slate-800 p-3 text-left hover:bg-slate-800" key={event.id} onClick={() => onSelect(event.id, event.traceId)} type="button">
            <span className="font-mono text-xs text-amber-200">{event.summary.protocol ?? 'flow'} · {event.summary.clientIp ?? event.summary.flowKey}</span>
            <span className="mt-1 block text-[11px] text-slate-500">Fixture queue event · select to inspect</span>
          </button>
        )) : null}
      </div>
      {recent.length > 0 ? <div className="border-t border-slate-700 p-3"><h3 className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Recent decisions</h3>{recent.slice(0, 5).map((item) => { const hostname = hostnameFor(item); return <p className="mt-1 font-mono text-[10px] text-slate-400" key={item.id}>{item.protocol} {hostname?.hostname ? `${hostname.hostname} · ` : ''}{item.remoteIp}:{item.remotePort} <b className={item.state === 'approved' ? 'text-emerald-300' : 'text-rose-300'}>{item.state}</b></p> })}</div> : null}
    </section>
  )
}
