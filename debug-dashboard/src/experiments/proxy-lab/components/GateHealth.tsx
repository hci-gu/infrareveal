import type { GateStatus } from '../types'

export function GateHealth({ status, traceStatus, controlStatus, dropped, busy, onPause, onResume, onDrain, onDisarm }: {
  status: GateStatus | null
  traceStatus: string
  controlStatus: string
  dropped: number
  busy: (key: string) => boolean
  onPause: () => void
  onResume: () => void
  onDrain: () => void
  onDisarm: () => void
}) {
  const watchdogBudget = status?.mode === 'strict' ? status.establishedTimeoutMs : status?.mode === 'dns' ? status.dnsTimeoutMs : status?.flowTimeoutMs ?? 0
  const budgetUsed = watchdogBudget > 0 ? (status?.oldestWaitMs ?? 0) / watchdogBudget : 0
  return (
    <section className="border border-slate-800 bg-slate-900/70 p-3 text-xs text-slate-400">
      <div className="flex items-center justify-between"><span>Trace stream</span><Status value={traceStatus} /></div>
      <div className="mt-2 flex items-center justify-between"><span>Control API</span><Status value={controlStatus} /></div>
      <div className="mt-2 flex items-center justify-between"><span>Flow gate</span><Status value={status?.state ?? 'off'} /></div>
      <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 border-t border-slate-800 pt-3 font-mono text-[10px]">
        <Metric label="pending" value={status?.pendingFlows} /><Metric label="held" value={status?.heldPackets} />
        <Metric label="kernel queue" value={status?.queue.queueDepth} /><Metric label="oldest ms" value={status?.oldestWaitMs} />
        <Metric danger label="overflow" value={status?.overflowCount} /><Metric danger label="watchdogs" value={status?.watchdogReleases} />
        <Metric danger label="parse bypass" value={status?.parseBypassCount} /><Metric danger label="audit drops" value={status?.auditDrops} />
        <Metric danger label="kernel drops" value={status?.queue.kernelDrops} /><Metric danger label="trace gaps" value={dropped} />
        <Metric danger label="user drops" value={status?.queue.userDrops} /><Metric danger label="verdict errors" value={status?.verdictErrors} />
      </div>
      {budgetUsed >= 0.5 ? <p className={`mt-3 border-l-2 pl-2 ${budgetUsed >= 0.8 ? 'border-rose-500 text-rose-300' : 'border-amber-500 text-amber-300'}`}>Oldest decision has used {Math.min(100, Math.round(budgetUsed * 100))}% of its safety watchdog. Expiry accepts traffic and is recorded as expired.</p> : null}
      {status?.auditDrops ? <p className="mt-2 border-l-2 border-rose-500 pl-2 text-rose-300">Audit loss detected. This session’s recorded gate trail is incomplete.</p> : null}
      {status && Object.keys(status.kernelSettings ?? {}).length > 0 ? <details className="mt-3 border-t border-slate-800 pt-2"><summary className="cursor-pointer text-[10px] uppercase tracking-wider text-slate-500">Read-only kernel settings</summary><div className="mt-2 space-y-1 font-mono text-[10px]">{Object.entries(status.kernelSettings).map(([key, value]) => <p className="flex justify-between gap-3" key={key}><span>{key}</span><b className="text-slate-200">{value}</b></p>)}</div></details> : null}
      {status?.lastError ? <p className="mt-3 border-l-2 border-rose-500 pl-2 text-rose-300">{status.lastError}</p> : null}
      {status?.armed ? (
        <div className="mt-3 grid grid-cols-2 gap-2 border-t border-slate-800 pt-3">
          {status.paused ? <Action busy={busy('resume')} label="Resume intake" onClick={onResume} /> : <Action busy={busy('pause')} label="Pause intake" onClick={onPause} />}
          <Action busy={busy('drain')} label="Drain held" onClick={onDrain} />
          <button className="col-span-2 border border-rose-600 px-2 py-1.5 font-bold text-rose-300 hover:bg-rose-950 disabled:opacity-40" disabled={busy('disarm')} onClick={onDisarm} type="button">{busy('disarm') ? 'Disarming…' : 'Emergency disarm'}</button>
        </div>
      ) : null}
    </section>
  )
}

function Metric({ label, value, danger = false }: { label: string; value?: number; danger?: boolean }) {
  return <span className="flex justify-between gap-2"><span>{label}</span><b className={danger && value ? 'text-rose-300' : 'text-slate-200'}>{value ?? 0}</b></span>
}
function Action({ busy, label, onClick }: { busy: boolean; label: string; onClick: () => void }) {
  return <button className="border border-slate-600 px-2 py-1.5 text-slate-200 hover:border-cyan-500 disabled:opacity-40" disabled={busy} onClick={onClick} type="button">{busy ? 'Working…' : label}</button>
}
function Status({ value }: { value: string }) {
  const healthy = value === 'live' || value === 'active' || value === 'ready'
  const danger = value === 'error' || value === 'degraded'
  return <span className={`font-mono uppercase ${healthy ? 'text-emerald-300' : danger ? 'text-rose-300' : 'text-amber-300'}`}>{value}</span>
}
