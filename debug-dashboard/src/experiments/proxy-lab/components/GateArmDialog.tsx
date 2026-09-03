import { useState } from 'react'
import type { StrictTuple } from '../data/gateClient'
import type { GateStatus, ProxyLabMode } from '../types'

type GateMode = 'flow' | 'strict' | 'dns'

export function GateArmDialog({ mode, status, sessionId, candidateClients, token, busy, onToken, onArm }: {
  mode: ProxyLabMode
  status: GateStatus | null
  sessionId: string
  candidateClients: string[]
  token: string
  busy: boolean
  onToken: (token: string) => void
  onArm: (clientIps: string[], mode: GateMode, strict?: StrictTuple) => void
}) {
  const [selected, setSelected] = useState<string[]>([])
  const [acknowledged, setAcknowledged] = useState(false)
  const [protocol, setProtocol] = useState<'tcp' | 'udp'>('tcp')
  const [clientPort, setClientPort] = useState('')
  const [remoteIp, setRemoteIp] = useState('')
  const [remotePort, setRemotePort] = useState('443')
  const validSelected = selected.filter((client) => candidateClients.includes(client))
  if (mode !== 'turn-based' && mode !== 'strict' && mode !== 'dns') return null
  if (status?.armed) {
    return (
      <section className="border border-amber-700 bg-amber-950/30 p-3 text-xs text-amber-100">
        <strong className="block text-sm">Gate armed for live traffic</strong>
        <p className="mt-1 font-mono text-amber-200">session {status.sessionId} · {status.clientIps.join(', ') || 'No selected client'} · {status.mode}</p>
        {status.sessionId !== sessionId ? <p className="mt-2 text-rose-300">This gate belongs to another active route. Disarm it before starting a new experiment.</p> : null}
        <p className="mt-2 text-amber-200/75">Playback controls never rewind this control state.</p>
      </section>
    )
  }
  const capabilityReady = Boolean(status?.enabled && status.supported && status.listenerReady && status.rulesReady && status.failOpen)
  const backendMode: GateMode = mode === 'strict' ? 'strict' : mode === 'dns' ? 'dns' : 'flow'
  const parsedClientPort = Number(clientPort)
  const parsedRemotePort = Number(remotePort)
  const strictValid = backendMode !== 'strict' || (
    validSelected.length === 1
    && Number.isInteger(parsedClientPort) && parsedClientPort > 0 && parsedClientPort <= 65_535
    && Number.isInteger(parsedRemotePort) && parsedRemotePort > 0 && parsedRemotePort <= 65_535
    && isIPv4(remoteIp)
  )
  const selectedValid = backendMode === 'strict' ? validSelected.length === 1 : validSelected.length > 0
  const strictTuple: StrictTuple | undefined = backendMode === 'strict' && strictValid ? {
    protocol, clientIp: validSelected[0], clientPort: parsedClientPort,
    remoteIp: remoteIp.trim(), remotePort: parsedRemotePort,
  } : undefined
  return (
    <section className="border border-amber-800 bg-amber-950/30 p-3 text-xs text-amber-100">
      <strong className="block text-sm">Arm real traffic control</strong>
      <p className="mt-1 leading-5 text-amber-200/80">This opt-in lab action changes and delays the selected client’s current network traffic. Kernel and controller failures are configured to accept traffic.</p>
      <label className="mt-3 block text-[10px] font-bold uppercase tracking-wider text-amber-300" htmlFor="gate-token">Operator token</label>
      <input autoComplete="off" className="mt-1 w-full border border-amber-800 bg-slate-950 px-2 py-1.5 font-mono text-slate-100 outline-none focus:border-amber-400" id="gate-token" onChange={(event) => onToken(event.target.value)} placeholder="Kept in memory only" type="password" value={token} />
      <fieldset className="mt-3 space-y-1.5">
        <legend className="text-[10px] font-bold uppercase tracking-wider text-amber-300">Client {backendMode === 'strict' ? '(choose exactly one)' : 'selection'}</legend>
        {candidateClients.length === 0 ? <p className="text-rose-300">No client IPs are visible in this active session.</p> : candidateClients.map((client) => (
          <label className="flex items-center gap-2 font-mono" key={client}>
            <input checked={validSelected.includes(client)} onChange={(event) => setSelected((current) => event.target.checked ? [...current.filter((item) => candidateClients.includes(item) && (backendMode !== 'strict' || item === client)), client] : current.filter((item) => item !== client))} type="checkbox" />
            {client}
          </label>
        ))}
      </fieldset>
      {backendMode === 'strict' ? (
        <fieldset className="mt-3 grid grid-cols-2 gap-2 border border-violet-900 bg-violet-950/20 p-2">
          <legend className="px-1 text-[10px] font-bold uppercase tracking-wider text-violet-300">Exact five-tuple</legend>
          <label className="text-[10px] text-violet-200">Protocol<select className="mt-1 w-full border border-violet-800 bg-slate-950 p-1.5" onChange={(event) => setProtocol(event.target.value as 'tcp' | 'udp')} value={protocol}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
          <label className="text-[10px] text-violet-200">Client port<input className="mt-1 w-full border border-violet-800 bg-slate-950 p-1.5 font-mono" inputMode="numeric" max="65535" min="1" onChange={(event) => setClientPort(event.target.value)} placeholder="e.g. 50324" type="number" value={clientPort} /></label>
          <label className="text-[10px] text-violet-200">Remote IPv4<input className="mt-1 w-full border border-violet-800 bg-slate-950 p-1.5 font-mono" onChange={(event) => setRemoteIp(event.target.value)} placeholder="1.1.1.1" value={remoteIp} /></label>
          <label className="text-[10px] text-violet-200">Remote port<input className="mt-1 w-full border border-violet-800 bg-slate-950 p-1.5 font-mono" inputMode="numeric" max="65535" min="1" onChange={(event) => setRemotePort(event.target.value)} type="number" value={remotePort} /></label>
          <p className="col-span-2 text-violet-200/75">Only this exact tuple, both directions, enters queue 43. Each packet has a {status?.establishedTimeoutMs ?? 500} ms watchdog.</p>
        </fieldset>
      ) : null}
      {backendMode === 'dns' ? <p className="mt-3 border-l-2 border-cyan-500 pl-2 text-cyan-200">Only selected UDP DNS datagrams and new TCP DNS connections to local dnsmasq enter queue 44. DHCP, the dashboard, and forwarded traffic bypass it.</p> : null}
      <div className="mt-3 grid grid-cols-2 gap-2 text-[10px] text-amber-200/75">
        <span>Session <b className="font-mono">{sessionId}</b></span><span>Policy <b>fail open</b></span>
        <span>Pending cap <b>{status?.maxPendingFlows ?? '—'}</b></span><span>Held cap <b>{status?.maxHeldPackets ?? '—'}</b></span>
        <span>Mode <b>{backendMode}</b></span><span>Watchdog <b>{backendMode === 'strict' ? status?.establishedTimeoutMs : backendMode === 'dns' ? status?.dnsTimeoutMs : status?.flowTimeoutMs ?? '—'} ms</b></span>
      </div>
      <label className="mt-3 flex items-start gap-2 leading-5"><input checked={acknowledged} className="mt-1" onChange={(event) => setAcknowledged(event.target.checked)} type="checkbox" />I understand this traffic-changing experiment may cause retries or visible failures on the selected client.</label>
      {!capabilityReady ? <p className="mt-2 text-rose-300">The gateway reports that lab support, the listener, rules, or fail-open policy is unavailable.</p> : null}
      <button className="mt-3 border border-amber-500 px-3 py-1.5 font-semibold hover:bg-amber-900 disabled:cursor-not-allowed disabled:opacity-40" disabled={!capabilityReady || !token || !selectedValid || !strictValid || !acknowledged || busy} onClick={() => onArm(validSelected, backendMode, strictTuple)} type="button">{busy ? 'Arming…' : `Arm ${backendMode === 'strict' ? 'strict flow' : backendMode === 'dns' ? 'DNS gate' : 'flow gate'}`}</button>
    </section>
  )
}

function isIPv4(value: string) {
  const parts = value.trim().split('.')
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}
