import { ArrowLeft, FlaskConical, Play, Square } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'

type Attempt = { id: number; startedAt: number; endedAt?: number; url: string; result: 'running' | 'completed' | 'timeout' | 'failed'; detail?: string }

export function ControlledClientPage() {
  const [url, setUrl] = useState('http://1.1.1.1/')
  const [timeoutMs, setTimeoutMs] = useState(8_000)
  const [count, setCount] = useState(1)
  const [gapMs, setGapMs] = useState(1_000)
  const [attempts, setAttempts] = useState<Attempt[]>([])
  const [running, setRunning] = useState(false)
  const active = useRef<AbortController | null>(null)

  useEffect(() => () => active.current?.abort(), [])

  const run = async () => {
    if (active.current) return
    const runController = new AbortController()
    active.current = runController
    setRunning(true)
    try {
      for (let index = 0; index < count && !runController.signal.aborted; index += 1) {
        const id = wallClockNow() * 100 + index
        const separator = url.includes('?') ? '&' : '?'
        const requestUrl = `${url}${separator}infrareveal_attempt=${id}`
        const startedAt = monotonicNow()
        setAttempts((current) => [{ id, startedAt, url: requestUrl, result: 'running' as const }, ...current].slice(0, 50))
        const attemptController = new AbortController()
        const stopAttempt = () => attemptController.abort(runController.signal.reason)
        runController.signal.addEventListener('abort', stopAttempt, { once: true })
        const timeout = window.setTimeout(() => attemptController.abort(new DOMException('Application timeout', 'TimeoutError')), timeoutMs)
        try {
          await fetch(requestUrl, { cache: 'no-store', mode: 'no-cors', signal: attemptController.signal })
          finish(id, startedAt, 'completed', 'Browser fetch completed (opaque response).')
        } catch (error) {
          const timedOut = error instanceof DOMException && (error.name === 'TimeoutError' || attemptController.signal.reason?.name === 'TimeoutError')
          finish(id, startedAt, timedOut ? 'timeout' : 'failed', error instanceof Error ? error.message : 'Request failed')
        } finally {
          window.clearTimeout(timeout)
          runController.signal.removeEventListener('abort', stopAttempt)
        }
        if (index + 1 < count && !runController.signal.aborted) await abortableDelay(gapMs, runController.signal)
      }
    } finally {
      if (active.current === runController) active.current = null
      setRunning(false)
    }
  }

  const finish = (id: number, startedAt: number, result: Attempt['result'], detail: string) => {
    const endedAt = monotonicNow()
    setAttempts((current) => current.map((attempt) => attempt.id === id ? { ...attempt, startedAt, endedAt, result, detail } : attempt))
  }

  return (
    <main className="min-h-screen bg-slate-950 px-5 py-8 text-slate-100">
      <div className="mx-auto max-w-4xl">
        <Link className="inline-flex items-center gap-2 text-sm text-cyan-300" to="/"><ArrowLeft size={15} /> Experiments</Link>
        <header className="mt-6 flex items-start gap-4"><div className="grid h-11 w-11 place-items-center border border-violet-700 bg-violet-950 text-violet-300"><FlaskConical size={20} /></div><div><p className="text-xs font-bold uppercase tracking-[0.18em] text-violet-300">Controlled client</p><h1 className="mt-1 text-3xl font-semibold">Network timeout probe</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Open this page on the selected Wi-Fi client. It records application-visible timing while Proxy Lab holds, releases, or rejects the corresponding traffic. Browser-internal retries are not exposed; alternate attempts appear as separate gateway flows.</p></div></header>
        <section className="mt-7 grid gap-4 border border-slate-800 bg-slate-900/70 p-5 md:grid-cols-2">
          <label className="md:col-span-2 text-xs text-slate-400">Target URL<input className="mt-1 w-full border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-slate-100" onChange={(event) => setUrl(event.target.value)} value={url} /></label>
          <NumberField label="Application timeout (ms)" max={60_000} min={100} onChange={setTimeoutMs} value={timeoutMs} />
          <NumberField label="Attempts" max={20} min={1} onChange={setCount} value={count} />
          <NumberField label="Gap between attempts (ms)" max={30_000} min={0} onChange={setGapMs} value={gapMs} />
          <div className="flex items-end gap-2"><button className="inline-flex items-center gap-2 border border-emerald-700 px-4 py-2 text-sm text-emerald-300 disabled:opacity-40" disabled={running || !/^https?:\/\//.test(url)} onClick={() => void run()} type="button"><Play size={15} /> Run probe</button><button className="inline-flex items-center gap-2 border border-rose-700 px-4 py-2 text-sm text-rose-300 disabled:opacity-40" disabled={!running} onClick={() => active.current?.abort()} type="button"><Square size={14} /> Stop</button></div>
          <p className="md:col-span-2 border-l-2 border-amber-500 pl-3 text-xs leading-5 text-amber-200">For a TCP handshake demonstration use an HTTP target by IP and disable QUIC in the controlled browser. For DNS retry behaviour use a hostname. Browsers may apply their own resolver, Happy Eyeballs, connection pooling, and timeout policies.</p>
        </section>
        <section className="mt-5 border border-slate-800 bg-slate-900/70"><h2 className="border-b border-slate-800 px-4 py-3 text-sm font-semibold">Application-visible attempts</h2>{attempts.length === 0 ? <p className="p-5 text-sm text-slate-500">No requests yet.</p> : <div className="divide-y divide-slate-800">{attempts.map((attempt) => <article className="grid gap-1 px-4 py-3 text-xs md:grid-cols-[120px_120px_1fr]" key={attempt.id}><b className={attempt.result === 'completed' ? 'text-emerald-300' : attempt.result === 'running' ? 'text-cyan-300' : 'text-rose-300'}>{attempt.result.toUpperCase()}</b><span className="font-mono text-slate-300">{attempt.endedAt === undefined ? 'running…' : `${Math.round(attempt.endedAt - attempt.startedAt)} ms`}</span><span className="truncate font-mono text-slate-500" title={attempt.url}>{attempt.url}</span>{attempt.detail ? <span className="md:col-start-3 text-slate-400">{attempt.detail}</span> : null}</article>)}</div>}</section>
      </div>
    </main>
  )
}

function NumberField({ label, value, min, max, onChange }: { label: string; value: number; min: number; max: number; onChange: (value: number) => void }) {
  return <label className="text-xs text-slate-400">{label}<input className="mt-1 w-full border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-slate-100" max={max} min={min} onChange={(event) => onChange(Math.min(max, Math.max(min, Number(event.target.value) || min)))} type="number" value={value} /></label>
}

function abortableDelay(milliseconds: number, signal: AbortSignal) {
  return new Promise<void>((resolve) => {
    if (signal.aborted || milliseconds <= 0) {
      resolve()
      return
    }
    const timeout = window.setTimeout(done, milliseconds)
    signal.addEventListener('abort', done, { once: true })
    function done() {
      window.clearTimeout(timeout)
      signal.removeEventListener('abort', done)
      resolve()
    }
  })
}
function wallClockNow() { return Date.now() }
function monotonicNow() { return performance.now() }
