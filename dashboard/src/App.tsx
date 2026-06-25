import { Activity, Database, Globe2, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { getGatewayData } from './pocketbase'
import type { DNSQuery, Flow, GatewayData } from './pocketbase'

type LoadState =
  | { status: 'loading'; data: GatewayData | null; error: null }
  | { status: 'ready'; data: GatewayData; error: null }
  | { status: 'error'; data: GatewayData | null; error: string }

const emptyData: GatewayData = { flows: [], dnsQueries: [] }

function App() {
  const [state, setState] = useState<LoadState>({
    status: 'loading',
    data: null,
    error: null,
  })

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const data = await getGatewayData()
        if (!cancelled) {
          setState({ status: 'ready', data, error: null })
        }
      } catch (error) {
        if (!cancelled) {
          setState((previous) => ({
            status: 'error',
            data: previous.data,
            error: error instanceof Error ? error.message : 'Failed to load gateway data',
          }))
        }
      }
    }

    load()
    const timer = window.setInterval(load, 2500)

    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [])

  const data = state.data ?? emptyData
  const totals = useMemo(() => summarize(data), [data])

  return (
    <main className="min-h-screen bg-slate-50 text-slate-950">
      <section className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-5 py-6 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="text-sm font-semibold uppercase text-teal-700">InfraReveal Gateway</p>
            <h1 className="mt-1 text-3xl font-semibold tracking-normal text-slate-950">
              Live network observations
            </h1>
          </div>
          <div className="flex items-center gap-2 text-sm text-slate-600">
            <span className={state.status === 'error' ? 'text-red-700' : 'text-emerald-700'}>
              {state.status === 'loading'
                ? 'Loading'
                : state.status === 'error'
                  ? 'Connection issue'
                  : 'Updating live'}
            </span>
            <span className="text-slate-300">/</span>
            <span>{new Date().toLocaleTimeString()}</span>
          </div>
        </div>
      </section>

      <section className="mx-auto grid w-full max-w-7xl grid-cols-1 gap-4 px-5 py-5 md:grid-cols-4">
        <Metric icon={<Activity size={18} />} label="Flows" value={totals.flowCount} />
        <Metric icon={<Search size={18} />} label="DNS Queries" value={totals.dnsCount} />
        <Metric icon={<Database size={18} />} label="Observed Bytes" value={formatBytes(totals.bytes)} />
        <Metric icon={<Globe2 size={18} />} label="Destinations" value={totals.destinations} />
      </section>

      {state.status === 'error' && (
        <section className="mx-auto w-full max-w-7xl px-5">
          <div className="border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            {state.error}
          </div>
        </section>
      )}

      <section className="mx-auto grid w-full max-w-7xl grid-cols-1 gap-5 px-5 pb-8 xl:grid-cols-[minmax(0,1.5fr)_minmax(360px,0.9fr)]">
        <FlowTable flows={data.flows} />
        <DNSTable dnsQueries={data.dnsQueries} />
      </section>
    </main>
  )
}

function Metric({
  icon,
  label,
  value,
}: {
  icon: ReactNode
  label: string
  value: string | number
}) {
  return (
    <div className="border border-slate-200 bg-white px-4 py-3">
      <div className="flex items-center gap-2 text-sm font-medium text-slate-600">
        {icon}
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold text-slate-950">{value}</div>
    </div>
  )
}

function FlowTable({ flows }: { flows: Flow[] }) {
  return (
    <div className="border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-4 py-3">
        <h2 className="text-lg font-semibold text-slate-950">Flows</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[820px] text-left text-sm">
          <thead className="bg-slate-100 text-xs uppercase text-slate-600">
            <tr>
              <th className="px-4 py-3 font-semibold">Client</th>
              <th className="px-4 py-3 font-semibold">Destination</th>
              <th className="px-4 py-3 font-semibold">Protocol</th>
              <th className="px-4 py-3 font-semibold">State</th>
              <th className="px-4 py-3 text-right font-semibold">Bytes</th>
              <th className="px-4 py-3 font-semibold">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {flows.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-slate-500" colSpan={6}>
                  No flow observations yet.
                </td>
              </tr>
            ) : (
              flows.map((flow) => (
                <tr className="border-t border-slate-100" key={flow.id}>
                  <td className="px-4 py-3 font-mono text-xs">{flow.client_ip}</td>
                  <td className="px-4 py-3 font-mono text-xs">
                    {flow.destination_ip}:{flow.destination_port}
                  </td>
                  <td className="px-4 py-3 uppercase">{flow.protocol}</td>
                  <td className="px-4 py-3">{flow.state || 'observed'}</td>
                  <td className="px-4 py-3 text-right">{formatBytes(flow.bytes_in + flow.bytes_out)}</td>
                  <td className="px-4 py-3">{formatTime(flow.last_seen)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function DNSTable({ dnsQueries }: { dnsQueries: DNSQuery[] }) {
  return (
    <div className="border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-4 py-3">
        <h2 className="text-lg font-semibold text-slate-950">DNS</h2>
      </div>
      <div className="divide-y divide-slate-100">
        {dnsQueries.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-slate-500">No DNS observations yet.</div>
        ) : (
          dnsQueries.map((query) => (
            <div className="px-4 py-3" key={query.id}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate font-medium text-slate-950">{query.query_name}</p>
                  <p className="mt-1 font-mono text-xs text-slate-500">{query.client_ip}</p>
                </div>
                <span className="shrink-0 text-xs uppercase text-slate-500">{query.query_type}</span>
              </div>
              <p className="mt-2 truncate font-mono text-xs text-slate-600">
                {query.answers?.length ? query.answers.join(', ') : 'No answer recorded yet'}
              </p>
              <p className="mt-1 text-xs text-slate-500">{formatTime(query.timestamp)}</p>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

function summarize(data: GatewayData) {
  const destinations = new Set(data.flows.map((flow) => flow.destination_ip))
  return {
    flowCount: data.flows.length,
    dnsCount: data.dnsQueries.length,
    bytes: data.flows.reduce((total, flow) => total + flow.bytes_in + flow.bytes_out, 0),
    destinations: destinations.size,
  }
}

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return '0 B'
  }
  const units = ['B', 'KB', 'MB', 'GB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`
}

function formatTime(value: string) {
  if (!value) {
    return 'n/a'
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return 'n/a'
  }
  return date.toLocaleTimeString()
}

export default App
