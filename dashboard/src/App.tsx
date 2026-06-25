import { Activity, Database, Globe2, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { getGatewayData } from './pocketbase'
import type { Destination, DNSQuery, Flow, FlowAttribution, GatewayData, Route } from './pocketbase'

type LoadState =
  | { status: 'loading'; data: GatewayData | null; error: null }
  | { status: 'ready'; data: GatewayData; error: null }
  | { status: 'error'; data: GatewayData | null; error: string }

const emptyData: GatewayData = {
  flows: [],
  dnsQueries: [],
  attributions: [],
  destinations: [],
  routes: [],
}

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
  const attributionsByFlow = useMemo(() => {
    return new Map(data.attributions.map((attribution) => [attribution.flow, attribution]))
  }, [data.attributions])
  const destinationsByIP = useMemo(() => {
    return new Map(data.destinations.map((destination) => [destination.ip, destination]))
  }, [data.destinations])
  const routesByDestination = useMemo(() => {
    const routes = new Map<string, Route>()
    for (const route of data.routes) {
      routes.set(routeKey(route.destination_ip, route.destination_port), route)
    }
    return routes
  }, [data.routes])

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
        <Metric icon={<Search size={18} />} label="Attributed" value={totals.attributedCount} />
        <Metric icon={<Globe2 size={18} />} label="Routes" value={totals.routeCount} />
        <Metric icon={<Database size={18} />} label="Observed Bytes" value={formatBytes(totals.bytes)} />
      </section>

      {state.status === 'error' && (
        <section className="mx-auto w-full max-w-7xl px-5">
          <div className="border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
            {state.error}
          </div>
        </section>
      )}

      <section className="mx-auto grid w-full max-w-7xl grid-cols-1 gap-5 px-5 pb-8 xl:grid-cols-[minmax(0,1.5fr)_minmax(360px,0.9fr)]">
        <FlowTable
          flows={data.flows}
          attributionsByFlow={attributionsByFlow}
          destinationsByIP={destinationsByIP}
          routesByDestination={routesByDestination}
        />
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

function FlowTable({
  flows,
  attributionsByFlow,
  destinationsByIP,
  routesByDestination,
}: {
  flows: Flow[]
  attributionsByFlow: Map<string, FlowAttribution>
  destinationsByIP: Map<string, Destination>
  routesByDestination: Map<string, Route>
}) {
  return (
    <div className="border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-4 py-3">
        <h2 className="text-lg font-semibold text-slate-950">Flows</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1180px] text-left text-sm">
          <thead className="bg-slate-100 text-xs uppercase text-slate-600">
            <tr>
              <th className="px-4 py-3 font-semibold">Client</th>
              <th className="px-4 py-3 font-semibold">Attribution</th>
              <th className="px-4 py-3 font-semibold">Destination</th>
              <th className="px-4 py-3 font-semibold">Context</th>
              <th className="px-4 py-3 font-semibold">Route</th>
              <th className="px-4 py-3 font-semibold">Confidence</th>
              <th className="px-4 py-3 font-semibold">Protocol</th>
              <th className="px-4 py-3 text-right font-semibold">Bytes</th>
              <th className="px-4 py-3 font-semibold">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {flows.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-slate-500" colSpan={9}>
                  No flow observations yet.
                </td>
              </tr>
            ) : (
              flows.map((flow) => {
                const attribution = attributionsByFlow.get(flow.id)
                const destination = destinationsByIP.get(flow.destination_ip)
                const route = routesByDestination.get(routeKey(flow.destination_ip, flow.destination_port))

                return (
                  <tr className="border-t border-slate-100" key={flow.id}>
                    <td className="px-4 py-3 font-mono text-xs">{flow.client_ip}</td>
                    <td className="max-w-[260px] px-4 py-3">
                      <p className="truncate font-medium text-slate-950">
                        {attribution?.candidate_hostname || flow.destination_ip}
                      </p>
                      <p className="mt-1 line-clamp-2 text-xs text-slate-500">
                        {attribution?.explanation || 'Attribution pending.'}
                      </p>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">
                      {flow.destination_ip}:{flow.destination_port}
                    </td>
                    <td className="max-w-[220px] px-4 py-3">
                      <p className="truncate text-sm text-slate-800">
                        {destination?.provider_label || destination?.reverse_dns || 'Pending'}
                      </p>
                      <p className="mt-1 truncate text-xs text-slate-500">
                        {formatLocation(destination)}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      <RouteSummary route={route} />
                    </td>
                    <td className="px-4 py-3">
                      <ConfidenceBadge confidence={attribution?.confidence ?? 'pending'} />
                    </td>
                    <td className="px-4 py-3 uppercase">
                      {flow.protocol}
                      {flow.state ? <span className="ml-2 text-xs normal-case text-slate-500">{flow.state}</span> : null}
                    </td>
                    <td className="px-4 py-3 text-right">{formatBytes(flow.bytes_in + flow.bytes_out)}</td>
                    <td className="px-4 py-3">{formatTime(flow.last_seen)}</td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function RouteSummary({ route }: { route?: Route }) {
  if (!route) {
    return <span className="text-xs text-slate-500">Pending</span>
  }

  const hopCount = route.hops?.filter((hop) => !hop.missing).length ?? 0
  return (
    <div>
      <p className={route.complete ? 'text-sm font-medium text-emerald-800' : 'text-sm font-medium text-amber-800'}>
        {route.complete ? 'Complete' : 'Approximate'}
      </p>
      <p className="mt-1 text-xs text-slate-500">
        {route.method}, {hopCount} hops
      </p>
    </div>
  )
}

function ConfidenceBadge({ confidence }: { confidence: FlowAttribution['confidence'] | 'pending' }) {
  const styles: Record<typeof confidence, string> = {
    high: 'bg-emerald-100 text-emerald-800',
    medium: 'bg-amber-100 text-amber-800',
    low: 'bg-slate-200 text-slate-700',
    hidden: 'bg-red-100 text-red-800',
    pending: 'bg-slate-100 text-slate-500',
  }

  return (
    <span className={`inline-flex min-w-20 justify-center px-2 py-1 text-xs font-semibold uppercase ${styles[confidence]}`}>
      {confidence}
    </span>
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
  const attributionByFlow = new Map(data.attributions.map((attribution) => [attribution.flow, attribution]))

  return {
    flowCount: data.flows.length,
    dnsCount: data.dnsQueries.length,
    attributedCount: attributionByFlow.size,
    routeCount: data.routes.length,
    bytes: data.flows.reduce((total, flow) => total + flow.bytes_in + flow.bytes_out, 0),
  }
}

function formatLocation(destination?: Destination) {
  if (!destination) {
    return 'Destination context pending'
  }
  const parts = [destination.city, destination.country].filter(Boolean)
  return parts.length ? parts.join(', ') : 'No GeoIP location'
}

function routeKey(destinationIP: string, destinationPort: number) {
  return `${destinationIP}:${destinationPort}`
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
