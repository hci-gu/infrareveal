import Pocketbase from 'pocketbase'

const defaultUrl =
  typeof window === 'undefined'
    ? 'http://localhost:8090'
    : `${window.location.protocol}//${window.location.hostname}:8090`

const pb = new Pocketbase(import.meta.env.VITE_POCKETBASE_URL ?? defaultUrl)

export type Flow = {
  id: string
  created: string
  updated: string
  client_ip: string
  destination_ip: string
  source_port: number
  destination_port: number
  protocol: string
  state: string
  start: string
  last_seen: string
  bytes_out: number
  bytes_in: number
  packets_out: number
  packets_in: number
}

export type DNSQuery = {
  id: string
  created: string
  client_ip: string
  query_name: string
  query_type: string
  answers: string[] | null
  timestamp: string
}

export type FlowAttribution = {
  id: string
  flow: string
  candidate_hostname: string
  source_signal: string
  confidence: 'high' | 'medium' | 'low' | 'hidden'
  explanation: string
  dns_query: string
  observed_at: string
}

export type Destination = {
  id: string
  ip: string
  reverse_dns: string
  asn: number
  organization: string
  provider_label: string
  city: string
  country: string
  lat: number
  lon: number
  last_seen: string
}

export type Route = {
  id: string
  destination: string
  destination_ip: string
  destination_port: number
  protocol: string
  method: string
  hops: Array<{
    ttl: number
    address: string
    missing: boolean
    timings: number[]
    city?: string
    country?: string
  }> | null
  complete: boolean
  error: string
  completed_at: string
}

export type GatewayData = {
  flows: Flow[]
  dnsQueries: DNSQuery[]
  attributions: FlowAttribution[]
  destinations: Destination[]
  routes: Route[]
}

export async function getGatewayData(): Promise<GatewayData> {
  const [flows, dnsQueries, attributions, destinations, routes] = await Promise.all([
    pb.collection('flows').getFullList<Flow>({
      sort: '-last_seen',
      requestKey: null,
    }),
    pb.collection('dns_queries').getFullList<DNSQuery>({
      sort: '-timestamp',
      requestKey: null,
    }),
    pb.collection('flow_attributions').getFullList<FlowAttribution>({
      sort: '-observed_at',
      requestKey: null,
    }),
    pb.collection('destinations').getFullList<Destination>({
      sort: '-last_seen',
      requestKey: null,
    }),
    pb.collection('routes').getFullList<Route>({
      sort: '-completed_at',
      requestKey: null,
    }),
  ])

  return {
    flows: flows.slice(0, 100),
    dnsQueries: dnsQueries.slice(0, 100),
    attributions: attributions.slice(0, 100),
    destinations: destinations.slice(0, 100),
    routes: routes.slice(0, 100),
  }
}
