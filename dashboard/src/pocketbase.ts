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

export type GatewayData = {
  flows: Flow[]
  dnsQueries: DNSQuery[]
}

export async function getGatewayData(): Promise<GatewayData> {
  const [flows, dnsQueries] = await Promise.all([
    pb.collection('flows').getFullList<Flow>({
      sort: '-last_seen',
      requestKey: null,
    }),
    pb.collection('dns_queries').getFullList<DNSQuery>({
      sort: '-timestamp',
      requestKey: null,
    }),
  ])

  return {
    flows: flows.slice(0, 100),
    dnsQueries: dnsQueries.slice(0, 100),
  }
}
