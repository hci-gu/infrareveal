export type Flow = {
  id: string
  created: string
  updated: string
  session: string
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
  session: string
  client_ip: string
  query_name: string
  query_type: string
  answers: string[] | null
  aliases: string[] | null
  timestamp: string
}

export type FlowAttribution = {
  id: string
  session: string
  flow: string
  candidate_hostname: string
  source_signal: string
  confidence: 'high' | 'medium' | 'low' | 'hidden'
  explanation: string
  dns_query: string
  observed_at: string
}

export type ActivityEpisode = {
  id: string
  session: string
  episode_key: string
  client_ip: string
  site_key: string
  label: string
  anchor_hostname: string
  start: string
  last_seen: string
  confidence: 'high' | 'medium' | 'low'
  explanation: string
}

export type FlowAssociation = {
  id: string
  session: string
  flow: string
  episode: string
  parent_site_key: string
  parent_label: string
  relationship: 'first_party' | 'cname_related' | 'temporally_associated'
  confidence: 'high' | 'medium' | 'low'
  score: number
  explanation: string
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
  session: string
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

export type Session = {
  id: string
  created: string
  updated: string
  name: string
  active: boolean
}

export type GatewayData = {
  sessions: Session[]
  selectedSession: Session | null
  flows: Flow[]
  dnsQueries: DNSQuery[]
  attributions: FlowAttribution[]
  activityEpisodes: ActivityEpisode[]
  flowAssociations: FlowAssociation[]
  destinations: Destination[]
  routes: Route[]
}

export type ConnectionState = 'loading' | 'live' | 'polling' | 'error'
