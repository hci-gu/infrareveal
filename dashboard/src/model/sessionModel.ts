import type { DNSQuery, Destination, Flow, FlowAttribution, GatewayData, Route } from '../data/types'

export const FPS = 30
export const COMPOSITION_WIDTH = 1440
export const COMPOSITION_HEIGHT = 810

const MIN_SESSION_SECONDS = 60
const MIN_CLIP_SECONDS = 1.5

export type Confidence = FlowAttribution['confidence'] | 'pending'

export type ServiceGroup = {
  id: string
  label: string
  sourceSignal: string
  confidence: Confidence
  destinationIPs: string[]
  hostnames: string[]
  clientIPs: string[]
  providerLabel: string
  totalBytes: number
  packetCount: number
  flowCount: number
  firstSeenMs: number
  lastSeenMs: number
  routeCompleteCount: number
  routeCount: number
}

export type TimelineClip = {
  id: string
  flowId: string
  serviceGroupId: string
  serviceGroupLabel: string
  label: string
  clientIP: string
  destinationIP: string
  destinationPort: number
  protocol: string
  state: string
  startMs: number
  endMs: number
  startFrame: number
  durationFrames: number
  bytes: number
  packets: number
  confidence: Confidence
  explanation: string
  sourceSignal: string
}

export type TimelineLane = {
  id: string
  label: string
  serviceGroupId: string
  totalBytes: number
  clips: TimelineClip[]
}

export type SessionComposition = {
  fps: number
  width: number
  height: number
  sessionStartMs: number
  sessionEndMs: number
  durationInFrames: number
  clips: TimelineClip[]
  lanes: TimelineLane[]
  serviceGroups: ServiceGroup[]
  attributionsByFlow: Map<string, FlowAttribution>
  destinationsByIP: Map<string, Destination>
  routesByDestination: Map<string, Route>
  totals: {
    flowCount: number
    attributedCount: number
    routeCount: number
    byteCount: number
    packetCount: number
    trafficCountersAvailable: boolean
  }
}

export function buildSessionComposition(data: GatewayData): SessionComposition {
  const attributionsByFlow = new Map(data.attributions.map((item) => [item.flow, item]))
  const destinationsByIP = new Map(data.destinations.map((item) => [item.ip, item]))
  const hostnamesByIP = buildHostnamesByIP(data.dnsQueries)
  const routesByDestination = new Map(
    data.routes.map((route) => [routeKey(route.destination_ip, route.destination_port), route]),
  )

  const timeBounds = data.flows.reduce(
    (bounds, flow) => {
      const start = parseTime(flow.start || flow.created || flow.updated, Date.now())
      const end = parseTime(flow.last_seen || flow.updated || flow.created, start)
      return {
        first: Math.min(bounds.first, start),
        last: Math.max(bounds.last, Math.max(end, start + MIN_CLIP_SECONDS * 1000)),
      }
    },
    { first: Number.POSITIVE_INFINITY, last: Number.NEGATIVE_INFINITY },
  )

  const now = Date.now()
  const sessionStartMs = Number.isFinite(timeBounds.first) ? timeBounds.first : now
  const minimumEnd = sessionStartMs + MIN_SESSION_SECONDS * 1000
  const sessionEndMs = Math.max(Number.isFinite(timeBounds.last) ? timeBounds.last : minimumEnd, minimumEnd)
  const durationInFrames = Math.max(
    1,
    Math.ceil(((sessionEndMs - sessionStartMs) / 1000) * FPS),
  )

  const groups = new Map<string, ServiceGroup>()
  const clips = data.flows
    .map((flow) =>
      buildClip({
        flow,
        sessionStartMs,
        attributionsByFlow,
        destinationsByIP,
        hostnamesByIP,
        routesByDestination,
      }),
    )
    .sort((a, b) => a.startFrame - b.startFrame || b.bytes - a.bytes)

  for (const clip of clips) {
    const flow = data.flows.find((item) => item.id === clip.flowId)
    const destination = destinationsByIP.get(clip.destinationIP)
    const route = routesByDestination.get(routeKey(clip.destinationIP, clip.destinationPort))
    const existing = groups.get(clip.serviceGroupId)

    if (existing) {
      existing.totalBytes += clip.bytes
      existing.packetCount += clip.packets
      existing.flowCount += 1
      existing.firstSeenMs = Math.min(existing.firstSeenMs, clip.startMs)
      existing.lastSeenMs = Math.max(existing.lastSeenMs, clip.endMs)
      existing.routeCount += route ? 1 : 0
      existing.routeCompleteCount += route?.complete ? 1 : 0
      if (!existing.destinationIPs.includes(clip.destinationIP)) {
        existing.destinationIPs.push(clip.destinationIP)
      }
      if (!existing.clientIPs.includes(clip.clientIP)) {
        existing.clientIPs.push(clip.clientIP)
      }
      if (isHostnameLabel(clip.label) && !existing.hostnames.includes(clip.label)) {
        existing.hostnames.push(clip.label)
      }
      existing.confidence = strongerConfidence(existing.confidence, clip.confidence)
      continue
    }

    groups.set(clip.serviceGroupId, {
      id: clip.serviceGroupId,
      label: clip.serviceGroupLabel,
      sourceSignal: clip.sourceSignal,
      confidence: clip.confidence,
      destinationIPs: [clip.destinationIP],
      hostnames: isHostnameLabel(clip.label) ? [clip.label] : [],
      clientIPs: [clip.clientIP],
      providerLabel: destination?.provider_label || destination?.organization || '',
      totalBytes: clip.bytes,
      packetCount: clip.packets,
      flowCount: flow ? 1 : 0,
      firstSeenMs: clip.startMs,
      lastSeenMs: clip.endMs,
      routeCompleteCount: route?.complete ? 1 : 0,
      routeCount: route ? 1 : 0,
    })
  }

  const lanes = Array.from(groups.values())
    .sort(compareGroups)
    .map((group) => ({
      id: `lane:${group.id}`,
      label: group.label,
      serviceGroupId: group.id,
      totalBytes: group.totalBytes,
      clips: clips.filter((clip) => clip.serviceGroupId === group.id),
    }))

  return {
    fps: FPS,
    width: COMPOSITION_WIDTH,
    height: COMPOSITION_HEIGHT,
    sessionStartMs,
    sessionEndMs,
    durationInFrames,
    clips,
    lanes,
    serviceGroups: Array.from(groups.values()).sort(compareGroups),
    attributionsByFlow,
    destinationsByIP,
    routesByDestination,
    totals: {
      flowCount: data.flows.length,
      attributedCount: attributionsByFlow.size,
      routeCount: data.routes.length,
      byteCount: data.flows.reduce((total, flow) => total + flow.bytes_in + flow.bytes_out, 0),
      packetCount: data.flows.reduce((total, flow) => total + flow.packets_in + flow.packets_out, 0),
      trafficCountersAvailable: data.flows.some(
        (flow) => flow.bytes_in > 0 || flow.bytes_out > 0 || flow.packets_in > 0 || flow.packets_out > 0,
      ),
    },
  }
}

function buildClip({
  flow,
  sessionStartMs,
  attributionsByFlow,
  destinationsByIP,
  hostnamesByIP,
}: {
  flow: Flow
  sessionStartMs: number
  attributionsByFlow: Map<string, FlowAttribution>
  destinationsByIP: Map<string, Destination>
  hostnamesByIP: Map<string, string>
  routesByDestination: Map<string, Route>
}): TimelineClip {
  const attribution = attributionsByFlow.get(flow.id)
  const destination = destinationsByIP.get(flow.destination_ip)
  const identity = serviceIdentity(flow, attribution, destination, hostnamesByIP.get(flow.destination_ip))
  const startMs = parseTime(flow.start || flow.created || flow.updated, sessionStartMs)
  const rawEndMs = parseTime(flow.last_seen || flow.updated || flow.created, startMs)
  const endMs = Math.max(rawEndMs, startMs + MIN_CLIP_SECONDS * 1000)
  const startFrame = Math.max(0, msToFrame(startMs - sessionStartMs))
  const durationFrames = Math.max(1, msToFrame(endMs - startMs))
  const bytes = Math.max(0, flow.bytes_in + flow.bytes_out)
  const packets = Math.max(0, flow.packets_in + flow.packets_out)

  return {
    id: `clip:${flow.id}`,
    flowId: flow.id,
    serviceGroupId: identity.id,
    serviceGroupLabel: identity.groupLabel,
    label: identity.requestLabel,
    clientIP: flow.client_ip,
    destinationIP: flow.destination_ip,
    destinationPort: flow.destination_port,
    protocol: flow.protocol,
    state: flow.state,
    startMs,
    endMs,
    startFrame,
    durationFrames,
    bytes,
    packets,
    confidence: attribution?.confidence ?? 'pending',
    explanation: attribution?.explanation || identity.explanation,
    sourceSignal: identity.sourceSignal,
  }
}

function serviceIdentity(
  flow: Flow,
  attribution?: FlowAttribution,
  destination?: Destination,
  dnsHostname?: string,
) {
  if (attribution?.candidate_hostname) {
    const activity = activityFromHostname(attribution.candidate_hostname)
    return {
      id: normalizeGroupId(`activity:${activity.key}`),
      groupLabel: activity.label,
      requestLabel: attribution.candidate_hostname,
      sourceSignal: attribution.source_signal || 'dns-attribution',
      explanation:
        attribution.explanation ||
        `Matched to ${attribution.candidate_hostname} by the flow attribution correlator, then grouped into ${activity.label}.`,
    }
  }

  if (dnsHostname) {
    const activity = activityFromHostname(dnsHostname)
    return {
      id: normalizeGroupId(`activity:${activity.key}`),
      groupLabel: activity.label,
      requestLabel: dnsHostname,
      sourceSignal: 'dns-answer',
      explanation: `Grouped into ${activity.label} by a DNS answer that resolved ${dnsHostname} to this destination IP during the session.`,
    }
  }

  if (destination?.reverse_dns) {
    const activity = activityFromHostname(destination.reverse_dns)
    return {
      id: normalizeGroupId(`activity:${activity.key}`),
      groupLabel: activity.label,
      requestLabel: destination.reverse_dns,
      sourceSignal: 'reverse-dns',
      explanation: `Grouped into ${activity.label} by reverse DNS for the destination IP.`,
    }
  }

  if (destination?.provider_label) {
    const activity = activityFromProvider(destination.provider_label)
    return {
      id: normalizeGroupId(`activity:${activity.key}`),
      groupLabel: activity.label,
      requestLabel: destination.provider_label,
      sourceSignal: 'destination-provider',
      explanation: `Grouped into ${activity.label} by destination provider because no hostname was observed.`,
    }
  }

  const fallback = unresolvedActivity(flow)
  return {
    id: normalizeGroupId(`unresolved:${fallback.key}`),
    groupLabel: fallback.label,
    requestLabel: fallback.label,
    sourceSignal: 'socket',
    explanation: 'No hostname was observed for this flow, so it is grouped by protocol instead of using the IP as the visible label.',
  }
}

function activityFromHostname(hostname: string) {
  const normalized = normalizeHostname(hostname)
  const known = knownActivity(normalized)
  if (known) {
    return known
  }

  const domain = registrableDomain(normalized)
  return { key: `domain:${domain}`, label: domain }
}

function activityFromProvider(provider: string) {
  const normalized = provider.trim().toLowerCase()
  const known = knownActivity(normalized)
  if (known) {
    return known
  }

  return {
    key: `provider:${normalized || 'unknown-provider'}`,
    label: provider.trim() || 'Unknown provider',
  }
}

function knownActivity(value: string) {
  const normalized = value.toLowerCase()
  const knownFamilies = [
    {
      key: 'svt.se',
      label: 'svt.se',
      matches: ['svt.se', 'svtstatic.se', 'svtplay.se'],
    },
    {
      key: 'spotify',
      label: 'Spotify',
      matches: ['spotify.com', 'spotifycdn.com', 'spotifycdn.net', 'scdn.co', 'pscdn.co', 'spotify'],
    },
    {
      key: 'youtube',
      label: 'YouTube',
      matches: ['youtube.com', 'youtu.be', 'ytimg.com', 'googlevideo.com', 'youtube'],
    },
    {
      key: 'netflix',
      label: 'Netflix',
      matches: ['netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflxext.com', 'netflix'],
    },
  ]

  return knownFamilies.find((family) =>
    family.matches.some((match) => normalized === match || normalized.endsWith(`.${match}`) || normalized.includes(match)),
  )
}

function unresolvedActivity(flow: Flow) {
  const protocol = flow.protocol.toUpperCase()
  const port = flow.destination_port

  if (port === 443) {
    return { key: 'https', label: 'Unresolved HTTPS' }
  }
  if (port === 80) {
    return { key: 'http', label: 'Unresolved HTTP' }
  }
  if (port === 53) {
    return { key: 'dns', label: 'DNS lookups' }
  }
  if (port === 123) {
    return { key: 'ntp', label: 'Time sync' }
  }

  return { key: `${flow.protocol}:${port}`, label: `Unresolved ${protocol}/${port}` }
}

function normalizeHostname(hostname: string) {
  return hostname.trim().toLowerCase().replace(/\.$/, '')
}

function registrableDomain(hostname: string) {
  const labels = normalizeHostname(hostname).split('.').filter(Boolean)
  if (labels.length <= 2) {
    return labels.join('.') || hostname
  }

  const multiPartSuffixes = new Set(['co.uk', 'com.au', 'com.br', 'co.jp', 'co.nz'])
  const suffix = labels.slice(-2).join('.')
  if (labels.length >= 3 && multiPartSuffixes.has(suffix)) {
    return labels.slice(-3).join('.')
  }

  return labels.slice(-2).join('.')
}

function isHostnameLabel(label: string) {
  return /[a-z]/i.test(label) && label.includes('.') && !isLikelyIPAddress(label)
}

function buildHostnamesByIP(dnsQueries: DNSQuery[]) {
  const hostnames = new Map<string, string>()
  const sortedQueries = dnsQueries
    .filter((query) => query.query_name && query.answers?.length)
    .sort((left, right) => new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime())

  for (const query of sortedQueries) {
    for (const answer of query.answers ?? []) {
      if (isLikelyIPAddress(answer)) {
        hostnames.set(answer, query.query_name)
      }
    }
  }

  return hostnames
}

function isLikelyIPAddress(value: string) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(':')
}

function normalizeGroupId(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9:._-]+/g, '-')
}

function parseTime(value: string, fallback: number) {
  if (!value) {
    return fallback
  }
  const time = new Date(value).getTime()
  return Number.isFinite(time) ? time : fallback
}

function msToFrame(ms: number) {
  return Math.round((ms / 1000) * FPS)
}

function routeKey(destinationIP: string, destinationPort: number) {
  return `${destinationIP}:${destinationPort}`
}

function compareGroups(left: ServiceGroup, right: ServiceGroup) {
  return (
    right.totalBytes - left.totalBytes ||
    right.flowCount - left.flowCount ||
    left.label.localeCompare(right.label)
  )
}

function strongerConfidence(left: Confidence, right: Confidence): Confidence {
  const rank: Record<Confidence, number> = {
    pending: 0,
    hidden: 1,
    low: 2,
    medium: 3,
    high: 4,
  }
  return rank[right] > rank[left] ? right : left
}
