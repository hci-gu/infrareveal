import type { DNSQuery, Destination, Flow, FlowActivityChunk, FlowAssociation, FlowAttribution, GatewayData, Route } from '../data/types'

export const FPS = 30
export const COMPOSITION_WIDTH = 1440
export const COMPOSITION_HEIGHT = 810

const MIN_SESSION_SECONDS = 60
const MIN_CLIP_SECONDS = 1.5
const DNS_ATTRIBUTION_WINDOW_MS = 5 * 60 * 1000
const DNS_FUTURE_TOLERANCE_MS = 10 * 1000
const DEFAULT_GATEWAY_IP = '10.0.0.1'

type DNSHostnameCandidate = {
  hostname: string
  clientIP: string
  timestampMs: number
  aliasCount: number
}

export type Confidence = FlowAttribution['confidence'] | 'pending'

export type FlowActivitySample = {
  startMs: number
  durationMs: number
  payloadBytesOut: number
  payloadBytesIn: number
  packetsOut: number
  packetsIn: number
  complete: boolean
}

export type FlowActivitySummary = {
  samples: FlowActivitySample[]
  completeRanges: Array<{ startMs: number; endMs: number }>
  activeMs: number
  coveredMs: number
  idleMs: number
  payloadBytesOut: number
  payloadBytesIn: number
  wireBytesOut: number
  wireBytesIn: number
  packetsOut: number
  packetsIn: number
  bucketMs: number | null
  droppedEvents: number
  captureComplete: boolean
  captureAvailable: boolean
}

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
  lastActivityMs: number | null
  routeCompleteCount: number
  routeCount: number
  associatedFlowCount: number
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
  lastActivityMs: number | null
  startFrame: number
  durationFrames: number
  bytes: number
  packets: number
  confidence: Confidence
  explanation: string
  sourceSignal: string
  associationRelationship: FlowAssociation['relationship'] | null
  associationConfidence: FlowAssociation['confidence'] | null
  associationScore: number | null
  associationExplanation: string
  activity: FlowActivitySummary
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
  captureStatus: GatewayData['flowActivityStatuses'][number] | null
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
  const flows = data.flows.filter(isDisplayableClientFlow)
  const flowIDs = new Set(flows.map((flow) => flow.id))
  const observableRouteKeys = new Set(flows.map((flow) => routeKey(flow.destination_ip, flow.destination_port)))
  const routes = data.routes.filter((route) => observableRouteKeys.has(routeKey(route.destination_ip, route.destination_port)))
  const attributionsByFlow = new Map(
    data.attributions.filter((item) => flowIDs.has(item.flow)).map((item) => [item.flow, item]),
  )
  const associationsByFlow = new Map(
    data.flowAssociations
      .filter((item) => flowIDs.has(item.flow) && (item.confidence === 'high' || item.confidence === 'medium'))
      .map((item) => [item.flow, item]),
  )
  const destinationsByIP = new Map(data.destinations.map((item) => [item.ip, item]))
  const hostnamesByIP = buildHostnameCandidatesByIP(data.dnsQueries)
  const routesByDestination = new Map(
    routes.map((route) => [routeKey(route.destination_ip, route.destination_port), route]),
  )
  const chunksByFlow = new Map<string, FlowActivityChunk[]>()
  for (const chunk of data.flowActivityChunks) {
    if (!flowIDs.has(chunk.flow)) continue
    const current = chunksByFlow.get(chunk.flow) ?? []
    current.push(chunk)
    chunksByFlow.set(chunk.flow, current)
  }

  const timeBounds = flows.reduce(
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
  const clips = flows
    .map((flow) =>
      buildClip({
        flow,
        sessionStartMs,
        attributionsByFlow,
        associationsByFlow,
        destinationsByIP,
        hostnamesByIP,
        routesByDestination,
        activityChunks: chunksByFlow.get(flow.id) ?? [],
        activityWindows: data.flowActivityWindows,
      }),
    )
    .sort((a, b) => a.startFrame - b.startFrame || b.bytes - a.bytes)

  for (const clip of clips) {
    const flow = flows.find((item) => item.id === clip.flowId)
    const destination = destinationsByIP.get(clip.destinationIP)
    const route = routesByDestination.get(routeKey(clip.destinationIP, clip.destinationPort))
    const existing = groups.get(clip.serviceGroupId)

    if (existing) {
      existing.totalBytes += clip.bytes
      existing.packetCount += clip.packets
      existing.flowCount += 1
      existing.firstSeenMs = Math.min(existing.firstSeenMs, clip.startMs)
      existing.lastSeenMs = Math.max(existing.lastSeenMs, clip.endMs)
      existing.lastActivityMs = latestTimestamp(existing.lastActivityMs, clip.lastActivityMs)
      existing.routeCount += route ? 1 : 0
      existing.routeCompleteCount += route?.complete ? 1 : 0
      existing.associatedFlowCount += clip.associationRelationship === 'temporally_associated' ? 1 : 0
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
      lastActivityMs: clip.lastActivityMs,
      routeCompleteCount: route?.complete ? 1 : 0,
      routeCount: route ? 1 : 0,
      associatedFlowCount: clip.associationRelationship === 'temporally_associated' ? 1 : 0,
    })
  }

  const lanes = Array.from(groups.values())
    .sort(compareGroups)
    .map((group) => ({
      id: `lane:${group.id}`,
      label: group.label,
      serviceGroupId: group.id,
      totalBytes: group.totalBytes,
      clips: clips
        .filter((clip) => clip.serviceGroupId === group.id)
        .sort(compareClipsByRecentActivity),
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
    captureStatus: data.flowActivityStatuses[0] ?? null,
    totals: {
      flowCount: flows.length,
      attributedCount: attributionsByFlow.size,
      routeCount: routes.length,
      byteCount: flows.reduce((total, flow) => total + flow.bytes_in + flow.bytes_out, 0),
      packetCount: flows.reduce((total, flow) => total + flow.packets_in + flow.packets_out, 0),
      trafficCountersAvailable: flows.some(
        (flow) => flow.bytes_in > 0 || flow.bytes_out > 0 || flow.packets_in > 0 || flow.packets_out > 0,
      ),
    },
  }
}

function buildClip({
  flow,
  sessionStartMs,
  attributionsByFlow,
  associationsByFlow,
  destinationsByIP,
  hostnamesByIP,
  activityChunks,
  activityWindows,
}: {
  flow: Flow
  sessionStartMs: number
  attributionsByFlow: Map<string, FlowAttribution>
  associationsByFlow: Map<string, FlowAssociation>
  destinationsByIP: Map<string, Destination>
  hostnamesByIP: Map<string, DNSHostnameCandidate[]>
  activityChunks: FlowActivityChunk[]
  activityWindows: GatewayData['flowActivityWindows']
  routesByDestination: Map<string, Route>
}): TimelineClip {
  const attribution = attributionsByFlow.get(flow.id)
  const association = associationsByFlow.get(flow.id)
  const destination = destinationsByIP.get(flow.destination_ip)
  const startMs = parseTime(flow.start || flow.created || flow.updated, sessionStartMs)
  const dnsHostname = bestDNSHostnameForFlow(flow, startMs, hostnamesByIP.get(flow.destination_ip))
  const identity = serviceIdentity(flow, attribution, destination, dnsHostname, association)
  const endMs = Math.max(startMs, parseTime(flow.last_seen || flow.updated || flow.created, startMs))
  const startFrame = Math.max(0, msToFrame(startMs - sessionStartMs))
  const durationFrames = Math.max(1, msToFrame(endMs - startMs))
  const bytes = Math.max(0, flow.bytes_in + flow.bytes_out)
  const packets = Math.max(0, flow.packets_in + flow.packets_out)
  const activity = buildFlowActivitySummary(startMs, endMs, activityChunks, activityWindows)
  const lastActivityMs = activity.samples.reduce<number | null>((latest, sample) => {
    const hasDirectionalActivity = sample.payloadBytesOut > 0 || sample.payloadBytesIn > 0 ||
      sample.packetsOut > 0 || sample.packetsIn > 0
    return hasDirectionalActivity
      ? latestTimestamp(latest, sample.startMs + sample.durationMs)
      : latest
  }, null)

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
    lastActivityMs,
    startFrame,
    durationFrames,
    bytes,
    packets,
    confidence: attribution?.confidence ?? 'pending',
    explanation: identity.explanation,
    sourceSignal: identity.sourceSignal,
    associationRelationship: association?.relationship ?? null,
    associationConfidence: association?.confidence ?? null,
    associationScore: association?.score ?? null,
    associationExplanation: association?.explanation ?? '',
    activity,
  }
}

export function decodeActivityChunk(chunk: FlowActivityChunk): FlowActivitySample[] {
  const value = chunk.samples
  if (!value || typeof value !== 'object' || Array.isArray(value)) return []
  const payload = value as Record<string, unknown>
  if (payload.version !== 1 || !Array.isArray(payload.samples)) return []
  const bucketMs = payload.bucket_ms === undefined
    ? positiveInteger(chunk.bucket_ms)
    : positiveInteger(payload.bucket_ms)
  const chunkMs = payload.chunk_ms === undefined
    ? positiveInteger(chunk.chunk_ms)
    : positiveInteger(payload.chunk_ms)
  const chunkStartMs = Date.parse(chunk.chunk_start)
  if (!bucketMs || !chunkMs || bucketMs < 20 || bucketMs > 1000 || chunkMs > 60_000 || bucketMs > chunkMs || !Number.isFinite(chunkStartMs)) return []
  const samples: FlowActivitySample[] = []
  for (const row of payload.samples) {
    if (!Array.isArray(row) || row.length < 5) continue
    const numbers = row.slice(0, 5).map(nonNegativeInteger)
    if (numbers.some((item) => item === null)) continue
    const [offsetMs, payloadBytesOut, payloadBytesIn, packetsOut, packetsIn] = numbers as number[]
    if (offsetMs >= chunkMs || offsetMs % bucketMs !== 0) continue
    samples.push({
      startMs: chunkStartMs + offsetMs,
      durationMs: bucketMs,
      payloadBytesOut,
      payloadBytesIn,
      packetsOut,
      packetsIn,
      complete: chunk.capture_complete && chunk.dropped_events === 0,
    })
  }
  return samples
}

function buildFlowActivitySummary(
  flowStartMs: number,
  flowEndMs: number,
  chunks: FlowActivityChunk[],
  windows: GatewayData['flowActivityWindows'],
): FlowActivitySummary {
  const byStart = new Map<number, FlowActivitySample>()
  let droppedEvents = 0
  let wireBytesOut = 0
  let wireBytesIn = 0
  const bucketSizes = new Set<number>()
  for (const chunk of chunks) {
    droppedEvents += Math.max(0, chunk.dropped_events || 0)
    wireBytesOut += Math.max(0, chunk.wire_bytes_out || 0)
    wireBytesIn += Math.max(0, chunk.wire_bytes_in || 0)
    if (positiveInteger(chunk.bucket_ms)) bucketSizes.add(chunk.bucket_ms)
    for (const sample of decodeActivityChunk(chunk)) {
      if (sample.startMs >= flowEndMs || sample.startMs + sample.durationMs <= flowStartMs) continue
      const previous = byStart.get(sample.startMs)
      if (!previous || sample.payloadBytesOut + sample.payloadBytesIn >= previous.payloadBytesOut + previous.payloadBytesIn) {
        byStart.set(sample.startMs, sample)
      }
    }
  }
  const samples = Array.from(byStart.values()).sort((left, right) => left.startMs - right.startMs)
  const activeMs = samples.reduce(
    (total, sample) => total + Math.max(0, Math.min(flowEndMs, sample.startMs + sample.durationMs) - Math.max(flowStartMs, sample.startMs)),
    0,
  )
  const relevantWindows = windows.filter((window) => {
    const start = Date.parse(window.window_start)
    return Number.isFinite(start) && start < flowEndMs && start + window.window_ms > flowStartMs
  })
  const windowDrops = relevantWindows.reduce((total, window) => total + Math.max(0, window.dropped_events || 0), 0)
  droppedEvents = Math.max(droppedEvents, windowDrops)
  const completeRanges = mergeIntervals(
    relevantWindows
      .filter((window) => window.capture_complete && window.dropped_events === 0)
      .map((window) => {
        const start = Date.parse(window.window_start)
        return [Math.max(flowStartMs, start), Math.min(flowEndMs, start + window.window_ms)] as const
      })
      .filter(([start, end]) => Number.isFinite(start) && end > start),
  ).map(([startMs, endMs]) => ({ startMs, endMs }))
  const coveredMs = completeRanges.reduce((total, range) => total + range.endMs - range.startMs, 0)
  return {
    samples,
    completeRanges,
    activeMs,
    coveredMs,
    idleMs: Math.max(0, coveredMs - activeMs),
    payloadBytesOut: samples.reduce((total, sample) => total + sample.payloadBytesOut, 0),
    payloadBytesIn: samples.reduce((total, sample) => total + sample.payloadBytesIn, 0),
    wireBytesOut,
    wireBytesIn,
    packetsOut: samples.reduce((total, sample) => total + sample.packetsOut, 0),
    packetsIn: samples.reduce((total, sample) => total + sample.packetsIn, 0),
    bucketMs: bucketSizes.size === 1 ? Array.from(bucketSizes)[0] : null,
    droppedEvents,
    captureComplete: coveredMs >= Math.max(0, flowEndMs - flowStartMs) && droppedEvents === 0,
    captureAvailable: relevantWindows.length > 0 || chunks.length > 0,
  }
}

function mergeIntervals(intervals: ReadonlyArray<readonly [number, number]>) {
  const ordered = intervals.slice().sort((left, right) => left[0] - right[0])
  const result: Array<[number, number]> = []
  let start = Number.NaN
  let end = Number.NaN
  for (const interval of ordered) {
    if (!Number.isFinite(start)) {
      ;[start, end] = interval
    } else if (interval[0] <= end) {
      end = Math.max(end, interval[1])
    } else {
      result.push([start, end])
      ;[start, end] = interval
    }
  }
  if (Number.isFinite(start)) result.push([start, end])
  return result
}

function positiveInteger(value: unknown) {
  const number = typeof value === 'number' ? value : Number.NaN
  return Number.isInteger(number) && number > 0 ? number : null
}

function nonNegativeInteger(value: unknown) {
  const number = typeof value === 'number' ? value : Number.NaN
  return Number.isSafeInteger(number) && number >= 0 ? number : null
}

function serviceIdentity(
  flow: Flow,
  attribution?: FlowAttribution,
  destination?: Destination,
  dnsHostname?: string,
  association?: FlowAssociation,
) {
  if (association && (association.confidence === 'high' || association.confidence === 'medium')) {
    const requestLabel = attribution?.candidate_hostname || dnsHostname || destination?.reverse_dns || association.parent_label
    return {
      id: normalizeGroupId(`activity:${association.parent_site_key}`),
      groupLabel: association.parent_label,
      requestLabel,
      sourceSignal: `activity-${association.relationship}`,
      explanation:
        attribution?.explanation ||
        `The connection retained its endpoint identity and was grouped under ${association.parent_label} by a separate activity association.`,
    }
  }
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

  const socketService = knownSocketService(flow, destination)
  if (socketService) {
    return socketService
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
    explanation: fallback.explanation,
  }
}

function knownSocketService(flow: Flow, destination?: Destination) {
  const provider = `${destination?.provider_label ?? ''} ${destination?.organization ?? ''}`.toLowerCase()
  if (flow.protocol.toLowerCase() === 'tcp' && flow.destination_port === 5223 && provider.includes('apple')) {
    return {
      id: normalizeGroupId('activity:apple-push-notifications'),
      groupLabel: 'Apple Push Notifications',
      requestLabel: 'Apple Push Notifications',
      sourceSignal: 'provider-port-hint',
      explanation: 'Identified as likely Apple Push Notification service from the Apple destination network and TCP port 5223.',
    }
  }
  if (flow.protocol.toLowerCase() === 'udp' && flow.destination_port === 443) {
    const providerLabel = destination?.provider_label || destination?.organization
    if (providerLabel) {
      return {
        id: normalizeGroupId(`activity:${providerLabel}:quic-http3`),
        groupLabel: `${providerLabel} — encrypted QUIC`,
        requestLabel: `${providerLabel} — encrypted QUIC / HTTP/3`,
        sourceSignal: 'provider-port-hint',
        explanation: `The destination belongs to ${providerLabel}, and UDP/443 is conventionally encrypted QUIC or HTTP/3. No hostname was visible.`,
      }
    }
  }
  return null
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
    if (flow.protocol.toLowerCase() === 'udp') {
      return {
        key: 'quic-http3',
        label: 'Encrypted QUIC / HTTP/3',
        explanation: 'UDP/443 is conventionally encrypted QUIC or HTTP/3. No hostname or provider evidence was available for this flow.',
      }
    }
    return {
      key: 'https',
      label: 'Unresolved HTTPS',
      explanation: 'No hostname was observed for this encrypted HTTPS flow.',
    }
  }
  if (port === 80) {
    return { key: 'http', label: 'Unresolved HTTP', explanation: 'No hostname was observed for this HTTP flow.' }
  }
  if (port === 53) {
    return { key: 'dns', label: 'DNS lookups', explanation: 'Classic DNS metadata is recorded separately from site/app flows.' }
  }
  if (port === 123) {
    return { key: 'ntp', label: 'Time sync', explanation: 'This flow uses the standard network time protocol port.' }
  }

  return {
    key: `${flow.protocol}:${port}`,
    label: `Unresolved ${protocol}/${port}`,
    explanation: 'No hostname or provider evidence was available for this remote client flow.',
  }
}

function isDisplayableClientFlow(flow: Flow) {
  if (flow.client_ip === DEFAULT_GATEWAY_IP) {
    return false
  }
  if (!isPublicDestinationIP(flow.destination_ip)) {
    return false
  }
  return !isInfrastructureFlow(flow.protocol, flow.destination_port)
}

function isInfrastructureFlow(protocol: string, port: number) {
  const normalizedProtocol = protocol.toLowerCase()
  if (port === 53 && (normalizedProtocol === 'udp' || normalizedProtocol === 'tcp')) {
    return true
  }
  if (normalizedProtocol !== 'udp') {
    return false
  }
  return [67, 68, 123, 5350, 5351, 5353].includes(port) || (port >= 33434 && port <= 33534)
}

function isPublicDestinationIP(value: string) {
  const ipv4 = value.split('.').map(Number)
  if (ipv4.length === 4 && ipv4.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) {
    const [first, second] = ipv4
    return !(
      first === 0 || first === 10 || first === 127 || first >= 224 ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168)
    )
  }

  const normalized = value.toLowerCase()
  if (!normalized.includes(':')) {
    return false
  }
  return normalized !== '::' && normalized !== '::1' &&
    !normalized.startsWith('fc') && !normalized.startsWith('fd') &&
    !normalized.startsWith('fe8') && !normalized.startsWith('fe9') &&
    !normalized.startsWith('fea') && !normalized.startsWith('feb') &&
    !normalized.startsWith('ff')
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

function buildHostnameCandidatesByIP(dnsQueries: DNSQuery[]) {
  const hostnames = new Map<string, DNSHostnameCandidate[]>()
  for (const query of dnsQueries) {
    if (!query.query_name || !query.answers?.length) {
      continue
    }
    for (const answer of query.answers ?? []) {
      if (isLikelyIPAddress(answer)) {
        const candidates = hostnames.get(answer) ?? []
        candidates.push({
          hostname: query.query_name,
          clientIP: query.client_ip,
          timestampMs: parseTime(query.timestamp, 0),
          aliasCount: query.aliases?.length ?? 0,
        })
        hostnames.set(answer, candidates)
      }
    }
  }
  return hostnames
}

function bestDNSHostnameForFlow(
  flow: Flow,
  flowStartMs: number,
  candidates: DNSHostnameCandidate[] | undefined,
) {
  return (candidates ?? [])
    .filter((candidate) => {
      const distance = flowStartMs - candidate.timestampMs
      return candidate.clientIP === flow.client_ip &&
        distance >= -DNS_FUTURE_TOLERANCE_MS &&
        distance <= DNS_ATTRIBUTION_WINDOW_MS
    })
    .sort((left, right) => {
      const leftDistance = Math.abs(flowStartMs - left.timestampMs)
      const rightDistance = Math.abs(flowStartMs - right.timestampMs)
      return leftDistance - rightDistance || right.aliasCount - left.aliasCount
    })[0]?.hostname
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
    compareLatestActivity(left.lastActivityMs, right.lastActivityMs) ||
    right.lastSeenMs - left.lastSeenMs ||
    right.totalBytes - left.totalBytes ||
    right.flowCount - left.flowCount ||
    left.label.localeCompare(right.label)
  )
}

function compareClipsByRecentActivity(left: TimelineClip, right: TimelineClip) {
  return (
    compareLatestActivity(left.lastActivityMs, right.lastActivityMs) ||
    right.endMs - left.endMs ||
    right.bytes - left.bytes ||
    left.label.localeCompare(right.label)
  )
}

function compareLatestActivity(left: number | null, right: number | null) {
  if (left === null && right === null) return 0
  if (left === null) return 1
  if (right === null) return -1
  return right - left
}

function latestTimestamp(left: number | null, right: number | null) {
  if (left === null) return right
  if (right === null) return left
  return Math.max(left, right)
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
