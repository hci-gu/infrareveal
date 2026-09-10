import type { ActivityEpisode, Flow, FlowAssociation, FlowAttribution, GatewayData } from './types'
import { parseEpoch } from '../timeline/domain/time'

export type FlowTrackIdentity = {
  id: string
  label: string
  client: string
  site: string
  episode?: ActivityEpisode
  association?: FlowAssociation
  attribution?: FlowAttribution
  hostname: string
}

type TrackEvidence = { associations: FlowAssociation[]; attributions: FlowAttribution[] }
export type FlowTrackIndex = { episodes: Map<string, ActivityEpisode>; evidence: Map<string, TrackEvidence> }

/** Shared by the Traffic workspace and map: a provider or shared IP is not an activity association. */
export function indexFlowTracks(data: Pick<GatewayData, 'flows' | 'activityEpisodes' | 'flowAssociations' | 'attributions'>): FlowTrackIndex {
  const episodes = new Map(data.activityEpisodes.map(episode => [episode.id, episode]))
  const flows = new Map(data.flows.map(flow => [flow.id, flow]))
  const evidence = new Map<string, TrackEvidence>(data.flows.map(flow => [flow.id, { associations: [], attributions: [] }]))
  for (const record of data.attributions) evidence.get(record.flow)?.attributions.push(record)
  for (const record of data.flowAssociations) {
    const episode = episodes.get(record.episode), flow = flows.get(record.flow)
    if ((record.confidence === 'high' || record.confidence === 'medium') && episode && flow && episode.client_ip === flow.client_ip && episode.session === flow.session && record.session === flow.session) evidence.get(record.flow)?.associations.push(record)
  }
  for (const item of evidence.values()) {
    item.associations.sort(byObservation)
    item.attributions.sort(byObservation)
  }
  return { episodes, evidence }
}

export function flowTrackAt(index: FlowTrackIndex, flow: Flow, cursorMs = Infinity): FlowTrackIdentity {
  const evidence = index.evidence.get(flow.id)
  const association = latestAt(evidence?.associations, cursorMs, record => parseEpoch(index.episodes.get(record.episode)?.start, Infinity) <= cursorMs)
  const episode = association ? index.episodes.get(association.episode) : undefined
  const attribution = latestAt(evidence?.attributions, cursorMs, record => record.session === flow.session)
  return {
    id: `${flow.client_ip}:${association ? 'activity:' + association.episode : 'independent'}`,
    label: association ? episode?.label || association.parent_label : 'Independent traffic',
    client: flow.client_ip,
    site: association ? episode?.site_key || association.parent_site_key : '',
    episode, association, attribution,
    hostname: attribution?.confidence !== 'hidden' && attribution?.candidate_hostname ? attribution.candidate_hostname : flow.destination_ip,
  }
}

function byObservation(a: { observed_at: string; id: string }, b: { observed_at: string; id: string }) {
  return parseEpoch(a.observed_at, -Infinity) - parseEpoch(b.observed_at, -Infinity) || a.id.localeCompare(b.id)
}
function latestAt<T extends { observed_at: string }>(records: T[] | undefined, cursorMs: number, eligible: (record: T) => boolean): T | undefined {
  for (let i = (records?.length ?? 0) - 1; i >= 0; i -= 1) {
    const record = records![i]
    const observed = parseEpoch(record.observed_at, NaN)
    if (Number.isFinite(observed) && observed <= cursorMs && eligible(record)) return record
  }
}

export function isTrafficConnection(flow: Flow) {
  if (flow.client_ip === '10.0.0.1') {
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
