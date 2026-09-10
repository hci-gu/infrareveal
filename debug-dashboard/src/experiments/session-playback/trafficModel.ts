import type { DNSQuery, Flow, FlowActivityChunk, FlowAssociation, FlowAttribution, GatewayData } from '@infrareveal/session-state'
import type { SessionComposition, SessionCompositionProjector, TimelineClip } from '../../model/sessionModel'
import { decodeActivityChunk } from '../../shared/activity/decodeActivityChunk'
import { captureCoverage } from '../../shared/activity/captureCoverage'

export type TrafficGroup = { id: string; label: string; client: string; clips: TimelineClip[]; dns: DNSQuery[]; attributions: FlowAttribution[]; associations: FlowAssociation[] }
export type TrafficSelection = { kind: 'flow' | 'dns' | 'attribution' | 'association' | 'gate'; id: string; flowId?: string; observedAtMs?: number }
export type TrafficRecord = { id: string; time: number; kind: string; client: string; endpoint: string; detail: string; provenance: string; selection: TrafficSelection; raw: unknown }
export function preferredActivityChunks(chunks: readonly FlowActivityChunk[]) {
  const result: FlowActivityChunk[] = []
  const byFlow = new Map<string, FlowActivityChunk[]>()
  for (const chunk of [...chunks].sort((a, b) => a.bucket_ms - b.bucket_ms || Date.parse(b.updated_at_source) - Date.parse(a.updated_at_source) || a.id.localeCompare(b.id))) {
    const siblings = byFlow.get(chunk.flow) ?? []
    const start = Date.parse(chunk.chunk_start), end = start + chunk.chunk_ms
    if (!Number.isFinite(start)) continue
    const overlaps = siblings.filter(other => Date.parse(other.chunk_start) < end && Date.parse(other.chunk_start) + other.chunk_ms > start)
    if (overlaps.length) {
      let coveredTo = start
      for (const other of [...overlaps].sort((a, b) => Date.parse(a.chunk_start) - Date.parse(b.chunk_start))) {
        if (Date.parse(other.chunk_start) > coveredTo) break
        coveredTo = Math.max(coveredTo, Date.parse(other.chunk_start) + other.chunk_ms)
      }
      if (coveredTo >= end) continue
      // An aggregate cannot be prorated into its uncovered part. Keep the full
      // coarser observation until finer chunks cover that entire interval.
      if (overlaps.some(other => Date.parse(other.chunk_start) < start || Date.parse(other.chunk_start) + other.chunk_ms > end)) continue
      for (const other of overlaps) { siblings.splice(siblings.indexOf(other), 1); result.splice(result.indexOf(other), 1) }
    }
    siblings.push(chunk); byFlow.set(chunk.flow, siblings); result.push(chunk)
  }
  return result
}
export function buildTrafficModel(data: GatewayData, projector: SessionCompositionProjector, fromMs: number, toMs: number) {
  const chunks = preferredActivityChunks(data.flowActivityChunks)
  const projected = projector.project({ ...data, flowActivityChunks: chunks }, { sessionStartMs: fromMs, sessionEndMs: toMs })
  const flows = new Map(data.flows.map(flow => [flow.id, flow]))
  const attributions = new Map([...data.attributions].sort((a, b) => Date.parse(a.observed_at) - Date.parse(b.observed_at)).map(record => [record.flow, record]))
  const episodes = new Map(data.activityEpisodes.map(episode => [episode.id, episode]))
  const associations = new Map([...data.flowAssociations].filter(record => {
    const episode = episodes.get(record.episode), flow = flows.get(record.flow)
    return (record.confidence === 'high' || record.confidence === 'medium') && episode?.client_ip === flow?.client_ip
  }).sort((a, b) => Date.parse(a.observed_at) - Date.parse(b.observed_at)).map(record => [record.flow, record]))
  const groups = new Map<string, TrafficGroup>()
  const clips = projected.clips.map(clip => {
    const flow = flows.get(clip.flowId)!, attribution = attributions.get(flow.id), association = associations.get(flow.id)
    const groupId = `${flow.client_ip}:${association ? 'activity:' + association.episode : 'independent'}`
    const label = association ? episodes.get(association.episode)?.label || association.parent_label : 'Independent traffic'
    const next: TimelineClip = { ...clip, serviceGroupId: groupId, serviceGroupLabel: label, label: attribution?.confidence !== 'hidden' && attribution?.candidate_hostname ? attribution.candidate_hostname : flow.destination_ip, confidence: attribution?.confidence ?? 'pending', explanation: attribution?.explanation || 'No supported hostname attribution', sourceSignal: attribution?.source_signal || 'Observed socket', associationRelationship: association?.relationship ?? null, associationConfidence: association?.confidence ?? null, associationExplanation: association?.explanation || '', associationScore: association?.score ?? null }
    const group = groups.get(groupId) ?? { id: groupId, label, client: flow.client_ip, clips: [], dns: [], attributions: [], associations: [] }
    group.clips.push(next); groups.set(groupId, group)
    return next
  })
  // Every DNS record has one client evidence row, independently of whether it links to a flow.
  for (const query of data.dnsQueries) {
    const id = `${query.client_ip}:dns`
    const group = groups.get(id) ?? { id, label: 'DNS observations', client: query.client_ip, clips: [], dns: [], attributions: [], associations: [] }
    group.dns.push(query); groups.set(id, group)
  }
  const groupByFlow = new Map(clips.map(clip => [clip.flowId, clip.serviceGroupId]))
  for (const record of data.attributions) { const id = groupByFlow.get(record.flow); if (id) groups.get(id)?.attributions.push(record) }
  for (const record of data.flowAssociations) { const id = groupByFlow.get(record.flow); if (id) groups.get(id)?.associations.push(record) }
  const ordered = [...groups.values()].sort((a, b) => a.client.localeCompare(b.client, undefined, { numeric: true }) || Number(b.id.endsWith(':dns')) - Number(a.id.endsWith(':dns')) || a.label.localeCompare(b.label))
  for (const group of ordered) group.clips.sort((a, b) => a.startMs - b.startMs || a.flowId.localeCompare(b.flowId))
  // The same conservative labels feed the retained treemap and render-bundle export.
  const serviceGroups = ordered.filter(group => group.clips.length).map(group => ({ id: group.id, label: `${group.client} / ${group.label}`, sourceSignal: 'observations', confidence: 'pending' as const, destinationIPs: [...new Set(group.clips.map(clip => clip.destinationIP))], hostnames: [...new Set(group.clips.map(clip => clip.label))], clientIPs: [group.client], providerLabel: '', totalBytes: group.clips.reduce((n, c) => n + (Number.isFinite(c.bytes) ? c.bytes : 0), 0), packetCount: group.clips.reduce((n, c) => n + (Number.isFinite(c.packets) ? c.packets : 0), 0), flowCount: group.clips.length, firstSeenMs: group.clips.reduce((min, c) => Math.min(min, c.startMs), Infinity), lastSeenMs: group.clips.reduce((max, c) => Math.max(max, c.endMs), -Infinity), lastActivityMs: null, routeCompleteCount: 0, routeCount: 0, associatedFlowCount: group.clips.filter(c => c.associationRelationship).length }))
  const composition: SessionComposition = { ...projected, sessionStartMs: fromMs, sessionEndMs: toMs, durationInFrames: Math.max(1, Math.ceil((toMs - fromMs) / 1000 * projected.fps)), clips, serviceGroups, lanes: ordered.filter(g => g.clips.length).map(g => ({ id: g.id, label: g.label, serviceGroupId: g.id, totalBytes: 0, clips: g.clips })) }
  return { groups: ordered, clips, composition, flows, chunks }
}
export function activityInWindow(chunks: readonly FlowActivityChunk[], windows: GatewayData['flowActivityWindows'], fromMs: number, toMs: number) {
  const preferred = preferredActivityChunks(chunks.filter(chunk => Date.parse(chunk.chunk_start) < toMs && Date.parse(chunk.chunk_start) + chunk.chunk_ms > fromMs))
  const samples = preferred.flatMap(decodeActivityChunk).filter(sample => sample.startMs >= fromMs && sample.startMs + sample.durationMs <= toMs)
  const coverage = captureCoverage(windows, fromMs, toMs)
  return { samples, payloadIn: samples.reduce((n, s) => n + s.payloadBytesIn, 0), payloadOut: samples.reduce((n, s) => n + s.payloadBytesOut, 0), packetsIn: samples.reduce((n, s) => n + s.packetsIn, 0), packetsOut: samples.reduce((n, s) => n + s.packetsOut, 0), complete: coverage.length > 0 && coverage.every(range => range.level === 'complete') && samples.every(sample => sample.complete), resolution: [...new Set(preferred.map(chunk => chunk.bucket_ms))].sort((a, b) => a - b), coverage }
}
export function trafficRecords(data: GatewayData): TrafficRecord[] {
  const flows = new Map(data.flows.map(flow => [flow.id, flow]))
  const endpoint = (flow?: Flow) => flow ? `${flow.destination_ip}:${flow.destination_port}` : 'Unavailable flow'
  const records: TrafficRecord[] = data.flows.map(flow => ({ id: 'flow:' + flow.id, time: Date.parse(flow.start), kind: flow.protocol.toUpperCase(), client: flow.client_ip, endpoint: endpoint(flow), detail: `${flow.state} · ${flow.source_port} → ${flow.destination_port}`, provenance: 'Observed', selection: { kind: 'flow', id: flow.id, flowId: flow.id }, raw: flow }))
  for (const q of data.dnsQueries) records.push({ id: 'dns:' + q.id, time: Date.parse(q.timestamp), kind: 'DNS', client: q.client_ip, endpoint: q.query_name, detail: `${q.query_type} → ${q.answers?.join(', ') || 'No answer'}${q.aliases?.length ? ' · aliases: ' + q.aliases.join(' → ') : ''}`, provenance: 'Observed', selection: { kind: 'dns', id: q.id }, raw: q })
  for (const a of data.attributions) records.push({ id: 'attribution:' + a.id, time: Date.parse(a.observed_at), kind: 'Attribution', client: flows.get(a.flow)?.client_ip || 'Unknown', endpoint: a.candidate_hostname, detail: `${a.confidence} · ${a.source_signal}`, provenance: 'Derived', selection: { kind: 'attribution', id: a.id, flowId: a.flow }, raw: a })
  for (const a of data.flowAssociations) records.push({ id: 'association:' + a.id, time: Date.parse(a.observed_at), kind: 'Association', client: flows.get(a.flow)?.client_ip || 'Unknown', endpoint: a.parent_label, detail: `${a.confidence} · ${a.relationship}`, provenance: 'Derived', selection: { kind: 'association', id: a.id, flowId: a.flow }, raw: a })
  for (const g of data.gateEvents) records.push({ id: 'gate:' + g.id, time: Date.parse(g.decided_at || g.queued_at), kind: 'Gate ' + g.state, client: g.client_ip, endpoint: `${g.destination_ip}:${g.destination_port}`, detail: `${g.actor} · ${g.reason}`, provenance: 'Observed', selection: { kind: 'gate', id: g.id }, raw: g })
  return records.filter(record => Number.isFinite(record.time)).sort((a, b) => a.time - b.time || a.id.localeCompare(b.id))
}
