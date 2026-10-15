import type { RouteEvidence, TrafficChunk } from './types'
type Binding = Pick<TrafficChunk, 'session' | 'destination_ip' | 'protocol' | 'destination_port' | 'network_epoch'>
export function routeBindingKey(value: Binding) { return JSON.stringify([value.session, value.network_epoch, value.destination_ip, value.protocol.toLowerCase(), value.destination_port]) }
export function routeForSeriesAt(binding: Binding, evidence: readonly RouteEvidence[], cursor: number): RouteEvidence | null {
  const candidates = evidence.filter(route => route.kind === 'path' && routeBindingKey(route) === routeBindingKey(binding) && route.available_ms <= cursor)
  candidates.sort((a, b) => b.available_ms - a.available_ms || b.revision - a.revision || b.id.localeCompare(a.id))
  const latest = candidates[0]
  if (!latest || cursor >= latest.valid_until_ms) return null
  if (evidence.some(route => route.kind === 'network_invalidated' && route.session === binding.session && route.network_epoch === binding.network_epoch && route.available_ms >= latest.available_ms && route.available_ms <= cursor)) return null
  return latest
}
export const routeStateLabel = (route: RouteEvidence, cursor: number) => cursor >= route.valid_until_ms ? 'Expired' : cursor >= route.fresh_until_ms ? 'Aged measurement' : route.destination_reached ? 'Destination reached' : 'Partial path'
