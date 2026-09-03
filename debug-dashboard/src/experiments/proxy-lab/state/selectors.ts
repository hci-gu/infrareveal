import type { PipelineEvent } from '../types'
import type { ProxyLabState } from './proxyLabStore'

export function selectFilteredEvents(state: ProxyLabState, events: readonly PipelineEvent[]) {
  const clientIps = new Set(state.filters.clientIps)
  const protocols = new Set(state.filters.protocols.map((value) => value.toLowerCase()))
  const kinds = new Set(state.filters.kinds)
  const directions = new Set(state.filters.directions)
  return events.filter((event) =>
    (clientIps.size === 0 || Boolean(event.summary.clientIp && clientIps.has(event.summary.clientIp))) &&
    (protocols.size === 0 || Boolean(event.summary.protocol && protocols.has(event.summary.protocol.toLowerCase()))) &&
    (kinds.size === 0 || kinds.has(event.kind)) &&
    (directions.size === 0 || Boolean(event.direction && directions.has(event.direction))),
  )
}
