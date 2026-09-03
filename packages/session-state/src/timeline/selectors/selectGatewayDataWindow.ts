import type { GatewayData } from '../../data/types'

/** Builds bounded domain input for a consumer-specific scene projection. */
export function selectGatewayDataWindow(
  data: GatewayData,
  flowIds: string[],
  detail: Pick<GatewayData, 'dnsQueries' | 'flowActivityChunks' | 'flowActivityWindows'> & Partial<Pick<GatewayData, 'gateEvents'>>,
): GatewayData {
  const requested = new Set(flowIds)
  const flows = data.flows.filter((flow) => requested.has(flow.id))
  const destinationSockets = new Set(flows.map((flow) => `${flow.destination_ip}:${flow.destination_port}:${flow.protocol}`))
  const destinationIPs = new Set(flows.map((flow) => flow.destination_ip))
  const associations = data.flowAssociations.filter((record) => requested.has(record.flow))
  const episodeIDs = new Set(associations.map((record) => record.episode))

  return {
    sessions: data.sessions,
    selectedSession: data.selectedSession,
    flows,
    dnsQueries: detail.dnsQueries,
    attributions: data.attributions.filter((record) => requested.has(record.flow)),
    activityEpisodes: data.activityEpisodes.filter((record) => episodeIDs.has(record.id)),
    flowAssociations: associations,
    flowActivityChunks: detail.flowActivityChunks.filter((record) => requested.has(record.flow)),
    flowActivityWindows: detail.flowActivityWindows,
    flowActivityStatuses: data.flowActivityStatuses,
    destinations: data.destinations.filter((record) => destinationIPs.has(record.ip)),
    routes: data.routes.filter((record) => destinationSockets.has(`${record.destination_ip}:${record.destination_port}:${record.protocol}`)),
    gateEvents: detail.gateEvents ?? [],
  }
}
