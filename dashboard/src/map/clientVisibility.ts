import { clientKey } from './mapWorkspace'
import type { HiddenClient, WorkspaceState } from './mapWorkspace'
import type { ConnectedClientsState } from './useConnectedClients'

export type ClientVisibilityRow = HiddenClient & { detail: string; connected: boolean; hidden: boolean }

/** Connected clients first, then hidden clients that have since left, so their
 * earlier traffic can be shown again. Shared by the map pill and Filters. */
export function clientVisibilityRows(clients: ConnectedClientsState | null, state: WorkspaceState): ClientVisibilityRow[] {
  const hidden = state.hiddenClients ?? []
  const hiddenKeys = new Set(hidden.map(client => client.key))
  const rows: ClientVisibilityRow[] = (clients?.clients ?? []).map(client => {
    const key = clientKey(client.id, client.ip)
    return { key, label: client.hostname || client.ip || 'Unknown device', detail: client.hostname ? client.ip : client.ip ? 'No hostname' : 'Waiting for address', connected: true, hidden: hiddenKeys.has(key) }
  })
  const listed = new Set(rows.map(row => row.key))
  for (const client of hidden) if (!listed.has(client.key)) rows.push({ ...client, detail: 'Disconnected', connected: false, hidden: true })
  return rows
}

export function toggleClient(state: WorkspaceState, row: ClientVisibilityRow): WorkspaceState {
  const hidden = state.hiddenClients ?? []
  return { ...state, hiddenClients: row.hidden ? hidden.filter(client => client.key !== row.key) : [...hidden, { key: row.key, label: row.label }] }
}
