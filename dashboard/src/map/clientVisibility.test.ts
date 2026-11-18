import { expect, it } from 'vitest'
import { clientVisibilityRows, toggleClient } from './clientVisibility'
import { DEFAULT_TRAFFIC_FILTERS, trafficFilterCount } from './mapWorkspace'
import type { WorkspaceState } from './mapWorkspace'

const clients = { connected: 2, clients: [{ id: 'abc', ip: '10.0.0.146', hostname: 'Galaxy' }, { id: '', ip: '10.0.0.135', hostname: '' }] }
const base: WorkspaceState = { locationId: null, expanded: false }

it('lists connected clients, keeps hidden ones that left, and counts as a resettable filter', () => {
  const rows = clientVisibilityRows(clients, base)
  expect(rows.map(row => [row.key, row.label, row.detail, row.hidden])).toEqual([['abc', 'Galaxy', '10.0.0.146', false], ['ip:10.0.0.135', '10.0.0.135', 'No hostname', false]])
  const hidden = toggleClient(base, rows[0])
  expect(trafficFilterCount(hidden)).toBe(1)
  const left = clientVisibilityRows({ connected: 1, clients: [clients.clients[1]] }, hidden)
  expect(left[left.length - 1]).toMatchObject({ key: 'abc', label: 'Galaxy', detail: 'Disconnected', hidden: true })
  expect(toggleClient(hidden, left[left.length - 1]).hiddenClients).toEqual([])
  expect({ ...hidden, ...DEFAULT_TRAFFIC_FILTERS }.hiddenClients).toEqual([])
})
