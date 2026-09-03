import { describe, expect, it } from 'vitest'
import type { Session } from '@infrareveal/session-state'
import { partitionSessions } from './sessionGroups'

function session(id: string, active: boolean): Session {
  return { id, active, name: id, created: '2026-09-02 10:00:00.000Z', updated: '2026-09-02 10:00:00.000Z' }
}

describe('partitionSessions', () => {
  it('handles an empty list', () => {
    expect(partitionSessions([])).toEqual({ active: [], recorded: [] })
  })

  it('keeps every active session instead of assuming there is only one', () => {
    const result = partitionSessions([session('a', true), session('b', true), session('c', false)])
    expect(result.active.map((item) => item.id)).toEqual(['a', 'b'])
    expect(result.recorded.map((item) => item.id)).toEqual(['c'])
  })
})
