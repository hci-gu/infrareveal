import { describe, expect, it } from 'vitest'
import { formatPocketBaseDate } from './pocketbaseClient'

describe('PocketBase date filters', () => {
  it('uses the PocketBase date literal format accepted by range comparisons', () => {
    expect(formatPocketBaseDate(Date.parse('2026-08-25T13:29:00.000Z')))
      .toBe('2026-08-25 13:29:00.000Z')
  })
})
