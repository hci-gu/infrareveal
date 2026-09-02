import { describe, expect, it } from 'vitest'
import { TemporalBucketIndex } from './temporalIndex'

describe('shared TemporalBucketIndex', () => {
  it('finds overlapping intervals without scanning unrelated buckets', () => {
    const index = new TemporalBucketIndex(1_000)
    index.upsert('early', 0, 2_500)
    index.upsert('late', 10_000, 11_000)
    expect(Array.from(index.query(2_000, 3_000))).toEqual(['early'])
  })

  it('moves a growing interval and removes stale bucket membership', () => {
    const index = new TemporalBucketIndex(1_000)
    index.upsert('flow', 2_000, 2_500)
    index.upsert('flow', 2_000, 5_500)
    expect(index.query(5_000, 6_000).has('flow')).toBe(true)
    index.remove('flow')
    expect(index.query(2_000, 6_000).size).toBe(0)
  })
})
