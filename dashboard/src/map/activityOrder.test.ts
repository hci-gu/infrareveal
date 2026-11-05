import { expect, it } from 'vitest'
import { stableActivityOrder } from './activityOrder'

const item = (id: string, lastActivityMs: number) => ({ id, lastActivityMs })

it('holds ongoing lanes despite packet timing changes, and demotes at fifteen seconds of silence', () => {
  const initial = stableActivityOrder([item('a', 1000), item('b', 900)], [], 1000)
  expect(initial.ids).toEqual(['a', 'b'])
  let previous = initial.activeIds
  for (let now = 2000; now < 16000; now += 1000) {
    const next = stableActivityOrder([item('b', now), item('a', 1000)], previous, now)
    expect(next.ids).toEqual(['a', 'b'])
    previous = next.activeIds
  }
  expect(stableActivityOrder([item('a', 1000), item('b', 16000)], previous, 16000)).toEqual({ ids: ['b', 'a'], activeIds: ['b'] })
})

it('admits new and returning lanes by recency behind ongoing activity, then lets them rise', () => {
  const items = [item('quiet', 1000), item('ongoing', 5000), item('returning', 19000), item('new', 20000)]
  const first = stableActivityOrder(items, ['ongoing'], 19999)
  expect(first.activeIds).toEqual(['ongoing', 'returning'])
  const joined = stableActivityOrder(items, ['ongoing'], 20000)
  // The incumbent reaches its 15s quiet threshold at this instant.
  expect(joined.ids).toEqual(['new', 'returning', 'ongoing', 'quiet'])
  const retained = stableActivityOrder([item('ongoing', 18000), ...items.filter(row => row.id !== 'ongoing')], ['ongoing'], 20000)
  expect(retained.ids).toEqual(['ongoing', 'new', 'returning', 'quiet'])
  const resumed = stableActivityOrder([item('quiet', 22000), item('new', 22000), item('returning', 22000)], retained.activeIds, 22000)
  expect(resumed.ids).toEqual(['new', 'returning', 'quiet'])
})

it('keeps a hundred sustained lanes stable while their timestamps alternate', () => {
  const lanes = Array.from({ length: 144 }, (_, i) => item(`lane-${i}`, 1000 + i))
  const initial = stableActivityOrder(lanes, [], 2000)
  let activeIds = initial.activeIds
  for (let now = 3000; now <= 60000; now += 1000) {
    const updates = lanes.map((lane, i) => item(lane.id, now - ((now / 1000 + i) % 2) * 100))
    const next = stableActivityOrder(updates, activeIds, now)
    expect(next.ids).toEqual(initial.ids)
    activeIds = next.activeIds
  }
})
