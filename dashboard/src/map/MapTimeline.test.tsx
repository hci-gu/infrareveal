// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, expect, it, vi } from 'vitest'
import { seriesKey, type TrafficChunk, type CaptureInterval } from '@infrareveal/session-state'
import fixture from '../../../testdata/aggregate-window-v2.json'
import { indexDestinationVolumes } from './destinationVolumes'
import type { MapSeries } from './mapTracks'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'
import { MapTimeline } from './MapTimeline'

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
const start = fixture.window.from_ms
const end = start + 600_000
const chunks = Array.from({ length: 135 }, (_, i) => ({ ...fixture.window.series[0], client_id: `client-${i}`, start_ms: start,
  bucket_ms: 50, samples: [[i === 134 ? 598_000 : i === 133 ? 595_000 : i === 132 ? 420_000 : 1000, i === 134 ? 1000 : 0, i === 134 ? 0 : 2000, 0, 0, 1, 1]],
})) as TrafficChunk[]
const index = indexDestinationVolumes(chunks, start, [{ ...fixture.window.coverage[0], start_ms: start, end_ms: end + 330_000 }] as CaptureInterval[], end + 330_000)
const rows = chunks.map((chunk, i) => ({ id: seriesKey(chunk), trackId: `track-${i}`, label: `Service ${i}`, client: `client-${i}`,
  endpoint: `${i}.example:443`, location: 'Test location', locationId: 'test', received: 2000, sent: 1000, bytes: 3000, partial: false, lastActivityMs: start + 1000,
  series: [{ id: seriesKey(chunk), startMs: start, endMs: end + 330_000, chunks: [chunk] } as MapSeries],
}))
const data = { rows, scene: { sessionId: 'large-session' }, locations: [] } as unknown as WorkspaceProjection
const container = document.createElement('div')
document.body.append(container)
let root = createRoot(container)
const onFollowLive = vi.fn()
let current = { cursorMs: end, index, state: { direction: 'both', locationId: null, expanded: true } as WorkspaceState }
const render = async (next: Partial<typeof current> = {}) => {
  current = { ...current, ...next }
  await act(() => root.render(<MapTimeline data={data} startMs={start} endMs={end + 330_000} {...current} onChange={() => {}} onSeek={() => {}} onTrack={() => {}} loading={false} error={false} refreshing={false} live following onFollowLive={onFollowLive} />))
}
const button = (label: string) => [...container.querySelectorAll('button')].find(node => node.textContent?.startsWith(label))!
const laneNames = () => [...container.querySelectorAll('.atlas-detail-track strong')].map(node => node.textContent)
HTMLElement.prototype.scrollTo = vi.fn(function(this: HTMLElement) { this.scrollTop = 0 })
afterEach(async () => { await act(() => root.unmount()); root = createRoot(container); current = { cursorMs: end, index, state: { direction: 'both', locationId: null, expanded: true } }; vi.clearAllMocks() })

it('defaults to five minutes with recent endpoints first and quieter history still visible', async () => {
  await render()
  expect(laneNames()).toEqual(['Service 134', 'Service 133', 'Service 132'])
  expect(container.textContent).toContain('2 active in last 30s')
  expect(container.querySelectorAll('.atlas-detail-row.is-active')).toHaveLength(2)
  expect(container.querySelectorAll<HTMLElement>('.atlas-detail-row')[2].style.getPropertyValue('--lane-opacity')).toBe('0.5')
  expect(container.querySelectorAll('.atlas-flow-envelope').length).toBeGreaterThan(0)
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-window-from')).toBe(String(end - 300_000))
  await render({ state: { ...current.state, direction: 'received' } })
  expect(laneNames()).toEqual(['Service 133', 'Service 132'])
  expect(container.querySelector('.atlas-detail-lane .atlas-flow-sent')).toBeNull()
})

it('holds the window while browsing a long list and returns directly to active traffic', async () => {
  await render()
  await act(() => button('All lanes').click())
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-visible-lanes')).toBe('135')
  expect(laneNames().length).toBeLessThanOrEqual(32)
  const scroll = container.querySelector<HTMLDivElement>('.atlas-detail-scroll')!
  await act(() => { scroll.scrollTop = 10_000; scroll.dispatchEvent(new Event('scroll', { bubbles: true })) })
  const heldTo = container.querySelector('.atlas-detail-timeline')?.getAttribute('data-window-to')
  const names = laneNames()
  await render({ cursorMs: end + 15_000 })
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-window-to')).toBe(heldTo)
  expect(laneNames()).toEqual(names)
  expect(container.textContent).toContain('Window held')
  await act(() => button('Follow live').click())
  expect(onFollowLive).toHaveBeenCalledOnce()
  expect(laneNames()).toEqual(['Service 134', 'Service 133', 'Service 132'])
  expect(scroll.scrollTop).toBe(0)
  expect(container.textContent).toContain('Following live')
})

it('expires quiet lanes, explains the empty state and lets the reader reveal them', async () => {
  await render({ cursorMs: end + 300_000 })
  expect(laneNames()).toEqual([])
  expect(container.textContent).toContain('No traffic in this window')
  await act(() => button('Show all').click())
  expect(laneNames().length).toBeGreaterThan(0)
})

it('holds a keyboard-focused lane and resets browsing on a location change', async () => {
  await render()
  await act(() => container.querySelector<HTMLButtonElement>('.atlas-detail-track')!.focus())
  await render({ cursorMs: end + 10_000 })
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-window-to')).toBe(String(end))
  await render({ state: { ...current.state, locationId: 'test' } })
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-window-to')).toBe(String(end + 10_000))
  expect(container.textContent).not.toContain('Window held')
})


it('promotes a previously quiet lane in place when new capture arrives', async () => {
  await render()
  const quietLane = container.querySelectorAll<HTMLElement>('.atlas-detail-row')[2]
  const previousFirst = container.querySelector<HTMLElement>('.atlas-detail-row')!
  expect(quietLane.style.getPropertyValue('--lane-y')).toBe('208px')
  const renewed = { ...chunks[132], samples: [...chunks[132].samples, [600_500, 0, 5000, 0, 0, 0, 1]] } as TrafficChunk
  await render({ cursorMs: end + 1000, index: indexDestinationVolumes([...chunks.slice(0, 132), renewed, ...chunks.slice(133)], start, index.coverage, index.toMs) })
  expect(laneNames()).toEqual(['Service 132', 'Service 134', 'Service 133'])
  expect(container.querySelector('.atlas-detail-row')).toBe(quietLane)
  expect(quietLane.style.getPropertyValue('--lane-y')).toBe('0px')
  expect(quietLane.style.getPropertyValue('--lane-opacity')).toBe('1')
  expect(previousFirst.style.getPropertyValue('--lane-y')).toBe('104px')
})

it('keeps the chosen history window when returning to live following', async () => {
  await render()
  const windowSelect = container.querySelector<HTMLSelectElement>('[aria-label="Timeline window"]')!
  expect(windowSelect.value).toBe('300000')
  await act(() => { windowSelect.value = '30000'; windowSelect.dispatchEvent(new Event('change', { bubbles: true })) })
  expect(laneNames()).toEqual(['Service 134', 'Service 133'])
  await act(() => container.querySelector<HTMLButtonElement>('.atlas-detail-track')!.focus())
  await act(() => button('Follow live').click())
  expect(windowSelect.value).toBe('30000')
})
