// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, expect, it, vi } from 'vitest'
import { type TrafficChunk, type CaptureInterval } from '@infrareveal/session-state'
import fixture from '../../../testdata/aggregate-window-v2.json'
import { indexDestinationVolumes } from './destinationVolumes'
import { buildMapTrackCatalog } from './mapTracks'
import { buildMapTimelineScene } from './mapModel'
import { projectWorkspace } from './mapWorkspace'
import type { MapWindow, SessionManifest } from '@infrareveal/session-state'
import type { WorkspaceState } from './mapWorkspace'
import { MapTimeline } from './MapTimeline'
import { MapPlaybackClock } from './mapPlaybackClock'

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
const start = fixture.window.from_ms
const end = start + 600_000
const chunks = Array.from({ length: 135 }, (_, i) => ({ ...fixture.window.series[0], client_id: `client-${i}`, service_key: `service-${i}`, service_label: `Service ${i}`, start_ms: start,
  bucket_ms: 50, samples: [[i === 134 ? 598_000 : i === 133 ? 595_000 : i === 132 ? 420_000 : 1000, i === 134 ? 1000 : 0, i === 134 ? 0 : 2000, 0, 0, 1, 1]],
})) as TrafficChunk[]
const index = indexDestinationVolumes(chunks, start, [{ ...fixture.window.coverage[0], start_ms: start, end_ms: end + 330_000 }] as CaptureInterval[], end + 330_000)
const source = { ...fixture.window, from_ms: start, to_ms: end + 330_000, series: chunks } as MapWindow
const scene = buildMapTimelineScene(source, fixture.manifest as SessionManifest, { latitude: 57.7, longitude: 11.9, label: 'Gateway' })
const catalog = buildMapTrackCatalog(source)
const projected = (cursorMs: number, captured: typeof index, state: WorkspaceState) => projectWorkspace(catalog, scene, captured, cursorMs, state)
const container = document.createElement('div')
document.body.append(container)
let root = createRoot(container)
let current = { cursorMs: end, index, navigationRevision: 0, state: { direction: 'both', locationId: null, expanded: true, order: 'latest' } as WorkspaceState }
const render = async (next: Partial<typeof current> = {}) => {
  current = { ...current, ...next }
  await act(() => root.render(<MapTimeline data={projected(current.cursorMs, current.index, current.state)} startMs={start} endMs={end + 330_000} {...current} onSeek={() => {}} onTrack={() => {}} loading={false} error={false} refreshing={false} live />))
}
const button = (label: string) => [...container.querySelectorAll('button')].find(node => node.textContent?.startsWith(label))!
const laneNames = () => [...container.querySelectorAll('.atlas-detail-track strong')].map(node => node.textContent)
HTMLElement.prototype.scrollTo = vi.fn(function(this: HTMLElement) { this.scrollTop = 0 })
afterEach(async () => { await act(() => root.unmount()); root = createRoot(container); current = { cursorMs: end, index, navigationRevision: 0, state: { direction: 'both', locationId: null, expanded: true, order: 'latest' } }; vi.clearAllMocks() })

it('defaults to five minutes with recent endpoints first and quieter history still visible', async () => {
  await render()
  expect(laneNames()).toEqual(['Service 134', 'Service 133', 'Service 132'])
  expect(container.querySelectorAll('.atlas-detail-row.is-active')).toHaveLength(2)
  expect(container.querySelectorAll<HTMLElement>('.atlas-detail-row')[2].style.getPropertyValue('--lane-opacity')).toBe('0.5')
  expect(container.querySelectorAll('.atlas-flow-envelope').length).toBeGreaterThan(0)
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-window-from')).toBe(String(end - 300_000))
  await render({ state: { ...current.state, direction: 'received' } })
  expect(laneNames()).toEqual(['Service 133', 'Service 132'])
  expect(container.querySelector('.atlas-detail-lane .atlas-flow-sent')).toBeNull()
})

it('holds the window while browsing and resumes from shared playback navigation', async () => {
  await render()
  await render({ state: { ...current.state, windowMs: 1_800_000 } })
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-visible-lanes')).toBe('135')
  expect(laneNames().length).toBeLessThanOrEqual(32)
  const scroll = container.querySelector<HTMLDivElement>('.atlas-detail-scroll')!
  await act(() => { scroll.scrollTop = 10_000; scroll.dispatchEvent(new Event('scroll', { bubbles: true })) })
  const heldTo = container.querySelector('.atlas-detail-timeline')?.getAttribute('data-window-to')
  const names = laneNames()
  await render({ cursorMs: end + 15_000 })
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-window-to')).toBe(heldTo)
  expect(laneNames()).toEqual(names)
  expect(container.querySelector('.atlas-detail-timeline')?.hasAttribute('data-held')).toBe(true)
  await render({ navigationRevision: current.navigationRevision + 1 })
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-visible-lanes')).toBe('135')
  expect(current.state.windowMs).toBe(1_800_000)
  expect(scroll.scrollTop).toBe(0)
  expect(container.querySelector('.atlas-detail-timeline')?.hasAttribute('data-held')).toBe(false)
})

it('uses shared history to reveal older traffic without a local selector', async () => {
  await render({ cursorMs: end + 300_000 })
  expect(laneNames()).toEqual([])
  expect(container.textContent).toContain('No traffic in this window')
  expect(button('Show all')).toBeUndefined()
  await render({ state: { ...current.state, windowMs: 1_800_000 } })
  expect(laneNames().length).toBeGreaterThan(0)
})

it('holds a keyboard-focused lane and resets browsing on a location change', async () => {
  await render()
  await act(() => container.querySelector<HTMLButtonElement>('.atlas-detail-track')!.focus())
  await render({ cursorMs: end + 10_000 })
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-window-to')).toBe(String(end))
  await render({ state: { ...current.state, locationId: '18.0686,59.3293' } })
  expect(container.querySelector('.atlas-detail-timeline')?.getAttribute('data-window-to')).toBe(String(end + 10_000))
  expect(container.querySelector('.atlas-detail-timeline')?.hasAttribute('data-held')).toBe(false)
})


it('holds ongoing lanes and animates returning traffic upward as others become quiet', async () => {
  await render()
  const quietLane = container.querySelectorAll<HTMLElement>('.atlas-detail-row')[2]
  const previousFirst = container.querySelector<HTMLElement>('.atlas-detail-row')!
  expect(quietLane.style.getPropertyValue('--lane-y')).toBe('144px')
  const renewed = { ...chunks[132], samples: [...chunks[132].samples, [600_500, 0, 5000, 0, 0, 0, 1]] } as TrafficChunk
  const updated = indexDestinationVolumes([...chunks.slice(0, 132), renewed, ...chunks.slice(133)], start, index.coverage, index.toMs)
  await render({ cursorMs: end + 1000, index: updated })
  expect(laneNames()).toEqual(['Service 134', 'Service 133', 'Service 132'])
  expect(quietLane.style.getPropertyValue('--lane-y')).toBe('144px')
  expect(quietLane.style.getPropertyValue('--lane-opacity')).toBe('1')
  await render({ cursorMs: end + 11_000 })
  expect(laneNames()).toEqual(['Service 134', 'Service 132', 'Service 133'])
  expect(quietLane.style.getPropertyValue('--lane-y')).toBe('72px')
  await render({ cursorMs: end + 14_000 })
  expect(laneNames()).toEqual(['Service 132', 'Service 134', 'Service 133'])
  expect(container.querySelector('.atlas-detail-row')).toBe(quietLane)
  expect(quietLane.style.getPropertyValue('--lane-y')).toBe('0px')
  expect(quietLane.style.getPropertyValue('--lane-opacity')).toBe('1')
  expect(previousFirst.style.getPropertyValue('--lane-y')).toBe('72px')
})

it('keeps the chosen history window when returning to live following', async () => {
  await render()
  const chart = () => container.querySelector<HTMLElement>('.atlas-detail-timeline')!
  expect(Number(chart().dataset.windowTo) - Number(chart().dataset.windowFrom)).toBe(300_000)
  await render({ state: { ...current.state, windowMs: 30_000, query: 'service' } })
  expect(laneNames()).toEqual(['Service 134', 'Service 133'])
  await act(() => container.querySelector<HTMLButtonElement>('.atlas-detail-track')!.focus())
  await render({ navigationRevision: current.navigationRevision + 1 })
  expect(Number(chart().dataset.windowTo) - Number(chart().dataset.windowFrom)).toBe(30_000)
  expect(current.state.query).toBe('service')
})

it('moves the live viewport between data publications, pauses exactly, and holds history', async () => {
  let now = 0
  let paint: FrameRequestCallback | undefined
  const clock = new MapPlaybackClock(30, { now: () => now, request: callback => { paint = callback; return 1 }, cancel: () => { paint = undefined } })
  clock.configure({ durationInFrames: 30_000, rate: 1 })
  clock.seekTo(18_000)
  const animation = { clock, playbackEpochMs: start }
  await act(() => root.render(<MapTimeline {...animation} data={projected(end, index, current.state)} startMs={start} endMs={end} cursorMs={end} index={index} state={current.state} onSeek={() => {}} onTrack={() => {}} loading={false} error={false} refreshing={false} live />))
  const chart = container.querySelector<HTMLElement>('.atlas-detail-timeline')!
  const position = () => chart.style.getPropertyValue('--timeline-offset')
  const initial = position()
  const paths = [...container.querySelectorAll('.atlas-flow-envelope')].map(path => path.getAttribute('d'))
  const advance = async (ms: number) => act(() => { now += ms; const callback = paint; paint = undefined; callback?.(now) })
  await act(() => clock.play())
  await advance(16)
  expect(position()).not.toBe(initial)
  const first = position()
  await advance(16)
  expect(position()).not.toBe(first)
  expect([...container.querySelectorAll('.atlas-flow-envelope')].map(path => path.getAttribute('d'))).toEqual(paths)
  await act(() => clock.pause())
  const paused = position()
  await advance(1000)
  expect(position()).toBe(paused)
  await act(() => clock.seekTo(17_000))
  expect(position()).not.toBe(paused)
  await act(() => container.querySelector<HTMLButtonElement>('.atlas-detail-track')!.focus())
  const held = position()
  await act(() => clock.play())
  await advance(1000)
  expect(position()).toBe(held)
  await act(() => root.unmount())
  root = createRoot(container)
  const afterUnmount = chart.getAttribute('style')
  await advance(1000)
  expect(chart.getAttribute('style')).toBe(afterUnmount)
  clock.dispose()
})

it('keeps the same sample resolution as a short live session grows', async () => {
  await render({ cursorMs: start + 47_900 })
  const resolution = container.querySelector('.atlas-detail-timeline')!.getAttribute('data-bin-ms')
  await render({ cursorMs: start + 48_100 })
  expect(container.querySelector('.atlas-detail-timeline')!.getAttribute('data-bin-ms')).toBe(resolution)
  await render({ cursorMs: start + 120_100 })
  expect(container.querySelector('.atlas-detail-timeline')!.getAttribute('data-bin-ms')).toBe(resolution)
})
