import { describe, expect, it, vi } from 'vitest'
import { Layer, WebMercatorViewport } from '@deck.gl/core'
import type { EffectContext, PreRenderOptions } from '@deck.gl/core'
import { MercatorBackground } from './MercatorBackground'

class TestLayer extends Layer { initializeState() {} }

const render = vi.hoisted(() => vi.fn())
vi.mock('@deck.gl/core', async importOriginal => ({
  ...await importOriginal<typeof import('@deck.gl/core')>(),
  _LayersPass: class { render = render; cleanup() {} },
}))

function harness() {
  render.mockClear()
  let size = [800, 600]
  const framebuffer = { width: 800, height: 600, destroy: vi.fn(), resize: vi.fn(({ width, height }) => {
    framebuffer.width = width; framebuffer.height = height
  }) }
  const createFramebuffer = vi.fn(() => framebuffer)
  const cache = new MercatorBackground()
  cache.setup({ device: { canvasContext: { getDrawingBufferSize: () => size }, createFramebuffer } } as unknown as EffectContext)
  const ground = new TestLayer({ id: 'base-geography' }), traffic = new TestLayer({ id: 'traffic-streams' })
  Object.defineProperty(ground, 'isLoaded', { value: true, configurable: true })
  const options: PreRenderOptions = { pass: 'screen', layers: [ground, traffic], viewports: [new WebMercatorViewport({ width: 800, height: 600, zoom: 2 })] }
  return { cache, options, ground, traffic, framebuffer, createFramebuffer, resize: () => { size = [1000, 700] } }
}

describe('Mercator background caching', () => {
  it('reuses a frame across traffic paints, and refreshes data, camera, size and visibility changes', () => {
    const h = harness()
    h.cache.preRender(h.options)
    expect(render).toHaveBeenCalledTimes(1)
    expect(render.mock.calls[0][0].layers).toEqual([h.ground])
    h.cache.preRender({ ...h.options, layers: [h.ground, new TestLayer({ id: 'traffic-streams' })] })
    expect(render).toHaveBeenCalledTimes(1)
    const next = new TestLayer({ id: 'country-footprints' })
    Object.defineProperty(next, 'isLoaded', { value: true })
    h.options.layers.push(next)
    h.cache.preRender(h.options)
    expect(render).toHaveBeenCalledTimes(2)
    h.options.viewports = [new WebMercatorViewport({ width: 800, height: 600, zoom: 3, pitch: 35 })]
    h.cache.preRender(h.options)
    expect(render).toHaveBeenCalledTimes(3)
    h.resize(); h.cache.preRender(h.options)
    expect(render).toHaveBeenCalledTimes(4)
    h.options.layers = [h.ground]
    h.cache.preRender(h.options)
    expect(render).toHaveBeenCalledTimes(5)
    expect(h.createFramebuffer).toHaveBeenCalledTimes(1)
    h.cache.cleanup()
    expect(h.framebuffer.destroy).toHaveBeenCalledTimes(1)
  })

  it('retains live picking geometry and does not reuse an unfinished texture', () => {
    const h = harness()
    expect(h.cache.filter({ layer: h.ground, isPicking: false })).toBe(false)
    expect(h.cache.filter({ layer: h.ground, isPicking: true })).toBe(true)
    expect(h.cache.filter({ layer: h.traffic, isPicking: false })).toBe(true)
    expect(h.cache.filter({ layer: new TestLayer({ id: 'cached-background' }), isPicking: true })).toBe(false)
    Object.defineProperty(h.ground, 'isLoaded', { value: false, configurable: true })
    h.cache.preRender(h.options)
    h.cache.preRender(h.options)
    expect(render).toHaveBeenCalledTimes(2)
    Object.defineProperty(h.ground, 'isLoaded', { value: true })
    h.cache.preRender(h.options)
    h.cache.preRender(h.options)
    expect(render).toHaveBeenCalledTimes(3)
    h.cache.preRender({ ...h.options, isPicking: true })
    expect(render).toHaveBeenCalledTimes(3)
  })
})
