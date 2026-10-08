import { describe, expect, it, vi } from 'vitest'
import { UniformStore } from '@luma.gl/core'
import type { Device } from '@luma.gl/core'

describe('rendering library uniform uploads', () => {
  it('uploads only blocks whose values changed, including in-place typed-array edits', () => {
    const writes = [vi.fn(), vi.fn()]
    let buffer = 0
    const device = { type: 'webgl', createBuffer: () => ({ write: writes[buffer++] }) } as unknown as Device
    const store = new UniformStore(device, {
      project: { uniformTypes: { scale: 'f32', origin: 'vec3<f32>' } },
      traffic: { uniformTypes: { clock: 'f32' } },
    })
    store.getManagedUniformBuffer('project')
    store.getManagedUniformBuffer('traffic')
    const origin = new Float32Array([1, 2, 3])
    store.setUniforms({ project: { scale: 2, origin }, traffic: { clock: 1 } })
    expect(writes.map(write => write.mock.calls.length)).toEqual([1, 1])
    // Models resubmit every module on each draw, even when only time changed.
    store.setUniforms({ project: { scale: 2, origin }, traffic: { clock: 2 } })
    expect(writes.map(write => write.mock.calls.length)).toEqual([1, 2])
    origin[0] = 4
    store.setUniforms({ project: { scale: 2, origin }, traffic: { clock: 2 } })
    expect(writes.map(write => write.mock.calls.length)).toEqual([2, 2])
    store.setUniforms({ project: { scale: 2, origin: [4, 2, 3] }, traffic: { clock: 2 } })
    expect(writes.map(write => write.mock.calls.length)).toEqual([2, 2])
    store.setUniforms({ project: { scale: 3 }, traffic: { clock: 2 } })
    expect(writes.map(write => write.mock.calls.length)).toEqual([3, 2])
  })
})
