import { describe, expect, it, vi } from 'vitest'
import { clearObservationData } from './clearObservationData'

describe('clearObservationData', () => {
  it('invalidates both gateway data and the separately cached flow activity range', async () => {
    const clearActivityCache = vi.fn()
    const refreshGatewayData = vi.fn()
    const result = { deleted: { flows: 2, flow_activity_chunks: 3 }, skipped: [] }

    await expect(clearObservationData({
      clearActivityCache,
      refreshGatewayData,
      requestClear: async () => result,
    })).resolves.toBe(result)

    expect(clearActivityCache).toHaveBeenCalledOnce()
    expect(refreshGatewayData).toHaveBeenCalledOnce()
  })

  it('keeps existing caches intact when the server clear fails', async () => {
    const clearActivityCache = vi.fn()
    const refreshGatewayData = vi.fn()

    await expect(clearObservationData({
      clearActivityCache,
      refreshGatewayData,
      requestClear: async () => { throw new Error('clear failed') },
    })).rejects.toThrow('clear failed')

    expect(clearActivityCache).not.toHaveBeenCalled()
    expect(refreshGatewayData).not.toHaveBeenCalled()
  })
})
