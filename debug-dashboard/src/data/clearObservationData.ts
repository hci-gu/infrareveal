import { clearGatewayData, type ClearGatewayDataResult } from './pocketbaseClient'

type ClearObservationDataDependencies = {
  clearActivityCache: () => void
  refreshGatewayData: () => void
  requestClear?: () => Promise<ClearGatewayDataResult>
}

export async function clearObservationData({
  clearActivityCache,
  refreshGatewayData,
  requestClear = clearGatewayData,
}: ClearObservationDataDependencies) {
  const result = await requestClear()
  clearActivityCache()
  refreshGatewayData()
  return result
}
