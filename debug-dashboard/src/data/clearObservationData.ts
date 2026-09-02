import { clearGatewayData, type ClearGatewayDataResult } from '@infrareveal/session-state'

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
