import type { GatewayOrigin } from './map/mapModel'

const DEFAULT_GATEWAY_LATITUDE = 57.69226
const DEFAULT_GATEWAY_LONGITUDE = 11.91737

export const gatewayOrigin: GatewayOrigin = {
  latitude: coordinate(import.meta.env.VITE_GATEWAY_LAT, DEFAULT_GATEWAY_LATITUDE, -90, 90),
  longitude: coordinate(import.meta.env.VITE_GATEWAY_LON, DEFAULT_GATEWAY_LONGITUDE, -180, 180),
  label: import.meta.env.VITE_GATEWAY_LABEL?.trim() || 'InfraReveal gateway',
}

export const mapStyleUrl = import.meta.env.VITE_MAP_STYLE_URL?.trim()
  || 'https://tiles.openfreemap.org/styles/positron'

function coordinate(value: string | undefined, fallback: number, minimum: number, maximum: number) {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed >= minimum && parsed <= maximum ? parsed : fallback
}
