/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_GATEWAY_LAT?: string
  readonly VITE_GATEWAY_LON?: string
  readonly VITE_GATEWAY_LABEL?: string
  readonly VITE_MAP_STYLE_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
