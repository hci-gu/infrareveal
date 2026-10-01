import MapLibre from 'react-map-gl/maplibre'
import type { MapProps } from 'react-map-gl/maplibre'
import { setWorkerUrl } from 'maplibre-gl'
// Bundle worker imports; the plain URL entry is not a complete production worker.
import workerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url'
import 'maplibre-gl/dist/maplibre-gl.css'

setWorkerUrl(workerUrl)
export default function TiledBasemap(props: MapProps) { return <MapLibre {...props} /> }
