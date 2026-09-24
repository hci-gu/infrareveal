import type { StyleSpecification } from 'maplibre-gl'

/** A deliberately quiet, token-free basemap. Network data owns the accent colors. */
export const atlasStyle: StyleSpecification = {
  version: 8,
  name: 'InfraReveal · Night atlas',
  glyphs: 'https://tiles.openfreemap.org/fonts/{fontstack}/{range}.pbf',
  sources: {
    earth: { type: 'vector', url: 'https://tiles.openfreemap.org/planet' },
  },
  layers: [
    { id: 'land', type: 'background', paint: { 'background-color': '#192a35' } },
    {
      id: 'water', type: 'fill', source: 'earth', 'source-layer': 'water',
      filter: ['!=', ['get', 'brunnel'], 'tunnel'],
      paint: { 'fill-color': '#0b1822' },
    },
    {
      id: 'coastline', type: 'line', source: 'earth', 'source-layer': 'water',
      paint: { 'line-color': '#2a414d', 'line-width': 0.65, 'line-opacity': 0.55 },
    },
    {
      id: 'parks', type: 'fill', source: 'earth', 'source-layer': 'landcover', minzoom: 6,
      filter: ['==', ['get', 'class'], 'wood'],
      paint: { 'fill-color': '#203b3c', 'fill-opacity': 0.3 },
    },
    {
      id: 'regional-boundaries', type: 'line', source: 'earth', 'source-layer': 'boundary', minzoom: 4,
      filter: ['all', ['>=', ['get', 'admin_level'], 3], ['<=', ['get', 'admin_level'], 6], ['!=', ['get', 'maritime'], 1]],
      paint: { 'line-color': '#344a55', 'line-width': 0.5, 'line-opacity': 0.5 },
    },
    {
      id: 'country-boundaries', type: 'line', source: 'earth', 'source-layer': 'boundary',
      filter: ['all', ['==', ['get', 'admin_level'], 2], ['!=', ['get', 'maritime'], 1], ['!=', ['get', 'disputed'], 1]],
      paint: { 'line-color': '#3a505a', 'line-width': 0.7, 'line-opacity': 0.65 },
    },
    {
      id: 'disputed-boundaries', type: 'line', source: 'earth', 'source-layer': 'boundary',
      filter: ['all', ['==', ['get', 'disputed'], 1], ['!=', ['get', 'maritime'], 1]],
      paint: { 'line-color': '#3a505a', 'line-width': 0.7, 'line-dasharray': [3, 3] },
    },
    {
      id: 'roads', type: 'line', source: 'earth', 'source-layer': 'transportation', minzoom: 6,
      filter: ['match', ['get', 'class'], ['motorway', 'trunk', 'primary', 'secondary'], true, false],
      paint: { 'line-color': '#35444c', 'line-width': ['interpolate', ['linear'], ['zoom'], 6, 0.3, 14, 1.6], 'line-opacity': 0.55 },
    },
    {
      id: 'buildings', type: 'fill', source: 'earth', 'source-layer': 'building', minzoom: 12,
      paint: { 'fill-color': '#263c48', 'fill-outline-color': '#344a55' },
    },
    {
      id: 'country-labels', type: 'symbol', source: 'earth', 'source-layer': 'place',
      filter: ['==', ['get', 'class'], 'country'],
      layout: {
        'text-field': ['coalesce', ['get', 'name:en'], ['get', 'name:latin'], ['get', 'name']],
        'text-font': ['Noto Sans Regular'], 'text-transform': 'uppercase',
        'text-letter-spacing': 0.16, 'text-max-width': 8,
        'text-size': ['interpolate', ['linear'], ['zoom'], 1, 9, 5, 12],
      },
      paint: { 'text-color': '#789099', 'text-halo-color': '#192a35', 'text-halo-width': 1.5, 'text-opacity': 0.85 },
    },
    {
      id: 'city-labels', type: 'symbol', source: 'earth', 'source-layer': 'place', minzoom: 4,
      filter: ['match', ['get', 'class'], ['city', 'town'], true, false],
      layout: {
        'text-field': ['coalesce', ['get', 'name:en'], ['get', 'name:latin'], ['get', 'name']],
        'text-font': ['Noto Sans Regular'], 'text-size': ['interpolate', ['linear'], ['zoom'], 4, 10, 12, 13],
        'text-padding': 12,
      },
      paint: { 'text-color': '#92a5ac', 'text-halo-color': '#192a35', 'text-halo-width': 1.5 },
    },
  ],
}

/** Theme the built-in style; an explicitly configured external style remains provider-owned. */
export function themedAtlasStyle(style: string | StyleSpecification, theme: 'dark' | 'light', labels: boolean): string | StyleSpecification {
  if (typeof style === 'string') return style
  const light: Record<string, string> = {
    '#192a35': '#dce8df', '#0b1822': '#eef3ef', '#2a414d': '#a7bbb3', '#203b3c': '#c5dec5',
    '#344a55': '#a8beb3', '#3a505a': '#96ada2', '#35444c': '#b0bcb3', '#263c48': '#cedbd2',
    '#789099': '#526f69', '#92a5ac': '#405e59',
  }
  return { ...style, layers: style.layers.map(layer => ({ ...layer,
    ...(layer.type === 'symbol' ? { layout: { ...layer.layout, visibility: labels ? 'visible' as const : 'none' as const } } : {}),
    ...('paint' in layer ? { paint: Object.fromEntries(Object.entries(layer.paint ?? {}).map(([key, value]) => [key, theme === 'light' && typeof value === 'string' ? light[value] ?? value : value])) } : {}),
  })) as StyleSpecification['layers'] }
}
