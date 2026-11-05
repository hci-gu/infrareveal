import { useEffect, useState } from 'react'

export type MapPreferences = { projection: 'equal-earth' | 'mercator'; theme: 'dark' | 'light' | 'system'; labels: boolean }
export const defaultMapPreferences: MapPreferences = { projection: 'equal-earth', theme: 'dark', labels: true }
export const MAP_PREFERENCES_KEY = 'infrareveal.map.display.v1'
export function parseMapPreferences(value: string | null): MapPreferences {
  try {
    const parsed = JSON.parse(value ?? '{}') ?? {}
    return {
      projection: parsed.projection === 'mercator' ? 'mercator' : 'equal-earth',
      theme: ['dark', 'light', 'system'].includes(parsed.theme) ? parsed.theme : 'dark',
      labels: typeof parsed.labels === 'boolean' ? parsed.labels : true,
    }
  } catch { return { ...defaultMapPreferences } }
}
export function useMapPreferences() {
  const [preferences, setPreferences] = useState(() => {
    try { return parseMapPreferences(localStorage.getItem(MAP_PREFERENCES_KEY)) } catch { return { ...defaultMapPreferences } }
  })
  const [systemLight, setSystemLight] = useState(() => matchMedia('(prefers-color-scheme: light)').matches)
  useEffect(() => {
    const media = matchMedia('(prefers-color-scheme: light)')
    const update = () => setSystemLight(media.matches)
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])
  useEffect(() => { try { localStorage.setItem(MAP_PREFERENCES_KEY, JSON.stringify(preferences)) } catch { /* Private browsing may disable storage. */ } }, [preferences])
  return { preferences, setPreferences, theme: preferences.theme === 'system' ? systemLight ? 'light' as const : 'dark' as const : preferences.theme }
}
