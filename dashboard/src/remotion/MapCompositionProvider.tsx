import { createContext, useContext } from 'react'
import type { ReactNode } from 'react'
import { MapComposition } from './MapComposition'
import type { MapCompositionProps } from './MapComposition'

const MapDataContext = createContext<MapCompositionProps | null>(null)

/** Data revisions must not replace Remotion's video config and restart its clock. */
export function MapCompositionProvider({ value, children }: { value: MapCompositionProps; children: ReactNode }) {
  return <MapDataContext.Provider value={value}>{children}</MapDataContext.Provider>
}

export function MapCompositionFromContext() {
  const props = useContext(MapDataContext)
  if (!props) throw new Error('MapCompositionProvider is required')
  return <MapComposition {...props} />
}
