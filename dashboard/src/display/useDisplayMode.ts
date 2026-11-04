import { createContext, useContext } from 'react'
import type { DisplayModeClient, DisplayState } from './DisplayModeClient'

export const DisplayModeContext = createContext<{ client: DisplayModeClient; state: DisplayState } | null>(null)
export function useDisplayMode() {
  const context = useContext(DisplayModeContext)
  if (!context) throw new Error('DisplayModeProvider is missing')
  return context
}
