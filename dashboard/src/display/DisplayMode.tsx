import { useEffect, useState, useSyncExternalStore } from 'react'
import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { baseUrl } from '@infrareveal/session-state'
import { DisplayModeClient } from './DisplayModeClient'
import { DisplayModeContext, useDisplayMode } from './useDisplayMode'
import './display.css'

export function DisplayModeProvider({ children }: { children: ReactNode }) {
  const [client] = useState(() => new DisplayModeClient(baseUrl, sessionStorage))
  const state = useSyncExternalStore(client.subscribe, client.snapshot)
  const navigate = useNavigate()
  useEffect(() => {
    const disconnect = client.connect()
    const wake = () => { if (document.visibilityState === 'visible') client.wake() }
    window.addEventListener('online', client.wake)
    document.addEventListener('visibilitychange', wake)
    return () => { disconnect(); window.removeEventListener('online', client.wake); document.removeEventListener('visibilitychange', wake) }
  }, [client])

  const blocked = state.phase === 'checking' || state.phase === 'stopping' || state.phase === 'ended'
    || state.phase === 'reconnecting' && !state.expiresAt
  const showing = state.phase === 'active' || state.phase === 'reconnecting'
  return <DisplayModeContext.Provider value={{ client, state }}>
    <div className={showing && !blocked ? 'display-mode-layout' : undefined}>
      {showing && !blocked ? <aside className="display-mode-bar" aria-label="Display mode">
        <span role="status">{state.error || 'Display mode · This device’s internet activity is excluded.'}</span>
        <button type="button" onClick={() => { void client.stop().then(stopped => { if (stopped) navigate('/') }) }}>Stop display mode</button>
      </aside> : null}
      {blocked ? <main className="display-mode-wait"><DisplayModeCard /></main> : children}
    </div>
  </DisplayModeContext.Provider>
}

export function DisplayModeCard() {
  const { client, state } = useDisplayMode()
  const navigate = useNavigate()
  const busy = state.phase === 'checking' || state.phase === 'stopping'
  const active = state.phase === 'active' || state.phase === 'reconnecting'
  return <section className="display-mode-card" aria-labelledby="display-mode-title">
    <p className="display-mode-eyebrow">One Wi-Fi. Any screen.</p>
    <h2 id="display-mode-title">Use this device as the display</h2>
    <p>Follow participant activity without including this device’s map downloads, browsing or background updates.</p>
    {state.error ? <p className="display-mode-error" role="alert">{state.error}</p> : null}
    <div className="display-mode-actions">
      {active ? <button type="button" onClick={() => { if (state.expiresAt) navigate('/display'); else client.wake() }}>{state.expiresAt ? 'Open display' : 'Retry connection'}</button>
        : <button type="button" disabled={busy} onClick={() => { void client.start().then(started => { if (started) navigate('/display') }) }}>
          {state.phase === 'stopping' ? 'Stopping display mode…' : busy ? 'Connecting display…' : 'Use this device as display'}
        </button>}
      {(active || state.phase === 'ended') ? <button type="button" className="display-mode-secondary" onClick={() => { void client.stop().then(stopped => { if (stopped) navigate('/') }) }}>Stop display mode</button> : null}
    </div>
    <small>Excludes this whole device from now on. Earlier recordings stay unchanged. Closing the dashboard ends display mode after three minutes.</small>
  </section>
}
