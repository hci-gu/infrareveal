import { useRef, useState } from 'react'
import { updateSession } from '@infrareveal/session-state'
import type { Session } from '@infrareveal/session-state'

export function DeleteSession({ session, onDeleted }: { session: Session; onDeleted: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const remove = async () => {
    setBusy(true); setError('')
    try {
      await updateSession(session.id, 'DELETE')
      dialog.current?.close()
      onDeleted()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not delete session') }
    finally { setBusy(false) }
  }
  return <>
    <button type="button" onClick={() => { setError(''); dialog.current?.showModal() }} className="h-9 whitespace-nowrap rounded-card px-3 text-sm font-semibold text-error hover:bg-error-paper active:bg-paper-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus" aria-label={`Delete ${session.name || 'Untitled session'}`}>Delete session</button>
    <dialog ref={dialog} onCancel={event => { if (busy) event.preventDefault() }} className="m-auto w-[min(32rem,calc(100%_-_2rem))] rounded-panel border border-rule-2 bg-paper-2 p-6 text-ink backdrop:bg-scrim" aria-labelledby={`delete-title-${session.id}`}>
      <h2 id={`delete-title-${session.id}`} className="text-lg font-semibold">Delete “{session.name || 'Untitled session'}”?</h2>
      <p className="mt-3 text-sm text-muted">Permanently removes this session’s traffic, activity blocks, route evidence and diagnostics. This cannot be undone.</p>
      {session.active && !session.simulation_expires_ms && <p className="mt-3 border-l-2 border-warn pl-3 text-sm text-warn">This session is live. A new empty live session will start so observation can continue.</p>}
      <p className="mt-3 text-sm text-muted">Deleted data frees space for reuse inside the database. The database file may stay the same size.</p>
      {error && <p role="alert" className="mt-3 text-sm text-error">{error}</p>}
      <div className="mt-6 flex justify-end gap-3">
        <button type="button" disabled={busy} onClick={() => dialog.current?.close()} className="h-9 rounded-card border border-field-edge px-4 text-sm font-semibold text-ink hover:bg-paper-3 active:bg-paper focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus disabled:cursor-not-allowed disabled:text-faint disabled:opacity-60">Cancel</button>
        <button type="button" disabled={busy} onClick={() => void remove()} className="h-9 rounded-card bg-error px-4 text-sm font-semibold text-paper hover:brightness-110 active:brightness-95 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus disabled:cursor-not-allowed disabled:opacity-60">{busy ? 'Deleting…' : 'Permanently delete'}</button>
      </div>
    </dialog>
  </>
}
