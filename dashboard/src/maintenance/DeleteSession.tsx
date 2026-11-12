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
    <button type="button" onClick={() => { setError(''); dialog.current?.showModal() }} className="rounded-lg px-3 py-2 text-sm font-semibold text-red-700 hover:bg-red-50" aria-label={`Delete ${session.name || 'Untitled session'}`}>Delete session</button>
    <dialog ref={dialog} onCancel={event => { if (busy) event.preventDefault() }} className="m-auto w-[min(32rem,calc(100%_-_2rem))] rounded-2xl border border-slate-200 bg-white p-6 text-slate-950 shadow-xl backdrop:bg-slate-950/50" aria-labelledby={`delete-title-${session.id}`}>
      <h2 id={`delete-title-${session.id}`} className="text-xl font-bold">Delete “{session.name || 'Untitled session'}”?</h2>
      <p className="mt-3 text-sm text-slate-600">Permanently removes this session’s traffic, activity blocks, route evidence and diagnostics. This cannot be undone.</p>
      {session.active && !session.simulation_expires_ms && <p className="mt-3 rounded-lg bg-amber-50 p-3 text-sm text-amber-900">This session is live. A new empty live session will start so observation can continue.</p>}
      <p className="mt-3 text-sm text-slate-600">Deleted data frees space for reuse inside the database. The database file may stay the same size.</p>
      {error && <p role="alert" className="mt-3 text-sm text-red-700">{error}</p>}
      <div className="mt-6 flex justify-end gap-3">
        <button type="button" disabled={busy} onClick={() => dialog.current?.close()} className="rounded-lg border border-slate-300 px-4 py-2 font-semibold disabled:opacity-50">Cancel</button>
        <button type="button" disabled={busy} onClick={() => void remove()} className="rounded-lg bg-red-700 px-4 py-2 font-semibold text-white disabled:opacity-50">{busy ? 'Deleting…' : 'Permanently delete'}</button>
      </div>
    </dialog>
  </>
}
