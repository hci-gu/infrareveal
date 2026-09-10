import { useState } from 'react'
import { Copy } from 'lucide-react'

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [message, setMessage] = useState('')
  return <span className="ui-copy"><button type="button" title={label} aria-label={label} onClick={async () => {
    try { await navigator.clipboard.writeText(value); setMessage('Copied') } catch { setMessage('Copy unavailable') }
  }}><Copy size={13} /></button><span role="status">{message}</span></span>
}
