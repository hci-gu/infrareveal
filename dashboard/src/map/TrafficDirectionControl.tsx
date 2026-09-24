import type { TrafficDirection } from './mapWorkspace'
export function TrafficDirectionControl({ value, onChange }: { value: TrafficDirection; onChange: (value: TrafficDirection) => void }) {
  return <div className="atlas-segmented atlas-direction" aria-label="Traffic direction">
    <button type="button" aria-pressed={value === 'both'} onClick={() => onChange('both')}>Both</button>
    <button type="button" aria-pressed={value === 'received'} onClick={() => onChange('received')}><span className="atlas-down">↓</span> Downloaded</button>
    <button type="button" aria-pressed={value === 'sent'} onClick={() => onChange('sent')}><span className="atlas-up">↑</span> Sent</button>
  </div>
}
