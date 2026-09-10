import { useRef } from 'react'

export function Splitter({ label, axis, value, min, max, onChange }: {
  label: string; axis: 'horizontal' | 'vertical'; value: number; min: number; max: number; onChange: (value: number) => void
}) {
  const drag = useRef<{ point: number; value: number } | null>(null)
  const change = (next: number) => onChange(Math.round(Math.max(min, Math.min(max, next))))
  return <div className={`ui-splitter ${axis}`} role="separator" tabIndex={0} aria-label={label}
    aria-orientation={axis} aria-valuenow={value} aria-valuemin={min} aria-valuemax={max}
    onPointerDown={event => { if (event.button !== 0) return; event.preventDefault(); event.currentTarget.setPointerCapture(event.pointerId); drag.current = { point: axis === 'vertical' ? event.clientX : event.clientY, value } }}
    onPointerMove={event => { if (drag.current) change(drag.current.value + drag.current.point - (axis === 'vertical' ? event.clientX : event.clientY)) }}
    onPointerUp={() => { drag.current = null }} onPointerCancel={() => { drag.current = null }}
    onKeyDown={event => { const negative = axis === 'vertical' ? 'ArrowRight' : 'ArrowDown'; const positive = axis === 'vertical' ? 'ArrowLeft' : 'ArrowUp'; if (event.key === negative || event.key === positive) { event.preventDefault(); event.stopPropagation(); change(value + (event.key === negative ? -10 : 10)) } }} />
}
