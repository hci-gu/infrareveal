import { AlertTriangle, CheckCircle2, CircleHelp, XCircle } from 'lucide-react'
import type { ActivityDataQuality as ActivityDataQualityModel, DataQualityLevel } from '../model/activityDataQuality'

export function ActivityDataQuality({ quality }: { quality: ActivityDataQualityModel }) {
  const Icon = quality.level === 'complete'
    ? CheckCircle2
    : quality.level === 'unavailable'
      ? XCircle
      : quality.level === 'partial'
        ? AlertTriangle
        : CircleHelp
  return (
    <section aria-label="Activity data quality" className="border-t border-slate-800 bg-slate-950/80 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs">
        <div className="flex min-w-48 items-center gap-2">
          <Icon aria-hidden className={levelColor(quality.level)} size={17} />
          <span className="font-semibold text-slate-200">Activity data quality</span>
          <span className={`border px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase ${levelBadge(quality.level)}`}>{quality.label}</span>
        </div>
        <QualityPart label="Capture" level={quality.capture.level} title={quality.capture.detail} value={quality.capture.label} />
        <QualityPart label="Live stream" level={quality.stream.level} title={quality.stream.detail} value={quality.stream.label} />
        <div className="ml-auto flex items-center gap-3 text-[10px] text-slate-500" aria-label="Timeline quality legend">
          <Legend color="bg-amber-500" label="capture partial" />
          <Legend color="bg-rose-500" label="capture unavailable" />
          <Legend color="bg-violet-400" label="live stream gap" narrow />
        </div>
      </div>
    </section>
  )
}

function QualityPart({ label, level, title, value }: {
  label: string
  level: DataQualityLevel
  title: string
  value: string
}) {
  return (
    <span className="inline-flex items-center gap-1.5" title={title}>
      <span className="text-slate-500">{label}</span>
      <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${levelDot(level)}`} />
      <strong className={levelColor(level)}>{value}</strong>
    </span>
  )
}

function Legend({ color, label, narrow = false }: { color: string; label: string; narrow?: boolean }) {
  return <span className="inline-flex items-center gap-1"><span aria-hidden className={`${color} ${narrow ? 'h-2.5 w-0.5' : 'h-1.5 w-3'}`} />{label}</span>
}

function levelColor(level: DataQualityLevel) {
  if (level === 'complete') return 'text-emerald-300'
  if (level === 'partial') return 'text-amber-300'
  if (level === 'unavailable') return 'text-rose-300'
  return 'text-slate-400'
}

function levelDot(level: DataQualityLevel) {
  if (level === 'complete') return 'bg-emerald-400'
  if (level === 'partial') return 'bg-amber-400'
  if (level === 'unavailable') return 'bg-rose-400'
  return 'bg-slate-500'
}

function levelBadge(level: DataQualityLevel) {
  if (level === 'complete') return 'border-emerald-800 bg-emerald-950 text-emerald-300'
  if (level === 'partial') return 'border-amber-800 bg-amber-950 text-amber-300'
  if (level === 'unavailable') return 'border-rose-800 bg-rose-950 text-rose-300'
  return 'border-slate-700 bg-slate-900 text-slate-400'
}
