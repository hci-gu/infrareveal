const SECOND = 1000, MINUTE = 60 * SECOND, HOUR = 60 * MINUTE
const STEPS = [5 * SECOND, 10 * SECOND, 15 * SECOND, 30 * SECOND, MINUTE, 2 * MINUTE, 5 * MINUTE, 10 * MINUTE, 15 * MINUTE, 30 * MINUTE, HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, 24 * HOUR]

export type TimelineTick = { time: number; fraction: number }

/** Round clock times ("13:05, 13:10…") instead of arbitrary quarter points, so
 * labels read like a real time axis. Times are aligned in local time. */
export function timelineTicks(from: number, to: number, maxTicks = 6): { step: number; ticks: TimelineTick[] } {
  const span = to - from
  if (!(span > 0) || maxTicks < 1) return { step: 0, ticks: [] }
  const step = STEPS.find(value => span / value <= maxTicks) ?? STEPS[STEPS.length - 1]
  const offset = new Date(from).getTimezoneOffset() * MINUTE
  const ticks: TimelineTick[] = []
  for (let time = Math.ceil((from - offset) / step) * step + offset; time <= to; time += step) {
    ticks.push({ time, fraction: (time - from) / span })
  }
  return { step, ticks }
}
