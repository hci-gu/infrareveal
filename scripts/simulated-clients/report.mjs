import { mkdirSync, openSync, writeSync, closeSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { freemem, loadavg, totalmem } from 'node:os'
import { command } from './process.mjs'

export function artifactWriter(path) {
  const directory = resolve(path)
  mkdirSync(dirname(directory), { recursive: true })
  mkdirSync(directory, { mode: 0o700 }) // Refuse to overwrite an earlier run.
  const fd = openSync(join(directory, 'events.ndjson'), 'wx', 0o600)
  let closed = false
  return {
    directory,
    event: (type, value = {}) => { if (!closed) writeSync(fd, JSON.stringify({ at: new Date().toISOString(), type, ...value }) + '\n') },
    json: (name, value) => writeFileSync(join(directory, name), JSON.stringify(value, null, 2) + '\n', { mode: 0o600 }),
    close: () => { if (!closed) { closed = true; closeSync(fd) } },
  }
}

export function newStats(id, profile) {
  return { id, profile, started: false, operations: 0, successes: 0, failures: 0, cancelled: 0,
    receivedBytes: 0, sentBytes: 0, resourceResponses: 0, resourceFailures: 0, resourceHttpErrors: 0,
    latencyMs: [], localIPs: new Set(), remoteIPs: new Set(), protocols: new Set() }
}

export function record(stats, result) {
  stats.operations++
  stats[result.ok ? 'successes' : 'failures']++
  stats.receivedBytes += result.receivedBytes || 0
  stats.sentBytes += result.sentBytes || 0
  if (Number.isFinite(result.elapsedMs)) {
    stats.latencyMs.push(result.elapsedMs)
    if (stats.latencyMs.length > 2048) stats.latencyMs.shift()
  }
  if (result.localIP) stats.localIPs.add(result.localIP)
  if (result.remoteIP && stats.remoteIPs.size < 1024) stats.remoteIPs.add(result.remoteIP)
  if (result.protocol) stats.protocols.add(result.protocol)
}

export function summarize(stats) {
  const { latencyMs, localIPs, remoteIPs, protocols, ...rest } = stats
  const sorted = [...latencyMs].sort((a, b) => a - b)
  const percentile = n => sorted.length ? sorted[Math.ceil(sorted.length * n) - 1] : null
  return { ...rest, localIPs: [...localIPs], remoteIPs: [...remoteIPs], protocols: [...protocols],
    latency: { samples: sorted.length, scope: 'last 2048 operations per client', p50Ms: percentile(.5), p95Ms: percentile(.95), p99Ms: percentile(.99) } }
}

export async function resources() {
  const result = await command('ps', ['-axo', 'pid=,ppid=,%cpu=,rss='], { timeout: 3000 })
  const rows = result.stdout.trim().split('\n').map(line => line.trim().split(/\s+/).map(Number))
  const descendants = new Set([process.pid])
  let added = true
  while (added) { added = false; for (const [pid, parent] of rows) if (descendants.has(parent) && !descendants.has(pid)) { descendants.add(pid); added = true } }
  const owned = rows.filter(([pid]) => descendants.has(pid))
  return { generatorRssBytes: owned.reduce((sum, row) => sum + row[3] * 1024, 0),
    generatorCpuPercentPs: owned.reduce((sum, row) => sum + row[2], 0), processCount: owned.length,
    hostLoad: loadavg(), hostFreeBytes: freemem(), hostTotalBytes: totalmem() }
}
