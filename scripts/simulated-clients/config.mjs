import { readFile } from 'node:fs/promises'
import { isIP } from 'node:net'

export function integer(value, label, min, max) {
  const number = Number(value)
  if (!Number.isInteger(number) || number < min || number > max) throw new Error(`${label} must be an integer from ${min} to ${max}`)
  return number
}

function keys(object, allowed, label) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) throw new Error(`${label} must be an object`)
  for (const key of Object.keys(object)) if (!allowed.includes(key)) throw new Error(`Unknown ${label} field: ${key}`)
}

export function loopback(host) {
  return host === '127.0.0.1' || host === '[::1]'
}

export function target(value, localOnly = false) {
  const url = new URL(value)
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Targets must be HTTP(S) URLs without credentials')
  if (localOnly && !loopback(url.hostname)) throw new Error('--local-only accepts literal loopback targets only')
  if (url.hostname.endsWith('.invalid')) throw new Error(`Replace the placeholder target: ${url.origin}`)
  return url.href
}

function range(value, fallback, label) {
  const result = value ?? fallback
  if (!Array.isArray(result) || result.length !== 2 || result.some(n => !Number.isFinite(n) || n < 0.1 || n > 3600) || result[0] > result[1]) {
    throw new Error(`${label} must be [minimum, maximum] seconds, between 0.1 and 3600`)
  }
  return result
}

export async function readScenario(path, { localOnly = false, allowPlaceholders = false } = {}) {
  const config = JSON.parse(await readFile(path, 'utf8'))
  keys(config, ['version', 'name', 'profiles'], 'scenario')
  if (config.version !== 1 || typeof config.name !== 'string' || !config.name.trim()) throw new Error('Scenario needs version: 1 and a name')
  if (!Array.isArray(config.profiles) || !config.profiles.length || config.profiles.length > 20) throw new Error('Provide 1–20 profiles')
  const names = new Set()
  return { version: 1, name: config.name, profiles: config.profiles.map((p) => {
    keys(p, ['name', 'kind', 'weight', 'urls', 'pauseSeconds', 'dwellSeconds', 'timeoutSeconds', 'rateBytesPerSecond', 'uploadBytes'], 'profile')
    if (typeof p.name !== 'string' || !p.name || names.has(p.name)) throw new Error('Profile names must be nonempty and unique')
    names.add(p.name)
    if (!['browser', 'download', 'poll', 'upload'].includes(p.kind)) throw new Error(`Unknown profile kind: ${p.kind}`)
    if (!Array.isArray(p.urls) || !p.urls.length || p.urls.length > 100) throw new Error(`${p.name} needs 1–100 URLs`)
    const urls = p.urls.map(url => {
      if (allowPlaceholders && !localOnly && new URL(url).hostname.endsWith('.invalid')) {
        // Plan can describe a template; check/run always reject placeholders.
        target(url.replace(new URL(url).hostname, 'example.com'))
        return url
      }
      return target(url, localOnly)
    })
    return {
      name: p.name, kind: p.kind, urls,
      weight: integer(p.weight ?? 1, 'weight', 1, 100),
      pauseSeconds: range(p.pauseSeconds, [5, 15], 'pauseSeconds'),
      dwellSeconds: range(p.dwellSeconds, [20, 45], 'dwellSeconds'),
      timeoutSeconds: integer(p.timeoutSeconds ?? 30, 'timeoutSeconds', 1, 120),
      rateBytesPerSecond: integer(p.rateBytesPerSecond ?? 262144, 'rateBytesPerSecond', 1024, 10485760),
      uploadBytes: p.kind === 'upload' ? integer(p.uploadBytes, 'uploadBytes', 1, 10485760) : 0,
    }
  }) }
}

export function makePlan(scenario, { clients = 5, duration = 300, ramp = 30, seed = 42, localOnly = false, gateway = '10.0.0.1', channel = 'chrome', headed = false } = {}) {
  clients = integer(clients, 'clients', 1, 200)
  duration = integer(duration, 'duration', 1, 86400)
  ramp = integer(ramp, 'ramp-seconds', 0, duration - 1)
  seed = integer(seed, 'seed', 0, 4294967295)
  if (isIP(gateway) !== 4) throw new Error('gateway must be an IPv4 address')
  if (!['chrome', 'chromium'].includes(channel)) throw new Error('channel must be chrome or chromium')
  const totalWeight = scenario.profiles.reduce((sum, p) => sum + p.weight, 0)
  const counts = scenario.profiles.map(p => Math.floor(clients * p.weight / totalWeight))
  const remainder = scenario.profiles.map((p, index) => ({ index, fraction: clients * p.weight / totalWeight - counts[index] }))
    .sort((a, b) => b.fraction - a.fraction || a.index - b.index)
  const remaining = clients - counts.reduce((a, b) => a + b, 0)
  for (let i = 0; i < remaining; i++) counts[remainder[i].index]++
  const assigned = []
  while (assigned.length < clients) {
    scenario.profiles.forEach((profile, index) => { if (counts[index] > 0) { assigned.push(profile); counts[index]-- } })
  }
  return {
    scenario: scenario.name, durationSeconds: duration, rampSeconds: ramp, seed, gateway, channel, headed, localOnly,
    identity: 'Shared Mac network identity; browser sessions are not Wi-Fi stations.',
    clients: assigned.map((profile, i) => ({ id: `client-${String(i + 1).padStart(3, '0')}`, startSeconds: clients === 1 ? 0 : ramp * i / (clients - 1), profile })),
  }
}

export function random(seed) {
  let value = seed >>> 0
  return () => { value += 0x6D2B79F5; let t = value; t = Math.imul(t ^ t >>> 15, t | 1); t ^= t + Math.imul(t ^ t >>> 7, t | 61); return ((t ^ t >>> 14) >>> 0) / 4294967296 }
}

export function between(rng, [minimum, maximum]) { return minimum + rng() * (maximum - minimum) }
