import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createBrowserHarness } from './browser-harness.mjs'

const [name, session = 'dashboard'] = process.argv.slice(2)
const checks = ['browser-product-api', 'browser-shared-filters', 'browser-traffic-timeline', 'browser-timeline-motion', 'check-map-playback', 'check-timeline-animation']
if (!checks.includes(name)) throw new Error(`Choose a check: ${checks.join(', ')}`)
const { default: check } = await import(`./${name}.js`)
const config = {
  map: process.env.DASHBOARD_ORIGIN || 'http://127.0.0.1:5193',
  debug: process.env.DEBUG_DASHBOARD_ORIGIN || 'http://127.0.0.1:5194',
  api: process.env.GATEWAY_ORIGIN || 'http://127.0.0.1:8091',
}
const directory = await mkdtemp(join(tmpdir(), 'infrareveal-browser-'))
try {
  const path = join(directory, 'check.js')
  const seeded = ['browser-product-api', 'browser-shared-filters', 'browser-traffic-timeline'].includes(name)
  await writeFile(path, `async (page) => { const harness = await (${createBrowserHarness})(page, ${JSON.stringify(config)}, ${seeded}); try { const result = await (${check})(page, harness); harness.assert(!harness.errors.length, harness.errors.join('; ')); return result; } finally { harness.cleanup(); } }`)
  const command = process.env.PLAYWRIGHT_CLI || 'corepack'
  const prefix = process.env.PLAYWRIGHT_CLI ? [] : ['pnpm', 'dlx', '@playwright/cli']
  const result = spawnSync(command, [...prefix, `-s=${session}`, 'run-code', `--filename=${path}`], { encoding: 'utf8' })
  process.stdout.write(result.stdout || '')
  process.stderr.write(result.stderr || '')
  // Playwright CLI may report scenario failures in its output with a zero exit.
  process.exitCode = result.status || (result.error || /^### Error/m.test(result.stdout || '') ? 1 : 0)
} finally { await rm(directory, { recursive: true, force: true }) }
