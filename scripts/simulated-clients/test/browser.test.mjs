import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { cli, fixture } from './fixture.mjs'

test('real Chrome sessions fetch subresources, retain cookies per session and shut down', { skip: !process.env.SIMULATOR_BROWSER_TEST }, async t => {
  const f = await fixture(); t.after(async () => { await f.close(); await rm(f.directory, { recursive: true }) })
  const scenario = await f.scenario([{ name: 'browsers', kind: 'browser', urls: [f.origin + '/page'], dwellSeconds: [.2, .3], pauseSeconds: [.1, .2] }])
  const output = join(f.directory, 'run')
  const result = await cli(['run', '--scenario', scenario, '--local-only', '--clients', '2', '--duration', '4', '--ramp-seconds', '0', '--out', output]).done
  assert.equal(result.code, 0, result.stdout + result.stderr)
  const summary = JSON.parse(await readFile(join(output, 'summary.json')))
  assert.equal(summary.success, true)
  assert.ok(summary.clients.every(c => c.successes >= 2 && c.resourceResponses > c.successes && c.receivedBytes > 0))
  assert.ok(summary.clients.every(c => c.protocols.includes('http/1.1')))
  const visits = f.requests.filter(r => r.url === '/page')
  assert.equal(visits.filter(r => !r.cookie).length, 2, 'each client must begin with its own empty cookie jar')
  assert.ok(visits.some(r => r.cookie === 'fixture=visited'))
  assert.ok(f.requests.some(r => r.url === '/asset'))
})
