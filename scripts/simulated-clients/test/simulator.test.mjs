import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import dgram from 'node:dgram'
import { makePlan, readScenario, target } from '../config.mjs'
import { parseRoute, requireGateway, publicIPv4, resolveFrom, requireSources } from '../network.mjs'
import { transfer } from '../process.mjs'
import { cli, fixture } from './fixture.mjs'

test('weighted client allocation, ramp and offline plans are repeatable', async () => {
  const scenario = await readScenario(new URL('../scenarios/controlled-mix.json', import.meta.url), { allowPlaceholders: true })
  const plan = makePlan(scenario, { clients: 30, ramp: 60 })
  assert.deepEqual(plan, makePlan(scenario, { clients: 30, ramp: 60 }))
  const counts = Object.fromEntries(scenario.profiles.map(p => [p.name, plan.clients.filter(c => c.profile.name === p.name).length]))
  assert.deepEqual(Object.values(counts), [10, 6, 6, 4, 2, 2])
  assert.equal(plan.clients.at(-1).startSeconds, 60)
  const small = makePlan(scenario, { clients: 3 })
  assert.deepEqual(small.clients.map(c => c.profile.name), ['readers', 'video-shaped', 'pollers'])
  await assert.rejects(readScenario(new URL('../scenarios/controlled-mix.json', import.meta.url)), /placeholder/)
})

test('preflight rejects bypass routes, unobservable addresses and non-loopback local targets', () => {
  const route = parseRoute('   gateway: 10.0.0.1\n interface: en0\n')
  assert.doesNotThrow(() => requireGateway(route, '10.0.0.1', 'en0'))
  assert.throws(() => requireGateway(route, '192.168.1.1'), /bypass/)
  assert.throws(() => requireGateway({ ...route, interface: 'utun1' }, '10.0.0.1', 'en0'), /bypass/)
  for (const ip of ['10.0.0.10', '192.168.1.10', '203.0.113.1', '198.18.0.1', '224.0.0.1']) assert.equal(publicIPv4(ip), false)
  assert.equal(publicIPv4('1.1.1.1'), true)
  assert.throws(() => target('https://example.com', true), /loopback/)
  assert.throws(() => target('http://user:pass@127.0.0.1'), /credentials/)
  assert.throws(() => requireSources(['10.0.0.10', '10.0.0.10'], 'en0'), /distinct/)
})

test('real source-bound DNS and HTTP preserve source and DNS-selected endpoint', async t => {
  const f = await fixture(); t.after(async () => { await f.close(); await rm(f.directory, { recursive: true }) })
  const dns = dgram.createSocket('udp4')
  t.after(() => dns.close())
  let dnsSource
  dns.on('message', (message, remote) => {
    dnsSource = remote.address
    const header = Buffer.from(message.subarray(0, 12)); header.writeUInt16BE(0x8180, 2); header.writeUInt16BE(1, 6); header.writeUInt16BE(0, 10)
    let end = 12
    while (message[end]) end += message[end] + 1
    end += 5
    const answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1])
    dns.send(Buffer.concat([header, message.subarray(12, end), answer]), remote.port, remote.address)
  })
  await new Promise(resolve => dns.bind(0, '127.0.0.1', resolve))
  const result = await resolveFrom('fixture.test', '127.0.0.1', '127.0.0.1', { port: dns.address().port })
  assert.equal(dnsSource, '127.0.0.1')
  assert.deepEqual(result.addresses, ['127.0.0.1'])
  const response = await transfer(f.origin.replace('127.0.0.1', 'fixture.test') + '/download', { kind: 'download', timeoutSeconds: 2, rateBytesPerSecond: 1048576 }, { sourceIP: '127.0.0.1', resolvedIP: result.addresses[0] })
  assert.equal(response.ok, true); assert.equal(response.localIP, '127.0.0.1'); assert.equal(response.receivedBytes, 8192)
})

test('concurrent download/upload workload records achieved bytes and final artifacts', async t => {
  const f = await fixture(); t.after(async () => { await f.close(); await rm(f.directory, { recursive: true }) })
  const scenario = await f.scenario([
    { name: 'downloads', kind: 'download', urls: [f.origin + '/download'], pauseSeconds: [10, 10] },
    { name: 'uploads', kind: 'upload', urls: [f.origin + '/upload'], uploadBytes: 1024, pauseSeconds: [10, 10] },
  ])
  const output = join(f.directory, 'run')
  const result = await cli(['run', '--scenario', scenario, '--local-only', '--clients', '4', '--duration', '2', '--ramp-seconds', '0', '--out', output]).done
  assert.equal(result.code, 0, result.stdout + result.stderr)
  const summary = JSON.parse(await readFile(join(output, 'summary.json')))
  assert.equal(summary.success, true); assert.equal(summary.clients.length, 4)
  assert.ok(summary.clients.every(c => c.successes > 0 && c.failures === 0))
  assert.equal(summary.receivedBytes, f.requests.reduce((sum, r) => sum + (r.url === '/download' ? 8192 : 32), 0))
  assert.equal(summary.clients.reduce((sum, c) => sum + c.sentBytes, 0), f.requests.reduce((sum, r) => sum + r.bytes, 0))
  const again = await cli(['run', '--scenario', scenario, '--local-only', '--duration', '2', '--ramp-seconds', '0', '--out', output]).done
  assert.equal(again.code, 1); assert.match(again.stderr, /exist/)
})

test('HTTP failures and redirects cannot produce successful workload reports', async t => {
  const f = await fixture(); t.after(async () => { await f.close(); await rm(f.directory, { recursive: true }) })
  const scenario = await f.scenario([{ name: 'failure', kind: 'poll', urls: [f.origin + '/fail', f.origin + '/redirect'], pauseSeconds: [.1, .1] }])
  const output = join(f.directory, 'run')
  const result = await cli(['run', '--scenario', scenario, '--local-only', '--clients', '1', '--duration', '1', '--ramp-seconds', '0', '--out', output]).done
  assert.equal(result.code, 1)
  const summary = JSON.parse(await readFile(join(output, 'summary.json')))
  assert.equal(summary.success, false); assert.ok(summary.clients[0].failures > 0)
  assert.equal(summary.clients[0].successes, 0)
})

test('SIGINT terminates an in-flight transfer and writes an interrupted report', async t => {
  const f = await fixture(); t.after(async () => { await f.close(); await rm(f.directory, { recursive: true }) })
  const scenario = await f.scenario([{ name: 'hanging', kind: 'poll', urls: [f.origin + '/hang'] }])
  const output = join(f.directory, 'run')
  const running = cli(['run', '--scenario', scenario, '--local-only', '--clients', '1', '--duration', '60', '--ramp-seconds', '0', '--out', output])
  const deadline = Date.now() + 5000
  while (!f.requests.length && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 30))
  assert.ok(f.requests.length, 'transfer never started')
  running.child.kill('SIGINT')
  const result = await running.done
  assert.equal(result.code, 130, result.stdout + result.stderr)
  const summary = JSON.parse(await readFile(join(output, 'summary.json')))
  assert.equal(summary.stopReason, 'interrupted'); assert.equal(summary.clients[0].cancelled, 1)
  assert.equal(summary.success, false)
})
