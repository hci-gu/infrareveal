#!/usr/bin/env node
import { parseArgs } from 'node:util'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readScenario, makePlan, target } from './config.mjs'
import { preflight } from './network.mjs'
import { run } from './runner.mjs'
import { probe } from './probe.mjs'

const help = `InfraReveal Mac client simulator (Node 22+)

  node cli.mjs plan  --scenario scenarios/browsing.json [options]
  node cli.mjs check --scenario scenarios/browsing.json [options]
  node cli.mjs run   --scenario scenarios/browsing.json [options]
  node cli.mjs probe --url https://YOUR_HOST/small-file --source-ips 10.0.0.10,10.0.0.11

Options:
  --clients N           Logical clients (default 5; no extra Wi-Fi associations)
  --duration SECONDS    Whole run, including ramp (default 300, maximum 86400)
  --ramp-seconds N      Stagger starts over this period (default 30)
  --seed N              Repeatable client schedules (default 42)
  --gateway IP          Required macOS gateway and DNS server (default 10.0.0.1)
  --channel NAME        chrome (installed Chrome, default) or chromium (Playwright)
  --headed              Show automated browser windows
  --out DIRECTORY       New artifact directory; existing directories are refused
  --local-only          Loopback-only fixture testing; never claims Pi validation
  --help                Show help

plan is offline. check resolves targets and reads routes, but sends no workload.
run starts real traffic. probe uses already-configured source IPs; never adds aliases.
Browser contexts isolate cookies/storage, not IP addresses or Wi-Fi stations.
`

try {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    scenario: { type: 'string' }, clients: { type: 'string' }, duration: { type: 'string' }, 'ramp-seconds': { type: 'string' }, seed: { type: 'string' },
    gateway: { type: 'string' }, channel: { type: 'string' }, headed: { type: 'boolean' }, out: { type: 'string' }, 'local-only': { type: 'boolean' },
    url: { type: 'string' }, 'source-ips': { type: 'string' }, help: { type: 'boolean' },
  } })
  const action = positionals[0]
  if (values.help || !action) console.log(help)
  else {
    if (positionals.length !== 1 || !['plan', 'check', 'run', 'probe'].includes(action)) throw new Error('Choose plan, check, run or probe; see --help')
    if (action !== 'probe' && (values.url || values['source-ips'])) throw new Error('--url and --source-ips are only supported by probe; browser clients cannot bind to source IPs yet')
    const options = { clients: values.clients, duration: values.duration, ramp: values['ramp-seconds'], seed: values.seed,
      gateway: values.gateway, channel: values.channel, headed: values.headed, localOnly: values['local-only'] }
    const output = values.out || resolve(dirname(fileURLToPath(import.meta.url)), '../../output/client-simulator', `${new Date().toISOString().replaceAll(':', '-')}-${process.pid}`)
    if (action === 'probe') {
      if (!values.url || !values['source-ips'] || values['local-only'] || values.scenario) throw new Error('probe requires --url and --source-ips, and uses the real Pi gateway')
      const profile = { name: 'source-ip-probe', kind: 'poll', weight: 1, urls: [target(values.url)], pauseSeconds: [1, 1], dwellSeconds: [1, 1], timeoutSeconds: 15, rateBytesPerSecond: 131072, uploadBytes: 0 }
      const plan = makePlan({ name: 'source-ip-probe', profiles: [profile] }, { ...options, clients: 1, ramp: 0 })
      process.exitCode = await probe(plan, values['source-ips'].split(',').map(ip => ip.trim()), output)
    } else {
      if (!values.scenario) throw new Error('--scenario is required')
      const scenario = await readScenario(values.scenario, { localOnly: options.localOnly, allowPlaceholders: action === 'plan' })
      const plan = makePlan(scenario, options)
      if (action === 'plan') console.log(JSON.stringify(plan, null, 2))
      if (action === 'check') console.log(JSON.stringify(await preflight(plan), null, 2))
      if (action === 'run') process.exitCode = (await run(plan, output)).exitCode
    }
  }
} catch (error) {
  console.error(`Simulator: ${error.message}`)
  process.exitCode = 1
}
