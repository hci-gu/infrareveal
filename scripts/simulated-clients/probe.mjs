import { performance } from 'node:perf_hooks'
import { guardRoute, preflight, requireSources, resolveFrom, requireGateway, routeTo, publicIPv4 } from './network.mjs'
import { transfer, sleep } from './process.mjs'
import { artifactWriter } from './report.mjs'

export async function probe(plan, sourceIPs, output) {
  const evidence = await preflight(plan)
  requireSources(sourceIPs, evidence.route.interface)
  const url = plan.clients[0].profile.urls[0]
  const writer = artifactWriter(output)
  writer.json('preflight.json', evidence)
  const controller = new AbortController()
  const stop = () => controller.abort()
  process.once('SIGINT', stop); process.once('SIGTERM', stop)
  const results = []
  try {
    for (let round = 1; round <= 3 && !controller.signal.aborted; round++) {
      for (const sourceIP of sourceIPs) {
        if (controller.signal.aborted) break
        const at = performance.now()
        try {
          await guardRoute(plan.gateway, evidence.route.interface)
          const dns = await resolveFrom(new URL(url).hostname, sourceIP, plan.gateway, { signal: controller.signal })
          if (!publicIPv4(dns.addresses[0])) throw new Error('Probe destination must be a public address observed by the Pi')
          requireGateway(await routeTo(dns.addresses[0]), plan.gateway, evidence.route.interface)
          writer.event('dns', { round, ...dns })
          const result = await transfer(url, plan.clients[0].profile, { signal: controller.signal, sourceIP, resolvedIP: dns.addresses[0] })
          const row = { round, sourceIP, ...result, ok: result.ok && result.localIP === sourceIP }
          results.push(row); writer.event('probe', row)
          console.log(`${sourceIP}: HTTP ${result.status}, actual source ${result.localIP}, ${row.ok ? 'OK' : 'FAILED'}`)
        } catch (error) {
          const row = { round, sourceIP, ok: false, error: error.message, elapsedMs: performance.now() - at }
          results.push(row); writer.event('probe', row)
        }
      }
      if (round < 3) await sleep(1000, controller.signal)
    }
  } finally {
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop)
  }
  const success = results.length === sourceIPs.length * 3 && results.every(r => r.ok)
  writer.json('summary.json', { success, results, interpretation: 'Confirms source-bound DNS and HTTP round trips from this Mac. Separately verify distinct identities and DNS attribution on the Pi. All source IPs still share one Wi-Fi station; no DHCP leases were created.' })
  writer.close()
  console.log(`Probe ${success ? 'passed' : 'failed'}; artifacts: ${writer.directory}`)
  return controller.signal.aborted ? 130 : success ? 0 : 1
}
