import { performance } from 'node:perf_hooks'
import { between, loopback, random } from './config.mjs'
import { guardRoute, preflight } from './network.mjs'
import { sleep, transfer } from './process.mjs'
import { artifactWriter, newStats, record, resources, summarize } from './report.mjs'

async function browserClient(browser, client, stats, rng, signal, event) {
  const context = await browser.newContext({ viewport: { width: 1365, height: 900 }, serviceWorkers: client.localOnly ? 'block' : 'allow' })
  let closing = false
  const pending = new Set()
  try {
    if (client.localOnly) {
      await context.route('**/*', route => loopback(new URL(route.request().url()).hostname) ? route.continue() : route.abort())
      await context.routeWebSocket('**/*', route => loopback(new URL(route.url()).hostname) ? route.connectToServer() : route.close())
    }
    const page = await context.newPage()
    const cdp = await context.newCDPSession(page)
    await cdp.send('Network.enable')
    cdp.on('Network.responseReceived', ({ response }) => {
      if (response.protocol) stats.protocols.add(response.protocol)
    })
    page.on('dialog', dialog => dialog.dismiss().catch(() => {}))
    context.on('page', popup => { if (popup !== page) popup.close().catch(() => {}) })
    page.on('requestfailed', () => { if (!closing && !signal.aborted) stats.resourceFailures++ })
    page.on('requestfinished', request => {
      const job = (async () => {
        const response = await request.response()
        const sizes = await request.sizes()
        stats.resourceResponses++
        if (response?.status() >= 400) stats.resourceHttpErrors++
        stats.receivedBytes += sizes.responseBodySize + sizes.responseHeadersSize
        stats.sentBytes += sizes.requestBodySize + sizes.requestHeadersSize
        const remote = await response?.serverAddr()
        if (remote && stats.remoteIPs.size < 1024) stats.remoteIPs.add(remote.ipAddress)
      })().catch(() => {}).finally(() => pending.delete(job))
      pending.add(job)
    })
    const profile = client.profile
    while (!signal.aborted) {
      const url = profile.urls[Math.floor(rng() * profile.urls.length)]
      const at = performance.now()
      let navigationRecorded = false
      try {
        const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: profile.timeoutSeconds * 1000 })
        const result = { ok: Boolean(response?.ok()), status: response?.status(), elapsedMs: performance.now() - at, finalURL: page.url() }
        record(stats, result)
        navigationRecorded = true
        event('operation', { client: client.id, kind: 'browser', url, ...result })
        const until = performance.now() + between(rng, profile.dwellSeconds) * 1000
        while (!signal.aborted && performance.now() < until) {
          await page.mouse.wheel(0, 500).catch(() => {})
          await sleep(Math.min(4000, Math.max(0, until - performance.now())), signal)
        }
        // End document activity for the quiet period; retain cookies/cache in this context.
        if (!signal.aborted) await page.goto('about:blank', { timeout: 5000 })
      } catch (error) {
        if (signal.aborted) { stats.cancelled++; break }
        if (!navigationRecorded) record(stats, { ok: false, elapsedMs: performance.now() - at })
        event(navigationRecorded ? 'browser-activity-error' : 'operation', { client: client.id, kind: 'browser', url, ok: false, error: error.message })
      }
      await sleep(between(rng, profile.pauseSeconds) * 1000, signal)
    }
  } finally {
    closing = true
    await context.close().catch(() => {})
    await Promise.allSettled([...pending])
  }
}

async function transferClient(client, stats, rng, signal, event) {
  while (!signal.aborted) {
    const url = client.profile.urls[Math.floor(rng() * client.profile.urls.length)]
    try {
      const result = await transfer(url, client.profile, { signal })
      record(stats, result)
      event('operation', { client: client.id, kind: client.profile.kind, url, ...result })
    } catch (error) {
      if (signal.aborted) { stats.cancelled++; break }
      record(stats, { ok: false })
      event('operation', { client: client.id, kind: client.profile.kind, url, ok: false, error: error.message })
    }
    await sleep(between(rng, client.profile.pauseSeconds) * 1000, signal)
  }
}

export async function run(plan, output) {
  const evidence = await preflight(plan)
  const writer = artifactWriter(output)
  const controller = new AbortController()
  const { signal } = controller
  const stats = plan.clients.map(c => newStats(c.id, c.profile.name))
  let browser, deadlineTimer, stopReason = 'duration', fatal, started
  const stop = reason => { if (!signal.aborted) { stopReason = reason; controller.abort() } }
  const interrupt = () => stop('interrupted')
  process.once('SIGINT', interrupt); process.once('SIGTERM', interrupt)
  writer.json('plan.json', plan)
  writer.json('preflight.json', evidence)
  console.log(`Artifacts: ${writer.directory}\n${plan.clients.length} logical clients; ${plan.identity}`)
  try {
    if (plan.clients.some(c => c.profile.kind === 'browser')) {
      const { chromium } = await import('playwright')
      browser = await chromium.launch({ headless: !plan.headed, ...(plan.channel === 'chrome' ? { channel: 'chrome' } : {}), timeout: 30000,
        args: ['--no-proxy-server', '--disable-features=DnsOverHttps,UseDnsHttpsSvcbAlpn'] })
      browser.on('disconnected', () => { if (!signal.aborted) { fatal = 'Browser disconnected unexpectedly'; stop('browser-failure') } })
    }
    started = performance.now()
    writer.event('start', { clients: plan.clients.length, network: evidence.mode })
    deadlineTimer = setTimeout(() => stop('duration'), plan.durationSeconds * 1000)
    const closeBrowser = () => browser?.close().catch(() => {})
    signal.addEventListener('abort', closeBrowser, { once: true })
    if (signal.aborted) closeBrowser()
    const monitoring = (async () => {
      while (!signal.aborted) {
        try {
          if (!plan.localOnly) {
            const route = await guardRoute(plan.gateway, evidence.route.interface)
            writer.event('route', route)
          }
        } catch (error) { fatal = error.message; stop('route-changed'); break }
        try {
          const host = await resources()
          const totals = stats.reduce((a, s) => ({ ok: a.ok + s.successes, failed: a.failed + s.failures, bytes: a.bytes + s.receivedBytes }), { ok: 0, failed: 0, bytes: 0 })
          writer.event('sample', { elapsedSeconds: (performance.now() - started) / 1000, ...host, totals })
          console.log(`${Math.round((performance.now() - started) / 1000)}s: ${totals.ok} successful, ${totals.failed} failed, ${(totals.bytes / 1e6).toFixed(2)} MB received; generator RSS ${Math.round(host.generatorRssBytes / 1048576)} MiB`)
        } catch (error) { writer.event('monitor-error', { error: error.message }) }
        await sleep(5000, signal)
      }
    })()
    await Promise.all(plan.clients.map(async (client, i) => {
      await sleep(Math.max(0, client.startSeconds * 1000 - (performance.now() - started)), signal)
      if (signal.aborted) return
      stats[i].started = true
      writer.event('client-start', { client: client.id, profile: client.profile.name })
      try {
        const rng = random(plan.seed + i * 65537)
        if (client.profile.kind === 'browser') await browserClient(browser, { ...client, localOnly: plan.localOnly }, stats[i], rng, signal, writer.event)
        else await transferClient(client, stats[i], rng, signal, writer.event)
      } catch (error) {
        if (!signal.aborted) { record(stats[i], { ok: false }); writer.event('client-error', { client: client.id, error: error.message }) }
      }
    }))
    if (!signal.aborted) { fatal = 'All workers stopped before the duration elapsed'; stop('workers-stopped') }
    await monitoring
    signal.removeEventListener('abort', closeBrowser)
  } catch (error) {
    fatal = error.message
    stop('error')
  } finally {
    clearTimeout(deadlineTimer)
    await browser?.close().catch(() => {})
    process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt)
  }
  const clients = stats.map(summarize)
  const success = !fatal && stopReason === 'duration' && clients.every(s => s.started && s.successes > 0 && s.failures === 0)
  const elapsedSeconds = started ? (performance.now() - started) / 1000 : 0
  const receivedBytes = clients.reduce((sum, c) => sum + c.receivedBytes, 0)
  const summary = { success, stopReason, error: fatal, elapsedSeconds, clients,
    receivedBytes, averageReceivedMbps: elapsedSeconds ? receivedBytes * 8 / elapsedSeconds / 1e6 : 0,
    interpretation: 'Workload completion only; not Pi capacity certification. Completed browser-resource byte estimates and curl body bytes are not packet/wire counters; in-flight/cancelled transfers may be missing. Resource failures are reported separately. Deadline-cancelled operations are not successful transfers. No DHCP or independent Wi-Fi stations are simulated.' }
  writer.event('stop', { success, stopReason, error: fatal })
  writer.json('summary.json', summary)
  writer.close()
  console.log(`Stopped: ${stopReason}; workload ${success ? 'completed' : 'incomplete or failed'}. See summary.json.`)
  return { ...summary, exitCode: stopReason === 'interrupted' ? 130 : success ? 0 : 1 }
}
