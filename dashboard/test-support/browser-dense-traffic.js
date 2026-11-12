export default async function check(page, h) {
  const response = await page.request.get(`${h.api}/api/infrareveal/sessions`)
  const { items } = await response.json()
  const session = items.find(s => s.name.startsWith('Load fixture'))
  h.assert(session, 'Start a traffic-load fixture backend')
  const expectedSeries = Number(session.name.match(/(\d+) clients/)?.[1]) * Number(session.name.match(/(\d+) bindings/)?.[1])
  const requests = []
  const onResponse = r => { if (r.url().includes('/map?')) requests.push({ status: r.status(), at: Date.now() }) }
  page.on('response', onResponse)
  try {
  const start = Date.now()
  await page.goto(`${h.map}/map/${session.id}`)
  if (h.historyMinutes !== 5) {
    await page.getByRole('button', { name: 'Filters', exact: true }).click()
    await page.getByLabel('History', { exact: true }).selectOption(String(h.historyMinutes * 60000))
    await page.getByRole('button', { name: 'Close filters', exact: true }).click()
  }
  const slider = page.getByRole('slider', { name: 'Session timeline', exact: true })
  await slider.waitFor()
  if (await page.getByRole('button', { name: 'Pause playback', exact: true }).count()) await page.getByRole('button', { name: 'Pause playback', exact: true }).click()
  await slider.evaluate(el => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set
    setter.call(el, String(Math.max(Number(el.min), Number(el.max) - 1800)))
    el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true }))
  })
  if (await page.getByRole('button', { name: 'Pause playback', exact: true }).count()) await page.getByRole('button', { name: 'Pause playback', exact: true }).click()
  await page.waitForFunction(expected => Number(document.querySelector('.atlas-overview-tabs button:last-child small')?.textContent) === expected, expectedSeries, { timeout: 120000 })
  await page.getByRole('button', { name: /^Tracks / }).click()
  const tracks = await page.locator('[data-track-id]').count()
  h.assert(tracks <= 32, `Track DOM grew with dataset: ${tracks}`)
  await page.getByRole('button', { name: 'Expand traffic timeline', exact: true }).click()
  await page.waitForSelector('.atlas-detail-timeline[aria-busy=false] .atlas-detail-row', { timeout: 120000 })
  const loadedMS = Date.now() - start
  const lanes = await page.locator('.atlas-detail-row').count()
  h.assert(lanes <= 32, `Timeline DOM grew with dataset: ${lanes}`)
  if (await page.getByRole('button', { name: 'Play session', exact: true }).count()) await page.getByRole('button', { name: 'Play session', exact: true }).click()
  const measureFrames = () => page.evaluate(async () => {
    const gaps = [], longTasks = []; let previous = performance.now()
    const observer = new PerformanceObserver(list => longTasks.push(...list.getEntries().map(e => e.duration)))
    observer.observe({ type: 'longtask', buffered: false })
    await new Promise(resolve => {
      const stop = previous + 5000
      function tick(now) { gaps.push(now - previous); previous = now; if (now < stop) requestAnimationFrame(tick); else resolve() }
      requestAnimationFrame(tick)
    })
    observer.disconnect(); gaps.sort((a, b) => a - b)
    return { frames: gaps.length, fps: gaps.length / 5, p95FrameMS: gaps[Math.floor(gaps.length * .95)], maxFrameMS: gaps.at(-1), longTasks, heap: performance.memory?.usedJSHeapSize }
  })
  const timings = await measureFrames()
  const scroll = page.locator('.atlas-detail-scroll')
  await scroll.evaluate(el => { el.scrollTop = el.scrollHeight / 2; el.dispatchEvent(new Event('scroll')) })
  h.assert(await page.locator('.atlas-detail-row').count() <= 32, 'Scrolling mounted unbounded rows')
  const pauseMS = await page.getByRole('button', { name: 'Pause playback', exact: true }).evaluate(async el => {
    const start = performance.now(); el.click()
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))
    return performance.now() - start
  })
  await page.getByRole('button', { name: 'Play session', exact: true }).waitFor()
  await page.getByRole('button', { name: 'Back to map', exact: true }).first().click()
  const projections = {}
  for (const projection of ['equal-earth', 'mercator']) {
    await page.getByRole('button', { name: 'Open display settings' }).click()
    await page.locator('#map-projection').selectOption(projection)
    await page.getByRole('button', { name: 'Close display settings' }).click()
    await page.getByRole('button', { name: 'Play session', exact: true }).click()
    projections[projection] = await measureFrames()
    await page.getByRole('button', { name: 'Pause playback', exact: true }).click()
    h.assert(projections[projection].fps >= 30, `${projection} below 30fps`)
  }
  const result = { expectedSeries, historyMinutes: h.historyMinutes, loadedMS, tracks, lanes, nodes: await page.locator('*').count(), requests: requests.length, failedRequests: requests.filter(r => r.status !== 200), pauseMS, timings, projections }
  h.assert(!result.failedRequests.length, JSON.stringify(result.failedRequests))
  h.assert(timings.fps >= 30, `Playback below 30fps: ${timings.fps}`)
  h.assert(pauseMS < 200, `Pause-to-paint exceeded 200ms: ${pauseMS}`)
  h.assert(await page.locator('.atlas-overview-tabs button:last-child small').textContent() === String(expectedSeries), 'Returning to the map discarded loaded traffic')
  await page.screenshot({ path: 'output/playwright/dense-traffic.png' })
  return result
  } finally { page.off('response', onResponse) }
}
