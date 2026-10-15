// Playwright CLI run-code function. Uses the real seeded development backend.
async (page) => {
  const api = 'http://127.0.0.1:8091'
  const map = 'http://127.0.0.1:5193'
  const debug = 'http://127.0.0.1:5194'
  const assert = (value, message) => { if (!value) throw new Error(message) }
  const errors = [], requests = []
  const onError = error => errors.push(error.message)
  const onRequest = request => { if (request.url().includes('/api/')) requests.push(request.url()) }
  page.on('pageerror', onError)
  page.on('request', onRequest)
  await page.addInitScript(() => {
    if ('__revisionStreams' in window) return
    const Source = window.EventSource
    window.__revisionStreams = 0
    window.EventSource = class extends Source {
      constructor(url, options) { super(url, options); this.tracked = String(url).endsWith('/revisions'); if (this.tracked) window.__revisionStreams++ }
      close() { if (this.tracked) { window.__revisionStreams--; this.tracked = false } super.close() }
    }
  })
  try {
    const response = await page.request.get(`${api}/api/infrareveal/sessions`)
    assert(response.ok(), 'Start the development backend before this check')
    const { items } = await response.json()
    const recorded = items.find(session => !session.active && session.name.startsWith('Example'))
    const live = items.find(session => session.active)
    assert(recorded && live, 'Seed an example recording and start one empty live session')
    await page.goto(`${map}/map/${recorded.id}`)
    await page.locator('.atlas-page[data-timeline-mode="recorded"]').waitFor()
    await page.getByRole('slider', { name: 'Session timeline', exact: true }).press('End')
    await page.getByRole('button', { name: 'Browse activity blocks' }).click()
    await page.locator('.atlas-block').first().waitFor()
    const mapBlocks = await page.locator('.atlas-block').count()
    await page.locator('.atlas-block').first().click()
    await page.getByText('Originally started', { exact: false }).waitFor()
    await page.locator('.atlas-block-detail').getByText(/dns_answer/).waitFor()
    await page.getByRole('button', { name: 'Close activity blocks' }).click()
    await page.getByRole('button', { name: 'Open display settings' }).click()
    for (const projection of ['equal-earth', 'mercator']) {
      await page.locator('#map-projection').selectOption(projection)
      await page.locator(`.atlas-page[data-projection="${projection}"]`).waitFor()
    }
    await page.getByRole('button', { name: 'Close display settings' }).click()
    assert(await page.evaluate(() => window.__revisionStreams) === 1, 'Map must own one revision stream')
    await page.goto(`${map}/map/${live.id}`)
    await page.locator('.atlas-page[data-timeline-mode="live"]').waitFor()
    await page.getByRole('button', { name: 'Pause playback' }).click()
    const pausedClock = await page.locator('.atlas-clock strong').innerText()
    await page.waitForTimeout(1200)
    assert(await page.locator('.atlas-clock strong').innerText() === pausedClock, 'Paused live cursor moved')
    assert(await page.locator('.atlas-connection-notice').innerText(), 'Unavailable capture needs explicit status')
    await page.goto(`${debug}/timeline/${recorded.id}`)
    await page.getByRole('heading', { name: recorded.name }).waitFor()
    await page.locator('.lab-replay > summary').click()
    await page.getByRole('slider', { name: 'Lab replay position' }).press('End')
    await page.locator('.activity-block').first().waitFor()
    const debugBlocks = await page.locator('.activity-block').count()
    await page.locator('.activity-block').first().click()
    await page.getByRole('heading', { name: 'Destinations in loaded minute' }).waitFor()
    await page.locator('.activity-diagnostics > summary').click()
    await page.getByText('Not recorded for this session.', { exact: true }).waitFor()
    assert(await page.evaluate(() => window.__revisionStreams) === 1, 'Activity page must own one revision stream')
    await page.getByRole('link', { name: 'Gateway lab' }).click()
    await page.locator('.lab-workspace').waitFor()
    await page.locator('.lab-recorded-audit').waitFor()
    assert(await page.evaluate(() => window.__revisionStreams) === 1, 'Activity → Lab leaked a revision stream')
    await page.getByRole('link', { name: 'Back to Sessions' }).click()
    await page.getByRole('heading', { name: 'Sessions', exact: true }).waitFor()
    assert(await page.evaluate(() => window.__revisionStreams) === 0, 'Leaving a session leaked its revision stream')
    assert(!requests.some(url => /\/api\/collections\/|\/window\?/.test(url)), 'Browser requested a retired collector API')
    assert(!errors.length, `Browser errors: ${errors.join('; ')}`)
    return { recorded: recorded.id, live: live.id, mapBlocks, debugBlocks, productRequests: requests.length, pageErrors: errors, checks: 'recorded map, both projections, block evidence, paused live, unavailable capture, activity, absent diagnostics, Lab and subscription cleanup' }
  } finally {
    page.off('pageerror', onError)
    page.off('request', onRequest)
  }
}
