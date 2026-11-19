// Playwright CLI run-code function. Uses the real seeded development backend.
export default async (page, harness) => {
  const { map, recorded, live, assert, errors } = harness
  const requests = []
  const onRequest = request => { if (request.url().includes('/api/')) requests.push(request.url()) }
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
    await page.goto(`${map}/map/${recorded.id}`)
    await page.locator('.atlas-page[data-timeline-mode="recorded"]').waitFor()
    await page.getByRole('slider', { name: 'Session timeline', exact: true }).press('End')
    await page.getByRole('button', { name: 'Activity', exact: true }).click()
    await page.locator('.atlas-visit').first().waitFor()
    const mapBlocks = await page.locator('.atlas-visit').count()
    await page.locator('.atlas-visit > button').filter({ hasText: 'svt.se' }).first().click()
    await page.locator('.atlas-visit-detail').getByText('Started', { exact: true }).waitFor()
    await page.locator('.atlas-visit-detail').getByText(/dns_answer/).waitFor()
    await page.getByRole('button', { name: 'Close activity' }).click()
    await page.getByRole('button', { name: 'Open display settings' }).click()
    for (const projection of ['equal-earth', 'mercator', 'globe']) {
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
    assert(!requests.some(url => /\/api\/collections\/|\/window\?/.test(url)), 'Browser requested a retired collector API')
    assert(!errors.length, `Browser errors: ${errors.join('; ')}`)
    return { recorded: recorded.id, live: live.id, mapBlocks, productRequests: requests.length, pageErrors: errors, checks: 'recorded map, all projections, block evidence, paused live, unavailable capture and one revision stream' }
  } finally {
    page.off('request', onRequest)
  }
}
