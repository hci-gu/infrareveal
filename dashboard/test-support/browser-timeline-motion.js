// Playwright CLI check of CSS transitions with a 135-endpoint fixture.
async (page) => {
  const assert = (value, message) => { if (!value) throw new Error(message) }
  await page.goto('http://127.0.0.1:5193')
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await page.evaluate(async () => {
    const { mountTimelineMotion } = await import('/test-support/timeline-motion-fixture.tsx')
    const container = document.createElement('div')
    document.body.append(container)
    window.timelineMotion = mountTimelineMotion(container)
  })
  try {
    await page.getByRole('button', { name: 'Endpoint 132', exact: false }).waitFor()
    assert(await page.getByRole('combobox', { name: 'Timeline window' }).inputValue() === '300000', 'Expected five-minute history')
    const names = () => page.locator('.atlas-detail-track strong').allTextContents()
    assert((await names()).join(',') === 'Endpoint 134,Endpoint 133,Endpoint 132', 'Quiet history should remain below recent traffic')
    await page.evaluate(() => Promise.all([...document.querySelectorAll('.atlas-detail-row')].flatMap(row => row.getAnimations().map(animation => animation.finished))))
    await page.evaluate(() => window.timelineMotion.advance(132, 1))
    await page.waitForFunction(() => document.querySelector('.atlas-detail-track strong')?.textContent === 'Endpoint 132')
    const moving = await page.evaluate(() => [...document.querySelectorAll('.atlas-detail-row')].some(row => row.getAnimations().some(animation => animation.transitionProperty === 'transform')))
    assert(moving, 'Activity changed the order without animating the row positions')
    await page.evaluate(() => Promise.all([...document.querySelectorAll('.atlas-detail-row')].flatMap(row => row.getAnimations().map(animation => animation.finished))))
    await page.evaluate(() => window.timelineMotion.advance(131, 2))
    await page.waitForFunction(() => document.querySelector('.atlas-detail-track strong')?.textContent === 'Endpoint 131')
    assert(await page.locator('.atlas-detail-row').count() === 4, 'Newly active endpoint did not appear')
    const entering = await page.evaluate(() => document.querySelector('.atlas-detail-row').getAnimations().some(animation => animation.transitionProperty === 'opacity'))
    assert(entering, 'Newly visible lane should fade into the list')
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.evaluate(() => window.timelineMotion.advance(133, 3))
    await page.waitForFunction(() => document.querySelector('.atlas-detail-track strong')?.textContent === 'Endpoint 133')
    assert(await page.evaluate(() => [...document.querySelectorAll('.atlas-detail-row')].some(row => row.getAnimations().some(animation => animation.transitionProperty === 'transform'))), 'Lane animation must remain enabled regardless of the system preference')
    await page.locator('.atlas-detail-track').first().focus()
    const heldOrder = await names()
    await page.evaluate(() => window.timelineMotion.advance(132, 4))
    assert((await names()).join(',') === heldOrder.join(','), 'A focused lane must not reorder')
    await page.screenshot({ path: 'output/playwright/traffic-timeline-five-minutes.png' })
    return { passed: true, checks: 'five-minute history, quiet lanes retained, animated promotion, newly active lane fade-in, animations remain enabled with either system preference, focused order held' }
  } finally {
    await page.evaluate(() => window.timelineMotion.dispose())
    await page.emulateMedia({ reducedMotion: 'no-preference' })
  }
}
