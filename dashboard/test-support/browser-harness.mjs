/** Serialized into Playwright CLI's sandbox by run.mjs; no Node dependencies. */
export async function createBrowserHarness(page, config, seeded) {
  const assert = (condition, message) => { if (!condition) throw new Error(message) }
  await page.setViewportSize({ width: 1440, height: 1000 })
  const errors = []
  const onError = error => errors.push(error.message)
  page.on('pageerror', onError)
  let recorded, live
  if (seeded) {
    const response = await page.request.get(`${config.api}/api/infrareveal/sessions`)
    assert(response.ok(), 'Start the isolated development backend before this check')
    const { items } = await response.json()
    recorded = items.find(session => !session.active && session.name.startsWith('Example'))
    live = items.find(session => session.active && !session.simulation_expires_ms)
    assert(recorded && live, 'Seed an Example recording and one empty live session')
  }
  return { ...config, assert, errors, recorded, live, cleanup: () => page.off('pageerror', onError) }
}
