// Start the standard gateway fixture and open a built dashboard on port 5188.
// This fixture adds captured counters and mixed location precision at the API boundary.
async (page) => {
  const app = 'http://127.0.0.1:5188', api = 'http://127.0.0.1:8095';
  const checks = [], errors = [];
  const assert = (condition, label) => { if (!condition) throw new Error(label); checks.push(label); };
  page.on('pageerror', error => errors.push(error.message));
  await page.request.post(api + '/__fixture', { data: { count: 24, resetSources: true, offline: false, routes: true } });
  const original = await (await page.request.get(api + '/api/infrareveal/sessions/recorded-session/window?lod=overview')).json();
  const locationIndex = new Map(original.destinations.map((destination, i) => [destination.ip, i]));
  const chunks = original.flows.flatMap((flow, i) => Array.from({ length: 5 }, (_, j) => {
    const start = Date.parse(flow.start) + j * 5000;
    return { id: 'workspace-' + flow.id + '-' + j, session: 'recorded-session', flow: flow.id, chunk_start: new Date(start).toISOString(), chunk_ms: 5000, bucket_ms: 1000, wire_bytes_in: [48000, 3200, 11000, 1000][i % 4], wire_bytes_out: [1600, 32000, 2800, 400][i % 4], capture_complete: j !== 2, dropped_events: j === 2 ? 2 : 0, updated_at_source: new Date(start + 5000).toISOString(), updated: new Date(start + 5000).toISOString() };
  }));
  await page.route('**/api/collections/flow_activity_chunks/records**', route => route.fulfill({ json: { items: chunks, page: 1, totalPages: 1, totalItems: chunks.length } }));
  await page.route('**/api/infrareveal/sessions/recorded-session/window**', async route => {
    const response = await route.fetch(); const data = await response.json();
    data.destinations = data.destinations.map(destination => ({ ...destination, ...[
      { city: 'Amsterdam', country: 'NL', lat: 52.4, lon: 4.9 },
      { city: '', country: 'US', lat: 39, lon: -98 },
      { city: 'Frankfurt', country: 'DE', lat: 50.1, lon: 8.7 },
      { city: '', country: '', lat: 0, lon: 0 },
    ][(locationIndex.get(destination.ip) ?? 0) % 4] }));
    await route.fulfill({ response, json: data });
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(app + '/map/recorded-session');
  await page.evaluate(() => { localStorage.removeItem('infrareveal.map.display.v1'); });
  await page.reload();
  await page.locator('.atlas-location-row').first().waitFor();
  await page.getByRole('button', { name: 'Pause playback', exact: true }).click();
  const scrubber = page.getByRole('slider', { name: 'Session timeline', exact: true });
  await scrubber.fill(await scrubber.getAttribute('max'));
  await page.waitForFunction(() => document.querySelectorAll('.atlas-location-row').length === 4);
  assert((await page.locator('.atlas-quality').innerText()).includes('partial'), 'Captured partial counters are identified');
  assert(await page.locator('.atlas-page').getAttribute('data-projection') === 'equal-earth', 'Equal Earth is the initial projection');
  assert(await page.locator('.atlas-earth-footprint').count() === 1, 'Country-only evidence renders a footprint');
  assert(await page.locator('.atlas-earth-point').count() === 2, 'Only city estimates get map points');
  await page.getByRole('button', { name: '↑ Sent', exact: true }).click();
  assert(await page.locator('.atlas-earth-flow.received').count() === 0, 'Sent filter removes received map streams');
  assert((await page.locator('.atlas-location-row').first().innerText()).includes('United States'), 'Sent volume controls location ranking');
  await page.locator('[data-location-id="country:US"]').click();
  const total = await page.locator('[data-direction-total="sent"]').innerText();
  const position = await scrubber.inputValue();
  await page.getByRole('button', { name: 'Expand traffic timeline', exact: true }).click();
  await page.getByRole('heading', { name: 'Traffic timeline', exact: true }).waitFor();
  assert(await scrubber.inputValue() === position, 'Expanding preserves playback position');
  assert(await page.locator('.atlas-detail-row:not([data-timeline-location="country:US"])').count() === 0, 'Timeline inherits location filter');
  assert(await page.locator('.atlas-wave-sent').count() > 0, 'Timeline renders captured outgoing wire rates');
  assert(await page.locator('.atlas-wave-received').count() === 0, 'Timeline inherits direction filter');
  assert(await page.locator('[data-direction-total="sent"]').innerText() === total, 'Map and timeline use identical totals');
  await page.screenshot({ path: 'output/playwright/workspace-timeline-filtered.png' });
  await page.keyboard.press('Escape');
  await page.locator('[data-workspace="map"]').waitFor();
  assert(await page.locator('.atlas-page').getAttribute('data-direction') === 'sent', 'Returning preserves direction');
  await page.locator('.atlas-clear-location').click();
  await page.getByRole('button', { name: 'Both', exact: true }).click();
  const handle = await page.locator('.atlas-pane-resize').boundingBox();
  await page.mouse.move(handle.x + 7, handle.y + handle.height / 2); await page.mouse.down();
  await page.mouse.move(1050, handle.y + handle.height / 2, { steps: 12 });
  await page.locator('.atlas-snap-target').waitFor(); await page.mouse.up();
  await page.locator('[data-workspace="timeline"]').waitFor();
  assert(true, 'Drag opens full-screen timeline');
  await page.screenshot({ path: 'output/playwright/workspace-timeline.png' });
  await page.getByRole('button', { name: '↙ Back to map', exact: true }).click();
  await page.getByRole('button', { name: 'Open display settings', exact: true }).click();
  await page.getByRole('button', { name: 'Light', exact: true }).click();
  await page.getByLabel('Show location labels', { exact: true }).uncheck();
  await page.locator('#map-projection').selectOption('mercator');
  await page.getByRole('button', { name: 'Done', exact: true }).click();
  await page.locator('.maplibregl-canvas').waitFor();
  assert(await page.locator('.atlas-page').getAttribute('data-theme') === 'light', 'Light theme applies immediately');
  await page.reload();
  await page.locator('.maplibregl-canvas').waitFor();
  assert(await page.locator('.atlas-page').getAttribute('data-projection') === 'mercator', 'Projection persists after reload');
  assert(await page.locator('.atlas-page').getAttribute('data-theme') === 'light', 'Theme persists after reload');
  await page.getByRole('button', { name: 'Open display settings', exact: true }).click();
  assert(!await page.getByLabel('Show location labels', { exact: true }).isChecked(), 'Label visibility persists after reload');
  await page.getByRole('button', { name: 'System', exact: true }).click();
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.waitForFunction(() => document.querySelector('.atlas-page').dataset.theme === 'dark');
  await page.emulateMedia({ colorScheme: 'light' });
  await page.waitForFunction(() => document.querySelector('.atlas-page').dataset.theme === 'light');
  assert(true, 'System appearance follows operating-system changes');
  await page.locator('#map-projection').selectOption('equal-earth'); await page.getByLabel('Show location labels', { exact: true }).check();
  await page.getByRole('button', { name: 'Dark', exact: true }).click(); await page.getByRole('button', { name: 'Done', exact: true }).click();
  await page.getByRole('button', { name: 'Pause playback', exact: true }).click(); await scrubber.fill(await scrubber.getAttribute('max'));
  await page.locator('[data-location-id="unlocated"]').click();
  assert(await page.locator('.atlas-map-location-card').getAttribute('data-location-card') === 'unlocated', 'Unlocated traffic can be selected without inventing a map point');
  await page.locator('.atlas-clear-location').click();
  await page.screenshot({ path: 'output/playwright/workspace-map.png' });
  await page.setViewportSize({ width: 390, height: 844 });
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Mobile map has no page overflow');
  await page.screenshot({ path: 'output/playwright/workspace-mobile.png' });
  await page.getByRole('button', { name: 'Expand traffic timeline', exact: true }).click();
  await page.locator('.atlas-mobile-timeline-filters').waitFor();
  await page.locator('.atlas-mobile-timeline-filters').getByRole('button', { name: '↑ Sent', exact: true }).click();
  assert(await page.locator('.atlas-wave-received').count() === 0, 'Mobile full-screen timeline retains direction controls');
  await page.screenshot({ path: 'output/playwright/workspace-mobile-timeline.png' });
  await page.keyboard.press('Escape');
  assert(errors.length === 0, 'No uncaught browser errors');
  return { checks, errors };
}
