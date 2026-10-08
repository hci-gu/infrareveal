// Run after browser-workspace.js against the production preview and gateway fixture.
async (page) => {
  await page.unrouteAll({ behavior: 'wait' });
  await page.route('**/api/infrareveal/demo', route => {
    const now = new Date().toISOString();
    return route.fulfill({ json: { enabled: true, serverNow: now, sessionId: 'live-session', ssid: 'Infrareveal', retentionMinutes: 30, observing: true, catalogueEnabled: true, maintenance: { lastSuccess: now, lastError: '' }, capture: { running: true, reportedAt: now, lastError: '' } } });
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('http://127.0.0.1:5188/demo');
  await page.waitForFunction(() => document.querySelector('.atlas-page')?.dataset.playbackState === 'following');
  if (!await page.locator('.atlas-transport').isVisible()) throw new Error('Demo map must show playback controls');
  if (await page.getByText('Connect to', { exact: false }).count()) throw new Error('Instructional Wi-Fi banner must be removed');
  await page.getByRole('button', { name: 'Pause playback', exact: true }).click();
  await page.waitForTimeout(1500);
  if (await page.locator('.atlas-page').getAttribute('data-playback-state') !== 'paused') throw new Error('Demo map must retain pause');
  await page.getByRole('button', { name: 'Go live', exact: true }).click();
  await page.getByRole('button', { name: 'Expand traffic timeline', exact: true }).click();
  await page.getByRole('button', { name: 'Pause playback', exact: true }).click();
  const slider = page.getByRole('slider', { name: 'Session timeline', exact: true });
  await slider.fill(String(Math.floor(Number(await slider.getAttribute('max')) / 2)));
  await page.waitForFunction(() => document.querySelector('.atlas-page').dataset.playbackState === 'paused');
  const frame = await slider.inputValue();
  // Observe multiple animation frames and a polling cycle: expanded demo must not force live.
  await page.waitForTimeout(1500);
  if (await slider.inputValue() !== frame) throw new Error('Expanded demo did not retain paused replay position');
  await page.getByRole('button', { name: '↙ Back to map', exact: true }).click();
  if (!await page.locator('.atlas-transport').isVisible()) throw new Error('Map must retain playback controls');
  await page.waitForTimeout(1500);
  if (await slider.inputValue() !== frame) throw new Error('Returning to map must retain replay position');
  await page.getByRole('button', { name: 'Go live', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('.atlas-page').dataset.playbackState === 'following');
  await page.goto('http://127.0.0.1:5188/map/recorded-session');
  await page.unrouteAll({ behavior: 'wait' });
  return { demoFollowsLive: true, expandedReplayPauses: true, returningPreservesReplay: true, mapTransportVisible: true, noInstructionBanner: true };
}
