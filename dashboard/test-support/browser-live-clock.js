// Run in an isolated browser against a dashboard build. Fixtures stay in this
// browser's intercepted requests; no gateway records or display settings change.
async (page) => {
  const app = new URL(page.url()).origin;
  const id = 'live-clock-regression', created = Date.now() - 3_600_000;
  const iso = value => new Date(value).toISOString();
  let offline = false, manifests = 0;
  const session = () => ({ id, name: 'Live clock regression', active: true, ephemeral: true,
    retention_minutes: 30, created: iso(created), started_at: iso(Date.now() - 1_800_000), updated: iso(Date.now()) });
  await page.unrouteAll({ behavior: 'wait' });
  await page.route('**/api/**', route => {
    const url = new URL(route.request().url()), now = Date.now();
    if (offline || url.pathname === '/api/realtime') return route.fulfill({ status: 503, json: { message: 'Test connection unavailable' } });
    if (url.pathname.endsWith('/manifest')) {
      manifests++;
      return route.fulfill({ json: { sessionId: id, name: session().name, active: true, ephemeral: true, retentionMinutes: 30,
        startedAt: session().started_at, endedAt: null, serverNow: iso(now), watermark: iso(now), counts: {},
        coverage: { from: session().started_at, to: iso(now) }, gateAuditComplete: true, gateAuditDrops: 0 } });
    }
    if (url.pathname.endsWith('/window')) {
      const flows = ['active', 'idle'].map((name, i) => ({ id: name, session: id, client_ip: '10.0.0.112',
        destination_ip: `203.0.113.${i + 1}`, source_port: 50000 + i, destination_port: 443, protocol: 'tcp', state: 'ESTABLISHED',
        start: iso(created + 1000), last_seen: iso(i ? created + 5000 : now), created: iso(created + 1000), updated: iso(now),
        bytes_in: 1000, bytes_out: 100, packets_in: 10, packets_out: 1 }));
      return route.fulfill({ json: { range: { from: iso(Number(url.searchParams.get('from'))), to: iso(Number(url.searchParams.get('to'))) },
        lod: url.searchParams.get('lod'), watermark: iso(now), flows, dnsQueries: [], attributions: [], activityEpisodes: [], flowAssociations: [],
        flowActivityChunks: [], flowActivityWindows: [], flowActivityStatuses: [], routes: [], gateEvents: [], nextCursor: null,
        destinations: flows.map((flow, i) => ({ id: `d${i}`, ip: flow.destination_ip, city: i ? 'London' : 'Stockholm', country: i ? 'GB' : 'SE',
          lat: i ? 51.5 : 59.3, lon: i ? -.1 : 18.1, created: iso(created), last_seen: iso(now), updated: iso(now) })) } });
    }
    return route.fulfill({ json: { items: url.pathname.includes('/sessions/') ? [session()] : [], page: 1, totalPages: 1, totalItems: 1 } });
  });
  try {
    await page.evaluate(() => localStorage.setItem('infrareveal.map.display.v1', JSON.stringify({ projection: 'mercator', quality: 'raspberry-pi', theme: 'dark', labels: true })));
    await page.goto(`${app}/map/${id}`);
    await page.waitForFunction(() => document.querySelector('.atlas-page')?.dataset.playbackState === 'following');
    await page.getByRole('button', { name: /^Tracks / }).click();
    await page.getByRole('button', { name: 'Active now', exact: true }).click();
    await page.locator('.atlas-track').first().waitFor();
    await page.getByRole('button', { name: 'Pause playback', exact: true }).click();
    const paused = await page.locator('.atlas-clock strong').innerText(), revision = manifests;
    // Cross multiple real manifest refreshes, with a moving startedAt as on the Pi.
    await page.waitForTimeout(6000);
    if (manifests <= revision) throw new Error('Regression did not cross a manifest refresh');
    const after = await page.locator('.atlas-clock strong').innerText();
    if (after !== paused) throw new Error(`Paused clock rebased: ${paused} -> ${after}`);
    if (!await page.locator('.atlas-track').count()) throw new Error('Active now lost the connection at the paused instant');
    await page.getByRole('button', { name: 'Go live', exact: true }).click();
    offline = true;
    // A radio outage can outlast the 30–60-second animation headroom. Live intent
    // must survive reaching that bound, so reconnection resumes without a click.
    await page.waitForTimeout(65000);
    if (await page.locator('.atlas-page').getAttribute('data-playback-state') !== 'following') throw new Error('Outage silently stopped live following');
    offline = false;
    await page.waitForFunction(() => !document.querySelector('.atlas-connection-notice'), undefined, { timeout: 25000 });
    await page.locator('.atlas-track').first().waitFor();
    await page.getByRole('button', { name: 'Pause playback', exact: true }).click();
    const recovered = await page.locator('.atlas-clock strong').innerText();
    await page.waitForTimeout(3000);
    if (await page.locator('.atlas-clock strong').innerText() !== recovered) throw new Error('Recovery broke explicit pause');
    return { pausedClockStable: true, activeFilterVisible: true, outageResumedLive: true, explicitPauseRetained: true, manifests };
  } finally {
    await page.goto('about:blank');
    await page.unrouteAll({ behavior: 'wait' });
  }
}
