export default async (page, harness) => {
  const { assert } = harness
  // Playwright CLI: run on a live /map/:sessionID with captured traffic.
  const timeline = page.locator('.atlas-detail-timeline');
  if (!await timeline.count()) await page.getByRole('button', { name: 'Expand traffic timeline', exact: true }).click();
  await page.locator('.atlas-flow-envelope').first().waitFor();
  const measure = (duration, stage) => page.evaluate(async ({ duration, stage }) => {
    const chart = document.querySelector('.atlas-detail-timeline');
    const time = Number(chart.dataset.windowTo) - 3000;
    const samples = [], longTasks = [];
    const observer = new PerformanceObserver(list => { for (const entry of list.getEntries()) longTasks.push(entry.duration); });
    observer.observe({ type: 'longtask', buffered: false });
    const start = performance.now();
    await new Promise((resolve, reject) => {
      const frame = now => {
        const svg = chart.querySelector('.atlas-detail-lane svg');
        if (!chart.isConnected || !svg) {
          observer.disconnect();
          reject(new Error(`${stage}: timeline lanes disappeared: ${JSON.stringify({ connected: chart.isConnected, ...chart.dataset, busy: chart.getAttribute('aria-busy'), empty: chart.querySelector('.atlas-timeline-empty')?.textContent })}`));
          return;
        }
        const from = Number(chart.dataset.gridFrom), to = Number(chart.dataset.gridTo);
        const transform = new DOMMatrixReadOnly(getComputedStyle(svg).transform);
        const offset = transform.e / svg.clientWidth, scale = transform.a;
        // One fixed timestamp must slide continuously, including across grid
        // rebases. Compare physical position, not changing SVG coordinates.
        const x = Number.isFinite(from) ? offset + (time - from) / (to - from) * scale : (time - Number(chart.dataset.windowFrom)) / (Number(chart.dataset.windowTo) - Number(chart.dataset.windowFrom));
        samples.push({ now, x });
        if (now - start < duration) requestAnimationFrame(frame); else resolve();
      };
      requestAnimationFrame(frame);
    });
    observer.disconnect();
    const changed = samples.slice(1).filter((sample, i) => Math.abs(sample.x - samples[i].x) > 1e-9);
    const frames = samples.slice(1).map((sample, i) => sample.now - samples[i].now).sort((a,b) => a-b);
    const gaps = changed.slice(1).map((sample, i) => sample.now - changed[i].now).sort((a,b) => a-b);
    return { frames: samples.length, updates: changed.length, motionFraction: changed.length / (samples.length - 1), medianMovementGapMS: gaps[Math.floor(gaps.length * .5)] ?? 0, p95FrameMS: frames[Math.floor(frames.length * .95)], longTasks: longTasks.length, maxLongTaskMS: Math.max(0, ...longTasks), lanes: Number(chart.dataset.visibleLanes) };
  }, { duration, stage });
  const setWindow = async value => {
    await page.getByRole('button', { name: 'Filters', exact: true }).click();
    await page.getByRole('combobox', { name: 'History', exact: true }).selectOption(value);
    await page.getByRole('button', { name: 'Close filters', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('.atlas-flow-envelope') && document.querySelector('.atlas-detail-timeline')?.getAttribute('aria-busy') === 'false');
  };
  await setWindow('300000');
  await page.getByRole('button', { name: /^(Go live|Live)$/ }).click();
  const fiveMinutes = await measure(8000, 'five minutes');
  assert(fiveMinutes.motionFraction > .9, 'Five-minute viewport freezes between data publications');
  await setWindow('30000');
  // Cross a thirty-second data-request boundary, not just a few paint frames.
  const thirtySeconds = await measure(35000, 'thirty seconds');
  assert(thirtySeconds.motionFraction > .9, 'Thirty-second viewport freezes between data publications');
  await page.getByRole('combobox', { name: 'Playback speed' }).selectOption('0.5');
  const slowReplay = await measure(3000, 'slow replay');
  assert(slowReplay.motionFraction > .9, 'Slow replay is quantized to data updates');
  await page.getByRole('button', { name: 'Pause playback' }).click();
  const paused = await measure(1200, 'paused');
  assert(paused.updates === 0, 'Paused viewport moved');
  await page.getByRole('button', { name: /^(Go live|Live)$/ }).click();
  await page.locator('.atlas-detail-track').first().focus();
  const held = await measure(1200, 'held');
  assert(held.updates === 0, 'Inspection did not hold the viewport');
  await page.getByRole('button', { name: /^(Go live|Live)$/ }).click();
  await setWindow('300000');
  return { fiveMinutes, thirtySeconds, slowReplay, paused, held };
}
