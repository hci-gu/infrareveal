// Run against the Vite dashboard on port 5188 and the standard gateway fixture.
async (page) => {
  await page.bringToFront();
  await page.setViewportSize({width:1280,height:800});
  await page.request.post('http://127.0.0.1:8095/__fixture', { data: { count: 4, routes: true } });
  await page.route('**/sessions/live-session/manifest', async route => {
    const response = await route.fetch();
    await route.fulfill({ response, json: { ...await response.json(), ephemeral: true, retentionMinutes: 1 } });
  });
  await page.goto('http://127.0.0.1:5188/map/live-session');
  await page.evaluate(() => localStorage.setItem('infrareveal.map.display.v1', JSON.stringify({ projection: 'mercator', theme: 'dark', labels: true })));
  await page.reload();
  await page.locator('.maplibregl-canvas').waitFor();
  await page.waitForFunction(() => document.querySelector('main')?.dataset.playbackState === 'following');
  // Let initial shader compilation finish before checking frame continuity.
  await page.waitForTimeout(3000);
  const measure = (duration) => page.evaluate(async duration => {
    const sources = performance.getEntriesByType('resource');
    const layers = await Promise.all(['FlowArcLayer', 'FlowPathLayer'].map(async name => {
      const url = sources.find(entry => entry.name.includes(`/src/map/${name}.ts`))?.name;
      if (!url) throw new Error(`Missing ${name} module`);
      return (await import(url))[name];
    }));
    const observations = [], restore = [];
    globalThis.__rollingLayers ??= {};
    const readClocks = () => { for (const [id, layer] of Object.entries(globalThis.__rollingLayers)) observations.push({layer:id,wall:performance.now(),clock:layer.getAnimationTime().time}); };
    readClocks();
    for (const Layer of layers) {
      const draw = Layer.prototype.draw;
      Layer.prototype.draw = function (...args) {
        if (this.props.id === 'traffic-streams' || this.props.id === 'traceroute-streams') { globalThis.__rollingLayers[this.props.id] = this; observations.push({ layer: this.props.id, wall: performance.now(), clock: this.getAnimationTime().time }); }
        return draw.apply(this, args);
      };
      restore.push(() => { Layer.prototype.draw = draw; });
    }
    try { await new Promise(resolve => setTimeout(resolve, duration)); }
    finally { readClocks(); restore.forEach(fn => fn()); }
    return ['traffic-streams', 'traceroute-streams'].map(layer => {
      const samples = observations.filter(sample => sample.layer === layer);
      if (samples.length < 2) throw new Error(`No ${layer} frames`);
      const elapsed = (samples.at(-1).wall - samples[0].wall) / 1000;
      const advanced = samples.at(-1).clock - samples[0].clock;
      const resets = samples.slice(1).filter((sample, i) => sample.clock < samples[i].clock - .01).length;
      const largestClockError = Math.max(...samples.slice(1).map((sample, i) => Math.abs(sample.clock - samples[i].clock - (sample.wall - samples[i].wall) / 1000)));
      const largestStep = Math.max(...samples.slice(1).map((sample, i) => Math.abs(sample.clock - samples[i].clock)));
      return { layer, elapsed, advanced, resets, largestStep, largestClockError, first: samples[0].clock, last: samples.at(-1).clock, renders: samples.length };
    });
  }, duration);
  const result = await measure(7000);
  if (result.some(item => item.resets || Math.abs(item.elapsed - item.advanced) > .3 || item.largestClockError > .1)) throw new Error(JSON.stringify(result));
  await page.getByRole('button', { name: 'Pause playback', exact: true }).click();
  const paused = await measure(1800);
  if (paused.some(item => item.advanced !== 0)) throw new Error('Retention moved paused playback: ' + JSON.stringify(paused));
  await page.getByRole('button', { name: 'Back 10 seconds', exact: true }).click();
  const sought = await measure(1800);
  if (sought.some((item, i) => Math.abs(item.first - paused[i].last + 10) > .1 || item.advanced !== 0)) throw new Error('Window-relative seek changed absolute playback time: ' + JSON.stringify(sought));
  await page.getByRole('button', { name: 'Play session', exact: true }).click();
  await page.getByRole('combobox', { name: 'Playback speed' }).selectOption('2');
  const replay = await measure(2500);
  if (replay.some(item => item.resets || Math.abs(item.elapsed * 2 - item.advanced) > .3)) throw new Error('Replay clock changed at retention ticks: ' + JSON.stringify(replay));
  await page.getByRole('button', { name: 'Pause playback', exact: true }).click();
  const slider = page.getByRole('slider', { name: 'Session timeline', exact: true });
  await slider.fill('0');
  await page.waitForTimeout(1500);
  if (Number(await slider.inputValue()) > 2 || await page.locator('main').getAttribute('data-playback-state') !== 'paused') throw new Error('Expired replay did not clamp to retained start while paused');
  if (Number(await slider.getAttribute('max')) > 31 * 60) throw new Error('Transport exposed history outside the one-minute retained window');
  await page.getByRole('button', { name: 'Go live', exact: true }).click();
  const resumed = await measure(2000);
  if (resumed.some(item => item.resets || Math.abs(item.elapsed - item.advanced) > .3)) throw new Error('Returning to live changed animation speed');
  const shader = await page.evaluate(async () => {
    const { CountryFlowArcLayer } = await import('/src/map/CountryLayers.ts');
    return (await import('/scripts/check-traffic-animation.js')).checkTrafficAnimation([CountryFlowArcLayer]);
  });
  if (!shader.passed) throw new Error(JSON.stringify(shader));
  await page.unrouteAll({ behavior: 'wait' });
  return { following: result, paused, sought, replay, resumed, expiredPositionClamped: true, shader };
}
