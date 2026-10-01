// Vite dashboard on port 5188, standard gateway fixture on 8095.
async (page) => {
  await page.bringToFront();
  await page.setViewportSize({width:1280,height:800});
  const api = 'http://127.0.0.1:8095';
  await page.request.post(api + '/__fixture', { data: { count: 4, routes: true } });
  const manifest = await (await page.request.get(api + '/api/infrareveal/sessions/recorded-session/manifest')).json();
  await page.goto('http://127.0.0.1:5188/map/recorded-session');
  await page.evaluate(() => localStorage.setItem('infrareveal.map.display.v1', JSON.stringify({ projection: 'mercator', theme: 'dark', labels: true })));
  await page.reload();
  await page.locator('.maplibregl-canvas').waitFor();
  await page.getByRole('button', { name: 'Pause playback', exact: true }).click();
  const start = Date.parse(manifest.startedAt);
  const boundary = Math.ceil((start + 5000) / 30000) * 30000;
  await page.getByRole('slider', { name: 'Session timeline', exact: true }).fill(String(Math.round((boundary - start - 2000) / 1000 * 30)));
  await page.getByRole('button', { name: 'Play session', exact: true }).click();
  await page.waitForTimeout(1500);
  const result = await page.evaluate(async () => {
    const resources = performance.getEntriesByType('resource');
    const observations = [], models = new Map(), restore = [];
    for (const name of ['FlowArcLayer', 'FlowPathLayer']) {
      const url = resources.find(entry => entry.name.includes(`/src/map/${name}.ts`))?.name;
      if (!url) throw new Error('Requires Vite module access');
      const Layer = (await import(url))[name], draw = Layer.prototype.draw;
      Layer.prototype.draw = function (...args) {
        const id = this.props.id;
        if (id === 'traffic-streams' || id === 'traceroute-streams') {
          if (!models.has(id)) models.set(id, new Set());
          models.get(id).add(this.state.model);
          observations.push({ id, wall: performance.now(), clock: this.getAnimationTime().time, count: this.props.data.length });
        }
        return draw.apply(this, args);
      };
      restore.push(() => { Layer.prototype.draw = draw; });
    }
    try { await new Promise(resolve => setTimeout(resolve, 7000)); }
    finally { restore.forEach(fn => fn()); }
    return ['traffic-streams', 'traceroute-streams'].map(id => {
      const frames = observations.filter(frame => frame.id === id);
      if (frames.length < 2) throw new Error('No animation frames');
      return { id, elapsed: (frames.at(-1).wall - frames[0].wall) / 1000, advanced: frames.at(-1).clock - frames[0].clock,
        resets: frames.slice(1).filter((frame, i) => frame.clock < frames[i].clock || frame.clock - frames[i].clock > .3).length,
        emptyFrames: frames.filter(frame => frame.count === 0).length, models: models.get(id).size };
    });
  });
  if (result.some(value => value.resets || value.emptyFrames || value.models !== 1 || Math.abs(value.advanced - value.elapsed) > .25)) throw new Error(JSON.stringify(result));
  return result;
}
