// Vite on 5188 and the standard gateway fixture. Exercise real GPU models and uploads.
async (page) => {
  await page.unrouteAll({ behavior: 'wait' });
  await page.request.post('http://127.0.0.1:8095/__fixture', { data: { count: 24, routes: true, resetSources: true } });
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 2, mobile: false });
  await page.goto('http://127.0.0.1:5188/map/live-session');
  await page.evaluate(() => localStorage.setItem('infrareveal.map.display.v1', JSON.stringify({ projection: 'mercator', theme: 'dark', labels: true, quality: 'full' })));
  await page.reload();
  await page.locator('.maplibregl-canvas').waitFor();
  const errors = [];
  const onError = error => errors.push(error.message);
  page.on('pageerror', onError);
  await page.evaluate(async () => {
    const countries = (await import('/src/map/data/countries.json')).default;
    globalThis.__qualityStats = {};
    globalThis.__qualityFailures = [];
    globalThis.__qualityRestore = [];
    for (const name of ['FlowArcLayer', 'FlowPathLayer']) {
      const url = performance.getEntriesByType('resource').find(entry => entry.name.includes(`/src/map/${name}.ts`))?.name;
      const Layer = (await import(url))[name], draw = Layer.prototype.draw;
      Layer.prototype.draw = function(...args) {
        if (this.props.id === 'traffic-streams' || this.props.id === 'traceroute-streams') {
          const data = this.props.data;
          if (data.length) {
            const attributes = this.getAttributeManager().getAttributes();
            for (let bank = 0; bank < 3; bank++) {
              const values = attributes['instanceRadii' + bank].value;
              for (let i = 0; i < Math.min(3, data.length); i++) for (let j = 0; j < 4; j++) {
                if (Math.abs(values[i * 4 + j] - data[i].radii[bank * 4 + j]) > .0001) globalThis.__qualityFailures.push('Stale radii: ' + name);
              }
            }
            globalThis.__qualityStats[name] = { segments: this.props.numSegments, indices: this.state.model.vertexCount, instances: data.length };
            const layers = this.context.deck.props.layers.flat();
            const basemap = layers.find(layer => layer?.id === 'base-geography');
            const labels = layers.find(layer => layer?.id === 'base-labels');
            if (basemap?.state.model && labels) {
              let alignmentError = 0;
              for (const label of labels.props.data) {
                const source = countries.find(country => country.name === label.name);
                const actual = labels.project([...label.position, 0]);
                const expected = this.context.viewport.project(source.position);
                alignmentError = Math.max(alignmentError, Math.hypot(actual[0] - expected[0], actual[1] - expected[1]));
              }
              globalThis.__qualityStats.basemap = { indices: basemap.state.model.vertexCount, textureWidth: basemap.props.image.width, bounds: basemap.props.bounds, alignmentError };
            }
          }
        }
        return draw.apply(this, args);
      };
      globalThis.__qualityRestore.push(() => { Layer.prototype.draw = draw; });
    }
  });
  async function sample() {
    await page.waitForTimeout(1800);
    return page.evaluate(() => ({ layers: globalThis.__qualityStats, failures: globalThis.__qualityFailures.slice(0, 3), canvases: [...document.querySelectorAll('canvas')].map(canvas => ({ width: canvas.width, cssWidth: canvas.clientWidth })) }));
  }
  try {
    const full = await sample();
    await page.getByRole('button', { name: 'Open display settings', exact: true }).click();
    await page.getByLabel('Rendering detail', { exact: true }).selectOption('raspberry-pi');
    await page.getByRole('button', { name: 'Done', exact: true }).click();
    const light = await sample();
    if (full.layers.FlowArcLayer?.indices !== 11520 || light.layers.FlowArcLayer?.indices !== 768) throw new Error('Arc mesh did not switch: ' + JSON.stringify({ full, light }));
    if (full.layers.FlowPathLayer?.indices !== 72 || light.layers.FlowPathLayer?.indices !== 24) throw new Error('Path mesh did not switch: ' + JSON.stringify({ full, light }));
    if (light.canvases.length !== 1) throw new Error('Pi basemap allocated another WebGL context');
    if (light.layers.basemap?.indices !== 6 || light.layers.basemap.alignmentError > .1) throw new Error('Cached basemap missing or misaligned: ' + JSON.stringify(light.layers.basemap));
    if (light.canvases.some(canvas => Math.abs(canvas.width - canvas.cssWidth) > 2)) throw new Error('Pi resolution not applied: ' + JSON.stringify(light.canvases));
    if (full.failures.length || light.failures.length || errors.length) throw new Error(JSON.stringify({ full, light, errors }));
    await page.screenshot({ path: 'output/playwright/map-raspberry-pi-quality.png' });
    await page.getByRole('button', { name: 'Center on gateway', exact: true }).click();
    const zoomed = await sample();
    if (zoomed.layers.basemap.textureWidth !== 4096 || zoomed.layers.basemap.bounds[2] - zoomed.layers.basemap.bounds[0] >= 512 || zoomed.layers.basemap.alignmentError > .1) throw new Error('Zoom did not refresh the detailed basemap region: ' + JSON.stringify(zoomed.layers.basemap));
    await page.screenshot({ path: 'output/playwright/map-raspberry-pi-zoom.png' });
    await page.evaluate(() => globalThis.__qualityRestore.forEach(restore => restore()));
    await page.reload();
    await page.getByRole('button', { name: 'Open display settings', exact: true }).click();
    if (await page.getByLabel('Rendering detail', { exact: true }).inputValue() !== 'raspberry-pi') throw new Error('Quality preference not saved');
    await page.getByRole('button', { name: 'Done', exact: true }).click();
    return { full, light, zoomed, errors, preferencePersists: true };
  } finally {
    await page.evaluate(() => globalThis.__qualityRestore?.forEach(restore => restore()));
    page.off('pageerror', onError);
    await cdp.send('Emulation.clearDeviceMetricsOverride');
    await cdp.detach();
  }
}
