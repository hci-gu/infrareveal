// Run against a production build with --minify false and the standard gateway fixture.
async (page) => {
  const counters = ['MapPage', 'MapComposition', 'MapOverview', 'EqualEarthMap', 'projectWorkspace', 'wireWaveform', 'projectMapFrame', 'projectTrafficProfiles', 'projectDestinationVolumes', 'buildTrafficPaths', 'indexDestinationVolumes'];
  const bypass = { projectMapFrame: '{points:[],arcs:[],hops:[]}', projectTrafficProfiles: 'new Map()', projectDestinationVolumes: '[]' };
  await page.unrouteAll({ behavior: 'wait' });
  await page.route('**/assets/MapPage-*.js', async route => {
    const response = await route.fetch();
    let body = await response.text();
    for (const name of counters) {
      const signature = new RegExp('function ' + name + '\\([^\\n]*\\) \\{');
      if (!signature.test(body)) throw new Error('Missing instrumentation seam: ' + name);
      body = body.replace(signature, match => match + '\n(globalThis.__mapPerfCalls ??= {})[' + JSON.stringify(name) + '] = (globalThis.__mapPerfCalls[' + JSON.stringify(name) + '] ?? 0) + 1;' + (bypass[name] ? '\nif (globalThis.__mapPerfSkipMercator) return ' + bypass[name] + ';' : ''));
    }
    await route.fulfill({ response, body });
  });
  await page.request.post('http://127.0.0.1:8095/__fixture', { data: { count: 24, routes: true, resetSources: true } });
  await page.route('**/api/infrareveal/sessions/live-session/window**', async route => {
    const response = await route.fetch();
    const body = await response.json();
    const locations = [
      {lat:59.3,lon:18.1,city:'Stockholm',country:'SE'},
      {lat:52.5,lon:13.4,city:'Berlin',country:'DE'},
      {lat:37.8,lon:-122.4,city:'San Francisco',country:'US'},
      {lat:39,lon:-98,city:'',country:'US'},
      {lat:35.7,lon:139.7,city:'Tokyo',country:'JP'},
      {lat:-33.9,lon:151.2,city:'Sydney',country:'AU'},
    ];
    if (body.destinations) body.destinations = body.destinations.map((item, i) => ({...item, ...locations[i % locations.length]}));
    await route.fulfill({ response, json: body });
  });
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('http://127.0.0.1:5188/map/live-session');
  await page.evaluate(() => localStorage.setItem('infrareveal.map.display.v1', JSON.stringify({projection:'equal-earth',appearance:'dark',labels:true})));
  await page.reload();
  await page.locator('.atlas-location-row').first().waitFor();
  await page.waitForTimeout(2500);
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: 6 });
  await cdp.send('Performance.enable');
  await cdp.send('Profiler.enable');
  await cdp.send('Profiler.setSamplingInterval', { interval: 1000 });
  const results = [];
  async function sample(label, seconds = 8) {
    await page.evaluate(() => {
      globalThis.__mapPerfCalls = {};
      globalThis.__mapPerfFrames = [];
      let previous = performance.now();
      const tick = now => { globalThis.__mapPerfFrames.push(now - previous); previous = now; globalThis.__mapPerfRaf = requestAnimationFrame(tick); };
      globalThis.__mapPerfRaf = requestAnimationFrame(tick);
    });
    const before = Object.fromEntries((await cdp.send('Performance.getMetrics')).metrics.map(m => [m.name,m.value]));
    await cdp.send('Profiler.start');
    await page.waitForTimeout(seconds * 1000);
    const {profile} = await cdp.send('Profiler.stop');
    const after = Object.fromEntries((await cdp.send('Performance.getMetrics')).metrics.map(m => [m.name,m.value]));
    const browser = await page.evaluate(() => {
      cancelAnimationFrame(globalThis.__mapPerfRaf);
      const frames = globalThis.__mapPerfFrames.slice(1).sort((a,b)=>a-b);
      return {calls:globalThis.__mapPerfCalls, rafCount:frames.length, rafP95:frames[Math.floor(frames.length * .95)], locations:document.querySelectorAll('.atlas-location-row').length, nodes:document.querySelectorAll('*').length};
    });
    const nodes = new Map(profile.nodes.map(n=>[n.id,n]));
    const parent = new Map();
    for (const n of profile.nodes) for (const child of n.children ?? []) parent.set(child,n.id);
    const self = new Map(), inclusive = new Map();
    for (let i=0;i<(profile.samples?.length ?? 0);i++) {
      const id=profile.samples[i], ms=(profile.timeDeltas?.[i] ?? 1000)/1000;
      self.set(id,(self.get(id)??0)+ms);
      for (let p=id;p;p=parent.get(p)) inclusive.set(p,(inclusive.get(p)??0)+ms);
    }
    const top = map => [...map].map(([id,ms])=>({name:nodes.get(id).callFrame.functionName || '(anonymous)',line:nodes.get(id).callFrame.lineNumber+1,ms:Math.round(ms)})).filter(n=>!['(root)','(idle)'].includes(n.name)).sort((a,b)=>b.ms-a.ms).slice(0,15);
    const metrics = {};
    for (const key of ['TaskDuration','ScriptDuration','LayoutDuration','RecalcStyleDuration']) metrics[key+'Ms'] = Math.round((after[key]-before[key])*1000);
    results.push({label,seconds,...browser,metrics,topSelf:top(self),topInclusive:top(inclusive)});
  }
  await sample('equal-earth-playing-optimized');
  await page.getByRole('button',{name:'Pause playback',exact:true}).click();
  await page.waitForTimeout(750);
  await sample('equal-earth-paused-optimized');
  await page.getByRole('button',{name:'Open display settings',exact:true}).click();
  await page.locator('#map-quality').selectOption('raspberry-pi');
  await page.locator('#map-projection').selectOption('mercator');
  await page.getByRole('button',{name:'Done',exact:true}).click();
  await page.getByRole('button',{name:'Play session',exact:true}).click();
  await page.locator('.maplibregl-canvas').waitFor();
  await page.waitForTimeout(2500);
  await sample('mercator-raspberry-pi-playing');
  const earth = results[0];
  if ((earth.calls.MapOverview ?? 0) > 100) throw new Error('Sidebar is following the animation clock');
  if (earth.calls.projectMapFrame || earth.calls.buildTrafficPaths || earth.calls.projectTrafficProfiles || earth.calls.projectDestinationVolumes) throw new Error('Equal Earth prepared the inactive Mercator projection');
  if ((earth.calls.wireWaveform ?? 0) > 24) throw new Error('Waveform is following the playhead');
  if ((results[2].calls.buildTrafficPaths ?? 0) > 2) throw new Error('Unchanged Mercator paths were resampled');
  await cdp.send('Emulation.setCPUThrottlingRate',{rate:1});
  await cdp.detach();
  const report = {environment:'Local Chromium, production React, unminified bundle for profiling, 6x CPU throttle; not a measurement of Pi FPS',fixture:'24 flows, six locations, one country footprint',results};
  await page.evaluate(report => { globalThis.__mapPerfReport = report; }, report);
  return report;
}
