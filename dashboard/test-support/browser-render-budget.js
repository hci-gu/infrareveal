// Run against the production build and gateway fixture. Assert real GPU work budgets.
async page => {
  await page.unrouteAll({behavior:'wait'});
  await page.setViewportSize({width:1280,height:800});
  await page.request.post('http://127.0.0.1:8095/__fixture',{data:{count:24,routes:true,resetSources:true}});
  await page.goto('http://127.0.0.1:5188/map/recorded-session');
  await page.evaluate(()=>localStorage.setItem('infrareveal.map.display.v1',JSON.stringify({projection:'mercator',quality:'raspberry-pi',theme:'dark',labels:true})));
  await page.reload();await page.bringToFront();
  await page.locator('#deckgl-overlay').waitFor();
  await page.waitForTimeout(1500);
  if(await page.locator('canvas').count()!==1)throw new Error('Pi mode must use one WebGL canvas');
  const install=()=>page.evaluate(()=>{
    globalThis.__renderDrawCalls=0;globalThis.__renderRestores=[];
    for(const name of ['drawElementsInstanced','drawArraysInstanced','drawElements','drawArrays']) {
      const original=WebGL2RenderingContext.prototype[name];
      WebGL2RenderingContext.prototype[name]=function(...args){globalThis.__renderDrawCalls++;return original.apply(this,args)};
      globalThis.__renderRestores.push(()=>WebGL2RenderingContext.prototype[name]=original);
    }
  });
  const sample=async()=>{await page.evaluate(()=>{globalThis.__renderDrawCalls=0});await page.waitForTimeout(1800);return page.evaluate(()=>globalThis.__renderDrawCalls)};
  await install();
  try {
    const playing=await sample();
    await page.getByRole('button',{name:'Pause playback',exact:true}).click();await page.waitForTimeout(700);
    const paused=await sample();
    if(playing===0 || paused>5)throw new Error(JSON.stringify({playing,paused}));
    await page.getByRole('button',{name:'Expand traffic timeline',exact:true}).click();
    await page.getByRole('button',{name:'Play session',exact:true}).click();await page.waitForTimeout(500);
    const expanded=await sample();
    if(expanded>5)throw new Error('Hidden map still draws: '+expanded);
    const resources=await page.evaluate(()=>performance.getEntriesByType('resource').map(r=>r.name));
    if(resources.some(url=>/TiledBasemap-|maplibre-gl-worker-/.test(url)))throw new Error('Pi mode loaded tiled basemap code');
    await page.getByRole('button',{name:'Back to map',exact:true}).first().click();
    await page.getByRole('button',{name:'Open display settings',exact:true}).click();
    await page.getByLabel('Map projection',{exact:true}).selectOption('equal-earth');
    await page.getByRole('button',{name:'Done',exact:true}).click();
    await page.reload();
    await page.locator('svg[aria-label="Equal Earth traffic map"]').waitFor();
    const earthResources=await page.evaluate(()=>performance.getEntriesByType('resource').map(r=>r.name));
    if(earthResources.some(url=>/MercatorComposition-|TiledBasemap-|maplibre-gl-worker-/.test(url)))throw new Error('Equal Earth loaded the unused graphics stack');
    return {playing,paused,expanded,oneCanvas:true,piTilesDeferred:true,equalEarthGraphicsDeferred:true};
  } finally {await page.evaluate(()=>globalThis.__renderRestores?.forEach(fn=>fn()));}
}
