// Run against Vite on 5188 and the gateway fixture. Exercise real cache renders and GPU picking.
async page => {
  await page.unrouteAll({behavior:'wait'});
  const app='http://127.0.0.1:5188';
  await page.setViewportSize({width:1440,height:1000});
  await page.route('**/api/infrareveal/sessions/recorded-session/window**',async route=>{
    const response=await route.fetch(), body=await response.json();
    body.destinations=body.destinations.map((item,i)=>({...item,...(i%2 ? {country:'SE',city:'Stockholm',lat:59.3,lon:18.1}:{country:'US',city:'',lat:39,lon:-98})}));
    await route.fulfill({response,json:body});
  });
  await page.goto(app+'/map/recorded-session');
  await page.evaluate(()=>localStorage.setItem('infrareveal.map.display.v1',JSON.stringify({projection:'mercator',quality:'raspberry-pi',theme:'dark',labels:true})));
  await page.reload();
  await page.locator('.atlas-location-row').first().waitFor();
  await page.getByRole('button',{name:'Pause playback',exact:true}).click();
  await page.getByRole('slider',{name:'Session timeline',exact:true}).fill('900');
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.evaluate(async()=>{
    const url=performance.getEntriesByType('resource').find(entry=>entry.name.includes('/src/map/MercatorBackground.ts'))?.name;
    const {MercatorBackgroundLayer}=await import(url), original=MercatorBackgroundLayer.prototype.draw;
    globalThis.__backgroundRenders=0;
    MercatorBackgroundLayer.prototype.draw=function(...args){
      globalThis.__backgroundDeck=this.context.deck;
      const cache=this.props.cache;
      if(globalThis.__backgroundCache!==cache){
        globalThis.__backgroundCache=cache;
        const render=cache.pass.render;
        cache.pass.render=function(...args){globalThis.__backgroundRenders++;return render.apply(this,args)};
        globalThis.__backgroundRestorePass=()=>{if(cache.pass)cache.pass.render=render};
      }
      return original.apply(this,args);
    };
    globalThis.__backgroundRestore=()=>{MercatorBackgroundLayer.prototype.draw=original;globalThis.__backgroundRestorePass?.()};
  });
  try {
    await page.getByRole('button',{name:'Top-down',exact:true}).click();
    await page.waitForTimeout(700);
    const stable=await page.evaluate(()=>{
      const before=globalThis.__backgroundRenders;
      for(let i=0;i<8;i++)globalThis.__backgroundDeck.redraw('cache regression');
      return globalThis.__backgroundRenders-before;
    });
    if(stable!==0)throw new Error('Unchanged background rendered '+stable+' times');
    const picked=await page.evaluate(()=>{
      const deck=globalThis.__backgroundDeck;
      const [x,y]=deck.getViewports()[0].project([-100,40]);
      return deck.pickObject({x,y,layerIds:['country-footprints']})?.object?.countryCode;
    });
    if(picked!=='US')throw new Error('Cached country lost GPU picking: '+picked);
    const before=await page.evaluate(()=>globalThis.__backgroundRenders);
    await page.getByRole('button',{name:'Zoom in',exact:true}).click();
    await page.waitForTimeout(400);
    const zoomed=await page.evaluate(()=>globalThis.__backgroundRenders);
    if(zoomed<=before)throw new Error('Zoom did not invalidate background');
    await page.setViewportSize({width:1100,height:800});
    await page.waitForTimeout(400);
    const size=await page.evaluate(()=>({texture:[globalThis.__backgroundCache.framebuffer.width,globalThis.__backgroundCache.framebuffer.height],canvas:[globalThis.__backgroundDeck.canvas.width,globalThis.__backgroundDeck.canvas.height]}));
    if(JSON.stringify(size.texture)!==JSON.stringify(size.canvas))throw new Error('Cache did not resize: '+JSON.stringify(size));
    const priorToggle=await page.evaluate(()=>globalThis.__backgroundRenders);
    await page.getByRole('button',{name:'Traffic',exact:true}).click();
    await page.waitForTimeout(400);
    if(await page.evaluate(()=>globalThis.__backgroundRenders)<=priorToggle)throw new Error('Hidden route geometry remained cached');
    await page.getByRole('button',{name:'Traffic',exact:true}).click();
    await page.getByRole('button',{name:'Open display settings',exact:true}).click();
    await page.getByRole('button',{name:'Light',exact:true}).click();
    await page.getByRole('button',{name:'Done',exact:true}).click();
    await page.waitForTimeout(400);
    await page.screenshot({path:'output/playwright/mercator-cache-light.png'});
    await page.getByRole('button',{name:'Open display settings',exact:true}).click();
    await page.getByLabel('Rendering detail',{exact:true}).selectOption('full');
    await page.getByRole('button',{name:'Done',exact:true}).click();
    await page.locator('.maplibregl-canvas').waitFor();
    if(!await page.evaluate(()=>!globalThis.__backgroundCache.framebuffer))throw new Error('Full quality retained cache allocation');
    if(errors.length)throw new Error(JSON.stringify(errors));
    return {stableBackgroundRedraws:stable,countryPicked:picked,cameraRefresh:true,resize:size,trafficToggle:true,qualityCleanup:true,errors};
  } finally {await page.evaluate(()=>globalThis.__backgroundRestore?.());await page.unrouteAll({behavior:'wait'});}
}
