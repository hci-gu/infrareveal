async (page) => {
  await page.setViewportSize({width:1440,height:900});
  await page.request.post('http://127.0.0.1:8095/__fixture',{data:{count:10000,resetSources:true,offline:false,delay:0,resetLog:true}});
  await page.goto('http://127.0.0.1:5174/');
  await page.evaluate(() => { for (const key of Object.keys(localStorage)) if (key.startsWith('infrareveal.debug.v3.traffic.recorded-session.')) localStorage.removeItem(key); localStorage.setItem('infrareveal.debug.v3.traffic.recorded-session.window', '10000'); });
  const opened = Date.now();
  await page.goto('http://127.0.0.1:5174/timeline/recorded-session');
  await page.waitForFunction(()=>document.querySelector('.traffic-workspace .desktop-status')?.textContent.includes('10,000')||document.querySelector('.traffic-workspace .desktop-status')?.textContent.includes('10000'));
  const slider=page.locator('#traffic-scrubber'),start=Number(await slider.getAttribute('min'));
  const initialLoadMs = Date.now() - opened;
  await slider.fill(String(start+10000));
  await page.waitForFunction(()=>document.querySelectorAll('.traffic-clip').length>0);
  await page.waitForFunction(()=>!document.querySelector('.desktop-status')?.textContent.includes('Loading detail'),null,{timeout:20000});
  const seeks=[];
  for(const seconds of [15,35,10,40,20]){const began=Date.now();await slider.fill(String(start+seconds*1000));await page.waitForFunction(value=>Number(document.querySelector('#traffic-scrubber').value)===value,start+seconds*1000);seeks.push(Date.now()-began);}
  await page.locator('.traffic-workspace').focus();await page.keyboard.press('Space');
  const frames=await page.evaluate(()=>new Promise(resolve=>{const gaps=[];let previous=performance.now();const tick=now=>{gaps.push(now-previous);previous=now;if(gaps.length<120)requestAnimationFrame(tick);else{gaps.sort((a,b)=>a-b);resolve({medianMs:gaps[60],p95Ms:gaps[114],maxMs:gaps[119],heap:performance.memory?performance.memory.usedJSHeapSize:null,domNodes:document.querySelectorAll('*').length,trackRows:document.querySelectorAll('.traffic-track').length,clips:document.querySelectorAll('.traffic-clip').length});}};requestAnimationFrame(tick);}));
  await page.locator('.traffic-workspace').focus();await page.keyboard.press('Space');
  const network=await (await page.request.get('http://127.0.0.1:8095/__fixture')).json();
  const detail=network.requests.filter(r=>r.path.endsWith('/window')&&r.query.lod!=='overview');
  await page.screenshot({path:'output/playwright/traffic-10000.png'});
  const moduleSource=await (await page.request.get('http://127.0.0.1:5174/src/experiments/session-playback/SessionPlaybackPage.tsx')).text();
  const runtimeModule=moduleSource.match(/from ["']([^"']+session-state[^"']+)["']/)?.[1];
  if(!runtimeModule)throw new Error('Use the Vite development server to inspect cache bounds.');
  const cache=await page.evaluate(async moduleURL=>{const {sessionTimelineStore}=await import(moduleURL);const s=sessionTimelineStore.getState();return{pages:s.pages.size,cacheBytes:s.cacheBytes,cacheBudget:s.detailCacheBudgetBytes,pending:s.loadingPageKeys.size};},runtimeModule);
  return {flows:10000,initialLoadMs,seeksMs:seeks,frames,detailRequests:detail.length,maxRequestSpanMs:Math.max(...detail.map(r=>Number(r.query.to)-Number(r.query.from))),maxRequestedFlows:Math.max(...detail.map(r=>(r.query.flow||'').split(',').filter(Boolean).length)),cache};
}
