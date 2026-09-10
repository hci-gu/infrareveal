async (page) => {
  const app='http://127.0.0.1:5174',api='http://127.0.0.1:8095',checks=[],errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  const config=data=>page.request.post(api+'/__fixture',{data});
  const state=async()=> (await page.request.get(api+'/__fixture')).json();
  const assert=(value,label)=>{if(!value)throw new Error(label);checks.push(label);};
  await config({count:48,resetSources:true,offline:false,delay:0,resetGate:true,resetLog:true});await page.setViewportSize({width:1440,height:900});
  await page.goto(app);await page.evaluate(()=>{for(const key of ['lab.live-session.cursor','traffic.second-live.cursor'])localStorage.removeItem('infrareveal.debug.v3.'+key);});
  await page.goto(app+'/proxy-lab/live-session');await page.getByRole('button',{name:'Live observe',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('.lab-status')?.textContent.includes('Trace: Live'));
  const labSource=await (await page.request.get(app+'/src/experiments/proxy-lab/ProxyLabPage.tsx')).text();
  const labModule=labSource.match(/from ["']([^"']+proxyLabStore[^"']+)["']/)?.[1];
  const sharedModule=labSource.match(/from ["']([^"']+session-state[^"']+)["']/)?.[1];
  const sample=()=>page.evaluate(async url=>{const {proxyLabStore}=await import(url);const s=proxyLabStore.getState(),times=[...s.ephemeralEvents.values()].map(e=>e.occurredAtMs);return{events:times.length,spanMs:Math.max(...times)-Math.min(...times),sequence:s.newestSequence,trace:s.traceConnection,heap:performance.memory?.usedJSHeapSize,dom:document.querySelectorAll('*').length,tokens:document.querySelectorAll('.lab-graph-viewport svg circle').length};},labModule);
  const initial=await sample();await page.waitForTimeout(40000);const sustained=await sample();
  assert(sustained.events>=500 && sustained.events<=640 && sustained.spanMs<=30000,'The live trace retains a bounded 30-second window after sustained delivery');
  assert((await state()).traceConnections===1,'Live observation has one active trace connection');
  await config({gap:true});await page.waitForFunction(()=>document.querySelector('.lab-status')?.textContent.includes('Trace: Loss detected'));
  checks.push('Stream delivery gaps stay visible separately from capture and audit');
  await page.emulateMedia({reducedMotion:'reduce'});await page.getByText('Reduced motion · static direction indicators',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Inspect Flow gate node',exact:true}).click();assert(await page.getByRole('button',{name:'Inspect Flow gate node',exact:true}).getAttribute('aria-pressed')==='true','Reduced motion retains selectable nodes and static paths');
  await page.emulateMedia({reducedMotion:'no-preference'});
  for(let i=0;i<3;i++){
    await page.getByRole('link',{name:'Back to Sessions',exact:true}).click();await page.getByRole('button',{name:'Video playback study',exact:true}).click();await page.getByRole('link',{name:'Open Traffic',exact:true}).click();await page.locator('#traffic-scrubber').waitFor();
    await page.locator('.traffic-workspace').focus();await page.keyboard.press('Space');await page.getByRole('link',{name:'Sessions',exact:true}).click();await page.getByRole('button',{name:'Morning browsing',exact:true}).click();await page.getByRole('link',{name:'Open Lab',exact:true}).click();await page.getByRole('button',{name:'Live observe',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('.lab-status')?.textContent.includes('Trace: Live'));assert((await state()).traceConnections===1,`Route cycle ${i+1} retains exactly one trace subscription`);
  }
  await page.getByRole('link',{name:'Back to Sessions',exact:true}).click();await page.getByRole('heading',{name:'Sessions',exact:true}).waitFor();
  const cleanup=await page.evaluate(async ({shared,lab})=>{const {sessionTimelineStore}=await import(shared);const {proxyLabStore}=await import(lab);const before=sessionTimelineStore.getState().cursorMs;await new Promise(resolve=>setTimeout(resolve,500));const s=proxyLabStore.getState();return{cursorStill:before===sessionTimelineStore.getState().cursorMs,session:s.sessionId,events:s.ephemeralEvents.size,tokenEmpty:!s.operatorToken};},{shared:sharedModule,lab:labModule});
  assert((await state()).traceConnections===0,'Leaving Lab closes its trace subscription');
  assert(cleanup.cursorStill && cleanup.session===null && cleanup.events===0 && cleanup.tokenEmpty,'Route cleanup stops playback and clears transient Lab state');
  await page.getByRole('button',{name:'Second live session',exact:true}).click();await page.getByRole('link',{name:'Open Traffic',exact:true}).click();await page.getByRole('button',{name:'Following live',exact:true}).waitFor();
  await config({endSession:'second-live'});await page.getByRole('button',{name:'End',exact:true}).waitFor({timeout:20000});assert(await page.getByRole('button',{name:'Go live',exact:true}).count()===0,'A live source that ends becomes a fixed recording');
  await page.getByRole('link',{name:'Sessions',exact:true}).click();await config({deleteSession:'second-live'});await page.getByRole('button',{name:'Refresh sessions',exact:true}).click();await page.getByRole('heading',{name:'Source no longer available'}).waitFor();checks.push('A deleted selected source is identified without silently switching');
  await page.goto(app+'/timeline/second-live');await page.getByRole('heading',{name:'Session not found'}).waitFor();checks.push('Deleted-source deep links show an explicit missing state');
  await page.goto('http://127.0.0.1:5175/');await page.getByRole('link').filter({has:page.getByRole('heading',{name:'Video playback study',exact:true})}).click();
  await page.waitForFunction(()=>document.querySelector('canvas'),null,{timeout:30000});
  const moduleSource=await (await page.request.get('http://127.0.0.1:5175/src/pages/MapPage.tsx')).text();const runtimeModule=moduleSource.match(/from ["']([^"']+session-state[^"']+)["']/)?.[1];
  await page.waitForFunction(async url=>{const {sessionTimelineStore,selectOverviewGatewayData}=await import(url);return sessionTimelineStore.getState().selectedSessionId==='recorded-session' && selectOverviewGatewayData().flows.length===48;},runtimeModule);
  await page.waitForFunction(()=>{const label=[...document.querySelectorAll('div')].find(el=>el.textContent==='Flows seen');return Number(label?.previousElementSibling?.textContent)>0;});
  await page.screenshot({path:'output/playwright/production-dashboard-map.png'});
  const consumer=await page.evaluate(async url=>{const {sessionTimelineStore,selectOverviewGatewayData}=await import(url);return{id:sessionTimelineStore.getState().selectedSessionId,flows:selectOverviewGatewayData().flows.length};},runtimeModule);
  assert(page.url().includes('/map/recorded-session') && consumer.id==='recorded-session' && consumer.flows===48,'Production dashboard still opens the same recording through the shared runtime');
  assert(await page.locator('.desktop-ui,.lab-workspace').count()===0,'Debug desktop styles do not reach the production dashboard');
  assert(errors.length===0,'No uncaught errors during sustained delivery or route cleanup');
  return{checks,initial,sustained,cleanup,consumer,errors};
}
