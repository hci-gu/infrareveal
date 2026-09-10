async (page) => {
  const summary=[];
  await page.request.post('http://127.0.0.1:8095/__fixture',{data:{count:48,resetSources:true,offline:false,delay:0,resetGate:true,clearQueue:true}});
  const fixture='http://127.0.0.1:8095', app='http://127.0.0.1:5174';
  await page.goto(app);
  const restore=async()=>page.evaluate(()=>{for(const id of ['recorded-session','live-session']){const p=`infrareveal.debug.v3.traffic.${id}.`;for(const [key,value] of Object.entries({cursor:0,window:60000,inspector:true,ledger:true,query:'',client:'all',selection:'',scroll:0,collapsed:[]}))localStorage.setItem(p+key,JSON.stringify(value));for(const [key,value] of Object.entries({cursor:0,query:'',client:'all',protocol:'all',trace:'',branches:true,graph:{x:0,y:0,zoom:1}}))localStorage.setItem(`infrareveal.debug.v3.lab.${id}.`+key,JSON.stringify(value));}});
  for(const [width,height] of [[1280,800],[1440,900],[1920,1080]]){
    await page.setViewportSize({width,height});await restore();
    for(const id of ['recorded-session','live-session']){
      await page.goto(app);await page.getByRole('button',{name:id==='recorded-session'?'Video playback study':'Morning browsing',exact:true}).click();
      await page.waitForFunction(()=>!document.querySelector('.session-details')?.textContent.includes('Loading session summary'),null,{timeout:15000});
      await page.screenshot({path:`output/playwright/sessions-${id}-${width}.png`});
      await page.getByRole('link',{name:'Open Traffic',exact:true}).click();await page.waitForFunction(()=>document.querySelectorAll('.traffic-clip').length>0,null,{timeout:15000});
      if(id==='live-session')await page.locator('.traffic-follow').click();
      await page.locator('.traffic-clip').first().click();
      await page.screenshot({path:`output/playwright/traffic-${id}-${width}.png`});
      summary.push(await page.evaluate(()=>({surface:'Traffic',width:innerWidth,height:innerHeight,timeline:Math.round(document.querySelector('.traffic-timeline').getBoundingClientRect().height),rows:document.querySelectorAll('.traffic-track').length,overflow:document.documentElement.scrollWidth>innerWidth})));
      await page.goto(`${app}/proxy-lab/${id}`);await page.waitForFunction(()=>[...document.querySelectorAll('[aria-label="Selected Lab trace"] option')].some(o=>o.value==='udp|10.42.0.18|53000|198.51.100.24|3478'),null,{timeout:15000});
      await page.getByLabel('Selected Lab trace',{exact:true}).selectOption('udp|10.42.0.18|53000|198.51.100.24|3478');await page.getByRole('button',{name:'Inspect Flow gate node',exact:true}).click();
      await page.screenshot({path:`output/playwright/lab-${id}-${width}.png`});
      summary.push(await page.evaluate(()=>({surface:'Lab',width:innerWidth,height:innerHeight,graph:Math.round(document.querySelector('.lab-graph-viewport').getBoundingClientRect().height),overflow:document.documentElement.scrollWidth>innerWidth})));
    }
  }
  await page.emulateMedia({reducedMotion:'reduce'});await page.setViewportSize({width:720,height:450});
  for(const [name,route] of [['sessions','/'],['traffic','/timeline/recorded-session'],['lab','/proxy-lab/recorded-session']]){
    await page.goto(app+route);await page.waitForFunction(surface=>surface==='sessions' ? document.querySelectorAll('.session-name').length>0 : surface==='traffic' ? document.querySelectorAll('.traffic-clip').length>0 : document.querySelector('.lab-main') && !document.querySelector('.lab-empty-notice'),name,{timeout:15000});
    await page.screenshot({path:`output/playwright/${name}-zoom-equivalent.png`,fullPage:true});
    summary.push({surface:name,zoomEquivalent:'200% on 1440 × 900',overflow:await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth)});
  }
  await page.setViewportSize({width:390,height:844});
  for(const [name,route] of [['sessions','/'],['traffic','/timeline/recorded-session'],['lab','/proxy-lab/recorded-session']]){
    await page.goto(app+route);await page.waitForFunction(surface=>surface==='sessions' ? document.querySelectorAll('.session-name').length>0 : surface==='traffic' ? document.querySelectorAll('.traffic-clip').length>0 : document.querySelector('.lab-main') && !document.querySelector('.lab-empty-notice'),name,{timeout:15000});
    await page.screenshot({path:`output/playwright/${name}-narrow.png`,fullPage:true});
    summary.push({surface:name,narrow:true,overflow:await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth)});
  }
  await page.emulateMedia({reducedMotion:'no-preference'});await page.setViewportSize({width:1440,height:900});
  return summary;
}
