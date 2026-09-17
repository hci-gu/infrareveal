// Local-only browser fixture. Never imported by application code.
import http from 'node:http';
const now = Date.now();
const start = now - 17 * 60_000;
const iso = n => new Date(n).toISOString();
let fixtureCount = 48;
let routeFixtures = false;
let fixtureOffline = false;
let fixtureFailSummary = '';
let fixtureDelay = 0;
let traceSequence = 0;
const requestLog = [];
const traceStreams = new Set();
const initialSources = [
  {id:'live-session', name:'Morning browsing', active:true, start},
  {id:'recorded-session', name:'Video playback study', active:false, start:start-86_400_000},
  {id:'partial-session', name:'DNS timeout experiment', active:false, start:start-172_800_000},
  {id:'unknown-session', name:'Background baseline', active:false, start:start-259_200_000},
  {id:'second-live', name:'Second live session', active:true, start:start+120_000},
];
const sources=initialSources.map(source=>({...source}));
const makeSessions=()=>sources.map(s=>({id:s.id,name:s.name,active:s.active,started_at:iso(s.start),ended_at:s.active?undefined:iso(s.start+60_000),created:iso(s.start),updated:iso(now),...(s.id==='unknown-session'?{}:{gate_audit_complete:s.id!=='partial-session',gate_audit_drops:s.id==='partial-session'?2:0})}));
const sessions=makeSessions();
function dataFor(id, count=fixtureCount, detail=false, requested=[], from=0, to=0) {
  const source=sources.find(s=>s.id===id);if(!source)return null;
  const base=source.active?now-60_000:source.start;
  const flows=Array.from({length:count},(_,i)=>({id:`flow${i}`,session:id,client_ip:`10.42.0.${18+i%3}`,destination_ip:`${i%2?'203.0.113':'198.51.100'}.${24+i%180}`,source_port:53000+i,destination_port:i%5?443:3478,protocol:i%4?'tcp':'udp',state:i%7?'ESTABLISHED':'SYN_SENT',start:iso(base+(i*1700)%25000),last_seen:iso(source.active?Date.now():base+35_000+(i*700)%25000),bytes_in:1200+i*97540,bytes_out:600+i*3440,packets_in:10+i*31,packets_out:3+i*9,created:iso(base),updated:iso(now)}));
  const dnsFlows=flows.filter((_,i)=>i%5!==0);
  const dnsQueries=dnsFlows.map((f,i)=>({id:`dns${i}`,session:id,client_ip:f.client_ip,query_name:`${['www','assets','api','media'][i%4]}.example${i%6}.org`,query_type:'A',answers:[f.destination_ip],aliases:[],timestamp:iso(Date.parse(f.start)-200),created:iso(base)}));
  const attributions=dnsQueries.map((q,i)=>({id:`attr${i}`,session:id,flow:dnsFlows[i].id,candidate_hostname:q.query_name,source_signal:'dns_answer',confidence:i%3?'high':'medium',explanation:'Observed DNS answer for this client and destination.',dns_query:q.id,observed_at:q.timestamp}));
  const activityEpisodes=Array.from({length:3},(_,i)=>({id:`episode${i}`,session:id,episode_key:`ep${i}`,client_ip:`10.42.0.${18+i}`,site_key:`example${i}.org`,label:`Example browsing ${i+1}`,anchor_hostname:`www.example${i}.org`,start:iso(base),last_seen:iso(base+60000),confidence:'high',explanation:'Client-specific first-party evidence.'}));
  const flowAssociations=flows.filter((_,i)=>i%5!==0).map((f,i)=>({id:`association${i}`,session:id,flow:f.id,episode:`episode${(f.source_port-53000)%3}`,parent_site_key:'example.org',parent_label:'Example browsing',relationship:'first_party',confidence:'high',score:.94,explanation:'Supported first-party association.',observed_at:f.start}));
  const windowBase=source.active?Math.floor((from||Date.now()-60_000)/5000)*5000:base;
  const windowCount=source.active?Math.min(120,Math.ceil(((to||Date.now())-windowBase)/5000)):12;
  const flowActivityWindows=detail?Array.from({length:Math.max(0,windowCount)},(_,i)=>({id:`window${windowBase+i*5000}`,session:id,window_key:`w${windowBase+i*5000}`,window_start:iso(windowBase+i*5000),window_ms:5000,capture_running:true,capture_complete:i!==4,dropped_events:i===4?21:0,last_error:''})):[];
  const chunkBase=source.active?Math.floor((from||Date.now()-60_000)/10000)*10000:base;
  const chunkCount=source.active?Math.max(0,Math.min(60,Math.ceil(((to||Date.now())-chunkBase)/10000))):6;
  const flowActivityChunks=detail?flows.filter(f=>!requested.length||requested.includes(f.id)).flatMap((f,fi)=>Array.from({length:chunkCount},(_,ci)=>({id:`chunk${f.id}-${chunkBase+ci*10000}`,session:id,flow:f.id,flow_key:`${f.protocol}|${f.client_ip}|${f.source_port}|${f.destination_ip}|${f.destination_port}`,chunk_start:iso(chunkBase+ci*10000),bucket_ms:1000,chunk_ms:10000,samples:{version:1,bucket_ms:1000,chunk_ms:10000,samples:Array.from({length:10},(_,j)=>[j*1000,80+j*10,(fi+j)%3?300+j*50:0,2,4])},wire_bytes_out:1800,wire_bytes_in:7200,payload_bytes_out:1100,payload_bytes_in:5100,packets_out:20,packets_in:40,tcp_flags_out:16,tcp_flags_in:16,capture_complete:ci!==2,dropped_events:ci===2?21:0,updated_at_source:iso(now)}))):[];
  return {flows,dnsQueries,attributions,activityEpisodes,flowAssociations,flowActivityChunks,flowActivityWindows,flowActivityStatuses:[{id:'capture',session:id,interface:'wlan0',enabled:true,running:source.active,dropped_events:21,last_error:'',last_event_at:iso(base+59_000),reported_at:iso(now)}],destinations:[...new Map(flows.map(f=>[f.destination_ip,f])).values()].map((f)=>({id:`dest${f.destination_ip}`,ip:f.destination_ip,reverse_dns:'edge.example.org',asn:64500,organization:'Example Network',provider_label:'Example Network',city:'Stockholm',country:'SE',lat:59,lon:18,last_seen:iso(now)})),routes:routeFixtures?flows.slice(0,3).map((f,i)=>({id:`route-${f.id}`,schema_version:2,evidence_class:'useful_path',session:id,destination:'',destination_ip:f.destination_ip,destination_port:f.destination_port,protocol:f.protocol,method:`${f.protocol}:`+f.destination_port,network_context:'fixture',complete:i!==1,destination_reached:i!==1,status:i===1?'partial':'reached',error:'',available_at:iso(base+2000),measured_at:iso(base+2000),completed_at:iso(base+2000),fresh_until:iso(base+600000),valid_until:iso(base+3600000),responding_hops:3,located_hops:i===1?0:2,probe_details:{profile:'selective',probe_count:28,reply_count:3},hops:[{ttl:1,address:'192.168.1.1',missing:false,state:'reply',timings:[1]},{ttl:2,address:'1.1.1.1',missing:false,state:'reply',timings:[3],...(i===1?{}:{lat:55.68,lon:12.56,city:'Copenhagen',country:'Denmark',accuracy_km:100})},...(i===2?[]:[{ttl:3,end_ttl:12,address:'',missing:true,state:'no_reply',timings:[]}]),{ttl:i===2?3:13,address:i===1?'8.8.8.8':f.destination_ip,missing:false,state:'reply',timings:[12],...(i===1?{}:{lat:59.33,lon:18.06,city:'Stockholm',country:'Sweden',accuracy_km:50})}]})):[],gateEvents:[{id:'gate-record',session:id,decision_id:'decision1',flow_key:'udp|10.42.0.18|53000|198.51.100.24|3478',client_ip:'10.42.0.18',destination_ip:'198.51.100.24',source_port:53000,destination_port:3478,protocol:'udp',packet_count:1,state:'approved',actor:'operator',reason:'Operator accepted',verdict_source:'operator',queued_at:iso(base+2000),decided_at:iso(base+4000),wait_ms:2000,created:iso(base+2000)}]};
}
const collectionKeys={flows:'flows',dns_queries:'dnsQueries',flow_attributions:'attributions',activity_episodes:'activityEpisodes',flow_associations:'flowAssociations',flow_activity_chunks:'flowActivityChunks',flow_activity_windows:'flowActivityWindows',flow_activity_status:'flowActivityStatuses',destinations:'destinations',routes:'routes',gate_events:'gateEvents'};
let status={enabled:true,supported:true,listenerReady:true,rulesReady:true,armed:false,state:'off',mode:null,sessionId:null,clientIps:[],paused:false,failOpen:true,pendingFlows:0,heldPackets:0,overflowCount:0,watchdogReleases:0,verdictErrors:0,auditDrops:0,oldestWaitMs:0,parseBypassCount:0,lastError:null,flowTimeoutMs:10000,establishedTimeoutMs:500,dnsTimeoutMs:3000,maxPendingFlows:100,maxHeldPackets:1000,strictAutoAccept:0,kernelSettings:{},queue:{queueDepth:0,kernelDrops:0,userDrops:0,parseBypass:0}};
let pending=[];
const updateStatus=()=>{status.pendingFlows=pending.length;status.heldPackets=pending.reduce((n,d)=>n+d.packetCount,0);status.oldestWaitMs=pending.length?Date.now()-pending[0].queuedAtMs:0;return status;};
const makePending=(options={})=>{const i=pending.length,mode=status.mode||'flow',queuedAtMs=Date.now();const decision={id:`decision-${queuedAtMs}-${i}`,sessionId:status.sessionId||'live-session',flowKey:'udp|10.42.0.18|53000|198.51.100.24|3478',clientIp:'10.42.0.18',remoteIp:'198.51.100.24',clientPort:53000,remotePort:mode==='dns'?53:3478,protocol:'udp',mode,packetCount:1,tcpFlags:2,queuedAtMs,deadlineMs:queuedAtMs+10000,state:'queued',...options};pending.push(decision);return decision;};
const parseBody=req=>new Promise(resolve=>{let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{try{resolve(JSON.parse(body||'{}'));}catch{resolve({});}});});
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://localhost');res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');if(req.method==='OPTIONS'){res.writeHead(204);return res.end();}
 const send=(body,code=200)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(body));};
 if(url.pathname==='/__fixture'&&req.method==='POST'){
   const body=await parseBody(req);
   if(body.resetSources){sources.splice(0,sources.length,...initialSources.map(source=>({...source})));sessions.splice(0,sessions.length,...makeSessions());}
   if('routes'in body)routeFixtures=Boolean(body.routes);
   if('count'in body)fixtureCount=Math.max(1,Math.min(10000,body.count));
   if('offline'in body)fixtureOffline=body.offline;
   if('failSummary'in body)fixtureFailSummary=body.failSummary;
   if('delay'in body)fixtureDelay=body.delay;
   if(body.resetGate){pending=[];status={...status,armed:false,state:'off',mode:null,sessionId:null,clientIps:[],paused:false};}
   if(body.arm)status={...status,armed:true,state:'active',mode:body.mode||'flow',sessionId:'live-session',clientIps:['10.42.0.18']};
   if(body.queue)makePending(body.decision||{});
   if(body.clearQueue)pending=[];
   if(body.endSession){const source=sources.find(s=>s.id===body.endSession),session=sessions.find(s=>s.id===body.endSession);if(source&&session){source.active=false;source.end=Date.now();session.active=false;session.ended_at=iso(source.end);session.updated=iso(Date.now());}}
   if(body.deleteSession){const i=sessions.findIndex(s=>s.id===body.deleteSession);if(i>=0)sessions.splice(i,1);}
   if(body.resetLog)requestLog.length=0;
   if(body.gap)for(const stream of traceStreams)stream.write(`data: ${JSON.stringify({type:'gap',version:1,sessionId:'live-session',events:[],droppedEvents:7,serverNowMs:Date.now(),oldestSequence:traceSequence,newestSequence:traceSequence,ingressRejected:7,subscriberDropped:0,burstDiscarded:0})}\n\n`);
   return send({ok:true,count:fixtureCount,status:updateStatus(),pending});
 }
 if(url.pathname==='/__fixture')return send({requests:requestLog,traceConnections:traceStreams.size,count:fixtureCount,status:updateStatus(),pending});
 requestLog.push({path:url.pathname,query:Object.fromEntries(url.searchParams),method:req.method,time:Date.now()});if(requestLog.length>3000)requestLog.shift();
 if(fixtureOffline)return send({message:'Fixture gateway offline'},503);
 if(fixtureDelay)await new Promise(resolve=>setTimeout(resolve,fixtureDelay));
 if(url.pathname==='/api/health')return send({code:200,message:'Local UI fixture'});
 if(url.pathname==='/api/realtime'){
   if(req.method==='POST')return send({});
   res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive'});res.write('id: ui-fixture\nevent: PB_CONNECT\ndata: {"clientId":"ui-fixture"}\n\n');const timer=setInterval(()=>res.write(': keepalive\n\n'),15000);res.on('close',()=>clearInterval(timer));return;
 }
 if(url.pathname.endsWith('/trace')){
   const id=url.pathname.split('/').slice(-2)[0];res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive'});traceStreams.add(res);
   const tick=()=>{const sequence=++traceSequence,occurredAtMs=Date.now()-500;res.write(`data: ${JSON.stringify({type:'batch',version:1,sessionId:id,events:Array.from({length:20},(_,i)=>({id:`live-${sequence}-${i}`,sequence:sequence*20+i,sessionId:id,traceId:'fixture-live-flow',kind:'burst',stage:'header_capture',direction:i%2?'remote_to_client':'client_to_remote',occurredAtMs:occurredAtMs+i*10,timing:'observed',summary:{protocol:'udp',clientIp:'10.42.0.18',clientPort:53000,remoteIp:'198.51.100.24',remotePort:3478,flowKey:'udp|10.42.0.18|53000|198.51.100.24|3478',payloadBytes:1200,packetCount:1}})),droppedEvents:0,serverNowMs:Date.now(),oldestSequence:Math.max(0,(sequence-30)*20),newestSequence:sequence*20+19,ingressRejected:0,subscriberDropped:0,burstDiscarded:0})}\n\n`);};tick();const timer=setInterval(tick,1000);res.on('close',()=>{clearInterval(timer);traceStreams.delete(res);});return;
 }
 if(url.pathname.includes('/lab-gate/')){
   const action=url.pathname.split('/lab-gate/')[1];
   if(action==='status')return send({requestId:'fixture',status:updateStatus()});
   if(req.headers.authorization!=='Bearer fixture-operator')return send({error:'Fixture operator token required'},401);
   pending=pending.filter(d=>{if(d.deadlineMs>Date.now())return true;status.watchdogReleases++;return false;});
   if(action==='pending')return send({requestId:'fixture',decisions:pending});
   const body=await parseBody(req);
   if(action==='arm'){if(status.armed)return send({error:'Already armed'},409);status={...status,armed:true,state:'active',mode:body.mode,sessionId:body.sessionId,clientIps:body.clientIps};}
   else if(action==='pause'){status.paused=true;status.state='paused';}
   else if(action==='resume'){status.paused=false;status.state='active';}
   else if(action==='drain')pending=[];
   else if(action==='disarm'){pending=[];status={...status,armed:false,state:'off',mode:null,sessionId:null,clientIps:[],paused:false};}
   else if(action==='strict/accept-next')status.strictAutoAccept+=body.count;
   else if(action.startsWith('decisions/')){const id=decodeURIComponent(action.split('/')[1]),decision=pending.find(d=>d.id===id);if(!decision)return send({error:'Decision already terminal'},409);pending=pending.filter(d=>d.id!==id);return send({requestId:'fixture',result:{...decision,state:body.verdict==='accept'?'approved':'rejected',verdict:body.verdict,verdictSource:'operator',actor:body.actor,decidedAtMs:Date.now(),waitMs:Date.now()-decision.queuedAtMs},alreadyTerminal:false});}
   else if(action==='approve-all'){const results=pending.map(d=>({...d,state:'approved',verdict:'accept',verdictSource:'operator'}));pending=[];return send({results,status:updateStatus()});}
   return send({requestId:'fixture',status:updateStatus()});
 }
 const match=url.pathname.match(/\/sessions\/([^/]+)\/(manifest|window)/);
 if(match){const [,id,kind]=match,source=sources.find(s=>s.id===id);if(!source)return send({message:'Session not found'},404);if(kind==='manifest'&&fixtureFailSummary===id)return send({message:'Fixture manifest failure'},500);
 const from=Number(url.searchParams.get('from'))||source.start,to=Number(url.searchParams.get('to'))||Date.now(),lod=url.searchParams.get('lod'),requested=(url.searchParams.get('flow')||'').split(',').filter(Boolean);
 const data=dataFor(id,fixtureCount,kind==='window'&&lod!=='overview',requested,from,to);
 if(kind==='manifest')return send({sessionId:id,name:source.name,startedAt:iso(source.start),endedAt:source.active?null:iso(source.end||source.start+60000),active:source.active,serverNow:iso(Date.now()),watermark:iso(Date.now()),counts:id==='unknown-session'?{}:Object.fromEntries(Object.entries(collectionKeys).map(([k,v])=>[k,data[v].length])),coverage:{from:iso(source.start),to:iso(source.active?Date.now():source.end||source.start+60000)},...(id==='unknown-session'?{}:{gateAuditComplete:id!=='partial-session',gateAuditDrops:id==='partial-session'?2:0})});
 if(lod==='overview'){data.flowActivityChunks=[];data.flowActivityWindows=[];data.dnsQueries=[];data.gateEvents=[];}
 else{data.flows=data.flows.filter(f=>(!requested.length||requested.includes(f.id))&&Date.parse(f.start)<to&&Date.parse(f.last_seen)>=from);const flowSet=new Set(data.flows.map(f=>f.id)),destSet=new Set(data.flows.map(f=>f.destination_ip));data.attributions=data.attributions.filter(a=>flowSet.has(a.flow));data.flowAssociations=data.flowAssociations.filter(a=>flowSet.has(a.flow));data.destinations=data.destinations.filter(d=>destSet.has(d.ip));data.flowActivityChunks=data.flowActivityChunks.filter(c=>Date.parse(c.chunk_start)<to&&Date.parse(c.chunk_start)+c.chunk_ms>from);data.flowActivityWindows=data.flowActivityWindows.filter(w=>Date.parse(w.window_start)<to&&Date.parse(w.window_start)+w.window_ms>from);data.dnsQueries=data.dnsQueries.filter(q=>Date.parse(q.timestamp)>=from-300000&&Date.parse(q.timestamp)<to);data.gateEvents=data.gateEvents.filter(g=>Date.parse(g.queued_at)<to&&Date.parse(g.decided_at||g.queued_at)>=from);}
 return send({...data,range:{from:iso(from),to:iso(to)},lod,watermark:iso(Date.now()),nextCursor:null});}
 if(url.pathname==='/api/infrareveal/routes/status')return send({session:'live-session',engine:'v2',useful_paths:3,unique_useful_bindings:3,running:0,pending:0,starts:10,failures:0,budget_remaining:30,manual_remaining:10,no_gain_attempts:7,evidence_bytes_written:32000,measured_byte_coverage:.6,targets:dataFor('live-session').flows.map((f,i)=>({destination_ip:f.destination_ip,protocol:f.protocol,destination_port:f.destination_port,state:i<3?'useful_path_saved':i===3?'access_only':'visibility_paused'}))});
 if(url.pathname==='/api/infrareveal/routes/measure'||url.pathname==='/api/infrareveal/routes/extend-budget')return send({accepted:true},202);
 if(url.pathname.startsWith('/api/collections/')){const name=url.pathname.split('/')[3],items=name==='sessions'?sessions:(dataFor('live-session')[collectionKeys[name]]||[]);return send({items,page:1,totalPages:1,totalItems:items.length});}
 return send({message:'Fixture endpoint unavailable'},404);
});
server.listen(8095,'127.0.0.1',()=>console.log('UI fixture http://127.0.0.1:8095 · operator token fixture-operator · POST /__fixture configures test state'));
