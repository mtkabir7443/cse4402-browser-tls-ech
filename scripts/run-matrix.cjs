#!/usr/bin/env node
'use strict';

// Real browser measurement runner. Browser transport: Chromium CDP and Firefox
// Marionette, both over loopback and scoped to a newly owned process/profile.
// https://chromedevtools.github.io/devtools-protocol/
// https://firefox-source-docs.mozilla.org/remote/marionette/Protocol.html
// No certificate bypass, security-prompt acceptance or registry modification.
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const https = require('node:https');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');

const ROOT = path.resolve(__dirname, '..');
const DASHBOARD = 'https://127.0.0.1:8443/';
const DOH = DASHBOARD + 'dns-query';
const CASE_IDS = ['V1','V2','V3','V4','C1','C2','C3','C4','C5','E1','E2','E3'];
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/;
const LEASE_RESERVE_MS = 180000;
const CLEANUP_RESERVE_MS = 30000;
let interrupted = false;
let activeControl = null;

function parseArgs(argv) {
  const options = { browsers: [], cases: [], repeats: 3, batch: 'matrix-' + new Date().toISOString().replace(/[-:.]/g,'').slice(0,15), dryRun: false, screenshots: 'representative', timeout: 60 };
  for (let i=0;i<argv.length;i++) {
    const arg=argv[i];
    if (arg==='--help' || arg==='-h') { options.help=true; continue; }
    if (arg==='--dry-run') { options.dryRun=true; continue; }
    const value=argv[++i];
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${arg}`);
    if (arg==='--browser') options.browsers.push(...value.split(',').filter(Boolean));
    else if (arg==='--case') options.cases.push(...value.split(',').filter(Boolean));
    else if (arg==='--repeats') options.repeats=Number(value);
    else if (arg==='--batch') options.batch=value;
    else if (arg==='--screenshots') options.screenshots=value;
    else if (arg==='--timeout') options.timeout=Number(value);
    else if (arg==='--stop-before-utc') options.stopBeforeUTC=value;
    else throw new Error(`Unknown option ${arg}`);
  }
  if (!Number.isInteger(options.repeats) || options.repeats<1 || options.repeats>10) throw new Error('--repeats must be 1-10');
  if (!Number.isInteger(options.timeout) || options.timeout<20 || options.timeout>90) throw new Error('--timeout must be 20-90 seconds');
  if (!ID_RE.test(options.batch) || options.batch.length>60) throw new Error('--batch must be a safe identifier, at most 60 characters');
  if (!['all','representative','none'].includes(options.screenshots)) throw new Error('--screenshots must be all, representative or none');
  if (options.stopBeforeUTC !== undefined) {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$/.test(options.stopBeforeUTC) || !Number.isFinite(Date.parse(options.stopBeforeUTC))) throw new Error('--stop-before-utc must be a valid UTC timestamp ending in Z');
    options.stopBeforeUTC=new Date(options.stopBeforeUTC).toISOString();
  }
  options.browsers=[...new Set(options.browsers)]; options.cases=[...new Set(options.cases)];
  if (options.cases.some(id=>!CASE_IDS.includes(id))) throw new Error('Unknown case ID; use ' + CASE_IDS.join(','));
  return options;
}

function cellAction(options, alreadyCompleted, now=Date.now()) {
  if (alreadyCompleted) return 'preserve';
  if (options.stopBeforeUTC && Date.parse(options.stopBeforeUTC)-now<LEASE_RESERVE_MS) return 'pause';
  return 'run';
}

class LeasePauseError extends Error {
  constructor() { super('Lease deadline reached before registration'); this.name='LeasePauseError'; }
}
function deadlineTimeout(timeout, deadline, now=Date.now()) {
  if(deadline && now>=deadline)throw new LeasePauseError();
  return deadline ? Math.min(timeout,deadline-now) : timeout;
}
function timedError(message, deadline) {
  return deadline && Date.now()>=deadline ? new LeasePauseError() : new Error(message);
}
async function afterReadiness(ready, action, deadline) {
  await ready();
  deadlineTimeout(1,deadline);
  return action();
}

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
async function hashFile(file) { const hash=crypto.createHash('sha256'); for await (const chunk of fs.createReadStream(file)) hash.update(chunk); return hash.digest('hex'); }
async function saveJSON(file,value) { await fsp.writeFile(file,JSON.stringify(value,null,2)+'\n','utf8'); }
function inside(parent,child) { const rel=path.relative(parent,child); return rel!=='' && !rel.startsWith('..'+path.sep) && rel!=='..' && !path.isAbsolute(rel); }

async function assertUnredirectedWithin(parent,target) {
  const absolute=path.resolve(target);
  if (!inside(parent,absolute)) throw new Error(`Path escapes the project-owned directory: ${absolute}`);
  const parts=path.relative(parent,absolute).split(path.sep);
  let at=parent;
  for (const part of parts) {
    at=path.join(at,part);
    try { if ((await fsp.lstat(at)).isSymbolicLink()) throw new Error(`Refusing redirected path: ${at}`); }
    catch(error) { if (error.code!=='ENOENT') throw error; }
  }
}

async function ensureFirefoxPolicy(browser) {
  const toolsDir=path.join(ROOT,'.tools');
  await assertUnredirectedWithin(toolsDir,browser.path);
  const policyDir=path.join(path.dirname(browser.path),'distribution');
  const policyPath=path.join(policyDir,'policies.json');
  await assertUnredirectedWithin(toolsDir,policyPath);
  const caPath=path.join(ROOT,'.runtime','ca.pem');
  const cert=new crypto.X509Certificate(await fsp.readFile(caPath));
  if (!cert.ca || !cert.subject.includes('CN=CSE4402 isolated TLS lab ')) throw new Error('Firefox trust input is not the lab CA');
  const wanted={policies:{DontCheckDefaultBrowser:true,DisableTelemetry:true,DisableAppUpdate:true,Certificates:{ImportEnterpriseRoots:false,Install:[caPath]}}};
  let created=false;
  try {
    const current=JSON.parse((await fsp.readFile(policyPath,'utf8')).replace(/^\uFEFF/,''));
    const p=current.policies,c=p?.Certificates;
    const recognized=Object.keys(current).length===1 && p && Object.keys(p).length===4 && p.DontCheckDefaultBrowser===true && p.DisableTelemetry===true && p.DisableAppUpdate===true && c && Object.keys(c).length===2 && c.ImportEnterpriseRoots===false && Array.isArray(c.Install) && c.Install.length===1 && path.resolve(c.Install[0]).toLowerCase()===caPath.toLowerCase();
    if (!recognized) throw new Error(`Existing Firefox policy is unrecognized and was preserved: ${policyPath}`);
  } catch(error) {
    if (error.code!=='ENOENT') throw error;
    await fsp.mkdir(policyDir,{recursive:true});
    await fsp.writeFile(policyPath,JSON.stringify(wanted,null,2)+'\n',{encoding:'utf8',flag:'wx'}); created=true;
  }
  return {method:'Firefox application-local Certificates.Install',policy_path:policyPath,policy_sha256:await hashFile(policyPath),ca_sha256:await hashFile(caPath),ca_fingerprint_sha256:cert.fingerprint256,import_enterprise_roots:false,policy_created:created,windows_store_modified:false};
}

function firefoxPrefs(port) {
  return {
    'marionette.port':port,'marionette.log.level':'Info',
    'network.trr.mode':3,'network.trr.uri':DOH,'network.trr.custom_uri':DOH,
    'network.trr.confirmationNS':'skip','network.trr.wait-for-portal':false,
    'network.trr.allow-rfc1918':true,'network.trr.excluded-domains':'','network.trr.temp_blocklist':false,
    'network.dns.echconfig.enabled':true,'network.http.http3.enable':false,
    'network.proxy.type':0,'security.enterprise_roots.enabled':false,
    'browser.shell.checkDefaultBrowser':false,'browser.startup.homepage_override.mstone':'ignore',
    'browser.aboutwelcome.enabled':false,'browser.startup.page':0,'app.update.auto':false,
    'datareporting.policy.dataSubmissionEnabled':false,'toolkit.telemetry.enabled':false,
    'network.captive-portal-service.enabled':false,'network.connectivity-service.enabled':false,
    'browser.tabs.warnOnClose':false,'browser.warnOnQuit':false,
  };
}

function chromiumPreferences() {
  return {dns_over_https:{mode:'secure',templates:DOH},async_dns:{enabled:true,additional_dns_query_types_enabled:true},ssl:{ech_enabled:true}};
}

function controlRequest(method,relative,body) {
  if (!relative.startsWith('/api/') || relative.includes('://')) return Promise.reject(new Error('Only the local control API is permitted'));
  const data=body===undefined ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve,reject)=>{
    const req=https.request(new URL(relative,DASHBOARD),{method,ca:fs.readFileSync(path.join(ROOT,'.runtime','ca.pem')),rejectUnauthorized:true,timeout:10000,headers:data?{'Content-Type':'application/json','Content-Length':data.length}:{}},res=>{
      const chunks=[];let length=0;
      res.on('data',b=>{length+=b.length;if(length>32*1024*1024){res.destroy(new Error('Control response too large'));return;}chunks.push(b);});
      res.on('error',reject);
      res.on('end',()=>{
        const text=Buffer.concat(chunks).toString('utf8');let value;
        try { value=JSON.parse(text); } catch {reject(new Error(`Control API returned invalid JSON (${res.statusCode})`));return;}
        if(res.statusCode<200 || res.statusCode>=300){const e=new Error(value.error||`Control HTTP ${res.statusCode}`);e.status=res.statusCode;reject(e);return;}
        resolve(value);
      });
    });
    req.on('timeout',()=>req.destroy(new Error('Control request timed out')));req.on('error',reject);
    if(data)req.write(data);req.end();
  });
}

async function waitUntil(check,timeout,message,child,leaseDeadline) {
  const deadline=Date.now()+deadlineTimeout(timeout,leaseDeadline);let lastError;
  while(Date.now()<deadline) {
    if(interrupted)throw new Error('Runner interrupted');
    if(child && (child.exitCode!==null || child.signalCode!==null))throw new Error(`Owned browser exited before readiness (${child.exitCode ?? child.signalCode})`);
    try { const value=await check();deadlineTimeout(1,leaseDeadline);if(value)return value; } catch(error) {if(error instanceof LeasePauseError)throw error;lastError=error;}
    await delay(Math.max(1,Math.min(150,deadline-Date.now())));
  }
  throw timedError(`${message}${lastError ? ': '+lastError.message : ''}`,leaseDeadline);
}

async function freePort() {
  const server=net.createServer();server.listen(0,'127.0.0.1');await once(server,'listening');
  const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;
}

class CDP {
  constructor(socket,deadline) {
    this.socket=socket;this.deadline=deadline;this.next=0;this.pending=new Map();this.events=[];
    socket.addEventListener('message',event=>{
      let msg;try{msg=JSON.parse(String(event.data));}catch{return;}
      if(msg.id) {
        const p=this.pending.get(msg.id);if(!p)return;this.pending.delete(msg.id);clearTimeout(p.timer);
        if(p.deadline && Date.now()>=p.deadline)p.reject(new LeasePauseError());
        else if(msg.error)p.reject(new Error(`CDP ${p.method}: ${msg.error.message}`));else p.resolve(msg.result||{});
      } else if(['Runtime.exceptionThrown','Log.entryAdded','Network.loadingFailed'].includes(msg.method) && this.events.length<200) this.events.push(msg);
    });
    socket.addEventListener('close',()=>this.fail(new Error('CDP connection closed')));
    socket.addEventListener('error',()=>this.fail(new Error('CDP socket error')));
  }
  static async connect(url,deadline) {
    const parsed=new URL(url);if(parsed.protocol!=='ws:' || !['127.0.0.1','localhost'].includes(parsed.hostname))throw new Error('Refusing non-loopback debugger');
    const timeout=deadlineTimeout(10000,deadline),socket=new WebSocket(url);
    await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{socket.close();reject(timedError('CDP open timed out',deadline));},timeout);socket.addEventListener('open',()=>{clearTimeout(timer);resolve();},{once:true});socket.addEventListener('error',()=>{clearTimeout(timer);reject(new Error('CDP open failed'));},{once:true});});
    return new CDP(socket,deadline);
  }
  fail(error) {for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(error);}this.pending.clear();}
  send(method,params={},sessionId,timeout=15000) {
    const deadline=this.deadline;
    timeout=deadlineTimeout(timeout,deadline);
    const id=++this.next;
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.pending.delete(id);reject(timedError(`CDP ${method} timed out`,deadline));},timeout);
      this.pending.set(id,{resolve,reject,timer,method,deadline});
      try{this.socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));}catch(error){clearTimeout(timer);this.pending.delete(id);reject(error);}
    });
  }
  close(){this.fail(new Error('CDP closed by runner'));this.socket.close();}
}

// Frames are byte-length-prefixed UTF-8 JSON, including the initial greeting.
class MarionetteFrames {
  constructor(onMessage){this.buffer=Buffer.alloc(0);this.onMessage=onMessage;}
  push(chunk){
    this.buffer=Buffer.concat([this.buffer,chunk]);
    while(this.buffer.length){
      const colon=this.buffer.indexOf(58);
      if(colon<0){if(this.buffer.length>12)throw new Error('Invalid Marionette frame header');return;}
      const prefix=this.buffer.subarray(0,colon).toString('ascii');
      if(!/^\d{1,9}$/.test(prefix))throw new Error('Invalid Marionette frame length');
      const length=Number(prefix);if(length<1 || length>32*1024*1024)throw new Error('Marionette frame exceeds limit');
      if(this.buffer.length<colon+1+length)return;
      const payload=this.buffer.subarray(colon+1,colon+1+length);this.buffer=this.buffer.subarray(colon+1+length);
      this.onMessage(JSON.parse(payload.toString('utf8')));
    }
  }
}

class Marionette {
  constructor(socket,deadline){
    this.socket=socket;this.deadline=deadline;this.next=0;this.pending=null;this.greeting=null;
    this.hello=new Promise((resolve,reject)=>{this.resolveHello=resolve;this.rejectHello=reject;});this.hello.catch(()=>{});
    this.frames=new MarionetteFrames(msg=>{
      if(!Array.isArray(msg)){
        if(this.greeting)throw new Error('Unexpected Marionette greeting');
        if(msg.marionetteProtocol!==3 || msg.applicationType!=='gecko')throw new Error('Unsupported Marionette greeting');
        this.greeting=msg;this.resolveHello(msg);return;
      }
      const p=this.pending;
      if(!p || msg[0]!==1 || msg[1]!==p.id)throw new Error('Mismatched Marionette response');
      this.pending=null;clearTimeout(p.timer);
      if(p.deadline && Date.now()>=p.deadline)p.reject(new LeasePauseError());
      else if(msg[2])p.reject(new Error(`Marionette ${p.method}: ${msg[2].error}: ${msg[2].message}`));else p.resolve(msg[3]);
    });
    socket.on('data',b=>{try{this.frames.push(b);}catch(error){this.fail(error);socket.destroy();}});
    socket.on('error',error=>this.fail(error));socket.on('close',()=>this.fail(new Error('Marionette connection closed')));
  }
  static async connect(port,deadline){
    const timeout=deadlineTimeout(2000,deadline);
    const socket=net.createConnection({host:'127.0.0.1',port});socket.setNoDelay(true);
    const client=new Marionette(socket,deadline);
    const timer=setTimeout(()=>socket.destroy(timedError('Marionette greeting timed out',deadline)),timeout);
    try{await Promise.all([once(socket,'connect'),client.hello]);return client;}catch(error){socket.destroy();throw error;}finally{clearTimeout(timer);}
  }
  fail(error){this.rejectHello(error);if(this.pending){clearTimeout(this.pending.timer);this.pending.reject(error);this.pending=null;}}
  send(method,params={},timeout=15000){
    const deadline=this.deadline;
    timeout=deadlineTimeout(timeout,deadline);
    if(this.pending)return Promise.reject(new Error('Marionette commands must remain sequential'));
    const id=++this.next,text=JSON.stringify([0,id,method,params]);
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.pending=null;reject(timedError(`Marionette ${method} timed out`,deadline));},timeout);
      this.pending={id,method,resolve,reject,timer,deadline};
      this.socket.write(Buffer.concat([Buffer.from(Buffer.byteLength(text)+':'),Buffer.from(text)]),error=>{if(error && this.pending?.id===id){clearTimeout(timer);this.pending=null;reject(error);}});
    });
  }
  async evaluate(expression){const r=await this.send('WebDriver:ExecuteScript',{script:`return (${expression});`,args:[],newSandbox:false,sandbox:null});return r?.value;}
  close(){this.fail(new Error('Marionette closed by runner'));this.socket.destroy();}
}

async function launchOwned(browser,args,runDir,extraEnv={}) {
  const stdout=fs.createWriteStream(path.join(runDir,'stdout.txt'),{flags:'wx'});
  const stderr=fs.createWriteStream(path.join(runDir,'stderr.txt'),{flags:'wx'});
  const child=spawn(browser.path,args,{cwd:ROOT,windowsHide:true,shell:false,env:{...process.env,...extraEnv},stdio:['ignore','pipe','pipe']});
  child.stdout.pipe(stdout);child.stderr.pipe(stderr);
  child.stdout.on('error',()=>{});child.stderr.on('error',()=>{});
  try {await once(child,'spawn');} catch(error) {stdout.end();stderr.end();throw error;}
  return {child,stdout,stderr};
}

async function finishOwned(owned,control,kind,metadata) {
  if(!owned)return;
  if(control)control.deadline=null; // Cleanup has its own short timeouts.
  const child=owned.child;
  try {
    if(control && child.exitCode===null && child.signalCode===null){
      try {
        if(kind==='chromium')await control.send('Browser.close',{},undefined,3000);
        else await control.send('Marionette:Quit',{flags:['eForceQuit']},3000);
      } catch(error){metadata.cleanup_notes.push(error.message);}
    }
    control?.close();
    const until=Date.now()+3000;
    while(child.exitCode===null && child.signalCode===null && Date.now()<until)await delay(100);
    if(child.exitCode===null && child.signalCode===null){
      // PID comes only from this still-live ChildProcess, never a name search.
      if(process.platform==='win32') {
        const killer=spawn(path.join(process.env.SystemRoot||'C:\\Windows','System32','taskkill.exe'),['/PID',String(child.pid),'/T','/F'],{windowsHide:true,shell:false,stdio:['ignore','pipe','pipe']});
        let killText='';killer.stdout.on('data',b=>killText+=b);killer.stderr.on('data',b=>killText+=b);
        const killerDone=once(killer,'close');const timer=setTimeout(()=>killer.kill(),5000);
        try{const [code]=await killerDone;if(code!==0)metadata.cleanup_notes.push(`taskkill exit ${code}: ${killText.trim()}`);}finally{clearTimeout(timer);}
      } else {child.kill('SIGKILL');}
      const stopBy=Date.now()+3000;while(child.exitCode===null && child.signalCode===null && Date.now()<stopBy)await delay(100);
    }
    metadata.process_exit_code=child.exitCode;metadata.process_signal=child.signalCode;
    if(child.exitCode===null && child.signalCode===null)throw new Error('Owned browser did not terminate; stop matrix before launching another');
  } finally {
    control?.close();owned.stdout.end();owned.stderr.end();
  }
}

async function chromiumControl(browser,profile,runDir,meta,startupDeadline) {
  const preferences=chromiumPreferences();
  // Opera owns a separate DoH selector which feeds the Chromium preferences.
  // Its bundled settings resource (opera.pak resource 19395) sets doh_mode to
  // "custom" and custom_servers to the entered URL; enabled_version=1 is the
  // observed migration marker. Netlog verifies these requests become active.
  if(browser.product==='Opera')preferences.dns_over_https.opera={enabled_version:1,doh_mode:'custom',custom_servers:DOH};
  await saveJSON(path.join(profile,'Local State'),preferences);
  const args=['--headless=new','--no-first-run','--no-default-browser-check','--disable-quic','--disable-background-networking','--disable-component-update','--disable-sync','--disable-default-apps','--no-proxy-server','--enable-features=EncryptedClientHello','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0',`--user-data-dir=${profile}`,`--log-net-log=${path.join(runDir,'netlog.json')}`,'--net-log-capture-mode=IncludeSensitive','--window-size=1400,1000','about:blank'];
  meta.arguments=args;meta.preferences=preferences;meta.trust={method:'Windows trusted lab CA; normal browser certificate verification',certificate_verification_bypassed:false};
  deadlineTimeout(1,startupDeadline);
  const owned=await launchOwned(browser,args,runDir);meta.root_pid=owned.child.pid;
  let control;
  try {
    const activePort=await waitUntil(async()=>{
      const lines=(await fsp.readFile(path.join(profile,'DevToolsActivePort'),'utf8')).trim().split(/\r?\n/);
      if(!/^\d+$/.test(lines[0]) || !lines[1]?.startsWith('/devtools/browser/'))return null;
      return {port:Number(lines[0]),path:lines[1]};
    },20000,'Chromium DevTools endpoint did not become ready',owned.child,startupDeadline);
    control=await CDP.connect(`ws://127.0.0.1:${activePort.port}${activePort.path}`,startupDeadline);activeControl=control;
    meta.runtime=await control.send('Browser.getVersion');
    const targets=await control.send('Target.getTargets');
    let target=targets.targetInfos.find(t=>t.type==='page' && t.url==='about:blank');
    if(!target){const made=await control.send('Target.createTarget',{url:'about:blank'});target={targetId:made.targetId};}
    const {sessionId}=await control.send('Target.attachToTarget',{targetId:target.targetId,flatten:true});
    await control.send('Page.enable',{},sessionId);await control.send('Runtime.enable',{},sessionId);await control.send('Network.enable',{},sessionId);await control.send('Log.enable',{},sessionId);
    const navigation=await control.send('Page.navigate',{url:DASHBOARD},sessionId,20000);
    if(navigation.errorText)throw new Error(`Dashboard navigation failed: ${navigation.errorText}`);
    const evaluate=async expression=>{
      const value=await control.send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:false},sessionId);
      if(value.exceptionDetails)throw new Error(`Page evaluation failed: ${value.exceptionDetails.text}`);
      return value.result?.value;
    };
    await waitUntil(()=>evaluate(`location.origin===${JSON.stringify(new URL(DASHBOARD).origin)} && typeof window.labRun==='function'`),15000,'Dashboard did not initialize (check trust and service)',owned.child,startupDeadline);
    meta.user_agent=await evaluate('navigator.userAgent');meta.platform=await evaluate('navigator.platform');
    return {owned,control,evaluate,screenshot:async()=>{const s=await control.send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true},sessionId);return Buffer.from(s.data,'base64');},diagnostics:()=>control.events};
  } catch(error) {await finishOwned(owned,control,'chromium',meta);throw error;}
}

async function firefoxControl(browser,profile,runDir,meta,startupDeadline) {
  meta.trust=await ensureFirefoxPolicy(browser);
  const port=await freePort(),prefs=firefoxPrefs(port);
  await fsp.writeFile(path.join(profile,'user.js'),Object.entries(prefs).map(([key,value])=>`user_pref(${JSON.stringify(key)}, ${JSON.stringify(value)});`).join('\n')+'\n','utf8');
  const args=['-no-remote','-profile',profile,'--headless','-marionette','-width','1400','-height','1000','about:blank'];
  meta.arguments=args;meta.preferences=prefs;
  deadlineTimeout(1,startupDeadline);
  const owned=await launchOwned(browser,args,runDir,{MOZ_LOG:'timestamp,sync,nsHostResolver:3,nsHttp:3',MOZ_LOG_FILE:path.join(runDir,'firefox-network.log')});meta.root_pid=owned.child.pid;
  let control;
  try {
    control=await waitUntil(()=>Marionette.connect(port,startupDeadline),20000,'Firefox Marionette did not become ready',owned.child,startupDeadline);activeControl=control;
    const session=await control.send('WebDriver:NewSession',{acceptInsecureCerts:false,unhandledPromptBehavior:'dismiss and notify',pageLoadStrategy:'normal'});
    meta.runtime=session.capabilities;meta.marionette_session_id=session.sessionId;
    if(session.capabilities?.acceptInsecureCerts!==false)throw new Error('Firefox did not confirm certificate validation remained enabled');
    const actual=session.capabilities?.browserVersion;
    if(actual && actual!==browser.version.replace(/esr$/i,''))throw new Error(`Firefox runtime version ${actual} differs from pinned manifest ${browser.version}`);
    await control.send('WebDriver:SetTimeouts',{script:15000,pageLoad:20000,implicit:0});
    await control.send('WebDriver:Navigate',{url:DASHBOARD},25000);
    const evaluate=expression=>control.evaluate(expression);
    await waitUntil(()=>evaluate(`location.origin===${JSON.stringify(new URL(DASHBOARD).origin)} && typeof window.labRun==='function'`),15000,'Dashboard did not initialize (check trust and service)',owned.child,startupDeadline);
    meta.user_agent=await evaluate('navigator.userAgent');meta.platform=await evaluate('navigator.platform');
    return {owned,control,evaluate,screenshot:async()=>{const s=await control.send('WebDriver:TakeScreenshot',{id:null,full:true,hash:false,scroll:false});return Buffer.from(s.value,'base64');},diagnostics:()=>[]};
  } catch(error) {await finishOwned(owned,control,'gecko',meta);throw error;}
}

async function recoverOwnRegistration(runID,reason) {
  let row;
  try{row=await controlRequest('GET','/api/runs/'+encodeURIComponent(runID));}catch(error){if(error.status===404)return null;throw error;}
  if(row.status==='completed')return row;
  if(row.status!=='registered')throw new Error('Unexpected own run state during recovery');
  return controlRequest('POST','/api/runs/'+encodeURIComponent(runID)+'/complete',{browser_outcome:'aborted',browser_error:'Browser runner interrupted: '+reason,observations:{runner_recovery:true,not_a_synthetic_browser_probe:true}});
}

async function runOne(browser,caseID,repetition,options,batchDir) {
  const runID=`${options.batch.slice(0,48)}-${browser.id}-${caseID}-r${repetition}-${crypto.randomBytes(4).toString('hex')}`;
  const runDir=path.join(batchDir,'runs',runID),profile=path.join(ROOT,'.runtime','profiles','matrix-'+runID);
  await assertUnredirectedWithin(ROOT,runDir);await assertUnredirectedWithin(ROOT,profile);
  await fsp.mkdir(runDir,{recursive:true});await fsp.mkdir(profile,{recursive:false});
  const canonicalOS=process.platform==='win32' ? `Windows 11 build ${os.release().split('.')[2]}` : `${os.type()} ${os.release()} ${os.arch()}`;
  const meta={run_id:runID,batch_id:options.batch,browser_id:browser.id,case_id:caseID,repetition,started_utc:new Date().toISOString(),status:'preparing',executable:browser.path,pinned_version:browser.version,distribution:browser.distribution,profile,run_directory:runDir,os:canonicalOS,os_runtime:{type:os.type(),release:os.release(),arch:os.arch()},certificate_verification_bypassed:false,cleanup_notes:[]};
  const expiry=options.stopBeforeUTC ? Date.parse(options.stopBeforeUTC) : null;
  const startupDeadline=expiry ? expiry-LEASE_RESERVE_MS : null;
  const measurementDeadline=expiry ? expiry-CLEANUP_RESERVE_MS : null;
  let client=null,result=null,failure=null,registrationDispatched=false;
  try {
    const observedHash=await hashFile(browser.path);meta.executable_sha256=observedHash;
    if(observedHash.toLowerCase()!==String(browser.sha256).toLowerCase())throw new Error(`Executable changed since browsers.json: ${browser.id}; refresh and review the manifest before measurement`);
    meta.certificate_sha256=await hashFile(path.join(ROOT,'.runtime','server.pem'));
    const kind=browser.engine?.family;
    if(kind==='chromium')client=await chromiumControl(browser,profile,runDir,meta,startupDeadline);
    else if(kind==='gecko')client=await firefoxControl(browser,profile,runDir,meta,startupDeadline);
    else throw new Error(`Unknown engine family ${kind}`);
    const config={run_id:runID,browser_id:browser.id,browser_product:browser.product,browser_version:browser.version,distribution:browser.distribution,os:meta.os,case_id:caseID,repetition,batch_id:options.batch,settings:{fresh_profile:true,profile_path:profile,https_over_tcp:true,http3_disabled:true,do_h_endpoint:DOH,secure_doh_requested:true,ech_explicitly_enabled:true,normal_certificate_validation:true,certificate_sha256:meta.certificate_sha256,executable_sha256:meta.executable_sha256,engine_family:kind,runtime:meta.runtime,preferences:meta.preferences,trust:meta.trust,runner:'scripts/run-matrix.cjs'}};
    if(startupDeadline)config.registration_deadline_utc=new Date(startupDeadline).toISOString();
    await afterReadiness(async()=>{
      await waitUntil(async()=>{
        const ready=await client.evaluate(`(()=>{if(!window.__LAB_READY_CHECK){window.__LAB_READY_CHECK={ready:false};Promise.resolve(window.labReady).then(()=>{window.__LAB_READY_CHECK.ready=true;},e=>{window.__LAB_READY_CHECK.error=String(e);});}return window.__LAB_READY_CHECK;})()`);
        if(ready?.error)throw new Error('Dashboard readiness failed: '+ready.error);
        return ready?.ready;
      },30000,'Dashboard labReady did not resolve',client.owned.child,startupDeadline);
      meta.registration=config;meta.status='pre_registration';await saveJSON(path.join(runDir,'runner.json'),meta);
    },async()=>{
      // The page repeats the deadline check immediately before POST /api/runs.
      // The control response may arrive later, so allow the measurement budget.
      client.control.deadline=measurementDeadline;
      registrationDispatched=true;
      await client.evaluate(`(window.labRun(${JSON.stringify(config)}).catch(()=>{}),true)`);
    },startupDeadline);
    result=await waitUntil(()=>client.evaluate('window.__LAB_DONE || null'),options.timeout*1000,'Browser measurement did not complete',client.owned.child,measurementDeadline);
    if(result.status==='paused_before_registration') { registrationDispatched=false;result=null;throw new LeasePauseError(); }
    if(result.status!=='completed')throw new Error(result.runner_error||'Browser control page did not save a completed measurement');
    meta.status='completed';meta.result=result;meta.protocol_diagnostics=client.diagnostics();
    await fsp.writeFile(path.join(runDir,'page.html'),await client.evaluate('document.documentElement.outerHTML'),'utf8');
    if(options.screenshots==='all' || (options.screenshots==='representative' && (repetition===1 || ['inconclusive','infrastructure_error','fixture_mismatch'].includes(result.outcome)))) {
      try{await fsp.writeFile(path.join(runDir,'page.png'),await client.screenshot());meta.screenshot='page.png';}catch(error){meta.screenshot_error=error.message;}
    }
  } catch(error) {
    if(error instanceof LeasePauseError && !registrationDispatched) {
      meta.status='paused_before_registration';meta.pause_reason='lease_deadline';
    } else {
      failure=error;meta.status='runner_error';meta.error=error.stack||error.message;
      if(client){try{await fsp.writeFile(path.join(runDir,'error-page.png'),await client.screenshot());}catch{}}
    }
  } finally {
    if(client){try{await finishOwned(client.owned,client.control,browser.engine.family,meta);}catch(error){failure=failure||error;meta.cleanup_notes.push(error.message);meta.status='runner_error';}}
    activeControl=null;
    if(failure){
      try {const recovered=await recoverOwnRegistration(runID,failure.message);if(recovered){result=recovered;meta.recovered_result=recovered;}}
      catch(error){meta.recovery_error=error.message;}
    }
    meta.finished_utc=new Date().toISOString();await saveJSON(path.join(runDir,'runner.json'),meta);
  }
  return {run_id:runID,browser_id:browser.id,case_id:caseID,repetition,status:meta.status,outcome:result?.outcome||null,result:result||null,error:failure?.message||null,runner_file:path.relative(ROOT,path.join(runDir,'runner.json')),cleanup_notes:meta.cleanup_notes};
}

async function main(argv=process.argv.slice(2)) {
  const options=parseArgs(argv);
  if(options.help){console.log('Usage: node scripts/run-matrix.cjs [--browser id,id] [--case E1,E2] [--repeats 3] [--batch safe-id] [--screenshots representative|all|none] [--timeout 60] [--stop-before-utc timestamp] [--dry-run]\nNo filters runs 7 builds x 12 cases x 3 repetitions. A lease deadline pauses before a new run when fewer than 180 seconds remain. Fresh profiles and normal TLS validation are mandatory. Results remain local.');return;}
  const manifest=JSON.parse((await fsp.readFile(path.join(ROOT,'browsers.json'),'utf8')).replace(/^\uFEFF/,''));
  const all=Array.isArray(manifest)?manifest:manifest.browsers;
  if(!Array.isArray(all)||!all.length)throw new Error('browsers.json contains no browser builds');
  if(options.browsers.some(id=>!all.some(b=>b.id===id)))throw new Error('Unknown browser ID; available: '+all.map(b=>b.id).join(','));
  const browsers=options.browsers.length?all.filter(b=>options.browsers.includes(b.id)):all;
  const cases=options.cases.length?CASE_IDS.filter(id=>options.cases.includes(id)):CASE_IDS;
  for(const browser of browsers){if(!ID_RE.test(browser.id)||!browser.path||!browser.sha256)throw new Error('Invalid browser manifest entry');}
  const count=browsers.length*cases.length*options.repeats;
  const plan={batch_id:options.batch,browsers:browsers.map(b=>({id:b.id,version:b.version,path:b.path})),cases,repetitions:options.repeats,planned_runs:count,fresh_profile_per_run:true,certificate_verification_bypassed:false};
  if(options.dryRun){console.log(JSON.stringify(plan,null,2));return;}
  const caPath=path.join(ROOT,'.runtime','ca.pem'),leafPath=path.join(ROOT,'.runtime','server.pem');
  for(const certPath of [caPath,leafPath]){const cert=new crypto.X509Certificate(await fsp.readFile(certPath));if(Date.now()<Date.parse(cert.validFrom)||Date.now()>=Date.parse(cert.validTo))throw new Error(`Certificate is outside its validity interval: ${certPath}`);}
  const availableCases=await controlRequest('GET','/api/cases');
  if(cases.some(id=>!availableCases.some(c=>c.id===id)))throw new Error('Server case manifest does not cover selected cases');
  const serverRuns=await controlRequest('GET','/api/runs');
  const outstanding=serverRuns.filter(r=>r.status==='registered' && r.client_ip==='127.0.0.1');
  if(outstanding.length)throw new Error('Outstanding loopback run must be completed before this matrix: '+outstanding.map(r=>r.run_id).join(','));
  const batchDir=path.join(ROOT,'evidence','matrix',options.batch);
  await assertUnredirectedWithin(ROOT,batchDir);
  await fsp.mkdir(path.join(ROOT,'.runtime','profiles'),{recursive:true});
  await fsp.mkdir(batchDir,{recursive:true});
  const manifestHash=await hashFile(path.join(ROOT,'browsers.json'));
  const cellKey=(browserID,caseID,repetition)=>`${browserID}/${caseID}/${repetition}`;
  const selectedCells=[];for(const browser of browsers){for(const caseID of cases){for(let rep=1;rep<=options.repeats;rep++)selectedCells.push(cellKey(browser.id,caseID,rep));}}
  let report;
  try{
    report=JSON.parse(await fsp.readFile(path.join(batchDir,'matrix.json'),'utf8'));
    if(report.batch_id!==options.batch || report.manifest_sha256!==manifestHash || !Array.isArray(report.runs) || !Array.isArray(report.planned_cells))throw new Error('Existing batch does not match this pinned manifest/schema; preserve it and choose a new --batch');
    const mergedBrowsers=new Map(report.browsers.map(b=>[b.id,b]));for(const b of plan.browsers)mergedBrowsers.set(b.id,b);
    report.browsers=[...mergedBrowsers.values()];report.cases=CASE_IDS.filter(id=>report.cases.includes(id)||cases.includes(id));report.repetitions=Math.max(report.repetitions,options.repeats);
    report.planned_cells=[...new Set([...report.planned_cells,...selectedCells])];report.planned_runs=report.planned_cells.length;
    report.status='running';delete report.error;delete report.finished_utc;delete report.pause;
  }catch(error){
    if(error.code!=='ENOENT')throw error;
    report={...plan,planned_cells:selectedCells,started_utc:new Date().toISOString(),status:'running',manifest_sha256:manifestHash,runs:[]};
  }
  report.invocations=report.invocations||[];report.invocations.push({started_utc:new Date().toISOString(),browsers:options.browsers,cases:options.cases,repeats:options.repeats,...(options.stopBeforeUTC?{stop_before_utc:options.stopBeforeUTC,lease_reserve_seconds:LEASE_RESERVE_MS/1000}:{})});
  // The server completion is authoritative even when later screenshot/HTML
  // capture failed or this process was interrupted before matrix.json saved.
  // Preserve that measurement rather than silently repeating a completed cell.
  for(const saved of serverRuns.filter(r=>r.batch_id===options.batch && r.status==='completed' && r.settings?.runner==='scripts/run-matrix.cjs')) {
    const known=report.runs.find(row=>row.run_id===saved.run_id);
    if(known){known.result=saved;continue;}
    report.runs.push({run_id:saved.run_id,browser_id:saved.browser_id,case_id:saved.case_id,repetition:saved.repetition,status:'server_completed_artifacts_unverified',outcome:saved.outcome,result:saved,error:null,runner_file:path.relative(ROOT,path.join(batchDir,'runs',saved.run_id,'runner.json')),cleanup_notes:[],reconciled_from_server:true});
  }
  const completedCells=new Set(report.runs.filter(r=>r.result?.status==='completed').map(r=>cellKey(r.browser_id,r.case_id,r.repetition)));
  await saveJSON(path.join(batchDir,'matrix.json'),report);
  const signalHandler=()=>{interrupted=true;activeControl?.close();};
  process.once('SIGINT',signalHandler);process.once('SIGTERM',signalHandler);
  try {
    measurementLoop: for(const browser of browsers){for(const caseID of cases){for(let repetition=1;repetition<=options.repeats;repetition++){
      if(interrupted)throw new Error('Runner interrupted');
      const action=cellAction(options,completedCells.has(cellKey(browser.id,caseID,repetition)));
      if(action==='preserve'){console.log(`[resume] Preserved completed ${browser.id} ${caseID} r${repetition}`);continue;}
      if(action==='pause') {
        report.status='paused';
        report.pause={reason:'lease_deadline',paused_utc:new Date().toISOString(),stop_before_utc:options.stopBeforeUTC,reserve_seconds:LEASE_RESERVE_MS/1000,next_cell:cellKey(browser.id,caseID,repetition)};
        console.log(`[paused] Lease reserve reached before ${report.pause.next_cell}; no new browser or measurement started. Resume the same batch with a fresh lease.`);
        break measurementLoop;
      }
      const row=await runOne(browser,caseID,repetition,options,batchDir);
      report.runs.push(row);await saveJSON(path.join(batchDir,'matrix.json'),report);
      if(row.status==='paused_before_registration') {
        report.status='paused';
        report.pause={reason:'lease_deadline_during_startup',paused_utc:new Date().toISOString(),stop_before_utc:options.stopBeforeUTC,reserve_seconds:LEASE_RESERVE_MS/1000,next_cell:cellKey(browser.id,caseID,repetition),startup_run_id:row.run_id};
        console.log(`[paused] Startup reached the lease reserve before registration of ${report.pause.next_cell}; owned browser cleaned up and no measurement recorded.`);
        break measurementLoop;
      }
      if(row.result?.status==='completed')completedCells.add(cellKey(browser.id,caseID,repetition));
      console.log(`[${completedCells.size}/${report.planned_runs}] ${browser.id} ${caseID} r${repetition}: ${row.outcome||row.status}${row.error?' - '+row.error:''}`);
      if(row.status!=='completed')throw new Error('Matrix stopped on runner/control failure; inspect '+row.runner_file);
    }}}
    if(report.status!=='paused')report.status='completed';
  } catch(error){report.status='stopped';report.error=error.message;throw error;}
  finally {
    report.finished_utc=new Date().toISOString();report.completed_runs=report.runs.filter(r=>r.result?.status==='completed').length;report.unique_completed_cells=completedCells.size;
    report.artifact_or_cleanup_gaps=report.runs.filter(r=>r.result?.status==='completed' && r.status!=='completed').map(r=>({run_id:r.run_id,status:r.status,error:r.error,runner_file:r.runner_file}));
    try{report.server_summary=await controlRequest('GET','/api/summary?batch_id='+encodeURIComponent(options.batch));}catch(error){report.summary_error=error.message;}
    await saveJSON(path.join(batchDir,'matrix.json'),report);
    process.removeListener('SIGINT',signalHandler);process.removeListener('SIGTERM',signalHandler);
    console.log(`Saved ${path.join(batchDir,'matrix.json')}`);
  }
}

module.exports={parseArgs,cellAction,LEASE_RESERVE_MS,CLEANUP_RESERVE_MS,LeasePauseError,deadlineTimeout,afterReadiness,CDP,MarionetteFrames,chromiumPreferences,firefoxPrefs,main};
if(require.main===module)main().catch(error=>{console.error(error.stack||error.message);process.exitCode=1;});
