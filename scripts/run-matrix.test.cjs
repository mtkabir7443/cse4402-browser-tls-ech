'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseArgs, cellAction, LEASE_RESERVE_MS, LeasePauseError, deadlineTimeout, afterReadiness, CDP } = require('./run-matrix.cjs');

test('lease expiry accepts the Windows UTC format and rejects ambiguous deadlines', () => {
  assert.equal(parseArgs(['--stop-before-utc','2026-11-15T18:30:00.1234567Z']).stopBeforeUTC,'2026-11-15T18:30:00.123Z');
  for (const value of ['2026-11-15T18:30:00','2026-11-15T18:30:00-05:00','tomorrow','2026-99-15T18:30:00Z']) {
    assert.throws(() => parseArgs(['--stop-before-utc',value]), /valid UTC timestamp/);
  }
});

test('new measurements require the full reserve and expired leases cannot start them', () => {
  const expiry=Date.parse('2026-11-15T18:30:00Z');
  const options=parseArgs(['--stop-before-utc',new Date(expiry).toISOString()]);
  assert.ok(LEASE_RESERVE_MS>=120000);
  assert.equal(cellAction(options,false,expiry-LEASE_RESERVE_MS),'run');
  assert.equal(cellAction(options,false,expiry-LEASE_RESERVE_MS+1),'pause');
  assert.equal(cellAction(options,false,expiry),'pause');
  assert.equal(cellAction(options,false,expiry+1),'pause');
});

test('resume preserves completed cells even after expiry and leaves unbounded runs unchanged', () => {
  const options=parseArgs(['--stop-before-utc','2026-11-15T18:30:00Z']);
  const after=Date.parse('2026-11-15T18:31:00Z');
  assert.equal(cellAction(options,true,after),'preserve');
  assert.equal(cellAction(options,false,after),'pause');
  assert.equal(cellAction(parseArgs([]),false,after),'run');
  assert.equal(cellAction(parseArgs([]),true,after),'preserve');
});

test('sequential slow startup commands cannot consume the lease then invoke registration', async t => {
  let now=1000,actions=0,sends=0;
  t.mock.method(Date,'now',()=>now);
  const deadline=now+180000;
  class Socket extends EventTarget {
    send(raw) {
      sends++;
      const {id}=JSON.parse(raw);
      queueMicrotask(()=>{
        now+=70000;
        this.dispatchEvent(new MessageEvent('message',{data:JSON.stringify({id,result:{}})}));
      });
    }
    close() {}
  }
  const cdp=new CDP(new Socket(),deadline);
  try {
    await assert.rejects(afterReadiness(async()=>{
      await cdp.send('Browser.getVersion');
      await cdp.send('Target.getTargets');
      await cdp.send('Page.navigate');
    },()=>{actions++;},deadline),LeasePauseError);
    assert.equal(actions,0);
    assert.equal(sends,3);
    assert.throws(()=>cdp.send('Runtime.evaluate'),LeasePauseError);
    assert.equal(sends,3);
  } finally { cdp.close(); }
});

test('readiness resolving at the deadline blocks the action and wait budgets shrink', async t => {
  let now=1000,actions=0;
  t.mock.method(Date,'now',()=>now);
  assert.equal(deadlineTimeout(15000,1100),100);
  await assert.rejects(afterReadiness(async()=>{now=1100;},()=>{actions++;},1100),LeasePauseError);
  assert.equal(actions,0);
  assert.throws(()=>deadlineTimeout(15000,1100),LeasePauseError);
  assert.equal(deadlineTimeout(15000,null),15000);
});

test('page delays before registration create no server record or measurement result', async () => {
  const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
  const app=fs.readFileSync(path.join(__dirname,'../web/app.js'),'utf8');
  const start=app.indexOf('window.labRun = async function');
  const end=app.indexOf("\nbyId('case-select').addEventListener",start);
  assert.ok(start>=0 && end>start);
  for(const delayAt of ['labReady','beforePost']) {
    let now=1000,posts=0,resolveReady;
    const ready=new Promise(resolve=>{resolveReady=resolve;});
    const elements=new Map(),state={running:false,cases:[{id:'C4'}],browsers:[]};
    const context={
      window:{labReady:ready},state,
      Date:{now:()=>now,parse:Date.parse},
      navigator:{platform:'test',userAgent:'test'},
      byId:id=>{if(!elements.has(id))elements.set(id,{value:''});return elements.get(id);},
      describeCase:()=>{if(delayAt==='beforePost')now=1100;},showError:()=>{},
      post:async()=>{posts++;throw new Error('Registration must not be called');}
    };
    vm.runInNewContext(app.slice(start,end),context);
    const pending=context.window.labRun({run_id:'guard-only',case_id:'C4',repetition:1,batch_id:'guard-only',registration_deadline_utc:new Date(1100).toISOString()});
    if(delayAt==='labReady')now=1100;
    resolveReady();
    const result=await pending;
    assert.equal(result.status,'paused_before_registration');
    assert.equal(posts,0);
    assert.equal(state.running,false);
    assert.equal(context.window.__LAB_DONE.status,'paused_before_registration');
    assert.equal(result.outcome,undefined);
  }
});
