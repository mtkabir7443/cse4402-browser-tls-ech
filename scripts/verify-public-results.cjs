#!/usr/bin/env node
'use strict';

// Portable verification of the published summary only. No private logs, browser
// binaries, certificate stores, network access, or external dependencies are used.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

const KIND = 'cse4402-public-results';
const SUMMARY_SCOPE = 'Sanitized selected observations and private-audit assertions; not raw handshake logs.';
const VERIFY_SCOPE = 'Internal consistency, included summary references, and complete coverage only; no replay of the private raw audit or independent proof of measurement authenticity.';
const BROWSER_IDS = ['chrome-current','firefox-current','edge-current','brave-current','opera-current','chrome-116','firefox-115'];
const CASES = [
  ['V1','version','TLS 1.0',null,null,'rejected_protocol'],
  ['V2','version','TLS 1.1',null,null,'rejected_protocol'],
  ['V3','version','TLS 1.2',null,null,'connected'],
  ['V4','version','TLS 1.3',null,null,'connected'],
  ['C1','cipher','TLS 1.2','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',null,'connected'],
  ['C2','cipher','TLS 1.2','TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',null,'connected'],
  ['C3','cipher','TLS 1.3','TLS_AES_128_GCM_SHA256',null,'connected'],
  ['C4','cipher','TLS 1.3','TLS_AES_256_GCM_SHA384',null,'connected'],
  ['C5','cipher','TLS 1.3','TLS_CHACHA20_POLY1305_SHA256',null,'connected'],
  ['E1','ech','TLS 1.3',null,true,'ech_accepted'],
  ['E2','ech','TLS 1.3',null,false,'connected_no_ech'],
  ['E3','ech','TLS 1.3',null,true,'ech_recovered'],
].map(([id,family,expected_tls,expected_cipher,expected_ech,outcome])=>({id,family,expected_tls,expected_cipher,expected_ech,outcome}));
const FILES = ['README.md','comparison-data.json','comparison.html','evidence-summary.json','results.csv','results.jsonl'];
const RECORD_FIELDS = ['run_id','batch_id','browser_id','browser_product','browser_version','executable_sha256','os','case_id','repetition','client_ip','started_utc','completed_utc','status','outcome','browser_outcome','tls_version','cipher_suite','ech_accepted','resumed','expected_match','controls','retry','summary_evidence_ids'];
const CSV_FIELDS = [...RECORD_FIELDS];
const CONTROL_FIELDS = ['fresh_profile','normal_certificate_validation','https_over_tcp','http3_disabled','secure_doh_requested','ech_explicitly_enabled'];
const RETRY_FIELDS = ['initial_config_id','accepted_config_id','initial_ech_accepted','final_ech_accepted','exact_retry_count','basis'];
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
function need(condition, message) { if (!condition) throw new Error(message); }
function keys(value, expected, label) {
  need(value && typeof value === 'object' && !Array.isArray(value), label + ': expected object');
  need(isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort()), label + ': fields differ from the public allowlist');
}
function string(value, label, max=200) { need(typeof value === 'string' && value.length > 0 && value.length <= max, label + ': invalid text'); }
function digest(value, label) { need(typeof value === 'string' && /^[a-f0-9]{64}$/.test(value), label + ': invalid SHA-256'); }
function timestamp(value, label) {
  need(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$/.test(value) && Number.isFinite(Date.parse(value)), label + ': invalid UTC time');
  return Date.parse(value);
}
function assertSanitized(value) {
  const visit = (item, label) => {
    if (typeof item === 'string') {
      need(!/(?:[a-z]:[\\/]|\\\\|file:\/\/|\/(?:Users|home|tmp)\/|\.runtime|\.tools|netlog|-----BEGIN|--user-data-dir|tlslab\.test|https?:\/\/)/i.test(item), label + ': private path, endpoint, raw diagnostic, or key material');
      need(!/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(item), label + ': control characters');
    } else if (Array.isArray(item)) item.forEach((v,i)=>visit(v, label+'['+i+']'));
    else if (item && typeof item === 'object') Object.entries(item).forEach(([k,v])=>visit(v,label+'.'+k));
  };
  visit(value,'public data');
}
function coverage(results, browsers, cases) {
  const slots = new Map(browsers.flatMap(b=>cases.flatMap(c=>[1,2,3].map(n=>[`${b.id}/${c.id}/${n}`,0]))));
  const outcomes = {}, ids = new Set();
  for (const r of results) {
    const slot = `${r.browser_id}/${r.case_id}/${r.repetition}`;
    need(slots.has(slot), 'Unexpected observation slot: '+slot);
    need(!ids.has(r.run_id), 'Duplicate run ID: '+r.run_id); ids.add(r.run_id);
    slots.set(slot,slots.get(slot)+1); outcomes[r.outcome]=(outcomes[r.outcome]||0)+1;
  }
  return {expected_records:252,actual_records:results.length,unique_slots:[...slots.values()].filter(n=>n>0).length,complete:results.length===252&&[...slots.values()].every(n=>n===1),outcomes:Object.fromEntries(Object.entries(outcomes).sort())};
}
function serializeResults(results) {
  const cell = value => {
    let s = value !== null && typeof value === 'object' ? JSON.stringify(value) : String(value ?? '');
    if (/^\s*[=+@-]/.test(s)) s="'"+s;
    return '"'+s.replaceAll('"','""')+'"';
  };
  return {
    jsonl:results.map(r=>JSON.stringify(r)).join('\n')+'\n',
    csv:[CSV_FIELDS.map(cell).join(','),...results.map(r=>CSV_FIELDS.map(k=>cell(r[k])).join(','))].join('\r\n')+'\r\n'
  };
}
function verifyData(data, evidence) {
  keys(data,['artifact_kind','schema_version','batch_id','prepared_utc','provenance','verification_scope','browsers','cases','results','coverage','evidence_file','evidence_sha256'],'dataset');
  need(data.artifact_kind===KIND&&data.schema_version===1,'Unsupported public schema');
  need(data.batch_id==='study-20261115','Unexpected study batch'); timestamp(data.prepared_utc,'prepared_utc');
  need(data.verification_scope===VERIFY_SCOPE,'Verification scope must disclose its limits');
  keys(data.provenance,['original_comparison_sha256','original_private_audit_sha256','original_exported_utc','private_audit_recorded_utc','private_audit_observed_records','private_audit_observed_checks_passed','private_audit_planned_coverage_complete'],'provenance');
  for(const k of ['original_comparison_sha256','original_private_audit_sha256'])digest(data.provenance[k],k);
  timestamp(data.provenance.original_exported_utc,'original_exported_utc');timestamp(data.provenance.private_audit_recorded_utc,'private_audit_recorded_utc');
  need(data.provenance.private_audit_observed_records===252&&data.provenance.private_audit_observed_checks_passed===true&&data.provenance.private_audit_planned_coverage_complete===true,'Private audit assertion is not a completed 252-run audit');
  need(data.evidence_file==='evidence-summary.json','Unexpected evidence companion');digest(data.evidence_sha256,'evidence_sha256');
  need(Array.isArray(data.browsers)&&data.browsers.length===7,'Expected seven browser builds');
  const browsers=new Map();
  for(const b of data.browsers){
    keys(b,['id','product','version','distribution','engine_family','engine_version','executable_sha256'],'browser');
    need(BROWSER_IDS.includes(b.id)&&!browsers.has(b.id),'Unknown/duplicate browser');
    for(const k of ['product','version','distribution'])string(b[k],'browser '+k,220);
    need(['chromium','gecko'].includes(b.engine_family),'Unknown engine family');
    need(b.id==='edge-current'?b.engine_version===null:typeof b.engine_version==='string','Edge Chromium patch must remain unknown');
    digest(b.executable_sha256,'browser executable hash');browsers.set(b.id,b);
  }
  need(Array.isArray(data.cases)&&data.cases.length===12,'Expected twelve cases');
  const cases=new Map();
  for(const c of data.cases){
    keys(c,['id','name','family','expected_tls','expected_cipher','expected_ech'],'case');string(c.name,'case name');
    const expected=CASES.find(e=>e.id===c.id);need(expected&&!cases.has(c.id),'Unknown/duplicate case');
    for(const k of ['family','expected_tls','expected_cipher','expected_ech'])need(c[k]===expected[k],'Case definition mismatch: '+c.id+'/'+k);
    cases.set(c.id,expected);
  }
  keys(evidence,['artifact_kind','schema_version','batch_id','scope','entries'],'evidence summary');
  need(evidence.artifact_kind==='cse4402-public-evidence-summary'&&evidence.schema_version===1&&evidence.batch_id===data.batch_id&&evidence.scope===SUMMARY_SCOPE,'Invalid evidence-summary metadata');
  need(Array.isArray(evidence.entries),'Evidence entries missing');
  const entries=new Map(),used=new Set();
  for(const e of evidence.entries){
    need(/^summary-[a-f0-9]{24}$/.test(e.id||'')&&!entries.has(e.id),'Invalid/duplicate summary evidence ID');
    string(e.run_id,'evidence run ID',120);
    if(e.kind==='selected_server_observation'){
      keys(e,['id','run_id','kind','event','timestamp','client_ip','tls_version','cipher_suite','ech_accepted','resumed','success','error_category','request_matches_run','name_role'],'selected observation');
      need(['http_result','handshake'].includes(e.event),'Unexpected observation event');timestamp(e.timestamp,'evidence time');
      need(e.client_ip==='127.0.0.1','Non-loopback IP in public evidence');
      for(const k of ['ech_accepted','resumed','success','request_matches_run'])need(e[k]===null||typeof e[k]==='boolean','Invalid evidence '+k);
      need(e.error_category===null||e.error_category==='protocol_rejection','Unsupported error summary');
      need(['outer_public','inner_requested','not_recorded'].includes(e.name_role),'Invalid name role');
    }else{
      keys(e,['id','run_id','kind','checks_passed','ech_sequence'],'private audit assertion');
      need(e.kind==='private_audit_assertion'&&e.checks_passed===true,'Invalid private audit assertion');
      if(e.ech_sequence!==null){keys(e.ech_sequence,['stale_config_id','accepted_config_id','exact_retry_count_claimed'],'ECH sequence');need(e.ech_sequence.stale_config_id===16&&e.ech_sequence.accepted_config_id===17&&e.ech_sequence.exact_retry_count_claimed===false,'Invalid ECH audit assertion');}
    }
    entries.set(e.id,e);
  }
  need(Array.isArray(data.results),'Missing result array');
  for(const r of data.results){
    keys(r,RECORD_FIELDS,'result');need(/^[A-Za-z0-9_-]{1,120}$/.test(r.run_id),'Invalid run ID');
    const b=browsers.get(r.browser_id),c=cases.get(r.case_id);need(b&&c,'Unknown run browser/case');
    need(r.batch_id===data.batch_id&&r.status==='completed'&&[1,2,3].includes(r.repetition),'Invalid completed run identity');
    need(r.browser_product===b.product&&r.browser_version===b.version&&r.executable_sha256===b.executable_sha256,'Run/browser metadata mismatch');
    need(r.os==='Windows 11 build 26300'&&r.client_ip==='127.0.0.1','Unexpected environment or IP');
    const start=timestamp(r.started_utc,'run start'),end=timestamp(r.completed_utc,'run end');need(end>=start&&end-start<=120000,'Invalid measurement time window');
    need(r.outcome===c.outcome,'Outcome differs from the recorded study: '+r.run_id);
    keys(r.controls,CONTROL_FIELDS,'controls');need(CONTROL_FIELDS.every(k=>r.controls[k]===true),'Study controls must be explicit and enabled');
    need(Array.isArray(r.summary_evidence_ids)&&r.summary_evidence_ids.length>=2&&new Set(r.summary_evidence_ids).size===r.summary_evidence_ids.length,'Missing/duplicate summary references');
    const refs=r.summary_evidence_ids.map(id=>{const e=entries.get(id);need(e&&e.run_id===r.run_id,'Dangling or cross-run summary reference');used.add(id);return e;});
    const audits=refs.filter(e=>e.kind==='private_audit_assertion'),observed=refs.filter(e=>e.kind==='selected_server_observation');
    need(audits.length===1&&observed.length>0,'Each run needs included observations and one private audit assertion');
    need(observed.every(e=>Date.parse(e.timestamp)>=start&&Date.parse(e.timestamp)<=end),'Summary observation outside run window');
    need(observed.every(e=>e.resumed===false),'Unexpected or unknown resumption in selected observations');
    if(r.outcome==='rejected_protocol'){
      need([r.tls_version,r.cipher_suite,r.ech_accepted,r.resumed,r.expected_match].every(v=>v===null),'Rejected run must not claim a negotiated connection');
      need(r.browser_outcome==='failed'&&observed.every(e=>e.event==='handshake'&&e.success===false&&e.error_category==='protocol_rejection'),'Protocol rejection lacks included summary evidence');
    }else{
      need(r.browser_outcome==='connected'&&r.tls_version===c.expected_tls&&r.expected_match===true&&r.resumed===false,'Invalid successful negotiation summary');
      need(typeof r.cipher_suite==='string'&&r.cipher_suite.startsWith('TLS_')&&typeof r.ech_accepted==='boolean','Missing negotiated fields');
      if(c.expected_cipher!==null)need(r.cipher_suite===c.expected_cipher,'Restricted suite mismatch');
      if(c.expected_ech!==null)need(r.ech_accepted===c.expected_ech,'ECH expectation mismatch');
      const http=observed.filter(e=>e.event==='http_result');need(http.length>0,'Successful run lacks HTTP summary');
      need(http.every(e=>e.request_matches_run===true&&e.name_role==='inner_requested'&&['tls_version','cipher_suite','ech_accepted','resumed'].every(k=>e[k]===r[k])),'HTTP summary disagrees with the run');
    }
    if(r.case_id==='E3'){
      keys(r.retry,RETRY_FIELDS,'retry summary');need(r.retry.initial_config_id===16&&r.retry.accepted_config_id===17&&r.retry.initial_ech_accepted===false&&r.retry.final_ech_accepted===true&&r.retry.exact_retry_count===null&&r.retry.basis==='private_raw_audit_assertion','Invalid retry summary');
      need(audits[0].ech_sequence!==null,'Retry lacks included private audit assertion');
      const finals=observed.filter(e=>e.event==='http_result');need(observed.some(e=>e.event==='handshake'&&e.success===true&&e.name_role==='outer_public'&&e.ech_accepted===false&&finals.some(h=>Date.parse(h.timestamp)>Date.parse(e.timestamp))),'Retry lacks preceding non-accepted outer summary');
    }else need(r.retry===null&&audits[0].ech_sequence===null,'Unexpected retry claim');
  }
  need(used.size===entries.size,'Unreferenced summary evidence entry');
  const actual=coverage(data.results,data.browsers,data.cases);
  need(actual.complete&&isDeepStrictEqual(data.coverage,actual),'Coverage summary differs from exact 7 x 12 x 3 records');
  need(isDeepStrictEqual(actual.outcomes,{connected:147,connected_no_ech:21,ech_accepted:21,ech_recovered:21,rejected_protocol:42}),'Unexpected study totals');
  assertSanitized(data);assertSanitized(evidence);
  return {passed:true,observations:252,browser_builds:7,cases:12,repetitions:3,summary_entries:entries.size,outcomes:actual.outcomes,private_raw_audit_replayed:false,verification_scope:VERIFY_SCOPE};
}
function verifyBundle(contents) {
  const data=JSON.parse(contents['comparison-data.json']),evidence=JSON.parse(contents['evidence-summary.json']),manifest=JSON.parse(contents['manifest.json']);
  const result=verifyData(data,evidence);
  need(hash(contents['evidence-summary.json'])===data.evidence_sha256,'Evidence companion hash mismatch');
  const serialized=serializeResults(data.results);
  need(contents['results.jsonl']===serialized.jsonl,'JSONL differs from the included records');
  need(contents['results.csv']===serialized.csv,'CSV differs from the included records');
  const embedded=contents['comparison.html'].match(/<script id="study-data" type="application\/json">([\s\S]*?)<\/script>/);
  need(embedded&&isDeepStrictEqual(JSON.parse(embedded[1]),data),'HTML embedded data differs from JSON');
  need(contents['comparison.html'].includes(VERIFY_SCOPE),'HTML omits verification limitations');
  need(!/<(?:script|link|img|iframe)\b[^>]*(?:src|href)\s*=/i.test(contents['comparison.html']),'HTML has an external asset reference');
  keys(manifest,['artifact_kind','schema_version','files'],'manifest');
  need(manifest.artifact_kind==='cse4402-public-results-manifest'&&manifest.schema_version===1&&Array.isArray(manifest.files)&&manifest.files.length===FILES.length,'Invalid public manifest');
  const names=new Set();
  for(const item of manifest.files){keys(item,['file','sha256'],'manifest item');need(FILES.includes(item.file)&&!names.has(item.file),'Unknown/duplicate manifest file');names.add(item.file);digest(item.sha256,'manifest digest');need(hash(contents[item.file])===item.sha256,'Artifact hash mismatch: '+item.file);}
  return result;
}
function verifyDirectory(directory) {
  const root=path.resolve(directory),names=fs.readdirSync(root).sort();
  need(isDeepStrictEqual(names,[...FILES,'manifest.json'].sort()),'Public results directory must contain only the seven declared files');
  const contents={};
  for(const name of names){const file=path.join(root,name);need(fs.lstatSync(file).isFile()&&!fs.lstatSync(file).isSymbolicLink(),'Expected a regular public file: '+name);contents[name]=fs.readFileSync(file,'utf8');}
  return verifyBundle(contents);
}
function main(args=process.argv.slice(2)) {
  if(args.length!==1||['--help','-h'].includes(args[0])){
    console.log('Usage: node scripts/verify-public-results.cjs <public-results-directory>');
    if(args.length!==1)process.exitCode=1;
    return;
  }
  console.log(JSON.stringify(verifyDirectory(args[0]),null,2));
}
module.exports={KIND,SUMMARY_SCOPE,VERIFY_SCOPE,BROWSER_IDS,CASES,FILES,RECORD_FIELDS,CSV_FIELDS,CONTROL_FIELDS,hash,coverage,serializeResults,verifyData,verifyBundle,verifyDirectory};
if(require.main===module){try{main();}catch(error){console.error('Public summary verification failed: '+error.message);process.exitCode=1;}}
