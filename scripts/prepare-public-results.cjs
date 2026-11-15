#!/usr/bin/env node
'use strict';

// Allowlist-only derivative of a completed private study. Reads saved files;
// never starts services, changes trust, fetches URLs, or changes original data.
const fs = require('node:fs');
const path = require('node:path');
const {KIND,SUMMARY_SCOPE,VERIFY_SCOPE,FILES,CSV_FIELDS,CONTROL_FIELDS,hash,coverage,serializeResults,verifyData,verifyDirectory} = require('./verify-public-results.cjs');
const ROOT=path.resolve(__dirname,'..');
const nullable=value=>value===undefined?null:value;
const json=value=>JSON.stringify(value,null,2)+'\n';
const safeJSON=value=>JSON.stringify(value).replaceAll('<','\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029');
const escapeHTML=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function need(condition,message){if(!condition)throw new Error(message);}
function parseArgs(args){
  const options={input:path.join(ROOT,'output','comparison-data.json'),audit:path.join(ROOT,'evidence','study-audit.json'),out:path.join(ROOT,'output','delivery','public-results')};
  for(let i=0;i<args.length;i++){
    if(args[i]==='--help'){options.help=true;continue;}
    const key={'--input':'input','--audit':'audit','--out':'out'}[args[i]];
    need(key&&args[i+1]&&!args[i+1].startsWith('--'),'Unknown/incomplete argument: '+args[i]);options[key]=path.resolve(args[++i]);
  }
  return options;
}
function prepareData(source,audit,sourceBytes,auditBytes){
  need(source.artifact_kind==='cse4402-browser-comparison'&&source.schema_version===1,'Unrecognized original comparison schema');
  need(audit.artifact_kind==='cse4402-independent-study-audit'&&audit.observed_checks_passed===true&&audit.planned_coverage_complete===true&&audit.observed_records===252&&audit.findings.length===0,'A complete passing private audit is required');
  need(source.batch_id===audit.batch_id,'Source/audit batch mismatch');
  const comparisonHash=hash(sourceBytes);
  need(audit.sources.some(item=>item.file==='output/comparison-data.json'&&item.sha256===comparisonHash),'Private audit does not bind this exact original comparison file');
  const checks=new Map(audit.run_checks.map(c=>[c.run_id,c]));
  need(checks.size===252&&audit.run_checks.length===252,'Private audit must include exactly 252 unique run checks');
  const browsers=source.browsers.map(b=>({id:b.id,product:b.product,version:b.version,distribution:b.distribution,engine_family:b.engine.family,engine_version:nullable(b.engine.version),executable_sha256:b.sha256.toLowerCase()}));
  const cases=source.cases.map(c=>({id:c.id,name:c.name,family:c.family,expected_tls:c.expected_tls,expected_cipher:nullable(c.expected_cipher),expected_ech:nullable(c.expected_ech)}));
  const entries=[];
  const results=source.results.map(r=>{
    const check=checks.get(r.run_id),item=source.cases.find(c=>c.id===r.case_id);
    need(check&&check.passed===true&&check.outcome===r.outcome&&check.slot===`${r.browser_id}/${r.case_id}/${r.repetition}`,'Private per-run audit mismatch: '+r.run_id);
    need(Array.isArray(r.evidence)&&r.evidence.length>0,'Run has no normalized evidence');
    const refs=r.evidence.map((e,index)=>{
      const id='summary-'+hash(JSON.stringify([r.run_id,index,e.file,e.line])).slice(0,24);
      const error=e.error?(/unsupported versions|unsupported protocol|alert protocol version|protocol version not supported/i.test(e.error)?'protocol_rejection':null):null;
      need(!e.error||error,'Cannot safely summarize an unrecognized handshake error');
      entries.push({id,run_id:r.run_id,kind:'selected_server_observation',event:e.event,timestamp:e.timestamp,client_ip:e.client_ip,tls_version:nullable(e.tls_version),cipher_suite:nullable(e.cipher_suite),ech_accepted:nullable(e.ech_accepted),resumed:nullable(e.resumed),success:nullable(e.success),error_category:error,request_matches_run:e.event==='http_result'?e.run_id===r.run_id:null,name_role:e.server_name==='public.tlslab.test'?'outer_public':e.server_name===item.host?'inner_requested':'not_recorded'});
      return id;
    });
    const auditId='summary-'+hash(JSON.stringify([r.run_id,'private_audit_assertion'])).slice(0,24);
    let retry=null,sequence=null;
    if(r.case_id==='E3'){
      need(check.ech_sequence?.stale_config_id===16&&check.ech_sequence.accepted_config_id===17&&check.ech_sequence.exact_retry_count_claimed===false,'Missing audited stale ECH sequence');
      sequence={stale_config_id:check.ech_sequence.stale_config_id,accepted_config_id:check.ech_sequence.accepted_config_id,exact_retry_count_claimed:false};
      retry={initial_config_id:sequence.stale_config_id,accepted_config_id:sequence.accepted_config_id,initial_ech_accepted:false,final_ech_accepted:true,exact_retry_count:null,basis:'private_raw_audit_assertion'};
    }
    entries.push({id:auditId,run_id:r.run_id,kind:'private_audit_assertion',checks_passed:true,ech_sequence:sequence});refs.push(auditId);
    return {run_id:r.run_id,batch_id:r.batch_id,browser_id:r.browser_id,browser_product:r.browser_product,browser_version:r.browser_version,executable_sha256:r.settings.executable_sha256.toLowerCase(),os:r.os,case_id:r.case_id,repetition:r.repetition,client_ip:r.client_ip,started_utc:r.started_utc,completed_utc:r.completed_utc,status:r.status,outcome:r.outcome,browser_outcome:r.browser_outcome,tls_version:nullable(r.tls_version),cipher_suite:nullable(r.cipher_suite),ech_accepted:nullable(r.ech_accepted),resumed:nullable(r.resumed),expected_match:nullable(r.expected_match),controls:Object.fromEntries(CONTROL_FIELDS.map(k=>[k,r.settings[k]])),retry,summary_evidence_ids:refs};
  });
  const evidence={artifact_kind:'cse4402-public-evidence-summary',schema_version:1,batch_id:source.batch_id,scope:SUMMARY_SCOPE,entries};
  const evidenceText=json(evidence);
  const data={artifact_kind:KIND,schema_version:1,batch_id:source.batch_id,prepared_utc:new Date().toISOString(),provenance:{original_comparison_sha256:comparisonHash,original_private_audit_sha256:hash(auditBytes),original_exported_utc:source.exported_utc,private_audit_recorded_utc:audit.audited_utc,private_audit_observed_records:audit.observed_records,private_audit_observed_checks_passed:audit.observed_checks_passed,private_audit_planned_coverage_complete:audit.planned_coverage_complete},verification_scope:VERIFY_SCOPE,browsers,cases,results,coverage:coverage(results,browsers,cases),evidence_file:'evidence-summary.json',evidence_sha256:hash(evidenceText)};
  verifyData(data,evidence);
  return {data,evidenceText};
}
function renderHTML(data){
  // Reuses the private export's matrix/filter/download interaction pattern, with
  // a public schema and no dependency on its private source paths or renderer.
  const script=String.raw`
const data=JSON.parse(document.getElementById('study-data').textContent);
const fields=JSON.parse(document.getElementById('csv-fields').textContent);
const get=id=>document.getElementById(id);
const make=(tag,value)=>{const e=document.createElement(tag);if(value!==undefined)e.textContent=String(value??'');return e;};
const labels={connected:'Connected',rejected_protocol:'Protocol rejected',ech_accepted:'ECH accepted',connected_no_ech:'No ECH',ech_recovered:'ECH recovered'};
const head=make('tr');head.append(make('th','Browser build'));for(const c of data.cases){const th=make('th',c.id);th.title=c.name;head.append(th);}get('matrix').tHead.append(head);
for(const b of data.browsers){const tr=make('tr');const th=make('th',b.product+' '+b.version);th.scope='row';tr.append(th);for(const c of data.cases){const rows=data.results.filter(r=>r.browser_id===b.id&&r.case_id===c.id);const td=make('td',labels[rows[0]?.outcome]||'Not measured');td.append(make('small',rows.length+' / 3'));tr.append(td);}get('matrix').tBodies[0].append(tr);}
for(const b of data.browsers)get('browser-filter').append(new Option(b.product+' '+b.version,b.id));
for(const c of data.cases)get('case-filter').append(new Option(c.id+' — '+c.name,c.id));
for(const outcome of Object.keys(data.coverage.outcomes))get('outcome-filter').append(new Option(labels[outcome],outcome));
function selected(){return data.results.filter(r=>(!get('browser-filter').value||r.browser_id===get('browser-filter').value)&&(!get('case-filter').value||r.case_id===get('case-filter').value)&&(!get('outcome-filter').value||r.outcome===get('outcome-filter').value));}
function render(){const rows=selected(),body=get('records').tBodies[0];body.replaceChildren();get('filtered-count').textContent=rows.length+' of '+data.results.length+' observations';for(const r of rows){const tr=make('tr'),first=make('td'),button=make('button',r.run_id);button.onclick=()=>{get('record-json').textContent=JSON.stringify(r,null,2);get('record-detail').open=true;};first.append(button);tr.append(first,make('td',r.browser_product+' '+r.browser_version),make('td',r.case_id+' / '+r.repetition),make('td',labels[r.outcome]),make('td',r.tls_version||'Not negotiated'),make('td',r.cipher_suite||'Not negotiated'),make('td',r.ech_accepted===null?'Not negotiated':String(r.ech_accepted)),make('td',r.client_ip));body.append(tr);}}
for(const id of ['browser-filter','case-filter','outcome-filter'])get(id).onchange=render;
function download(name,type,content){const url=URL.createObjectURL(new Blob([content],{type})),a=make('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function csv(value){let s=value!==null&&typeof value==='object'?JSON.stringify(value):String(value??'');if(/^\s*[=+@-]/.test(s))s="'"+s;return '"'+s.replaceAll('"','""')+'"';}
get('download-json').onclick=()=>download('comparison-data.json','application/json',JSON.stringify(data,null,2)+'\n');
get('download-jsonl').onclick=()=>download('selected-results.jsonl','application/x-ndjson',selected().map(r=>JSON.stringify(r)).join('\n')+'\n');
get('download-csv').onclick=()=>download('selected-results.csv','text/csv',[fields.map(csv).join(','),...selected().map(r=>fields.map(k=>csv(r[k])).join(','))].join('\r\n')+'\r\n');
render();`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'"><title>Browser TLS and ECH — public comparison</title><style>
:root{font:15px/1.5 system-ui,Segoe UI,sans-serif;color:#18374c;background:#f4f7f9}*{box-sizing:border-box}body{margin:0}main{max-width:1600px;margin:auto;padding:30px}h1{font-size:34px;line-height:1.2}h2{font-size:22px}.muted,small{color:#506777}small{display:block;margin-top:5px}.notice{padding:18px;background:#e8f2f5;border-left:4px solid #197588}.panel{margin:24px 0;padding:22px;background:white;border:1px solid #d5e0e7;border-radius:10px}.metrics{display:flex;gap:18px;flex-wrap:wrap}.metrics strong{font-size:27px}.scroll{overflow:auto}table{border-collapse:collapse;text-align:left;width:100%;font-size:12px}th,td{padding:12px;border-bottom:1px solid #dce5ea;vertical-align:top}th{background:#edf3f6}#matrix{min-width:1450px}#matrix td{min-width:100px}#records{min-width:1300px}button,select{font:inherit;padding:8px;border:1px solid #a9bfcd;border-radius:5px;color:inherit;background:white}button{cursor:pointer;overflow-wrap:anywhere}button:hover{background:#edf4f7}label{display:flex;flex-direction:column;gap:4px;font-size:13px}.toolbar,.downloads{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}:focus-visible{outline:3px solid #ad7521;outline-offset:2px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7f9;padding:15px;font-size:12px}summary{cursor:pointer}footer{font-size:12px;color:#506777;overflow-wrap:anywhere}@media(max-width:700px){main{padding:16px}.panel{padding:15px}h1{font-size:28px}}
</style></head><body><main><p class="muted">CSE 4402 · Sanitized recorded study</p><h1>Browser TLS and ECH comparison</h1><p>Batch <strong>${escapeHTML(data.batch_id)}</strong> · Seven pinned Windows browser builds · Three repetitions per case</p>
<div class="metrics"><p><strong>252 / 252</strong><br>recorded observations</p><p><strong>7 × 12 × 3</strong><br>builds × cases × repetitions</p><p><strong>42</strong><br>obsolete-TLS rejections</p><p><strong>147</strong><br>modern version/suite connections</p><p><strong>21 each</strong><br>valid ECH, baseline, stale recovery</p></div>
<p class="notice"><strong>Public summary, not raw audit evidence.</strong> ${VERIFY_SCOPE} All summary IDs resolve in the included evidence-summary.json. Raw logs, private paths, profiles, launch arguments, and cryptographic fixture material are excluded.</p>
<p class="muted">These are explicitly configured DoH/ECH measurements on one Windows host with normal certificate validation. They do not establish untouched consumer defaults or rank overall browser security. The observed client IP is local loopback 127.0.0.1. Edge's underlying Chromium patch version is unknown. Exact ECH retry counts are not claimed.</p>
<section class="panel"><h2>All builds and cases</h2><div class="scroll" tabindex="0" role="region" aria-label="Browser comparison matrix"><table id="matrix"><thead></thead><tbody></tbody></table></div></section>
<section class="panel"><h2>Recorded observations</h2><div class="toolbar"><label>Browser<select id="browser-filter"><option value="">All builds</option></select></label><label>Case<select id="case-filter"><option value="">All cases</option></select></label><label>Outcome<select id="outcome-filter"><option value="">All outcomes</option></select></label></div><p id="filtered-count" aria-live="polite"></p><div class="downloads"><button id="download-json">Download complete JSON</button><button id="download-jsonl">Download filtered JSONL</button><button id="download-csv">Download filtered CSV</button></div><div class="scroll" tabindex="0" role="region" aria-label="Individual observations"><table id="records"><thead><tr><th>Run / details</th><th>Browser</th><th>Case / repeat</th><th>Outcome</th><th>TLS</th><th>Cipher suite</th><th>ECH accepted</th><th>Client IP</th></tr></thead><tbody></tbody></table></div><details id="record-detail"><summary>Selected record and included summary IDs</summary><pre id="record-json">Select a run to inspect its sanitized record.</pre></details></section>
<footer>Prepared ${escapeHTML(data.prepared_utc)}. This file embeds its data and runs offline without services or certificate trust. Full public evidence summaries and the portable verification command are in the adjacent files. Original comparison SHA-256: ${data.provenance.original_comparison_sha256}. Original private audit SHA-256: ${data.provenance.original_private_audit_sha256}.</footer><noscript>Enable JavaScript for filtering. The adjacent JSON, CSV and JSONL files contain all records.</noscript></main><script id="study-data" type="application/json">${safeJSON(data)}</script><script id="csv-fields" type="application/json">${safeJSON(CSV_FIELDS)}</script><script>${script}</script></body></html>\n`;
}
function readme(data){return `# Public browser TLS/ECH results

This portable derivative preserves all **252 genuine recorded observations** from batch ${data.batch_id}: seven pinned builds, twelve cases, three repetitions. It creates no new measurements. Open comparison.html directly; it embeds its data and makes no network requests.

From the repository root, verify the included package with Node.js (built-in modules only):

\`\`\`powershell
node scripts/verify-public-results.cjs ./results
\`\`\`

If this directory has a different location, pass that directory instead. The verifier does not require browsers, private files, lab services, a certificate store, or network access.

## Files and schema

- comparison-data.json: public schema version 1; artifact_kind ${KIND}. The browsers array retains product/version, distribution, engine family/version (Edge Chromium patch is null), and pinned executable SHA-256. Cases retain IDs, meanings and expected TLS/suite/ECH values, without endpoint addresses.
- results.jsonl and results.csv: the same 252 allowlisted records, in the same order. CSV objects/arrays are JSON inside quoted cells; null is an empty CSV cell. JSON is authoritative for types. Spreadsheet formula prefixes are escaped.
- evidence-summary.json: selected normalized server observations plus one private-audit assertion per run. These are summaries, not raw server or network logs. Each summary_evidence_ids entry resolves to a summary- ID in this file. They are deliberately different from omitted raw-file/line references. Name roles and protocol-error categories are reduced descriptions; configuration 16-to-17 recovery is explicitly attributed to the private raw-audit assertion.
- comparison.html: offline matrix, filters, individual record details and JSON/CSV/JSONL downloads. The HTML contains the same public dataset; filtered downloads are subsets and are not complete verifier inputs.
- manifest.json: SHA-256 of the six companion files, for detecting accidental changes. It is not a signature or proof of authenticity.

Records retain run/build/case/repetition identity, pinned binary hash, timestamps, observed loopback IP, browser and server outcomes, negotiated TLS/suite/ECH state, resumption state, explicit controls, retry summary and included evidence-summary references. Rejected pre-HTTP runs have null negotiated fields: no successful negotiated session is invented. Their selected failed-handshake observations report no resumption. Every successful recorded handshake reports resumed=false. E3 has initial configuration 16, accepted configuration 17, and a null exact retry count; parallel connections are not counted as retries.

## What verification means

${VERIFY_SCOPE}

The verifier checks an exact field allowlist, no filesystem paths/endpoints/key material in the structured public data, 252 unique planned slots, per-build versions/hashes, expected negotiation/outcomes, timestamps, included summary IDs, complete summary use, and agreement of JSON/JSONL/CSV/HTML. It checks artifact hashes. A passing result does not reproduce ClientHello parsing, certificate validation, browser execution, policy restoration, or raw audit findings, and does not independently authenticate a publisher who can edit all files together.

The preparation script required a completed private audit that named the exact source comparison hash, then copied only allowed fields. Original source SHA-256 values are immutable identifiers for this export; checking the omitted originals requires access to the private archive:

- Original comparison: ${data.provenance.original_comparison_sha256}
- Full original private raw-audit artifact: ${data.provenance.original_private_audit_sha256}
- Recorded private-audit time: ${data.provenance.private_audit_recorded_utc}

The original observations and private audit are retained separately. This public package excludes absolute/relative machine paths, raw server logs and network diagnostics, user-agent strings, launch arguments, profiles, private CA/certificate/key material, fixture hosts/ports, and registry details. It retains only 127.0.0.1 as the intentionally documented client IP. Source hashes, binary hashes and public summary IDs are identifiers, not private-file download links.

The findings apply to explicitly configured DoH/ECH, normal trust validation, fresh profiles, headless operation and one Windows host. They do not establish untouched consumer defaults, a security ranking, a population reliability rate, publication, submission, or a grade.
`;}
function assertTargets(out){
  for(let at=out;;at=path.dirname(at)){if(fs.existsSync(at))need(!fs.lstatSync(at).isSymbolicLink(),'Refusing a redirected output directory');if(path.dirname(at)===at)break;}
  if(fs.existsSync(out)){
    need(fs.statSync(out).isDirectory(),'Output is not a directory');
    const names=fs.readdirSync(out);need(names.every(n=>[...FILES,'manifest.json'].includes(n)),'Preserving unrecognized files in output directory');
    if(names.length){need(names.includes('manifest.json'),'Preserving output without a recognized manifest');const m=JSON.parse(fs.readFileSync(path.join(out,'manifest.json'),'utf8'));need(m.artifact_kind==='cse4402-public-results-manifest','Preserving unrelated output');}
    for(const n of names)need(fs.lstatSync(path.join(out,n)).isFile()&&!fs.lstatSync(path.join(out,n)).isSymbolicLink(),'Preserving redirected/non-file output');
  }
}
function main(args=process.argv.slice(2)){
  const options=parseArgs(args);
  if(options.help){console.log('Usage: node scripts/prepare-public-results.cjs [--input original-comparison.json] [--audit private-audit.json] [--out public-directory]');return;}
  const sourceBytes=fs.readFileSync(options.input),auditBytes=fs.readFileSync(options.audit);
  const {data,evidenceText}=prepareData(JSON.parse(sourceBytes),JSON.parse(auditBytes),sourceBytes,auditBytes);
  const serialized=serializeResults(data.results);
  const contents={'README.md':readme(data),'comparison-data.json':json(data),'comparison.html':renderHTML(data),'evidence-summary.json':evidenceText,'results.csv':serialized.csv,'results.jsonl':serialized.jsonl};
  contents['manifest.json']=json({artifact_kind:'cse4402-public-results-manifest',schema_version:1,files:FILES.map(file=>({file,sha256:hash(contents[file])}))});
  need(![options.input,options.audit].some(file=>path.dirname(file)===options.out),'Output must not overwrite private source locations');
  assertTargets(options.out);fs.mkdirSync(options.out,{recursive:true});
  for(const [file,body] of Object.entries(contents))fs.writeFileSync(path.join(options.out,file),body,'utf8');
  const result=verifyDirectory(options.out);
  console.log(JSON.stringify({output:options.out,...result},null,2));
}
module.exports={prepareData,renderHTML,readme,parseArgs};
if(require.main===module){try{main();}catch(error){console.error('Public results preparation failed: '+error.message);process.exitCode=1;}}
