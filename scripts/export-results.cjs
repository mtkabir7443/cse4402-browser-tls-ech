#!/usr/bin/env node
'use strict';

// Fetch the local authenticated API and produce a self-contained review artifact.
// Acquisition/measurement and conclusions are deliberately separate operations.
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const crypto = require('node:crypto');

const projectRoot = path.resolve(__dirname, '..');
const requiredCases = ['V1', 'V2', 'V3', 'V4', 'C1', 'C2', 'C3', 'C4', 'C5', 'E1', 'E2', 'E3'];
const csvFields = ['run_id','batch_id','browser_id','browser_product','browser_version','distribution','os','case_id','repetition','client_ip','started_utc','completed_utc','outcome','browser_outcome','tls_version','cipher_suite','ech_accepted','expected_match','reason','retry_evidence','browser_error','certificate_sha256','evidence'];

function parseArgs(args) {
  const options = { batch: '', output: path.join(projectRoot, 'output', 'comparison.html'), allowIncomplete: false };
  for (let i = 0; i < args.length; i++) {
    if (['--batch-id', '--batch'].includes(args[i]) && args[i + 1]) options.batch = args[++i];
    else if (args[i] === '--out' && args[i + 1]) options.output = path.resolve(args[++i]);
    else if (args[i] === '--allow-incomplete') options.allowIncomplete = true;
    else throw new Error(`Unknown or incomplete argument: ${args[i]}`);
  }
  if (!options.batch || options.batch.length > 100) throw new Error('Use --batch-id <recorded batch ID> (maximum 100 characters).');
  if (path.extname(options.output).toLowerCase() !== '.html') throw new Error('--out must name an .html file; data companions use the same stem.');
  return options;
}

function artifactPaths(htmlPath) {
  const html = path.resolve(htmlPath), directory = path.dirname(html), stem = path.basename(html, path.extname(html));
  const canonical = html.toLowerCase() === path.join(projectRoot, 'output', 'comparison.html').toLowerCase();
  const resultStem = canonical ? 'results' : stem + '-results';
  return { html, data: path.join(directory, stem + '-data.json'), jsonl: path.join(directory, resultStem + '.jsonl'), csv: path.join(directory, resultStem + '.csv') };
}

function serializeResults(results) {
  const cell = value => {
    let text = value !== null && typeof value === 'object' ? JSON.stringify(value) : String(value ?? '');
    if (/^\s*[=+@-]/.test(text)) text = "'" + text;
    return '"' + text.replaceAll('"', '""') + '"';
  };
  return {
    jsonl: results.map(row => JSON.stringify(row)).join('\n') + (results.length ? '\n' : ''),
    csv: [csvFields.map(cell).join(','), ...results.map(row => csvFields.map(key => cell(row[key])).join(','))].join('\r\n') + '\r\n'
  };
}

function assertArtifactTargets(files) {
  for (const file of Object.values(files)) {
    for (let cursor = file; ; cursor = path.dirname(cursor)) {
      if (fs.existsSync(cursor) && fs.lstatSync(cursor).isSymbolicLink()) throw new Error('Refusing a redirected export path: ' + cursor);
      if (path.dirname(cursor) === cursor) break;
    }
    if (fs.existsSync(file) && !fs.statSync(file).isFile()) throw new Error('Export target is not a regular file: ' + file);
  }
  let previous = null;
  if (fs.existsSync(files.data)) {
    try { previous = JSON.parse(fs.readFileSync(files.data, 'utf8')); } catch { throw new Error('Preserving unrecognized existing data file: ' + files.data); }
    if (previous.artifact_kind !== 'cse4402-browser-comparison' || previous.generator !== 'scripts/export-results.cjs' || !Array.isArray(previous.results)) throw new Error('Preserving unrelated existing data file: ' + files.data);
  }
  const previousResults = previous && serializeResults(previous.results);
  for (const type of ['jsonl', 'csv']) {
    if (fs.existsSync(files[type]) && (!previousResults || fs.readFileSync(files[type], 'utf8') !== previousResults[type])) throw new Error('Preserving existing result file that does not match the prior export: ' + files[type]);
  }
  if (fs.existsSync(files.html)) {
    const html = fs.readFileSync(files.html, 'utf8');
    if (!html.includes('<title>Browser TLS / ECH comparison — ') || !html.includes('id="study-data"')) throw new Error('Preserving unrelated existing HTML: ' + files.html);
  }
}

function getJSON(route, ca) {
  return new Promise((resolve, reject) => {
    const request = https.get({ hostname: '127.0.0.1', port: 8443, path: route, ca, rejectUnauthorized: true, agent: false }, response => {
      const chunks = [];
      let length = 0;
      response.on('data', chunk => {
        length += chunk.length;
        if (length > 32 * 1024 * 1024) { request.destroy(new Error('API response exceeded 32MiB limit.')); return; }
        chunks.push(chunk);
      });
      response.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        if (response.statusCode !== 200) { reject(new Error(`GET ${route}: HTTP ${response.statusCode}: ${body.slice(0, 300)}`)); return; }
        try { resolve(JSON.parse(body)); } catch (error) { reject(new Error(`Invalid JSON for ${route}: ${error.message}`)); }
      });
      response.on('error', reject);
    });
    request.setTimeout(15000, () => request.destroy(new Error(`GET ${route} timed out.`)));
    request.on('error', reject);
  });
}

function analyzeCoverage(records, browsers, cases) {
  const expected = new Map();
  const browserMap = new Map(browsers.map(browser => [browser.id, browser]));
  const caseSet = new Set(cases.map(item => item.id));
  for (const browser of browsers) for (const item of cases) for (let repetition = 1; repetition <= 3; repetition++) {
    expected.set(`${browser.id}/${item.id}/${repetition}`, []);
  }
  const unexpected = [], versionMismatches = [], unfinished = [], runIds = new Map();
  const outcomes = {};
  for (const record of records) {
    const key = `${record.browser_id}/${record.case_id}/${record.repetition}`;
    if (expected.has(key)) expected.get(key).push(record.run_id);
    else unexpected.push({ run_id: record.run_id, key });
    const browser = browserMap.get(record.browser_id);
    if (browser && record.browser_version !== browser.version) versionMismatches.push({ run_id: record.run_id, expected: browser.version, recorded: record.browser_version });
    if (record.status !== 'completed' || !record.outcome) unfinished.push(record.run_id);
    runIds.set(record.run_id, (runIds.get(record.run_id) || 0) + 1);
    const outcome = record.outcome || 'unclassified';
    outcomes[outcome] = (outcomes[outcome] || 0) + 1;
  }
  const missing = [...expected].filter(([, ids]) => !ids.length).map(([key]) => key);
  const duplicates = [...expected].filter(([, ids]) => ids.length > 1).map(([key, ids]) => ({ key, run_ids: ids }));
  const duplicateRunIds = [...runIds].filter(([, count]) => count > 1).map(([run_id, count]) => ({ run_id, count }));
  const matrixDefinitionValid = browsers.length === 7 && browserMap.size === 7 && cases.length === 12 && caseSet.size === 12 && requiredCases.every(id => caseSet.has(id));
  const complete = matrixDefinitionValid && expected.size === 252 && records.length === 252 && !missing.length && !duplicates.length && !unexpected.length && !versionMismatches.length && !unfinished.length && !duplicateRunIds.length;
  return {
    matrix_definition_valid: matrixDefinitionValid,
    expected_records: expected.size,
    actual_records: records.length,
    required_slots_recorded: expected.size - missing.length,
    coverage_complete: complete,
    outcomes,
    missing,
    duplicates,
    duplicate_run_ids: duplicateRunIds,
    unexpected,
    version_mismatches: versionMismatches,
    unfinished,
    interpretation: 'Coverage checks whether the planned observations are recorded exactly once. Inconclusive or unsupported outcomes remain results; complete coverage does not establish that every measurement is conclusive or every browser supports every feature.'
  };
}

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function safeJSON(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

function renderReport(data) {
  const css = `:root{color-scheme:light;font-family:"Segoe UI",Arial,sans-serif;color:#17364b;background:#f4f7f9}*{box-sizing:border-box}body{margin:0;font-size:14px;line-height:1.5}main{max-width:1600px;margin:auto;padding:38px}h1{font-size:36px;line-height:1.15;letter-spacing:-.03em;margin:5px 0 16px}h2{font-size:22px;margin:0 0 15px}h3{font-size:17px}.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.13em;color:#087d8b;font-weight:700}.muted{color:#526c7b}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:26px 0}.metric{padding:18px;background:white;border:1px solid #d8e4e9;border-radius:12px}.metric strong{display:block;font-size:28px}.metric span{font-size:12px;color:#526c7b}.panel{padding:25px;background:white;border:1px solid #d8e4e9;border-radius:12px;margin:20px 0}.notice{padding:13px 16px;border:1px solid #c7dfe3;background:#eef6f7;border-radius:8px}.warning{background:#fff3df;border-color:#ead6ae;color:#865719}.toolbar{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:20px 0}label{display:flex;flex-direction:column;gap:5px;font-size:12px;font-weight:600}select,input,button{font:inherit;border:1px solid #b9ccd5;border-radius:7px;padding:9px 12px;background:white;color:#17364b}button{cursor:pointer}button:hover{background:#eef6f7}:focus-visible{outline:3px solid #b47722;outline-offset:3px}.downloads{display:flex;flex-wrap:wrap;gap:10px;margin:20px 0}.scroll{overflow:auto;border:1px solid #dae5e9;border-radius:9px}table{border-collapse:collapse;width:100%;text-align:left;font-size:12px}th{background:#edf3f6;padding:11px;white-space:nowrap;vertical-align:top}td{padding:11px;vertical-align:top;border-top:1px solid #e0e9ed}tbody th{border-top:1px solid #e0e9ed;font-size:12px;white-space:normal}#matrix{min-width:1600px}#matrix th:first-child{position:sticky;left:0;min-width:185px;z-index:1}#matrix td{min-width:110px}.small{display:block;font-size:10px;color:#526c7b;margin-top:5px;overflow-wrap:anywhere}.badge{display:block;padding:4px 7px;border-radius:5px;background:#edf3f6;font-size:10px;margin:3px 0}.good{background:#e6f4ed;color:#246649}.warn{background:#fff1d9;color:#8d5d22}.reject{background:#eee8f5;color:#71549b}#attempts{min-width:1150px}.run{max-width:240px;overflow-wrap:anywhere}.reason{max-width:320px}details{margin-top:14px}summary{cursor:pointer;font-weight:600}pre{overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;max-height:500px;padding:16px;border:1px solid #d8e4e9;background:#f6f9fa;font:11px/1.5 Consolas,monospace}footer{font-size:11px;color:#526c7b;margin-top:30px}.empty{text-align:center;padding:30px;color:#526c7b}@media(max-width:750px){main{padding:20px 12px}.summary{grid-template-columns:repeat(2,1fr)}.panel{padding:18px 12px}h1{font-size:29px}}@media print{main{padding:10px}.toolbar,.downloads{display:none}.panel{box-shadow:none}.scroll{overflow:visible}#matrix{min-width:0;font-size:7px}#matrix th:first-child{min-width:95px}#matrix td{min-width:0;padding:3px}.badge{font-size:7px;padding:2px}.panel{break-inside:avoid}}`;
  const script = String.raw`
const data=JSON.parse(document.getElementById('study-data').textContent);
const get=id=>document.getElementById(id);
const make=(tag,value,cls)=>{const n=document.createElement(tag);if(value!==undefined)n.textContent=String(value??'');if(cls)n.className=cls;return n;};
const names={connected:'Connected',ech_accepted:'ECH accepted',connected_no_ech:'No-ECH baseline',connected_without_ech:'Connected; ECH off',ech_recovered:'ECH recovered',ech_accepted_retry_unverified:'ECH on; retry unverified',unexpected_ech_acceptance:'Unexpected ECH',inconclusive:'Inconclusive',fixture_mismatch:'Fixture mismatch',protocol_rejected:'Protocol rejected',cipher_rejected:'Cipher rejected',certificate_error:'Certificate error',handshake_only:'Handshake only'};
const label=value=>names[value]||String(value||'unclassified').replaceAll('_',' ');
const tone=value=>/inconclusive|error|timeout|mismatch|unexpected|unverified|failed|handshake_only/.test(value||'')?'warn':/reject|unsupported/.test(value||'')?'reject':/connect|accept|recovered/.test(value||'')?'good':'';
const short={V1:'TLS 1.0',V2:'TLS 1.1',V3:'TLS 1.2',V4:'TLS 1.3',C1:'1.2 AES-128',C2:'1.2 ChaCha',C3:'1.3 AES-128',C4:'1.3 AES-256',C5:'1.3 ChaCha',E1:'Valid ECH',E2:'No ECH',E3:'Stale ECH'};
const matrix=get('matrix');const heading=make('tr');heading.append(make('th','Browser / version'));
for(const c of data.cases){const th=make('th',c.id);th.title=c.name;th.append(make('span',short[c.id]||c.name,'small'));heading.append(th);}matrix.tHead.append(heading);
for(const b of data.browsers){const row=make('tr');const th=make('th',b.product);th.scope='row';th.append(make('span',b.version,'small'),make('span',b.distribution,'small'));row.append(th);for(const c of data.cases){const rows=data.results.filter(r=>r.browser_id===b.id&&r.case_id===c.id);const td=make('td');const counts={};for(const r of rows)counts[r.outcome||'unclassified']=(counts[r.outcome||'unclassified']||0)+1;if(!rows.length)td.append(make('span','Not measured','badge'));for(const [outcome,n]of Object.entries(counts).sort()){td.append(make('span',n+' '+label(outcome),'badge '+tone(outcome)));}td.append(make('span',rows.length+' / 3 recorded','small'));row.append(td);}matrix.tBodies[0].append(row);}
for(const b of data.browsers)get('browser-filter').append(new Option(b.product+' '+b.version,b.id));
for(const c of data.cases)get('case-filter').append(new Option(c.id+' — '+c.name,c.id));
for(const outcome of Object.keys(data.coverage.outcomes).sort())get('outcome-filter').append(new Option(label(outcome),outcome));
function selected(){const browser=get('browser-filter').value,caseId=get('case-filter').value,outcome=get('outcome-filter').value,search=get('search').value.toLowerCase();return data.results.filter(r=>(!browser||r.browser_id===browser)&&(!caseId||r.case_id===caseId)&&(!outcome||(r.outcome||'unclassified')===outcome)&&(!search||JSON.stringify(r).toLowerCase().includes(search)));}
function render(){const body=get('attempts').tBodies[0];body.replaceChildren();const rows=selected();get('filtered-count').textContent=rows.length+' of '+data.results.length+' attempts shown';for(const r of rows){const row=make('tr');const run=make('td',undefined,'run');const button=make('button',r.run_id);button.onclick=()=>{get('record-json').textContent=JSON.stringify(r,null,2);get('record-detail').open=true;get('record-detail').scrollIntoView({block:'nearest'});};run.append(button,make('span',r.completed_utc||r.started_utc,'small'));const browser=make('td',(r.browser_product||r.browser_id)+' '+(r.browser_version||''));const c=make('td',r.case_id+' / repeat '+r.repetition);const outcome=make('td');outcome.append(make('span',label(r.outcome),'badge '+tone(r.outcome)));const negotiation=make('td',r.tls_version||'Not established');negotiation.append(make('span',r.cipher_suite||'','small'),make('span',typeof r.ech_accepted==='boolean'?'ECH accepted: '+(r.ech_accepted?'yes':'no'):'ECH: not established','small'));row.append(run,browser,c,outcome,negotiation,make('td',r.client_ip||'Not recorded'),make('td',r.reason||r.browser_error||'','reason'));body.append(row);}if(!rows.length){const tr=make('tr'),td=make('td','No attempts match these filters.','empty');td.colSpan=7;tr.append(td);body.append(tr);}}
for(const id of ['browser-filter','case-filter','outcome-filter'])get(id).onchange=render;get('search').oninput=render;
function download(name,type,content){const url=URL.createObjectURL(new Blob([content],{type}));const link=make('a');link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function csv(value){let str=typeof value==='object'&&value!==null?JSON.stringify(value):String(value??'');if(/^[\s]*[=+@-]/.test(str))str="'"+str;return '"'+str.replaceAll('"','""')+'"';}
get('download-jsonl').onclick=()=>download('browser-results-'+data.batch_id+'.jsonl','application/x-ndjson',selected().map(r=>JSON.stringify(r)).join('\n')+'\n');
get('download-csv').onclick=()=>{const fields=['run_id','batch_id','browser_id','browser_product','browser_version','distribution','os','case_id','repetition','client_ip','started_utc','completed_utc','outcome','browser_outcome','tls_version','cipher_suite','ech_accepted','expected_match','reason','retry_evidence','browser_error','certificate_sha256','evidence'];const rows=[fields.map(csv).join(',')];for(const r of selected())rows.push(fields.map(key=>csv(r[key])).join(','));download('browser-results-'+data.batch_id+'.csv','text/csv;charset=utf-8',rows.join('\r\n')+'\r\n');};
get('download-bundle').onclick=()=>download('browser-study-'+data.batch_id+'.json','application/json',JSON.stringify(data,null,2));
get('coverage-json').textContent=JSON.stringify(data.coverage,null,2);render();
`;
  const coverage = data.coverage;
  const inconclusive = Object.entries(coverage.outcomes).filter(([key]) => /inconclusive|error|unclassified|mismatch|unverified|timeout|handshake_only/.test(key)).reduce((sum, [, count]) => sum + count, 0);
  const status = coverage.coverage_complete ? 'All 252 planned observation slots are recorded exactly once.' : 'The recorded matrix is incomplete or has a coverage discrepancy. Inspect the coverage audit below.';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Browser TLS / ECH comparison — ${escapeHTML(data.batch_id)}</title><style>${css}</style></head><body><main>
<p class="eyebrow">CSE 4402 · Recorded browser comparison</p><h1>Browser TLS and ECH observations</h1><p class="muted">Mohammed Kabir · mtk21002 · Batch <strong>${escapeHTML(data.batch_id)}</strong><br>Exported ${escapeHTML(data.exported_utc)}. This standalone file opens without the lab server or certificate trust.</p>
<div class="summary"><div class="metric"><strong>${coverage.actual_records} / ${coverage.expected_records}</strong><span>recorded / planned attempts</span></div><div class="metric"><strong>${data.browsers.length}</strong><span>browser builds in manifest</span></div><div class="metric"><strong>${data.cases.length}</strong><span>controlled configurations</span></div><div class="metric"><strong>${inconclusive}</strong><span>inconclusive or review-needed outcomes</span></div></div>
<p class="notice ${coverage.coverage_complete ? '' : 'warning'}">${escapeHTML(status)} Complete recording is not a claim that every browser supports every feature or that every result is conclusive.</p>
<section class="panel"><h2>All browsers, all configurations</h2><p class="muted">Each cell shows saved server classifications across three planned repetitions. A non-ECH baseline is expected to have ECH off; legacy TLS rejection may be the intended behavior. Missing and inconclusive observations are retained.</p><div class="scroll" tabindex="0" role="region" aria-label="Browser comparison matrix"><table id="matrix"><thead></thead><tbody></tbody></table></div></section>
<section class="panel"><h2>Inspect individual attempts</h2><div class="toolbar"><label>Browser<select id="browser-filter"><option value="">All browser builds</option></select></label><label>Configuration<select id="case-filter"><option value="">All cases</option></select></label><label>Outcome<select id="outcome-filter"><option value="">All outcomes</option></select></label><label>Search evidence<input id="search" type="search" placeholder="Run ID, cipher, reason…"></label><span id="filtered-count" class="muted" aria-live="polite"></span></div>
<div class="downloads"><button id="download-jsonl">Download filtered JSONL</button><button id="download-csv">Download filtered CSV</button><button id="download-bundle">Download complete evidence bundle</button></div><div class="scroll"><table id="attempts"><thead><tr><th>Run / timestamp</th><th>Browser</th><th>Case / repeat</th><th>Server outcome</th><th>TLS / suite / ECH</th><th>Client IP</th><th>Reason</th></tr></thead><tbody></tbody></table></div><details id="record-detail"><summary>Full selected record and evidence references</summary><pre id="record-json">Select a run ID above.</pre></details></section>
<section class="panel"><h2>Coverage and interpretation</h2><p>The audit requires seven manifest builds, cases V1–V4/C1–C5/E1–E3, and repetitions 1–3. It checks missing slots, duplicate slots/run IDs, unexpected records, exact browser-version mismatches and unfinished records. It does not silently discard retries or substitute a synthetic result.</p><details><summary>Show coverage audit</summary><pre id="coverage-json"></pre></details><p class="muted">The server supplies the observed client IP and correlates TLS/ECH evidence. Browser fetch errors alone cannot establish lack of protocol support. ECH recovery observations do not by themselves decode retry extensions or establish an exact retry count. This export presents observations; conclusions belong in the written report after reviewing the evidence.</p></section>
<footer>Local study artifact. Raw client IPs and evidence are included for review; keep this file separate from a public summary. Source JSON SHA256: ${escapeHTML(data.source_payload_sha256)}.</footer>
</main><script id="study-data" type="application/json">${safeJSON(data)}</script><script>${script}</script></body></html>`;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const ca = fs.readFileSync(path.join(projectRoot, '.runtime', 'ca.pem'));
  const manifest = JSON.parse(fs.readFileSync(path.join(projectRoot, 'browsers.json'), 'utf8'));
  const query = '?batch_id=' + encodeURIComponent(options.batch);
  const [results, summary, cases] = await Promise.all([
    getJSON('/api/results' + query, ca), getJSON('/api/summary' + query, ca), getJSON('/api/cases' + query, ca)
  ]);
  if (!Array.isArray(results) || !Array.isArray(cases) || !Array.isArray(manifest.browsers)) throw new Error('Unexpected API/manifest schema.');
  if (results.some(record => record.batch_id !== options.batch)) throw new Error('API returned a record outside the requested batch.');
  const coverage = analyzeCoverage(results, manifest.browsers, cases);
  coverage.summary_matches_results = summary.completed === results.length;
  coverage.summary_registered = summary.registered;
  if (!coverage.summary_matches_results || summary.registered !== results.length) coverage.coverage_complete = false;
  const source = { batch_id: options.batch, browsers: manifest.browsers, cases, results, summary };
  const data = {
    ...source,
    artifact_kind: 'cse4402-browser-comparison',
    generator: 'scripts/export-results.cjs',
    schema_version: 1,
    exported_utc: new Date().toISOString(),
    source_payload_sha256: crypto.createHash('sha256').update(JSON.stringify(source)).digest('hex'),
    coverage,
    certificate_validation: 'Local HTTPS API verified with the explicit lab CA; certificate verification was not bypassed.'
  };
  const files = artifactPaths(options.output);
  assertArtifactTargets(files);
  const serialized = serializeResults(results);
  fs.mkdirSync(path.dirname(files.html), { recursive: true });
  fs.writeFileSync(files.html, renderReport(data), 'utf8');
  fs.writeFileSync(files.jsonl, serialized.jsonl, 'utf8');
  fs.writeFileSync(files.csv, serialized.csv, 'utf8');
  fs.writeFileSync(files.data, JSON.stringify(data, null, 2) + '\n', 'utf8');
  process.stdout.write(JSON.stringify({ output: files.html, artifacts: files, batch_id: options.batch, ...coverage }, null, 2) + '\n');
  if (!coverage.coverage_complete && !options.allowIncomplete) process.exitCode = 2;
}

module.exports = { analyzeCoverage, renderReport, parseArgs, artifactPaths, serializeResults, assertArtifactTargets };
if (require.main === module) main().catch(error => { console.error(error.message); process.exitCode = 1; });
