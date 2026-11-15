'use strict';

const byId = id => document.getElementById(id);
const state = { cases: [], browsers: [], allResults: [], results: [], summary: null, running: false };
const outcomeNames = {
  connected: 'Connected', accepted: 'Accepted', rejected: 'Rejected', unsupported: 'Unsupported',
  inconclusive: 'Inconclusive', timeout: 'Timeout', failed: 'Failed', error: 'Error',
  expected_rejection: 'Expected rejection', unexpected_rejection: 'Unexpected rejection',
  expected_match: 'Matches fixture', expected_mismatch: 'Fixture mismatch',
  negotiated_expected: 'Expected negotiation', negotiated_unexpected: 'Unexpected negotiation',
  ech_accepted: 'ECH accepted', connected_no_ech: 'No-ECH baseline',
  connected_without_ech: 'Connected; ECH off', ech_recovered: 'ECH recovered',
  ech_accepted_retry_unverified: 'ECH on; retry unverified', unexpected_ech_acceptance: 'Unexpected ECH',
  fixture_mismatch: 'Fixture mismatch', protocol_rejected: 'Protocol rejected',
  cipher_rejected: 'Cipher rejected', certificate_error: 'Certificate error',
  handshake_only: 'Handshake only'
};

function text(value, fallback = 'Not recorded') {
  return value === undefined || value === null || value === '' ? fallback : String(value);
}

function element(tag, value, className) {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = text(value, '');
  if (className) node.className = className;
  return node;
}

function titleFor(outcome) {
  return outcomeNames[outcome] || text(outcome, 'Not classified').replaceAll('_', ' ');
}

function toneFor(outcome) {
  if (/inconclusive|timeout|error|unknown|unverified|mismatch|unexpected|failed|handshake_only/i.test(outcome || '')) return 'inconclusive';
  if (/reject|unsupported/i.test(outcome || '')) return 'rejected';
  if (/connect|accept|recovered|expected|success|pass/i.test(outcome || '')) return 'connected';
  return 'neutral';
}

function showError(message) {
  byId('page-error').textContent = message;
  byId('page-error').hidden = !message;
}

async function api(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(path, { cache: 'no-store', ...options, signal: controller.signal });
    const body = await response.text();
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}: ${body.slice(0, 600)}`);
    return body ? JSON.parse(body) : null;
  } finally { clearTimeout(timer); }
}

function post(path, body) {
  return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

function queryForBatch() {
  const batch = byId('batch-filter').value;
  return batch ? '?batch_id=' + encodeURIComponent(batch) : '';
}

function updateExports() {
  const batch = byId('batch-filter').value;
  const suffix = batch ? '&batch_id=' + encodeURIComponent(batch) : '';
  byId('jsonl-export').href = '/api/export?format=jsonl' + suffix;
  byId('csv-export').href = '/api/export?format=csv' + suffix;
}

function describeCase() {
  const item = state.cases.find(row => row.id === byId('case-select').value);
  if (!item) return;
  const details = [item.name, item.expected_tls, item.expected_cipher].filter(Boolean);
  if (typeof item.expected_ech === 'boolean') details.push('Expected ECH: ' + (item.expected_ech ? 'accepted' : 'not accepted'));
  byId('case-description').textContent = details.join(' · ');
}

function renderResult(record) {
  byId('run-result').hidden = false;
  byId('result-heading').textContent = `${record.case_id || 'Case'} · ${text(record.browser_product, 'Browser')} ${text(record.browser_version, '')}`;
  const badge = byId('result-outcome');
  badge.textContent = titleFor(record.outcome);
  badge.className = 'badge ' + toneFor(record.outcome);
  const fields = [
    ['Run ID', record.run_id, true], ['Repetition', record.repetition], ['Client IP', record.client_ip],
    ['TLS version', record.tls_version], ['ECH accepted', typeof record.ech_accepted === 'boolean' ? (record.ech_accepted ? 'Yes' : 'No') : null],
    ['Fixture expectation', typeof record.expected_match === 'boolean' ? (record.expected_match ? 'Matched' : 'Not matched') : null],
    ['Browser observation', record.browser_outcome], ['Cipher suite', record.cipher_suite, true],
    ['Retry evidence', record.retry_evidence, true], ['Batch', record.batch_id], ['Correlation', record.correlation]
  ];
  const list = byId('result-fields');
  list.replaceChildren();
  for (const [label, value, wide] of fields) {
    const entry = element('div', undefined, wide ? 'wide' : '');
    entry.append(element('dt', label), element('dd', typeof value === 'object' && value !== null ? JSON.stringify(value) : text(value)));
    list.append(entry);
  }
  const comments = [record.reason, record.browser_error].filter(Boolean);
  byId('result-observation').textContent = comments.join(' ');
  byId('result-json').textContent = JSON.stringify(record, null, 2);
}

function renderComparison() {
  const summary = state.summary || { browsers: [], cases: state.cases, cells: [], registered: 0, completed: 0 };
  const cases = summary.cases && summary.cases.length ? summary.cases : state.cases;
  const browsers = new Map(state.browsers.map(browser => [browser.id, {
    browser_id: browser.id, product: browser.product, version: browser.version, distribution: browser.distribution
  }]));
  for (const browser of summary.browsers || []) browsers.set(browser.browser_id, browser);
  const cells = new Map((summary.cells || []).map(cell => [`${cell.browser_id}/${cell.case_id}`, cell]));
  const table = byId('comparison-table');
  const header = element('tr');
  const browserHeading = element('th', 'Browser / exact build');
  browserHeading.scope = 'col';
  header.append(browserHeading);
  for (const item of cases) {
    const th = element('th', item.id);
    th.scope = 'col';
    th.title = `${item.name} · ${text(item.expected_tls, '')}`;
    const shortNames = { V1: 'TLS 1.0', V2: 'TLS 1.1', V3: 'TLS 1.2', V4: 'TLS 1.3', C1: '1.2 AES-128', C2: '1.2 ChaCha', C3: '1.3 AES-128', C4: '1.3 AES-256', C5: '1.3 ChaCha', E1: 'Valid ECH', E2: 'No ECH', E3: 'Stale ECH' };
    th.append(element('span', shortNames[item.id] || item.family, 'browser-version'));
    header.append(th);
  }
  table.tHead.replaceChildren(header);
  const body = table.tBodies[0];
  body.replaceChildren();
  for (const browser of browsers.values()) {
    const row = element('tr');
    const label = element('th', text(browser.product, browser.browser_id));
    label.scope = 'row';
    label.title = text(browser.distribution, '');
    label.append(element('span', browser.version, 'browser-version'));
    row.append(label);
    for (const item of cases) {
      const td = element('td');
      const cell = cells.get(`${browser.browser_id}/${item.id}`);
      if (!cell || !cell.registered) {
        td.append(element('span', 'Not measured', 'badge missing'), element('span', '0 / 3 recorded', 'cell-count'));
      } else {
        const outcomes = element('div', undefined, 'cell-outcomes');
        for (const [outcome, count] of Object.entries(cell.counts || {}).sort((a, b) => a[0].localeCompare(b[0]))) {
          outcomes.append(element('span', `${count} ${titleFor(outcome)}`, 'badge ' + toneFor(outcome)));
        }
        if (cell.pending) outcomes.append(element('span', `${cell.pending} pending`, 'badge inconclusive'));
        td.append(outcomes, element('span', `${cell.completed || 0} / ${cell.expected_repetitions || 3} recorded`, 'cell-count'));
        td.title = (cell.run_ids || []).join('\n');
      }
      row.append(td);
    }
    body.append(row);
  }
  byId('comparison-count').textContent = `${summary.completed || 0} completed · ${Math.max(0, (summary.registered || 0) - (summary.completed || 0))} pending · ${browsers.size} builds shown`;
}

function renderHistory() {
  const body = byId('history-table').tBodies[0];
  body.replaceChildren();
  if (!state.results.length) {
    const row = element('tr');
    const empty = element('td', 'No completed attempts in this selection.', 'empty-cell');
    empty.colSpan = 6;
    row.append(empty);
    body.append(row);
    return;
  }
  for (const record of [...state.results].reverse()) {
    const row = element('tr');
    const runCell = element('td');
    const runButton = element('button', record.run_id, 'run-id secondary');
    runButton.type = 'button';
    runButton.title = 'Show this complete saved record';
    runButton.addEventListener('click', () => {
      renderResult(record);
      byId('run-result').scrollIntoView({ block: 'nearest', behavior: 'auto' });
    });
    runCell.append(runButton, element('span', record.completed_utc || record.started_utc, 'history-detail'));
    const browserCell = element('td', `${text(record.browser_product)} ${text(record.browser_version, '')}`);
    browserCell.append(element('span', record.distribution, 'history-detail'));
    const caseCell = element('td', `${text(record.case_id)} / ${text(record.repetition)}`);
    caseCell.append(element('span', record.batch_id, 'history-detail'));
    const outcomeCell = element('td');
    outcomeCell.append(element('span', titleFor(record.outcome), 'badge ' + toneFor(record.outcome)));
    outcomeCell.append(element('span', record.reason || record.browser_error, 'history-detail'));
    const tlsCell = element('td', text(record.tls_version));
    tlsCell.append(element('span', record.cipher_suite, 'history-detail'));
    tlsCell.append(element('span', typeof record.ech_accepted === 'boolean' ? `ECH accepted: ${record.ech_accepted ? 'yes' : 'no'}` : 'ECH: not established', 'history-detail'));
    row.append(runCell, browserCell, caseCell, outcomeCell, tlsCell, element('td', text(record.client_ip)));
    body.append(row);
  }
}

async function refreshResults() {
  const currentBatch = byId('batch-filter').value;
  const [allResults, results, summary] = await Promise.all([
    api('/api/results'), api('/api/results' + queryForBatch()), api('/api/summary' + queryForBatch())
  ]);
  state.allResults = Array.isArray(allResults) ? allResults : [];
  state.results = Array.isArray(results) ? results : [];
  state.summary = summary;
  const batches = [...new Set(state.allResults.map(row => row.batch_id).filter(Boolean))].sort();
  if (currentBatch && !batches.includes(currentBatch)) batches.push(currentBatch);
  const select = byId('batch-filter');
  select.replaceChildren(new Option('All batches', ''));
  for (const batch of batches) select.append(new Option(batch, batch));
  select.value = currentBatch;
  updateExports();
  renderComparison();
  renderHistory();
}

async function initialize() {
  const [cases, manifest] = await Promise.all([api('/api/cases'), api('/api/browsers')]);
  if (!Array.isArray(cases) || !cases.length) throw new Error('The server returned no measurement cases.');
  state.cases = cases;
  state.browsers = Array.isArray(manifest) ? manifest : (manifest.browsers || []);
  const select = byId('case-select');
  select.replaceChildren();
  for (const item of cases) select.append(new Option(`${item.id} — ${item.name}`, item.id));
  select.value = cases.find(item => item.id === 'E2') ? 'E2' : cases[0].id;
  select.disabled = false;
  byId('run-button').disabled = false;
  byId('service-status').textContent = 'Local control service ready';
  byId('service-status').className = 'service-status ready';
  describeCase();
  await refreshResults();
  return true;
}

// Browser automation calls this function after page load. Its return value is
// the server's completed record, not a client-generated support classification.
window.labRun = async function labRun(config = {}) {
  let registration = null;
  let completed = null;
  let claimedRunning = false;
  let runId = config.run_id || (crypto.randomUUID ? crypto.randomUUID() : `manual-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  try {
    await window.labReady;
    if (state.running) throw new Error('A measurement is already active in this page.');
    state.running = true;
    claimedRunning = true;
    window.__LAB_DONE = null;
    window.__LAB_ERROR = null;
    showError('');
    byId('run-button').disabled = true;
    const caseId = config.case_id || byId('case-select').value;
    const item = state.cases.find(entry => entry.id === caseId);
    if (!item) throw new Error(`Unknown case: ${caseId}`);
    const browser = config.browser || state.browsers.find(entry => entry.id === config.browser_id) || {};
    const run = {
      run_id: runId,
      browser_id: config.browser_id || browser.id || 'manual-browser',
      browser_product: config.browser_product || browser.product || 'Manual browser',
      browser_version: config.browser_version || browser.version || 'unverified (see user agent)',
      distribution: config.distribution || browser.distribution || 'Manual current-session observation',
      os: config.os || navigator.platform || 'unverified',
      settings: config.settings || { execution: 'manual_current_session', fresh_profile: 'unverified', tls_dns_settings: 'unverified' },
      case_id: caseId,
      repetition: Number(config.repetition || byId('repetition').value || 1),
      batch_id: config.batch_id || byId('batch-id').value.trim() || 'manual',
      user_agent: navigator.userAgent
    };
    byId('case-select').value = caseId;
    byId('repetition').value = run.repetition;
    byId('batch-id').value = run.batch_id;
    describeCase();
    const progress = byId('run-progress');
    progress.hidden = false;
    progress.textContent = `Registering ${caseId} before the browser connection…`;
    if (config.registration_deadline_utc) {
      const deadline = Date.parse(config.registration_deadline_utc);
      if (!Number.isFinite(deadline)) throw new Error('Invalid registration deadline.');
      if (Date.now() >= deadline) {
        progress.textContent = 'Paused before registration. Resume with a fresh policy lease.';
        window.__LAB_DONE = { status: 'paused_before_registration', run_id: runId };
        return window.__LAB_DONE;
      }
    }
    registration = await post('/api/runs', run);
    progress.textContent = `Measuring ${caseId} from this browser. The endpoint has a 12-second limit…`;
    const target = new URL(`https://${item.host}:${item.port}/probe`);
    target.searchParams.set('run', runId);
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, 12000);
    const observed = { browser_outcome: 'failed', observations: { target: target.href, browser_request_started_utc: new Date().toISOString() } };
    try {
      const response = await fetch(target.href, { cache: 'no-store', credentials: 'omit', mode: 'cors', redirect: 'error', signal: controller.signal });
      observed.observations.http_status = response.status;
      if (!response.ok) throw new Error(`Endpoint HTTP status ${response.status}`);
      observed.observations.endpoint_response = await response.json();
      observed.browser_outcome = 'connected';
    } catch (error) {
      observed.browser_outcome = timedOut ? 'timeout' : 'failed';
      observed.browser_error = `${error.name || 'Error'}: ${error.message || error}`;
    } finally { clearTimeout(timer); }
    observed.observations.browser_request_finished_utc = new Date().toISOString();
    progress.textContent = 'Saving the attempt and correlating server evidence…';
    try {
      completed = await post('/api/runs/' + encodeURIComponent(runId) + '/complete', observed);
    } catch (completionError) {
      // A response can be lost after persistence. Read back before reporting an
      // unsaved result; do not silently retry or register another attempt.
      const recovered = await api('/api/runs/' + encodeURIComponent(runId)).catch(() => null);
      if (recovered && recovered.status === 'completed') completed = recovered;
      else throw completionError;
    }
    renderResult(completed);
    progress.textContent = 'Saved. Outcome and negotiated parameters below come from the server record.';
    window.__LAB_DONE = completed;
    try { await refreshResults(); }
    catch (error) { showError(`The run was saved, but the comparison could not refresh: ${error.message}`); }
    return completed;
  } catch (error) {
    if (registration && !completed) {
      // Keep the single outstanding registration recoverable even if a page
      // error occurs outside the fetch block.
      try {
        completed = await post('/api/runs/' + encodeURIComponent(runId) + '/complete', {
          browser_outcome: 'error', browser_error: `Control-page error: ${error.message}`,
          observations: { client_error: true }
        });
        renderResult(completed);
      } catch (_) { /* Preserve the original failure and expose the run ID. */ }
    }
    window.__LAB_ERROR = error.message;
    window.__LAB_DONE = completed || { status: 'client_error', run_id: runId, runner_error: error.message };
    showError(`Measurement could not finish cleanly: ${error.message}. Run ID: ${runId}`);
    throw error;
  } finally {
    if (claimedRunning) {
      state.running = false;
      byId('run-button').disabled = false;
    }
  }
};

byId('case-select').addEventListener('change', describeCase);
byId('run-form').addEventListener('submit', event => {
  event.preventDefault();
  window.labRun().catch(() => {});
});
byId('refresh-button').addEventListener('click', () => refreshResults().catch(error => showError(error.message)));
byId('batch-filter').addEventListener('change', () => refreshResults().catch(error => showError(error.message)));
window.labReady = initialize();
window.labReady.catch(error => {
  byId('service-status').textContent = 'Control service unavailable';
  showError(`Cannot initialize the lab: ${error.message}`);
});
