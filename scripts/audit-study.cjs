#!/usr/bin/env node
'use strict';

// Independent, offline audit. Never launches browsers or changes measurement data.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const ROOT = path.resolve(__dirname, '..');
const BROWSERS = ['chrome-current', 'firefox-current', 'edge-current', 'brave-current', 'opera-current', 'chrome-116', 'firefox-115'];
const CASES = [
  ['V1', 'tls10', 9440, 'TLS 1.0'], ['V2', 'tls11', 9441, 'TLS 1.1'],
  ['V3', 'tls12', 9442, 'TLS 1.2'], ['V4', 'tls13', 9443, 'TLS 1.3'],
  ['C1', 'tls12-aes128', 9445, 'TLS 1.2', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'],
  ['C2', 'tls12-chacha', 9446, 'TLS 1.2', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'],
  ['C3', 'tls13-aes128', 9451, 'TLS 1.3', 'TLS_AES_128_GCM_SHA256'],
  ['C4', 'tls13-aes256', 9452, 'TLS 1.3', 'TLS_AES_256_GCM_SHA384'],
  ['C5', 'tls13-chacha', 9453, 'TLS 1.3', 'TLS_CHACHA20_POLY1305_SHA256'],
  ['E1', 'valid', 9443, 'TLS 1.3', '', true],
  ['E2', 'baseline', 9443, 'TLS 1.3', '', false],
  ['E3', 'stale', 9443, 'TLS 1.3', '', true]
].map(([id, label, port, tls, cipher, ech]) => ({ id, host: label + '.tlslab.test', port, tls, cipher, ech, fixture: port === 9443 ? 'tls13-ech' : label }));
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const lower = value => String(value || '').toLowerCase();
const sameHash = (a, b) => /^[a-f0-9]{64}$/.test(lower(a)) && lower(a) === lower(b);
const stamp = value => Date.parse(value);
const samePath = (a, b) => typeof a === 'string' && typeof b === 'string' && lower(path.resolve(a)) === lower(path.resolve(b));
const cell = run => `${run.browser_id}/${run.case_id}/${run.repetition}`;
const stableJSON = value => JSON.stringify(value, (_, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);

function matchesRuntimeVersion(browser, runtime) {
  // Edge's CDP product is its vendor version, not a Chromium patch version.
  if (browser.id === 'edge-current') return browser.engine.family === 'chromium' && runtime?.product === `Edg/${browser.version}`;
  const observed = browser.engine.family === 'gecko' ? runtime?.browserVersion : runtime?.product?.split('/').slice(1).join('/');
  const expected = browser.engine.family === 'gecko' ? browser.version.replace(/esr$/i, '') : browser.engine.version;
  return observed === expected;
}

function auditStudy({ root = ROOT, input = path.join(root, 'output', 'comparison-data.json'), data: suppliedData } = {}) {
  const sources = [], sourceCache = new Map(), findings = [], counters = {}, perRun = [];
  const read = file => {
    const absolute = path.resolve(file);
    if (!sourceCache.has(absolute)) {
      const bytes = fs.readFileSync(absolute);
      sourceCache.set(absolute, bytes);
      sources.push({ file: path.relative(root, absolute).replaceAll('\\', '/'), bytes: bytes.length, sha256: digest(bytes) });
    }
    return sourceCache.get(absolute);
  };
  const json = file => JSON.parse(read(file).toString('utf8').replace(/^\uFEFF/, ''));
  const check = (ok, code, detail, runID) => {
    const count = counters[code] ||= { passed: 0, failed: 0 };
    count[ok ? 'passed' : 'failed']++;
    if (!ok) findings.push({ code, ...(runID ? { run_id: runID } : {}), detail });
    return Boolean(ok);
  };
  const scoped = (base, relative) => {
    const full = path.resolve(base, relative), rel = path.relative(base, full);
    if (path.isAbsolute(rel) || rel === '..' || rel.startsWith('..' + path.sep)) throw new Error('Path escapes expected directory: ' + relative);
    return full;
  };
  const data = suppliedData || json(input);
  const manifestPath = path.join(root, 'browsers.json'), manifest = json(manifestPath);
  const manifestHash = digest(read(manifestPath));
  const leafBytes = read(path.join(root, '.runtime', 'server.pem')), leafHash = digest(leafBytes);
  const leaf = new crypto.X509Certificate(leafBytes);
  const browsers = new Map(manifest.browsers.map(browser => [browser.id, browser]));
  const caseMap = new Map(CASES.map(item => [item.id, item]));
  const runs = Array.isArray(data.results) ? data.results : [];
  const expected = new Map(BROWSERS.flatMap(browser => CASES.flatMap(item => [1, 2, 3].map(rep => [`${browser}/${item.id}/${rep}`, []]))));
  check(data.artifact_kind === 'cse4402-browser-comparison' && Array.isArray(data.results), 'export_schema', 'Expected browser-comparison export with a results array.');
  check(browsers.size === 7 && BROWSERS.every(id => browsers.has(id)), 'manifest_builds', 'The seven planned browser IDs must be present exactly once.');
  check(Array.isArray(data.browsers) && stableJSON(data.browsers) === stableJSON(manifest.browsers), 'export_manifest', 'Exported browser definitions must match the current pinned manifest.');
  check(Array.isArray(data.cases) && data.cases.length === 12 && new Set(data.cases.map(c => c.id)).size === 12 && CASES.every(c => data.cases.some(d => d.id === c.id && d.host === c.host && d.port === c.port && d.expected_tls === c.tls && (d.expected_cipher || '') === (c.cipher || '') && d.expected_ech === c.ech)), 'case_definitions', 'Independent 12-case definition must agree with the export.');
  const sourcePayload = { batch_id: data.batch_id, browsers: data.browsers, cases: data.cases, results: data.results, summary: data.summary };
  check(sameHash(data.source_payload_sha256, digest(JSON.stringify(sourcePayload))), 'export_payload_hash', 'Export source payload hash must be reproducible.');
  check(typeof data.batch_id === 'string' && /^[a-zA-Z0-9_-]{1,100}$/.test(data.batch_id), 'batch_id', 'A safe, explicit batch ID is required.');
  if (!/^[a-zA-Z0-9_-]{1,100}$/.test(data.batch_id || '')) throw new Error('Unsafe batch ID.');
  const batchDir = path.join(root, 'evidence', 'matrix', data.batch_id);
  const matrix = json(path.join(batchDir, 'matrix.json'));
  const matrixRows = new Map();
  for (const row of matrix.runs || []) {
    check(!matrixRows.has(row.run_id), 'matrix_run_uniqueness', 'Duplicate run ID in matrix runner records.', row.run_id);
    matrixRows.set(row.run_id, row);
  }
  check(matrix.batch_id === data.batch_id && sameHash(matrix.manifest_sha256, manifestHash), 'matrix_manifest', 'Matrix batch and pinned manifest hash must agree.');
  check(!(matrix.artifact_or_cleanup_gaps || []).length, 'matrix_artifacts', 'Matrix reports artifact or cleanup gaps.');
  const logs = new Map();
  for (const name of ['server-events.jsonl', 'suite-events.jsonl']) {
    const lines = read(path.join(root, 'evidence', name)).toString('utf8').split(/\r?\n/);
    logs.set(name, lines.map((line, index) => {
      if (!line.trim()) return null;
      try { return { raw: JSON.parse(line), file: name, line: index + 1 }; }
      catch { throw new Error(`Malformed ${name}:${index + 1}; audit stopped.`); }
    }));
  }
  const allEvents = [...logs.values()].flat().filter(Boolean);
  const handshakes = allEvents.filter(e => e.raw.event === 'handshake');
  const httpEvents = allEvents.filter(e => e.raw.event === 'http_result');
  const byHTTPRun = new Map();
  for (const event of httpEvents) {
    const bucket = byHTTPRun.get(event.raw.run_id) || [];
    bucket.push(event); byHTTPRun.set(event.raw.run_id, bucket);
  }
  const journal = read(path.join(root, 'evidence', 'runs.jsonl')).toString('utf8').split(/\r?\n/).filter(Boolean).map(JSON.parse);
  const journalCompleted = journal.filter(entry => entry.event === 'completed' && entry.run.batch_id === data.batch_id);
  check(journalCompleted.length === runs.length, 'journal_export_count', 'Export must include every completed record in this batch.');
  check(data.summary?.completed === runs.length && data.summary?.registered === runs.length, 'summary_counts', 'All registrations in this export batch must be completed and counted.');
  const runIDs = new Set(), profiles = new Map(), windows = [], launchWindows = [], binaryHashes = new Map();
  const omitted = [], unexpected = [];
  for (const run of runs) {
    const before = findings.length, id = run.run_id, c = caseMap.get(run.case_id), b = browsers.get(run.browser_id), s = run.settings || {};
    if (expected.has(cell(run))) expected.get(cell(run)).push(id); else unexpected.push({ run_id: id, slot: cell(run) });
    check(!runIDs.has(id), 'run_id_uniqueness', 'Run IDs must be unique in the export.', id); runIDs.add(id);
    check(run.status === 'completed' && run.batch_id === data.batch_id && Boolean(c && b) && [1, 2, 3].includes(run.repetition), 'run_identity', 'Completed run must belong to a planned case/browser/repetition in this batch.', id);
    if (!c || !b || typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,160}$/.test(id)) continue;
    const start = stamp(run.started_utc), end = stamp(run.completed_utc);
    check(Number.isFinite(start) && Number.isFinite(end) && end >= start && end - start <= 120000, 'run_time_window', 'Registration/completion window must be ordered and at most two minutes.', id);
    windows.push({ run_id: id, start, end });
    check(run.browser_product === b.product && run.browser_version === b.version && run.distribution === b.distribution && run.os === 'Windows 11 build 26300', 'browser_metadata', 'Browser version/product/distribution/OS must match the pinned cohort.', id);
    check(sameHash(run.certificate_sha256, leafHash) && sameHash(s.certificate_sha256, leafHash), 'certificate_hash', 'Run and settings must use the current leaf PEM hash.', id);
    check(start >= stamp(leaf.validFrom) && end <= stamp(leaf.validTo), 'certificate_valid_at_measurement', 'The leaf certificate must be valid throughout the observation window.', id);
    check(s.runner === 'scripts/run-matrix.cjs' && s.fresh_profile === true && s.https_over_tcp === true && s.http3_disabled === true && s.normal_certificate_validation === true && s.secure_doh_requested === true && s.do_h_endpoint === 'https://127.0.0.1:8443/dns-query', 'measurement_settings', 'Expected isolated profile, TCP, strict DoH and normal certificate-validation settings are required.', id);
    check(sameHash(s.executable_sha256, b.sha256), 'registered_executable_hash', 'Registered executable hash must match the manifest.', id);
    if (!binaryHashes.has(b.id)) binaryHashes.set(b.id, digest(read(b.path)));
    check(sameHash(binaryHashes.get(b.id), b.sha256), 'current_executable_hash', 'Measured browser binary must still match the pinned manifest.', id);
    const completed = journalCompleted.filter(entry => entry.run.run_id === id);
    check(completed.length === 1 && stableJSON(completed[0].run) === stableJSON(run), 'journal_record', 'Exported record must equal its unique persisted server completion.', id);
    const row = matrixRows.get(id);
    check(Boolean(row) && row.status === 'completed' && stableJSON(row.result) === stableJSON(run), 'matrix_record', 'Matrix row must contain the same completed server result.', id);
    const runnerFile = scoped(batchDir, path.join('runs', id, 'runner.json'));
    let runner;
    try { runner = json(runnerFile); }
    catch (error) { check(false, 'runner_file', error.message, id); continue; }
    check(runner.run_id === id && runner.batch_id === data.batch_id && runner.browser_id === b.id && runner.case_id === c.id && runner.repetition === run.repetition && runner.status === 'completed' && stableJSON(runner.result) === stableJSON(run), 'runner_record', 'Saved runner record must identify the same completed measurement.', id);
    check(samePath(runner.executable, b.path) && runner.pinned_version === b.version && runner.distribution === b.distribution && sameHash(runner.executable_sha256, b.sha256) && sameHash(runner.certificate_sha256, leafHash), 'runner_provenance', 'Runner executable/version/distribution and certificate hashes must match.', id);
    check(runner.certificate_verification_bypassed === false && !runner.runtime?.acceptInsecureCerts && !(runner.arguments || []).some(a => /--ignore-certificate-errors|--allow-insecure-localhost|--no-sandbox|--disable-web-security/.test(a)) && !(runner.cleanup_notes || []).length, 'runner_safety_and_cleanup', 'No certificate/security bypass or unhandled cleanup error is allowed.', id);
    check(matchesRuntimeVersion(b, runner.runtime) && stableJSON(runner.runtime) === stableJSON(s.runtime), 'actual_runtime_version', 'Browser-reported version must match the manifest and registered runtime; Edge must report its exact pinned Edg product/version.', id);
    check(runner.user_agent === run.user_agent && run.request_user_agent === run.user_agent && /^Mozilla\/5\.0/.test(run.user_agent || '') && /Firefox\/|Chrome\//.test(run.user_agent || ''), 'actual_browser_user_agent', 'Runner, registration HTTP and navigator browser user agents must agree.', id);
    const profile = lower(path.resolve(runner.profile || '.'));
    check(samePath(runner.profile, s.profile_path) && profile === lower(path.join(root, '.runtime', 'profiles', 'matrix-' + id)) && !profiles.has(profile) && fs.existsSync(runner.profile), 'unique_profile', 'Each observation requires its own existing run-named profile, matching registration.', id);
    profiles.set(profile, id);
    const launchStart = stamp(runner.started_utc), launchEnd = stamp(runner.finished_utc);
    check(Number.isFinite(launchStart) && Number.isFinite(launchEnd) && launchStart <= start && launchEnd >= end, 'runner_encloses_measurement', 'Owned browser launch/cleanup interval must enclose the server observation.', id);
    launchWindows.push({ run_id: id, start: launchStart, end: launchEnd });
    const evidence = Array.isArray(run.evidence) ? run.evidence : [];
    check(evidence.length > 0, 'evidence_present', 'Every classification requires raw event references.', id);
    const referenced = [];
    for (const ref of evidence) {
      const event = logs.get(ref.file)?.[ref.line - 1];
      const exact = event && Number.isInteger(ref.line) && ref.line > 0 && Object.entries(ref).every(([key, value]) => ['file', 'line'].includes(key) || isDeepStrictEqual(event.raw[key], value));
      check(exact, 'raw_event_reference', `Normalized evidence must match ${ref.file}:${ref.line} exactly.`, id);
      if (event) referenced.push(event);
    }
    const inWindow = event => stamp(event.raw.timestamp) >= start && stamp(event.raw.timestamp) <= end && event.raw.client_ip === run.client_ip;
    check(referenced.every(inWindow), 'evidence_window_and_ip', 'All cited evidence must belong to the registered IP/time window.', id);
    const fixtureHS = handshakes.filter(event => inWindow(event) && event.raw.fixture === c.fixture);
    const http = (byHTTPRun.get(id) || []).filter(inWindow);
    const detail = { run_id: id, slot: cell(run), outcome: run.outcome, http_evidence: http.map(e => ({ file: e.file, line: e.line })), handshake_evidence: fixtureHS.map(e => ({ file: e.file, line: e.line, connection_id: e.raw.connection_id })) };
    const success = ['connected', 'ech_accepted', 'connected_no_ech', 'ech_recovered'].includes(run.outcome);
    if (success) {
      check(http.length >= 1 && http.every(event => event.raw.host === `${c.host}:${c.port}` && event.raw.server_name === c.host && event.raw.user_agent === run.user_agent && event.raw.tls_version === c.tls && (!c.cipher || event.raw.cipher_suite === c.cipher) && (c.ech === undefined || event.raw.ech_accepted === c.ech)), 'run_tagged_browser_http', 'Successful outcome requires target-specific, run-tagged browser HTTP with expected negotiated parameters.', id);
      check(http.every(event => ['tls_version', 'cipher_suite', 'ech_accepted', 'resumed'].every(key => event.raw[key] === run[key])) && run.measured_user_agent === run.user_agent && run.tls_version === c.tls && (!c.cipher || run.cipher_suite === c.cipher) && (c.ech === undefined || run.ech_accepted === c.ech) && run.expected_match === true, 'reported_negotiation', 'Reported TLS/cipher/ECH fields must agree with the raw browser HTTP and independent case expectation.', id);
      const connected = http.map(event => fixtureHS.filter(hs => hs.file === event.file && hs.raw.remote_address === event.raw.remote_address && hs.raw.success === true && stamp(hs.raw.timestamp) <= stamp(event.raw.timestamp)));
      check(connected.every(matches => matches.length === 1), 'http_handshake_join', 'Each successful HTTP connection must match exactly one prior successful fixture handshake by raw source address.', id);
      check(run.resumed === false && http.every(e => e.raw.resumed === false) && fixtureHS.filter(e => e.raw.success === true).every(e => e.raw.resumed === false), 'no_session_resumption', 'All successful target handshakes in the run window and final HTTP must be full handshakes.', id);
      check(connected.every(matches => matches.every(e => e.raw.tls_version === c.tls && (!c.cipher || e.raw.cipher_suite === c.cipher) && (c.ech === undefined || e.raw.ech_accepted === c.ech))), 'handshake_parameters', 'Raw matching handshakes must agree with the controlled case.', id);
      if (c.id === 'E1') check(connected.every(matches => matches.every(e => e.raw.ech_offered === true && e.raw.ech_config_id === 17 && e.raw.ech_accepted === true && /^[a-f0-9]{64}$/.test(e.raw.client_hello_sha256 || ''))), 'valid_ech_clienthello', 'E1 must accept real configured ECH ID 17, not merely offer GREASE.', id);
      if (c.id === 'E3') {
        const stale = fixtureHS.filter(e => e.raw.ech_config_id === 16 && e.raw.ech_offered === true && e.raw.ech_accepted === false && e.raw.server_name === 'public.tlslab.test' && e.raw.success === true);
        const accepted = connected.flat().filter(e => e.raw.ech_config_id === 17 && e.raw.ech_offered === true && e.raw.ech_accepted === true && e.raw.server_name === c.host && e.raw.outer_server_name === 'public.tlslab.test');
        check(run.outcome === 'ech_recovered' && stale.length >= 1 && accepted.length >= 1 && accepted.every(a => stale.some(s0 => stamp(s0.raw.timestamp) < stamp(a.raw.timestamp) && s0.raw.connection_id !== a.raw.connection_id)) && [...stale, ...accepted].every(e => /^[a-f0-9]{64}$/.test(e.raw.client_hello_sha256 || '')), 'stale_ech_recovery', 'E3 requires stale ID 16 / ECH=false followed by current ID 17 / ECH=true and run-tagged inner HTTP, on distinct connections.', id);
        detail.ech_sequence = { stale_config_id: 16, accepted_config_id: 17, stale_connections_observed: stale.length, accepted_http_connections_observed: accepted.length, exact_retry_count_claimed: false, note: 'Multiple connections may be parallel browser preconnections; counts are not interpreted as retries.' };
      }
    } else if (['V1', 'V2'].includes(c.id) && run.outcome === 'rejected_protocol') {
      const versionID = c.id === 'V1' ? '0x0301' : '0x0302';
      const rejected = referenced.filter(e => e.raw.event === 'handshake');
      check(!http.length && fixtureHS.length > 0 && rejected.length > 0 && rejected.every(e => e.raw.fixture === c.fixture && e.raw.success === false && /unsupported versions|protocol version/i.test(e.raw.error || '') && Array.isArray(e.raw.offered_version_ids) && e.raw.offered_version_ids.length > 0 && !e.raw.offered_version_ids.map(lower).includes(versionID) && e.raw.offered_version_ids.some(v => ['0x0303', '0x0304'].includes(lower(v))) && /^[a-f0-9]{64}$/.test(e.raw.client_hello_sha256 || '')), 'legacy_tls_rejection', 'V1/V2 rejection must have a raw ClientHello offering modern versions but not the fixture version and an explicit protocol rejection.', id);
      detail.offered_version_ids = [...new Set(rejected.flatMap(e => e.raw.offered_version_ids || []))];
    } else {
      check(false, 'conclusive_case_outcome', 'This observation needs review: it is neither an evidence-backed expected connection nor an explicit legacy-version rejection.', id);
    }
    detail.passed = findings.length === before;
    perRun.push(detail);
  }
  for (const [slot, ids] of expected) if (!ids.length) omitted.push(slot);
  const duplicates = [...expected].filter(([, ids]) => ids.length > 1).map(([slot, run_ids]) => ({ slot, run_ids }));
  check(!duplicates.length, 'unique_expected_slots', 'Every observed planned slot must be recorded exactly once.');
  check(!unexpected.length, 'no_unplanned_slots', 'No unexpected browser/case/repetition slots may appear.');
  check(runs.length > 0, 'nonempty_study', 'At least one genuine browser measurement is required.');
  const verifyWindows = (items, code) => {
    const sorted = items.filter(w => Number.isFinite(w.start) && Number.isFinite(w.end)).sort((a, b) => a.start - b.start);
    for (let i = 1; i < sorted.length; i++) check(sorted[i].start >= sorted[i - 1].end, code, `Intervals overlap: ${sorted[i - 1].run_id} and ${sorted[i].run_id}.`, sorted[i].run_id);
  };
  verifyWindows(windows, 'serialized_measurement_windows');
  verifyWindows(launchWindows, 'serialized_browser_lifetimes');
  const journalIDs = new Set(journalCompleted.map(entry => entry.run.run_id));
  check([...journalIDs].every(id => runIDs.has(id)), 'no_omitted_completed_runs', 'Every server-completed run in the batch must appear in the export.');
  const measuredBuilds = [...new Set(runs.map(r => r.browser_id))];
  const coverage = !omitted.length && !duplicates.length && !unexpected.length && runs.length === 252;
  return {
    schema_version: 1, artifact_kind: 'cse4402-independent-study-audit', generator: 'scripts/audit-study.cjs', audited_utc: new Date().toISOString(), batch_id: data.batch_id,
    observed_checks_passed: findings.length === 0, planned_coverage_complete: coverage, all_requirements_verified: findings.length === 0 && coverage,
    planned_cells: expected.size, observed_records: runs.length, unique_observed_slots: expected.size - omitted.length,
    measured_browsers: measuredBuilds, missing_browsers: BROWSERS.filter(id => !measuredBuilds.includes(id)), missing_cells: omitted, duplicate_slots: duplicates, unexpected_slots: unexpected,
    certificate: { pem_sha256: leafHash, certificate_der_sha256: leaf.fingerprint256, valid_from: leaf.validFrom, valid_to: leaf.validTo },
    checks: counters, findings, run_checks: perRun, sources,
    interpretation: 'Missing planned measurements affect coverage separately from defects in observed measurements. Browser and raw server records are compared offline; no measurement is created, changed or substituted.',
    limitations: ['Fresh profiles are established by unique run-named paths, runner records and settings; this audit cannot reconstruct unlogged filesystem history.', 'Client IP is the local server-observed loopback address in this controlled demo.', 'ECH IDs and accepted connection state are recorded from ClientHello/handshake evidence. Parallel connections do not establish an exact retry count or decode the server retry extension.', 'Manifest hashes and runtime records establish the pinned measured binary and engine family; user-agent strings alone do not identify vendor patch versions. Edge CDP identifies its Edg product/version; its underlying Chromium patch version remains unknown.', 'Certificate provenance uses the recorded PEM file hash and validity. It does not independently capture each transmitted Certificate message.']
  };
}

function main() {
  let input = path.join(ROOT, 'output', 'comparison-data.json'), checkOnly = false, requireFull = false;
  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === '--input' && process.argv[i + 1]) input = path.resolve(process.argv[++i]);
    else if (process.argv[i] === '--check-only') checkOnly = true;
    else if (process.argv[i] === '--require-full') requireFull = true;
    else throw new Error('Usage: node scripts/audit-study.cjs [--input file.json] [--check-only] [--require-full]');
  }
  const report = auditStudy({ input });
  const output = path.join(ROOT, 'evidence', 'study-audit.json');
  if (!checkOnly) {
    if (fs.existsSync(output) && fs.lstatSync(output).isSymbolicLink()) throw new Error('Refusing a redirected audit output.');
    const temp = output + '.tmp-' + process.pid;
    fs.writeFileSync(temp, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    fs.renameSync(temp, output);
  }
  console.log(JSON.stringify({ output: checkOnly ? null : output, observed_checks_passed: report.observed_checks_passed, planned_coverage_complete: report.planned_coverage_complete, observed_records: report.observed_records, missing_cells: report.missing_cells.length, findings: report.findings }, null, 2));
  if (!report.observed_checks_passed) process.exitCode = 1;
  else if (requireFull && !report.planned_coverage_complete) process.exitCode = 2;
}

module.exports = { auditStudy, matchesRuntimeVersion, CASES, BROWSERS };
if (require.main === module) { try { main(); } catch (error) { console.error(error.stack || error.message); process.exitCode = 1; } }
