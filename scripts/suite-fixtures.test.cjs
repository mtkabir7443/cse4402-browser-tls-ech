'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const tls = require('node:tls');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { createFixtureServers, FIXTURES } = require('./suite-fixtures.cjs');

test('TLS 1.3 fixtures enforce exact suites, log failed handshakes, and decline resumption', { timeout: 35000 }, async t => {
  const root = path.resolve(__dirname, '..');
  const openssl = process.env.SUITE_TEST_OPENSSL || 'C:\\msys64\\mingw64\\bin\\openssl.exe';
  const stamp = new Date().toISOString().replace(/[:.]/g, '-') + '-' + crypto.randomBytes(3).toString('hex');
  const evidence = path.join(root, 'evidence', 'suite-fixture-probes', stamp);
  fs.mkdirSync(evidence, { recursive: true });
  const eventPath = path.join(evidence, 'events.jsonl');
  const running = await createFixtureServers({ projectRoot: root, eventPath, fixtures: FIXTURES.map(f => ({ ...f, port: 0 })) });
  t.after(() => running.close());
  const results = [];
  const caFile = path.join(root, '.runtime', 'ca.pem');
  const ca = fs.readFileSync(caFile);

  async function probe(fixture, offered, id) {
    const args = ['s_client', '-connect', `127.0.0.1:${fixture.port}`, '-servername', `${fixture.name}.tlslab.test`,
      '-verify_hostname', `${fixture.name}.tlslab.test`, '-CAfile', caFile, '-verify_return_error',
      '-tls1_3', '-ciphersuites', offered, '-alpn', 'http/1.1', '-brief', '-ign_eof'];
    const result = await new Promise((resolve, reject) => {
      const child = spawn(openssl, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '', stderr = '';
      let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; child.kill(); }, 5000);
      child.stdout.on('data', chunk => { stdout += chunk; });
      child.stderr.on('data', chunk => { stderr += chunk; });
      child.stdin.on('error', () => {}); // A rejected handshake closes before HTTP input is consumed.
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('close', code => { clearTimeout(timer); resolve({ id, offered, code, stdout, stderr, timedOut }); });
      child.stdin.end(`GET /probe?run=${id} HTTP/1.1\r\nHost: ${fixture.name}.tlslab.test:${fixture.port}\r\nOrigin: https://127.0.0.1:8443\r\nUser-Agent: independent-openssl-fixture-test\r\nConnection: close\r\n\r\n`);
    });
    fs.writeFileSync(path.join(evidence, `${id}.stdout.txt`), result.stdout);
    fs.writeFileSync(path.join(evidence, `${id}.stderr.txt`), result.stderr);
    results.push({ ...result, stdout: undefined, stderr: undefined });
    assert.equal(result.timedOut, false, `${id} timed out`);
    return result;
  }

  for (let index = 0; index < running.servers.length; index++) {
    const fixture = running.servers[index].fixture;
    await t.test(`${fixture.name}: matching suite succeeds and another suite fails`, async () => {
      const matching = await probe(fixture, fixture.cipher, `positive-${fixture.name}`);
      assert.equal(matching.code, 0, matching.stderr);
      assert.match(matching.stderr, /Verification: OK/);
      assert.match(matching.stderr, /Protocol version: TLSv1\.3/);
      assert.ok(matching.stderr.includes(`Ciphersuite: ${fixture.cipher}`));
      assert.match(matching.stdout, /HTTP\/1\.1 200 OK/);
      assert.match(matching.stdout, /Access-Control-Allow-Origin: https:\/\/127\.0\.0\.1:8443/i);
      const body = JSON.parse(matching.stdout.split('\r\n\r\n')[1]);
      assert.equal(body.cipher_suite, fixture.cipher);
      assert.equal(body.fixture, fixture.name);
      assert.equal(body.tls_version, 'TLS 1.3');
      assert.equal(body.ech_accepted, false);
      assert.equal(body.resumed, false);
      assert.equal(body.client_ip, '127.0.0.1');
      assert.equal(body.run_id, `positive-${fixture.name}`);
      const other = FIXTURES[(index + 1) % FIXTURES.length].cipher;
      const mismatch = await probe(fixture, other, `negative-${fixture.name}`);
      assert.notEqual(mismatch.code, 0);
      assert.match(mismatch.stderr, /alert handshake failure/i);
      assert.doesNotMatch(mismatch.stdout, /HTTP\/1\.1 200/);
    });
  }

  async function nodeConnection(session, id) {
    const fixture = running.servers[0].fixture;
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host: '127.0.0.1', port: fixture.port, ca,
        servername: `${fixture.name}.tlslab.test`, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
        ciphers: fixture.cipher, session, ALPNProtocols: ['http/1.1'] });
      const sessions = [];
      let reused;
      let body = '';
      const timer = setTimeout(() => socket.destroy(new Error('session probe timeout')), 5000);
      socket.on('session', data => sessions.push(data));
      socket.once('secureConnect', () => {
        reused = socket.isSessionReused();
        socket.write(`GET /probe?run=${id} HTTP/1.1\r\nHost: ${fixture.name}.tlslab.test\r\nConnection: close\r\n\r\n`);
      });
      socket.on('data', chunk => { body += chunk; });
      socket.once('error', error => { clearTimeout(timer); reject(error); });
      socket.once('end', () => { clearTimeout(timer); socket.end(); resolve({ sessions, reused, body }); });
    });
  }
  const first = await nodeConnection(undefined, 'session-first');
  assert.equal(first.reused, false);
  assert.match(first.body, /HTTP\/1\.1 200/);
  const sessionResult = { received_tickets: first.sessions.length, attempted_resumption: false, resumed: false };
  if (first.sessions.length) {
    const retry = await nodeConnection(first.sessions[0], 'session-reuse-attempt');
    assert.equal(retry.reused, false, 'server must decline the offered previous session');
    assert.match(retry.body, /HTTP\/1\.1 200/);
    sessionResult.attempted_resumption = true;
    sessionResult.resumed = retry.reused;
  }
  const records = fs.readFileSync(eventPath, 'utf8').trim().split('\n').map(JSON.parse);
  for (const { fixture } of running.servers) {
    const successes = records.filter(r => r.event === 'handshake' && r.fixture === fixture.name && r.success);
    const failures = records.filter(r => r.event === 'handshake' && r.fixture === fixture.name && r.success === false);
    assert.ok(successes.length >= 1, `missing successful handshake evidence for ${fixture.name}`);
    assert.ok(failures.length >= 1, `missing pre-HTTP failure evidence for ${fixture.name}`);
    for (const row of [...successes, ...failures]) {
      assert.equal(row.client_ip, '127.0.0.1');
      assert.match(row.remote_address, /^127\.0\.0\.1:\d+$/);
      assert.ok(row.timestamp);
    }
    const http = records.find(r => r.event === 'http_result' && r.run_id === `positive-${fixture.name}`);
    assert.ok(http);
    assert.ok(successes.some(r => r.connection_id === http.connection_id));
  }
  const summary = {
    purpose: 'Independent Node/OpenSSL fixture checks; not browser measurements',
    timestamp: new Date().toISOString(), node_version: process.version, node_openssl: process.versions.openssl,
    certificate_sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(root, '.runtime', 'server.pem'))).digest('hex'),
    all_passed: true, probes: results, session_control: sessionResult,
  };
  fs.writeFileSync(path.join(evidence, 'summary.json'), JSON.stringify(summary, null, 2));
  t.diagnostic(`Evidence: ${evidence}`);
});
