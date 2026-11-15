'use strict';

// Node's TLS ciphers option accepts canonical TLS 1.3 names. Unlike the Go
// fixtures, these endpoints each permit exactly one TLS 1.3 ciphersuite.
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const FIXTURES = Object.freeze([
  { name: 'tls13-aes128', port: 9451, cipher: 'TLS_AES_128_GCM_SHA256' },
  { name: 'tls13-aes256', port: 9452, cipher: 'TLS_AES_256_GCM_SHA384' },
  { name: 'tls13-chacha', port: 9453, cipher: 'TLS_CHACHA20_POLY1305_SHA256' },
]);
const CONTROL_ORIGIN = 'https://127.0.0.1:8443';

async function createFixtureServers({ projectRoot, fixtures = FIXTURES, eventPath, instance = crypto.randomUUID() }) {
  const root = path.resolve(projectRoot);
  const events = eventPath || path.join(root, 'evidence', 'suite-events.jsonl');
  fs.mkdirSync(path.dirname(events), { recursive: true });
  const cert = fs.readFileSync(path.join(root, '.runtime', 'server.pem'));
  const key = fs.readFileSync(path.join(root, '.runtime', 'server-key.pem'));
  const servers = [];
  const sockets = new Set();
  const metadata = new WeakMap();
  let sequence = 0;

  function event(kind, fields) {
    const row = { ...fields, event: kind, timestamp: new Date().toISOString(), process_id: process.pid, instance };
    // Synchronous append prevents a successful /probe reply preceding its log.
    fs.appendFileSync(events, `${JSON.stringify(row)}\n`, { mode: 0o600 });
    return row;
  }
  function socketFields(socket, fixture) {
    let info = metadata.get(socket);
    if (!info) {
      const address = socket.remoteAddress || null;
      const port = socket.remotePort || null;
      info = {
        connection_id: `suite-${process.pid}-${++sequence}`,
        client_ip: address,
        remote_address: address && port ? `${address}:${port}` : null,
      };
      metadata.set(socket, info);
    }
    const cipher = socket.getCipher?.();
    return {
      ...info,
      fixture: fixture.name,
      endpoint_port: fixture.port,
      tls_version: socket.getProtocol?.()?.replace('TLSv', 'TLS ') || '',
      cipher_suite: cipher?.standardName || cipher?.name || '',
      server_name: socket.servername || '',
      ech_accepted: false, // These three fixtures have no ECH keys/configuration.
      resumed: socket.isSessionReused?.() || false,
      alpn: socket.alpnProtocol || '',
    };
  }
  function logFailure(socket, error) {
    process.stderr.write(`Suite evidence logging failed: ${error.message}\n`);
    socket.destroy();
  }
  async function close() {
    const done = servers.map(({ server }) => new Promise(resolve => server.close(resolve)));
    for (const socket of sockets) socket.destroy();
    await Promise.all(done);
  }

  try {
    for (const definition of fixtures) {
      const fixture = { ...definition };
      const server = https.createServer({
        key, cert,
        minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
        ciphers: fixture.cipher,
        ALPNProtocols: ['http/1.1'],
        handshakeTimeout: 8000,
        secureOptions: crypto.constants.SSL_OP_NO_TICKET,
      }, (request, response) => {
        response.setHeader('Access-Control-Allow-Origin', CONTROL_ORIGIN);
        response.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        response.setHeader('Cache-Control', 'no-store');
        response.setHeader('Connection', 'close');
        response.setHeader('Content-Type', 'application/json');
        if (request.method === 'OPTIONS') {
          response.writeHead(204);
          response.end();
          return;
        }
        const url = new URL(request.url, CONTROL_ORIGIN);
        if (request.method !== 'GET' || url.pathname !== '/probe') {
          response.writeHead(404);
          response.end(JSON.stringify({ error: 'Use GET /probe?run=<run-id>' }));
          return;
        }
        const fields = {
          ...socketFields(request.socket, fixture),
          run_id: (url.searchParams.get('run') || '').slice(0, 160),
          host: request.headers.host || '',
          user_agent: (request.headers['user-agent'] || '').slice(0, 1024),
        };
        try {
          event('http_result', fields);
          response.end(JSON.stringify(fields));
        } catch (error) {
          process.stderr.write(`Suite evidence logging failed: ${error.message}\n`);
          response.writeHead(503);
          response.end(JSON.stringify({ error: 'evidence_log_failure' }));
        }
      });
      // NO_TICKET disables stateless tickets; TLS 1.3 can still issue stateful
      // tickets. Keep no sessions and explicitly decline every resumption lookup.
      server.on('newSession', (_id, _data, callback) => callback());
      server.on('resumeSession', (_id, callback) => callback(null, null));
      server.on('connection', socket => {
        sockets.add(socket);
        socket.once('close', () => sockets.delete(socket));
      });
      server.on('secureConnection', socket => {
        socket.setTimeout(10000, () => socket.destroy());
        try { event('handshake', { ...socketFields(socket, fixture), success: true }); }
        catch (error) { logFailure(socket, error); }
      });
      server.on('tlsClientError', (error, socket) => {
        try {
          event('handshake', {
            ...socketFields(socket, fixture), success: false,
            error: error.message, error_code: error.code || '',
          });
        } catch (loggingError) { logFailure(socket, loggingError); }
      });
      server.requestTimeout = 10000;
      server.headersTimeout = 8000;
      server.keepAliveTimeout = 1;
      server.maxRequestsPerSocket = 1;
      servers.push({ server, fixture });
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen({ host: '127.0.0.1', port: fixture.port, exclusive: true }, () => {
          server.removeListener('error', reject);
          fixture.port = server.address().port;
          resolve();
        });
      });
      server.on('error', error => process.stderr.write(`${fixture.name}: ${error.stack}\n`));
    }
    event('suite_server_start', {
      address: '127.0.0.1', node_version: process.version, openssl_version: process.versions.openssl,
      certificate_sha256: crypto.createHash('sha256').update(cert).digest('hex'),
      fixtures: servers.map(({ fixture }) => fixture),
      resumption_policy: 'Stateless tickets disabled; stateful sessions not stored; every resume lookup rejected; actual resumed field recorded.',
    });
    return { servers, close, eventPath: events, instance };
  } catch (error) {
    await close();
    throw error;
  }
}

async function main() {
  const args = process.argv.slice(2);
  function option(name, fallback) {
    const index = args.indexOf(name);
    return index < 0 ? fallback : args[index + 1];
  }
  const projectRoot = path.resolve(option('--root', path.join(__dirname, '..')));
  const instance = option('--instance', crypto.randomUUID());
  const running = await createFixtureServers({ projectRoot, instance });
  const readyPath = path.join(projectRoot, '.runtime', 'suite-fixtures-ready.json');
  const ready = {
    pid: process.pid, instance, started_utc: new Date().toISOString(),
    node_version: process.version, openssl_version: process.versions.openssl,
    log_path: running.eventPath, fixtures: running.servers.map(({ fixture }) => fixture),
  };
  fs.writeFileSync(readyPath, JSON.stringify(ready, null, 2));
  process.stdout.write(`${JSON.stringify(ready)}\n`);
  let stopping = false;
  async function stop() {
    if (stopping) return;
    stopping = true;
    await running.close();
    process.exitCode = 0;
  }
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

if (require.main === module) main().catch(error => { process.stderr.write(`${error.stack}\n`); process.exitCode = 1; });
module.exports = { createFixtureServers, FIXTURES };
