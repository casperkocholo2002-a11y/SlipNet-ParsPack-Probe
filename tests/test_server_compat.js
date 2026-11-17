'use strict';

const http = require('http');
const { spawn } = require('child_process');
const assert = require('assert');
const path = require('path');

function getHealth(port) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/health', timeout: 1000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
  });
}

async function runCase({ port, route, expectWorkerCompat }) {
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      CONCURRENCY_GUARD: '0',
      LOCAL_VLESS_ORIGIN: '1',
      LOCAL_VLESS_HOST: '127.0.0.1',
      LOCAL_VLESS_PORT: '29999',
      SESSION_GUARD_ROUTE: route,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let health = null;
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });

  try {
    for (let i = 0; i < 50; i += 1) {
      try {
        health = await getHealth(port);
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 100));
      }
    }

    assert(health, 'server did not become healthy: ' + stderr.slice(-1200));
    assert.strictEqual(health.status, 200);
    assert.strictEqual(health.body.ok, true);
    assert.strictEqual(health.body.build, 'no95-shadow-v2-parspack-compat');
    assert.strictEqual(health.body.primaryRelayMode, 'local-vless');
    assert.strictEqual(health.body.concurrencyGuardRoute, route);
    assert.strictEqual(health.body.workerDirectConfigured, expectWorkerCompat);
    assert.strictEqual(health.body.workerFixedConfigured, expectWorkerCompat);
    assert.strictEqual(health.body.workerRelayMode, 'wss');
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolve) => {
      child.once('exit', resolve);
      setTimeout(resolve, 1500);
    });
  }
}

async function main() {
  await runCase({ port: 28999, route: 'parspack', expectWorkerCompat: true });
  await runCase({ port: 29000, route: 'arvan', expectWorkerCompat: false });
  console.log('SERVER_COMPAT_TEST=PASS');
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
