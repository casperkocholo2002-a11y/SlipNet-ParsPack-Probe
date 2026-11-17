'use strict';

const http = require('http');
const { spawn } = require('child_process');
const assert = require('assert');

const PORT = 28999;

function getHealth() {
  return new Promise((resolve, reject) => {
    const req = http.get({
      host: '127.0.0.1',
      port: PORT,
      path: '/health',
      timeout: 1000,
    }, (res) => {
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

async function main() {
  const child = spawn(process.execPath, ['server.js'], {
    cwd: require('path').resolve(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      CONCURRENCY_GUARD: '0',
      LOCAL_VLESS_ORIGIN: '1',
      LOCAL_VLESS_HOST: '127.0.0.1',
      LOCAL_VLESS_PORT: '29999',
      SESSION_GUARD_ROUTE: 'parspack',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let health = null;
  try {
    for (let i = 0; i < 40; i += 1) {
      try {
        health = await getHealth();
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    assert(health, 'server did not become healthy');
    assert.strictEqual(health.status, 200);
    assert.strictEqual(health.body.ok, true);
    assert.strictEqual(health.body.build, 'no95-shadow-v2-parspack-compat');
    assert.strictEqual(health.body.primaryRelayMode, 'local-vless');
    assert.strictEqual(health.body.workerDirectConfigured, true);
    assert.strictEqual(health.body.workerFixedConfigured, true);
    assert.strictEqual(health.body.workerRelayMode, 'wss');
    assert.strictEqual(health.body.concurrencyGuardRoute, 'parspack');
    console.log('SERVER_COMPAT_TEST=PASS');
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolve) => {
      child.once('exit', resolve);
      setTimeout(resolve, 1500);
    });
  }
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
