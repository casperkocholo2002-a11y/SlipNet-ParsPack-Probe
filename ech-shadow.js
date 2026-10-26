'use strict';

const http = require('http');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const net = require('net');
const { spawn } = require('child_process');

const PORT = Number(process.env.PORT || 3000);
const XRAY_DIR = '/tmp/slipnet-ech-shadow';
const XRAY_ZIP = path.join(XRAY_DIR, 'xray.zip');
const XRAY_BIN = path.join(XRAY_DIR, 'xray');
const XRAY_CONFIG = path.join(XRAY_DIR, 'config.json');
const XRAY_URL = 'https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip';
const XRAY_SHA256 = '0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978';

const TARGET_HOST = String(process.env.ECH_TARGET_HOST || 'ppw-3c19aa324d48.edgecache-628bbe41dc.workers.dev').trim();
const TARGET_PATH = String(process.env.ECH_TARGET_PATH || '/health').trim();
const ECH_CONFIG_LIST = String(process.env.ECH_CONFIG_LIST || 'AEX+DQBBSgAgACCyBPYM6kjaE2K5itIb/Y6fAcmNI9em8L4c/cSEQHfBdwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=').trim();
const SOCKS_PORT = Number(process.env.ECH_SOCKS_PORT || 29997);

let xrayProcess = null;
let bootstrapError = null;
let ready = false;
let lastProbe = null;

function json(res, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': String(body.length),
    'cache-control': 'no-store',
  });
  res.end(body);
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function findEocd(buf) {
  const sig = 0x06054b50;
  const min = Math.max(0, buf.length - 0x10000 - 22);
  for (let i = buf.length - 22; i >= min; i -= 1) {
    if (buf.readUInt32LE(i) === sig) return i;
  }
  throw new Error('zip_eocd_not_found');
}

function extractZipEntry(zip, wantedName) {
  const eocd = findEocd(zip);
  const centralOffset = zip.readUInt32LE(eocd + 16);
  const entries = zip.readUInt16LE(eocd + 10);
  let off = centralOffset;

  for (let i = 0; i < entries; i += 1) {
    if (zip.readUInt32LE(off) !== 0x02014b50) throw new Error('zip_central_corrupt');
    const method = zip.readUInt16LE(off + 10);
    const compressedSize = zip.readUInt32LE(off + 20);
    const uncompressedSize = zip.readUInt32LE(off + 24);
    const nameLen = zip.readUInt16LE(off + 28);
    const extraLen = zip.readUInt16LE(off + 30);
    const commentLen = zip.readUInt16LE(off + 32);
    const localOffset = zip.readUInt32LE(off + 42);
    const name = zip.subarray(off + 46, off + 46 + nameLen).toString('utf8');

    if (name === wantedName) {
      if (zip.readUInt32LE(localOffset) !== 0x04034b50) throw new Error('zip_local_corrupt');
      const localNameLen = zip.readUInt16LE(localOffset + 26);
      const localExtraLen = zip.readUInt16LE(localOffset + 28);
      const dataStart = localOffset + 30 + localNameLen + localExtraLen;
      const compressed = zip.subarray(dataStart, dataStart + compressedSize);
      let out;
      if (method === 0) out = Buffer.from(compressed);
      else if (method === 8) out = zlib.inflateRawSync(compressed);
      else throw new Error('zip_method_unsupported_' + method);
      if (out.length !== uncompressedSize) throw new Error('zip_size_mismatch');
      return out;
    }

    off += 46 + nameLen + extraLen + commentLen;
  }
  throw new Error('zip_entry_not_found_' + wantedName);
}

async function downloadBuffer(url) {
  const response = await fetch(url, { redirect: 'follow' });
  if (!response.ok) throw new Error('download_http_' + response.status);
  return Buffer.from(await response.arrayBuffer());
}

async function ensureXray() {
  await fsp.mkdir(XRAY_DIR, { recursive: true, mode: 0o700 });
  try {
    const current = await fsp.readFile(XRAY_BIN);
    if (current.length > 1024 * 1024) return;
  } catch {}

  const zip = await downloadBuffer(XRAY_URL);
  const digest = sha256(zip);
  if (digest !== XRAY_SHA256) throw new Error('xray_sha256_mismatch');
  await fsp.writeFile(XRAY_ZIP, zip, { mode: 0o600 });
  const binary = extractZipEntry(zip, 'xray');
  await fsp.writeFile(XRAY_BIN, binary, { mode: 0o700 });
}

async function writeConfig() {
  const cfg = {
    log: { loglevel: 'warning' },
    inbounds: [{
      listen: '127.0.0.1',
      port: SOCKS_PORT,
      protocol: 'socks',
      settings: { udp: false },
    }],
    outbounds: [{
      tag: 'ech-probe',
      protocol: 'freedom',
      settings: { redirect: TARGET_HOST + ':443' },
      streamSettings: {
        security: 'tls',
        tlsSettings: {
          serverName: TARGET_HOST,
          echConfigList: ECH_CONFIG_LIST,
          alpn: ['http/1.1'],
        },
      },
    }],
  };
  await fsp.writeFile(XRAY_CONFIG, JSON.stringify(cfg), { mode: 0o600 });
}

async function waitForPort(port, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await new Promise((resolve) => {
      const socket = net.connect({ host: '127.0.0.1', port });
      const timer = setTimeout(() => { socket.destroy(); resolve(false); }, 300);
      socket.once('connect', () => { clearTimeout(timer); socket.destroy(); resolve(true); });
      socket.once('error', () => { clearTimeout(timer); resolve(false); });
    });
    if (ok) return true;
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

async function startXray() {
  await ensureXray();
  await writeConfig();

  xrayProcess = spawn(XRAY_BIN, ['run', '-c', XRAY_CONFIG], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let recent = '';
  const capture = (chunk) => {
    recent = (recent + chunk.toString('utf8')).slice(-8000);
  };
  xrayProcess.stdout.on('data', capture);
  xrayProcess.stderr.on('data', capture);
  xrayProcess.once('exit', (code, signal) => {
    ready = false;
    if (!bootstrapError) bootstrapError = 'xray_exit_' + String(code) + '_' + String(signal || '');
  });

  if (!await waitForPort(SOCKS_PORT)) {
    throw new Error('xray_socks_not_ready:' + recent.slice(-500));
  }
  ready = true;
}

function socksConnect(host, port, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port: SOCKS_PORT });
    socket.setTimeout(timeoutMs);
    let stage = 0;
    let buffer = Buffer.alloc(0);

    const fail = (error) => {
      socket.destroy();
      reject(error instanceof Error ? error : new Error(String(error)));
    };

    socket.once('error', fail);
    socket.once('timeout', () => fail(new Error('socks_timeout')));
    socket.once('connect', () => socket.write(Buffer.from([0x05, 0x01, 0x00])));

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (stage === 0 && buffer.length >= 2) {
        if (buffer[0] !== 0x05 || buffer[1] !== 0x00) return fail(new Error('socks_auth_rejected'));
        buffer = buffer.subarray(2);
        stage = 1;
        const h = Buffer.from(host, 'utf8');
        if (h.length > 255) return fail(new Error('target_host_too_long'));
        const p = Buffer.alloc(2);
        p.writeUInt16BE(port, 0);
        socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, h.length]), h, p]));
      }
      if (stage === 1 && buffer.length >= 5) {
        if (buffer[0] !== 0x05 || buffer[1] !== 0x00) return fail(new Error('socks_connect_rejected_' + buffer[1]));
        const atyp = buffer[3];
        let need;
        if (atyp === 0x01) need = 10;
        else if (atyp === 0x04) need = 22;
        else if (atyp === 0x03) {
          if (buffer.length < 5) return;
          need = 7 + buffer[4];
        } else return fail(new Error('socks_bad_atyp'));
        if (buffer.length < need) return;
        socket.removeAllListeners('data');
        socket.setTimeout(0);
        resolve(socket);
      }
    });
  });
}

async function runProbe() {
  if (!ready) throw new Error(bootstrapError || 'xray_not_ready');
  const started = Date.now();
  const socket = await socksConnect(TARGET_HOST, 80);
  return await new Promise((resolve, reject) => {
    let data = Buffer.alloc(0);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('probe_timeout'));
    }, 8000);

    socket.on('data', (chunk) => {
      data = Buffer.concat([data, chunk]);
      if (data.length > 65536) {
        clearTimeout(timer);
        socket.destroy();
        reject(new Error('probe_response_too_large'));
      }
    });
    socket.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    socket.once('end', () => {
      clearTimeout(timer);
      const text = data.toString('utf8');
      const statusLine = text.split('\r\n', 1)[0] || '';
      const ok = /^HTTP\/1\.[01] 200\b/.test(statusLine) && /\r\n\r\nok\s*$/i.test(text);
      const result = {
        ok,
        ech: ok,
        target: TARGET_HOST,
        statusLine,
        ms: Date.now() - started,
      };
      lastProbe = { ...result, at: new Date().toISOString() };
      if (!ok) return reject(new Error('probe_bad_response:' + statusLine));
      resolve(result);
    });

    socket.write(
      'GET ' + TARGET_PATH + ' HTTP/1.1\r\n' +
      'Host: ' + TARGET_HOST + '\r\n' +
      'Connection: close\r\n' +
      'User-Agent: SlipNet-ECH-Shadow/1\r\n\r\n'
    );
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://shadow.local');
  if (req.method === 'GET' && url.pathname === '/health') {
    return json(res, ready ? 200 : 503, {
      ok: ready,
      mode: 'ech-shadow-only',
      xrayReady: ready,
      bootstrapError,
      target: TARGET_HOST,
      lastProbe,
    });
  }
  if (req.method === 'GET' && url.pathname === '/ech-test') {
    try {
      const result = await runProbe();
      return json(res, 200, result);
    } catch (error) {
      return json(res, 502, {
        ok: false,
        ech: false,
        target: TARGET_HOST,
        error: String(error && error.message ? error.message : error).slice(0, 500),
      });
    }
  }
  return json(res, 404, { ok: false, error: 'not_found' });
});

startXray().catch((error) => {
  bootstrapError = String(error && error.message ? error.message : error).slice(0, 1000);
  ready = false;
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('SlipNet ECH shadow probe listening on', PORT);
});

function shutdown() {
  try { if (xrayProcess) xrayProcess.kill('SIGTERM'); } catch {}
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
