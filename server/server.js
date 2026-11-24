// Сервер MAX (Drognev).
//
// Сервер — «слепой» ретранслятор. Он хранит только:
//   * открытые ключи (ключ личности, подписанный предключ, одноразовые предключи);
//   * зашифрованные конверты до момента доставки (не дольше 30 дней).
// Он не знает отправителя сообщения (запечатанный конверт), не ведёт журналов,
// не записывает IP-адреса и не может прочитать ни одного сообщения.

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import { Store } from './store.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(HERE, '..', 'public');

const HANDLE_RE = /^[a-z0-9_]{3,24}$/;
const B64_RE = /^[A-Za-z0-9_-]+$/;
const MAX_PAYLOAD = 6 * 1024 * 1024;
const MAX_BLOB = 5.5 * 1024 * 1024;
const MAX_QUEUE_ITEMS = 1000;
const MAX_QUEUE_BYTES = 64 * 1024 * 1024;
const MAX_OPKS = 200;
const QUEUE_TTL = 30 * 864e5;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
  '.webmanifest': 'application/manifest+json',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
};

// ---------------------------------------------------------------- утилиты

function raw(s, len) {
  if (typeof s !== 'string' || !B64_RE.test(s) || s.length > Math.ceil((len * 4) / 3) + 2) return null;
  const b = Buffer.from(s, 'base64url');
  return b.length === len ? b : null;
}

function edVerify(pub, sig, data) {
  try {
    const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: pub.toString('base64url') }, format: 'jwk' });
    return crypto.verify(null, data, key, sig);
  } catch {
    return false;
  }
}

function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
}

class Bucket {
  constructor(rate, burst) { this.rate = rate; this.burst = burst; this.t = burst; this.last = Date.now(); }
  take(n = 1) {
    const now = Date.now();
    this.t = Math.min(this.burst, this.t + ((now - this.last) / 1000) * this.rate);
    this.last = now;
    if (this.t < n) return false;
    this.t -= n;
    return true;
  }
}

function parseSpk(spk, ikSig) {
  if (!spk || !Number.isInteger(spk.id) || spk.id < 0 || spk.id > 0xffffffff) return null;
  const pub = raw(spk.pub, 32);
  const sig = raw(spk.sig, 64);
  if (!pub || !sig) return null;
  if (!edVerify(ikSig, sig, Buffer.concat([Buffer.from('MAX-SPK'), u32(spk.id), pub]))) return null;
  return { id: spk.id, pub: spk.pub, sig: spk.sig };
}

function parseOpks(list) {
  if (!Array.isArray(list) || list.length > MAX_OPKS) return null;
  const out = [];
  for (const k of list) {
    if (!k || !Number.isInteger(k.id) || k.id < 0 || !raw(k.pub, 32)) return null;
    out.push({ id: k.id, pub: k.pub });
  }
  return out;
}

function parseBundle(b) {
  if (!b || typeof b !== 'object') return null;
  const ikSig = raw(b.ikSig, 32);
  const ikDh = raw(b.ikDh, 32);
  const ikDhSig = raw(b.ikDhSig, 64);
  if (!ikSig || !ikDh || !ikDhSig) return null;
  if (!edVerify(ikSig, ikDhSig, Buffer.concat([Buffer.from('MAX-IKDH'), ikDh]))) return null;
  const spk = parseSpk(b.spk, ikSig);
  const opks = parseOpks(b.opks || []);
  if (!spk || !opks) return null;
  return { ikSig: b.ikSig, ikDh: b.ikDh, ikDhSig: b.ikDhSig, spk, opks };
}

function loadStatic() {
  const files = new Map();
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(p);
      else {
        const ext = path.extname(ent.name);
        if (!MIME[ext]) continue;
        const body = fs.readFileSync(p);
        const rel = '/' + path.relative(PUBLIC, p).split(path.sep).join('/');
        files.set(rel, { body, type: MIME[ext] });
      }
    }
  };
  walk(PUBLIC);
  return files;
}

function securityHeaders(tls, hsts) {
  const csp = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' blob: data:",
    "media-src 'self' blob:",
    "connect-src 'self'",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "worker-src 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
  ];
  if (tls) csp.push('upgrade-insecure-requests');
  const h = {
    'Content-Security-Policy': csp.join('; '),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), hid=(), midi=(), magnetometer=(), gyroscope=(), accelerometer=(), browsing-topics=(), interest-cohort=()',
    'X-DNS-Prefetch-Control': 'off',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Cache-Control': 'no-store',
  };
  if (hsts) h['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload';
  return h;
}

// ---------------------------------------------------------------- сервер

export function createServer(opts = {}) {
  const tlsCert = opts.tlsCert ?? process.env.TLS_CERT;
  const tlsKey = opts.tlsKey ?? process.env.TLS_KEY;
  const tls = !!(tlsCert && tlsKey);
  const trustProxy = opts.trustProxy ?? (process.env.TRUST_PROXY === '1' || !!process.env.RENDER);
  const hsts = tls || (opts.hsts ?? (process.env.HSTS === '1' || !!process.env.RENDER));
  const allowed = (opts.allowedOrigins ?? process.env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const store = new Store(opts.dataDir === undefined ? (process.env.DATA_DIR || path.join(HERE, '..', 'data')) : opts.dataDir);

  const regPerHour = Number(opts.registerPerHour ?? process.env.REGISTER_PER_HOUR ?? 5);
  const files = loadStatic();
  const headers = securityHeaders(tls, hsts);
  const ipSecret = crypto.randomBytes(32); // живёт только в памяти; IP нигде не сохраняется
  const online = new Map();
  const ipConns = new Map();
  const regBuckets = new Map();

  const onRequest = (req, res) => {
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' });
      return res.end();
    }
    let p;
    try { p = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch { res.writeHead(400); return res.end(); }
    if (p === '/') p = '/index.html';
    const f = files.get(p);
    if (!f) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': f.type, 'Content-Length': f.body.length });
    res.end(req.method === 'HEAD' ? undefined : f.body);
  };

  const server = tls
    ? https.createServer({ cert: fs.readFileSync(tlsCert), key: fs.readFileSync(tlsKey), minVersion: 'TLSv1.2' }, onRequest)
    : http.createServer(onRequest);
  server.headersTimeout = 15000;
  server.requestTimeout = 30000;

  // Сжатие выключено намеренно: оно раскрывает длину содержимого (атаки класса CRIME).
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_PAYLOAD, perMessageDeflate: false });

  const ipOf = (req) => {
    let ip = req.socket.remoteAddress || '';
    if (trustProxy && req.headers['x-forwarded-for']) ip = String(req.headers['x-forwarded-for']).split(',')[0].trim();
    return crypto.createHmac('sha256', ipSecret).update(ip).digest('base64url');
  };

  server.on('upgrade', (req, socket, head) => {
    const deny = (code) => { socket.write(`HTTP/1.1 ${code} Denied\r\nConnection: close\r\n\r\n`); socket.destroy(); };
    let url;
    try { url = new URL(req.url, 'http://x'); } catch { return deny(400); }
    if (url.pathname !== '/ws') return deny(404);
    const origin = req.headers.origin;
    if (origin) {
      let ok = false;
      try { ok = allowed.length ? allowed.includes(origin) : new URL(origin).host === req.headers.host; } catch { ok = false; }
      if (!ok) return deny(403);
    }
    const ipKey = ipOf(req);
    const n = ipConns.get(ipKey) || 0;
    if (n >= 20) return deny(429);
    ipConns.set(ipKey, n + 1);
    socket.once('close', () => {
      const left = (ipConns.get(ipKey) || 1) - 1;
      if (left <= 0) ipConns.delete(ipKey); else ipConns.set(ipKey, left);
    });
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req, ipKey));
  });

  const send = (ws, obj) => { if (ws.readyState === 1) ws.send(JSON.stringify(obj)); };

  const queueOf = (h) => store.queues[h] || [];

  const deliver = (handle, item) => {
    const ctx = online.get(handle);
    if (ctx) send(ctx.ws, { t: 'msg', id: item.id, blob: item.blob, ts: item.ts });
  };

  const regAllowed = (ipKey) => {
    let b = regBuckets.get(ipKey);
    if (!b) { b = new Bucket(regPerHour / 3600, regPerHour); regBuckets.set(ipKey, b); }
    return b.take();
  };

  const authenticate = (ctx, handle) => {
    ctx.handle = handle;
    clearTimeout(ctx.authTimer);
    const prev = online.get(handle);
    if (prev && prev !== ctx) prev.ws.close(4001, 'replaced');
    online.set(handle, ctx);
  };

  const flushQueue = (ctx) => {
    for (const item of queueOf(ctx.handle)) send(ctx.ws, { t: 'msg', id: item.id, blob: item.blob, ts: item.ts });
  };

  const handlers = {
    register(ctx, m, reply) {
      if (ctx.handle) return reply.err('already');
      if (!regAllowed(ctx.ipKey)) return reply.err('rate');
      if (typeof m.handle !== 'string' || !HANDLE_RE.test(m.handle)) return reply.err('handle');
      const b = parseBundle(m.bundle);
      if (!b) return reply.err('bundle');
      const sig = raw(m.sig, 64);
      const msg = Buffer.concat([Buffer.from('MAX-AUTH-v1'), ctx.nonce, Buffer.from(m.handle)]);
      if (!sig || !edVerify(Buffer.from(b.ikSig, 'base64url'), sig, msg)) return reply.err('sig');
      if (store.users[m.handle]) return reply.err('taken');
      store.users[m.handle] = b;
      store.save();
      authenticate(ctx, m.handle);
      reply.ok({ opkCount: b.opks.length });
    },

    login(ctx, m, reply) {
      if (ctx.handle) return reply.err('already');
      const u = typeof m.handle === 'string' && HANDLE_RE.test(m.handle) ? store.users[m.handle] : null;
      const sig = raw(m.sig, 64);
      const msg = Buffer.concat([Buffer.from('MAX-AUTH-v1'), ctx.nonce, Buffer.from(String(m.handle))]);
      if (!u || !sig || !edVerify(Buffer.from(u.ikSig, 'base64url'), sig, msg)) {
        reply.err('auth');
        setTimeout(() => ctx.ws.close(4002, 'auth'), 50);
        return;
      }
      authenticate(ctx, m.handle);
      reply.ok({ opkCount: u.opks.length });
      flushQueue(ctx);
    },

    lookup(ctx, m, reply) {
      const u = typeof m.handle === 'string' ? store.users[m.handle] : null;
      reply.ok({ identity: u ? { ikSig: u.ikSig, ikDh: u.ikDh, ikDhSig: u.ikDhSig } : null });
    },

    bundle(ctx, m, reply) {
      if (!ctx.bundles.take()) return reply.err('rate');
      const u = typeof m.handle === 'string' ? store.users[m.handle] : null;
      if (!u) return reply.ok({ bundle: null });
      const opk = u.opks.shift() || null; // каждый одноразовый ключ выдаётся ровно один раз
      store.save();
      reply.ok({ bundle: { ikSig: u.ikSig, ikDh: u.ikDh, ikDhSig: u.ikDhSig, spk: u.spk, opk } });
    },

    send(ctx, m, reply) {
      if (!ctx.sends.take()) return reply.err('rate');
      if (typeof m.to !== 'string' || !store.users[m.to]) return reply.err('nouser');
      if (typeof m.blob !== 'string' || m.blob.length > MAX_BLOB || !B64_RE.test(m.blob)) return reply.err('bad');
      const q = (store.queues[m.to] ||= []);
      const bytes = q.reduce((a, x) => a + x.blob.length, 0);
      if (q.length >= MAX_QUEUE_ITEMS || bytes + m.blob.length > MAX_QUEUE_BYTES) return reply.err('full');
      // Время округляется до минуты; отправитель не записывается вовсе.
      const item = { id: crypto.randomBytes(16).toString('base64url'), blob: m.blob, ts: Math.floor(Date.now() / 60000) * 60000 };
      q.push(item);
      store.save();
      reply.ok();
      deliver(m.to, item);
    },

    ack(ctx, m) {
      if (!Array.isArray(m.ids)) return;
      const ids = new Set(m.ids.slice(0, 1000).filter((x) => typeof x === 'string'));
      const q = store.queues[ctx.handle];
      if (!q) return;
      const left = q.filter((x) => !ids.has(x.id));
      if (left.length) store.queues[ctx.handle] = left; else delete store.queues[ctx.handle];
      store.save();
    },

    opks(ctx, m, reply) {
      const list = parseOpks(m.opks);
      if (!list) return reply.err('bad');
      const u = store.users[ctx.handle];
      u.opks = u.opks.concat(list).slice(-MAX_OPKS);
      store.save();
      reply.ok({ opkCount: u.opks.length });
    },

    spk(ctx, m, reply) {
      const u = store.users[ctx.handle];
      const spk = parseSpk(m.spk, Buffer.from(u.ikSig, 'base64url'));
      if (!spk) return reply.err('bad');
      u.spk = spk;
      store.save();
      reply.ok();
    },

    'delete-account'(ctx, m, reply) {
      delete store.users[ctx.handle];
      delete store.queues[ctx.handle];
      store.save();
      online.delete(ctx.handle);
      reply.ok();
      setTimeout(() => ctx.ws.close(4003, 'deleted'), 50);
    },

    ping(ctx, m, reply) { reply.ok(); },
  };

  const PUBLIC_TYPES = new Set(['register', 'login']);

  wss.on('connection', (ws, req, ipKey) => {
    const ctx = {
      ws,
      ipKey,
      handle: null,
      nonce: crypto.randomBytes(32),
      alive: true,
      strikes: 0,
      rate: new Bucket(50, 200),
      sends: new Bucket(30, 120),
      bundles: new Bucket(0.5, 10),
    };
    ws.ctx = ctx;
    ctx.authTimer = setTimeout(() => { if (!ctx.handle) ws.close(4000, 'auth timeout'); }, 30000);
    send(ws, { t: 'challenge', nonce: ctx.nonce.toString('base64url') });

    ws.on('pong', () => { ctx.alive = true; });
    ws.on('message', (data, isBinary) => {
      if (isBinary) return ws.close(1003, 'text only');
      let m;
      try { m = JSON.parse(data.toString('utf8')); } catch { return ws.close(1007, 'bad json'); }
      if (!m || typeof m !== 'object' || typeof m.t !== 'string') return;
      const rid = m.rid;
      const reply = {
        ok: (extra = {}) => send(ws, { ...extra, t: 'res', rid, ok: true }),
        err: (error) => send(ws, { t: 'res', rid, ok: false, error }),
      };
      if (!ctx.rate.take()) {
        if (++ctx.strikes > 500) return ws.close(4029, 'rate');
        return reply.err('rate');
      }
      const fn = Object.prototype.hasOwnProperty.call(handlers, m.t) ? handlers[m.t] : null;
      if (!fn) return reply.err('unknown');
      if (!PUBLIC_TYPES.has(m.t) && !ctx.handle) return reply.err('noauth');
      try { fn(ctx, m, reply); } catch { reply.err('bad'); }
    });
    ws.on('close', () => {
      clearTimeout(ctx.authTimer);
      if (ctx.handle && online.get(ctx.handle) === ctx) online.delete(ctx.handle);
    });
    ws.on('error', () => {});
  });

  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      const ctx = ws.ctx;
      if (!ctx.alive) { ws.terminate(); continue; }
      ctx.alive = false;
      ws.ping();
    }
  }, 30000);

  const cleanup = setInterval(() => {
    const cutoff = Date.now() - QUEUE_TTL;
    for (const [h, q] of Object.entries(store.queues)) {
      const left = q.filter((x) => x.ts > cutoff);
      if (left.length) store.queues[h] = left; else delete store.queues[h];
    }
    for (const [k, b] of regBuckets) { b.take(0); if (b.t >= b.burst) regBuckets.delete(k); }
    store.save();
  }, 3600e3);
  heartbeat.unref();
  cleanup.unref();

  return {
    server,
    store,
    listen(port, host) {
      return new Promise((resolve) => server.listen(port, host, () => resolve(server.address())));
    },
    close() {
      clearInterval(heartbeat);
      clearInterval(cleanup);
      for (const ws of wss.clients) ws.terminate();
      store.flush();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 8080);
  // Render.com (и похожие PaaS) задают RENDER/PORT и требуют слушать все интерфейсы.
  const host = process.env.HOST || (process.env.RENDER ? '0.0.0.0' : '127.0.0.1');
  const app = createServer();
  app.listen(port, host).then(() => {
    const proto = process.env.TLS_CERT ? 'https' : 'http';
    process.stdout.write(`MAX (Drognev) слушает ${proto}://${host}:${port}\n`);
  });
  const stop = () => { app.close().then(() => process.exit(0)); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
