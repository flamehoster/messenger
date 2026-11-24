// Логика клиента без интерфейса: сессии, контакты, отправка и приём.
// Используется и в браузере, и в тестах под Node.

import * as P from './protocol.js';
import { b64, rand, te, td } from './crypto.js';

export const HANDLE_RE = /^[a-z0-9_]{3,24}$/;
export const TIMERS = [0, 30, 300, 3600, 86400, 604800];
export const MAX_FILE = 3 * 1024 * 1024;
export const MAX_TEXT = 20000;

const OPK_BATCH = 50;
const OPK_MIN = 25;
const OPK_LOCAL_MAX = 400;
const SPK_ROTATE = 7 * 864e5;
const SPK_KEEP = 30 * 864e5;
const MAX_SESSIONS = 5;
const MAX_HISTORY = 5000;

export function timerLabel(t) {
  return { 0: 'выкл', 30: '30 сек', 300: '5 мин', 3600: '1 час', 86400: '1 день', 604800: '1 неделя' }[t] || `${t} с`;
}

export async function newAccountState(handle) {
  const identity = await P.createIdentity();
  const spk = await P.makeSignedPrekey(identity, 1);
  const opks = await P.makeOneTimePrekeys(1, 100);
  return {
    v: 1,
    handle,
    identity,
    spks: { 1: spk },
    spkCurrent: 1,
    nextSpkId: 2,
    opks: Object.fromEntries(opks.map((k) => [k.id, k])),
    nextOpkId: 101,
    contacts: {},
    settings: { autoLock: 300, blurOnHide: true, receipts: true, wipeAfter: 0 },
  };
}

export async function registerAccount(net, state, nonce) {
  const sig = await P.authSignature(state.identity, nonce, state.handle);
  const bundle = P.publicBundle(state.identity, state.spks[state.spkCurrent], Object.values(state.opks));
  return net.request('register', { handle: state.handle, bundle, sig });
}

function newContact(handle, id) {
  return {
    handle,
    ikSig: id.ikSig,
    ikDh: id.ikDh,
    ikDhSig: id.ikDhSig,
    verified: false,
    keyChanged: null,
    sessions: {},
    active: null,
    timer: 0,
    messages: [],
    outbox: [],
    unread: 0,
    last: Date.now(),
  };
}

function sys(text) {
  return { id: b64(rand(9)), dir: 'sys', kind: 'system', ts: Date.now(), text };
}

function err(text) { return new Error(text); }

export class Core extends EventTarget {
  #lock = Promise.resolve();
  #flushing = false;
  #reflush = false;
  #rcpt = new Map();
  #timer;

  constructor(state, { net, persist }) {
    super();
    this.s = state;
    this.net = net;
    this.persist = persist || (() => {});
    this.online = false;
    net.addEventListener('challenge', (e) => this.#login(e.detail.nonce));
    net.addEventListener('msg', (e) => { this.#serial(() => this.#onEnvelope(e.detail)).catch(() => {}); });
    net.addEventListener('status', (e) => { if (!e.detail.online) { this.online = false; this.emit('status'); } });
    net.addEventListener('kicked', (e) => this.emit('kicked', e.detail));
    this.#timer = setInterval(() => this.#expire(), 1000);
  }

  destroy() {
    clearInterval(this.#timer);
    this.net.close();
  }

  emit(type, detail = {}) { this.dispatchEvent(new CustomEvent(type, { detail })); }

  save() { return this.persist(this.s); }

  // Все изменения криптографического состояния — строго по очереди.
  #serial(fn) {
    const p = this.#lock.then(fn);
    this.#lock = p.catch(() => {});
    return p;
  }

  // ------------------------------------------------------------ сервер

  async #login(nonce) {
    try {
      const sig = await P.authSignature(this.s.identity, nonce, this.s.handle);
      const r = await this.net.request('login', { handle: this.s.handle, sig });
      this.online = true;
      this.emit('status');
      await this.#serial(() => this.#maintainKeys(r.opkCount));
      this.#flush();
    } catch (e) {
      if (e.code === 'auth') this.emit('fatal', { message: 'Сервер не знает этот аккаунт (возможно, он удалён).' });
    }
  }

  async #maintainKeys(opkCount) {
    const s = this.s;
    if (opkCount < OPK_MIN) {
      const fresh = await P.makeOneTimePrekeys(s.nextOpkId, OPK_BATCH);
      s.nextOpkId += OPK_BATCH;
      for (const k of fresh) s.opks[k.id] = k;
      const ids = Object.keys(s.opks).map(Number).sort((a, b) => a - b);
      for (const id of ids.slice(0, Math.max(0, ids.length - OPK_LOCAL_MAX))) delete s.opks[id];
      await this.save(); // закрытые ключи — на диск до публикации открытых
      await this.net.request('opks', { opks: fresh.map(({ id, pub }) => ({ id, pub })) });
    }
    const cur = s.spks[s.spkCurrent];
    if (Date.now() - cur.created > SPK_ROTATE) {
      const spk = await P.makeSignedPrekey(s.identity, s.nextSpkId++);
      s.spks[spk.id] = spk;
      s.spkCurrent = spk.id;
      await this.save();
      await this.net.request('spk', { spk: { id: spk.id, pub: spk.pub, sig: spk.sig } });
    }
    for (const [id, k] of Object.entries(s.spks)) {
      if (Number(id) !== s.spkCurrent && Date.now() - k.created > SPK_KEEP) delete s.spks[id];
    }
    await this.save();
  }

  // ------------------------------------------------------------ контакты

  async addContact(raw) {
    const handle = String(raw).trim().replace(/^@/, '').toLowerCase();
    if (!HANDLE_RE.test(handle)) throw err('Имя: 3–24 символа — латиница, цифры, «_»');
    if (handle === this.s.handle) throw err('Это ваше имя');
    if (this.s.contacts[handle]) return handle;
    const r = await this.net.request('lookup', { handle });
    if (!r.identity) throw err('Пользователь не найден');
    if (!(await P.verifyIdentity(r.identity))) throw err('Подпись ключей пользователя неверна');
    await this.#serial(async () => {
      if (!this.s.contacts[handle]) this.s.contacts[handle] = newContact(handle, r.identity);
      await this.save();
    });
    this.emit('contacts');
    return handle;
  }

  markRead(handle) {
    const c = this.s.contacts[handle];
    if (c && c.unread) { c.unread = 0; this.save(); this.emit('contacts'); }
  }

  setVerified(handle, v) {
    const c = this.s.contacts[handle];
    if (!c || c.keyChanged) return;
    c.verified = !!v;
    this.#push(c, sys(v ? 'Вы отметили код безопасности как проверенный' : 'Отметка о проверке снята'));
    this.save();
    this.emit('messages', { handle });
  }

  acceptNewKey(handle) {
    return this.#serial(async () => {
      const c = this.s.contacts[handle];
      const k = c && c.keyChanged;
      if (!k) return;
      c.ikSig = k.ikSig;
      c.ikDh = k.ikDh;
      c.ikDhSig = k.ikDhSig;
      const keep = k.sid && c.sessions[k.sid];
      c.sessions = keep ? { [k.sid]: keep } : {};
      c.active = keep ? k.sid : null;
      c.keyChanged = null;
      c.verified = false;
      c.outbox = [];
      this.#push(c, sys('Новый ключ собеседника принят. Сверьте код безопасности.'));
      await this.save();
      this.emit('messages', { handle });
    });
  }

  deleteChat(handle) {
    const c = this.s.contacts[handle];
    if (!c) return;
    c.messages = [];
    c.unread = 0;
    this.save();
    this.emit('messages', { handle });
  }

  deleteContact(handle) {
    return this.#serial(async () => {
      delete this.s.contacts[handle];
      await this.save();
      this.emit('contacts');
    });
  }

  safetyNumber(handle) {
    const c = this.s.contacts[handle];
    const k = c.keyChanged || c;
    const me = this.s.identity;
    return P.safetyNumber(this.s.handle, me.ikSig.pub, me.ikDh.pub, handle, k.ikSig, k.ikDh);
  }

  myFingerprint() {
    return P.fingerprint(this.s.handle, this.s.identity.ikSig.pub, this.s.identity.ikDh.pub);
  }

  deleteAccount() {
    return this.net.request('delete-account');
  }

  // ------------------------------------------------------------ отправка

  sendText(to, text) {
    text = String(text);
    if (!text.trim()) return Promise.resolve();
    if (text.length > MAX_TEXT) return Promise.reject(err('Сообщение слишком длинное'));
    return this.#send(to, { type: 'text', text });
  }

  sendFile(to, { name, type, data }) {
    if (data.length > MAX_FILE) return Promise.reject(err('Файл больше 3 МБ'));
    return this.#send(to, {
      type: 'file',
      file: {
        name: String(name || 'file').slice(0, 200),
        type: String(type || 'application/octet-stream').slice(0, 100),
        size: data.length,
        data: b64(data),
      },
    });
  }

  setTimer(to, ttl) {
    if (!TIMERS.includes(ttl)) return Promise.reject(err('bad timer'));
    return this.#send(to, { type: 'timer', ttl });
  }

  wipeBoth(to) {
    return this.#send(to, { type: 'wipe' });
  }

  retry(to, id) {
    const c = this.s.contacts[to];
    const m = c && c.messages.find((x) => x.id === id && x.dir === 'out');
    if (!m) return Promise.resolve();
    return this.#send(to, { type: m.kind, text: m.text, file: m.file }, m);
  }

  #send(to, body, existing = null) {
    return this.#serial(async () => {
      const c = this.s.contacts[to];
      if (!c) throw err('Нет такого контакта');
      if (c.keyChanged) throw err('Ключ безопасности собеседника изменился. Сверьте код и примите новый ключ.');
      const content = body.type === 'text' || body.type === 'file';
      const id = existing ? existing.id : b64(rand(12));
      const ts = existing ? existing.ts : Date.now();
      const ttl = body.type === 'timer' ? body.ttl : content ? (existing ? existing.ttl || 0 : c.timer) : 0;
      const payload = { ...body, id, ts, ttl };
      let msg = existing;
      if (existing) existing.status = 'sending';
      else if (content) {
        msg = { id, dir: 'out', ts, ttl, kind: body.type, text: body.text, file: body.file, expires: ttl ? ts + ttl * 1000 : null, status: 'sending' };
        this.#push(c, msg);
      } else if (body.type === 'timer') {
        c.timer = ttl;
        this.#push(c, sys(ttl ? `Исчезающие сообщения: ${timerLabel(ttl)} (вы включили)` : 'Вы выключили исчезающие сообщения'));
      } else if (body.type === 'wipe') {
        c.messages = [];
        this.#push(c, sys('Вы удалили историю чата у обоих'));
      }
      try {
        const blob = await this.#encryptFor(c, payload);
        c.outbox.push({ id, blob });
      } catch (e) {
        if (msg) msg.status = 'failed';
        await this.save();
        this.emit('messages', { handle: to });
        throw e;
      }
      // Состояние храповика сохраняется ДО отправки: иначе после сбоя ключ сообщения мог бы повториться.
      await this.save();
      this.emit('messages', { handle: to });
    }).then(() => { this.#flush(); });
  }

  async #encryptFor(c, payload) {
    let st = c.active && c.sessions[c.active];
    if (!st || !st.cks) {
      const r = await this.net.request('bundle', { handle: c.handle });
      const b = r.bundle;
      if (!b) throw err('Пользователь не найден на сервере');
      if (b.ikSig !== c.ikSig || b.ikDh !== c.ikDh) {
        if (!(await P.verifyIdentity(b))) throw err('Подпись ключей собеседника неверна');
        c.keyChanged = { ikSig: b.ikSig, ikDh: b.ikDh, ikDhSig: b.ikDhSig, sid: null };
        c.verified = false;
        this.#push(c, sys('⚠ Ключ безопасности собеседника изменился. Отправка остановлена до проверки.'));
        throw err('Ключ безопасности собеседника изменился. Сверьте код и примите новый ключ.');
      }
      st = await P.initiateSession(this.s.identity, b);
    }
    const [st2, m] = await P.ratchetEncrypt(st, te.encode(JSON.stringify(payload)));
    c.sessions[st2.sid] = st2;
    c.active = st2.sid;
    this.#pruneSessions(c);
    return P.seal(c.ikDh, { from: this.s.handle, m });
  }

  #pruneSessions(c) {
    const ids = Object.keys(c.sessions);
    if (ids.length <= MAX_SESSIONS) return;
    ids.filter((id) => id !== c.active)
      .sort((a, b) => c.sessions[a].created - c.sessions[b].created)
      .slice(0, ids.length - MAX_SESSIONS)
      .forEach((id) => delete c.sessions[id]);
  }

  async #flush() {
    if (!this.online) return;
    if (this.#flushing) { this.#reflush = true; return; }
    this.#flushing = true;
    let changed = false;
    try {
      do {
        this.#reflush = false;
        for (const c of Object.values(this.s.contacts)) {
          while (c.outbox.length) {
            const item = c.outbox[0];
            try {
              await this.net.request('send', { to: c.handle, blob: item.blob });
              this.#setStatus(c, item.id, 'sent');
            } catch (e) {
              if (e.code === 'rate') { setTimeout(() => this.#flush(), 1500); return; }
              if (e.code === 'offline' || e.code === 'timeout') return;
              this.#setStatus(c, item.id, 'failed');
            }
            if (c.outbox[0] === item) c.outbox.shift();
            changed = true;
          }
        }
      } while (this.#reflush);
    } finally {
      this.#flushing = false;
      if (changed) this.save();
    }
  }

  #setStatus(c, id, status) {
    const m = c.messages.find((x) => x.id === id && x.dir === 'out');
    if (!m) return;
    if (status === 'sent' && m.status === 'delivered') return;
    m.status = status;
    this.emit('messages', { handle: c.handle });
  }

  #queueReceipt(handle, id) {
    let q = this.#rcpt.get(handle);
    if (!q) {
      q = [];
      this.#rcpt.set(handle, q);
      setTimeout(() => {
        this.#rcpt.delete(handle);
        this.#send(handle, { type: 'rcpt', ids: q.slice(0, 200) }).catch(() => {});
      }, 400);
    }
    q.push(id);
  }

  // ------------------------------------------------------------ приём

  async #onEnvelope({ id, blob }) {
    let env;
    try {
      env = await P.unseal(this.s.identity, blob);
    } catch {
      this.net.notify('ack', { ids: [id] });
      return;
    }
    const from = env && env.from;
    const m = env && env.m;
    try {
      if (typeof from !== 'string' || !HANDLE_RE.test(from) || from === this.s.handle) throw err('bad sender');
      if (!m || typeof m.sid !== 'string') throw err('bad message');
      let c = this.s.contacts[from];
      let st = c && c.sessions[m.sid];
      let created = null;
      let usedOpk = null;
      let changedKey = null;
      if (!st) {
        const init = m.init;
        if (!init || init.ek !== m.sid) throw err('unknown session');
        if (!(await P.verifyIdentity(init))) throw err('bad identity');
        if (!c || init.ikSig !== c.ikSig || init.ikDh !== c.ikDh) {
          // Имя отправителя — лишь заявление внутри конверта. Новый ключ принимаем,
          // только если сервер подтверждает, что это действительно ключ этого имени.
          const r = await this.net.request('lookup', { handle: from });
          if (!r.identity || r.identity.ikSig !== init.ikSig || r.identity.ikDh !== init.ikDh) throw err('identity mismatch');
          if (!c) created = newContact(from, init);
          else changedKey = { ikSig: init.ikSig, ikDh: init.ikDh, ikDhSig: init.ikDhSig, sid: m.sid };
        }
        st = await P.respondSession(this.s.identity, this.s.spks, this.s.opks, init);
        if (init.opkId !== null && init.opkId !== undefined) usedOpk = init.opkId;
      }
      const [st2, pt] = await P.ratchetDecrypt(st, m);
      const payload = JSON.parse(td.decode(pt));

      // Расшифровка удалась — фиксируем изменения.
      if (created) c = this.s.contacts[from] = created;
      if (changedKey) {
        c.keyChanged = changedKey;
        c.verified = false;
        this.#push(c, sys('⚠ Ключ безопасности собеседника изменился (новое устройство или переустановка?). Сверьте код безопасности.'));
      }
      if (usedOpk !== null) delete this.s.opks[usedOpk];
      c.sessions[st2.sid] = st2;
      c.active = st2.sid;
      this.#pruneSessions(c);
      this.#handlePayload(c, payload);
      await this.save();
      this.emit(created ? 'contacts' : 'messages', { handle: from });
      if (created) this.emit('messages', { handle: from });
    } catch {
      const c = typeof from === 'string' && this.s.contacts[from];
      if (c) {
        this.#push(c, sys('Получено сообщение, которое не удалось расшифровать'));
        await this.save();
        this.emit('messages', { handle: from });
      }
    } finally {
      this.net.notify('ack', { ids: [id] });
    }
  }

  #handlePayload(c, p) {
    if (!p || typeof p !== 'object' || typeof p.id !== 'string' || p.id.length > 40) throw err('bad payload');
    const ttl = TIMERS.includes(p.ttl) ? p.ttl : 0;
    const now = Date.now();
    switch (p.type) {
      case 'text':
      case 'file': {
        if (c.messages.some((x) => x.id === p.id)) return;
        const m = { id: p.id, dir: 'in', ts: now, kind: p.type, expires: ttl ? now + ttl * 1000 : null };
        if (p.type === 'text') {
          if (typeof p.text !== 'string' || p.text.length > MAX_TEXT) throw err('bad text');
          m.text = p.text;
        } else {
          const f = p.file;
          if (!f || typeof f.data !== 'string' || f.data.length > Math.ceil(MAX_FILE * 4 / 3) + 4) throw err('bad file');
          m.file = {
            name: String(f.name || 'file').slice(0, 200),
            type: String(f.type || '').slice(0, 100),
            size: Number(f.size) || 0,
            data: f.data,
          };
        }
        this.#push(c, m);
        c.unread++;
        if (this.s.settings.receipts) this.#queueReceipt(c.handle, p.id);
        this.emit('incoming', { handle: c.handle, message: m });
        break;
      }
      case 'timer':
        c.timer = ttl;
        this.#push(c, sys(ttl ? `Исчезающие сообщения: ${timerLabel(ttl)} (включил собеседник)` : 'Собеседник выключил исчезающие сообщения'));
        break;
      case 'rcpt':
        if (Array.isArray(p.ids)) {
          for (const rid of p.ids.slice(0, 200)) {
            const m = c.messages.find((x) => x.id === rid && x.dir === 'out');
            if (m) m.status = 'delivered';
          }
        }
        break;
      case 'wipe':
        c.messages = [];
        c.unread = 0;
        this.#push(c, sys('Собеседник удалил историю чата у обоих'));
        break;
      default:
        break;
    }
  }

  #push(c, m) {
    c.messages.push(m);
    if (c.messages.length > MAX_HISTORY) c.messages.splice(0, c.messages.length - MAX_HISTORY);
    c.last = m.ts;
  }

  #expire() {
    const now = Date.now();
    let any = false;
    for (const c of Object.values(this.s.contacts)) {
      const before = c.messages.length;
      c.messages = c.messages.filter((m) => !m.expires || m.expires > now);
      if (c.messages.length !== before) {
        any = true;
        this.emit('messages', { handle: c.handle });
      }
    }
    if (any) this.save();
  }
}
