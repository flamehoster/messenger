// Транспорт: WebSocket с запросами/ответами и автопереподключением.

function codeError(code) {
  const e = new Error(code);
  e.code = code;
  return e;
}

export class Net extends EventTarget {
  constructor(url) {
    super();
    this.url = url;
    this.ws = null;
    this.rid = 0;
    this.pending = new Map();
    this.closed = false;
    this.backoff = 1000;
    this.waiters = [];
  }

  emit(type, detail = {}) { this.dispatchEvent(new CustomEvent(type, { detail })); }

  connect() {
    if (this.closed) return;
    const ws = new WebSocket(this.url);
    this.ws = ws;
    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') return;
      let m;
      try { m = JSON.parse(ev.data); } catch { return; }
      if (m.t === 'challenge') {
        this.backoff = 1000;
        const w = this.waiters;
        this.waiters = [];
        w.forEach((f) => f(m.nonce));
        this.emit('challenge', { nonce: m.nonce });
      } else if (m.t === 'res') {
        const p = this.pending.get(m.rid);
        if (!p) return;
        this.pending.delete(m.rid);
        clearTimeout(p.timer);
        if (m.ok) p.resolve(m); else p.reject(codeError(m.error || 'error'));
      } else if (m.t === 'msg') {
        this.emit('msg', m);
      }
    };
    ws.onclose = (ev) => {
      if (this.ws === ws) this.ws = null;
      for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(codeError('offline')); }
      this.pending.clear();
      this.emit('status', { online: false, code: ev.code });
      if (ev.code === 4001 || ev.code === 4003) {
        this.closed = true;
        this.emit('kicked', { code: ev.code });
        return;
      }
      if (!this.closed) {
        const delay = this.backoff * (0.75 + Math.random() * 0.5);
        this.backoff = Math.min(this.backoff * 2, 30000);
        setTimeout(() => this.connect(), delay);
      }
    };
    ws.onerror = () => {};
  }

  nextChallenge() {
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  request(t, data = {}, timeout = 30000) {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== 1) return reject(codeError('offline'));
      const rid = ++this.rid;
      const timer = setTimeout(() => { this.pending.delete(rid); reject(codeError('timeout')); }, timeout);
      this.pending.set(rid, { resolve, reject, timer });
      this.ws.send(JSON.stringify({ ...data, t, rid }));
    });
  }

  notify(t, data = {}) {
    if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify({ ...data, t }));
  }

  close() {
    this.closed = true;
    if (this.ws) this.ws.close();
  }
}
