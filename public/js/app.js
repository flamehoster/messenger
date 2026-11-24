// Интерфейс MAX (Drognev).
// Весь DOM строится через createElement/textContent: innerHTML не используется
// (сервер ещё и запрещает его политикой Trusted Types) — XSS через сообщения невозможен.

import { Net } from './net.js';
import { Core, newAccountState, registerAccount, HANDLE_RE, TIMERS, MAX_FILE, timerLabel } from './core.js';
import * as V from './vault.js';
import { unb64 } from './crypto.js';

const app = document.getElementById('app');
const WS_URL = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;
const SVG_NS = 'http://www.w3.org/2000/svg';
const IMG_TYPES = /^image\/(png|jpeg|gif|webp)$/;

let core = null;
let vault = null;
let current = null;
let lastActivity = Date.now();
const els = {};
const blobCache = new Map();

// ------------------------------------------------------------------ DOM-помощники

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}

const ICONS = {
  lock: 'M6 11h12v9H6z M8.5 11V8a3.5 3.5 0 0 1 7 0v3',
  settings: 'M4 7h9 M17 7h3 M4 17h3 M11 17h9 M15 5v4 M9 15v4',
  send: 'M4.5 12L20 4.5 16 20l-4-6.5z M12 13.5L20 4.5',
  clip: 'M19.5 11.5l-7.8 7.8a5 5 0 0 1-7-7l8-8a3.4 3.4 0 0 1 4.8 4.8l-8 8a1.7 1.7 0 0 1-2.4-2.4l7.3-7.3',
  shield: 'M12 3l8 3v6c0 5-3.4 8.3-8 9.5C7.4 20.3 4 17 4 12V6z M8.5 12l2.5 2.5 4.5-4.5',
  back: 'M15 5l-7 7 7 7',
  trash: 'M4 7h16 M9.5 7V4.5h5V7 M6.5 7l1 13h9l1-13',
  timer: 'M12 9v4l2.5 1.5 M12 21a8 8 0 1 0 0-16 8 8 0 0 0 0 16z M9.5 2.5h5',
  plus: 'M12 5v14 M5 12h14',
  key: 'M13.5 10.5a4.5 4.5 0 1 1-1.3-3.2 4.5 4.5 0 0 1 1.3 3.2z M12.2 13.7L20 21.5 M17 18.5l2.2-2.2 M15 16.5l1.5-1.5',
  x: 'M6 6l12 12 M18 6L6 18',
  file: 'M14 3H7v18h10V6z M14 3v3h3',
  warn: 'M12 4L2.5 20h19z M12 10v4 M12 17h.01',
  check: 'M5 12.5l4.5 4.5L19 7.5',
};

function icon(name) {
  const s = document.createElementNS(SVG_NS, 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('aria-hidden', 'true');
  s.setAttribute('class', 'ic');
  const p = document.createElementNS(SVG_NS, 'path');
  p.setAttribute('d', ICONS[name]);
  s.append(p);
  return s;
}

function toast(text, bad = false) {
  const t = h('div', { class: 'toast' + (bad ? ' bad' : ''), role: 'status' }, text);
  document.body.append(t);
  requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, 4000);
}

function modal(title, body, actions = []) {
  const close = () => { ov.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const ov = h('div', { class: 'overlay', onclick: (e) => { if (e.target === ov) close(); } },
    h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('div', { class: 'modal-head' },
        h('h2', {}, title),
        h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Закрыть', onclick: close }, icon('x'))),
      h('div', { class: 'modal-body' }, body),
      actions.length ? h('div', { class: 'modal-actions' }, actions.map((a) => h('button', {
        class: 'btn ' + (a.kind || ''),
        type: 'button',
        onclick: async (e) => {
          const b = e.currentTarget;
          b.disabled = true;
          try { if ((await a.run?.()) !== false) close(); } catch (err) { toast(errText(err), true); } finally { b.disabled = false; }
        },
      }, a.label))) : null));
  document.addEventListener('keydown', onKey);
  document.body.append(ov);
  return close;
}

function errText(e) {
  const map = {
    offline: 'Нет соединения с сервером',
    timeout: 'Сервер не ответил',
    taken: 'Это имя уже занято',
    rate: 'Слишком много запросов — подождите немного',
    handle: 'Недопустимое имя',
    nouser: 'Пользователь не найден',
    full: 'Очередь получателя переполнена',
  };
  return map[e && e.code] || (e && e.message) || String(e);
}

function withTimeout(p, ms, text) {
  return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(text)), ms))]);
}

function hue(s) {
  let x = 0;
  for (const ch of s) x = (x * 31 + ch.codePointAt(0)) >>> 0;
  return x % 360;
}

function avatar(handle, size = '') {
  const el = h('div', { class: 'avatar ' + size }, handle[0].toUpperCase());
  el.style.setProperty('--h', String(hue(handle))); // CSSOM, а не атрибут style: CSP запрещает инлайн-стили
  return el;
}

const pad2 = (n) => String(n).padStart(2, '0');
function fmtTime(ts) { const d = new Date(ts); return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`; }
function fmtDay(ts) {
  const d = new Date(ts);
  const today = new Date();
  const y = new Date(Date.now() - 864e5);
  if (d.toDateString() === today.toDateString()) return 'Сегодня';
  if (d.toDateString() === y.toDateString()) return 'Вчера';
  return d.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', year: d.getFullYear() === today.getFullYear() ? undefined : 'numeric' });
}
function fmtLeft(exp) {
  const s = Math.max(0, Math.round((exp - Date.now()) / 1000));
  if (s < 60) return `${s} с`;
  if (s < 3600) return `${Math.ceil(s / 60)} мин`;
  if (s < 86400) return `${Math.ceil(s / 3600)} ч`;
  return `${Math.ceil(s / 86400)} д`;
}
function fmtSize(n) {
  if (n < 1024) return `${n} Б`;
  if (n < 1048576) return `${(n / 1024).toFixed(0)} КБ`;
  return `${(n / 1048576).toFixed(1)} МБ`;
}

// Грубая оценка стойкости пароля в битах.
function entropy(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9Ѐ-ӿ]/.test(pw)) pool += 33;
  if (/[Ѐ-ӿ]/.test(pw)) pool += 66;
  const uniq = new Set(pw).size;
  return Math.round(pw.length * Math.log2(Math.max(pool, 1)) * Math.min(1, (uniq / Math.max(pw.length, 1)) * 1.6));
}

// ------------------------------------------------------------------ запуск

function fatal(text) {
  app.replaceChildren(h('div', { class: 'auth' }, h('div', { class: 'auth-card' }, logo(),
    h('div', { class: 'notice bad' }, icon('warn'), h('span', {}, text)),
    h('button', { class: 'btn wide', onclick: () => location.reload() }, 'Обновить страницу'))));
}

async function boot() {
  if (!window.isSecureContext || !globalThis.crypto || !crypto.subtle) {
    return fatal('Откройте мессенджер по HTTPS (или на localhost): без защищённого соединения браузер не даёт доступ к криптографии.');
  }
  try {
    await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  } catch {
    return fatal('Браузер не поддерживает X25519/Ed25519. Обновите его до актуальной версии (Chrome, Edge, Firefox или Safari).');
  }
  if (navigator.locks) {
    navigator.locks.request('max-drognev-tab', { ifAvailable: true }, (lock) => {
      if (!lock) {
        fatal('MAX уже открыт в другой вкладке. Закройте её: две вкладки одновременно могут повредить ключи шифрования.');
        return undefined;
      }
      start();
      return new Promise(() => {}); // держим блокировку, пока вкладка открыта
    });
  } else {
    start();
  }
}

async function start() {
  try { await navigator.storage?.persist?.(); } catch { /* ignore */ }
  try {
    if (await V.exists()) screenUnlock(); else screenSetup();
  } catch {
    fatal('Браузер запретил локальное хранилище (возможно, это приватное окно).');
  }
}

function logo() {
  return h('div', { class: 'logo' }, h('img', { src: 'icon.svg', alt: '' }),
    h('div', {}, h('div', { class: 'logo-title' }, 'MAX'), h('div', { class: 'logo-sub' }, '(Drognev)')));
}

function authShell(...content) {
  app.replaceChildren(h('div', { class: 'auth' }, h('div', { class: 'auth-card' }, logo(), ...content)));
}

function field(label, input, hint) {
  return h('label', { class: 'field' }, h('span', { class: 'label' }, label), input, hint ? h('span', { class: 'hint' }, hint) : null);
}

function meterFor(input) {
  const bar = h('span');
  const txt = h('span', { class: 'meter-txt' });
  const update = () => {
    const bits = entropy(input.value);
    const lvl = !input.value ? 0 : bits < 50 ? 1 : bits < 75 ? 2 : 3;
    bar.style.width = `${Math.min(100, (bits / 100) * 100)}%`;
    bar.dataset.lvl = lvl;
    txt.textContent = input.value ? ['', 'слабый', 'нормальный', 'сильный'][lvl] + ` · ≈${bits} бит` : '';
  };
  input.addEventListener('input', update);
  return h('div', { class: 'meter' }, h('div', { class: 'meter-bar' }, bar), txt);
}

function screenSetup() {
  const handle = h('input', { autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', maxlength: '24', placeholder: 'например, ivan_d', required: true });
  const pass = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Не меньше 12 символов', required: true });
  const pass2 = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  const err = h('div', { class: 'err', role: 'alert' });
  const btn = h('button', { class: 'btn primary wide', type: 'submit' }, 'Создать аккаунт');
  const form = h('form', {
    class: 'form',
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = '';
      const name = handle.value.trim().toLowerCase().replace(/^@/, '');
      if (!HANDLE_RE.test(name)) { err.textContent = 'Имя: 3–24 символа — латиница, цифры, «_»'; return; }
      if (pass.value.length < 12) { err.textContent = 'Пароль должен быть не короче 12 символов'; return; }
      if (entropy(pass.value) < 50) { err.textContent = 'Пароль слишком простой — добавьте слов, цифр или символов'; return; }
      if (pass.value !== pass2.value) { err.textContent = 'Пароли не совпадают'; return; }
      btn.disabled = true;
      let net = null;
      try {
        btn.textContent = 'Генерация ключей…';
        const state = await newAccountState(name);
        btn.textContent = 'Регистрация…';
        net = new Net(WS_URL);
        const ch = net.nextChallenge();
        net.connect();
        const nonce = await withTimeout(ch, 15000, 'Сервер недоступен');
        await registerAccount(net, state, nonce);
        net.close();
        btn.textContent = 'Шифрование хранилища…';
        const v = await V.create(pass.value, state);
        pass.value = '';
        pass2.value = '';
        enterApp(state, v);
      } catch (ex) {
        if (net) net.close();
        err.textContent = errText(ex);
        btn.disabled = false;
        btn.textContent = 'Создать аккаунт';
      }
    },
  },
  field('Имя пользователя', handle, 'Его вы сообщаете собеседникам. Телефон и почта не нужны.'),
  field('Пароль хранилища', pass, 'Шифрует ключи и переписку на этом устройстве. Восстановить его невозможно — запомните.'),
  meterFor(pass),
  field('Повторите пароль', pass2),
  err, btn);

  authShell(
    h('h1', {}, 'Новый аккаунт'),
    form,
    h('ul', { class: 'features' },
      h('li', {}, icon('shield'), 'Сквозное шифрование: X3DH + Double Ratchet, новый ключ на каждое сообщение'),
      h('li', {}, icon('lock'), 'Сервер не видит текст, файлы и даже отправителя'),
      h('li', {}, icon('timer'), 'Исчезающие сообщения и автоблокировка')),
  );
  handle.focus();
}

function screenUnlock() {
  const pass = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Пароль хранилища', required: true });
  const err = h('div', { class: 'err', role: 'alert' });
  const btn = h('button', { class: 'btn primary wide', type: 'submit' }, 'Разблокировать');
  const form = h('form', {
    class: 'form',
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = '';
      btn.disabled = true;
      btn.textContent = 'Проверка…';
      try {
        const { vault: v, state } = await V.unlock(pass.value);
        pass.value = '';
        localStorage.removeItem('max.fails');
        enterApp(state, v);
        return;
      } catch (ex) {
        if (ex.code === 'wrongpass') {
          const fails = Number(localStorage.getItem('max.fails') || 0) + 1;
          localStorage.setItem('max.fails', String(fails));
          const lim = Number(localStorage.getItem('max.wipeAfter') || 0);
          if (lim && fails >= lim) {
            await V.wipe();
            location.reload();
            return;
          }
          err.textContent = 'Неверный пароль' + (lim ? ` — до самоуничтожения осталось попыток: ${lim - fails}` : '');
        } else {
          err.textContent = errText(ex);
        }
      }
      btn.disabled = false;
      btn.textContent = 'Разблокировать';
      pass.select();
    },
  }, field('Пароль', pass), err, btn);

  authShell(
    h('h1', {}, 'Хранилище заблокировано'),
    h('p', { class: 'muted' }, 'Ключи и переписка зашифрованы на этом устройстве.'),
    form,
    h('button', {
      class: 'link danger',
      type: 'button',
      onclick: () => modal('Стереть данные на устройстве?', h('p', {}, 'Ключи и вся переписка будут удалены с этого устройства без возможности восстановления. Аккаунт на сервере останется, но войти в него будет нельзя.'), [
        { label: 'Отмена' },
        { label: 'Стереть всё', kind: 'danger', run: async () => { await V.wipe(); location.reload(); } },
      ]),
    }, 'Забыли пароль? Стереть данные'),
  );
  pass.focus();
}

function enterApp(state, v) {
  vault = v;
  const net = new Net(WS_URL);
  core = new Core(state, { net, persist: (s) => V.save(vault, s) });
  core.addEventListener('status', renderStatus);
  core.addEventListener('contacts', () => { renderContacts(); if (current && !core.s.contacts[current]) { current = null; renderChat(); } });
  core.addEventListener('messages', (e) => {
    if (e.detail.handle === current && !document.hidden) core.s.contacts[current].unread = 0;
    renderContacts();
    if (e.detail.handle === current) renderChat();
  });
  core.addEventListener('kicked', (e) => fatal(e.detail.code === 4001
    ? 'Аккаунт открыт в другом окне или на другом устройстве. Здесь сеанс завершён.'
    : 'Аккаунт удалён.'));
  core.addEventListener('fatal', (e) => toast(e.detail.message, true));
  try { localStorage.setItem('max.wipeAfter', String(state.settings.wipeAfter || 0)); } catch { /* ignore */ }
  renderMain();
  net.connect();
  setupGuards();
}

async function lock() {
  if (core) { try { await V.save(vault, core.s); } catch { /* ignore */ } }
  location.reload(); // полная перезагрузка гарантированно стирает ключи из памяти
}

function setupGuards() {
  const touch = () => { lastActivity = Date.now(); };
  for (const ev of ['pointerdown', 'keydown', 'touchstart', 'wheel']) addEventListener(ev, touch, { passive: true });
  setInterval(() => {
    if (Date.now() - lastActivity > core.s.settings.autoLock * 1000) lock();
    for (const el of document.querySelectorAll('[data-exp]')) el.lastChild.textContent = fmtLeft(Number(el.dataset.exp));
  }, 1000);
  const privacy = (on) => document.body.classList.toggle('privacy', on && core.s.settings.blurOnHide);
  document.addEventListener('visibilitychange', () => {
    privacy(document.hidden);
    if (!document.hidden && current) core.markRead(current);
  });
  addEventListener('blur', () => privacy(true));
  addEventListener('focus', () => privacy(false));
  addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.shiftKey && e.code === 'KeyL') { e.preventDefault(); lock(); }
  });
}

// ------------------------------------------------------------------ главный экран

function renderMain() {
  els.status = h('span', { class: 'dot' });
  els.contacts = h('ul', { class: 'contacts' });
  els.chat = h('main', { class: 'chat' });
  const input = h('input', { placeholder: 'Новый чат: имя собеседника', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', 'aria-label': 'Имя собеседника' });
  const add = h('form', {
    class: 'new-chat',
    onsubmit: async (e) => {
      e.preventDefault();
      if (!input.value.trim()) return;
      try {
        const hd = await core.addContact(input.value);
        input.value = '';
        openChat(hd);
      } catch (ex) { toast(errText(ex), true); }
    },
  }, input, h('button', { class: 'icon-btn accent', type: 'submit', title: 'Начать чат', 'aria-label': 'Начать чат' }, icon('plus')));

  els.layout = h('div', { class: 'layout' },
    h('aside', { class: 'sidebar' },
      h('header', { class: 'side-head' },
        h('img', { class: 'brand-ic', src: 'icon.svg', alt: '' }),
        h('div', { class: 'brand' },
          h('div', {}, h('b', {}, 'MAX'), h('span', { class: 'muted' }, ' (Drognev)')),
          h('div', { class: 'me' }, els.status, '@' + core.s.handle)),
        h('button', { class: 'icon-btn', title: 'Настройки', 'aria-label': 'Настройки', onclick: openSettings }, icon('settings')),
        h('button', { class: 'icon-btn', title: 'Заблокировать (Ctrl+Shift+L)', 'aria-label': 'Заблокировать', onclick: lock }, icon('lock'))),
      add,
      els.contacts,
      h('div', { class: 'side-foot' }, icon('shield'), 'Сквозное шифрование. Сервер не видит переписку.')),
    els.chat);
  app.replaceChildren(els.layout);
  renderStatus();
  renderContacts();
  renderChat();
}

function renderStatus() {
  if (!els.status) return;
  els.status.classList.toggle('on', core.online);
  els.status.title = core.online ? 'Подключено' : 'Нет соединения';
}

function preview(c) {
  const m = [...c.messages].reverse().find((x) => x.kind !== 'system');
  if (!m) return c.keyChanged ? 'Ключ безопасности изменился' : 'Нет сообщений';
  const p = m.dir === 'out' ? 'Вы: ' : '';
  return p + (m.kind === 'file' ? `📎 ${m.file.name}` : m.text.replace(/\s+/g, ' ').slice(0, 80));
}

function renderContacts() {
  if (!els.contacts) return;
  const list = Object.values(core.s.contacts).sort((a, b) => b.last - a.last);
  let unread = 0;
  els.contacts.replaceChildren(...list.map((c) => {
    unread += c.unread;
    return h('li', {}, h('button', {
      class: 'contact' + (c.handle === current ? ' active' : ''),
      onclick: () => openChat(c.handle),
    },
    avatar(c.handle),
    h('div', { class: 'c-main' },
      h('div', { class: 'c-top' },
        h('span', { class: 'c-name' }, '@' + c.handle),
        c.verified ? h('span', { class: 'v-ok', title: 'Ключ проверен' }, icon('check')) : null,
        c.keyChanged ? h('span', { class: 'v-warn', title: 'Ключ изменился' }, icon('warn')) : null,
        h('span', { class: 'c-time' }, c.messages.length ? fmtTime(c.last) : '')),
      h('div', { class: 'c-bottom' },
        h('span', { class: 'c-prev' }, preview(c)),
        c.unread ? h('span', { class: 'badge-n' }, String(c.unread)) : null))));
  }));
  if (!list.length) {
    els.contacts.append(h('li', { class: 'empty-list' }, 'Чатов пока нет. Введите имя собеседника выше.'));
  }
  document.title = unread ? `(${unread}) MAX (Drognev)` : 'MAX (Drognev)';
}

function openChat(handle) {
  current = handle;
  core.markRead(handle);
  renderContacts();
  renderChat();
  els.composer?.querySelector('textarea')?.focus();
}

function blobUrl(m) {
  let u = blobCache.get(m.id);
  if (!u) {
    // Не-изображения отдаются как octet-stream: такой blob нельзя открыть как страницу
    // в нашем источнике (защита от HTML/SVG-вложений с кодом).
    const type = IMG_TYPES.test(m.file.type) ? m.file.type : 'application/octet-stream';
    u = URL.createObjectURL(new Blob([unb64(m.file.data)], { type }));
    blobCache.set(m.id, u);
  }
  return u;
}

function renderFile(m) {
  const f = m.file;
  const url = blobUrl(m);
  if (IMG_TYPES.test(f.type)) {
    return h('a', { class: 'img-link', href: url, download: f.name, title: 'Скачать' }, h('img', { class: 'att-img', src: url, alt: f.name }));
  }
  return h('a', { class: 'file', href: url, download: f.name },
    icon('file'), h('div', {}, h('div', { class: 'fname' }, f.name), h('div', { class: 'fsize' }, fmtSize(f.size))));
}

function statusEl(m) {
  if (m.status === 'failed') {
    return h('button', { class: 'st failed', type: 'button', onclick: () => core.retry(current, m.id).catch((e) => toast(errText(e), true)) }, 'не отправлено · повторить');
  }
  const map = { sending: ['…', 'Отправляется'], sent: ['✓', 'На сервере'], delivered: ['✓✓', 'Доставлено'] };
  const [t, title] = map[m.status] || ['', ''];
  return h('span', { class: 'st ' + m.status, title }, t);
}

function renderMessage(m) {
  if (m.kind === 'system') return h('div', { class: 'sys' }, h('span', {}, m.text));
  const meta = h('div', { class: 'meta' });
  if (m.expires) meta.append(h('span', { class: 'ttl', 'data-exp': m.expires, title: 'Исчезнет через' }, icon('timer'), h('span', {}, fmtLeft(m.expires))));
  meta.append(h('span', {}, fmtTime(m.ts)));
  if (m.dir === 'out') meta.append(statusEl(m));
  return h('div', { class: 'row ' + m.dir },
    h('div', { class: 'bubble' + (m.kind === 'file' ? ' has-file' : '') },
      m.kind === 'file' && m.file ? renderFile(m) : null,
      m.text ? h('div', { class: 'text' }, m.text) : null,
      meta));
}

function makeComposer(handle) {
  const ta = h('textarea', { rows: '1', placeholder: 'Сообщение', spellcheck: 'false', autocomplete: 'off', autocorrect: 'off', maxlength: '20000', 'aria-label': 'Сообщение' });
  const fileIn = h('input', { type: 'file', hidden: true });
  const autosize = () => { ta.style.height = 'auto'; ta.style.height = `${Math.min(ta.scrollHeight, 180)}px`; };
  const send = async () => {
    const text = ta.value;
    if (!text.trim()) return;
    ta.value = '';
    autosize();
    try { await core.sendText(handle, text); } catch (e) { toast(errText(e), true); }
  };
  ta.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); }
  });
  ta.addEventListener('input', autosize);
  fileIn.addEventListener('change', async () => {
    const f = fileIn.files[0];
    fileIn.value = '';
    if (!f) return;
    if (f.size > MAX_FILE) { toast('Файл больше 3 МБ', true); return; }
    try { await core.sendFile(handle, { name: f.name, type: f.type, data: new Uint8Array(await f.arrayBuffer()) }); } catch (e) { toast(errText(e), true); }
  });
  const form = h('form', { class: 'composer', onsubmit: (e) => { e.preventDefault(); send(); } },
    fileIn,
    h('button', { type: 'button', class: 'icon-btn', title: 'Прикрепить файл (до 3 МБ)', 'aria-label': 'Прикрепить файл', onclick: () => fileIn.click() }, icon('clip')),
    ta,
    h('button', { class: 'send', type: 'submit', title: 'Отправить', 'aria-label': 'Отправить' }, icon('send')));
  form.dataset.handle = handle;
  return form;
}

function renderChat() {
  const box = els.chat;
  if (!box) return;
  const c = current && core.s.contacts[current];
  els.layout.classList.toggle('in-chat', !!c);
  if (!c) {
    els.composer = null;
    for (const u of blobCache.values()) URL.revokeObjectURL(u);
    blobCache.clear();
    box.replaceChildren(h('div', { class: 'empty' },
      h('img', { src: 'icon.svg', alt: '' }),
      h('h2', {}, 'Защищённый мессенджер'),
      h('p', {}, 'Сообщения шифруются на вашем устройстве. Для каждого сообщения — новый ключ (Double Ratchet), поэтому даже утечка ключей не раскроет прошлую переписку.'),
      h('p', { class: 'muted' }, 'Сверьте код безопасности с собеседником при встрече или по видеосвязи — так вы исключите подмену ключей.')));
    return;
  }

  const prev = box.querySelector('.messages');
  const stick = !prev || prev.dataset.handle !== c.handle || prev.scrollHeight - prev.scrollTop - prev.clientHeight < 120;
  const prevTop = prev ? prev.scrollTop : 0;

  const timerSel = h('select', {
    class: 'timer',
    title: 'Исчезающие сообщения',
    'aria-label': 'Исчезающие сообщения',
    onchange: async () => {
      try { await core.setTimer(c.handle, Number(timerSel.value)); } catch (e) { toast(errText(e), true); renderChat(); }
    },
  }, TIMERS.map((t) => h('option', { value: t, selected: t === c.timer }, t ? `⏱ ${timerLabel(t)}` : '⏱ выкл')));

  const header = h('header', { class: 'chat-head' },
    h('button', { class: 'icon-btn back', 'aria-label': 'Назад', onclick: () => { current = null; renderChat(); renderContacts(); } }, icon('back')),
    avatar(c.handle),
    h('div', { class: 'who' },
      h('div', { class: 'name' }, '@' + c.handle),
      h('button', { class: 'vbadge ' + (c.keyChanged ? 'bad' : c.verified ? 'ok' : 'warn'), onclick: () => openSafety(c.handle) },
        c.keyChanged ? 'Ключ изменился!' : c.verified ? 'Ключ проверен' : 'Не проверен — сверить код')),
    timerSel,
    h('button', { class: 'icon-btn', title: 'Код безопасности', 'aria-label': 'Код безопасности', onclick: () => openSafety(c.handle) }, icon('key')),
    h('button', { class: 'icon-btn', title: 'Удалить', 'aria-label': 'Удалить', onclick: () => openDelete(c.handle) }, icon('trash')));

  const banner = c.keyChanged ? h('div', { class: 'banner' }, icon('warn'),
    h('div', {}, h('b', {}, 'Ключ безопасности собеседника изменился.'), ' Это бывает при переустановке приложения — или при попытке перехвата. Сверьте новый код, прежде чем продолжать.'),
    h('button', { class: 'btn small', onclick: () => openSafety(c.handle) }, 'Сверить код')) : null;

  const list = h('div', { class: 'messages', role: 'log', 'aria-live': 'polite' });
  list.dataset.handle = c.handle;
  let day = '';
  const used = new Set();
  for (const m of c.messages) {
    const d = fmtDay(m.ts);
    if (d !== day) { day = d; list.append(h('div', { class: 'day' }, h('span', {}, d))); }
    if (m.kind === 'file') used.add(m.id);
    list.append(renderMessage(m));
  }
  if (!c.messages.length) {
    list.append(h('div', { class: 'sys' }, h('span', {}, 'Начало зашифрованного чата. Сообщения видите только вы и собеседник.')));
  }
  for (const [id, u] of blobCache) if (!used.has(id)) { URL.revokeObjectURL(u); blobCache.delete(id); }

  if (!els.composer || els.composer.dataset.handle !== c.handle) els.composer = makeComposer(c.handle);
  box.replaceChildren(header, banner || '', list, els.composer);
  list.scrollTop = stick ? list.scrollHeight : prevTop;
}

// ------------------------------------------------------------------ окна

async function openSafety(handle) {
  const c = core.s.contacts[handle];
  if (!c) return;
  const num = await core.safetyNumber(handle);
  const grid = h('div', { class: 'sn-grid' }, num.match(/.{5}/g).map((g) => h('span', {}, g)));
  const body = h('div', {},
    h('p', {}, `Сравните эти 60 цифр с цифрами на устройстве @${handle} — лично или по видеосвязи. Если они совпадают, между вами нет посредника.`),
    grid,
    c.keyChanged ? h('div', { class: 'notice bad' }, icon('warn'), h('span', {}, 'Это код для НОВОГО ключа собеседника. Примите ключ только после сверки.')) : null);
  const actions = c.keyChanged
    ? [{ label: 'Отмена' }, { label: 'Код совпадает — принять новый ключ', kind: 'primary', run: () => core.acceptNewKey(handle) }]
    : c.verified
      ? [{ label: 'Снять отметку', run: () => core.setVerified(handle, false) }, { label: 'Закрыть', kind: 'primary' }]
      : [{ label: 'Закрыть' }, { label: 'Цифры совпадают', kind: 'primary', run: () => core.setVerified(handle, true) }];
  modal('Код безопасности', body, actions);
}

function openDelete(handle) {
  modal('Удаление', h('p', {}, `Что сделать с чатом @${handle}?`), [
    { label: 'Очистить у меня', run: () => core.deleteChat(handle) },
    { label: 'Очистить у обоих', kind: 'danger', run: () => core.wipeBoth(handle) },
    { label: 'Удалить контакт', kind: 'danger', run: async () => { await core.deleteContact(handle); current = null; renderChat(); } },
  ]);
}

function openSettings() {
  const st = core.s.settings;
  const sel = (value, options, onchange) => {
    const s = h('select', { onchange: () => onchange(Number(s.value)) }, options.map(([v, l]) => h('option', { value: v, selected: v === value }, l)));
    return s;
  };
  const check = (value, onchange) => {
    const i = h('input', { type: 'checkbox', checked: value, onchange: () => onchange(i.checked) });
    return i;
  };
  const set = (k, v) => {
    st[k] = v;
    core.save();
    if (k === 'wipeAfter') { try { localStorage.setItem('max.wipeAfter', String(v)); } catch { /* ignore */ } }
  };

  const fp = h('div', { class: 'sn-grid small' }, '…');
  core.myFingerprint().then((n) => fp.replaceChildren(...n.match(/.{5}/g).map((g) => h('span', {}, g))));

  const cur = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Текущий пароль' });
  const np = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Новый пароль (от 12 символов)' });
  const np2 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Повторите новый пароль' });
  const pErr = h('div', { class: 'err' });
  const pBtn = h('button', { class: 'btn', type: 'submit' }, 'Сменить пароль');
  const passForm = h('form', {
    class: 'form tight',
    onsubmit: async (e) => {
      e.preventDefault();
      pErr.textContent = '';
      if (np.value.length < 12 || entropy(np.value) < 50) { pErr.textContent = 'Новый пароль слишком короткий или простой'; return; }
      if (np.value !== np2.value) { pErr.textContent = 'Пароли не совпадают'; return; }
      pBtn.disabled = true;
      try {
        await V.unlock(cur.value);
        vault = await V.rekey(np.value, core.s);
        cur.value = np.value = np2.value = '';
        toast('Пароль изменён');
      } catch (ex) {
        pErr.textContent = ex.code === 'wrongpass' ? 'Текущий пароль неверен' : errText(ex);
      }
      pBtn.disabled = false;
    },
  }, cur, np, meterFor(np), np2, pErr, pBtn);

  const body = h('div', { class: 'settings' },
    h('section', {},
      h('h3', {}, 'Защита устройства'),
      h('label', { class: 'row-set' }, h('span', {}, 'Автоблокировка при бездействии'),
        sel(st.autoLock, [[60, '1 мин'], [300, '5 мин'], [900, '15 мин'], [3600, '1 час']], (v) => set('autoLock', v))),
      h('label', { class: 'row-set' }, h('span', {}, 'Размывать экран, когда окно неактивно'), check(st.blurOnHide, (v) => set('blurOnHide', v))),
      h('label', { class: 'row-set' }, h('span', {}, 'Стереть всё после неверных паролей'),
        sel(st.wipeAfter || 0, [[0, 'выкл'], [5, '5 попыток'], [10, '10 попыток'], [20, '20 попыток']], (v) => set('wipeAfter', v))),
      h('p', { class: 'hint' }, 'Быстрая блокировка: Ctrl+Shift+L.')),
    h('section', {},
      h('h3', {}, 'Приватность'),
      h('label', { class: 'row-set' }, h('span', {}, 'Отправлять отчёты о доставке (✓✓)'), check(st.receipts, (v) => set('receipts', v)))),
    h('section', {},
      h('h3', {}, 'Ваш отпечаток ключа'),
      h('p', { class: 'hint' }, 'Половина кода безопасности, которая относится к вам.'),
      fp),
    h('section', {}, h('h3', {}, 'Пароль хранилища'), passForm),
    h('section', {},
      h('h3', {}, 'Опасная зона'),
      h('button', {
        class: 'btn danger',
        type: 'button',
        onclick: () => {
          const conf = h('input', { placeholder: core.s.handle, autocomplete: 'off', spellcheck: 'false' });
          modal('Удалить аккаунт навсегда?', h('div', {},
            h('p', {}, 'Аккаунт будет удалён с сервера, а ключи и переписка — с этого устройства. Отменить это нельзя.'),
            field(`Введите «${core.s.handle}» для подтверждения`, conf)), [
            { label: 'Отмена' },
            {
              label: 'Удалить навсегда',
              kind: 'danger',
              run: async () => {
                if (conf.value.trim() !== core.s.handle) { toast('Имя введено неверно', true); return false; }
                await core.deleteAccount();
                await V.wipe();
                location.reload();
                return true;
              },
            },
          ]);
        },
      }, 'Удалить аккаунт и все данные')),
    h('section', {},
      h('h3', {}, 'Как вас защищает MAX'),
      h('ul', { class: 'about' },
        h('li', {}, 'X3DH + Double Ratchet (X25519, Ed25519, HKDF-SHA256, AES-256-GCM): прямая секретность и самовосстановление после компрометации.'),
        h('li', {}, 'Запечатанный отправитель: сервер видит только получателя, но не знает, от кого сообщение.'),
        h('li', {}, 'Длина сообщений выравнивается — по размеру шифротекста не угадать содержание.'),
        h('li', {}, 'Никаких телефонов, почты, контактов, журналов и IP-адресов на сервере.'),
        h('li', {}, 'Локальные данные зашифрованы паролем (PBKDF2, 600 000 итераций).'),
        h('li', {}, 'Строгая CSP и Trusted Types, никаких внешних скриптов, трекеров и шрифтов.'))));
  modal('Настройки', body);
}

boot();
