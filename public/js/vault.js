// Локальное хранилище: всё состояние (ключи, контакты, переписка) шифруется
// AES-256-GCM ключом из пароля (PBKDF2-SHA256, 600 000 итераций) и лежит в IndexedDB.
// Ключ хранилища неизвлекаемый и живёт только в памяти открытой вкладки.

import { pbkdf2, rand, b64, unb64, te, td } from './crypto.js';

const DB = 'max-drognev';
const STORE = 'vault';
const KEY = 'main';
const ITER = 600000;
const AD = te.encode('MAX-VAULT-v1');

function openDb() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function tx(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const req = fn(t.objectStore(STORE));
      t.oncomplete = () => resolve(req && req.result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  } finally {
    db.close();
  }
}

const getRec = () => tx('readonly', (s) => s.get(KEY));
const putRec = (v) => tx('readwrite', (s) => s.put(v, KEY));

export async function exists() {
  return !!(await getRec());
}

async function write(vault, json) {
  const iv = rand(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AD }, vault.key, te.encode(json)));
  await putRec({ v: 1, kdf: 'PBKDF2-SHA256', iter: vault.iter, salt: vault.salt, iv: b64(iv), ct });
}

// Сохранения объединяются: если запись уже идёт, сохранится только самый свежий снимок.
let pending = null;
let running = null;

export function save(vault, state) {
  pending = { vault, json: JSON.stringify(state) };
  if (!running) {
    running = (async () => {
      try {
        while (pending) {
          const p = pending;
          pending = null;
          await write(p.vault, p.json);
        }
      } finally {
        running = null;
      }
    })();
  }
  return running;
}

export async function create(pass, state) {
  const salt = rand(16);
  const vault = { key: await pbkdf2(pass, salt, ITER), salt: b64(salt), iter: ITER };
  await save(vault, state);
  return vault;
}

export async function unlock(pass) {
  const rec = await getRec();
  if (!rec) throw new Error('Хранилище не найдено');
  const key = await pbkdf2(pass, unb64(rec.salt), rec.iter);
  let pt;
  try {
    pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(rec.iv), additionalData: AD }, key, rec.ct);
  } catch {
    const e = new Error('Неверный пароль');
    e.code = 'wrongpass';
    throw e;
  }
  return { vault: { key, salt: rec.salt, iter: rec.iter }, state: JSON.parse(td.decode(new Uint8Array(pt))) };
}

export async function rekey(newPass, state) {
  const salt = rand(16);
  const vault = { key: await pbkdf2(newPass, salt, ITER), salt: b64(salt), iter: ITER };
  await save(vault, state);
  return vault;
}

export async function wipe() {
  try { localStorage.clear(); } catch { /* ignore */ }
  try { sessionStorage.clear(); } catch { /* ignore */ }
  await new Promise((resolve) => {
    const r = indexedDB.deleteDatabase(DB);
    r.onsuccess = r.onerror = r.onblocked = () => resolve();
  });
}
