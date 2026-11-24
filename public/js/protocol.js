// Протокол MAX (Drognev): X3DH + Double Ratchet + «запечатанный отправитель».
//
//  * X3DH — асинхронное установление общего секрета по опубликованным ключам
//    (ключ личности, подписанный предключ, одноразовый предключ).
//  * Double Ratchet — новый ключ для каждого сообщения: прямая секретность
//    (утечка ключей сегодня не раскрывает вчерашние сообщения) и самовосстановление
//    (после утечки защита возвращается после следующего обмена репликами).
//  * Запечатанный отправитель — имя отправителя лежит внутри шифротекста,
//    сервер видит только получателя.
//
// Все ключи в состоянии хранятся строками base64url, поэтому состояние — обычный JSON.

import * as c from './crypto.js';

const { b64, unb64, te } = c;
const ZERO = new Uint8Array(32);
const FF = new Uint8Array(32).fill(0xff);
const MAX_SKIP = 1000;
const MAX_STORED_SKIPPED = 2000;

const enc = (kp) => ({ pub: b64(kp.pub), priv: b64(kp.priv) });
const key32 = (s) => { const k = unb64(s); if (k.length !== 32) throw new Error('bad key'); return k; };

// ---------------------------------------------------------------- ключи

export async function createIdentity() {
  const ikSig = await c.genSig();
  const ikDh = await c.genDH();
  const ikDhSig = await c.sign(ikSig.priv, c.concat(te.encode('MAX-IKDH'), ikDh.pub));
  return { ikSig: enc(ikSig), ikDh: enc(ikDh), ikDhSig: b64(ikDhSig) };
}

export async function makeSignedPrekey(identity, id) {
  const k = await c.genDH();
  const sig = await c.sign(unb64(identity.ikSig.priv), c.concat(te.encode('MAX-SPK'), c.u32(id), k.pub));
  return { id, pub: b64(k.pub), priv: b64(k.priv), sig: b64(sig), created: Date.now() };
}

export async function makeOneTimePrekeys(startId, n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const k = await c.genDH();
    out.push({ id: startId + i, pub: b64(k.pub), priv: b64(k.priv) });
  }
  return out;
}

export function publicBundle(identity, spk, opks) {
  return {
    ikSig: identity.ikSig.pub,
    ikDh: identity.ikDh.pub,
    ikDhSig: identity.ikDhSig,
    spk: { id: spk.id, pub: spk.pub, sig: spk.sig },
    opks: opks.map(({ id, pub }) => ({ id, pub })),
  };
}

// Ключ DH должен быть подписан ключом подписи того же пользователя.
export async function verifyIdentity(id) {
  try {
    return await c.verify(key32(id.ikSig), unb64(id.ikDhSig), c.concat(te.encode('MAX-IKDH'), key32(id.ikDh)));
  } catch {
    return false;
  }
}

export async function verifyBundle(b) {
  try {
    if (!(await verifyIdentity(b))) return false;
    if (!Number.isInteger(b.spk.id)) return false;
    return await c.verify(key32(b.ikSig), unb64(b.spk.sig), c.concat(te.encode('MAX-SPK'), c.u32(b.spk.id), key32(b.spk.pub)));
  } catch {
    return false;
  }
}

export async function authSignature(identity, nonce, handle) {
  const msg = c.concat(te.encode('MAX-AUTH-v1'), unb64(nonce), te.encode(handle));
  return b64(await c.sign(unb64(identity.ikSig.priv), msg));
}

// ---------------------------------------------------------------- KDF

async function kdfRK(rk, dhOut) {
  const o = await c.hkdf(dhOut, rk, 'MAX-DR-RK', 64);
  return [o.slice(0, 32), o.slice(32)];
}

async function kdfCK(ck) {
  return [await c.hmac(ck, Uint8Array.of(2)), await c.hmac(ck, Uint8Array.of(1))]; // [следующий CK, ключ сообщения]
}

async function msgKeys(mk) {
  const o = await c.hkdf(mk, ZERO, 'MAX-DR-MK', 44);
  return [o.slice(0, 32), o.slice(32)];
}

function hdrBytes(h) {
  return c.concat(key32(h.dh), c.u32(h.pn), c.u32(h.n));
}

// ---------------------------------------------------------------- X3DH

export async function initiateSession(identity, bundle) {
  if (!(await verifyBundle(bundle))) throw new Error('Подпись ключей собеседника неверна');
  const ek = await c.genDH();
  const myDh = unb64(identity.ikDh.priv);
  const spk = key32(bundle.spk.pub);
  const theirIk = key32(bundle.ikDh);
  const parts = [FF, await c.dh(myDh, spk), await c.dh(ek.priv, theirIk), await c.dh(ek.priv, spk)];
  if (bundle.opk) parts.push(await c.dh(ek.priv, key32(bundle.opk.pub)));
  const sk = await c.hkdf(c.concat(...parts), ZERO, 'MAX-X3DH', 32);
  const ad = c.concat(key32(identity.ikSig.pub), key32(identity.ikDh.pub), key32(bundle.ikSig), theirIk);

  const dhs = await c.genDH();
  const [rk, cks] = await kdfRK(sk, await c.dh(dhs.priv, spk));
  return {
    sid: b64(ek.pub),
    ad: b64(ad),
    rk: b64(rk),
    dhs: enc(dhs),
    dhr: bundle.spk.pub,
    cks: b64(cks),
    ckr: null,
    ns: 0, nr: 0, pn: 0,
    skipped: {},
    pendingInit: {
      ikSig: identity.ikSig.pub,
      ikDh: identity.ikDh.pub,
      ikDhSig: identity.ikDhSig,
      ek: b64(ek.pub),
      spkId: bundle.spk.id,
      opkId: bundle.opk ? bundle.opk.id : null,
    },
    created: Date.now(),
  };
}

// spks / opks — словари {id: {pub, priv}}. Использованный одноразовый ключ вызывающий удаляет сам
// (только после успешной расшифровки первого сообщения).
export async function respondSession(identity, spks, opks, init) {
  if (!(await verifyIdentity(init))) throw new Error('bad initiator identity');
  const spk = spks[init.spkId];
  if (!spk) throw new Error('unknown signed prekey');
  let opk = null;
  if (init.opkId !== null && init.opkId !== undefined) {
    opk = opks[init.opkId];
    if (!opk) throw new Error('one-time prekey already used');
  }
  const ek = key32(init.ek);
  const theirIk = key32(init.ikDh);
  const spkPriv = unb64(spk.priv);
  const parts = [FF, await c.dh(spkPriv, theirIk), await c.dh(unb64(identity.ikDh.priv), ek), await c.dh(spkPriv, ek)];
  if (opk) parts.push(await c.dh(unb64(opk.priv), ek));
  const sk = await c.hkdf(c.concat(...parts), ZERO, 'MAX-X3DH', 32);
  const ad = c.concat(key32(init.ikSig), theirIk, key32(identity.ikSig.pub), key32(identity.ikDh.pub));
  return {
    sid: init.ek,
    ad: b64(ad),
    rk: b64(sk),
    dhs: { pub: spk.pub, priv: spk.priv },
    dhr: null,
    cks: null,
    ckr: null,
    ns: 0, nr: 0, pn: 0,
    skipped: {},
    pendingInit: null,
    created: Date.now(),
  };
}

// ---------------------------------------------------------------- Double Ratchet
// Функции не меняют входное состояние: возвращают [новое состояние, результат].
// Поддельное или испорченное сообщение не портит сессию.

export async function ratchetEncrypt(st0, plaintext) {
  if (!st0.cks) throw new Error('session cannot send yet');
  const st = structuredClone(st0);
  const [ck, mk] = await kdfCK(unb64(st.cks));
  st.cks = b64(ck);
  const h = { dh: st.dhs.pub, pn: st.pn, n: st.ns };
  st.ns++;
  const [key, iv] = await msgKeys(mk);
  const ct = await c.aeadSeal(key, iv, plaintext, c.concat(unb64(st.ad), hdrBytes(h)));
  const msg = { sid: st.sid, h, c: b64(ct) };
  if (st.pendingInit) msg.init = st.pendingInit;
  return [st, msg];
}

function validHeader(h) {
  return h && typeof h.dh === 'string' && Number.isInteger(h.pn) && Number.isInteger(h.n)
    && h.pn >= 0 && h.n >= 0 && h.pn < 2 ** 31 && h.n < 2 ** 31;
}

async function skipKeys(st, until) {
  if (st.ckr === null) return;
  if (until - st.nr > MAX_SKIP) throw new Error('too many skipped messages');
  while (st.nr < until) {
    const [ck, mk] = await kdfCK(unb64(st.ckr));
    st.ckr = b64(ck);
    st.skipped[st.dhr + ':' + st.nr] = b64(mk);
    st.nr++;
  }
  const keys = Object.keys(st.skipped);
  for (let i = 0; i < keys.length - MAX_STORED_SKIPPED; i++) delete st.skipped[keys[i]];
}

async function dhRatchet(st, h) {
  st.pn = st.ns;
  st.ns = 0;
  st.nr = 0;
  st.dhr = h.dh;
  let [rk, ck] = await kdfRK(unb64(st.rk), await c.dh(unb64(st.dhs.priv), key32(st.dhr)));
  st.ckr = b64(ck);
  const dhs = await c.genDH();
  st.dhs = enc(dhs);
  [rk, ck] = await kdfRK(rk, await c.dh(dhs.priv, key32(st.dhr)));
  st.rk = b64(rk);
  st.cks = b64(ck);
}

async function openWith(mk, ct, ad) {
  const [key, iv] = await msgKeys(mk);
  return c.aeadOpen(key, iv, ct, ad);
}

export async function ratchetDecrypt(st0, msg) {
  const h = msg.h;
  if (!validHeader(h) || typeof msg.c !== 'string') throw new Error('bad message');
  const st = structuredClone(st0);
  const ad = c.concat(unb64(st.ad), hdrBytes(h));
  const ct = unb64(msg.c);
  const sk = h.dh + ':' + h.n;
  let pt;
  if (st.skipped[sk]) {
    const mk = unb64(st.skipped[sk]);
    delete st.skipped[sk];
    pt = await openWith(mk, ct, ad);
  } else {
    if (h.dh !== st.dhr) {
      await skipKeys(st, h.pn);
      await dhRatchet(st, h);
    }
    await skipKeys(st, h.n);
    const [ck, mk] = await kdfCK(unb64(st.ckr));
    st.ckr = b64(ck);
    st.nr++;
    pt = await openWith(mk, ct, ad);
  }
  st.pendingInit = null; // собеседник ответил — X3DH-заголовок больше не нужен
  return [st, pt];
}

// ---------------------------------------------------------------- запечатанный конверт

export async function seal(recipientIkDh, obj) {
  const eph = await c.genDH();
  const rpk = key32(recipientIkDh);
  const shared = await c.dh(eph.priv, rpk);
  const okm = await c.hkdf(shared, c.concat(eph.pub, rpk), 'MAX-SEAL', 44);
  const pt = c.pad(te.encode(JSON.stringify(obj)));
  const ct = await c.aeadSeal(okm.slice(0, 32), okm.slice(32), pt, c.concat(eph.pub, rpk));
  return b64(c.concat(eph.pub, ct));
}

export async function unseal(identity, blob) {
  const raw = unb64(blob);
  if (raw.length < 32 + 16) throw new Error('short envelope');
  const epub = raw.subarray(0, 32);
  const mypub = key32(identity.ikDh.pub);
  const shared = await c.dh(unb64(identity.ikDh.priv), epub);
  const okm = await c.hkdf(shared, c.concat(epub, mypub), 'MAX-SEAL', 44);
  const pt = await c.aeadOpen(okm.slice(0, 32), okm.slice(32), raw.subarray(32), c.concat(epub, mypub));
  return JSON.parse(c.td.decode(c.unpad(pt)));
}

// ---------------------------------------------------------------- код безопасности

async function fingerprint(handle, ikSig, ikDh) {
  const keys = c.concat(key32(ikSig), key32(ikDh));
  let hsh = c.concat(Uint8Array.of(0, 1), keys, te.encode(handle));
  for (let i = 0; i < 5200; i++) hsh = await c.sha('SHA-512', c.concat(hsh, keys));
  let s = '';
  for (let i = 0; i < 30; i += 5) {
    const v = hsh[i] * 2 ** 32 + hsh[i + 1] * 2 ** 24 + hsh[i + 2] * 2 ** 16 + hsh[i + 3] * 2 ** 8 + hsh[i + 4];
    s += String(v % 100000).padStart(5, '0');
  }
  return s;
}

export { fingerprint };

// 60 цифр, одинаковые у обоих собеседников.
export async function safetyNumber(myHandle, myIkSig, myIkDh, theirHandle, theirIkSig, theirIkDh) {
  const a = await fingerprint(myHandle, myIkSig, myIkDh);
  const b = await fingerprint(theirHandle, theirIkSig, theirIkDh);
  return myHandle < theirHandle ? a + b : b + a;
}
