// Криптографические примитивы MAX (Drognev).
// Только стандартный WebCrypto: X25519, Ed25519, HKDF-SHA256, HMAC-SHA256,
// AES-256-GCM, SHA-512, PBKDF2. Один и тот же код работает в браузере и в Node 22+.

const C = globalThis.crypto;
const S = C.subtle;

export const te = new TextEncoder();
export const td = new TextDecoder('utf-8', { fatal: true });

export function rand(n) {
  const b = new Uint8Array(n);
  C.getRandomValues(b);
  return b;
}

export function concat(...parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function u32(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0);
  return b;
}

// Сравнение за постоянное время.
export function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// base64url без '='.
export function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('bad base64');
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const X = { name: 'X25519' };
const E = { name: 'Ed25519' };

async function exportPair(kp) {
  return {
    pub: new Uint8Array(await S.exportKey('raw', kp.publicKey)),
    priv: new Uint8Array(await S.exportKey('pkcs8', kp.privateKey)),
  };
}

export async function genDH() {
  return exportPair(await S.generateKey(X, true, ['deriveBits']));
}

export async function genSig() {
  return exportPair(await S.generateKey(E, true, ['sign', 'verify']));
}

export async function dh(priv, pub) {
  if (pub.length !== 32) throw new Error('bad X25519 key');
  const sk = await S.importKey('pkcs8', priv, X, false, ['deriveBits']);
  const pk = await S.importKey('raw', pub, X, false, []);
  const out = new Uint8Array(await S.deriveBits({ name: 'X25519', public: pk }, sk, 256));
  // Защита от точек малого порядка: общий секрет из одних нулей недопустим.
  if (out.every((b) => b === 0)) throw new Error('weak DH output');
  return out;
}

export async function sign(priv, data) {
  const k = await S.importKey('pkcs8', priv, E, false, ['sign']);
  return new Uint8Array(await S.sign(E, k, data));
}

export async function verify(pub, sig, data) {
  try {
    if (pub.length !== 32 || sig.length !== 64) return false;
    const k = await S.importKey('raw', pub, E, false, ['verify']);
    return await S.verify(E, k, sig, data);
  } catch {
    return false;
  }
}

export async function hkdf(ikm, salt, info, len) {
  const k = await S.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await S.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) }, k, len * 8));
}

export async function hmac(key, data) {
  const k = await S.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await S.sign('HMAC', k, data));
}

export async function sha(alg, data) {
  return new Uint8Array(await S.digest(alg, data));
}

export async function aeadSeal(key, iv, pt, ad) {
  const k = await S.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  return new Uint8Array(await S.encrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, k, pt));
}

export async function aeadOpen(key, iv, ct, ad) {
  const k = await S.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await S.decrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, k, ct));
}

// Ключ хранилища из пароля. Ключ неизвлекаемый — его нельзя выгрузить из WebCrypto.
export async function pbkdf2(pass, salt, iterations) {
  const k = await S.importKey('raw', te.encode(pass.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return S.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    k,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// Выравнивание длины (ISO/IEC 7816-4): сервер видит только размер «корзины», а не точную длину.
export function pad(u8) {
  const block = u8.length < 4000 ? 256 : 16384;
  const total = Math.ceil((u8.length + 1) / block) * block;
  const out = new Uint8Array(total);
  out.set(u8);
  out[u8.length] = 0x80;
  return out;
}

export function unpad(u8) {
  let i = u8.length - 1;
  while (i >= 0 && u8[i] === 0) i--;
  if (i < 0 || u8[i] !== 0x80) throw new Error('bad padding');
  return u8.subarray(0, i);
}
