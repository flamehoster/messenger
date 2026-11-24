import test from 'node:test';
import assert from 'node:assert/strict';
import * as P from '../public/js/protocol.js';
import { te, td, pad, unpad } from '../public/js/crypto.js';

async function party() {
  const identity = await P.createIdentity();
  const spk = await P.makeSignedPrekey(identity, 1);
  const opks = await P.makeOneTimePrekeys(1, 3);
  return { identity, spks: { 1: spk }, opks: Object.fromEntries(opks.map((k) => [k.id, k])), spk, opkList: opks };
}

function bundleOf(p, withOpk = true) {
  const b = P.publicBundle(p.identity, p.spk, []);
  delete b.opks;
  b.opk = withOpk ? { id: p.opkList[0].id, pub: p.opkList[0].pub } : null;
  return b;
}

const T = (s) => te.encode(s);
const S = (u) => td.decode(u);

async function establish() {
  const A = await party();
  const B = await party();
  let a = await P.initiateSession(A.identity, bundleOf(B));
  let m;
  [a, m] = await P.ratchetEncrypt(a, T('привет'));
  let b = await P.respondSession(B.identity, B.spks, B.opks, m.init);
  let pt;
  [b, pt] = await P.ratchetDecrypt(b, m);
  assert.equal(S(pt), 'привет');
  return { A, B, a, b };
}

test('X3DH + обмен сообщениями в обе стороны', async () => {
  let { a, b } = await establish();
  let m, pt;
  for (let i = 0; i < 5; i++) {
    [b, m] = await P.ratchetEncrypt(b, T('b' + i));
    assert.equal(m.init, undefined);
    [a, pt] = await P.ratchetDecrypt(a, m);
    assert.equal(S(pt), 'b' + i);
    assert.equal(a.pendingInit, null);
    [a, m] = await P.ratchetEncrypt(a, T('a' + i));
    [b, pt] = await P.ratchetDecrypt(b, m);
    assert.equal(S(pt), 'a' + i);
  }
});

test('сообщения вне очереди расшифровываются', async () => {
  let { a, b } = await establish();
  const msgs = [];
  for (let i = 0; i < 6; i++) { let m; [a, m] = await P.ratchetEncrypt(a, T('m' + i)); msgs.push(m); }
  const order = [5, 1, 0, 3, 2, 4];
  for (const i of order) { let pt; [b, pt] = await P.ratchetDecrypt(b, msgs[i]); assert.equal(S(pt), 'm' + i); }
});

test('повтор и подделка отвергаются, состояние не портится', async () => {
  let { a, b } = await establish();
  let m, pt;
  [a, m] = await P.ratchetEncrypt(a, T('x'));
  [b, pt] = await P.ratchetDecrypt(b, m);
  await assert.rejects(P.ratchetDecrypt(b, m)); // повтор
  let m2;
  [a, m2] = await P.ratchetEncrypt(a, T('y'));
  const bad = structuredClone(m2);
  bad.c = bad.c.slice(0, -2) + (bad.c.endsWith('AA') ? 'BB' : 'AA');
  await assert.rejects(P.ratchetDecrypt(b, bad));
  const badHdr = structuredClone(m2);
  badHdr.h.n += 1;
  await assert.rejects(P.ratchetDecrypt(b, badHdr));
  [b, pt] = await P.ratchetDecrypt(b, m2);
  assert.equal(S(pt), 'y');
});

test('одноразовый предключ нельзя использовать повторно', async () => {
  const A = await party();
  const B = await party();
  let a = await P.initiateSession(A.identity, bundleOf(B));
  let m;
  [a, m] = await P.ratchetEncrypt(a, T('1'));
  await P.respondSession(B.identity, B.spks, B.opks, m.init);
  delete B.opks[m.init.opkId];
  await assert.rejects(P.respondSession(B.identity, B.spks, B.opks, m.init));
});

test('X3DH без одноразового ключа', async () => {
  const A = await party();
  const B = await party();
  let a = await P.initiateSession(A.identity, bundleOf(B, false));
  let m, pt;
  [a, m] = await P.ratchetEncrypt(a, T('ok'));
  let b = await P.respondSession(B.identity, B.spks, {}, m.init);
  [b, pt] = await P.ratchetDecrypt(b, m);
  assert.equal(S(pt), 'ok');
});

test('поддельный подписанный предключ отвергается', async () => {
  const A = await party();
  const B = await party();
  const M = await party();
  const b = bundleOf(B);
  b.spk = { id: M.spk.id, pub: M.spk.pub, sig: M.spk.sig }; // подпись чужим ключом
  await assert.rejects(P.initiateSession(A.identity, b));
});

test('запечатанный конверт: открыть может только получатель', async () => {
  const A = await party();
  const B = await party();
  const blob = await P.seal(B.identity.ikDh.pub, { from: 'alice', m: { x: 1 } });
  assert.deepEqual(await P.unseal(B.identity, blob), { from: 'alice', m: { x: 1 } });
  await assert.rejects(P.unseal(A.identity, blob));
});

test('выравнивание длины', () => {
  for (const n of [0, 1, 255, 256, 3999, 4000, 20000]) {
    const u = new Uint8Array(n).fill(7);
    const p = pad(u);
    assert.equal(p.length % (n < 4000 ? 256 : 16384), 0);
    assert.deepEqual(unpad(p), u);
  }
});

test('код безопасности одинаков у обоих и меняется вместе с ключом', async () => {
  const A = await party();
  const B = await party();
  const n1 = await P.safetyNumber('alice', A.identity.ikSig.pub, A.identity.ikDh.pub, 'bob', B.identity.ikSig.pub, B.identity.ikDh.pub);
  const n2 = await P.safetyNumber('bob', B.identity.ikSig.pub, B.identity.ikDh.pub, 'alice', A.identity.ikSig.pub, A.identity.ikDh.pub);
  assert.equal(n1, n2);
  assert.match(n1, /^\d{60}$/);
  const C = await party();
  const n3 = await P.safetyNumber('alice', A.identity.ikSig.pub, A.identity.ikDh.pub, 'bob', C.identity.ikSig.pub, C.identity.ikDh.pub);
  assert.notEqual(n1, n3);
});
