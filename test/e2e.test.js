// Сквозной тест: настоящий сервер + два клиента (Core) по WebSocket.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../server/server.js';
import { Net } from '../public/js/net.js';
import { Core, newAccountState, registerAccount } from '../public/js/core.js';

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 5000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (await fn()) return; await wait(20); }
  throw new Error('timeout waiting for condition');
}

let srv, url, dir;
const cores = [];

test.before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'max-test-'));
  srv = createServer({ dataDir: dir, registerPerHour: 1000 });
  const addr = await srv.listen(0, '127.0.0.1');
  url = `ws://127.0.0.1:${addr.port}/ws`;
});

test.after(async () => {
  for (const c of cores) c.destroy();
  await srv.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

async function account(handle) {
  const state = await newAccountState(handle);
  const net = new Net(url);
  const ch = net.nextChallenge();
  net.connect();
  await registerAccount(net, state, await ch);
  net.close();
  return state;
}

async function start(state) {
  const net = new Net(url);
  const core = new Core(state, { net });
  cores.push(core);
  net.connect();
  await until(() => core.online);
  return core;
}

const texts = (c, h) => (c.s.contacts[h]?.messages || []).filter((m) => m.kind === 'text').map((m) => m.text);

test('регистрация, переписка, подтверждения, офлайн-доставка, смена ключа', async () => {
  const aliceState = await account('alice');
  const bobState = await account('bob');

  // имя занято
  await assert.rejects(account('alice'), (e) => e.code === 'taken');

  const alice = await start(aliceState);
  let bob = await start(bobState);

  await alice.addContact('@Bob');
  await alice.sendText('bob', 'Привет, Боб!');
  await until(() => texts(bob, 'alice').includes('Привет, Боб!'));
  assert.equal(bob.s.contacts.alice.ikSig, aliceState.identity.ikSig.pub);

  // подтверждение доставки
  await until(() => alice.s.contacts.bob.messages.find((m) => m.text === 'Привет, Боб!')?.status === 'delivered');

  await bob.sendText('alice', 'Привет, Алиса');
  await until(() => texts(alice, 'bob').includes('Привет, Алиса'));

  // сервер не хранит доставленное и не знает текстов
  await wait(300);
  srv.store.flush();
  const onDisk = fs.readFileSync(path.join(dir, 'store.json'), 'utf8');
  assert.ok(!onDisk.includes('Привет'));
  assert.ok(!onDisk.includes('"alice","bob"'));

  // офлайн-доставка
  bob.destroy();
  await alice.sendText('bob', 'пока тебя не было 1');
  await alice.sendText('bob', 'пока тебя не было 2');
  await until(() => alice.s.contacts.bob.messages.filter((m) => m.status === 'sent').length >= 2);
  bob = await start(bob.s);
  await until(() => texts(bob, 'alice').includes('пока тебя не было 2'));
  assert.deepEqual(texts(bob, 'alice').slice(-2), ['пока тебя не было 1', 'пока тебя не было 2']);

  // файл
  const data = new Uint8Array(100000).map((_, i) => i % 251);
  await bob.sendFile('alice', { name: 'a.bin', type: 'application/octet-stream', data });
  await until(() => alice.s.contacts.bob.messages.some((m) => m.kind === 'file'));

  // таймер исчезающих сообщений синхронизируется
  await alice.setTimer('bob', 30);
  await until(() => bob.s.contacts.alice.timer === 30);
  await alice.sendText('bob', 'исчезну');
  await until(() => texts(bob, 'alice').includes('исчезну'));
  const m = bob.s.contacts.alice.messages.find((x) => x.text === 'исчезну');
  assert.ok(m.expires > Date.now());

  // Подмена отправителя: Мэллори кладёт в конверт from:'alice'.
  const mallory = await account('mallory');
  const mal = await start(mallory);
  // Мэллори пытается выдать себя за Алису: конверт с from:'alice', но своими ключами
  await mal.addContact('bob');
  const realHandle = mal.s.handle;
  mal.s.handle = 'alice';
  await mal.sendText('bob', 'я Алиса, честно').catch(() => {});
  mal.s.handle = realHandle;
  await wait(500);
  assert.ok(!texts(bob, 'alice').includes('я Алиса, честно'));
  assert.equal(bob.s.contacts.alice.keyChanged, null);
});

test('собеседник переустановил приложение: предупреждение о смене ключа', async () => {
  const dave = await start(await account('dave'));
  let erin = await start(await account('erin'));
  await dave.addContact('erin');
  await dave.sendText('erin', 'до переустановки');
  await until(() => texts(erin, 'dave').length === 1);

  // Эрин удаляет аккаунт и регистрируется заново с новыми ключами
  await erin.deleteAccount();
  await wait(100);
  erin.destroy();
  erin = await start(await account('erin'));
  await erin.addContact('dave');
  await erin.sendText('dave', 'я с нового устройства');
  await until(() => dave.s.contacts.erin.keyChanged);
  assert.ok(texts(dave, 'erin').includes('я с нового устройства'));
  assert.equal(dave.s.contacts.erin.verified, false);
  await assert.rejects(dave.sendText('erin', 'не уйдёт'), /изменился/);

  await dave.acceptNewKey('erin');
  await dave.sendText('erin', 'ключ принят');
  await until(() => texts(erin, 'dave').includes('ключ принят'));
});

test('удаление аккаунта стирает данные на сервере', async () => {
  const st = await account('carol');
  const carol = await start(st);
  await carol.deleteAccount();
  await wait(100);
  assert.equal(srv.store.users.carol, undefined);
});
