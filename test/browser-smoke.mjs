// Проверка в настоящем браузере: node test/browser-smoke.mjs [папка-для-скриншотов]
// Два независимых профиля Chromium регистрируются и переписываются через локальный сервер.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { createServer } from '../server/server.js';

// playwright может быть установлен глобально — подключаем через require
const { chromium } = createRequire(import.meta.url)('playwright');
const shots = process.argv[2];
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'max-browser-'));
const srv = createServer({ dataDir: dir, registerPerHour: 100 });
const { port } = await srv.listen(0, '127.0.0.1');
const URL = `http://localhost:${port}/`;
const browser = await chromium.launch();
const problems = [];

async function user(name, viewport = { width: 1200, height: 800 }) {
  const ctx = await browser.newContext({ viewport });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error') problems.push(`${name}: ${m.text()}`); });
  page.on('pageerror', (e) => problems.push(`${name}: ${e.message}`));
  await page.goto(URL);
  await page.getByPlaceholder('например, ivan_d').fill(name);
  await page.getByPlaceholder('Не меньше 12 символов').fill('Correct-Horse-Battery-77');
  await page.locator('input[type=password]').nth(1).fill('Correct-Horse-Battery-77');
  await page.getByRole('button', { name: 'Создать аккаунт' }).click();
  await page.locator('.dot.on').waitFor({ timeout: 20000 });
  return { ctx, page };
}

try {
  const a = await user('alice');
  const b = await user('bob');

  await a.page.getByPlaceholder('Новый чат: имя собеседника').fill('bob');
  await a.page.keyboard.press('Enter');
  await a.page.getByPlaceholder('Сообщение').fill('Привет, Боб! <img src=x onerror=alert(1)>');
  await a.page.keyboard.press('Enter');

  await b.page.locator('.contact').filter({ hasText: '@alice' }).click();
  await b.page.locator('.text', { hasText: 'Привет, Боб!' }).waitFor();
  if (await b.page.locator('.text img').count()) throw new Error('XSS: HTML в сообщении отрисован');
  await b.page.getByPlaceholder('Сообщение').fill('Привет, Алиса 👋\nВторая строка');
  await b.page.keyboard.press('Enter');
  await a.page.locator('.text', { hasText: 'Привет, Алиса' }).waitFor();
  await a.page.locator('.st.delivered').first().waitFor();

  // файл-картинка
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAMklEQVR4nGNk+M9Qz0ABYKJE86gBowaMGjBqwKgBowaMGjBqwKgBo4ZQQ4BkAQAAG9EBEZ4dqHEAAAAASUVORK5CYII=', 'base64');
  await b.page.locator('input[type=file]').setInputFiles({ name: 'pic.png', mimeType: 'image/png', buffer: png });
  await a.page.locator('.att-img').waitFor();

  // таймер
  await a.page.locator('select.timer').selectOption('300');
  await b.page.locator('.sys', { hasText: '5 мин' }).waitFor();

  // код безопасности совпадает у обоих
  await a.page.locator('.vbadge').click();
  await b.page.locator('.vbadge').click();
  const snA = await a.page.locator('.sn-grid').innerText();
  const snB = await b.page.locator('.sn-grid').innerText();
  if (snA.replace(/\s/g, '') !== snB.replace(/\s/g, '') || snA.replace(/\s/g, '').length !== 60) throw new Error('коды безопасности не совпадают');
  if (shots) await a.page.screenshot({ path: path.join(shots, 'safety.png') });
  await a.page.getByRole('button', { name: 'Цифры совпадают' }).click();
  await b.page.keyboard.press('Escape');
  await a.page.locator('.vbadge.ok').waitFor();

  // перезагрузка → блокировка → разблокировка, история на месте
  await a.page.reload();
  await a.page.getByPlaceholder('Пароль хранилища').fill('wrong-password-123');
  await a.page.keyboard.press('Enter');
  await a.page.locator('.err', { hasText: 'Неверный пароль' }).waitFor();
  if (shots) await a.page.screenshot({ path: path.join(shots, 'unlock.png') });
  await a.page.getByPlaceholder('Пароль хранилища').fill('Correct-Horse-Battery-77');
  await a.page.keyboard.press('Enter');
  await a.page.locator('.contact').filter({ hasText: '@bob' }).click();
  await a.page.locator('.text', { hasText: 'Привет, Алиса' }).waitFor();
  await a.page.getByPlaceholder('Сообщение').fill('После перезагрузки сессия жива');
  await a.page.keyboard.press('Enter');
  await b.page.locator('.text', { hasText: 'После перезагрузки' }).waitFor();

  // вторая вкладка того же профиля блокируется
  const tab2 = await a.ctx.newPage();
  await tab2.goto(URL);
  await tab2.locator('text=уже открыт в другой вкладке').waitFor();
  await tab2.close();

  if (shots) {
    await a.page.screenshot({ path: path.join(shots, 'desktop.png') });
    const m = await user('mobile_user', { width: 390, height: 780 });
    await m.page.getByPlaceholder('Новый чат: имя собеседника').fill('alice');
    await m.page.keyboard.press('Enter');
    await m.page.getByPlaceholder('Сообщение').fill('Пишу с телефона');
    await m.page.keyboard.press('Enter');
    await m.page.locator('.st.delivered').waitFor();
    await m.page.screenshot({ path: path.join(shots, 'mobile.png') });
  }

  // сервер не знает текстов
  srv.store.flush();
  const disk = fs.readFileSync(path.join(dir, 'store.json'), 'utf8');
  if (disk.includes('Привет')) throw new Error('на сервере найден открытый текст');

  const real = problems.filter((p) => !p.includes('favicon'));
  if (real.length) throw new Error('ошибки в консоли:\n' + real.join('\n'));
  console.log('OK: браузерный сценарий пройден');
} finally {
  await browser.close();
  await srv.close();
  fs.rmSync(dir, { recursive: true, force: true });
}
