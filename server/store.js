// Хранилище сервера: открытые ключи пользователей и очереди зашифрованных конвертов.
// Никаких текстов, контактов, IP-адресов и журналов.

import fs from 'node:fs';
import path from 'node:path';

export class Store {
  constructor(dir) {
    this.file = dir ? path.join(dir, 'store.json') : null;
    this.data = { users: {}, queues: {} };
    this.timer = null;
    if (this.file) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      if (fs.existsSync(this.file)) this.data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    }
  }

  get users() { return this.data.users; }
  get queues() { return this.data.queues; }

  save() {
    if (!this.file || this.timer) return;
    this.timer = setTimeout(() => this.flush(), 200);
  }

  flush() {
    clearTimeout(this.timer);
    this.timer = null;
    if (!this.file) return;
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.data), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
}
