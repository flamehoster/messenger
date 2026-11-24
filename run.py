"""Запуск MAX (Drognev) из PyCharm: правый клик по run.py → Run 'run'
(или кнопка ▶ с конфигурацией «MAX server» вверху справа).

Сам мессенджер написан на Node.js, этот файл лишь запускает его.
Нужен Node.js 22+ (https://nodejs.org). Сторонних Python-пакетов не нужно.
"""
import os
import shutil
import subprocess
import sys
import threading
import webbrowser

ROOT = os.path.dirname(os.path.abspath(__file__))


def fail(text):
    print(f"\n[ОШИБКА] {text}\n", file=sys.stderr)
    sys.exit(1)


def main():
    node = shutil.which("node")
    npm = shutil.which("npm")
    if not node or not npm:
        fail("Не найден Node.js. Установите Node.js 22 LTS или новее с https://nodejs.org "
             "и перезапустите PyCharm.")

    version = subprocess.run([node, "-v"], capture_output=True, text=True).stdout.strip()
    try:
        major = int(version.lstrip("v").split(".")[0])
    except ValueError:
        major = 0
    if major < 22:
        fail(f"Нужен Node.js 22 или новее, установлен {version or 'неизвестная версия'}.")

    if not os.path.isdir(os.path.join(ROOT, "node_modules", "ws")):
        print("Устанавливаю зависимости (npm install)…")
        subprocess.run([npm, "install", "--omit=dev"], cwd=ROOT, check=True)

    port = os.environ.get("PORT", "8080")
    url = f"http://localhost:{port}"
    env = dict(os.environ, PORT=port)
    print(f"Открываю {url}  (остановить — кнопка ■ в PyCharm или Ctrl+C)")
    if os.environ.get("NO_BROWSER") != "1":
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    proc = subprocess.Popen([node, os.path.join("server", "server.js")], cwd=ROOT, env=env)
    try:
        sys.exit(proc.wait())
    except KeyboardInterrupt:
        pass
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
