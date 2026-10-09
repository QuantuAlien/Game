"""
Сервер аккаунтов и данных для игры «Маяк».

Запуск для проверки на своём компьютере:
    pip install -r requirements.txt
    python app.py                       # http://127.0.0.1:8000

Запуск на хостинге:
    gunicorn app:app

Что делает сервер:
  - регистрирует и авторизует игроков (пароли хранятся только в виде соли и хеша);
  - выдаёт сессионные токены (в базе лежит только хеш токена, срок жизни 30 дней);
  - хранит игровые данные игрока (пары «поле — значение» в JSON);
  - блокирует подбор паролей: 5 неудачных входов = блокировка аккаунта на 5 минут.

Все ответы приходят с HTTP-кодом 200 и телом вида {"ok": true, ...}
или {"ok": false, "error": "текст"} (для ошибок авторизации ещё "code": "auth").
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque

from flask import Flask, g, jsonify, request

# ----------------------------- настройки -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("MAYAK_DB", os.path.join(BASE_DIR, "server_data", "mayak_server.db"))

ITERATIONS = 200_000          # сложность хеширования паролей
SESSION_DAYS = 30             # сколько живёт токен
MAX_FAILS = 5                 # неудачных входов до блокировки
LOCK_SECONDS = 300            # на сколько блокируем аккаунт
MAX_BODY_BYTES = 64 * 1024    # максимальный размер запроса
MAX_VALUE_BYTES = 16 * 1024   # максимальный размер одного значения
MAX_FIELDS = 200              # максимум полей данных на игрока
IP_LIMIT = 30                 # запросов входа/регистрации с одного IP ...
IP_WINDOW = 60                # ... за столько секунд

USERNAME_RE = re.compile(r"^[\w .\-]{3,24}$")
FIELD_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

# За прокси хостинга (Render, Railway, nginx) настоящий IP игрока приходит в
# заголовке X-Forwarded-For. Включайте только если реально стоите за прокси:
#   MAYAK_PROXIES=1
if os.environ.get("MAYAK_PROXIES"):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=int(os.environ["MAYAK_PROXIES"]))


# ----------------------------- база данных -----------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    salt            TEXT NOT NULL,
    hash            TEXT NOT NULL,
    iterations      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    last_login      INTEGER,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_data (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    field      TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, field)
);
"""


def connect():
    folder = os.path.dirname(DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    conn = connect()
    with conn:
        conn.executescript(SCHEMA)
    conn.close()


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


# ----------------------------- вспомогательное -----------------------------

def ok(**extra):
    return jsonify({"ok": True, **extra})


def fail(message, code=None):
    body = {"ok": False, "error": message}
    if code:
        body["code"] = code
    return jsonify(body)


def hash_password(password, salt_hex=None, iterations=ITERATIONS):
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return salt.hex(), digest.hex()


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn = db()
    with conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute(
            "INSERT INTO sessions(token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token_hash(token), user_id, now, now + SESSION_DAYS * 86400))
    return token


def current_user(data):
    """Пользователь по токену из запроса или None."""
    token = data.get("token")
    if not isinstance(token, str) or not token:
        return None
    return db().execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires_at > ?",
        (token_hash(token), int(time.time()))).fetchone()


_ip_hits = defaultdict(deque)


def ip_limited():
    """True, если с этого IP слишком много попыток входа/регистрации."""
    now = time.time()
    hits = _ip_hits[request.remote_addr]
    while hits and hits[0] < now - IP_WINDOW:
        hits.popleft()
    if len(hits) >= IP_LIMIT:
        return True
    hits.append(now)
    return False


def valid_credentials(username, password):
    if not isinstance(username, str) or not isinstance(password, str):
        return "Неверный запрос."
    username = username.strip()
    if len(username) < 3:
        return "Имя должно быть не короче 3 символов."
    if len(username) > 24:
        return "Имя должно быть не длиннее 24 символов."
    if not USERNAME_RE.match(username):
        return "В имени можно использовать буквы, цифры, пробел, точку, дефис и подчёркивание."
    if len(password) < 4:
        return "Пароль должен быть не короче 4 символов."
    if len(password) > 64:
        return "Пароль должен быть не длиннее 64 символов."
    return None


# ----------------------------- маршруты -----------------------------

@app.get("/health")
def health():
    return ok()


@app.post("/register")
def register():
    if ip_limited():
        return fail("Слишком много запросов. Подождите минуту.")
    data = payload()
    username, password = data.get("username"), data.get("password")

    error = valid_credentials(username, password)
    if error:
        return fail(error)

    username = username.strip()
    salt, digest = hash_password(password)
    conn = db()
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO users(username, display_name, salt, hash, iterations, created_at, last_login) "
                "VALUES (?,?,?,?,?,?,?)",
                (username.lower(), username, salt, digest, ITERATIONS,
                 int(time.time()), int(time.time())))
    except sqlite3.IntegrityError:
        return fail("Такой пользователь уже существует.")

    return ok(token=create_session(cur.lastrowid), name=username)


@app.post("/login")
def login():
    if ip_limited():
        return fail("Слишком много запросов. Подождите минуту.")
    data = payload()
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or len(password) > 64:
        return fail("Неверное имя или пароль.")

    conn = db()
    user = conn.execute("SELECT * FROM users WHERE username = ?",
                        (username.strip().lower(),)).fetchone()
    if user is None:
        hash_password(password)             # чтобы время ответа не выдавало, есть ли такой юзер
        return fail("Неверное имя или пароль.")

    now = int(time.time())
    if user["locked_until"] > now:
        wait = user["locked_until"] - now
        return fail("Слишком много неудачных попыток. Подождите %d сек." % wait)

    _, digest = hash_password(password, user["salt"], user["iterations"])
    if not hmac.compare_digest(digest, user["hash"]):
        fails = user["failed_attempts"] + 1
        locked = now + LOCK_SECONDS if fails >= MAX_FAILS else 0
        with conn:
            conn.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                         (0 if locked else fails, locked, user["id"]))
        return fail("Неверное имя или пароль.")

    with conn:
        conn.execute("UPDATE users SET failed_attempts = 0, locked_until = 0, last_login = ? WHERE id = ?",
                     (now, user["id"]))
    return ok(token=create_session(user["id"]), name=user["display_name"])


@app.post("/logout")
def logout():
    data = payload()
    token = data.get("token")
    if isinstance(token, str) and token:
        conn = db()
        with conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
    return ok()


@app.post("/data/set")
def data_set():
    data = payload()
    user = current_user(data)
    if user is None:
        return fail("Сессия истекла. Войдите заново.", code="auth")

    field = data.get("field")
    if not isinstance(field, str) or not FIELD_RE.match(field):
        return fail("Недопустимое имя поля.")
    if "value" not in data:
        return fail("Не передано значение.")

    text = json.dumps(data["value"], ensure_ascii=False)
    if len(text.encode("utf-8")) > MAX_VALUE_BYTES:
        return fail("Значение слишком большое.")

    conn = db()
    exists = conn.execute("SELECT 1 FROM user_data WHERE user_id = ? AND field = ?",
                          (user["id"], field)).fetchone()
    if not exists:
        count = conn.execute("SELECT COUNT(*) FROM user_data WHERE user_id = ?",
                             (user["id"],)).fetchone()[0]
        if count >= MAX_FIELDS:
            return fail("Слишком много сохранённых полей.")

    with conn:
        conn.execute("INSERT OR REPLACE INTO user_data(user_id, field, value, updated_at) VALUES (?,?,?,?)",
                     (user["id"], field, text, int(time.time())))
    return ok()


@app.post("/data/get")
def data_get():
    data = payload()
    user = current_user(data)
    if user is None:
        return fail("Сессия истекла. Войдите заново.", code="auth")

    field = data.get("field")
    row = db().execute("SELECT value FROM user_data WHERE user_id = ? AND field = ?",
                       (user["id"], field if isinstance(field, str) else "")).fetchone()
    if row is None:
        return ok(found=False, value=None)
    return ok(found=True, value=json.loads(row["value"]))


@app.post("/data/all")
def data_all():
    data = payload()
    user = current_user(data)
    if user is None:
        return fail("Сессия истекла. Войдите заново.", code="auth")

    rows = db().execute("SELECT field, value FROM user_data WHERE user_id = ?",
                        (user["id"],)).fetchall()
    return ok(data={r["field"]: json.loads(r["value"]) for r in rows})


@app.post("/delete")
def delete_account():
    data = payload()
    user = current_user(data)
    if user is None:
        return fail("Сессия истекла. Войдите заново.", code="auth")

    password = data.get("password")
    if not isinstance(password, str) or len(password) > 64:
        return fail("Неверный пароль.")
    _, digest = hash_password(password, user["salt"], user["iterations"])
    if not hmac.compare_digest(digest, user["hash"]):
        return fail("Неверный пароль.")

    conn = db()
    with conn:                                   # сессии и данные удалятся каскадом
        conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    return ok()


@app.errorhandler(413)
def too_large(_e):
    return fail("Запрос слишком большой.")


@app.errorhandler(404)
def not_found(_e):
    return fail("Неизвестный адрес.")


@app.errorhandler(405)
def bad_method(_e):
    return fail("Неверный метод запроса.")


init_db()

if __name__ == "__main__":
    # Только для проверки на своём компьютере. На хостинге используйте gunicorn.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8000)))
