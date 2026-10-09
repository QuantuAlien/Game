# =============================================================================
# remote.rpy — связь игры с сервером аккаунтов (см. папку server/)
#
# SERVER_URL = None   -> локальный режим (SQLite на компьютере игрока)
# SERVER_URL = "..."  -> аккаунты и данные хранятся на сервере
# =============================================================================

define SERVER_URL = None
# define SERVER_URL = "http://127.0.0.1:8000"            # проверка на своём компьютере
# define SERVER_URL = "https://ваш-сервер.example.com"   # настоящий сервер (только https!)

default persistent.token = None         # токен сессии (не пароль)
default persistent.data_cache = {}      # копия данных игрока, чтобы не ходить на сервер за каждым get


init -1 python:
    import json

    def remote_enabled():
        return bool(SERVER_URL)

    def api_call(path, payload):
        # Всегда возвращает dict с полем "ok". Сетевые сбои превращаются
        # в {"ok": False, "error": "..."}, поэтому игра не вылетает.
        url = SERVER_URL.rstrip("/") + path

        local = url.startswith("http://127.0.0.1") or url.startswith("http://localhost")
        if not (url.startswith("https://") or local):
            return {"ok": False, "error": "Адрес сервера должен начинаться с https://"}

        try:
            raw = renpy.fetch(
                url,
                method="POST",
                data=json.dumps(payload).encode("utf-8"),
                content_type="application/json",
                timeout=8,
                result="bytes")
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {"ok": False, "error": "Нет связи с сервером. Попробуйте позже."}

    def _forget_session():
        persistent.token = None
        persistent.current_user = None
        persistent.current_name = None
        persistent.data_cache = {}
        renpy.save_persistent()

    def _check_auth(reply):
        # Токен устарел или удалён на сервере: выходим из аккаунта
        if not reply.get("ok") and reply.get("code") == "auth":
            _forget_session()

    def _start_session(reply):
        persistent.token = reply["token"]
        persistent.current_user = reply["name"].lower()
        persistent.current_name = reply["name"]
        persistent.data_cache = {}
        renpy.save_persistent()
        remote_pull_data()

    # ---------- аккаунт ----------

    def remote_register(username, password):
        reply = api_call("/register", {"username": username, "password": password})
        if not reply.get("ok"):
            return reply.get("error", "Ошибка сервера.")
        _start_session(reply)
        return None

    def remote_login(username, password):
        reply = api_call("/login", {"username": username, "password": password})
        if not reply.get("ok"):
            return reply.get("error", "Ошибка сервера.")
        _start_session(reply)
        return None

    def remote_logout():
        if persistent.token:
            api_call("/logout", {"token": persistent.token})   # если нет связи, не страшно
        _forget_session()

    def remote_delete_account(password):
        reply = api_call("/delete", {"token": persistent.token, "password": password})
        _check_auth(reply)
        if reply.get("ok"):
            _forget_session()
            return None
        return reply.get("error", "Ошибка сервера.")

    # ---------- данные игрока ----------

    def remote_pull_data():
        # Загружает все данные игрока с сервера в локальную копию
        if not persistent.token:
            return False
        reply = api_call("/data/all", {"token": persistent.token})
        _check_auth(reply)
        if reply.get("ok"):
            persistent.data_cache = reply.get("data", {})
            renpy.save_persistent()
            return True
        return False

    def remote_set(field, value):
        if not persistent.token:
            return False
        reply = api_call("/data/set", {"token": persistent.token, "field": field, "value": value})
        _check_auth(reply)
        if not reply.get("ok"):
            return False
        persistent.data_cache[field] = value
        renpy.save_persistent()
        return True

    def remote_get(field, default=None):
        return persistent.data_cache.get(field, default)
