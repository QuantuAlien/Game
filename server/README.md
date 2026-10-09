# Сервер аккаунтов «Маяк»

## Проверка на своём компьютере
```
cd server
pip install -r requirements.txt
python app.py
```
Сервер запустится на http://127.0.0.1:8000. В игре в `remote.rpy`:
`define SERVER_URL = "http://127.0.0.1:8000"`.

## Деплой (Render, Railway, Fly.io и т. п.)
- Команда запуска: `gunicorn app:app --workers 2 --threads 4`
  (на Render и Railway подхватывается из `Procfile`).
- Хостинг должен отдавать HTTPS: пароли идут в теле запроса.
- Переменные окружения:
  - `MAYAK_DB` — путь к файлу базы. Укажите папку на **постоянном диске**,
    иначе на бесплатных тарифах база пропадёт при перезапуске.
  - `MAYAK_PROXIES=1` — включить, если сервер стоит за прокси хостинга
    (нужно, чтобы лимит попыток считал настоящие IP игроков).

## API
Все запросы: `POST`, JSON. Ответ всегда с кодом 200:
`{"ok": true, ...}` или `{"ok": false, "error": "текст"}`
(для плохого токена добавляется `"code": "auth"`).

| Адрес | Тело запроса | Ответ |
|---|---|---|
| `/register` | `username`, `password` | `token`, `name` |
| `/login` | `username`, `password` | `token`, `name` |
| `/logout` | `token` | |
| `/data/set` | `token`, `field`, `value` | |
| `/data/get` | `token`, `field` | `found`, `value` |
| `/data/all` | `token` | `data` |
| `/delete` | `token`, `password` | |
| `GET /health` | | `ok` |
