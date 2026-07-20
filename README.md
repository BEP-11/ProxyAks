# ProxyAks — HTTPS Прокси-сервер с обходом блокировок

Быстрый, лёгкий прокси на чистом Node.js без внешних зависимостей.

## Возможности

| Фича | Описание |
|------|----------|
| **HTTP/HTTPS туннелирование** | Поддержка CONNECT для HTTPS-сайтов |
| **TLS шифрование** | Входящие соединения шифруются через self-signed сертификат |
| **Ротация User-Agent** | 11 реалистичных UA (Chrome, Firefox, Edge, Safari) |
| **Рандомизация заголовков** | Случайный порядок + секции Sec-CH-UA |
| **Удаление следов** | Убираются Via, X-Forwarded-For и др. |
| **Белый/чёрный список** | Фильтрация доменов по шаблонам |
| **Быстрая активация** | `npm start` — готов к работе за 1 секунду |

## Установка

```bash
git clone https://github.com/BEP-11/ProxyAks
# Прокси работает без npm install (нет зависимостей)

# Опционально: сгенерировать TLS-сертификат
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/key.pem -out certs/cert.pem \
  -subj "/CN=proxy-aks.local/O=ProxyAks"
```

## Быстрый старт

```bash
node src/server.js
```

Сервер запустится на:
- **HTTP:** `http://0.0.0.0:8080`
- **HTTPS:** `https://0.0.0.0:8443` (если есть сертификаты)

## Настройка через config.local.json

```json
{
  "host": "0.0.0.0",
  "port": 8080,
  "tlsPort": 8443,
  "enableTls": true,
  "bypass": {
    "rotateUserAgent": true,
    "randomizeHeaders": true,
    "addBrowserHeaders": true,
    "removeIdentifyingHeaders": true
  },
  "whitelist": ["google.com", "github.com"],
  "blacklist": ["tracker.bad-domain.com"],
  "logging": {
    "enabled": true,
    "logRequests": true,
    "logTimestamps": true
  }
}
```

## Настройка через environment variables

| Переменная | Описание | По умолчанию |
|------------|----------|-------------|
| `PROXY_HOST` | Bind-адрес | `0.0.0.0` |
| `PROXY_PORT` | HTTP-порт | `8080` |
| `PROXY_TLS_PORT` | HTTPS- порт | `8443` |
| `PROXY_ENABLE_TLS` | Включить/выключить TLS | `true` |
| `PROXY_WHITELIST` | Допустимые домены (CSV) | все |
| `PROXY_BLACKLIST` | Запрещённые домены (CSV) | пусто |

```bash
PROXY_PORT=3128 PROXY_ENABLE_TLS=false node src/server.js
```

## Использование в браузере

Настройте браузер на прокси:
- **Host:** `localhost` (или ваш IP)
- **HTTP Port:** `8080`
- **HTTPS/SOCKS Port:** `8443` (если TLS включён)

Или используйте расширение FoxyProxy / AutoProxy.

## API статусов

```
GET http://127.0.0.1:8080/status
```

Возвращает JSON с текущей статистикой: количество запросов, трафик, uptime.

## Структура проекта

```
ProxyAks/
├── src/
│   ├── server.js          # Основной прокси-сервер
│   ├── bypass.js          # Ротация UA, рандомизация заголовков
│   ├── config.js          # Загрузка конфигурации
│   └── cert-manager.js    # Генерация TLS-сертификатов
├── certs/                 # Self-signed сертификаты (auto-generated)
├── config.default.json    # Шаблон конфигурации
├── .env.example           # Пример переменных окружения
└── package.json
```

## Лицензия

MIT
