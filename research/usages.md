# Selector Proxy — принципы работы и примеры конфигураций

## Принцип работы

Selector — inbound-proxy, мультиплексор протоколов на одном порту. Анализирует первые байты соединения через MSG_PEEK, определяет протокол и делегирует обработку другому inbound-хендлеру.

### Цепочка обработки

```
Клиент → TCP:443 → Selector
                      │
                      ├─ MSG_PEEK: читает первые байты без потребления
                      ├─ Детекция: TLS? SNI? ECH? MTProto? HTTP?
                      ├─ Матчит правила по порядку → handlerTag
                      │
                      ├─ Handler с TLS/Reality (loopback relay):
                      │    net.Dial("127.0.0.1:port") → buf.Copy ↔
                      │    [опционально: PROXY protocol header]
                      │
                      └─ Handler без security (direct):
                           handler.GetInbound().Process(ctx, conn, dispatcher)
```

### Выбор режима

Решение loopback/direct определяется конфигурацией **целевого handler'а**:
- `StreamSettings.SecurityType != ""` → loopback (TLS/Reality нужен listener)
- `StreamSettings.SecurityType == ""` → direct (plain TCP, mtproto)
- Нет порта → direct

Это не зависит от типа match — любая комбинация match + handler корректна.

### Детекция протоколов

| Протокол | Как определяется |
|---|---|
| **TLS** | Первый байт = `0x16`, второй = `0x03` (TLS record layer) |
| **SNI** | Парсинг TLS ClientHello → extension `0x0000` (server_name) |
| **ECH** | extension `0xfe0d` (encrypted_client_hello) в ClientHello |
| **MTProto** | Не TLS, не HTTP, >= 64 байт, высокая энтропия первых 56 байт |
| **HTTP** | Начинается с GET/POST/HEAD/PUT/DELETE/OPTIONS/CONNECT/PATCH |

### Типы правил (match)

| match | Описание | pattern |
|---|---|---|
| `tls` | TLS без ECH. Если задан pattern — матч по SNI. | regex по SNI |
| `ech` | TLS с ECH. Если задан pattern — матч по внешнему SNI. | regex по outer SNI |
| `tls_default` | Любой TLS (catch-all после специфичных). | игнорируется |
| `notls` | Не TLS. | игнорируется |
| `mtproto` | MTProto по эвристике. | игнорируется |
| `unknown` | Не TLS и не MTProto. | игнорируется |

---

## Параметры конфигурации

```json
{
  "protocol": "selector",
  "settings": {
    "rules": [
      {
        "match": "tls | ech | tls_default | notls | mtproto | unknown",
        "pattern": "regex (опционально, для tls и ech)",
        "handlerTag": "тег целевого inbound-хендлера",
        "loopbackAddr": "127.0.0.1:10001 (опционально)",
        "proxyProtocol": 0
      }
    ],
    "defaultHandlerTag": "тег по умолчанию",
    "readSize": 2048,
    "peekTimeoutMs": 5000,
    "minPeekSize": 16
  }
}
```

| Поле | Тип | Описание |
|---|---|---|
| `rules[].match` | string | Тип проверки |
| `rules[].pattern` | string | Regex по SNI (только для `tls` и `ech`) |
| `rules[].handlerTag` | string | Тег целевого inbound-хендлера |
| `rules[].loopbackAddr` | string | Явный адрес для relay. Если пустой — автоматически из handler'а |
| `rules[].proxyProtocol` | uint | 0 = off, 1 = PROXY v1, 2 = PROXY v2 |
| `defaultHandlerTag` | string | Fallback-хендлер |
| `readSize` | int | Макс байт для peek (по умолчанию 2048) |
| `peekTimeoutMs` | int | Таймаут peek в мс (по умолчанию 5000) |
| `minPeekSize` | int | Мин байт перед детекцией (по умолчанию 16) |

---

## Примеры конфигураций

### Пример 1: VLESS + Trojan на одном порту, разделение по SNI

```json
{
  "inbounds": [
    {
      "tag": "selector-in",
      "port": 443,
      "protocol": "selector",
      "settings": {
        "rules": [
          {
            "match": "tls",
            "pattern": "^vless\\.example\\.com$",
            "handlerTag": "vless-in"
          },
          {
            "match": "tls",
            "pattern": "^trojan\\.example\\.com$",
            "handlerTag": "trojan-in"
          },
          {
            "match": "tls_default",
            "handlerTag": "fallback-in"
          }
        ],
        "defaultHandlerTag": "fallback-in"
      },
      "streamSettings": { "network": "tcp" }
    },
    {
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "[UUID]", "flow": "xtls-rprx-vision" }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "/etc/ssl/vless.example.com.crt",
            "keyFile": "/etc/ssl/vless.example.com.key"
          }]
        }
      }
    },
    {
      "tag": "trojan-in",
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "trojan",
      "settings": {
        "clients": [{ "password": "secret" }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "/etc/ssl/trojan.example.com.crt",
            "keyFile": "/etc/ssl/trojan.example.com.key"
          }]
        }
      }
    },
    {
      "tag": "fallback-in",
      "listen": "127.0.0.1",
      "port": 10080,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1", "port": 8080, "network": "tcp" }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" }
  ]
}
```

Здесь `vless-in` и `trojan-in` имеют `security: tls` → selector автоматически использует loopback relay. `fallback-in` (dokodemo-door) без security → direct.

### Пример 2: MTProto + VLESS

Нативный MTProto handler и VLESS на одном порту.

```json
{
  "inbounds": [
    {
      "tag": "selector-in",
      "port": 443,
      "protocol": "selector",
      "settings": {
        "rules": [
          { "match": "mtproto", "handlerTag": "mtproto-in" },
          { "match": "tls", "handlerTag": "vless-in" }
        ],
        "defaultHandlerTag": "vless-in"
      },
      "streamSettings": { "network": "tcp" }
    },
    {
      "tag": "mtproto-in",
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "mtproto",
      "settings": {
        "secret": "[HEX-SECRET]",
        "antiReplay": true
      }
    },
    {
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "[UUID]", "flow": "xtls-rprx-vision" }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "/etc/ssl/example.com.crt",
            "keyFile": "/etc/ssl/example.com.key"
          }]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" }
  ]
}
```

`mtproto-in` без security → direct call. `vless-in` с TLS → loopback relay.

### Пример 3: PROXY protocol для сохранения client IP

```json
{
  "inbounds": [
    {
      "tag": "selector-in",
      "port": 443,
      "protocol": "selector",
      "settings": {
        "rules": [
          {
            "match": "tls",
            "handlerTag": "vless-in",
            "proxyProtocol": 1
          }
        ]
      },
      "streamSettings": { "network": "tcp" }
    },
    {
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "[UUID]" }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "/etc/ssl/cert.crt",
            "keyFile": "/etc/ssl/cert.key"
          }]
        },
        "sockopt": { "acceptProxyProtocol": true }
      }
    }
  ]
}
```

Selector отправляет PROXY protocol v1 header перед relay данными. Handler должен иметь `acceptProxyProtocol: true` в sockopt.

### Пример 4: Мульти-доменный хостинг с regex

```json
{
  "inbounds": [
    {
      "tag": "selector-in",
      "port": 443,
      "protocol": "selector",
      "settings": {
        "rules": [
          { "match": "tls", "pattern": "^api\\.", "handlerTag": "api-vless" },
          { "match": "tls", "pattern": "^(www\\.)?shop\\.", "handlerTag": "shop-trojan" },
          { "match": "tls", "pattern": "\\.(ru|by|kz)$", "handlerTag": "cis-vless" },
          { "match": "tls_default", "handlerTag": "default-nginx" },
          { "match": "notls", "handlerTag": "http-redirect" }
        ]
      },
      "streamSettings": { "network": "tcp" }
    }
  ]
}
```

Каждый TLS handler должен слушать на своём порту с `security: tls`. Handler'ы без TLS (`default-nginx`, `http-redirect`) получают соединения через direct call.

---

## Важные замечания

### TLS termination

Selector читает сырые байты через MSG_PEEK до TLS-расшифровки:
- У selector'а **не должно быть** `"security": "tls"` в `streamSettings`
- TLS терминируется на целевых handler'ах через их TCP listener

### Порядок правил

Первое совпадение побеждает. Рекомендуемый порядок:
1. Специфичные TLS/ECH-правила с pattern
2. `tls_default` — catch-all для TLS
3. `mtproto` — MTProto-трафик
4. `notls` / `unknown` — всё остальное

### gRPC-управление пользователями

Управление через gRPC API (`AlterInbound`) по тегу целевого хендлера, не selector'а.

### MTProto детекция

Основана на эвристике — может давать ложные срабатывания на бинарные протоколы. Рекомендуется ставить правило `mtproto` после `tls`.

---

# MTProto Proxy — принципы работы и конфигурация

## Принцип работы

MTProto — inbound-proxy для Telegram на базе [mtg v2](https://github.com/9seconds/mtg). Принимает MTProto-соединения и проксирует к серверам Telegram через Xray routing/outbound.

```
Telegram-клиент → TCP → MTProto Handler
                          ├─ Парсит secret → расшифровывает обфускацию
                          ├─ Определяет целевой DC Telegram
                          ├─ dispatcher.Dispatch() → routing → outbound
                          └─ Проксирует клиент ↔ DC Telegram
```

### Ключевые детали

- **mtglib.Proxy** — ядро обработки: криптография, anti-replay, DC routing, domain fronting
- **xrayNetwork** — адаптер mtglib.Network → xray dispatcher для исходящих соединений
- **Secret** — hex-ключ MTProto. Генерируется `mtg generate-secret`
- **CanSpliceCopy = 3** — mtglib управляет I/O самостоятельно

## Параметры конфигурации

```json
{
  "protocol": "mtproto",
  "settings": {
    "secret": "hex-строка секрета",
    "concurrency": 8,
    "allowFallbackOnUnknownDc": true,
    "preferIp": "prefer-ipv6",
    "autoUpdate": true,
    "domainFrontingPort": 443,
    "tolerateTimeSkewnessSeconds": 120,
    "antiReplay": true
  }
}
```

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `secret` | string | **обязательно** | MTProto secret в hex |
| `concurrency` | uint | 8 | Горутины для обработки |
| `allowFallbackOnUnknownDc` | bool | false | Фоллбэк на ближайший DC |
| `preferIp` | string | "prefer-ipv6" | `"prefer-ipv4"`, `"prefer-ipv6"`, `"only-ipv4"`, `"only-ipv6"` |
| `autoUpdate` | bool | false | Автообновление списка DC |
| `domainFrontingPort` | uint | 443 | Порт для domain fronting |
| `tolerateTimeSkewnessSeconds` | uint | 120 | Допустимый рассинхрон времени |
| `antiReplay` | bool | false | Anti-replay кэш (Stable Bloom Filter) |

## Генерация secret

```bash
go install github.com/9seconds/mtg/v2@latest
mtg generate-secret tls ya.ru
# Клиенту — полный secret. В конфиг Xray — hex-часть без префикса dd.
```
