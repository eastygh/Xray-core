# Selector Proxy — принципы работы и примеры конфигураций

## Принцип работы

Selector — это inbound-proxy, который работает как мультиплексор протоколов на одном порту. Вместо того чтобы обрабатывать трафик самостоятельно, он анализирует первые байты соединения, определяет протокол и делегирует обработку другому inbound-хендлеру.

### Цепочка обработки

```
Клиент → TCP:443 → Selector
                      │
                      ├─ Читает первые 2048 байт (настраиваемо)
                      ├─ Анализирует: TLS? SNI? ECH? MTProto? HTTP?
                      ├─ Проверяет правила по порядку
                      ├─ Находит первое совпадение → берет handler_tag
                      ├─ Получает proxy.Inbound целевого хендлера через inbound.Manager
                      ├─ Оборачивает connection в bufferedConn (возвращает прочитанные байты)
                      │
                      └─ Вызывает targetProxy.Process(ctx, network, bufferedConn, dispatcher)
                           │
                           ├── VLESS handler (tag: "vless-in")
                           ├── Trojan handler (tag: "trojan-in")
                           ├── VMess handler (tag: "vmess-in")
                           └── ... любой другой inbound
```

### Ключевые детали

**bufferedConn** — обертка поверх `net.Conn`, которая сначала отдает уже прочитанные байты через `io.MultiReader`, а затем читает из реального соединения. Целевой хендлер не знает, что байты были предварительно прочитаны — для него соединение выглядит нормально.

**Делегирование без сетевого соединения** — selector обращается к целевому хендлеру через Go-интерфейс `proxy.Inbound.Process()`, а не через сетевое соединение. Даже если целевой хендлер слушает на localhost:10001, selector вызывает его proxy напрямую в том же процессе.

**Правила проверяются последовательно** — первое совпадение побеждает. Если ни одно правило не сработало, используется `defaultHandlerTag`.

### Детекция протоколов

| Протокол | Как определяется |
|---|---|
| **TLS** | Первый байт = `0x16`, второй байт = `0x03` (TLS record layer) |
| **SNI** | Парсинг TLS ClientHello → extension `0x0000` (server_name) |
| **ECH** | Наличие extension `0xfe0d` (encrypted_client_hello) в ClientHello |
| **MTProto** | Эвристика: не TLS, не HTTP, >= 64 байт, высокая энтропия первых 56 байт |
| **HTTP** | Начинается с GET/POST/HEAD/PUT/DELETE/OPTIONS/CONNECT/PATCH |

### Типы правил (match)

| match | Описание | pattern |
|---|---|---|
| `tls` | TLS без ECH. Если задан pattern — матч по SNI. | regex по SNI |
| `ech` | TLS с ECH extension. Если задан pattern — матч по внешнему SNI. | regex по outer SNI |
| `tls_default` | Любой TLS (catch-all для TLS после более специфичных правил). | игнорируется |
| `notls` | Соединение не является TLS. | игнорируется |
| `mtproto` | Определен как MTProto по эвристике. | игнорируется |
| `unknown` | Не TLS и не MTProto (catch-all для всего остального). | игнорируется |

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
        "handlerTag": "тег целевого inbound-хендлера"
      }
    ],
    "defaultHandlerTag": "тег по умолчанию (если ни одно правило не сработало)",
    "readSize": 2048
  }
}
```

| Поле | Тип | Описание |
|---|---|---|
| `rules` | array | Список правил маршрутизации (проверяются по порядку) |
| `rules[].match` | string | Тип проверки: `tls`, `ech`, `tls_default`, `notls`, `mtproto`, `unknown` |
| `rules[].pattern` | string | Regex-паттерн для SNI (только для `tls` и `ech`). Пустой = любой SNI. |
| `rules[].handlerTag` | string | Тег inbound-хендлера, которому делегировать соединение |
| `defaultHandlerTag` | string | Fallback-хендлер, если ни одно правило не сработало |
| `readSize` | int | Сколько байт читать для детекции (по умолчанию 2048) |

---

## Примеры конфигураций

### Пример 1: VLESS + Trojan на одном порту, разделение по SNI

Два протокола на порту 443, каждый привязан к своему домену.

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
      "streamSettings": {
        "network": "tcp"
      }
    },
    {
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "flow": "xtls-rprx-vision"
          }
        ],
        "fallbacks": []
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/vless.example.com.crt",
              "keyFile": "/etc/ssl/vless.example.com.key"
            }
          ]
        }
      }
    },
    {
      "tag": "trojan-in",
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "my-secret-password"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/trojan.example.com.crt",
              "keyFile": "/etc/ssl/trojan.example.com.key"
            }
          ]
        }
      }
    },
    {
      "tag": "fallback-in",
      "listen": "127.0.0.1",
      "port": 10080,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 8080,
        "network": "tcp"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
```

### Пример 2: ECH-трафик на отдельный хендлер

Соединения с ECH extension обрабатываются отдельным VLESS-хендлером с ECH-ключами.

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
            "match": "ech",
            "handlerTag": "vless-ech"
          },
          {
            "match": "tls",
            "pattern": "\\.example\\.com$",
            "handlerTag": "vless-standard"
          },
          {
            "match": "tls_default",
            "handlerTag": "nginx-backend"
          },
          {
            "match": "notls",
            "handlerTag": "http-redirect"
          }
        ]
      }
    },
    {
      "tag": "vless-ech",
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "aaaaaaaa-1111-2222-3333-444444444444" }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/ech.example.com.crt",
              "keyFile": "/etc/ssl/ech.example.com.key"
            }
          ],
          "echServerKeys": "base64-encoded-ech-keys"
        }
      }
    },
    {
      "tag": "vless-standard",
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "bbbbbbbb-1111-2222-3333-444444444444" }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/example.com.crt",
              "keyFile": "/etc/ssl/example.com.key"
            }
          ]
        }
      }
    },
    {
      "tag": "nginx-backend",
      "listen": "127.0.0.1",
      "port": 10003,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 8443,
        "network": "tcp"
      }
    },
    {
      "tag": "http-redirect",
      "listen": "127.0.0.1",
      "port": 10004,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 80,
        "network": "tcp"
      }
    }
  ]
}
```

### Пример 3: MTProto + обычный прокси

Совмещение MTProto Telegram-прокси и VLESS на одном порту.

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
            "match": "mtproto",
            "handlerTag": "mtproto-in"
          },
          {
            "match": "tls",
            "handlerTag": "vless-in"
          },
          {
            "match": "unknown",
            "handlerTag": "blackhole"
          }
        ]
      }
    },
    {
      "tag": "mtproto-in",
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 9443,
        "network": "tcp"
      }
    },
    {
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/example.com.crt",
              "keyFile": "/etc/ssl/example.com.key"
            }
          ]
        }
      }
    },
    {
      "tag": "blackhole",
      "listen": "127.0.0.1",
      "port": 10099,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 1,
        "network": "tcp"
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
```

### Пример 4: Мульти-доменный хостинг с regex

Множество доменов маршрутизируются на разные бэкенды по wildcard-паттернам.

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
            "pattern": "^api\\.",
            "handlerTag": "api-vless"
          },
          {
            "match": "tls",
            "pattern": "^(www\\.)?shop\\.",
            "handlerTag": "shop-trojan"
          },
          {
            "match": "tls",
            "pattern": "\\.(ru|by|kz)$",
            "handlerTag": "cis-vless"
          },
          {
            "match": "tls_default",
            "handlerTag": "default-nginx"
          },
          {
            "match": "notls",
            "handlerTag": "http-to-https"
          }
        ]
      }
    },
    {
      "tag": "api-vless",
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "11111111-1111-1111-1111-111111111111" }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/wildcard.crt",
              "keyFile": "/etc/ssl/wildcard.key"
            }
          ]
        }
      }
    },
    {
      "tag": "shop-trojan",
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "trojan",
      "settings": {
        "clients": [
          { "password": "shop-secret" }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/wildcard.crt",
              "keyFile": "/etc/ssl/wildcard.key"
            }
          ]
        }
      }
    },
    {
      "tag": "cis-vless",
      "listen": "127.0.0.1",
      "port": 10003,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "22222222-2222-2222-2222-222222222222" }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/wildcard.crt",
              "keyFile": "/etc/ssl/wildcard.key"
            }
          ]
        }
      }
    },
    {
      "tag": "default-nginx",
      "listen": "127.0.0.1",
      "port": 10080,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 8443,
        "network": "tcp"
      }
    },
    {
      "tag": "http-to-https",
      "listen": "127.0.0.1",
      "port": 10081,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 80,
        "network": "tcp"
      }
    }
  ]
}
```

---

## Важные замечания

### TLS termination

Selector читает **сырые байты до TLS-расшифровки**. Поэтому:
- У selector'а в `streamSettings` **не должно быть** `"security": "tls"` — иначе TLS терминируется ДО selector'а и он увидит расшифрованный трафик вместо ClientHello.
- TLS должен терминироваться на **целевых хендлерах** (у них `"security": "tls"` в `streamSettings`).

### Порядок правил

Правила проверяются сверху вниз, первое совпадение побеждает. Рекомендуемый порядок:
1. Специфичные TLS/ECH-правила с pattern (конкретные домены)
2. `tls_default` — catch-all для TLS
3. `mtproto` — MTProto-трафик
4. `notls` — не-TLS трафик
5. `unknown` — все остальное

### gRPC-управление пользователями

Целевые хендлеры — обычные inbound-записи с собственными тегами. Управление пользователями через gRPC API (`AlterInbound` / `AddUserOperation` / `RemoveUserOperation`) работает как обычно — обращайтесь по тегу целевого хендлера, а не selector'а.

### MTProto детекция

Детекция MTProto основана на эвристике (не TLS, не HTTP, >= 64 байт, высокая энтропия). Это может давать ложные срабатывания на другие бинарные протоколы. Рекомендуется ставить правило `mtproto` **после** `tls` и `notls` правил, чтобы оно срабатывало только на нераспознанный бинарный трафик.
