# Selector -> inbound routing fix

## Симптом

При маршрутизации TLS-соединения через selector на inbound VLESS с TLS/Reality:

```
proxy/selector: selector: routing to handler [inbound-444] tls=true sni= ech=false mtproto=false
proxy/vless/inbound: firstLen = 24
connection ends > proxy/vless/inbound: invalid request from ... > proxy/vless/encoding: invalid request version
```

## Корневая причина

Selector вызывал `proxy.Process()` напрямую, **обходя транспортный уровень** (TLS/Reality), который в нормальном потоке выполняется в `keepAccepting()` TCP listener'а (`transport/internet/tcp/hub.go:116-128`).

VLESS получал сырые TLS-данные (байт `0x16`) вместо расшифрованного VLESS-протокола (байт `0x00`).

MTProto работал потому что у него нет TLS на транспорте — прямой `proxy.Process()` корректен.

## Неудачные подходы

**1. bufferedConn + tls.Server/reality.Server** — оборачивали прочитанные байты в `bufferedConn` (`io.MultiReader`), применяли TLS/Reality к обёртке. `bufferedConn` не реализует нативные интерфейсы Reality (`CloseWriteConn`, `SyscallConn`, splice), даже после добавления `CloseWrite()` — panic или невалидные данные.

**2. Pipe к listener'у (loopback)** — `net.Dial("tcp", "127.0.0.1:port")` + двунаправленное копирование. Overhead, потеря client IP, требует listener на порту.

## Решение: MSG_PEEK + нативное соединение

### Идея

`syscall.Recvfrom(fd, buf, MSG_PEEK)` подсматривает данные в socket buffer **без потребления**. Оригинальный `*net.TCPConn` передаётся в TLS/Reality transport нетронутым — все нативные интерфейсы работают.

```
клиент → selector → peekBytes(MSG_PEEK) → детекция протокола
                     [данные ОСТАЮТСЯ в socket buffer]
                                ↓
         ┌──────────────────────┴──────────────────────┐
         │ handler с TLS/Reality                       │ handler без transport security
         │                                             │
         │ unwrap CounterConnection → *net.TCPConn     │ unwrap → *net.TCPConn
         │ tls.Server() / reality.Server()             │ proxy.Process() напрямую
         │ transport читает байты из socket buffer      │ proxy читает из socket buffer
         │ → TLS handshake → расшифрованные данные     │
         │ → proxy.Process()                           │
         └─────────────────────────────────────────────┘
```

### Параметры peek

| Параметр | Дефолт | Описание |
|---|---|---|
| `readSize` | 2048 | Макс размер peek буфера |
| `minPeekSize` | 16 | Мин байт перед детекцией |
| `peekTimeoutMs` | 5000 | Таймаут (мс) от зависших соединений |

```json
{
  "protocol": "selector",
  "settings": {
    "readSize": 2048,
    "minPeekSize": 16,
    "peekTimeoutMs": 5000,
    "rules": [...],
    "defaultHandlerTag": "..."
  }
}
```

### Механика peek

1. `SetReadDeadline(now + timeout)` — ограничиваем ожидание
2. Цикл `MSG_PEEK` — повторяем пока не наберётся `minPeekSize` байт
3. Между попытками `5ms` пауза для прибытия данных в socket buffer
4. Если таймаут но есть байты → partial detection (TLS type без SNI)
5. `SetReadDeadline(zero)` — сбрасываем deadline после peek

### Платформы

Общая логика в `peek.go`, platform-specific только `recvfromPeek()` + `isRetryable()`:

| Файл | Платформа | Отличие |
|---|---|---|
| `peek.go` | Все | Общая логика: deadline, retry loop, ошибки |
| `peek_unix.go` | Linux, macOS, BSD | `Recvfrom(int(fd), MSG_PEEK)`, `EAGAIN`/`EWOULDBLOCK` |
| `peek_windows.go` | Windows | `Recvfrom(Handle(fd), 0x2)`, `WSAEWOULDBLOCK` (10035) |

### Применение transport security

```go
processConn := unwrapRawConn(conn)                          // CounterConnection → *net.TCPConn
processConn, err = applyTransportSecurity(processConn, handler) // TLS/Reality если есть
inboundProxy.Process(ctx, network, processConn, dispatcher)
```

`applyTransportSecurity()` проверяет `ReceiverSettings()` handler'а:
- Есть TLS → `tls.Server(conn, config.GetTLSConfig())`
- Есть Reality → `reality.Server(conn, config.GetREALITYConfig())`
- Нет security → conn без изменений

### Почему это работает

1. **MSG_PEEK** не потребляет данные — `Read()` вернёт те же байты
2. **Оригинальный `*net.TCPConn`** — `CloseWrite`, `SyscallConn`, splice, sendfile
3. **Reality** получает настоящий TCP-сокет → `MirrorConn`, type assertions, `io.Copy` работают
4. **Универсально** — любой транспорт (TLS, Reality, plain TCP) без спецобработки
5. **Zero-copy detection** — данные остаются в kernel buffer

## Изменённые файлы

| Файл | Что изменено |
|---|---|
| `proxy/selector/selector.go` | Peek + apply transport + конфиг параметры |
| `proxy/selector/peek.go` | **Новый.** Общая логика peek с retry и timeout |
| `proxy/selector/peek_unix.go` | **Новый.** `recvfromPeek()` для Unix |
| `proxy/selector/peek_windows.go` | **Новый.** `recvfromPeek()` для Windows |
| `proxy/selector/config.proto` | Поля `peek_timeout_ms`, `min_peek_size` |
| `proxy/selector/config.pb.go` | Соответствующие поля + getter'ы |
| `infra/conf/selector.go` | JSON-поля `peekTimeoutMs`, `minPeekSize` |

Основной код (handler'ы, worker'ы, transport layer) **не затронут**.
