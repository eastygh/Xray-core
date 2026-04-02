# Selector: архитектура маршрутизации

## Два режима передачи соединений

Selector определяет протокол по первым байтам (MSG_PEEK) и маршрутизирует к целевому handler'у одним из двух способов:

### 1. Loopback relay (handler с TLS/Reality)

Если целевой handler имеет transport security (`StreamSettings.SecurityType != ""`), selector устанавливает TCP-соединение к локальному порту handler'а и релеит данные. Handler получает соединение через свой штатный TCP listener → TLS handshake → proxy.Process.

```
клиент → selector:443 → net.Dial("127.0.0.1:10001") → handler listener
                         ↕ buf.Copy (bidirectional)      ↓
                         ← ← ← ← ← ← ← ← ← ← ←    TLS → proxy.Process
```

Опционально перед relay отправляется PROXY protocol v1/v2 header для передачи реального client IP.

### 2. Direct call (handler без transport security)

Если handler не имеет transport security (plain TCP, mtproto), selector вызывает `handler.GetInbound().Process()` напрямую, подменяя `inbound.Tag` на тег целевого handler'а.

```
клиент → selector:443 → handler.Process(ctx, network, conn, dispatcher)
                         [inbound.Tag = "mtproto-in"]
```

### Как определяется режим

Решение loopback/direct принимается по конфигурации **целевого handler'а**, не по типу match:

```
resolveLoopbackAddr(handler):
  SecurityType != ""  → loopback (нужен TLS handshake через listener)
  SecurityType == ""  → direct (transport security отсутствует)
  Нет порта           → direct (некуда подключаться)
```

Это означает что любая комбинация match type + handler type корректна.

## MSG_PEEK

Чтение первых байт через `recvfrom(fd, buf, MSG_PEEK)` — данные остаются в socket buffer. При loopback relay `buf.Copy` передаёт эти же байты серверу. При direct call handler читает их при первом `Read()`.

### Платформы

| Файл | Платформа |
|---|---|
| `peek_unix.go` | Linux, macOS, BSD |
| `peek_windows.go` | Windows |

## Idle timeout и half-close

Relay использует `signal.CancelAfterInactivity` (5 мин) с `buf.UpdateActivity(timer)` на обоих направлениях. После завершения client → server вызывается `CloseWrite()` на server conn для корректного TCP half-close.

## Конфигурация правил

```json
{
  "match": "tls",
  "pattern": "^ya\\.ru$",
  "handlerTag": "vless-in",
  "loopbackAddr": "127.0.0.1:10001",
  "proxyProtocol": 1
}
```

| Поле | Описание |
|---|---|
| `loopbackAddr` | Явный адрес для relay. Если пустой — автоматически из ReceiverConfig handler'а |
| `proxyProtocol` | 0 = off, 1 = PROXY v1 (текст), 2 = PROXY v2 (бинарный) |

## Изменённые файлы

| Файл | Назначение |
|---|---|
| `proxy/selector/selector.go` | Routing logic, resolveLoopbackAddr |
| `proxy/selector/relay.go` | Loopback relay + PROXY protocol (через go-proxyproto) |
| `proxy/selector/peek.go` | MSG_PEEK с retry и timeout |
| `proxy/selector/peek_unix.go` | recvfromPeek для Unix |
| `proxy/selector/peek_windows.go` | recvfromPeek для Windows |
| `proxy/selector/detect.go` | Детекция TLS/ECH/MTProto |
| `proxy/selector/config.proto` | Protobuf-определение Config и Rule |
| `infra/conf/selector.go` | JSON-конфиг → protobuf |
