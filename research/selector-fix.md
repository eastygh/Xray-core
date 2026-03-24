# Selector -> inbound routing fix

## Симптом

При маршрутизации TLS-соединения через selector на inbound VLESS с TLS/Reality:

```
proxy/selector: selector: routing to handler [inbound-444] tls=true sni= ech=false mtproto=false
proxy/vless/inbound: firstLen = 24
app/proxyman/inbound: connection ends > proxy/vless/inbound: invalid request from ... > proxy/vless/encoding: invalid request version
```

VLESS получает "invalid request version". При этом на mtproto перенаправление работает нормально.

## Корневая причина

### Нормальный поток данных (без selector)

```
клиент → TCP listener → keepAccepting() → TLS/Reality handshake → decrypted conn → proxy.Process()
```

В `transport/internet/tcp/hub.go:116-128` при приёме соединения listener'ом:
1. `tls.Server(conn, tlsConfig)` — если настроен TLS
2. `reality.Server(conn, realityConfig)` — если настроен Reality
3. Передаёт **расшифрованное** соединение в callback worker'а
4. Worker вызывает `proxy.Process()` с уже расшифрованными данными

### Поток через selector (до исправления)

```
клиент → selector.Process() → read first bytes → detect TLS →
    bufferedConn(raw TLS data) → vless.Process() ← ОШИБКА: VLESS видит 0x16 вместо 0x00
```

Selector вызывал `inboundProxy.Process()` напрямую через `proxy.GetInbound`, **полностью обходя транспортный уровень** целевого handler'а.

### Почему mtproto работал

MTProto — протокол прикладного уровня без TLS на транспорте. Прямой вызов `proxy.Process()` работает корректно.

### Почему нельзя просто применить TLS/Reality в selector

Первый подход: реконструировать TLS/Reality конфиг из protobuf настроек handler'а и вызвать `tls.Server()` / `reality.Server()` в selector'е.

**Проблемы этого подхода:**
1. **Reality** имеет сложную внутреннюю логику (MirrorConn, dial to dest, DetectPostHandshakeRecordsLens) — реконструкция конфига из protobuf roundtrip может терять runtime-состояние
2. **bufferedConn** не реализует все интерфейсы, которые ожидает Reality (`CloseWriteConn`, и потенциально другие через type assertion)
3. **Не универсально** — нужно отдельно обрабатывать TLS, Reality, а также потенциально WebSocket, gRPC и другие транспорты
4. Результат: handshake проходит, но расшифрованные данные невалидны (`firstLen = 24`, не VLESS)

## Исправление: pipe к listener'у handler'а

Файл: `proxy/selector/selector.go`

Вместо прямого вызова `proxy.Process()` для handler'ов с transport security, selector теперь **перенаправляет сырое TCP-соединение на listener целевого handler'а**. Это тот же подход, который используют VLESS fallbacks.

### Алгоритм

```
1. selector читает первые байты → определяет протокол (TLS/SNI/MTProto)
2. Находит целевой handler по правилам
3. Проверяет: есть ли у handler'а transport security (TLS/Reality)?

   ДА → pipe на listener handler'а (handler сам выполнит TLS/Reality):
       bufferedConn ←→ net.Dial("tcp", "127.0.0.1:port") ←→ handler listener

   НЕТ → прямой вызов proxy.Process() (как раньше):
       bufferedConn → proxy.Process()
```

### Ключевые функции

**`getHandlerListenAddr(handler)`** — извлекает адрес listener'а из `ReceiverSettings`:
- Декодирует `ReceiverConfig` из protobuf
- Проверяет наличие `StreamSettings.HasSecuritySettings()`
- Возвращает `"host:port"` или `""` если pipe не нужен

**`pipeToListener(clientConn, addr)`** — двунаправленное копирование:
- `net.Dial("tcp", addr)` — подключение к listener'у handler'а
- Два goroutine: `client→handler` и `handler→client`
- `CloseWrite()` для корректного завершения TLS

### Исправленный поток

```
клиент → selector → detect TLS → pipe → handler listener → TLS handshake → proxy.Process() ✓
клиент → selector → detect MTProto → direct proxy.Process() ✓
```

## Преимущества подхода

1. **Универсальность** — работает с любым транспортом (TLS, Reality, WebSocket, gRPC, etc.)
2. **Надёжность** — используется тот же code path, что и при прямом подключении к handler'у
3. **Малоинвазивность** — изменения только в `proxy/selector/selector.go`
4. **Проверенный паттерн** — аналогичен VLESS fallbacks (`transport/internet/tcp/hub.go`)

## Ограничения

1. **Overhead** — добавляется локальное TCP-соединение через loopback (минимальная задержка, ~50μs)
2. **Client IP** — handler видит source IP как 127.0.0.1, а не IP клиента. Для сохранения IP можно в будущем добавить PROXY protocol
3. **Требуется listener** — целевой handler должен слушать на порту. Если у handler'а нет порта, pipe невозможен (fallback на прямой proxy.Process)

## Изменённые файлы

- `proxy/selector/selector.go` — pipe для handler'ов с transport security
