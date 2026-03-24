# Selector -> VLESS routing fix

## Симптом

При маршрутизации TLS-соединения через selector на inbound VLESS с XTLS-Reality:

```
proxy/selector: selector: routing to handler [inbound-444] tls=true sni= ech=false mtproto=false
proxy/vless/inbound: firstLen = 60
app/proxyman/inbound: connection ends > proxy/vless/inbound: invalid request from ... > proxy/vless/encoding: invalid request version
```

VLESS получает `firstLen = 60` и ошибку "invalid request version". При этом на mtproto перенаправление работает нормально.

## Корневая причина

### Нормальный поток данных (без selector)

```
TCP listener → keepAccepting() → TLS/Reality handshake → decrypted conn → proxy.Process()
```

В `transport/internet/tcp/hub.go:116-128` при приёме соединения listener выполняет:
1. `tls.Server(conn, tlsConfig)` — если настроен TLS
2. `reality.Server(conn, realityConfig)` — если настроен Reality
3. Передаёт **расшифрованное** соединение в callback worker'а
4. Worker вызывает `proxy.Process()` с уже расшифрованными данными

### Поток через selector (до исправления)

```
TCP listener → selector.Process() → read first bytes → detect TLS →
    bufferedConn(raw TLS data) → vless.Process() ← ОШИБКА!
```

Selector вызывал `inboundProxy.Process()` напрямую через интерфейс `proxy.GetInbound`, **полностью обходя транспортный уровень** целевого handler'а. VLESS получал сырые TLS-данные:
- Первый байт: `0x16` (TLS record type) вместо `0x00` (VLESS version)
- Отсюда "invalid request version"
- `firstLen = 60` — это длина TLS ClientHello фрагмента, а не VLESS заголовка

### Почему mtproto работал

MTProto — это протокол прикладного уровня без TLS-обёртки на транспорте. Его inbound handler не настроен с TLS/Reality в `streamSettings`, поэтому прямой вызов `proxy.Process()` получал именно те данные, которые ожидал.

## Исправление

Файл: `proxy/selector/selector.go`

После создания `bufferedConn` (с replay первых байт), selector теперь проверяет настройки транспорта целевого handler'а и применяет TLS/Reality handshake перед вызовом `proxy.Process()`:

```go
var wrappedConn stat.Connection = newBufferedConn(conn, firstBytes)
if rs := handler.(inbound.Handler).ReceiverSettings(); rs != nil {
    if msg, err := rs.GetInstance(); err == nil {
        if rc, ok := msg.(*proxyman.ReceiverConfig); ok && rc.StreamSettings != nil {
            if mss, err := internet.ToMemoryStreamConfig(rc.StreamSettings); err == nil {
                if tlsConfig := tls.ConfigFromStreamSettings(mss); tlsConfig != nil {
                    wrappedConn = tls.Server(wrappedConn, tlsConfig.GetTLSConfig())
                } else if realityConfig := reality.ConfigFromStreamSettings(mss); realityConfig != nil {
                    realityConn, err := reality.Server(wrappedConn, realityConfig.GetREALITYConfig())
                    // ...
                    wrappedConn = realityConn
                }
            }
        }
    }
}
return inboundProxy.Process(ctx, network, wrappedConn, dispatcher)
```

### Как это работает

1. `handler.ReceiverSettings()` → получаем `*proxyman.ReceiverConfig` через protobuf десериализацию
2. `rc.StreamSettings` → достаём настройки транспорта целевого handler'а
3. `internet.ToMemoryStreamConfig()` → конвертируем в рабочий формат
4. `tls.ConfigFromStreamSettings()` / `reality.ConfigFromStreamSettings()` → проверяем тип security
5. `tls.Server()` / `reality.Server()` — это те же самые функции, которые вызывает `keepAccepting()` в TCP listener'е
6. `bufferedConn` через `io.MultiReader` воспроизводит прочитанные selector'ом байты → Reality/TLS получает полный ClientHello и выполняет handshake нормально

### Исправленный поток

```
TCP listener → selector.Process() → read first bytes → detect TLS →
    bufferedConn(raw TLS data) → Reality handshake → decrypted conn → vless.Process() ✓
```

## Изменённые файлы

- `proxy/selector/selector.go` — добавлено применение TLS/Reality из stream settings целевого handler'а

## Без изменений в основном коде

Исправление не затрагивает интерфейсы, handler'ы, worker'ы или транспортный уровень. Используются только существующие публичные API:
- `inbound.Handler.ReceiverSettings()`
- `serial.TypedMessage.GetInstance()`
- `internet.ToMemoryStreamConfig()`
- `tls.ConfigFromStreamSettings()` / `reality.ConfigFromStreamSettings()`
- `tls.Server()` / `reality.Server()`
