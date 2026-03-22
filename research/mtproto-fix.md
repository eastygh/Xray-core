# Fix: MTProto outbound tunneling deadlock

## Симптомы

MTProto inbound принимает соединения от Telegram-клиентов, но исходящие соединения через xray dispatcher (VLESS outbound) зависают и закрываются с 0 переданных байт:

```
proxy/vless/outbound: tunneling request to tcp:95.161.76.100:443 via my.vless.com:443
proxy/mtproto: mtproto.proxy.relay: telegram -> client has been finished
proxy/mtproto: mtproto.proxy.relay: client -> telegram has been finished (written 0 bytes): io: read/write on closed pipe
proxy/mtproto: mtproto.proxy: Stream has been finished
```

Между запросом tunnel и завершением relay — 2мс. Соединение закрывается до передачи данных.

## Root Cause: Deadlock в DialContext

**Файл:** `proxy/mtproto/network.go`, метод `DialContext`

Использовался `DispatchLink` — **синхронный** метод диспетчера.

### Цепочка deadlock

```
mtglib.ServeConn()
  └─ xrayNetwork.DialContext()
       └─ dispatcher.DispatchLink()          ← СИНХРОННЫЙ, блокирует
            └─ routedDispatch()
                 └─ handler.Dispatch()
                      └─ VLESS.Process()
                           └─ task.Run(postRequest, getResponse)  ← блокирует до завершения relay
                                │
                                ├─ postRequest: buf.Copy(uplinkReader → remote)
                                │   └─ ЖДЁТ данных от mtglib через pipe
                                │
                                └─ getResponse: buf.Copy(remote → downlinkWriter)
                                    └─ ЖДЁТ ответа от сервера

mtglib НЕ МОЖЕТ писать в pipe, потому что DialContext ещё не вернул соединение
→ DEADLOCK
```

### Dispatch vs DispatchLink

| Метод | Поведение | Файл |
|---|---|---|
| `Dispatch()` | Создаёт pipes, запускает `go routedDispatch()` **асинхронно**, возвращает link сразу | `dispatcher/default.go:281` |
| `DispatchLink()` | Принимает pipes, вызывает `routedDispatch()` **синхронно**, блокирует до завершения | `dispatcher/default.go:338` |

## Fix

Заменил `DispatchLink` на `Dispatch` в `proxy/mtproto/network.go:DialContext`:

**Было:**
```go
func (n *xrayNetwork) DialContext(ctx context.Context, network, address string) (essentials.Conn, error) {
    dest := parseDestination(network, address)
    dispCtx := n.getContext()

    outbounds := session.OutboundsFromContext(dispCtx)
    if len(outbounds) > 0 {
        ob := outbounds[len(outbounds)-1]
        ob.Target = dest
    }

    uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
    downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())

    err := n.dispatcher.DispatchLink(dispCtx, dest, &transport.Link{
        Reader: uplinkReader,
        Writer: downlinkWriter,
    })
    if err != nil {
        return nil, err
    }

    conn := cnc.NewConnection(
        cnc.ConnectionInputMulti(uplinkWriter),
        cnc.ConnectionOutputMulti(downlinkReader),
        cnc.ConnectionRemoteAddr(&net.TCPAddr{IP: dest.Address.IP(), Port: int(dest.Port)}),
    )
    return essentials.WrapNetConn(conn), nil
}
```

**Стало:**
```go
func (n *xrayNetwork) DialContext(ctx context.Context, network, address string) (essentials.Conn, error) {
    dest := parseDestination(network, address)
    dispCtx := n.getContext()

    link, err := n.dispatcher.Dispatch(dispCtx, dest)
    if err != nil {
        return nil, err
    }

    conn := cnc.NewConnection(
        cnc.ConnectionInputMulti(link.Writer),
        cnc.ConnectionOutputMulti(link.Reader),
        cnc.ConnectionRemoteAddr(&net.TCPAddr{IP: dest.Address.IP(), Port: int(dest.Port)}),
    )
    return essentials.WrapNetConn(conn), nil
}
```

### Что изменилось

1. **`DispatchLink` → `Dispatch`** — асинхронный dispatch, не блокирует DialContext
2. **Убрано ручное создание pipes** — `Dispatch` создаёт их сам внутри `getLink()`
3. **Убрана ручная установка `ob.Target`** — `Dispatch` делает это автоматически (строки 290-292)
4. **Убраны неиспользуемые импорты** — `session`, `transport`, `transport/pipe`

### Почему это работает

```
mtglib.ServeConn()
  └─ xrayNetwork.DialContext()
       └─ dispatcher.Dispatch()              ← АСИНХРОННЫЙ
            ├─ создаёт pipes
            ├─ запускает go routedDispatch()  ← в отдельной горутине
            └─ возвращает link СРАЗУ
       └─ cnc.NewConnection(link.Writer, link.Reader)
       └─ return conn                        ← mtglib получает соединение
  └─ mtglib начинает relay
       ├─ пишет в link.Writer → uplinkWriter → uplinkReader → VLESS читает → remote
       └─ читает из link.Reader ← downlinkReader ← downlinkWriter ← VLESS пишет ← remote
```

Теперь mtglib получает соединение сразу и может начать relay параллельно с outbound processing.

## Изменённые файлы

- `proxy/mtproto/network.go` — метод `DialContext`, убраны неиспользуемые импорты
