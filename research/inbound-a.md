# Обработка Inbound-соединений в Xray-core: от создания до рабочей нагрузки

## 1. Создание и инициализация Inbound-хендлеров

### 1.1 Загрузка конфигурации при старте

**Файл:** `core/xray.go`

```
New(config) → initInstanceWithConfig() → addInboundHandlers() → AddInboundHandler()
```

`AddInboundHandler` получает `inbound.Manager` из реестра фич и вызывает `CreateObject` для создания хендлера из конфига:

```go
func AddInboundHandler(server *Instance, config *InboundHandlerConfig) error {
    inboundManager := server.GetFeature(inbound.ManagerType()).(inbound.Manager)
    rawHandler, err := CreateObject(server, config)
    handler, ok := rawHandler.(inbound.Handler)
    return inboundManager.AddHandler(server.ctx, handler)
}
```

### 1.2 Интерфейс Handler

**Файл:** `features/inbound/inbound.go`

```go
type Handler interface {
    common.Runnable              // Start() и Close()
    Tag() string
    ReceiverSettings() *serial.TypedMessage
    ProxySettings() *serial.TypedMessage
}

type Manager interface {
    features.Feature
    GetHandler(ctx context.Context, tag string) (Handler, error)
    AddHandler(ctx context.Context, handler Handler) error
    RemoveHandler(ctx context.Context, tag string) error
    ListHandlers(ctx context.Context) []Handler
}
```

### 1.3 Manager — хранение хендлеров

**Файл:** `app/proxyman/inbound/inbound.go`

```go
type Manager struct {
    access           sync.RWMutex
    untaggedHandlers []inbound.Handler
    taggedHandlers   map[string]inbound.Handler
    running          bool
}
```

`AddHandler` помещает хендлер в `taggedHandlers` (по тегу) или `untaggedHandlers`. Если менеджер уже запущен — сразу вызывает `handler.Start()`.

### 1.4 AlwaysOnInboundHandler — основная реализация

**Файл:** `app/proxyman/inbound/always.go`

```go
type AlwaysOnInboundHandler struct {
    proxy          proxy.Inbound          // конкретная реализация протокола (VMess, VLESS, Trojan...)
    receiverConfig *proxyman.ReceiverConfig
    workers        []worker               // TCP/UDP/DS воркеры
    mux            *mux.Server            // мультиплексор
    tag            string
}
```

Создание (`NewAlwaysOnInboundHandler`):
1. Создает proxy-реализацию через `common.CreateObject(ctx, proxyConfig)` → `proxy.Inbound`
2. Создает `mux.Server` — диспетчер мультиплексированных соединений
3. Парсит stream settings (TLS, REALITY, transport)
4. Для каждого порта/сети создает воркер:
   - **tcpWorker** — TCP-соединения
   - **udpWorker** — UDP-пакеты
   - **dsWorker** — Unix Domain Socket

### 1.5 Запуск

```
Manager.Start() → для каждого handler: handler.Start() → для каждого worker: worker.Start()
```

---

## 2. Прием и обработка TCP-соединений

### 2.1 TCP Listener

**Файл:** `transport/internet/tcp/hub.go`

`tcpWorker.Start()` вызывает `internet.ListenTCP()`, который:
1. Создает системный TCP-слушатель через `internet.ListenSystem()`
2. Запускает горутину `keepAccepting()`:

```go
func (v *Listener) keepAccepting() {
    for {
        conn, err := v.listener.Accept()
        go func() {
            if v.tlsConfig != nil {
                conn = tls.Server(conn, v.tlsConfig)
            } else if v.realityConfig != nil {
                conn, err = reality.Server(conn, v.realityConfig)
            }
            if v.authConfig != nil {
                conn = v.authConfig.Server(conn)
            }
            v.addConn(stat.Connection(conn))  // → tcpWorker.callback
        }()
    }
}
```

### 2.2 tcpWorker.callback — точка входа обработки

**Файл:** `app/proxyman/inbound/worker.go:62-135`

```go
func (w *tcpWorker) callback(conn stat.Connection) {
    ctx, cancel := context.WithCancel(w.ctx)

    // 1. Извлечение original destination (TPROXY/REDIRECT)
    if w.recvOrigDest {
        switch getTProxyType(w.stream) {
        case internet.SocketConfig_Redirect:
            dest, _ = tcp.GetOriginalDestination(conn)
        case internet.SocketConfig_TProxy:
            dest = net.DestinationFromAddr(conn.LocalAddr())
        }
    }

    // 2. Обертка счетчиками статистики
    if w.uplinkCounter != nil || w.downlinkCounter != nil {
        conn = &stat.CounterConnection{...}
    }

    // 3. Контекст сессии — метаданные inbound
    ctx = session.ContextWithInbound(ctx, &session.Inbound{
        Source:  net.DestinationFromAddr(conn.RemoteAddr()),
        Local:   net.DestinationFromAddr(conn.LocalAddr()),
        Gateway: net.TCPDestination(w.address, w.port),
        Tag:     w.tag,
        Conn:    conn,
    })

    // 4. Настройка sniffing
    if w.sniffingConfig != nil {
        content.SniffingRequest.Enabled = w.sniffingConfig.Enabled
        content.SniffingRequest.OverrideDestinationForProtocol = w.sniffingConfig.DestinationOverride
        content.SniffingRequest.RouteOnly = w.sniffingConfig.RouteOnly
    }

    // 5. КЛЮЧЕВОЙ ВЫЗОВ: передача в протокольный обработчик
    w.proxy.Process(ctx, net.Network_TCP, conn, w.dispatcher)

    cancel()
    conn.Close()
}
```

### 2.3 proxy.Process — обработка протокола

**Файл:** `proxy/proxy.go`

```go
type Inbound interface {
    Network() []net.Network
    Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error
}
```

Каждый протокол реализует `Process` по одной схеме:

#### Пример: VMess (`proxy/vmess/inbound/inbound.go`)

```go
func (h *Handler) Process(ctx, network, connection, dispatcher) error {
    // 1. Установить deadline для handshake
    connection.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake))

    // 2. Декодировать заголовок запроса VMess
    request, err := svrSession.DecodeRequestHeader(reader, isDrain)

    // 3. Обновить метаданные сессии
    inbound.Name = "vmess"
    inbound.User = request.User

    // 4. DISPATCH — получить link (двунаправленный pipe) от диспетчера
    link, err := dispatcher.Dispatch(ctx, request.Destination())

    // 5. Двунаправленная передача данных
    requestDone := func() error {  // клиент → outbound
        bodyReader := svrSession.DecodeRequestBody(request, reader)
        return buf.Copy(bodyReader, link.Writer, ...)
    }
    responseDone := func() error {  // outbound → клиент
        return transferResponse(timer, svrSession, request, response, link.Reader, writer)
    }
    task.Run(ctx, requestDone, responseDone)
}
```

#### Пример: Trojan (`proxy/trojan/server.go`)

То же, но с fallback-логикой:
```go
func (s *Server) Process(ctx, network, conn, dispatcher) error {
    // 1. Читаем первые байты
    first.ReadFrom(conn)

    // 2. Пытаемся распарсить как Trojan
    if firstLen < 58 || first.Byte(56) != '\r' {
        shouldFallback = true  // не Trojan-протокол
    } else {
        user = s.validator.Get(hexString(first.BytesTo(56)))
        if user == nil { shouldFallback = true }  // неизвестный пользователь
    }

    // 3. Fallback при неудаче
    if isfb && shouldFallback {
        return s.fallback(ctx, err, ..., napfb, first, ...)
    }

    // 4. Нормальная обработка → dispatcher.Dispatch()
}
```

### 2.4 Dispatcher — маршрутизация

**Файл:** `app/dispatcher/default.go`

```go
func (d *DefaultDispatcher) Dispatch(ctx, destination) (*transport.Link, error) {
    // 1. Создать bidirectional pipe (inbound link ← pipe → outbound link)
    inbound, outbound := d.getLink(ctx)

    // 2. Если sniffing включен — определить протокол трафика
    if sniffingRequest.Enabled {
        go func() {
            result, err := sniffer(ctx, cReader, ...)
            if shouldOverride(...) {
                destination.Address = net.ParseAddress(result.Domain())
            }
            d.routedDispatch(ctx, outbound, destination)
        }()
    } else {
        go d.routedDispatch(ctx, outbound, destination)
    }

    return inbound, nil
}
```

### 2.5 routedDispatch — выбор outbound

```go
func (d *DefaultDispatcher) routedDispatch(ctx, link, destination) {
    // Приоритет выбора outbound handler:
    // 1. ForcedOutboundTag (из контекста)
    // 2. Router.PickRoute() (по правилам маршрутизации)
    // 3. Default handler

    handler.Dispatch(ctx, link)  // передать в outbound
}
```

---

## 3. Полная цепочка вызовов

```
TCP Accept (transport/internet/tcp/hub.go)
    │ TLS/REALITY/Auth обертка
    ▼
tcpWorker.callback (app/proxyman/inbound/worker.go)
    │ Создание session context (Inbound metadata, sniffing config)
    ▼
proxy.Inbound.Process (proxy/vmess|vless|trojan|...)
    │ Декодирование протокола, извлечение destination и user
    ▼
Dispatcher.Dispatch (app/dispatcher/default.go)
    │ Создание pipe, опциональный sniffing
    ▼
routedDispatch (app/dispatcher/default.go)
    │ Router.PickRoute() → выбор outbound по правилам
    ▼
outbound.Handler.Dispatch (proxy/freedom|shadowsocks|...)
    │ Подключение к удаленному серверу
    ▼
Remote Server
```

---

## 4. Механизмы переброски соединения на другой handler

### 4.1 Fallback (VLESS / Trojan) — ЕСТЬ

**Файлы:**
- `proxy/vless/inbound/inbound.go:300-509`
- `proxy/trojan/server.go:365-550`

Единственный реальный механизм "переброски" на другой обработчик. Работает так:

1. Соединение приходит на VLESS/Trojan inbound
2. При чтении первых байтов обнаруживается, что это **не VLESS/Trojan** (неверный формат, неизвестный пользователь)
3. Fallback выбирает destination по критериям:
   - **SNI** (Server Name Indication из TLS)
   - **ALPN** (h2, http/1.1)
   - **HTTP Path** (для HTTP-запросов)
4. Устанавливает новое соединение к fallback-destination
5. Проксирует трафик двунаправленно (с опциональным PROXY protocol v1/v2)

```go
type Fallback struct {
    Name  string  // SNI-matching
    Alpn  string  // ALPN-matching
    Path  string  // HTTP path matching
    Dest  string  // куда перенаправить (addr:port или unix socket)
    Xver  uint64  // PROXY protocol version (0/1/2)
}
```

**Ограничения:**
- Срабатывает **только при провале протокольного handshake** — нельзя перенаправить успешное VLESS/Trojan-соединение
- Fallback-destination — это **внешний сервер** (nginx, другой порт), а не другой inbound handler Xray
- Однонаправленный — нельзя вернуть обратно в VLESS/Trojan после fallback

### 4.2 Sniffing + Routing Override — ЧАСТИЧНО

**Файл:** `app/dispatcher/default.go:240-395`

Может изменить **destination** (куда идет трафик), но не может сменить inbound-handler.

- Определяет протокол трафика (HTTP, TLS, QUIC, BitTorrent)
- Может подменить destination domain (из SNI/HTTP Host)
- `RouteOnly=true` — меняет только маршрут, не фактический destination

**Ограничение:** работает только на стороне outbound — после того, как inbound уже обработал протокол.

### 4.3 Inbound Tag Routing — НЕТ переброски

**Файл:** `app/router/condition.go:251-279`

Позволяет маршрутизировать трафик на разные **outbound** в зависимости от inbound-тега. Но это не переброска между inbound-хендлерами — это выбор outbound.

### 4.4 ForcedOutboundTag — НЕТ для inbound

**Файл:** `common/session/context.go:100-113`, `app/dispatcher/default.go:462-473`

Позволяет принудительно выбрать outbound handler через контекст. Опять же — только outbound, не inbound.

### 4.5 Reverse Proxy (VLESS) — СПЕЦИАЛЬНЫЙ СЛУЧАЙ

**Файл:** `proxy/vless/inbound/inbound.go`

VLESS поддерживает `RequestCommandRvs` — команду reverse proxy. Это не переброска на другой handler, а создание динамического outbound для обратного проксирования.

---

## 5. Возможность встроить переброску на другой handler

### Текущее состояние: НЕТ встроенного механизма

Архитектура Xray-core **не предусматривает** переброску соединения между inbound-хендлерами. Ключевые ограничения:

1. **`proxy.Inbound.Process()` — терминальный вызов.** После входа в `Process()` конкретного протокола, соединение обрабатывается до конца. Нет возврата к воркеру для передачи другому протоколу.

2. **Worker жестко привязан к одному proxy.** `tcpWorker.proxy` — одна конкретная реализация (`*vmess.Handler`, `*trojan.Server`...). Все соединения на этом порту идут через один протокол.

3. **Нет интерфейса для "отката".** Если протокол прочитал байты из connection, нет механизма "положить их обратно" и передать другому протоколу (кроме fallback в VLESS/Trojan, который делает это руками через `BufferedReader`).

### Где можно встроить переброску

#### Вариант A: Расширение Fallback-механизма

Самый реалистичный путь — по аналогии с существующим fallback в VLESS/Trojan:

**Точка вставки:** `app/proxyman/inbound/worker.go`, метод `tcpWorker.callback`

```go
func (w *tcpWorker) callback(conn stat.Connection) {
    // ... существующий код setup context ...

    err := w.proxy.Process(ctx, net.Network_TCP, conn, w.dispatcher)

    // НОВОЕ: если Process вернул специальную ошибку "reroute"
    if reroute, ok := err.(*RerouteError); ok {
        // Найти другой handler по тегу
        handler, _ := w.ihm.GetHandler(ctx, reroute.Tag)
        p, _ := getInbound(handler)
        // Передать buffered connection с уже прочитанными байтами
        p.Process(ctx, net.Network_TCP, reroute.BufferedConn, w.dispatcher)
    }
}
```

**Проблема:** tcpWorker не имеет ссылки на `inbound.Manager`. Нужно добавить.

#### Вариант B: Meta-proxy на уровне worker

Создать обертку-proxy, которая:
1. Читает первые байты соединения
2. Определяет протокол (аналог sniffing, но для inbound)
3. Передает `BufferedReader` + connection нужному `proxy.Inbound`

**Точка вставки:** новый тип proxy, оборачивающий несколько `proxy.Inbound`:

```go
type MultiProtocolProxy struct {
    handlers map[string]proxy.Inbound  // протокол → handler
    detector ProtocolDetector
}

func (m *MultiProtocolProxy) Process(ctx, network, conn, dispatcher) error {
    buffered := &buf.BufferedReader{Reader: buf.NewReader(conn)}
    first := buf.New()
    first.ReadFrom(conn)

    protocol := m.detector.Detect(first.Bytes())
    handler := m.handlers[protocol]

    // Создать buffered connection с уже прочитанными байтами
    buffered.Buffer = buf.MultiBuffer{first}
    return handler.Process(ctx, network, wrappedConn, dispatcher)
}
```

#### Вариант C: Модификация Dispatcher для inbound re-entry

Расширить `routing.Dispatcher` для поддержки маршрутизации к inbound-хендлерам (не только outbound). Аналогично тому, как `routedDispatch` выбирает outbound, можно выбрать другой inbound.

**Проблема:** fundamentally меняет архитектуру. Inbound и outbound — разные абстракции. Inbound принимает сырое соединение, outbound работает с абстрактным `transport.Link`.

---

## 6. Итоговая таблица механизмов

| Механизм | Переброска inbound? | Когда работает | Ограничения |
|---|---|---|---|
| **Fallback (VLESS/Trojan)** | Частично (на внешний сервер) | При провале handshake | Только на внешний destination, не на другой inbound |
| **Sniffing** | Нет | После обработки протокола | Только outbound destination |
| **Inbound Tag Routing** | Нет | При маршрутизации | Только выбор outbound |
| **ForcedOutboundTag** | Нет | При dispatch | Только outbound |
| **Reverse Proxy** | Нет | VLESS-specific | Динамический outbound, не inbound |

**Вывод:** Для полноценной переброски соединения между inbound-хендлерами потребуется модификация архитектуры. Наиболее практичный подход — **Вариант B** (meta-proxy), который не требует изменения core-интерфейсов и работает как обычный `proxy.Inbound`.
