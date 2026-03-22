# Анализ метода `AlterInbound` в `handlerServer`

**Файл:** `app/proxyman/command/command.go:85-101`

## Сигнатура

```go
func (s *handlerServer) AlterInbound(ctx context.Context, request *AlterInboundRequest) (*AlterInboundResponse, error)
```

## Что делает

`AlterInbound` — это gRPC-обработчик, который позволяет **динамически модифицировать уже работающий inbound-хендлер** (входящий прокси) по его тегу. Основное назначение — добавление/удаление пользователей «на лету», без перезапуска сервера.

## Пошаговая логика

### 1. Десериализация операции (строки 86-88)

```go
rawOperation, err := request.Operation.GetInstance()
```

`request.Operation` имеет тип `*serial.TypedMessage` — это обертка protobuf, хранящая:
- `Type` (string) — полное имя protobuf-типа (напр. `"xray.app.proxyman.command.AddUserOperation"`)
- `Value` ([]byte) — сериализованные данные

Метод `GetInstance()` (`common/serial/typed_message.go:37-47`):
1. По имени типа ищет зарегистрированный protobuf-тип в глобальном реестре (`protoregistry.GlobalTypes`)
2. Создает новый экземпляр этого типа
3. Десериализует (`proto.Unmarshal`) байты `Value` в созданный экземпляр
4. Возвращает `proto.Message`

### 2. Проверка на `InboundOperation` (строки 90-93)

```go
operation, ok := rawOperation.(InboundOperation)
```

Проверяет, реализует ли полученный объект интерфейс:

```go
type InboundOperation interface {
    ApplyInbound(context.Context, inbound.Handler) error
}
```

Известные реализации в этом же файле:
- **`AddUserOperation`** (строка 38) — добавляет пользователя в inbound-прокси
- **`RemoveUserOperation`** (строка 54) — удаляет пользователя из inbound-прокси

### 3. Поиск inbound-хендлера по тегу (строки 95-98)

```go
handler, err := s.ihm.GetHandler(ctx, request.Tag)
```

`s.ihm` — это `inbound.Manager` (интерфейс из `features/inbound/inbound.go:27`). Метод `GetHandler` находит зарегистрированный inbound-хендлер по строковому тегу (напр. `"vmess-in"`, `"trojan-in"`).

### 4. Применение операции (строка 100)

```go
return &AlterInboundResponse{}, operation.ApplyInbound(ctx, handler)
```

Вызывает `ApplyInbound` на найденном хендлере. Например, для `AddUserOperation.ApplyInbound`:
1. Извлекает proxy через `getInbound(handler)` — приводит хендлер к интерфейсу `proxy.GetInbound`
2. Приводит proxy к `proxy.UserManager`
3. Вызывает `um.AddUser(ctx, mUser)` — добавляет пользователя в работающий прокси

## Protobuf-определение

```protobuf
// command.proto
message AlterInboundRequest {
  string tag = 1;                                  // тег inbound-хендлера
  xray.common.serial.TypedMessage operation = 2;   // полиморфная операция
}

service HandlerService {
  rpc AlterInbound(AlterInboundRequest) returns (AlterInboundResponse) {}
}
```

## Связь с `common/common.go`

Файл `common/common.go` содержит утилитарные функции, используемые в данном модуле:
- **`common.Must(err)`** — паникует если `err != nil`. Используется в `init()` (строка 230) при регистрации конфигурации и в `Register()` (строка 217) при подключении зависимостей (`RequireFeatures`).
- **`common.RegisterConfig()`** — вызывается через `common.Must` в `init()` для регистрации `*Config` как конфигурации, которая создает `service` при инициализации.

## Схема вызовов

```
gRPC клиент
  │
  ▼
AlterInbound(ctx, AlterInboundRequest{Tag, Operation})
  │
  ├─ request.Operation.GetInstance()       // десериализация TypedMessage → proto.Message
  │    └─ serial.TypedMessage.GetInstance() // protoregistry lookup + unmarshal
  │
  ├─ rawOperation.(InboundOperation)       // type assertion к интерфейсу
  │
  ├─ s.ihm.GetHandler(ctx, tag)            // поиск хендлера в inbound.Manager
  │
  └─ operation.ApplyInbound(ctx, handler)  // применение операции
       │
       ├─ AddUserOperation:  getInbound → UserManager.AddUser()
       └─ RemoveUserOperation: getInbound → UserManager.RemoveUser()
```

## Итог

Метод реализует **паттерн Command** — позволяет через единый gRPC-эндпоинт применять произвольные операции к inbound-хендлерам. Конкретная операция определяется типом сериализованного protobuf-сообщения в поле `Operation`. Это обеспечивает расширяемость: для новой операции достаточно создать protobuf-тип, реализующий `InboundOperation`, без изменения самого `AlterInbound`.
