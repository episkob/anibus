# Proxy Chain (HTTP CONNECT Tunneling)

## Описание

Сервис `ProxyChainService` реализует надежный способ построения цепочки прокси-серверов на Java, используя метод **HTTP CONNECT** для туннелирования.

### Архитектура

**Цепочка через SOCKS** (HTTP-туннелирование):
```
[Клиент] 
    ↓ TCP connect
[Proxy 1 (HTTP/SOCKS5)]
    ↓ HTTP CONNECT proxy2:port
[Proxy 2 (HTTP/SOCKS5)]
    ↓ HTTP CONNECT target:port
[Целевой хост]
```

### Преимущества

- ✅ **Надежность**: Явное управление каждым этапом туннелирования
- ✅ **Гибкость**: Поддержка произвольной длины цепочки
- ✅ **Прозрачность**: Полный контроль над процессом подключения
- ✅ **Диагностика**: Логирование каждого шага туннелирования

## API

### ProxyChainService

```java
ProxyChainService chainService = new ProxyChainService();

// Создать соединение через цепочку прокси
Socket socket = chainService.connectThroughChain(
    List.of(proxy1, proxy2, proxy3),  // Цепочка прокси
    "target.com",                     // Целевой хост
    443                               // Целевой порт
);
```

### ProxyConnectionFactory (интеграция)

```java
ProxyConnectionFactory factory = new ProxyConnectionFactory();

// Через фабрику
Socket socket = factory.createSocketThroughChain(chain, host, port);
Socket socketAlt = factory.createSocketThroughChainForPort(chain, host, port);
```

## Примеры использования

### Пример 1: Базовая цепочка из двух прокси

```java
List<ProxyNode> chain = List.of(
    new ProxyNode("proxy1.example.com", 8080, ProxyType.HTTP, "US", 50),
    new ProxyNode("proxy2.example.com", 3128, ProxyType.HTTP, "UK", 60)
);

ProxyChainService service = new ProxyChainService();
try (Socket socket = service.connectThroughChain(chain, "target.com", 443)) {
    // Используем соединение через цепочку прокси
    // Отправляем HTTPS запрос, парсим сертификат и т.д.
} catch (IOException e) {
    System.err.println("Ошибка при подключении через цепочку: " + e.getMessage());
}
```

### Пример 2: Анализ HTTP-ресурса через цепочку

```java
List<ProxyNode> chain = List.of(
    new ProxyNode("10.0.0.1", 8080, ProxyType.HTTP, "XX", -1),
    new ProxyNode("192.168.1.1", 3128, ProxyType.HTTP, "XX", -1)
);

ProxyChainService service = new ProxyChainService();
Socket socket = service.connectThroughChain(chain, "example.com", 80);

// Отправляем HTTP GET
PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
out.println("GET / HTTP/1.1");
out.println("Host: example.com");
out.println("Connection: close");
out.println();

// Читаем ответ
BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
String line;
while ((line = in.readLine()) != null) {
    System.out.println(line);
}
socket.close();
```

### Пример 3: Вывод цепочки в логах

```java
List<ProxyNode> chain = List.of(proxy1, proxy2, proxy3);
String chainStr = ProxyChainService.formatChain(chain);
System.out.println("Цепочка: " + chainStr);
// Вывод: Цепочка: 10.0.0.1:8080 (HTTP) -> 192.168.1.1:3128 (HTTP) -> proxy.com:80 (SOCKS5)
```

## Процесс туннелирования

### Шаг 1: TCP-подключение к первому прокси
```
Socket → TCP SYN → Proxy1:8080
```

### Шаг 2: HTTP CONNECT к второму прокси
```
Client: "CONNECT proxy2.com:3128 HTTP/1.1\r\nHost: proxy2.com:3128\r\n\r\n"
Proxy1: "HTTP/1.1 200 Connection Established\r\n\r\n"
```

### Шаг 3: HTTP CONNECT к целевому хосту
```
Client: "CONNECT target.com:443 HTTP/1.1\r\nHost: target.com:443\r\n\r\n"
Proxy2: "HTTP/1.1 200 Connection Established\r\n\r\n"
```

### Шаг 4: Прямое соединение (туннель готов)
```
Client ←→ [Encrypted tunnel through chain] ←→ Target
```

## Обработка ошибок

### IOException при разрыве цепочки

Если любое звено в цепочке отказывает соединение, выбрасывается `IOException`:

```java
try {
    Socket socket = service.connectThroughChain(chain, host, port);
} catch (IOException e) {
    // "Proxy rejected CONNECT to target.com:443. Response: HTTP/1.1 403 Forbidden"
    // "Failed to connect to first proxy 10.0.0.1:8080: Connection refused"
    // "No response from proxy for CONNECT to 192.168.1.1:3128"
    System.err.println("Ошибка подключения: " + e.getMessage());
}
```

### IllegalArgumentException для пустой цепочки

```java
try {
    Socket socket = service.connectThroughChain(List.of(), host, port);
} catch (IllegalArgumentException e) {
    // "Proxy chain cannot be empty"
    System.err.println(e.getMessage());
}
```

## Поддерживаемые типы прокси

- **HTTP** (через CONNECT)
- **SOCKS5** (через CONNECT)

## Таймауты

- **Подключение к прокси**: 5 секунд
- **Чтение ответа**: 5 секунд

## Логирование

Сервис использует стандартный Java Logger:

```
мая 10, 2026 4:37:12 AM it.r2u.anibus.service.network.proxy.ProxyChainService connectToFirstProxy
INFO: Connected to first proxy: 127.0.0.1:8080 [HTTP, country=US, latency=45ms]

мая 10, 2026 4:37:12 AM it.r2u.anibus.service.network.proxy.ProxyChainService tunnelToProxy
INFO: Tunneled to intermediate proxy: 192.168.1.1:3128

мая 10, 2026 4:37:12 AM it.r2u.anibus.service.network.proxy.ProxyChainService tunnelToTarget
INFO: Tunneled to target: example.com:443
```

## Интеграция в проект Anibus

ProxyChainService автоматически интегрирован в `ProxyConnectionFactory`:

```java
ProxyConnectionFactory factory = new ProxyConnectionFactory();
// Метод создания соединения через цепочку
Socket socket = factory.createSocketThroughChain(chain, host, port);
```

## Тестирование

Модульные тесты в [ProxyChainServiceTest](../test/java/it/r2u/anibus/service/network/proxy/ProxyChainServiceTest.java) покрывают:

- ✅ Подключение через цепочку из 2+ прокси
- ✅ Форматирование цепочки
- ✅ Обработка пустой цепочки (IllegalArgumentException)

Запуск тестов:
```bash
mvn test -Dtest=ProxyChainServiceTest
```

## Ограничения

1. **Шифрование**: Передача CONNECT-запроса происходит **в открытом виде** (текст) — не используйте чувствительные данные в именах хостов на первом прокси.
2. **Аутентификация**: HTTP-аутентификация на прокси не поддерживается в текущей реализации (нужны расширения).
3. **Поддержка протоколов**: Работает с TCP-туннелями (HTTP, HTTPS, SSH и т.д.), но не с UDP.

## Рекомендации

- Используйте HTTPS для финального соединения с целевым хостом.
- Проверяйте доступность каждого прокси перед добавлением в цепочку (использует `ReactiveValidator`).
- Логируйте все CONNECT-запросы для диагностики сбоев.
- Установите разумные таймауты для больших цепочек (>3 узлов).
