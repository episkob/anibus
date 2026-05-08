# Anibus — Продвинутый сканер сетевой безопасности

> **Версия:** 2.0.0 · **Автор:** Iaroslav Tsymbaliuk · **Должность:** Intern (2025–2026) @ r2u

Полнофункциональный десктопный сканер сетевой безопасности, построенный на **Java 21 (JPMS)**, **JavaFX 21.0.5** и кастомной теме **Bootstrap 5 Dark**.
Anibus — это не просто сканер портов: он объединяет фингерпринтинг сервисов, сопоставление CVE, анализ JavaScript-источников, тестирование SQL-инъекций, геолокацию, инспекцию SSL/TLS и обнаружение инфраструктуры в едином самодостаточном приложении.

---

## Содержание

- [Что нового в 2.0.0](#что-нового-в-200)
- [Возможности](#возможности)
- [Архитектура](#архитектура)
- [Структура проекта](#структура-проекта)
- [Паттерны проектирования](#паттерны-проектирования)
- [Интерфейс](#интерфейс)
- [Технологии](#технологии)
- [Требования](#требования)
- [Сборка и запуск](#сборка-и-запуск)
- [Руководство по использованию](#руководство-по-использованию)
- [Тестирование](#тестирование)
- [Форматы экспорта](#форматы-экспорта)
- [Лицензия](#лицензия)

---

## Что нового в 2.0.0

| Область | Изменение |
|---------|----------|
| **Прокси-модуль** | Полный пайплайн: харвестинг → валидация → гео-резолюция → пул |
| **Сохранение пула** | Валидированный пул сохраняется в `~/.anibus/proxy-pool.json`; загружается при следующем запуске |
| **Гео-роутинг** | Автоматически выбирает лучший прокси по стране цели; переключается при смене хоста |
| **Ручная ротация** | Кнопка ↻ рядом с активным прокси для смены вручную |
| **Заголовки прокси** | Обнаруживает `Via`, `X-Forwarded-For`, `X-Real-IP` и другие прокси-заголовки в выводе сканирования |
| **Заголовок скана** | Консоль показывает TARGET и ROUTING (прокси или DIRECT) перед результатами |
| **Остановка харвестинга** | Кнопка Clear становится ■ Stop; отмена на каждом этапе |
| **Семафор сети** | Одновременно не более 200 открытых сокетов (раньше без ограничений) |

---

## Что нового в 1.8.0

| Область | Изменение |
|---------|-----------|
| Архитектура | Сервисный слой разбит на 6 специализированных подпакетов |
| Модель | `LeakInfo` перенесён в `model/` как иммутабельный класс |
| DI | Внедрение через конструктор везде — никаких DI-фреймворков |
| UI | Полный редизайн: боковая панель + TabPane |
| Тема | Полная перезапись CSS на Bootstrap 5 Dark |
| Обнаружение утечек | Конфиденциальные данные только на вкладке JS Analysis |
| Тесты | 49 юнит-тестов JUnit 5 |
| Язык | Интерфейс только на английском |
| Экспорт | JS Analysis экспортирует в CSV или XML (как сканирование портов) |

---

## Возможности

### Сканирование портов
- Сканирование любого хоста, IP или URL
- Настраиваемый диапазон портов (`1-65535`) и количество потоков (по умолчанию: 10 виртуальных потоков)
- Измерение задержки для каждого порта (мс)
- Прогресс-бар в реальном времени и живая статистика
- Плавная отмена сканирования в любой момент

### Расширенное определение сервисов

Многоуровневый анализ баннеров и протоколо-специфичные зонды:

| Уровень | Что делает |
|---------|-----------|
| Захват баннеров | HTTP HEAD, SSH приветствие, SMTP EHLO, FTP, рукопожатие MySQL |
| Извлечение версии | Парсит заголовки `Server:`, баннеры SSH, Redis `INFO`, приветствие FTP |
| Определение ОС | TCP-отпечатки + анализ баннеров |
| Сопоставление CVE | Сравнивает версии с встроенной базой уязвимостей |
| Геолокация | IP → местоположение, провайдер, ASN, облачный провайдер |
| SSL/TLS | Срок действия, издатель, самоподписанные сертификаты |

Поддерживаемые сервисы: HTTP/HTTPS, SSH, FTP, SMTP, DNS, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Kibana, Kubernetes API, Jenkins, Grafana, Prometheus, RabbitMQ, Kafka, ZooKeeper, LDAP, Memcached, Cassandra, CouchDB, Neo4j, InfluxDB, Splunk, Vault, Consul, Etcd и многие другие.

### Анализ безопасности

| Функция | Описание |
|---------|---------|
| **Keycloak IAM** | Находит Keycloak-серверы, извлекает открытые криптоключи и секреты клиентов |
| **Заголовки безопасности** | Проверяет CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy |
| **Определение CMS** | WordPress, Drupal, Magento, Joomla, 1C-Bitrix — фингерпринтинг версий |
| **IoT-устройства** | IP-камеры, DVR/NVR, роутеры — предупреждения о стандартных учётных данных |
| **Контейнеры** | Docker API, Kubernetes API, Rancher, Portainer |
| **Облачные метаданные** | Зондирует эндпоинты AWS/GCP/Azure IMDS |

### Анализ JavaScript (вкладка JS Analysis)

Загружает и парсит JavaScript из целевого приложения, включая бандлы Webpack/Vite/Rollup с хэшированными именами:

| Анализ | Подробности |
|--------|------------|
| **Маппинг API-эндпоинтов** | REST/GraphQL эндпоинты, HTTP-методы, URL-шаблоны из JS-бандлов |
| **Извлечение учётных данных** | Строки подключения для 30+ движков: MongoDB, MySQL, PostgreSQL, Redis, Elasticsearch, Cassandra, Neo4j, InfluxDB, RabbitMQ, DynamoDB, Supabase, PlanetScale и другие |
| **Инференция схем БД** | Таблицы, столбцы, связи из ORM/query паттернов в JS |
| **Определение инфраструктуры** | Docker, Kubernetes, AWS/GCP/Azure, Nginx, Traefik, Cloudflare, Fastly с оценкой уверенности |
| **Определение фреймворков** | React, Vue, Angular, Next.js, Nuxt.js, SvelteKit, Remix, Astro, Gatsby, Alpine.js, Solid.js, Qwik и 20+ других |
| **Конфиденциальные данные** | API-ключи, секретные токены, приватные ключи, JWT-секреты, OAuth-учётные данные |

Результаты отображаются в раскрываемом **TreeView**, сгруппированном по типам находок.

### SQL Injection Testing

- **110+ пейлоадов** в 12 категориях:
  - Error-based, UNION-based, time-based (sleep/benchmark), boolean-based
  - Auth-bypass, stacked queries, NoSQL, XPath, LDAP-инъекции
  - Обход кодирования (URL, hex, double-URL, Unicode, mixed-case)
- **Профили CMS**: WordPress (`wp-login.php`, `xmlrpc.php`), Joomla, Drupal, Magento, 1C-Bitrix, OpenCart, PrestaShop, ModX, Shopify
- **Автообнаружение форм**: парсит `<form>`, `<input>`, `<select>`, `<textarea>`
- **Анализ ответов**: определяет SQL-ошибки MySQL, PostgreSQL, MSSQL, SQLite, Oracle, MongoDB и time-based задержки

---

## Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    AnibusController                      │
│     (FXML-контроллер JavaFX, только UI-поток)            │
└───────┬─────────────────────────────────┬───────────────┘
        │                                 │
        ▼                                 ▼
┌───────────────┐                ┌────────────────────┐
│ ScanCoordinator│               │  Обработчики       │
│ Strategy+Facade│               │ ScanActionHandler  │
│               │                │ ExportActionHandler│
│  ScanContext  │                │ ClipboardHandler   │
│  ScanStrategy │                └────────────────────┘
└───────┬───────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│               Сервисный слой                 │
│                                             │
│  service/core/        service/detection/    │
│  PortScannerService   EnhancedServiceDet.   │
│  BannerGrabber        OSDetector            │
│  HTTPAnalyzer         IoTDetector           │
│  VulnScanner          KeycloakDetector      │
│                       SoftwareStackDet.     │
│                       ContainerDetector     │
│                                             │
│  service/analysis/    service/network/      │
│  JSSecurityAnalyzer   SubnetScanner         │
│  JSDatabaseAnalyzer   TracerouteService     │
│  WebSourceAnalyzer    ReverseDnsExpander    │
│  SQLInjectionAnalyzer CloudMetadataProbe    │
│                                             │
│  service/export/      service/geo/          │
│  ExportService        GeolocationService    │
└─────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│                  Модельный слой              │
│  LeakInfo · PortScanResult · PortRegistry   │
│  JavaScriptAnalysisResult · EndpointInfo    │
│  DatabaseSchemaInfo · DataStructureInfo     │
│  ArchitectureInfo                           │
└─────────────────────────────────────────────┘
```

### Поток данных

1. Пользователь вводит цель + опции → **ScanCoordinator** создаёт `ScanContext`
2. **PortScannerService** запускает задачи на виртуальных потоках по одной на порт
3. Каждый открытый порт → **EnhancedServiceDetector** → баннер → версия → CVE
4. **GeolocationService** параллельно разрешает метаданные IP
5. JS Analysis включён → **JavaScriptSecurityAnalyzer** загружает и парсит бандлы
6. SQL Injection включён → **SQLInjectionAnalyzer** находит формы и тестирует их
7. Результаты возвращаются через `Platform.runLater()` — UI всегда на JavaFX-потоке
8. **ExportService** / **ExportActionHandler** пишут CSV или XML по запросу

---

## Структура проекта

```
src/main/java/it/r2u/anibus/
├── AnibusApplication.java               # Точка входа JavaFX Application
├── AnibusController.java                # Главный FXML-контроллер
│
├── coordinator/
│   ├── ScanCoordinator.java             # Оркестрация полного конвейера сканирования
│   ├── ScanContext.java                 # Изменяемый контейнер состояния сканирования
│   ├── ScanStrategy.java               # Интерфейс стратегии
│   ├── StandardScanStrategy.java       # Стандартный поток сканирования
│   └── ServiceDetectionStrategy.java   # Поток с акцентом на определение сервисов
│
├── handlers/                            # Command pattern — один класс на действие UI
│   ├── ScanActionHandler.java
│   ├── ExportActionHandler.java         # Экспорт CSV/XML: порт-скан + JS-анализ
│   ├── ClipboardActionHandler.java
│   └── TracerouteActionHandler.java
│
├── model/                               # Иммутабельные классы данных
│   ├── LeakInfo.java                   # Запись об утечке + инференция приоритета
│   ├── PortScanResult.java
│   ├── PortRegistry.java               # Карта порт/имя сервиса (1000+ записей)
│   ├── JavaScriptAnalysisResult.java
│   ├── EndpointInfo.java
│   ├── DatabaseSchemaInfo.java
│   ├── DataStructureInfo.java
│   └── ArchitectureInfo.java
│
├── network/
│   ├── HostResolver.java               # DNS-разрешение + нормализация URL
│   └── NetworkStatusMonitor.java       # Периодическая проверка подключения
│
├── service/
│   ├── analysis/
│   │   ├── JavaScriptSecurityAnalyzer.java    # Загрузка бандлов + оркестрация анализа
│   │   ├── JavaScriptDatabaseAnalyzer.java    # Поиск учётных данных БД + схем
│   │   ├── WebSourceAnalyzer.java             # Парсер HTML/JS (inline-скрипты, ссылки)
│   │   └── SQLInjectionAnalyzer.java          # Обнаружение форм + инъекции
│   │
│   ├── core/
│   │   ├── PortScannerService.java            # Сканер портов на виртуальных потоках
│   │   ├── ScanTask.java                      # Callable на один порт
│   │   ├── ServiceDetectionTask.java          # Углублённое определение после сканирования
│   │   ├── BannerGrabber.java                 # Получение сырого баннера
│   │   ├── HTTPAnalyzer.java                  # HTTP-анализ
│   │   └── VulnerabilityScanner.java          # Движок сопоставления CVE
│   │
│   ├── detection/
│   │   ├── EnhancedServiceDetector.java       # Главный диспетчер определения
│   │   ├── OSDetector.java                    # Фингерпринтинг ОС
│   │   ├── PassiveFingerprinter.java          # Пассивный анализ трафика
│   │   ├── IoTDetector.java                   # Обнаружение камер/DVR/роутеров
│   │   ├── KeycloakDetector.java              # Скрейпер Keycloak realm
│   │   ├── SoftwareStackDetector.java         # Определение CMS/фреймворков
│   │   └── ContainerDetector.java             # Обнаружение Docker/Kubernetes
│   │
│   ├── export/
│   │   └── ExportService.java                 # Запись CSV/XML для сканирования портов
│   │
│   ├── geo/
│   │   └── GeolocationService.java            # Интеграция ip-api.com
│   │
│   └── network/
│       ├── SubnetScanner.java                 # Расширение диапазона CIDR
│       ├── TracerouteService.java             # ICMP/TCP трассировка
│       ├── ReverseDnsExpander.java            # Поиск PTR-записей
│       ├── CloudMetadataProbe.java            # Зонд AWS/GCP/Azure IMDS
│       └── VersionExtractor.java             # Извлечение версии через regex
│
└── ui/
    ├── AlertHelper.java                       # Стилизованные диалоги
    ├── ClipboardService.java                  # Интеграция с буфером обмена
    ├── ConsoleViewManager.java                # Рендеринг консольной вкладки
    ├── InfoCardManager.java                   # Обновление карточки Host Info
    └── TableConfigurator.java                 # Настройка столбцов таблицы

src/main/resources/it/r2u/anibus/
├── hello-view.fxml                            # Полный макет UI (боковая панель + TabPane)
├── anibus-style.css                           # Кастомная тема Bootstrap 5 Dark
└── logging.properties

src/test/java/it/r2u/anibus/
├── service/core/PortScannerServiceTest.java         # 9 тестов
├── model/LeakInfoTest.java                          # 22 теста
├── service/analysis/WebSourceAnalyzerTest.java      # 8 тестов
├── service/WebSourceAnalyzerLeakInfoTest.java       # 3 теста
└── service/JavaScriptSecurityAnalyzerServiceInferenceTest.java  # 7 тестов
```

---

## Паттерны проектирования

| Паттерн | Где применён | Зачем |
|---------|-------------|-------|
| **Strategy** | `ScanStrategy` / `ScanCoordinator` | Замена алгоритма сканирования без изменения контроллера |
| **Command** | Классы `*ActionHandler` | Разделение UI-действий и бизнес-логики; один класс = одна ответственность |
| **Facade** | `ScanCoordinator` | Единая точка входа для сложного многосервисного конвейера |
| **Builder** | `JavaScriptAnalysisResult` | Инкрементальный сбор асинхронных результатов |
| **Constructor Injection** | Все сервисы | Явные зависимости, тестируемость, совместимость с JPMS, ноль накладных расходов |
| **Observer** | `Platform.runLater()`, `Task<>` | Потокобезопасные обновления UI из фоновых потоков |

### Почему нет DI-фреймворка?

Java 21 JPMS конфликтует с большинством DI-фреймворков (Spring, Guice), поскольку они полагаются на рефлексию через границы модулей. Инъекция через конструктор даёт такое же разделение ответственности без накладных расходов фреймворка и с полной совместимостью JPMS.

### Почему виртуальные потоки?

Сканирование портов — это чисто I/O-bound задача. Виртуальные потоки Java 21 (`Executors.newVirtualThreadPerTaskExecutor()`) позволяют запускать сотни параллельных сокетных соединений с минимальными накладными расходами — без сложностей реактивного программирования.

---

## Интерфейс

```
┌────────────────────────────────── Anibus 2.0.0 ─────────────────────────────────────┐
│ [●] Anibus  ░░░░░░░░░░░░░░░░░░░░░░░░  ● Подключён  192.168.1.1               │  ← Навбар
│───────────────────────────────────────────────────────────────────────────────│
│ ┌── Scan Target ───────────────┐  ┌── [Scan Results] [JS Analysis] ──────────┐│
│ │ Host: [example.com_______]   │  │  Scan Results               [Export][Clear]││
│ │ Ports:[1-1024] Threads:[10]  │  │ ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  ││
│ │ ☑ JavaScript Analysis        │  │  ╔══ PORT 22 — SSH ═══════════════════╗  ││
│ │ ☑ SQL Injection Testing      │  │  ║ OpenSSH 8.9p1 Ubuntu              ║  ││
│ │ [▶ Start Scan       ] [Stop] │  │  ║ CVE-2023-38408  HIGH              ║  ││
│ │ ████████████░░░░░  67%       │  │  ╚═══════════════════════════════════╝  ││
│ └──────────────────────────────┘  │  ╔══ PORT 80 — HTTP ══════════════════╗  ││
│ ┌── Host Info ─────────────────┐  │  ║ nginx/1.24.0  WordPress 6.4.2    ║  ││
│ │ IP                           │  │  ╚═══════════════════════════════════╝  ││
│ │ 93.184.216.34                │  └────────────────────────────────────────┘│
│ │ Hostname                     │                                             │
│ │ example.com                  │                                             │
│ │ Scan Time    │ Ports Scanned │                                             │
│ │ 4.2s         │ 1024          │                                             │
│ │ Open Ports   │ Avg Latency   │                                             │
│ │ 3            │ 12ms          │                                             │
│ └──────────────────────────────┘                                             │
│───────────────────────────────────────────────────────────────────────────────│
│ ● Сканирование завершено — найдено 3 открытых порта                           │  ← Статус-бар
└───────────────────────────────────────────────────────────────────────────────┘
```

**Левая панель (300 пкс):**
- **Карточка Scan Target** — поле хоста с живым DNS-разрешением, диапазон портов, счётчик потоков, два чекбокса, кнопки Start/Stop, прогресс-бар
- **Карточка Host Info** — появляется после сканирования; IP и хостнейм (с переносом строк), сетка 2 колонки: Scan Time / Ports Scanned / Open Ports / Avg Latency

**Правая панель (гибкая):**
- **Вкладка Scan Results** — монопространственная тёмная консоль с ASCII-баннерами сервисов
- **Вкладка JS Analysis** — строка статистики + раскрываемый TreeView + кнопка Export

---

## Технологии

| Технология | Версия | Роль |
|-----------|--------|------|
| Java | 21 (LTS) | Язык, система модулей JPMS, виртуальные потоки |
| JavaFX | 21.0.5 | UI-фреймворк (FXML + CSS) |
| Bootstrap 5 Dark (CSS) | Кастомный порт | Дизайн-система |
| Maven Shade Plugin | 3.5.0 | Fat JAR со встроенными нативными библиотеками |
| JUnit 5 | 5.10.2 | Юнит-тестирование |
| junit-jupiter-params | 5.10.2 | Параметризованные тесты |

---

## Требования

| Инструмент | Версия | Примечания |
|-----------|--------|-----------|
| Java | **21+** | Рекомендуется LTS |
| Maven | 3.8+ | Или встроенный `./mvnw` |
| JavaFX | — | Встроен в fat JAR — отдельная установка не нужна |
| ОС | Linux / Windows / macOS | Все платформы |

---

## Сборка и запуск

**Клонировать и запустить напрямую:**

```bash
git clone https://github.com/episkob/anibus.git
cd anibus
./mvnw javafx:run
```

**Собрать fat JAR:**

```bash
./mvnw clean package -DskipTests
java -jar target/anibus-2.0.0.jar
```

**Linux — Wayland / XWayland:**

```bash
xhost +local:
DISPLAY=:0 java -jar target/anibus-2.0.0.jar
```

**Из терминала Flatpak VS Code:**

```bash
flatpak-spawn --host xhost +local:
DISPLAY=:0 java -jar target/anibus-2.0.0.jar
```

---

## Руководство по использованию

### 1 — Введите цель

Введите хостнейм, IP-адрес или полный URL. DNS разрешается автоматически при потере фокуса. Индикатор SSL появляется, если порт 443 отвечает.

### 2 — Настройте опции

| Параметр | Описание |
|---------|---------|
| **Ports** | Диапазон `1-1024` или список через запятую `22,80,443,8080` |
| **Threads** | Параллельных соединений (1–200, по умолчанию 10) |
| **JavaScript Analysis** | Загружать и парсить JS-бандлы в поисках секретов и эндпоинтов |
| **SQL Injection Testing** | Автообнаружение форм и зондирование 110+ пейлоадами |

### 3 — Запустите сканирование

Нажмите **▶ Start Scan**. Прогресс-бар и статус-бар обновляются в реальном времени.

### 4 — Результаты сканирования

Вкладка **Scan Results** показывает форматированные баннеры: версия, ОС, CVE-предупреждения, геолокация, данные SSL.

### 5 — Вкладка JS Analysis

Переключитесь на **JS Analysis** для просмотра: API-эндпоинты, конфиденциальные учётные данные, схемы БД, структуры данных, инфраструктура и фреймворки.

### 6 — Экспорт

Обе вкладки имеют независимую кнопку **Export** с диалогом выбора формата:
- **CSV** — читаемый формат, совместимый с электронными таблицами
- **XML** — структурированный машиночитаемый формат

---

## Тестирование

```bash
./mvnw test
```

| Тестовый класс | Тестов | Покрывает |
|---------------|--------|----------|
| `PortScannerServiceTest` | 9 | Парсинг диапазона портов, безопасность потоков, null-входы |
| `LeakInfoTest` | 22 | Инференция приоритета, обнаружение placeholder, builder |
| `WebSourceAnalyzerTest` | 8 | Парсинг JS-источников, извлечение эндпоинтов |
| `WebSourceAnalyzerLeakInfoTest` | 3 | Интеграция LeakInfo |
| `JavaScriptSecurityAnalyzerServiceInferenceTest` | 7 | Обнаружение движков БД и фреймворков |
| **Итого** | **49** | |

---

## Форматы экспорта

### Сканирование портов — CSV
```
Port,Protocol,Service,State,Banner,Version,Latency(ms),CVE,Severity
22,TCP,SSH,OPEN,OpenSSH 8.9p1,8.9p1,8,CVE-2023-38408,HIGH
80,TCP,HTTP,OPEN,nginx/1.24.0,,12,,
```

### JS Analysis — CSV
```
## ENDPOINTS
Method,URL,Dynamic
GET,"/api/v1/users",false
POST,"/api/v1/auth/login",true

## SENSITIVE INFORMATION
Type,Value,Priority,Placeholder
API_KEY,"sk-prod-abc123...",1,false

## DATABASE SCHEMAS
Table,DatabaseType,Confidence,Columns
users,POSTGRESQL,95%,"id|email|password_hash"
```

### JS Analysis — XML
```xml
<jsAnalysis>
  <meta target="example.com" timestamp="2026-05-06T10:30:00" analysisTimeMs="3200"/>
  <endpoints>
    <endpoint method="GET" dynamic="false"><url>/api/v1/users</url></endpoint>
  </endpoints>
  <sensitiveInfo>
    <leak type="API_KEY" priority="1" placeholder="false">
      <value>sk-prod-abc123...</value>
    </leak>
  </sensitiveInfo>
  <databaseSchemas>
    <schema table="users" dbType="POSTGRESQL" confidence="0.95">
      <column name="id" type="INTEGER"/>
      <column name="email" type="VARCHAR"/>
    </schema>
  </databaseSchemas>
</jsAnalysis>
```

---

## Роадмап

### v2.0.0 — Прокси-модуль

- ✅ Харвестинг прокси (Phase 1)
- ✅ Triple-handshake валидация с виртуальными потоками (Phase 2)
- ✅ Гео-резолюция через ip-api.com (Phase 3)
- ✅ `GeoRoutingStrategy` — своя страна → соседи → глобальный фоллбек
- ✅ `ProxyStore` — сохранение в `~/.anibus/proxy-pool.json`
- ✅ Кнопка "Загрузить из файла" — восстановление без повторного харвестинга
- ✅ Авто-ротация при смене хоста
- ✅ Ручная ротация — кнопка ↻
- ✅ Ограничение сети (200 сокетов одновременно)
- ✅ Обнаружение заголовков прокси в результатах сканирования

### Запланировано

**Сетевой слой**
- 🟡 **UDP-сканирование**
- 🟡 **Перечисление поддоменов**

**Слой анализа**
- 🟡 **Анализ Source Map**
- 🟡 **Param Miner**

**Экспорт**
- 🟡 **Diff Mode**
- 🟡 **Планировщик сканов**

---

## Лицензия

MIT License. Подробности в файле `LICENSE`.

**Сетевой слой**
- 🟡 **UDP-сканирование** — зондирование DNS (53), SNMP (161/162), NTP (123), mDNS (5353), SSDP (1900), NetBIOS (137), TFTP (69), Syslog (514) с протокольными payload-пробами и разбором баннеров
- 🟡 **Перечисление поддоменов** — пассивное обнаружение через [crt.sh](https://crt.sh) (Certificate Transparency) + активный DNS brute-force (70+ префиксов) с DNS-проверкой

**Слой анализа**
- 🟡 **Анализ Source Map** — обнаруживает и загружает `.js.map` файлы, восстанавливает оригинальные пути файлов и исходный код, запускает полный анализ утечек по деминифицированному коду
- 🟡 **Param Miner** — обнаруживает скрытые GET/POST-параметры через canary-инъекцию; фиксирует отражённые параметры (потенциал XSS/SSRF)

**Экспорт и отчётность**
- 🟡 **Diff Mode** — сравнение двух XML-экспортов; подсвечивает новые открытые порты, закрытые порты и изменения в сервисах/версиях
- 🟡 **Планировщик сканирования** — повторные сканы с настраиваемым интервалом

---

## Лицензия

MIT License. Подробности в файле `LICENSE`.
