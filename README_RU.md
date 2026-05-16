# Anibus — Продвинутый сканер сетевой безопасности

> **Версия:** 2.2.0 · **Автор:** Iaroslav Tsymbaliuk · **Должность:** Intern (2025–2026) @ r2u

Полнофункциональный десктопный сканер сетевой безопасности, построенный на **Java 21 (JPMS)**, **JavaFX 21.0.5** и кастомной теме **Bootstrap 5 Dark**.
Anibus — это не просто сканер портов: он объединяет фингерпринтинг сервисов, сопоставление CVE, анализ JavaScript-источников, тестирование SQL-инъекций, геолокацию, инспекцию SSL/TLS и обнаружение инфраструктуры в едином самодостаточном приложении.

---

## Содержание

- [Что нового](#что-нового)
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

## Что нового

Текущая сборка — это большой шаг вперёд от обычного TCP-сканера: Anibus стал полноценным набором для аудита веб/API/инфраструктуры. Ниже — сводка ключевых добавлений.

### Новые анализаторы безопасности

| Модуль | Что делает |
|--------|-----------|
| **XSS Detector** | Reflected + DOM-based + stored XSS, context-aware payloads (HTML/attr/JS/URL/CSS/комментарий), polyglot-набор, генерация PoC-ссылки и `curl` |
| **SSRF Detector** | Подмена URL-параметров, доступ к cloud-metadata, схемы `file://`/`dict://`/`gopher://`/`ftp://`, IPv6-mapped, octal/hex/decimal/short-form IP и обход через `nip.io` rebinding |
| **XXE Detector** | Inline + OOB XXE через встроенный loopback DTD-сервер, blind XXE/SSRF по diff длины ответа |
| **CORS Misconfiguration** | Отражение Origin, credentials + wildcard, `Origin: null`, pre-flight заголовки, per-endpoint sweep |
| **JWT Analyzer** | `alg:none`, слабый HMAC, expired, JWK/JWKS, `kid` injection / path traversal / SQLi, alg-confusion, TTL-diff пары access/refresh, claim-tamper helper |
| **GraphQL Introspection** | 10 путей схемы, depth-limit probe, batch-query abuse, авто-генерация query/mutation |
| **Subdomain Takeover** | 50+ fingerprint провайдеров (Vercel/Render/Fly.io/Pantheon/Tumblr/Acquia/Railway/…), рекурсия CNAME, DNS-wildcard baseline против ложных срабатываний |
| **Auth Crawling** | Basic / Bearer / OAuth2 client_credentials / Digest (RFC 7616) / form-login с авто-извлечением CSRF / **NTLM v2** (свои MD4 + HMAC-MD5, без сторонних библиотек) |
| **Tech Stack Fingerprinter 2.0** | 40+ сигнатур: web-серверы, CMS, JS-фреймворки, CDN, аналитика, cookie-based runtimes — с захватом версии |
| **Service Misconfiguration** | `.git/config`, `.env`, `/actuator/env`, `/server-status`, `/phpinfo.php`, открытые Docker/K8s/etcd — content-based confidence |
| **Container Exposure** | Зонды Docker / Kubernetes / etcd API (только read-only GET) |
| **Weak TLS Policy** | TLS 1.0/1.1, слабые ciphers, self-signed, OCSP/HSTS/ALPN, доверие цепочке через JVM TrustManager |
| **Auth Surface Auditor** | Поиск login-endpoint, burst rate-limit, детект captcha-токенов и lockout-заголовков |
| **Heartbleed Checker** | Сырой TLS heartbeat со структурной проверкой ответа и анти-FP guard |
| **Passive Recon** | Title/headers/robots/sitemap, favicon hash (Jenkins/GitLab/Confluence/JIRA/Grafana/…), `<meta name="generator">`, extraction CSP-origin, OSINT email-harvest, анализ cross-origin (TAO/CORP/COOP/COEP/ACAO) |
| **Cookie Flags Auditor** | Аудит `Set-Cookie` (`Secure`/`HttpOnly`/`SameSite`), повышенный severity для auth-куки |
| **Secrets Validation** | Format-валидация AWS/GitHub/Stripe/Telegram/Slack/Google/NPM/Docker PAT, GCP service-account JSON, PEM private keys, fuzzy-словарь, фильтр placeholder |
| **SQLi Boolean-Blind + OOB** | Diff по длине ответа и статус-коду, OOB-примитивы MSSQL/Oracle/PostgreSQL/MySQL через loopback callback, 8 time-based payload |
| **JS Endpoint Reachability** | Проверка живости + метод/статус каждого endpoint, найденного в JS-бандлах |
| **AI Summary** | Эвристический executive summary (EN/RU) для JS Analysis — severity buckets, top risk-scored, type-aware рекомендации, без внешних LLM |
| **SourceMap Exploit Context** | Каждый LeakInfo аннотируется категорией атаки, нарративом, рекомендацией и ссылкой CVE/OWASP |

### Сеть и инфраструктура

- **ASN/BGP enrichment** через Team Cymru bulk whois, **GeoIP-карта** с ASCII-диаграммой по странам
- **Multi-target batch scan** с агрегированным отчётом (`BatchScanService`)
- **Banner timeline** — TSV-хранилище + diff между сканами
- **Traceroute** в режимах ICMP / TCP / UDP с метриками потерь; **Topology Map** с кластеризацией /24 + ASN
- **WHOIS Lookup** с RDAP fallback, нормализация registrar/abuse (IANA root → авторитативный)
- **SSL/TLS Deep Audit** — протокол, ciphers, chain, SANs, OCSP, HSTS, ALPN
- **DNS AXFR** zone transfer (raw TCP/53), **HTTP/2 + HTTP/3** через ALPN + `Alt-Svc`, **WebSocket** probe
- **IoT / Devices tools (ручной запуск из GUI)**: RTSP (OPTIONS), ONVIF (heuristic), ADB (host:version) + быстрый IoT quick-scan по common ports (меню **Actions → IoT / Devices**)
- Поддержка **IPv6** в `HostResolver`

### CVE-интеллект

- **Оффлайн NVD-кэш** (`CveDbCacheService`, NVD 2.0 API, flat `.cvecache`)
- **EPSS + CISA KEV** приоритизация (`EpssKevService`)
- **Exploit maturity** (WEAPONIZED / POC / THEORETICAL) и оценка возраста CVE
- **PoC-ссылки**: NVD, MITRE, Exploit-DB, PacketStorm, vendor advisory
- Расширенные fingerprint: Node.js / Jetty / WildFly / JBoss / OpenSSL / Spring / IIS / GitLab

### Proxy-подсистема

- **Visual Proxy Chain Manager** — drag-and-drop, карточка `ACTIVE CHAIN`, диалог `Build Chain` (локализован EN/IT/RU)
- Продвинутые routing-контролы, политики ротации, гибкое поведение цепочки
- Geo-aware выбор прокси, реактивная triple-handshake валидация, персистентный пул в `~/.anibus/proxy-pool.json`

### UI и экспорт

- **История сканов** в `~/.anibus/history/` с контекстным меню сравнения и повторного запуска
- Вкладка **Statistic Dashboard** с графиками портов/сервисов/рисков
- **Переключатель тёмной/светлой темы**, **уведомления в трей**, **горячие клавиши** (F5 / Esc / Ctrl+S / Ctrl+L / Ctrl+F)
- Экспорт в **PDF и стилизованный HTML** (JavaFX PrinterJob), realtime-**фильтр в консоли**
- **Группировка CVE по severity** (CRITICAL / HIGH / MEDIUM / LOW), сортировка JS Analysis по приоритету
- **Wordlist selector** для Subdomain, SQLi payload и Endpoint; индикатор активных wordlist в Scan Target
- Режимы **одного порта и диапазона**, расширенные опции scheduler, realtime-лог статусов с таймстампами
- **Diff View** между двумя сохранёнными XML-сканами

### Архитектура и качество

- **Виртуальные потоки (JEP 444)** в `ScanTask`, `ServiceDetectionTask`, `JavaScriptSecurityAnalyzer`, `ReactiveValidator`, `ReverseDnsExpander` и всех blocking-IO путях
- **Ручной DI** в `AnibusApplication` (без рефлексии, JPMS-clean)
- **Единый HTTP-фасад** `HttpClientFactory.open(url, profile)` с trust-all TLS, retry + экспоненциальным backoff + jitter
- **Реестр timeout-профилей** (FAST 2s / NORMAL 5s / SLOW 10s / VERY_SLOW 20–30s)
- **Named daemon ThreadFactory** + graceful shutdown с изоляцией ошибок сервисов
- **ArchUnit-тесты границ модулей**, FXML-валидация, проверка соответствия Messages_en/it/ru
- **162 юнит-теста** в 50+ test-классах

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
│  service/iot/                                │
│  RtspProbeService · OnvifProbeService · AdbProbeService │
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
┌────────────────────────────────── Anibus 2.2.0 ─────────────────────────────────────┐
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
| Maven Shade Plugin | 3.5.1 | Fat JAR со встроенными нативными библиотеками |
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
java -jar anibus-2.2.0.jar
```

Исполняемый shaded JAR создается в корне проекта как `anibus-2.2.0.jar`.

**Windows:**

```cmd
REM Нужен JDK 21. Убедитесь, что JAVA_HOME указывает на него, например:
REM setx JAVA_HOME "C:\\Program Files\\Java\\jdk-21"

mvnw.cmd test
mvnw.cmd clean package
java -jar anibus-2.2.0.jar
```

**Linux — Wayland / XWayland:**

```bash
xhost +local:
DISPLAY=:0 java -jar anibus-2.2.0.jar
```

**Из терминала Flatpak VS Code:**

```bash
flatpak-spawn --host xhost +local:
DISPLAY=:0 java -jar anibus-2.2.0.jar
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
| `LeakInfoTest` | 14 | Инференция приоритета, обнаружение placeholder, builder |
| `RetryPolicyTest` | 9 | HTTP повторные запросы и backoff |
| `PortScannerServiceTest` | 7 | Парсинг диапазона портов, безопасность потоков, null-входы |
| `JavaScriptSecurityAnalyzerServiceInferenceTest` | 7 | Обнаружение движков БД и фреймворков |
| `ProxyRoutingServiceTest` | 6 | Маршрутизация и выбор proxy |
| `NtlmMessagesTest` | 6 | Парсинг NTLM-аутентификации |
| `FaviconFingerprintDatabaseTest` | 6 | Фингерпринтинг по хешу favicon |
| `ContainerExposureCheckerTest` | 6 | Обнаружение открытых container API |
| `AuthCrawlerTest` | 6 | Авторизованный краулинг с управлением сессией |
| `WebSourceAnalyzerTest` | 5 | Парсинг JS-источников, извлечение эндпоинтов |
| `SQLInjectionAnalyzerTest` | 5 | Выполнение SQL-пейлоадов |
| `ServiceMisconfigurationCheckerTest` | 5 | Обнаружение неправильных конфигураций сервисов |
| `ModuleBoundaryTest` | 5 | Проверка границ модулей JPMS |
| `HarPostmanParserTest` | 5 | Импорт HAR/Postman-коллекций |
| `TCP,HTTP,OPEN,nginx/1.24.0,,12,,
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
### v2.2.0 — Minor Release

- ✅ Расширена proxy-подсистема: гибкий routing, ротация и управление цепочками
- ✅ Добавлен поток управления wordlist для Subdomain, SQLi payload и Endpoint
- ✅ Интегрированы endpoint из JS-анализа и endpoint wordlist в SQLi/XSS-сканирование
- ✅ Добавлена поддержка режима одного порта в парсере диапазона портов
- ✅ Добавлены расширенные настройки scheduler с более понятной конфигурацией запуска
- ✅ Добавлен realtime-поток статус-логов с таймстампами в консоль
- ✅ Добавлены индикаторы активных wordlist в UI Scan Target
- ✅ Обновлены документация и ссылки на артефакты до `2.2.0`
### v2.0.1 — Patch Release

- ✅ Добавлена карточка отображения цепочки (`ACTIVE CHAIN`) во вкладке Proxy
- ✅ Добавлена кнопка `Build Chain` и привязка обработчика
- ✅ Добавлены локализованные тексты диалога Proxy Chain Builder (EN/IT/RU)
- ✅ Исправлены регрессии FXML-структуры и биндингов, влиявшие на запуск
- ✅ Обновлены документация и ссылки на артефакты версии `2.0.1`

---

## Лицензия

MIT License. Подробности в файле `LICENSE`.
