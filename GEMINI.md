# GEMINI.md — База Знаний и Архитектурный Справочник ClaudeCage

> **Назначение файла:** Этот файл является полным, концентрированным и самодостаточным техническим руководством для модели **Gemini** (и других ИИ-агентов). Он содержит полную модель кодовой базы, архитектурные решения, инварианты безопасности, структуру файлов и правила разработки проекта **ClaudeCage**, устраняя необходимость повторно вычитывать все файлы проекта при каждом новом диалоге.

---

## 1. Общие Сведения о Проекте (Project Overview)

- **Название приложения:** `ClaudeCage` (пакет: `com.example.claudecageand`).
- **Текущая версия:** `1.0 (Build 1)` • **Hardening:** `Stage 10: Zero-Trust Hardening & Code Review Remediation`.
- **Целевая платформа:** Android 13+ (Min SDK: 33, Target/Compile SDK: 36).
- **Боевая среда тестирования:** Samsung Galaxy S25 Ultra (`SM-S938B`, `pa3q`), Android 17 (API 37).
- **Целевой VPN-клиент:** Amnezia VPN Premium (`tun0` / `tun1`, NetID ~300+, протоколы WireGuard, Awg, Xray).
- **Целевой сервис:** Anthropic Claude (`https://claude.ai`).
- **Главная цель:** 100% изоляция веб-сессий Claude от реального сетевого окружения (IP-адреса, системных DNS, геолокации, часового пояса, системного языка и фингерпринтинга устройства) с соблюдением принципа **Strict Fail-Closed Zero-Leak** (при падении VPN трафик мгновенно отсекается, утечка в открытую сеть физически невозможна).

---

## 2. Незыблемые Инварианты Безопасности (Security Invariants)

Каждый агент, модифицирующий проект, **ОБЯЗАН** соблюдать следующие инварианты:

1. **Запрет открытого трафика (Zero Cleartext):**
   - `android:usesCleartextTraffic="false"` в [`AndroidManifest.xml`](app/src/main/AndroidManifest.xml).
   - Прямой выход сокетов в сеть запрещён на уровне конфигурации.
2. **Тотальная маршрутизация через локальный шлюз (100% SOCKS5 Proxy Override + Anti-Bypass):**
   - Весь трафик Chromium WebView принудительно направляется на внутренний SOCKS5 прокси (`127.0.0.1:<ephemeral_port>`) через `ProxyController.getInstance().setProxyOverride(...)`.
   - Режим `direct://` и любой сетевой fallback исключены (`isDirectFallbackDisallowed = true`).
   - Применяется `.removeImplicitRules()` в `ProxyConfig.Builder()`, предотвращающий автоматический обход прокси Chromium для `localhost` и `127.0.0.1`.
   - Google Safe Browsing отключён через `WebSettingsCompat.setSafeBrowsingEnabled(settings, false)`, исключая сторонние внепрокси-запросы Chromium к серверам Google.
3. **Белый список назначений и фильтр приватных IP (Destination Allowlist & Private IP Filter):**
   - Доступ через SOCKS5 шлюз разрешён исключительно к доменам из белого списка `ALLOWED_DOMAIN_SUFFIXES` (`claude.ai`, `anthropic.com`, `intercom.io`, `statsig.com`, `browserleaks.com`, `google.com`, `gstatic.com`, `googleapis.com`, `appleid.apple.com`). Все сторонние домены мгновенно отклоняются `0x05 (Connection Refused)`.
   - Прямые IPv4-подключения фильтруются через `isForbiddenIp`: запрещены loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), RFC 1918 приватные подсети (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) и IP самого tun-интерфейса.
4. **Строгая привязка сокетов к VPN и поколенческий Kill-Switch (Generational Socket Binding):**
   - Состояние `VpnTunnelState.Connected` строго хранит non-null `network: Network` и монотонный счётчик `generation: Long`.
   - При подключении VPN вызывается `connectivityManager.bindProcessToNetwork(network)` (и `bindProcessToNetwork(null)` при отключении).
   - Каждый исходящий TCP-сокет (`VpnGatekeeperProxy` и `TunnelDnsResolver`) привязывается в строгом порядке:
     1. `network.bindSocket(socket)` — обязательный системный вызов ядра. При любой ошибке соединение немедленно прерывается (никакого silent fail-open).
     2. `socket.bind(InetSocketAddress(tunIpv4, 0))` — привязка локального IP источника к IPv4 адресу tun-адаптера.
   - Исходящие сокеты регистрируются с номером поколения: `outboundSockets: ConcurrentHashMap<Socket, Long>`.
   - Синхронный слушатель `TunnelListener` вызывается под блокировкой `stateLock` при любом изменении VPN:
     - При падении VPN мгновенно закрывает дескрипторы всех активных клиентских и серверных сокетов.
     - При VPN handover (смене tun/NetID) мгновенно закрывает сокеты устаревших поколений (`gen < currentGeneration`).
5. **Выделенный пул потоков для передачи трафика (Relay Anti-Starvation):**
   - Двунаправленный пайпинг данных (`relayTraffic`) работает на выделенном пуле потоков `relayExecutor = Executors.newCachedThreadPool { ... }.asCoroutineDispatcher()`.
   - Лимит пула `Dispatchers.IO` (64 потока) больше не расходуется на блокирующий ввод-вывод сокетов, что гарантирует мгновенное выполнение корутин таймеров, телеметрии и мониторинга.
   - Реализовано полудуплексное закрытие TCP (`shutdownOutput()` / `shutdownInput()`).
6. **Fail-Closed TCP DNS с выделенным Scheduled Watchdog, True SWR и Single-Flight:**
   - Системный DNS Android и сторонние Smart DNS полностью игнорируются.
   - Все запросы резолвятся внутри туннеля через TCP (`1.1.1.1:53` -> `8.8.8.8:53`).
   - Сторожевой таймер реализован через `watchdogExecutor: ScheduledExecutorService` (`newSingleThreadScheduledExecutor`), исключая влияние загрузки корутинного пула потоков.
   - **Single-Flight дедупликация:** `inFlightQueries: ConcurrentHashMap<String, Deferred<Inet4Address?>>` объединяет параллельные запросы к одному домену в один сетевой запрос.
   - **True Stale-While-Revalidate (SWR):** при истечении TTL кэша сразу отдаётся stale-запись из памяти, а в фоне запускается асинхронное обновление через туннель (`dnsScope.launch { executeNetworkResolve(...) }`).
   - Stale-кэш сохраняется при переподключениях VPN (`clearCache(clearStale = false)`).
   - Валидация QNAME в DNS-ответе и рандомизация выбора адреса при множественных A-записях.
7. **Региональный фильтр доменов (Regional Domain Guard):**
   - Нормализация доменов перед проверкой: `.trim().trimEnd('.').lowercase(Locale.ROOT)`.
   - Запросы к `.google.ru` прозрачно переписываются на `.google.com`.
   - Домены СНГ (`.ru`, `.su`, `.by`, `.xn--p1ai`) немедленно блокируются ответом `REP_CONN_REFUSED` (`0x05`).
   - IPv6 (`ATYP 0x04`) отклоняется ответом `REP_ADDR_TYPE_NOT_SUPPORTED` (`0x08`).
8. **Многопрофильная контейнеризация аккаунтов (Multi-Account Isolation & Keystore Security):**
   - Каждый аккаунт Claude имеет свой `profileSeed` и изолированное хранилище сессий.
   - При поддержке `WebViewFeature.MULTI_PROFILE` используется `ProfileStore` (`Profile.getOrCreate(...)`).
   - В `AccountCookieJarFallback` генерация IV доверена провайдеру `AndroidKeyStore` (`cipher.init(Cipher.ENCRYPT_MODE, key)` без явного IV, с последующим получением `cipher.iv`), что устраняет `InvalidAlgorithmParameterException: Caller-provided IV not permitted`.
   - Аутентифицированные данные GCM AAD привязаны к идентификатору профиля (`cipher.updateAAD(profileId.toByteArray())`) для защиты от подмены шифротекста между профилями.
   - Парсинг JSON профилей переведён на надёжный `org.json.JSONArray` / `JSONObject` вместо хрупких регулярных выражений.
   - Удаление активного профиля защищено предварительным переключением на оставшийся профиль.
9. **Глубокий спуфинг фингерпринта и окружения (Document-Start JS & DOM Protection):**
   - POSIX: `setenv("TZ", "Europe/Amsterdam", 1)` + `tzset()`.
   - JVM: `TimeZone.setDefault("Europe/Amsterdam")`, `Locale.setDefault(Locale.US)`.
   - Android OS: `LocaleList.setDefault(LocaleList(Locale.US))` (на API 24+).
   - Document-Start JS: WebRTC полностью ампутирован (`RTCPeerConnection = null`).
   - **Offscreen Canvas Farbling:** при вызовах `toDataURL` и `toBlob` для наложения детерминированного шума создаётся временный оффскрин-холст (`document.createElement('canvas')`), предотвращая перманентное разрушение исходного холста страницы и визуальные артефакты.
   - **`Function.prototype.toString` Cloaking:** использование `WeakMap` маскирует переопределённые JS-методы под нативные (`function name() { [native code] }`).
   - Блокировка TTS-голосов на уровне `window.speechSynthesis` и `SpeechSynthesis.prototype.getVoices`.
   - Фиксация `Intl.*` на `en-US`, `hardwareConcurrency = 8`, `deviceMemory = 8`, `navigator.webdriver = false`, `navigator.connection.onchange = null`.
10. **Отказоустойчивость WebView и валидация Origin:**
    - Реализован `onRenderProcessGone` в `WebViewClient`: при сбое или нехватке памяти рендерера Chromium Activity не падает, а безопасно пересоздаёт WebView.
    - В `SafeDownloadBridge` встроена строгая валидация источника (`url.startsWith("https://claude.ai")`), предотвращающая междоменный вызов загрузчика.

---

## 3. Карта Файлов и Архитектура Компонентов (Codebase Directory & Map)

```text
app/src/main/java/com/example/claudecageand/
├── ClaudeCageApp.kt                      # Application класс: синглтоны, POSIX TZ, JVM Locale, LocaleList.setDefault
├── MainActivity.kt                       # Главная Activity: WebView, профили, плавающий якорь, Card UI, версии, SafeDownload, onRenderProcessGone
├── accounts/
│   ├── AccountProfile.kt                 # Модель данных профиля: id, displayName, storageKey, profileSeed, createdAt
│   ├── AccountProfileManager.kt          # Менеджер профилей: переключение, добавление, удаление, StateFlow
│   ├── AccountProfileJsonCodec.kt        # JSON сериализация профилей на org.json (JSONArray / JSONObject)
│   └── AccountCookieJarFallback.kt       # Резервный CookieJar: AES-256-GCM (AndroidKeyStore auto-IV, AAD привязка к profileId)
├── net/
│   ├── TunnelDnsResolver.kt              # TCP DNS: ScheduledExecutor watchdog, True SWR, Single-Flight, RFC 1035
│   ├── VpnGatekeeperProxy.kt             # SOCKS5 шлюз: Allowlist доменов, private IP filter, relay thread pool, generational sockets
│   ├── VpnStateMonitor.kt                # Мониторинг VPN: non-null Network, generation counter, bindProcessToNetwork, TunnelListener
│   └── VpnTunnelState.kt                 # Sealed class состояний: Connected (tunIpv4, network, iface, generation) vs Disconnected
├── security/
│   └── AntiFingerprintHardener.kt        # Document-Start JS: WebRTC Kill-Switch, offscreen Canvas farbling, toString cloaking, TTS/Intl lock
├── telemetry/
│   └── SecurityAuditLogger.kt            # Логгер безопасности, кольцевой буфер (500 записей), генератор отчётов Markdown
└── ui/
    ├── AppIconManager.kt                 # Динамическая смена иконки (activity-alias)
    ├── AppIconOption.kt                  # Варианты иконки: VARIANT_1, VARIANT_2
    ├── UiLanguage.kt                     # Enum языков интерфейса: RU, EN
    └── UiStrings.kt                      # Двуязычный строковый каталог (полная независимость от Android resources)
```

---

## 4. Спецификация Ключевых Компонентов

### 4.1. Сетевой Шлюз `VpnGatekeeperProxy.kt`
- **Протокол:** RFC 1928 SOCKS5 на `127.0.0.1:<random-port>`.
- **Поддерживаемые команды:** `CMD_CONNECT (0x01)`.
- **Политика назначения (Zero-Trust Allowlist):**
  - Разрешены только домены экосистемы Claude/Anthropic: `claude.ai`, `anthropic.com`, `intercom.io`, `statsig.com`, `browserleaks.com`, `google.com`, `gstatic.com`, `googleapis.com`, `appleid.apple.com`. Любые иные домены отвергаются `0x05 (Connection refused)`.
  - Фильтр IP-адресов `isForbiddenIp`: запрещает loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), RFC 1918 приватные диапазоны (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) и собственный IP tun-адаптера.
- **Адресные типы:**
  - `ATYP_IPV4 (0x01)`: проверка `isForbiddenIp`, исключение непубличных IP.
  - `ATYP_DOMAIN (0x03)`:
    - Нормализация: `.trim().trimEnd('.').lowercase(Locale.ROOT)`.
    - `.google.ru` $\to$ прозрачный rewrite в `.google.com`.
    - Домены СНГ (`.ru`, `.su`, `.by`, `.xn--p1ai`) и домены вне белого списка $\to$ моментальный отказ `0x05`.
    - Локальный резолвинг через `TunnelDnsResolver.resolve(domain)`.
  - `ATYP_IPV6 (0x04)`: немедленный отказ `0x08 (Address type not supported)`.
- **Выделенный пул ретрансляции (`relayExecutor`):**
  - Двунаправленный обмен сокетов обслуживается `Executors.newCachedThreadPool()`, предотвращая голодание `Dispatchers.IO` (лимит 64 потока) при параллельных запросах.
  - Симметричный half-duplex shutdown (`shutdownOutput()` / `shutdownInput()`) при завершении одного из направлений.
- **Поколенческий сокет-трекинг:** `outboundSockets: ConcurrentHashMap<Socket, Long>` регистрирует исходящие сокеты с номером поколения туннеля. При разрыве VPN или смене туннеля (handover) синхронный коллбэк `TunnelListener` закрывает дескрипторы устаревших сокетов.

### 4.2. Резолвер DNS `TunnelDnsResolver.kt`
- **Протокол:** RFC 1035 TCP DNS (2-байтный префикс длины сообщения).
- **Серверы:** Primary `1.1.1.1:53`, Fallback `8.8.8.8:53`.
- **Scheduled Watchdog:** `watchdogExecutor: ScheduledExecutorService` (`newSingleThreadScheduledExecutor`) принудительно закрывает системный сокет ровно через `DNS_TIMEOUT_MS = 2500` мс, не завися от корутинного пула потоков.
- **Single-Flight Дедупликация:** `inFlightQueries: ConcurrentHashMap<String, Deferred<Inet4Address?>>` объединяет одновременные запросы к одному домену в один сетевой запрос, устраняя шквал повторных обращений к DNS.
- **True Stale-While-Revalidate (SWR):**
  - Если запись есть в кэше и TTL не истёк — отдаётся немедленно.
  - Если запись устарела по TTL, но присутствует в `staleCache`, она отдаётся сразу, а обновление запускается в фоне: `dnsScope.launch { executeNetworkResolve(...) }`.
  - Stale-кэш сохраняется при кратковременных падениях VPN (`clearCache(clearStale = false)`).
- **Валидация ответов:** сверка QNAME в секции Query ответа с запрошенным доменом, защита от спуфинга Transaction ID через `SecureRandom`, рандомизация адреса при возврате нескольких A-записей.

### 4.3. Харденинг Веб-Движка `AntiFingerprintHardener.kt`
- Инжектируется через `WebViewCompat.addDocumentStartJavaScript(...)`.
- **WebRTC:** Полная ампутация: `RTCPeerConnection`, `webkitRTCPeerConnection`, `RTCDataChannel`, `RTCSessionDescription`, `navigator.mediaDevices.getUserMedia` обращены в `null` и удалены.
- **Offscreen Canvas Farbling:**
  - Детерминированный шум на базе `profileSeed`: `val safeSeed = (kotlin.math.abs(profileSeed) % 997) + 1`.
  - При вызовах `toDataURL` и `toBlob` шум накладывается на **временный оффскрин-холст** (`document.createElement('canvas')`), предотвращая порчу пикселей на оригинальном холсте страницы и исключая детекцию антифрод-системами.
- **Маскировка функций (`Function.prototype.toString` Cloaking):**
  - Подмененные функции регистрируются в `WeakMap`.
  - `Function.prototype.toString` возвращает `function name() { [native code] }` для всех перехваченных методов, маскируя внедрение скрипта.
- **TTS-голоса:** `window.speechSynthesis.getVoices = () => []` и `SpeechSynthesis.prototype.getVoices = () => []` блокируют определение русских системных голосовых пакетов.
- **Intl & Окружение:** `Intl.*` зафиксирован на `en-US`, `hardwareConcurrency = 8`, `deviceMemory = 8`, `navigator.webdriver = false`, `navigator.connection.onchange = null`.

### 4.4. Менеджер Аккаунтов и Cookie `AccountProfileManager.kt`
- **Профили:** Хранятся в JSON в приватных SharedPreferences (`claudecage_account_profiles`), сериализуются через `AccountProfileJsonCodec` на базе `org.json`.
- **Изоляция:**
  - Modern (API 29+ & WebKit feature): `ProfileStore.getInstance().getOrCreateProfile(storageKey)`.
  - Fallback: `AccountCookieJarFallback` перехватывает cookie активного профиля перед сменой, очищает `CookieManager`, восстанавливает cookie нового профиля.
- **Шифрование Cookie (AES-256-GCM):**
  - Генерация IV доверена аппаратной реализации `AndroidKeyStore` (`cipher.init(Cipher.ENCRYPT_MODE, secretKey)` без явного IV, IV считывается из `cipher.iv`), что исключает `InvalidAlgorithmParameterException`.
  - Дополнительные аутентифицированные данные GCM AAD привязаны к `profileId` (`cipher.updateAAD(profileId.toByteArray())`) для защиты от перестановки зашифрованных cookie между профилями.
- **Безопасное переключение и удаление:** перед удалением активного профиля менеджер переключается на альтернативный профиль, предотвращая гонки и белый экран.

### 4.5. Интерфейс и Activity `MainActivity.kt`
- **Anti-Bypass и отключение SafeBrowsing:**
  - `ProxyConfig.Builder().removeImplicitRules()` гарантирует, что WebView не обходит внутренний SOCKS5 прокси для обращений к `localhost` и `127.0.0.1`.
  - `WebSettingsCompat.setSafeBrowsingEnabled(settings, false)` отключает внепроксийные запросы Chromium к облачной телеметрии Google Safe Browsing.
- **Устойчивость к падениям рендерера (`onRenderProcessGone`):**
  - При нехватке памяти или сбое Chromium рендерер перезапускается без падения Activity, возвращая `true`.
- **Безопасная загрузка (`SafeDownloadBridge`):**
  - JS-мост `"ClaudeCageDownload"` проверяет происхождение: `wv.url?.startsWith("https://claude.ai") == true`, блокируя загрузки из недоверенных фреймов.
- **Сворачиваемый статус-бар и плавающий якорь:**
  - Индикация состояний: 🟢 Protected, 🟡 Amber (таймауты туннеля $\ge 2$), 🔴 Blocked (Kill-Switch).
  - Перемещаемый бейдж безопасности с сохранением координат.
- **Карточный UI и просмотр версий компонентов (`ComponentVersions`).**
- **Защита Recents (`FLAG_SECURE`):** предотвращение скриншотов и превью в диспетчере задач.

---

## 5. Команды Сборки, Тестирования и Верификации

Всегда запускать проверку после внесения любых правок в исходный код:

```bash
# Запуск полного набора модульных тестов
./gradlew testDebugUnitTest

# Сборка Debug APK
./gradlew assembleDebug

# Комплексный прогон: тесты + сборка APK
./gradlew testDebugUnitTest assembleDebug
```

- **Путь к собранному APK:** `ClaudeCage-1.0.apk` (автоматически сохраняется в корень проекта, а также дублируется в `app/build/outputs/apk/debug/ClaudeCage-1.0.apk`).
- **HTML-отчёты о тестах:** `app/build/reports/tests/testDebugUnitTest/index.html`

---

## 6. Каталог Модульных Тестов

| Тестовый класс | Расположение | Проверяемый функционал |
| :--- | :--- | :--- |
| `TunnelDnsResolverTest` | `app/src/test/.../net/` | Watchdog таймауты, `staleCache` fallback, кэширование, canary NODATA, TCP DNS |
| `VpnGatekeeperProxyTest` | `app/src/test/.../net/` | Блокировка при VPN Off, разрыв сокетов, блокировка IPv6 (0x08), блокировка доменов СНГ (.ru/.by/.su), Network binding |
| `VpnTunnelStateTest` | `app/src/test/.../net/` | Модели состояний туннеля, равенство и форматирование |
| `AntiFingerprintHardenerTest` | `app/src/test/.../security/` | Canvas шум для seed 0, `toBlob`, `speechSynthesis`, `Intl` en-US, `webdriver` |
| `AccountProfileManagerTest` | `app/src/test/.../accounts/` | Создание, переименование, удаление, переключение профилей, seed |
| `SecurityAuditLoggerTest` | `app/src/test/.../telemetry/` | Кольцевой буфер, метрики, формат Markdown отчёта, thread-safety |
| `UiStringsAndLanguageTest` | `app/src/test/.../ui/` | Полнота двуязычных строк (RU/EN), отсутствие пустых значений, версии |
| `AppIconManagerTest` | `app/src/test/.../ui/` | Переключение лаунчер-алиасов |

---

## 7. Журнал Телеметрии с Реального Устройства (`logs_from_app/logs.txt`)

Пользователь запускает приложение на смартфоне и периодически сохраняет логи в директорию `logs_from_app/logs.txt`.
При анализе этого файла обращать внимание на:
- `DNS Latency (Last / Max)` и `DNS Failures`: резкий рост Max Latency до 50+ секунд означает проблемы сокета при выходе из Doze mode.
- `consecutiveNetworkTimeouts`: значение $\ge 2$ активирует Amber-статус в приложении.
- `POSIX TZ`, `JVM TimeZone`, `JVM Locale`: должны строго оставаться `Europe/Amsterdam` и `en-US`.
- `Accepted / Rejected / Killed`: метрики соединений шлюза SOCKS5.

---

## 8. Золотые Правила для Разработки и Редактирования (Golden Rules)

1. **Никакого хардкода строк в UI:** Все строки интерфейса должны объявляться в [`UiStrings.kt`](app/src/main/java/com/example/claudecageand/ui/UiStrings.kt) сразу на двух языках (RU и EN). После добавления новых методов обязательно добавлять проверки в [`UiStringsAndLanguageTest.kt`](app/src/test/java/com/example/claudecageand/ui/UiStringsAndLanguageTest.kt).
2. **Никаких блокирующих вызовов в основном потоке:** Сетевые операции, шифрование и работа с сокетами проводятся только в диспетчере `Dispatchers.IO` или фоновых потоках.
3. **Блокирующие системные вызовы сокетов и пулы потоков:** Никогда не полагаться только на `withTimeoutOrNull` для прерывания вызовов вроде `Socket.connect()` или `InputStream.read()`. Для DNS-запросов обязательно использовать выделенный `ScheduledExecutorService` watchdog, не зависящий от корутинного пула. Длительный двунаправленный ретрансляционный I/O сокетов (`pipe`) выносить исключительно в отдельный пул потоков (`relayExecutor`), не занимая ограниченный `Dispatchers.IO` (лимит 64 потока).
4. **Безопасность криптографии AndroidKeyStore:** При шифровании AES-GCM не передавать собственный IV в `cipher.init(Cipher.ENCRYPT_MODE, key)`. Доверять генерацию случайного IV аппаратному провайдеру Keystore, считывать сгенерированный IV через `cipher.iv` и сохранять его с префиксом к шифротексту. Всегда связывать AAD с контекстом сущности (например, `profileId`).
5. **Сохранение совместимости с JVM Unit Tests:** Классы, взаимодействующие с Android Keystore, ProfileStore или системными сервисами, обязаны иметь безопасный fallback/mock для прохождения тестов `./gradlew testDebugUnitTest` на хост-машине разработчика.
6. **Не трогать dotfiles без инструкции:** В соответствии с пользовательскими правилами, любые изменения в dotfiles требуют предварительного создания ветки в git bare репозитории и бэкапа в `~/.config-backups/`.
