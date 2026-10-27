# GEMINI.md — База Знаний и Архитектурный Справочник ClaudeCage

> **Назначение файла:** Этот файл является полным, концентрированным и самодостаточным техническим руководством для модели **Gemini** (и других ИИ-агентов). Он содержит полную модель кодовой базы, архитектурные решения, инварианты безопасности, структуру файлов и правила разработки проекта **ClaudeCage**, устраняя необходимость повторно вычитывать все файлы проекта при каждом новом диалоге.

---

## 1. Общие Сведения о Проекте (Project Overview)

- **Название приложения:** `ClaudeCage` (пакет: `com.example.claudecageand`).
- **Текущая версия:** `1.0 (Build 1)` • **Hardening:** `Stage 9: Final Production Hardening`.
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
2. **Тотальная маршрутизация через локальный шлюз (100% SOCKS5 Proxy Override):**
   - Весь трафик Chromium WebView принудительно направляется на внутренний SOCKS5 прокси (`127.0.0.1:<ephemeral_port>`) через `ProxyController.getInstance().setProxyOverride(...)`.
   - Режим `direct://` и любой сетевой fallback исключены (`isDirectFallbackDisallowed = true`).
3. **Строгая привязка сокетов к VPN (Socket-Level Kernel Binding):**
   - Каждый исходящий TCP-сокет (`VpnGatekeeperProxy` и `TunnelDnsResolver`) привязывается к сетевому стеку туннеля в строгом порядке:
     1. `vpnNetwork?.bindSocket(socket)` — привязка непривязанного сокета к `NetID` сети VPN в ядре Android.
     2. `socket.bind(InetSocketAddress(tunIpv4, 0))` — привязка локального IP источника к IPv4 адресу tun-адаптера.
4. **Аппаратный Kill-Switch при потере VPN:**
   - При переходе состояния VPN в `Disconnected` метод `VpnGatekeeperProxy.closeAllActiveSockets()` принудительно закрывает системные дескрипторы всех активных сокетов. Ни единого байта не может уйти через обычный Wi-Fi или сотовую сеть.
5. **Fail-Closed TCP DNS с защитой от Doze Mode (Socket Watchdog):**
   - Системный DNS Android и сторонние Smart DNS полностью игнорируются.
   - Все запросы резолвятся внутри туннеля через TCP (`1.1.1.1:53` -> `8.8.8.8:53`).
   - Для предотвращения 54-секундного зависания Linux ядра (`tcp_syn_retries`) при выходе устройства из сна используется сторожевой таймер `launch { delay(2500); socket.close() }`.
   - Реализован **Stale-While-Revalidate DNS-кэш** (`staleCache`): если сеть временно не отвечает при включении экрана, отдаётся последний валидный IP домена для текущей VPN-сессии.
6. **Региональный фильтр доменов (Regional Domain Guard):**
   - Запросы к `.google.ru` прозрачно переписываются на `.google.com`.
   - Домены СНГ (`.ru`, `.su`, `.by`, `.xn--p1ai`) немедленно блокируются ответом `REP_CONN_REFUSED` (`0x05`).
   - IPv6 (`ATYP 0x04`) отклоняется ответом `REP_ADDR_TYPE_NOT_SUPPORTED` (`0x08`).
7. **Многопрофильная контейнеризация аккаунтов (Multi-Account Isolation):**
   - Каждый аккаунт Claude имеет свой `profileSeed` и изолированное хранилище сессий.
   - При поддержке `WebViewFeature.MULTI_PROFILE` используется `ProfileStore` (`Profile.getOrCreate(...)`).
   - При отсутствии `MULTI_PROFILE` используется шифрованный Cookie Jar с ключом в аппаратном `AndroidKeyStore` (`AES-256-GCM`) и программным fallback для тестов.
8. **Глубокий спуфинг фингерпринта и окружения:**
   - POSIX: `setenv("TZ", "Europe/Amsterdam", 1)` + `tzset()`.
   - JVM: `TimeZone.setDefault("Europe/Amsterdam")`, `Locale.setDefault(Locale.US)`.
   - Android OS: `LocaleList.setDefault(LocaleList(Locale.US))` (на API 24+) для предотвращения утечки `Accept-Language: ru-RU` в субресурсах.
   - Document-Start JS: WebRTC полностью отключён (`RTCPeerConnection = null`), детерминированный шум Canvas (`safeSeed >= 1`) для `getImageData`, `toDataURL` и `toBlob`, блокировка русских TTS-голосов (`speechSynthesis.getVoices = () => []`), фиксация `Intl.*` на `en-US`, `navigator.webdriver = false`, `navigator.connection.onchange = null`.

---

## 3. Карта Файлов и Архитектура Компонентов (Codebase Directory & Map)

```text
app/src/main/java/com/example/claudecageand/
├── ClaudeCageApp.kt                      # Application класс: синглтоны, POSIX TZ, JVM Locale, LocaleList.setDefault
├── MainActivity.kt                       # Главная Activity: WebView, профили, плавающий якорь, Card UI, версии, SafeDownload
├── accounts/
│   ├── AccountProfile.kt                 # Модель данных профиля: id, displayName, storageKey, profileSeed, createdAt
│   ├── AccountProfileManager.kt          # Менеджер профилей: переключение, добавление, удаление, StateFlow
│   └── AccountCookieJarFallback.kt       # Резервный CookieJar: AES-256-GCM шифрование через AndroidKeyStore (с JVM fallback)
├── net/
│   ├── TunnelDnsResolver.kt              # TCP DNS (1.1.1.1/8.8.8.8): Watchdog 2.5с, StaleCache, TTL 300с, RFC 1035
│   ├── VpnGatekeeperProxy.kt             # SOCKS5 шлюз: привязка к tun, Regional Guard (.ru/.by блок), socket killer
│   ├── VpnStateMonitor.kt                # Мониторинг VPN: ConnectivityManager NetworkCallback, StateFlow<VpnTunnelState>
│   └── VpnTunnelState.kt                 # Sealed class состояний: Connected (tunIpv4, network, iface) vs Disconnected
├── security/
│   └── AntiFingerprintHardener.kt        # Document-Start JS: WebRTC Kill-Switch, Canvas noise, TTS voice block, Intl lock
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
- **Адресные типы:**
  - `ATYP_IPV4 (0x01)`: проверка валидности, исключение loopback/multicast.
  - `ATYP_DOMAIN (0x03)`:
    - `.google.ru` $\to$ прозрачный rewrite в `.google.com`.
    - Домены `.ru`, `.su`, `.by`, `.xn--p1ai` $\to$ моментальный отказ `0x05 (Connection refused)`.
    - Локальный резолвинг через `TunnelDnsResolver.resolve(domain)`.
  - `ATYP_IPV6 (0x04)`: немедленный отказ `0x08 (Address type not supported)`.
- **Сокет-трекинг:** `activeSockets: Set<Socket>` регистрирует каждый сокет клиента и удалённого сервера. Метод `closeAllActiveSockets()` вызывается при смене VPN-состояния.

### 4.2. Резолвер DNS `TunnelDnsResolver.kt`
- **Протокол:** RFC 1035 TCP DNS (2-байтный префикс длины сообщения).
- **Серверы:** Primary `1.1.1.1:53`, Fallback `8.8.8.8:53`.
- **Watchdog:** `val watchdog = launch { delay(2500); socket.close() }` прерывает блокирующие системные вызовы ядра. `DNS_TIMEOUT_MS = 2500`.
- **Алгоритм резолвинга (`resolve`):**
  1. Проверка `cache[cleanDomain]` (положительный TTL: 300 секунд).
  2. Проверка `negativeCache[cleanDomain]` (отрицательный TTL: 60 секунд, для canaries/NODATA).
  3. Сетевой запрос к Primary (1.1.1.1:53).
  4. При ошибке/таймауте — запрос к Fallback (8.8.8.8:53).
  5. При повторной ошибке (Doze Mode wake-up) — пауза 150 мс и повтор к 1.1.1.1.
  6. Если все сетевые попытки исчерпаны — проверка `staleCache[cleanDomain]`. Если запись есть, она возвращается с логированием `Wake-up fallback: serving last-known IP`.
  7. При успехе результат кэшируется в `cache` и `staleCache`.
  8. При разрыве VPN вызов `clearCache()` полностью очищает `cache` и `staleCache`.

### 4.3. Харденинг Веб-Движка `AntiFingerprintHardener.kt`
- Инжектируется через `WebViewCompat.addDocumentStartJavaScript(...)`.
- **WebRTC:** Переопределены в `null` и удалены: `RTCPeerConnection`, `webkitRTCPeerConnection`, `RTCDataChannel`, `RTCSessionDescription`, `navigator.mediaDevices.getUserMedia`.
- **Canvas шум:**
  ```javascript
  const safeSeed = (Math.abs(profileSeed) % 997) + 1; // Гарантированно >= 1
  ```
  Модифицирует первый пиксель на детерминированное смещение в `getImageData`, `toDataURL` и `HTMLCanvasElement.prototype.toBlob`.
- **TTS-голоса:** `speechSynthesis.getVoices = () => []` блокирует детекцию русских системных голосовых пакетов.
- **Intl:** `NumberFormat`, `Collator`, `PluralRules`, `RelativeTimeFormat` возвращают `locale = 'en-US'`.
- **Аппаратные характеристики:** `hardwareConcurrency = 8`, `deviceMemory = 8`.
- **Webdriver и сеть:** `navigator.webdriver = false`, `navigator.connection.onchange = null`.

### 4.4. Менеджер Аккаунтов и Cookie `AccountProfileManager.kt`
- **Профили:** Хранятся в JSON в приватных SharedPreferences (`claudecage_account_profiles`).
- **Изоляция:**
  - Modern (API 29+ & WebKit feature): `ProfileStore.getInstance().getOrCreateProfile(storageKey)`.
  - Fallback: `AccountCookieJarFallback` перехватывает cookie активного профиля перед сменой, очищает `CookieManager`, восстанавливает cookie нового профиля.
- **Шифрование Cookie:** AES-256-GCM с 12-байтным IV. Мастер-ключ создаётся в аппаратном модуле `AndroidKeyStore` (`claudecage_cookie_aes_key`). При запуске на хост-JVM (без AndroidKeyStore) автоматически переключается на программный AES генератор.
- **Смена профиля в UI:** `switchAccountProfile()` обязательно устанавливает `hasLoadedInitialUrl = false` перед `initWebView(targetProfile)`, устраняя проблему белого экрана.

### 4.5. Интерфейс и Activity `MainActivity.kt`
- **Сворачиваемый статус-бар:**
  - 🟢 **Зелёный (Protected):** VPN активен, туннель исправен.
  - 🟡 **Жёлтый (Amber Dead-Tunnel):** VPN подключён, но `consecutiveNetworkTimeouts >= 2` (таймауты DNS).
  - 🔴 **Красный (Blocked):** VPN отключён, Kill-Switch изолирует сеть.
- **Плавающий якорь безопасности (`viewFloatingSecurityAnchor`):** Минималистичный перемещаемый бейдж с точкой-индикатором и названием активного аккаунта. Сохраняет координаты в `SharedPreferences`.
- **Карточный UI (`createCardBackground`):** Все списки, секции диагностики и метрики обёрнуты в закруглённые карточки (`#161B22` / `#1E222B`).
- **Просмотр версий (`ComponentVersions`):**
  - Секция 0 в панели диагностики: отображает версии приложения, WebKit Chromium, Android OS, ABI устройства и стадию харденинга.
  - Кнопка «📦 Версии компонентов» открывает модальное окно с детальным отчётом и возможностью копирования в буфер обмена.
- **Безопасная загрузка (`SafeDownloadBridge`):** Скачивание файлов и артефактов Claude через JS bridge `"ClaudeCageDownload"` (fetch $\to$ blob $\to$ Base64 $\to$ Storage Access Framework `createDocumentLauncher`).
- **Защита Recents (`FLAG_SECURE`):** Предотвращает снятие скриншотов и превью в списке недавних приложений. Включена по умолчанию с возможностью переключения в диалоге диагностики.

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
3. **Блокирующие системные вызовы сокетов:** Никогда не полагаться только на `withTimeoutOrNull` для прерывания вызовов вроде `Socket.connect()` или `InputStream.read()`. Всегда использовать закрытие дескриптора через Socket Watchdog (`launch { delay(timeout); socket.close() }`).
4. **Сохранение совместимости с JVM Unit Tests:** Классы, взаимодействующие с Android Keystore, ProfileStore или системными сервисами, обязаны иметь безопасный fallback/mock для прохождения тестов `./gradlew testDebugUnitTest` на хост-машине разработчика.
5. **Не трогать dotfiles без инструкции:** В соответствии с пользовательскими правилами, любые изменения в dotfiles требуют предварительного создания ветки в git bare репозитории и бэкапа в `~/.config-backups/`.
