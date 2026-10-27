# ClaudeCage 🛡️
### Android Zero-Trust Security Cage for Anthropic Claude

[![Android](https://img.shields.io/badge/Platform-Android%2013%2B%20(API%2033--37)-3DDC84.svg?style=flat&logo=android)](https://developer.android.com)
[![Version](https://img.shields.io/badge/Release-v1.3%20(Build%204)-blue.svg?style=flat)]()
[![Stage](https://img.shields.io/badge/Hardening-Stage%2010.2%20Production%20Hotfix-purple.svg?style=flat)]()
[![Architecture](https://img.shields.io/badge/Security-Strict%20Fail--Closed%20Zero--Leak-red.svg?style=flat)]()
[![Tests](https://img.shields.io/badge/Unit%20Tests-62%2F62%20Passed-brightgreen.svg?style=flat)]()

**ClaudeCage** — это бескомпромиссный, аппаратно изолированный Android-контейнер для веб-интерфейса [Anthropic Claude](https://claude.ai), построенный по принципу **Strict Fail-Closed Zero-Leak**.

Приложение решает ключевую проблему мобильной безопасности: предотвращение утечек реального сетевого окружения (IP-адреса, системных DNS, геолокации, часового пояса, системного языка и аппаратного фингерпринтинга устройства) при работе через VPN (Amnezia VPN Premium: протоколы WireGuard, Awg, Xray). При малейшем сбое, реконнекте или падении VPN-туннеля любой трафик мгновенно отсекается на уровне сокетов ядра Linux — выход в открытую сеть через Wi-Fi или сотовую связь физически невозможен.

---

## 🚀 1. Как устроен ClaudeCage v1.3 и почему это круто

Внутри **ClaudeCage v1.3** реализована глубокая эшелонированная оборона. Вместо стандартного Android WebView, где происходят фоновые утечки через Google Safe Browsing, WebRTC, сторонние DNS и неявные правила обхода прокси, в ClaudeCage трафик движка замкнут на локальный сетевой шлюз ядра, защищён криптографическим резолвером и маскируется стелс-скриптами:

```mermaid
flowchart TD
    subgraph App["📦 Клиентский Слой (Chromium WebView & UI)"]
        WV["🌐 Изолированный Chromium WebView (ProfileStore / Multi-Account)"]
        HARD["🕵️ Document-Start JS Hardening\n• WebRTC Kill-Switch (RTCPeerConnection = null)\n• Offscreen Canvas Farbling (чистый DOM холст)\n• Function.toString Cloaking ([native code] via WeakMap)\n• TTS / SpeechSynthesis Block & Intl en-US Lock"]
        W3C["🔔 W3C Web Notifications Polyfill (window.Notification + ServiceWorker)"]
        UI["🎛️ Защитный Интерфейс (Плавающий якорь 🟢/🟡/🔴, 🔄 Reload, 🧹 Purge, FLAG_SECURE)"]
    end

    subgraph Bridges["🌉 Безопасные Мосты и Управление Потоками (JavaBridge Thread-Safe)"]
        CACHE["⚡ @Volatile currentWebViewUrl (Кэш URL без обращения к WebView из фонового потока)"]
        DL_BRIDGE["💾 SafeDownloadBridge (Zero-Trust Origin Check + UI Thread Validation)"]
        NOTIF_BRIDGE["📢 ClaudeCageNotificationBridge (Heads-Up, BigTextStyle, Origin Check)"]
        SMART_WL["🔋 Smart PARTIAL_WAKE_LOCK (hasRecentTraffic < 15с по байтам в pipe)"]
    end

    subgraph Proxy["🧱 Локальный Шлюз Безопасности (In-Process SOCKS5 Gatekeeper Proxy)"]
        PROXY_CFG["⚙️ ProxyConfig (removeImplicitRules + No Direct Fallback + SafeBrowsing OFF)"]
        ALLOW["📋 Destination Allowlist (24 доверенных домена Claude/Turnstile/Stripe)"]
        IP_FILTER["🚫 Private IP Blacklist (RFC 1918, 127.0.0.0/8, Link-Local, Tun IP)"]
        REGIONAL["🌍 Regional Guard (.ru / .by / .su -> 0x05 REFUSED, .google.ru -> .google.com)"]
        RELAY["⚡ Dedicated Relay Thread Pool (Cached Thread Pool, Half-Duplex TCP Shutdown)"]
        GEN_TRACK["🏷️ Generational Socket Tracking (ConcurrentHashMap Socket -> Tunnel Gen)"]
    end

    subgraph DNS["📡 Fail-Closed TCP DNS Резолвер (RFC 1035 TCP DNS)"]
        TCP_DNS["🔒 TCP DNS Резолвер (1.1.1.1:53 / 8.8.8.8:53 строго внутри туннеля)"]
        WATCHDOG["⏱️ ScheduledExecutor Watchdog (2500 мс hard socket close против Doze)"]
        SINGLE_FLIGHT["✈️ Single-Flight Дедупликация (Параллельные запросы -> 1 сетевой вызов)"]
        SWR["💾 True Stale-While-Revalidate (Мгновенная отдача кэша + фоновый апдейт)"]
    end

    subgraph Kernel["🛡️ Сетевой Стек Ядра Linux и VPN-Мониторинг"]
        MONITOR["👁️ VpnStateMonitor (Non-null Network, generation counter, TunnelListener)"]
        BIND["🔗 Generational Dual Binding (network.bindSocket + socket.bind к tunIpv4)"]
        KILLSWITCH["⚡ Поколенческий Kill-Switch (0 мс сброс сокетов при handover и VPN off)"]
    end

    subgraph Net["🌐 Сетевые Интерфейсы Устройства"]
        VPN["🟢 VPN-туннель tun0 / tun1 (Amnezia / WireGuard / Xray)"]
        PHYS["🔴 Физические интерфейсы (Wi-Fi wlan0 / Сотовая связь rmnet_data)"]
    end

    WV --> HARD --> W3C --> UI
    WV --> CACHE
    CACHE --> DL_BRIDGE & NOTIF_BRIDGE
    NOTIF_BRIDGE --> SMART_WL

    WV ==>|"100% трафика WebView строго через SOCKS5"| PROXY_CFG
    PROXY_CFG --> ALLOW --> IP_FILTER --> REGIONAL --> RELAY
    RELAY -.->|"Резолвинг доменов"| TCP_DNS
    TCP_DNS --> WATCHDOG & SINGLE_FLIGHT & SWR

    RELAY --> GEN_TRACK --> BIND
    TCP_DNS --> BIND
    BIND --> MONITOR --> KILLSWITCH

    KILLSWITCH ==>|"Разрешено: трафик строго в туннель"| VPN
    KILLSWITCH x--x|"Заблокировано: прямой выход исключен (0 мс DROP / Fail-Closed)"| PHYS
    TCP_DNS ==>|"DNS строго через адрес туннеля"| VPN
    TCP_DNS x--x|"Блокировка: системный DNS хоста отключен"| PHYS

    VPN ==>|"Шифрованный выход"| Internet["🌍 Серверы Anthropic Claude (claude.ai)"]
```

---

## ⚡ 2. Ключевые Возможности и Архитектурные Инварианты

### 🔒 100% SOCKS5 Proxy Override & Anti-Bypass
* **Тотальная маршрутизация:** весь трафик Chromium WebView принудительно направляется на локальный шлюз `127.0.0.1:<ephemeral_port>` через `ProxyController.getInstance().setProxyOverride(...)`.
* **Запрет Fallback:** режим прямого соединения исключён (`isDirectFallbackDisallowed = true`).
* **Анти-обход (Anti-Bypass):** применён метод `.removeImplicitRules()`, отключающий стандартные неявные правила Chromium, разрешающие сайтам прямой опрос `localhost` и `127.0.0.1`.
* **Ампутация SafeBrowsing:** вызов `WebSettingsCompat.setSafeBrowsingEnabled(settings, false)` гарантирует отсутствие внепроксийных фоновых запросов браузерного движка к серверам Google.
* **Строгий Cleartext запрет:** `android:usesCleartextTraffic="false"` в манифесте исключает открытую передачу HTTP-пакетов.

### 🛡️ Белый Список Назначений (Destination Allowlist) & Фильтр Приватных IP
* **Zero-Trust Allowlist:** разрешены исключительно 24 проверенных домена, необходимых для корректной работы экосистемы Claude:
  - Сервисы Anthropic: `claude.ai`, `anthropic.com`, `claude.com`.
  - Антифрод и защита: `cloudflare.com`, `hcaptcha.com`.
  - Биллинг: `stripe.com`, `stripe.network`.
  - Клиентский интерфейс и CDN: `intercom.io`, `intercomcdn.com`.
  - Телеметрия сервиса: `statsig.com`, `statsigapi.net`, `datadoghq.com`, `sentry.io`.
  - Google OAuth / Аватары: `google.com`, `gstatic.com`, `googleapis.com`, `googleusercontent.com`, `youtube.com`.
  - Apple ID авторизация: `apple.com`, `appleid.apple.com`.
  - Диагностика безопасности: `browserleaks.com`, `browserleaks.net`, `browserleaks.org`, `ripe.net`.
  - *Все сторонние домены мгновенно отвергаются кодом `0x05 (Connection Refused)`.*
* **Private IP Blacklist (`isForbiddenIp`):** полностью запрещены подключения к loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), RFC 1918 приватным сетям (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) и локальному IP самого tun-адаптера.
* **Региональный фильтр:** домены СНГ (`.ru`, `.su`, `.by`, `.рф`) блокируются немедленно (`0x05`), а запросы к `.google.ru` прозрачно переписываются на `.google.com`. IPv6 (`ATYP 0x04`) отклоняется ответом `0x08`.

### ⚡ Поколенческий Kill-Switch и Двойная Привязка к Ядру (Dual-Binding)
* **Generational Socket Binding:** каждый исходящий TCP-сокет связывается с сетевым стеком туннеля в два этапа:
  1. `network.bindSocket(socket)` — привязка к системному NetID туннеля VPN.
  2. `socket.bind(InetSocketAddress(tunIpv4, 0))` — аппаратная привязка IP источника к IPv4 адресу tun-интерфейса.
* **Синхронный `TunnelListener`:** при разрыве VPN или смене туннеля (handover) синхронно закрываются все сокеты устаревших поколений (`gen < currentGeneration`), предотвращая утечки данных в открытые физические интерфейсы (`wlan0` / `rmnet_data`).
* **Relay Anti-Starvation:** передача трафика вынесена на выделенный пул потоков `relayExecutor = Executors.newCachedThreadPool()`, что исключает исчерпание стандартного корутинного пула `Dispatchers.IO` (лимит 64 потока) при множественных параллельных запросах.

### 📡 Fail-Closed TCP DNS (RFC 1035) с Scheduled Watchdog, True SWR и Single-Flight
* **Изолированный DNS:** системный DNS Android полностью игнорируется. Все DNS-запросы направляются по протоколу TCP через туннель на `1.1.1.1:53` (primary) и `8.8.8.8:53` (fallback).
* **Scheduled Watchdog:** сторожевой таймер на базе `ScheduledExecutorService` жёстко обрывает зависший сокет ровно через `2500 мс`, предотвращая freeze при выходе из Doze-режима.
* **Single-Flight Дедупликация:** параллельные запросы к одному домену объединяются в один сетевой запрос, исключая лавинообразные DNS-штормы.
* **True Stale-While-Revalidate (SWR):** при истечении TTL запись немедленно отдаётся из stale-кэша, а обновление выполняется асинхронно в фоне. Stale-кэш сохраняется при кратковременных падениях VPN.

### 🔔 W3C Web Notifications API & Потокобезопасный Нативный Шлюз
* **W3C Polyfill в Document-Start JS:** системный Android WebView не поддерживает стандартный браузерный API `window.Notification`. В ClaudeCage внедрён полный полифилл конструктора `Notification`, статических геттеров и воркеров (`ServiceWorkerRegistration.prototype.showNotification`).
* **Маскировка WeakMap:** все переопределённые методы замаскированы под нативный движок Chromium (`[native code]`).
* **Нативный Шлюз (`ClaudeCageNotificationBridge.kt`):**
  - Поддержка рантайм-разрешений Android 13+ (`POST_NOTIFICATIONS`).
  - Выделенный канал `IMPORTANCE_HIGH` с вибрацией и всплывающими Heads-Up уведомлениями.
  - Раскрывающийся текст ответа в шторке (`NotificationCompat.BigTextStyle`).
  - Двусторонняя маршрутизация клика по уведомлению в чат через `onNewIntent` $\to$ `window.__dispatchNotificationClick(id)`.
* **JavaBridge Thread Safety:** URL активной вкладки кэшируется в `@Volatile currentWebViewUrl` в UI-коллбэках, исключая `RuntimeException: A WebView method was called on thread 'JavaBridge'` при межпоточных проверках Origin.

### 🔋 Интеллектуальный Фоновый Режим (Smart WakeLock)
* **Проблема cgroup freezer:** при сворачивании приложения Android замораживает процесс через 10–30 секунд, обрывая входящий SSE-поток генерации ответа Claude.
* **Решение:** в `MainActivity.onStop()` фоновый `PARTIAL_WAKE_LOCK` захватывается только при наличии свежего трафика через прокси за последние 15 секунд (`hasRecentTraffic(15_000L)` на базе отслеживания байтов в `pipe()`). Если приложение свернуто в покое — процессор мгновенно засыпает без расхода батареи.

### 🕵️ Глубокий Anti-Fingerprint Hardening
* **POSIX & JVM:** `setenv("TZ", "Europe/Amsterdam", 1)`, `TimeZone.setDefault("Europe/Amsterdam")`, `Locale.setDefault(Locale.US)`, `LocaleList.setDefault(LocaleList(Locale.US))`.
* **WebRTC Kill-Switch:** полное удаление `RTCPeerConnection`, `webkitRTCPeerConnection`, `RTCDataChannel`, `getUserMedia`.
* **Offscreen Canvas Farbling:** наложение детерминированного псевдослучайного шума на базе `profileSeed` при вызовах `getImageData`, `toDataURL` и `toBlob`. При конвертациях в PNG/Blob шум генерируется на **временном оффскрин-холсте**, исключая порчу видимого DOM-холста страницы.
* **Маскировка `toString()`:** замена `Function.prototype.toString` зарегистрирована в `WeakMap`, благодаря чему `Function.prototype.toString.toString()` и все перехваченные методы возвращают честный `[native code]`.
* **Ампутация TTS:** `speechSynthesis.getVoices = () => []` блокирует определение установленных системных русских голосовых движков.
* **Фиксация окружения:** `Intl.*` зафиксирован на `en-US`, `hardwareConcurrency = 8`, `deviceMemory = 8`, `navigator.webdriver = false`, `navigator.connection.onchange = null`.

### 👥 Многопрофильность и Управление Сессией
* **Multi-Account Контейнеризация:** независимые сессии через современный AndroidX `ProfileStore` (`getOrCreateProfile(storageKey)`).
* **Аппаратный Keystore Fallback:** резервный CookieJar с AES-256-GCM шифрованием (автоматическая генерация IV аппаратным провайдером `AndroidKeyStore`, привязка AAD к `profileId`).
* **Комплексный сброс сессии (`btnPurgeSession` 🧹):** точечная очистка `ProfileStore`, кэша WebView и аппаратных Keystore-кук без удаления профиля.
* **Быстрая перезагрузка (`btnReload` 🔄):** кнопка обновления страницы в статусной панели при залипании интерфейса.
* **Privacy Screen (`FLAG_SECURE`):** защита содержимого чатов от снимков экрана и превью в недавних приложениях Android.

---

## 📂 3. Структура Проекта и Карта Компонентов

```text
ClaudeCage/
├── app/src/main/java/com/example/claudecageand/
│   ├── ClaudeCageApp.kt                      # Application: синглтоны, POSIX TZ, JVM Locale, LocaleList
│   ├── MainActivity.kt                       # Главная Activity: WebView, профили, плавающий якорь, Card UI, JavaBridge safety
│   ├── accounts/
│   │   ├── AccountProfile.kt                 # Модель данных профиля: id, displayName, storageKey, profileSeed
│   │   ├── AccountProfileManager.kt          # Менеджер профилей: переключение, добавление, удаление, StateFlow
│   │   ├── AccountProfileJsonCodec.kt        # JSON сериализация профилей на org.json
│   │   └── AccountCookieJarFallback.kt       # Fallback CookieJar: AES-256-GCM (AndroidKeyStore auto-IV + AAD)
│   ├── net/
│   │   ├── TunnelDnsResolver.kt              # TCP DNS: ScheduledExecutor watchdog, True SWR, Single-Flight
│   │   ├── VpnGatekeeperProxy.kt             # SOCKS5 шлюз: Allowlist 24 доменов, private IP filter, relay thread pool
│   │   ├── VpnStateMonitor.kt                # Мониторинг VPN: non-null Network, generation counter, TunnelListener
│   │   └── VpnTunnelState.kt                 # Модели состояний: Connected (tunIpv4, generation) vs Disconnected
│   ├── notifications/
│   │   └── ClaudeCageNotificationBridge.kt   # W3C Web Notification Bridge: JS-bridge, origin check, heads-up системные уведомления
│   ├── security/
│   │   └── AntiFingerprintHardener.kt        # Document-Start JS: WebRTC Kill, offscreen Canvas, toString cloaking, TTS/Intl lock
│   ├── telemetry/
│   │   └── SecurityAuditLogger.kt            # Логгер безопасности, кольцевой буфер (500 записей), экспорт Markdown-отчётов
│   └── ui/
│       ├── AppIconManager.kt                 # Динамическая смена иконки (activity-alias)
│       ├── AppIconOption.kt                  # Варианты иконки приложения
│       ├── UiLanguage.kt                     # Enum языков: RU, EN
│       ├── UiLanguageManager.kt              # Менеджер языка интерфейса
│       └── UiStrings.kt                      # Двуязычный строковый каталог
└── app/src/test/                             # 62 модульных теста (DNS, SOCKS5, AntiFingerprint, Profiles, Bridge)
```

---

## 🛠️ 4. Сборка Проекта и Запуск Тестов

### Системные требования:
* **Android SDK:** Compile & Target SDK: 36 (Android 16/17+), Min SDK: 33 (Android 13+)
* **JDK:** 17+
* **Gradle:** 9.3+ (включён Gradle Wrapper)

### Основные команды:

```bash
# 1. Запуск полного набора из 62 модульных тестов:
./gradlew testDebugUnitTest

# 2. Сборка готового Debug APK:
./gradlew assembleDebug

# 3. Полный цикл (верификация тестов + автоматическая сборка APK в корень):
./gradlew testDebugUnitTest assembleDebug
```

> [!NOTE]
> Скрипт сборки Gradle автоматически именует и сохраняет актуальный бинарник **прямо в корень проекта**:
> **`ClaudeCage-1.3.apk`** (устаревшие версии удаляются автоматически).

---

## 📚 5. Архитектурная База Знаний и Документация

* [**`GEMINI.md`**](file:///home/milk13/IdeaProjects/ClaudeCageAnd/GEMINI.md) — Полная самодостаточная модель системы, архитектурный справочник и инварианты кодовой базы для ИИ-агентов.
* [**`SECURITY_AUDIT.md`**](file:///home/milk13/IdeaProjects/ClaudeCageAnd/SECURITY_AUDIT.md) — Подробный отчет архитектурного аудита безопасности с верификацией всех механизмов харденинга.
* [**`AUDIT_REPORT_ARGON4.md`**](file:///home/milk13/IdeaProjects/ClaudeCageAnd/AUDIT_REPORT_ARGON4.md) — Комплексный отчет и полный манифест исходного кода для анализа моделями глубокого рассуждения (Gemini Argon 4 / Claude 3.5 Sonnet).

---

## ⚖️ Лицензия и Отказ от Ответственности
Проект разработан исключительно в образовательных целях и для защиты конфиденциальности персональных данных в исследовательской среде информационной безопасности.
