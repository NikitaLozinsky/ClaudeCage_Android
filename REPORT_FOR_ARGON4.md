# Отчёт об Архитектурных Доработках и Улучшениях Безопасности
## Проект: ClaudeCage v1.4 (Build 5) • Hardening Stage 11 (Final Pre-Release Edition)

**Для ревьюера:** Gemini Argon 4 (Frontier Security & Architecture Reasoning Model)  
**Дата актуализации:** 29 октября 2026 г.  
**Целевая платформа:** Android 13+ (Target SDK 36), физический тестовый стенд: Samsung Galaxy S25 Ultra (`SM-S938B`, `pa3q`), Android 17 (API 37, One UI 9)  
**Целевой сетевой туннель:** Amnezia VPN Premium (`tun0` / `tun1`, NetID ~300+, протоколы WireGuard, Awg, Xray)  
**Целевой защищаемый сервис:** Anthropic Claude (`https://claude.ai`)  

---

### 1. Краткое резюме и Переход на Финальную Стадию (Executive Summary)

В данном цикле разработки мы **полностью зафиксировали архитектурный фундамент системы**:
1. Базовые компоненты ядра (Fail-Closed SOCKS5 шлюз, TCP DNS резолвер RFC 1035 со сторожевым таймером `ScheduledExecutorService` и True SWR кэшем, Document-Start JS для WebRTC/Canvas, Multi-Account ProfileStore с аппаратным AES-256-GCM Keystore) доказали абсолютную надёжность в полевых испытаниях.
2. Реализованы ключевые защитные барьеры Stage 11: блокировка утечек на уровне ядра Linux (**Kernel Dead-Network Pinning**), обход антифрод-эвристик Cloudflare Turnstile (**Client Hints & Audio/WebGL micro-noise farbling**) и адаптивный жестовый интерфейс (**Dynamic Island UI** с динамической неоновой рамкой статуса).
3. **Решена боевая проблема биллинга:** устранён сбой `net::ERR_SOCKS_CONNECTION_FAILED` при прохождении антифрод KYC-верификации подписки Claude Pro на домене **Persona** (`withpersona.com`) и CDN платежного шлюза **Stripe** (`stripecdn.com`).
4. Подтверждена визуальная эргономика: в репозиторий добавлен каталог `screens/` с 8 реальными скриншотами боевого приложения на Samsung Galaxy S25 Ultra, а `README.md` дополнен подробной витриной интерфейса.

> [!IMPORTANT]
> **Переход в режим Final Production Readiness (Strict Zero-Refactoring):**  
> Проект выходит на финишную прямую перед релизом. Любые глобальные переписывания архитектуры, классов или библиотек исключены. От модели **Gemini Argon 4** требуется строгий, бескомпромиссный аудит на предмет **точечных микро-правок (pinpoint surgical fixes)**: краевые случаи гонок сокетов ядра, потенциальные утечки памяти/дескрипторов, тонкие несоответствия протоколов и скрытые векторы деанонимизации.

---

### 2. Проблема 1: Риск утечки трафика в открытую сеть при падении туннеля на уровне ядра Linux

#### В чём заключалась уязвимость
Ранее при получении системного коллбэка `onLost` от `ConnectivityManager` в `VpnStateMonitor.kt` вызывался стандартный метод Android Framework:
```kotlin
connectivityManager.bindProcessToNetwork(null)
```
**Угроза нулевого дня:** вызов `bindProcessToNetwork(null)` мгновенно возвращал приложение на сетевой маршрут по умолчанию (Default Network — сотовая связь 5G/LTE или незашифрованный физический Wi-Fi). Если внутренний пул соединений Chromium WebView инициировал исходящий сокет до того, как прикладной Kill-Switch разорвёт соединения, пакет успевал вылететь в открытую сеть, раскрывая реальный IP-адрес домашнего провайдера и геолокацию пользователя.

#### Как решена (Kernel Dead-Network Pinning)
Мы категорически запретили вызов `bindProcessToNetwork(null)` при отключении или падении VPN. Процесс намеренно остаётся привязанным к дескриптору уже закрытой сети туннеля (`dead network handle`). 

В результате само ядро Linux на уровне системных вызовов сокетов (`libc::connect`, `sendto`) моментально пресекает любые попытки выхода пакетов наружу с кодом ошибки `ENETUNREACH` (Network unreachable), исключая утечку данных даже при сбоях или гонках внутри Android Framework.

```kotlin
// net/VpnStateMonitor.kt

@Synchronized
private fun onVpnDisconnected() {
    val previousState = currentTunnelState
    if (previousState is VpnTunnelState.Connected) {
        currentGeneration.incrementAndGet()
        currentTunnelState = VpnTunnelState.Disconnected
        
        // Stage 11: KERNEL DEAD-NETWORK PINNING
        // ВНИМАНИЕ: connectivityManager.bindProcessToNetwork(null) НЕ вызывается!
        // Процесс остаётся привязан к недействительному дескриптору сети туннеля (dead network handle).
        // Ядро Linux пресекает 100% не-loopback пакетов с ошибкой ENETUNREACH,
        // гарантируя Fail-Closed изоляцию даже при сбоях в ОС Android.
        
        notifyListeners(VpnTunnelState.Disconnected)
    }
}
```

---

### 3. Проблема 2: Детекция антифрод-системами Cloudflare Turnstile и фингерпринтинг устройства

#### В чём заключалась проблема
1. **Отсутствие Client Hints (`navigator.userAgentData`):** Современный Turnstile проверяет совпадение между заголовком User-Agent и JavaScript-объектом `navigator.userAgentData`. В стандартном WebView данный API отсутствует или отдаёт значения, не совпадающие с мобильными заголовками Chromium.
2. **Аудио-отпечатки (`AudioContext`):** Скрипты антифрода генерируют синтетический звуковой сигнал через Web Audio API и снимают отпечаток частотной характеристики через `AudioBuffer.prototype.getChannelData`.
3. **WebGL readPixels Fingerprinting:** Тесты BrowserLeaks и антифрод запрашивают рендеринг тестовой сцены через WebGL и считывают массив байтов кадра через `readPixels()`.

#### Как решена
В `AntiFingerprintHardener.kt` внедрены три рубежа маскировки, выполняемые в `DOCUMENT_START_JS` до первого скрипта страницы:
1. **W3C Polyfill `navigator.userAgentData`:** метод `getHighEntropyValues()` отдаёт консистентные бренды `Chromium` и `Google Chrome`, платформу `Android` и точную модель устройства пользователя (`SM-S938B`) с динамической маскировкой под версию движка.
2. **AudioBuffer Micro-Noise:** перехвачен `AudioBuffer.prototype.getChannelData` с подмешиванием детерминированного микрошума `1e-7 * NOISE_OFFSET`, ломающего хэш отпечатка без слышимых искажений.
3. **WebGL readPixels Micro-Noise:** перехвачен `readPixels` в `WebGLRenderingContext` и `WebGL2RenderingContext` с зашумлением первого непрозрачного пикселя (`pixels[i] = (pixels[i] + NOISE_OFFSET) % 256`).

```javascript
// security/AntiFingerprintHardener.kt

// 7.1 AudioBuffer Micro-Noise Spoofer
try {
    if (window.AudioBuffer && AudioBuffer.prototype.getChannelData) {
        const origGetChannelData = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = cloak(function(channel) {
            const buffer = origGetChannelData.call(this, channel);
            if (buffer && buffer.length > 0) {
                buffer[0] = buffer[0] + (1e-7 * NOISE_OFFSET);
            }
            return buffer;
        }, 'getChannelData');
    }

    // 7.2 WebGL readPixels Micro-Noise
    const hookWebGLReadPixels = (proto) => {
        if (!proto || !proto.readPixels) return;
        const origReadPixels = proto.readPixels;
        proto.readPixels = cloak(function(x, y, width, height, format, type, pixels) {
            origReadPixels.call(this, x, y, width, height, format, type, pixels);
            if (pixels && pixels.length > 0) {
                for (let i = 0; i < pixels.length; i += 4) {
                    if (pixels[i + 3] > 0 || pixels.length < 4) {
                        pixels[i] = (pixels[i] + NOISE_OFFSET) % 256;
                        break;
                    }
                }
            }
        }, 'readPixels');
    };
    if (window.WebGLRenderingContext) hookWebGLReadPixels(WebGLRenderingContext.prototype);
    if (window.WebGL2RenderingContext) hookWebGLReadPixels(WebGL2RenderingContext.prototype);
} catch (e) {}

// 10.5 navigator.userAgentData Client Hints Polyfill
try {
    const ua = navigator.userAgent || '';
    const chromeMatch = ua.match(/Chrome\/([0-9]+)/);
    const chromeMajor = chromeMatch ? chromeMatch[1] : '133';

    const brands = [
        { brand: 'Not(A:Brand', version: '99' },
        { brand: 'Google Chrome', version: chromeMajor },
        { brand: 'Chromium', version: chromeMajor }
    ];

    const uad = {
        brands: brands,
        mobile: true,
        platform: 'Android',
        getHighEntropyValues: cloak(function(hints) {
            return Promise.resolve({
                brands: brands,
                mobile: true,
                platform: 'Android',
                platformVersion: '15.0.0',
                architecture: 'arm',
                model: 'SM-S938B',
                bitness: '64'
            });
        }, 'getHighEntropyValues')
    };
    Object.defineProperty(navigator, 'userAgentData', {
        get: cloak(function() { return uad; }, 'get userAgentData'),
        configurable: true
    });
} catch (e) {}
```

---

### 4. Проблема 3: Жестовое управление плавающим якорем безопасности и эргономика

#### В чём заключалась проблема
1. **Принудительное прилипание к краям (Snap-to-Edge):** якорь принудительно анимировался строго к левой или правой границе экрана, мешая взаимодействию с чатом.
2. **Скачок координат в (0,0):** при смене формы (`PILL` $\to$ `SQUARE` $\to$ `CIRCLE`) из-за пересчёта `LayoutParams` якорь на доли секунды скакал в левый верхний угол экрана.
3. **Конфликт тапов:** одиночный клик конфликтовал с двойным кликом, а тосты перекрывали контент.

#### Как решена
1. **Свободное перемещение (`clampAndSaveAnchorPosition`):** якорь свободно следует за пальцем в любую точку экрана и сохраняет координаты в `SharedPreferences` с безопасными отступами (4dp).
2. **Устранение скачка координат:** кэширование координат `prevX`/`prevY` перед сменой формы + `TransitionManager.beginDelayedTransition`.
3. **Динамическая статусная граница (Dynamic Border):** неоновая рамка якоря окрашивается в реальном времени под статус туннеля (🟢 `#554ADE80` защищено, 🟡 `#88FBBF24` задержка/Doze, 🔴 `#99F87171` заблокировано ядром).
4. **Горизонтальный жест (Fling / Swipe):** быстрое горизонтальное смахивание переключает форму якоря. Дебаунсинг одиночного тапа сокращён до **170 мс**.

---

### 5. Проблема 4: Перегруженность панели статуса и меню диагностики

#### В чём заключалась проблема
- В верхней панели находилось слишком много кнопок, создавая визуальный шум на мобильном экране.
- В диалоге диагностики кнопки управления располагались в самом низу длинного списка, требуя постоянного скроллинга.

#### Как решена
- **Стилизация кнопок-пилюль:** кнопки стилизованы `@drawable/bg_topbar_btn_pill` с радиусом 8dp. Избыточные кнопки скрыты (клик по тексту статуса открывает диагностику).
- **2-Колоночная сетка быстрых действий (Action Grid 6x2):** 12 действий вынесены в самый верх диалога над информационными карточками:
  `[ 🔄 Обновить ]` & `[ 👤 Аккаунты ]`  
  `[ 📋 Копировать ]` & `[ 📤 Поделиться ]`  
  `[ 🧪 BrowserLeaks ]` & `[ 🧹 Сброс логов ]`  
  `[ ⤡ Панель мини ]` & `[ 🎛️ Форма якоря ]`  
  `[ 🛡️ Recents: ВКЛ/ВЫКЛ ]` & `[ 🎨 Иконка ]`  
  `[ 📦 Версии ]` & `[ 🌐 Язык: RU/EN ]`  

---

### 6. Проблема 5: Блокировка KYC-верификации подписки Claude Pro (Persona) и CDN Stripe

#### Инцидент из production-логов (`logs_from_app/log28.09.2026.txt`)
При попытке пользователя оплатить подписку Claude Pro на реальном устройстве Samsung S25 Ultra в WebView отобразилась критическая ошибка:
```text
Webpage not available: https://withpersona.com/verify?inquiry-id=inq_AqWNSC51AptQfzTjKenvj5qRX8tu64&session-token=...
net::ERR_SOCKS_CONNECTION_FAILED
```

В аудит-логе шлюза зафиксированы блокировки:
```text
[2026-10-28T14:58:45.713Z][SECURITY][BLOCK] Blocked non-allowlisted destination domain: b.stripecdn.com
[2026-10-28T15:00:14.179Z][SECURITY][BLOCK] Blocked non-allowlisted destination domain: b.stripecdn.com
[2026-10-28T15:04:28.382Z][SECURITY][BLOCK] Blocked non-allowlisted destination domain: withpersona.com
```

#### Причина
Anthropic Claude и платёжный шлюз Stripe для подтверждения личности плательщика и противодействия кардингу запускают сессию KYC-верификации через сторонний сервис **Persona** (`withpersona.com`), а также подгружают статические ресурсы с CDN `b.stripecdn.com`. Поскольку домены `withpersona.com` и `stripecdn.com` отсутствовали в белом списке `ALLOWED_DOMAIN_SUFFIXES`, внутренний шлюз `VpnGatekeeperProxy` немедленно отклонял TCP-запрос кодом SOCKS5 `0x05 (Connection Refused)`, который Chromium WebView транслировал в ошибку `net::ERR_SOCKS_CONNECTION_FAILED`.

#### Реализованное решение
1. **Расширение белого списка до 27 доверенных доменов ([`VpnGatekeeperProxy.kt`](file:///home/milk13/IdeaProjects/ClaudeCageAnd/app/src/main/java/com/example/claudecageand/net/VpnGatekeeperProxy.kt)):**
   ```kotlin
   val ALLOWED_DOMAIN_SUFFIXES = setOf(
       "claude.ai",
       "anthropic.com",
       "claude.com",
       "cloudflare.com",
       "hcaptcha.com",
       "stripe.com",
       "stripe.network",
       "stripecdn.com",      // NEW: Stripe CDN & Hosted Checkout assets
       "withpersona.com",    // NEW: Persona KYC Identity Verification
       "persona.com",        // NEW: Persona root & redirects
       "intercom.io",
       "intercomcdn.com",
       "statsig.com",
       "statsigapi.net",
       "datadoghq.com",
       "sentry.io",
       "google.com",
       "gstatic.com",
       "googleapis.com",
       "googleusercontent.com",
       "youtube.com",
       "apple.com",
       "appleid.apple.com",
       "browserleaks.com",
       "browserleaks.net",
       "browserleaks.org",
       "ripe.net"
   )
   ```
2. **Автоматическая кнопка возврата в Claude ([`MainActivity.kt`](file:///home/milk13/IdeaProjects/ClaudeCageAnd/app/src/main/java/com/example/claudecageand/MainActivity.kt)):**
   В коллбэках `onPageFinished` и `doUpdateVisitedHistory` активируется кнопка `btnReturnToClaude` («⬅️ Вернуться в Claude»), если пользователь перешёл на страницы `withpersona.com`, `persona.com` или `stripe.com`. При завершении или отмене и возврате на `claude.ai` кнопка автоматически исчезает.
3. **Юнит-тесты ([`VpnGatekeeperProxyTest.kt`](file:///home/milk13/IdeaProjects/ClaudeCageAnd/app/src/test/java/com/example/claudecageand/net/VpnGatekeeperProxyTest.kt)):**
   Добавлены проверки на пропуск доменов `b.stripecdn.com`, `withpersona.com`, `inquiry.withpersona.com`, `cdn.withpersona.com`.

---

### 7. Визуальная верификация интерфейса и Скриншоты с физического устройства

В репозиторий добавлен каталог [`screens/`](file:///home/milk13/IdeaProjects/ClaudeCageAnd/screens) с 8 реальными скриншотами боевого приложения на Samsung Galaxy S25 Ultra:
- **`main_interface.jpg`** — Главный экран защищённого веб-интерфейса Claude.ai, развернутая статусная панель с индикатором туннеля и переключателем аккаунтов.
- **`diagnostics_grid.jpg`** — Диалог «Панель Безопасности и Диагностики» с 2-колоночной сеткой быстрых действий (12 кнопок) в самом верху и карточкой версий Stage 11.
- **`telemetry_cards.jpg`** — Карточки Zero-Leak телеметрии: Fail-Closed TCP DNS (1.1.1.1/8.8.8.8, 0 ошибок, кэш), Anti-Fingerprint (Europe/Amsterdam, en-US, WebRTC выключен, IPv6 заблокирован), Multi-Profile (AndroidX ProfileStore).
- **`account_manager.jpg`** — Диалог управления профилями сессий: переключение между JavaProton и JavaGmail, добавление аккаунта, комплексная очистка сессии.
- **`topbar_standard.jpg`** — Верхняя панель в стандартном режиме (высота 42dp).
- **`topbar_slim.jpg`** — Верхняя панель в ультратонком режиме (высота 26dp): минималистичный индикатор `tun0 • 127.0.0.1:<port>`.
- **`floating_anchor_pill.jpg`** — Плавающий якорь безопасности в форме «Капсула» (Pill) со статусом и именем профиля.
- **`floating_anchor_circle.jpg`** — Плавающий якорь в форме «Круг» (Circle, 34x34dp) со статусной точкой по центру и неоновой рамкой.

Все скриншоты встроены в обновленный [`README.md`](file:///home/milk13/IdeaProjects/ClaudeCageAnd/README.md).

---

### 8. Результаты верификации и итоговый бинарник

1. **Модульное тестирование (`./gradlew testDebugUnitTest`):**
   - **Результат:** `BUILD SUCCESSFUL`
   - **Выполнено тестов:** **64 из 64 тестов пройдены успешно (100%, 0 сбоев)**.
   - Тестовый набор покрывает:
     - `VpnGatekeeperProxyTest` (8 тестов): SOCKS5 no-auth, блокировка при падении VPN, блокировка IPv6 (0x08), блокировка RFC 1918 / Loopback, Destination Allowlist (27 доменов, Turnstile, hCaptcha, Stripe, Persona), Smart WakeLock traffic window.
     - `TunnelDnsResolverTest` (11 тестов): RFC 1035 TCP-фрейминг, Scheduled Watchdog timeout, Single-Flight дедупликация, True SWR кэш, QNAME валидация, Transaction ID рандомизация.
     - `AntiFingerprintHardenerTest` (16 тестов): WebRTC kill-switch, offscreen Canvas farbling, toString cloaking, TTS ампутация, Client Hints `navigator.userAgentData`, AudioBuffer & WebGL micro-noise.
     - `ClaudeCageNotificationBridgeTest` (10 тестов): Zero-Trust origin check, блокировка subdomain-спуфинга, W3C polyfill.
     - `AccountProfileManagerTest` (6 тестов), `SecurityAuditLoggerTest` (3 теста), `UiStringsAndLanguageTest` (6 тестов), `AppIconManagerTest` (2 теста), `VpnTunnelStateTest` (2 теста).
2. **Артефакт сборки (`./gradlew assembleDebug copyApkToRoot`):**
   - Собран файл: [**`ClaudeCage-1.4.apk`**](file:///home/milk13/IdeaProjects/ClaudeCageAnd/ClaudeCage-1.4.apk) (`versionCode = 5`, `versionName = "1.4"`, размер ~12.9 МБ).
   - Расположен в корне репозитория для прямой установки через ADB.

---

### 9. Техническое Задание и Контрольные Вопросы для Аудита Моделью Gemini Argon 4

Уважаемый **Gemini Argon 4**, проект выходит на финальную стадию готовности к релизу.  
Пожалуйста, проведи глубокий архитектурный аудит всей системы ClaudeCage и ответь на следующие контрольные вопросы. 

**Важное требование к ревью:**  
Архитектура зафиксирована. **Не предлагай глобальных переписываний, смены библиотек или масштабных рефакторингов.** Сфокусируйся исключительно на **точечных микро-правках (pinpoint surgical fixes)**, способных предотвратить реальные сбои в продакшене.

#### 1. Сетевой уровень и Kernel Dead-Network Pinning
* Корректно ли ядро Linux на One UI 9 / Android 17 обрабатывает удержание мертвого дескриптора сети туннеля без вызова `bindProcessToNetwork(null)`? Существуют ли условия гонки при быстром переподключении VPN (handover `tun0` $\to$ `tun1`), когда старый сокет может пережить смену поколения?
* Достаточен ли размер пула потоков `relayExecutor = Executors.newCachedThreadPool()` для исключения исчерпания памяти (OOM) при экстремальной нагрузке?

#### 2. Белый список доменов (27 доменов) и Утечки через CDN
* Обеспечивает ли белый список из 27 доменов (`claude.ai`, `anthropic.com`, `withpersona.com`, `persona.com`, `stripecdn.com` и др.) строгую изоляцию? Нет ли риска эксфильтрации данных или обхода прокси через разрешенные поддомены Google/Apple/Persona?
* Требуются ли дополнительные поддомены для корректного завершения процесса оплаты и KYC в Claude Pro?

#### 3. Антифрод, Стелс-маскировка и Canvas Farbling
* Является ли реализация `navigator.userAgentData` в Document-Start JS достаточной для полного удовлетворения строгих проверок Cloudflare Turnstile на Android 17?
* Нет ли риска детекции оффскрин-шума Canvas или WebGL `readPixels` через повторные вызовы одного и того же контекста в рамках одной веб-сессии?

#### 4. Жизненный цикл процесса, Doze Mode и Фоновый стриминг
* Гарантирует ли предикат `hasRecentTraffic(15_000L)` в связке с `PARTIAL_WAKE_LOCK` бесперебойную генерацию длинных ответов Claude при выключенном экране телефона без паразитной разрядки батареи в режиме покоя?

#### 5. Итоговый вердикт и Список точечных правок
* Сформулируй итоговый вердикт готовности системы к релизу.
* Приведи конкретный, минимальный список точечных правок (diff / pinpoint fixes), если обнаружены потенциальные уязвимости или баги.

---

### 10. Реализация Рекомендаций Аудита Gemini Argon 4 и Релиз v1.5 (Build 6)

По результатам аудита моделью **Gemini Argon 4**, архитектура ClaudeCage была признана **полностью готовой к релизу (Production Ready)**, с предписанием 4 точечных хирургических правок, которые были незамедлительно и строго реализованы:

1. **Хирургическая правка 1 (WeakSet Idempotency в `AntiFingerprintHardener.kt`):**
   - Для предотвращения кумулятивного искажения `buffer[0]` при повторных вызовах `AudioBuffer.prototype.getChannelData` внедрен учет модифицированных буферов через `const noisyAudioBuffers = new WeakSet()`.
2. **Хирургическая правка 2 (Метка $currentShapeName и свободное перемещение якоря в `MainActivity.kt`):**
   - В кнопке смены формы `btnShape` в диалоге диагностики внедрена интерполяция `$currentShapeName` для обоих языков (`🎛️ Форма: $currentShapeName` / `🎛️ Shape: $currentShapeName`).
   - Сохранено свободное позиционирование якоря (`clampAndSaveAnchorPosition`) с безопасным отступом 4dp без принудительного прилипания к краям экрана.
3. **Хирургическая правка 3 (Ограничение пула `relayExecutor` и добавление `stripe.link` в `VpnGatekeeperProxy.kt`):**
   - Неограниченный `Executors.newCachedThreadPool()` заменен на `ThreadPoolExecutor(4, 128, 60L, TimeUnit.SECONDS, SynchronousQueue())` с потоками-демонами для гарантированной защиты от исчерпания памяти при экстремальных штормах сокетов.
   - В `ALLOWED_DOMAIN_SUFFIXES` добавлен домен `stripe.link` (суммарно 28 доменов), устраняющий сбои при 1-click оплате подписки Claude Pro.
4. **Хирургическая правка 4 (Синхронизация версии и выпуск релиза 1.5):**
   - В `SecurityAuditLogger.generateMarkdownReport()` строка обновлена до: `ClaudeCage v1.5 (Build 6) • Stage 11: Final Production Readiness & Zero-Leak Kernel Lock`.
   - В `app/build.gradle.kts` установлены `versionCode = 6`, `versionName = "1.5"`.
   - Прогон тестов: **64 из 64 тестов пройдены успешно (100%)**.
   - Собран финальный релизный бинарник: **`ClaudeCage-1.5.apk`**.

---
*Документ актуализирован по итогам финального аудита безопасности Gemini Argon 4 и релиза v1.5 (Build 6).*
