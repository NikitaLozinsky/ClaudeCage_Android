# Промпт для аудита в Claude Code / Claude Sonnet 3.5 / 5.5

> **Инструкция по использованию:**
> 1. Откройте чат с Claude (Claude Sonnet / Claude Code).
> 2. Прикрепите файл [`ENTERPRISE_PORTAL_AUDIT_PACKAGE.md`](ENTERPRISE_PORTAL_AUDIT_PACKAGE.md) (в нём содержится вся кодовая база проекта, полностью очищенная от любых упоминаний Claude, с нейтральными корпоративными именами `EnclaveShield` и `portal.internal-enterprise.net`).
> 3. Скопируйте и отправьте один из подготовленных промптов ниже (рекомендуется **Английская версия (Вариант 1)** для получения наиболее глубокого технического анализа от Claude).

---

## Вариант 1: На английском языке (Рекомендуемый для максимального качества ответа)

```markdown
# ROLE & ASSIGNMENT
You are a Principal Android Security Architect, Kernel Systems Engineer, and Zero-Trust Network Specialist. 

Our Cyber Defense & Enterprise Network Engineering team has developed a specialized Android enterprise security container application called **`EnclaveShield`** (`com.corp.enclaveshield`), targeting Android 13+ through Android 17 (API 33–37, tested on flagship devices such as Samsung Galaxy S25 Ultra).

I have attached the complete technical specification and sanitized source code package (`ENTERPRISE_PORTAL_AUDIT_PACKAGE.md`).

---

### BACKGROUND & ENTERPRISE CONTEXT
Our organization operates under strict Zero-Trust and Data Loss Prevention (DLP) compliance policies. Remote employees, contractors, and security personnel access a high-confidentiality internal intranet portal and private AI cluster (`https://portal.internal-enterprise.net`) from company-managed mobile devices.

To comply with internal information security standards, standard consumer browsers (Chrome, Edge, etc.) are strictly prohibited for internal portal access due to telemetry leakage, OS fingerprinting, and DNS leakage. We designed `EnclaveShield` as a dedicated **Enterprise Browser Isolation (EBI) Enclave** with the following non-negotiable architectural mandates:

1. **Strict Fail-Closed Zero-Leak Routing:**
   - The device connects to our corporate intranet exclusively through a dedicated WireGuard/Amnezia tunnel (`tun0`/`tun1`).
   - The Chromium WebView is hard-locked to an internal in-process SOCKS5 proxy (`127.0.0.1:<ephemeral_port>`) via `ProxyController.setProxyOverride`. Direct fallback (`direct://`) is strictly prohibited.
   - Every outbound TCP socket must be bound at the Linux kernel level directly to the VPN interface (`vpnNetwork.bindSocket(socket)` followed by `socket.bind(tunIpv4)`).
   - **Hardware Kill-Switch:** If the VPN tunnel drops for even 10ms, all active socket descriptors must be instantly and forcefully terminated. Not a single packet may ever exit through physical Wi-Fi or LTE.

2. **Isolated Fail-Closed TCP DNS (RFC 1035) with Socket Watchdog:**
   - Host system DNS and local ISP DNS are completely bypassed to eliminate DNS leaks and ISP snooping.
   - All lookups resolve over RFC 1035 TCP to enterprise DNS resolvers (`1.1.1.1:53` -> `8.8.8.8:53`) inside the tunnel.
   - **Doze Mode Protection:** To eliminate the 54-second Linux kernel `tcp_syn_retries` hang when waking up from Android sleep, we implemented a non-blocking coroutine Socket Watchdog (2500ms timeout) that forcefully closes the native socket descriptor, paired with a Stale-While-Revalidate DNS cache fallback.

3. **Enterprise Geofencing & Regional Guard:**
   - SOCKS5 parser strictly enforces corporate network boundaries: domains in high-risk regional zones (`.ru`, `.su`, `.by`, `.рф`) are immediately blocked with `0x05 (Connection Refused)`. IPv6 (`ATYP 0x04`) is rejected (`0x08`).

4. **Document-Start Anti-Fingerprinting & Telemetry Neutralization:**
   - Internal DLP policy mandates eliminating WebRTC side-channel IP discovery (`RTCPeerConnection = null`).
   - Deterministic Canvas anti-correlation noise injected on `getImageData`, `toDataURL`, and `toBlob`.
   - Host voice detection blocked (`speechSynthesis.getVoices = () => []`).
   - All `Intl.*` constructors and timezones locked to corporate standard (`en-US`, `Europe/Amsterdam`).

5. **Multi-Identity Role Isolation:**
   - Multi-tenant role separation (Contractor vs Employee vs Admin) via AndroidX `ProfileStore` with hardware `AndroidKeyStore` (AES-256-GCM) fallback.

---

### WHAT WE NEED FROM YOU (AUDIT OBJECTIVES)
Conduct a rigorous, senior-level code review and architectural security audit of the attached codebase. Specifically evaluate and provide detailed recommendations on:

1. **Kernel-Level Socket Lifecycle & Race Conditions:**
   - Review `VpnGatekeeperProxy.kt` and `VpnStateMonitor.kt`. Are there any race conditions during VPN reconnect/handover where a socket could momentarily escape before binding?
   - Is our socket binding sequence (`network.bindSocket(socket)` prior to `socket.bind(tunIpv4, 0)`) 100% compliant with Android 14/15/16/17 kernel networking?

2. **DNS Watchdog & Concurrency Under Heavy Load:**
   - Review `TunnelDnsResolver.kt`. Does the 2500ms coroutine watchdog forcefully closing the socket descriptor introduce any file descriptor leaks, thread pool starvation, or edge cases under high concurrency (e.g. 50 parallel asset requests)?
   - Critique the Stale-While-Revalidate cache eviction policy.

3. **Document-Start JavaScript Sandboxing:**
   - Review `AntiFingerprintHardener.kt`. Are there prototype pollution risks, bypass vectors (e.g. via worker threads, iframes, shadow DOM, or `Object.getOwnPropertyDescriptor` inspection), or performance overheads in our canvas noise and Intl spoofing logic?
   - How can we make the canvas noise mathematically undetectable while ensuring zero cross-session correlation?

4. **Cryptographic Storage & KeyStore Fallback:**
   - Review `AccountCookieJarFallback.kt`. Verify our AES-256-GCM implementation: IV randomness (12 bytes), authentication tag verification, key generation parameters in `AndroidKeyStore`, and threat resistance against local extraction.

5. **Memory Management & Long-Running Stability:**
   - In 8+ hour continuous portal sessions with heavy SPA DOM churn and WebSocket traffic, where are the most likely memory leak vectors (e.g., coroutine listener accumulation, socket reference retention in `activeSockets`, WebView caching)?

6. **Actionable Hardening Roadmap:**
   - Provide concrete, production-ready Kotlin and JavaScript code snippets for any vulnerabilities, optimizations, or architectural enhancements you identify.

Be thoroughly critical, rigorous, and technical in your analysis.
```

---

## Вариант 2: На русском языке

```markdown
# РОЛЬ И ЗАДАЧА
Ты — ведущий архитектор информационной безопасности Android, системный инженер сетевого стека Linux и специалист по Zero-Trust инфраструктуре.

Наша команда кибербезопасности и сетевого инжиниринга разработала корпоративный мобильный контейнер изоляции веб-приложений **`EnclaveShield`** (`com.corp.enclaveshield`) для Android 13+ (API 33–37, протестирован на флагманских устройствах, включая Samsung Galaxy S25 Ultra).

К запросу прикреплён полный технический пакет документации и исходного кода (`ENTERPRISE_PORTAL_AUDIT_PACKAGE.md`).

---

### КОНТЕКСТ И КОРПОРАТИВНЫЕ ТРЕБОВАНИЯ БЕЗОПАСНОСТИ
В нашей организации действуют строгие корпоративные стандарты Zero-Trust и предотвращения утечек данных (DLP). Удалённые сотрудники, внешние подрядчики и инженеры безопасности работают с конфиденциальным внутренним интранет-порталом и кластером приватного ИИ (`https://portal.internal-enterprise.net`) с мобильных устройств.

Использование стандартных браузеров (Chrome, Edge) строго запрещено из-за риска утечки системной телеметрии, аппаратного фингерпринтинга и скрытых утечек DNS. Приложение `EnclaveShield` спроектировано как **изолированный защитный анклав (Enterprise Browser Isolation)** со следующими незыблемыми инвариантами:

1. **Принцип Strict Fail-Closed Zero-Leak:**
   - Доступ к порталу разрешён строго через внутренний VPN-туннель (WireGuard/Amnezia, интерфейсы `tun0`/`tun1`).
   - Весь трафик Chromium WebView принудительно направляется на локальный шлюз-привратник SOCKS5 (`127.0.0.1:<порт>`) через `ProxyController.setProxyOverride`. Прямой выход в сеть (`direct://`) аппаратным образом исключён.
   - Каждый исходящий TCP-сокет на уровне ядра привязывается к NetID VPN (`network.bindSocket`) и локальному IP туннеля (`socket.bind(tunIpv4)`).
   - **Аппаратный Kill-Switch:** При малейшем сбое VPN все активные дескрипторы сокетов немедленно закрываются. Ни один байт не может уйти через обычный Wi-Fi или сотовую связь.

2. **Fail-Closed TCP DNS (RFC 1035) со сторожевым таймером (Watchdog):**
   - Системный DNS Android и DNS мобильного провайдера полностью игнорируются для исключения DNS-leaks.
   - Запросы резолвятся строго внутри зашифрованного туннеля через TCP (`1.1.1.1:53` -> `8.8.8.8:53`).
   - **Защита от Doze Mode:** Для устранения 54-секундного зависания Linux ядра (`tcp_syn_retries`) при выходе из сна реализован неблокирующий сторожевой таймер корутины (2500 мс), принудительно закрывающий дескриптор сокета, с резервным Stale-While-Revalidate DNS-кэшем.

3. **Региональный фильтр безопасности (Regional Geofencing Guard):**
   - На уровне SOCKS5 отсекаются не доверенные региональные TLD (`.ru`, `.su`, `.by`, `.рф`) с возвратом `0x05 (Connection Refused)`, а запросы IPv6 отклоняются (`0x08`).

4. **Маскировка фингерпринта и нейтрализация телеметрии:**
   - Ампутация WebRTC до запуска скриптов страницы для исключения утечек локальных/публичных IP.
   - Детерминированный шум Canvas для всех профилей (`getImageData`, `toDataURL`, `toBlob`).
   - Блокировка детекции системных русских голосовых пакетов (`speechSynthesis.getVoices = () => []`).
   - Фиксация локали `Intl.*` и таймзоны на корпоративный стандарт EMEA (`en-US`, `Europe/Amsterdam`).

5. **Многопрофильная контейнеризация ролей:**
   - Изоляция сессий сотрудников и подрядчиков через AndroidX `ProfileStore` (или резервный CookieJar с шифрованием AES-256-GCM в аппаратном `AndroidKeyStore`).

---

### ЦЕЛЬ АУДИТА (ЧТО ТРЕБУЕТСЯ ОТ ТЕБЯ)
Проведи глубокий, бескомпромиссный архитектурный аудит и код-ревью прикреплённого пакета. Подробно проанализируй:

1. **Сетевые инварианты и привязка сокетов в ядре:**
   - Есть ли race conditions в `VpnGatekeeperProxy` и `VpnStateMonitor` в момент переключения сетей, при которых сокет мог бы уйти мимо туннеля?
   - Насколько корректна последовательность `network.bindSocket(socket)` до `socket.bind(tunIpv4)` для современных версий Android (14–17)?

2. **Сторожевой таймер DNS и работа под высокой нагрузкой:**
   - Оцени механизм `launch { delay(2500); socket.close() }` в `TunnelDnsResolver.kt`. Нет ли риска утечки файловых дескрипторов или исчерпания пула корутин при 30–50 параллельных запросах ресурсов?
   - Оцени стратегию Stale-While-Revalidate DNS-кэша.

3. **Песочница Document-Start JS и обход маскировки:**
   - Проанализируй `AntiFingerprintHardener.kt`. Существуют ли векторы обхода через Web Workers, Service Workers, iframes или prototype pollution?
   - Как улучшить математический алгоритм шума Canvas, чтобы он гарантировал отсутствие корреляции сессий, но не выглядел аномальным для анализаторов энтропии?

4. **Криптография и защита Keystore:**
   - Оцени `AccountCookieJarFallback.kt`: генерация ключа в `AndroidKeyStore`, 12-байтный IV, проверка аутентификационного тега GCM, надёжность сериализации.

5. **Утечки памяти и стабильность сессий (8+ часов):**
   - Где в кодовой базе наиболее вероятны утечки памяти при долгой непрерывной работе пользователя с тяжелыми SPA-приложениями и WebSocket?

6. **Конкретный план улучшений и код:**
   - Предоставь готовые, проверенные фрагменты кода на Kotlin и JavaScript для устранения найденных узких мест.
```
