package com.example.claudecageand.telemetry

import android.content.Context
import android.os.Build
import android.system.Os
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

enum class LogCategory {
    VPN,
    KILLSWITCH,
    PROXY,
    DNS,
    WEBVIEW,
    SECURITY
}

enum class LogLevel {
    INFO,
    WARN,
    BLOCK,
    ERROR
}

data class LogEntry(
    val timestampIso: String,
    val elapsedMs: Long,
    val category: LogCategory,
    val level: LogLevel,
    val message: String
) {
    val tag: String get() = category.name

    override fun toString(): String {
        return "[$timestampIso][+${elapsedMs}ms][$category][$level] $message"
    }
}

data class DnsStats(
    val totalQueries: Long,
    val cacheHits: Long,
    val resolveErrors: Long,
    val averageLatencyMs: Long,
    val cacheEntries: Long
)

data class TelemetrySnapshot(
    val connectionsAccepted: Long,
    val connectionsRejected: Long,
    val connectionsKilled: Long
)

/**
 * Thread-safe audit logger and telemetry tracker for ClaudeCageAnd.
 *
 * Collects runtime metrics, maintains a 500-entry in-memory ring buffer,
 * logs asynchronously to a rotating log file, and generates self-contained
 * Markdown audit reports for AI security review.
 */
class SecurityAuditLogger(context: Context) {

    private val appContext = context.applicationContext
    val appStartTimeMillis: Long = System.currentTimeMillis()

    // --- Runtime Metric Counters ---
    val vpnConnectCount = AtomicLong(0)
    val vpnDisconnectCount = AtomicLong(0)
    val totalSocksRequests = AtomicLong(0)
    val successfulConnections = AtomicLong(0)
    val activeSocketsCount = AtomicInteger(0)
    val consecutiveNetworkTimeouts = AtomicInteger(0)
    val blockedVpnOffCount = AtomicLong(0)
    val blockedIpv6Count = AtomicLong(0)
    val forceClosedSocketsCount = AtomicLong(0)

    val dnsQueriesTotal = AtomicLong(0)
    val dnsCacheHits = AtomicLong(0)
    val dnsNetworkLookups = AtomicLong(0)
    val dnsFailures = AtomicLong(0)
    val dnsCacheEntries = AtomicLong(0)
    val lastDnsLatencyMs = AtomicLong(0)
    val maxDnsLatencyMs = AtomicLong(0)

    val totalBytesSent = AtomicLong(0)
    val totalBytesReceived = AtomicLong(0)

    @Volatile
    var isProxyOverrideActive: Boolean = false

    @Volatile
    var isDocumentStartJsActive: Boolean = false

    // --- In-Memory Ring Buffer (500 entries) ---
    private val bufferLock = Any()
    private val ringBuffer = ArrayDeque<LogEntry>(MAX_RING_BUFFER_ENTRIES)

    // --- Asynchronous File Appender ---
    private val logScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val logChannel = Channel<LogEntry>(Channel.UNLIMITED)
    private val logFile = File(appContext.filesDir, LOG_FILE_NAME)

    init {
        logScope.launch {
            for (entry in logChannel) {
                appendToFile(entry)
            }
        }
    }

    /**
     * Records a structured security/telemetry log entry.
     * Enforces privacy: NEVER include tokens, cookies, or chat messages in [message].
     */
    fun log(category: LogCategory, level: LogLevel, message: String) {
        val now = System.currentTimeMillis()
        val elapsed = now - appStartTimeMillis
        val isoTimestamp = formatIsoUtc(now)
        val entry = LogEntry(isoTimestamp, elapsed, category, level, message)

        // Log to Android logcat
        when (level) {
            LogLevel.INFO -> Log.i(TAG, "[$category] $message")
            LogLevel.WARN -> Log.w(TAG, "[$category] $message")
            LogLevel.BLOCK -> Log.w(TAG, "[BLOCK][$category] $message")
            LogLevel.ERROR -> Log.e(TAG, "[$category] $message")
        }

        // Store in memory ring buffer
        synchronized(bufferLock) {
            if (ringBuffer.size >= MAX_RING_BUFFER_ENTRIES) {
                ringBuffer.removeFirst()
            }
            ringBuffer.addLast(entry)
        }

        // Dispatch for file logging
        logChannel.trySend(entry)
    }

    fun logInfo(category: String, message: String) = log(parseCategory(category), LogLevel.INFO, message)
    fun logWarning(category: String, message: String) = log(parseCategory(category), LogLevel.WARN, message)
    fun logCritical(category: String, message: String) = log(parseCategory(category), LogLevel.ERROR, message)
    fun logBlock(category: String, message: String) = log(parseCategory(category), LogLevel.BLOCK, message)

    private fun parseCategory(name: String): LogCategory = try {
        LogCategory.valueOf(name.uppercase(Locale.US))
    } catch (_: Exception) {
        LogCategory.SECURITY
    }

    /**
     * Returns a snapshot copy of the in-memory ring buffer (up to [limit] recent entries).
     */
    fun getRecentLogs(limit: Int = 30): List<LogEntry> {
        synchronized(bufferLock) {
            return ringBuffer.toList().takeLast(limit)
        }
    }

    /**
     * Clears all in-memory ring buffer entries and truncates the persistent log file.
     */
    fun clearLogs() {
        synchronized(bufferLock) {
            ringBuffer.clear()
        }
        logScope.launch {
            runCatching {
                if (logFile.exists()) {
                    logFile.writeText("")
                }
            }
        }
        log(LogCategory.SECURITY, LogLevel.INFO, "Audit logs cleared by user request")
    }

    fun clearAllLogs() = clearLogs()

    fun getDnsStats(): DnsStats {
        return DnsStats(
            totalQueries = dnsQueriesTotal.get(),
            cacheHits = dnsCacheHits.get(),
            resolveErrors = dnsFailures.get(),
            averageLatencyMs = lastDnsLatencyMs.get(),
            cacheEntries = dnsCacheEntries.get()
        )
    }

    fun getSnapshot(): TelemetrySnapshot {
        return TelemetrySnapshot(
            connectionsAccepted = successfulConnections.get(),
            connectionsRejected = blockedVpnOffCount.get() + blockedIpv6Count.get(),
            connectionsKilled = forceClosedSocketsCount.get()
        )
    }

    fun generateMarkdownAuditReport(tunnelState: Any? = null, proxyPort: Int? = null): String {
        return generateMarkdownReport(tunnelState, proxyPort)
    }

    /**
     * Updates max DNS latency if [latencyMs] exceeds current maximum.
     */
    fun recordDnsLatency(latencyMs: Long) {
        lastDnsLatencyMs.set(latencyMs)
        var currentMax = maxDnsLatencyMs.get()
        while (latencyMs > currentMax) {
            if (maxDnsLatencyMs.compareAndSet(currentMax, latencyMs)) {
                break
            }
            currentMax = maxDnsLatencyMs.get()
        }
    }

    /**
     * Generates a self-contained Markdown report suitable for pasting to AI assistants
     * (e.g. Gemini Argon 4) for automated security and network invariant verification.
     */
    fun generateMarkdownReport(tunnelState: Any? = null, proxyPort: Int? = null): String {
        val now = System.currentTimeMillis()
        val uptimeSeconds = (now - appStartTimeMillis) / 1000

        val posixTz = runCatching { Os.getenv("TZ") }.getOrNull() ?: "UNKNOWN"
        val jvmTz = TimeZone.getDefault().id
        val jvmLocale = Locale.getDefault().toLanguageTag()

        val recentLogsSnapshot: List<LogEntry> = synchronized(bufferLock) {
            ringBuffer.toList()
        }

        val sb = StringBuilder()
        sb.appendLine("# ClaudeCage Telemetry & Security Audit Report")
        sb.appendLine("Generated at: `${formatIsoUtc(now)}` (Uptime: `${uptimeSeconds}s`)")
        sb.appendLine()

        sb.appendLine("## 1. Device & OS Environment")
        sb.appendLine("- **App & Hardening:** `ClaudeCage v1.1 (Build 2) • Stage 10: Zero-Trust Hardening & Code Review Remediation`")
        sb.appendLine("- **Device:** `${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})`")
        sb.appendLine("- **Android Version:** `Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})`")
        sb.appendLine("- **Target SDK:** `API 36`, **Min SDK:** `API 33`")
        if (tunnelState != null) {
            sb.appendLine("- **Active Tunnel State:** `$tunnelState`")
        }
        if (proxyPort != null) {
            sb.appendLine("- **SOCKS5 Proxy Loopback Port:** `127.0.0.1:$proxyPort`")
        }
        sb.appendLine()

        sb.appendLine("## 2. Security Invariant Self-Checks")
        sb.appendLine("| Security Invariant | Expected Value | Runtime Observed | Status |")
        sb.appendLine("| :--- | :--- | :--- | :--- |")

        val tzMatch = (posixTz == "Europe/Amsterdam" && jvmTz == "Europe/Amsterdam")
        sb.appendLine("| **POSIX / JVM TimeZone** | `Europe/Amsterdam` | POSIX: `$posixTz` / JVM: `$jvmTz` | ${if (tzMatch) "✅ SECURE" else "❌ LEAK RISK"} |")

        val localeMatch = (jvmLocale == "en-US" || jvmLocale.startsWith("en"))
        sb.appendLine("| **JVM Locale** | `en-US` | `$jvmLocale` | ${if (localeMatch) "✅ SECURE" else "❌ LEAK RISK"} |")

        sb.appendLine("| **ProxyController Lock** | `Active (127.0.0.1:<port>)` | `${if (isProxyOverrideActive) "Active (No Fallback)" else "Inactive"}` | ${if (isProxyOverrideActive) "✅ SECURE" else "❌ UNPROTECTED"} |")
        sb.appendLine("| **WebRTC / Document-Start JS** | `Active` | `${if (isDocumentStartJsActive) "Injected" else "Missing"}` | ${if (isDocumentStartJsActive) "✅ SECURE" else "❌ UNPROTECTED"} |")
        sb.appendLine()

        sb.appendLine("## 3. Network & Gatekeeper Telemetry Metrics")
        sb.appendLine("| Metric | Value | Description |")
        sb.appendLine("| :--- | :--- | :--- |")
        sb.appendLine("| **VPN Connect Count** | `${vpnConnectCount.get()}` | Number of times active VPN tunnel was detected |")
        sb.appendLine("| **VPN Disconnect Count** | `${vpnDisconnectCount.get()}` | Number of VPN drop / lost events |")
        sb.appendLine("| **Total SOCKS5 Requests** | `${totalSocksRequests.get()}` | Total connection requests handled by proxy |")
        sb.appendLine("| **Successful Outbound Connects** | `${successfulConnections.get()}` | Connections established through `tun*` source IP |")
        sb.appendLine("| **Blocked (VPN Off / Disconnected)** | `${blockedVpnOffCount.get()}` | Connections refused because VPN was inactive |")
        sb.appendLine("| **Blocked IPv6 Requests** | `${blockedIpv6Count.get()}` | IPv6 (ATYP 0x04) requests rejected with 0x08 |")
        sb.appendLine("| **Force-Closed Sockets** | `${forceClosedSocketsCount.get()}` | Sockets terminated mid-stream on VPN drop |")
        sb.appendLine("| **Active Sockets in Pool** | `${activeSocketsCount.get()}` | Currently open client / remote sockets |")
        sb.appendLine("| **DNS Queries Total** | `${dnsQueriesTotal.get()}` | Raw DNS requests handled by `TunnelDnsResolver` |")
        sb.appendLine("| **DNS Cache Hits** | `${dnsCacheHits.get()}` | Resolved from 60s in-memory cache |")
        sb.appendLine("| **DNS Network TCP Lookups** | `${dnsNetworkLookups.get()}` | RFC 1035 TCP queries sent via `tun*` interface |")
        sb.appendLine("| **DNS Failures** | `${dnsFailures.get()}` | Failed DNS queries |")
        sb.appendLine("| **DNS Latency (Last / Max)** | `${lastDnsLatencyMs.get()}ms / ${maxDnsLatencyMs.get()}ms` | TCP DNS resolution response time |")
        sb.appendLine("| **Data Relayed (Sent / Recv)** | `${formatBytes(totalBytesSent.get())} / ${formatBytes(totalBytesReceived.get())}` | Bytes relayed through SOCKS5 gatekeeper |")
        sb.appendLine()

        sb.appendLine("## 4. Chronological Event Log (Recent ${recentLogsSnapshot.size} events)")
        sb.appendLine("```text")
        if (recentLogsSnapshot.isEmpty()) {
            sb.appendLine("(No log entries recorded yet)")
        } else {
            for (entry in recentLogsSnapshot) {
                sb.appendLine(entry.toString())
            }
        }
        sb.appendLine("```")

        return sb.toString()
    }

    private fun appendToFile(entry: LogEntry) {
        runCatching {
            // Rotate file if exceeding 512 KB
            if (logFile.exists() && logFile.length() > MAX_LOG_FILE_BYTES) {
                val backupFile = File(appContext.filesDir, "${LOG_FILE_NAME}.old")
                if (backupFile.exists()) backupFile.delete()
                logFile.renameTo(backupFile)
            }

            FileWriter(logFile, true).use { writer ->
                writer.appendLine(entry.toString())
            }
        }
    }

    private fun formatIsoUtc(timestampMillis: Long): String {
        val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        sdf.timeZone = TimeZone.getTimeZone("UTC")
        return sdf.format(Date(timestampMillis))
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        return String.format(Locale.US, "%.2f MB", mb)
    }

    companion object {
        private const val TAG = "SecurityAuditLogger"
        private const val LOG_FILE_NAME = "claudecage_audit.log"
        private const val MAX_LOG_FILE_BYTES = 512 * 1024L // 512 KB
        private const val MAX_RING_BUFFER_ENTRIES = 500
    }
}
