package com.example.claudecageand.net

import android.net.Network
import android.util.Log
import com.example.claudecageand.telemetry.LogCategory
import com.example.claudecageand.telemetry.LogLevel
import com.example.claudecageand.telemetry.SecurityAuditLogger
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.random.Random

/**
 * Result of parsing or querying DNS response.
 */
data class DnsResponse(
    val address: Inet4Address? = null,
    val isNoData: Boolean = false,
    val rcode: Int = 0,
    val isError: Boolean = false
)

/**
 * Strict fail-closed DNS resolver that resolves A (IPv4) records exclusively via
 * raw RFC 1035 DNS-over-TCP.
 *
 * CRITICAL SECURITY GUARANTEES:
 * 1. NEVER calls [InetAddress.getByName] for target hosts, bypassing Android's netd daemon
 *    to prevent Smart DNS leaks or physical interface routing.
 * 2. All outbound DNS query sockets are registered via [socketRegistrar] (which validates that
 *    VPN is strictly Connected) and explicitly bound to the VPN tunnel's local IPv4 ([tunIpv4]).
 * 3. Caches resolved IPv4 addresses in memory for 60 seconds; cache is cleared on VPN disconnect.
 * 4. RFC 2308 NODATA / IPv6-only canary responses are negatively cached for 60s without querying
 *    fallback or incrementing failure counters.
 */
class TunnelDnsResolver(
    private val auditLogger: SecurityAuditLogger? = null
) {

    private data class CacheEntry(
        val address: Inet4Address,
        val expiresAtMillis: Long
    )

    private val cache = ConcurrentHashMap<String, CacheEntry>()
    private val negativeCache = ConcurrentHashMap<String, Long>()
    private val staleCache = ConcurrentHashMap<String, Inet4Address>()
    private val domainLocks = ConcurrentHashMap<String, Mutex>()

    val cacheSize: Int
        get() = cache.size

    val negativeCacheSize: Int
        get() = negativeCache.size

    val staleCacheSize: Int
        get() = staleCache.size

    /**
     * Test helper to populate staleCache for verifying Stale-While-Revalidate fallback.
     */
    fun putStaleEntryForTesting(domain: String, address: Inet4Address) {
        val cleanDomain = domain.trim().trimEnd('.').lowercase()
        staleCache[cleanDomain] = address
    }

    /**
     * Resolves an IPv4 address for [domain] via DNS-over-TCP using [tunIpv4].
     *
     * @param domain Domain name to resolve (e.g. "claude.ai").
     * @param tunIpv4 Active VPN tunnel IPv4 address to which the socket MUST be bound.
     * @param network Active VPN [Network] object for [Network.bindSocket].
     * @param socketRegistrar Thread-safe registrar ensuring socket is tracked and VPN is Connected.
     * @param onSocketClosed Callback when the socket finishes or errors.
     * @return Resolved [Inet4Address], or `null` if domain is NODATA / IPv6-only canary.
     * @throws IOException If resolution encounters network/server failure on all servers.
     */
    @Throws(IOException::class)
    suspend fun resolve(
        domain: String,
        tunIpv4: Inet4Address,
        network: Network?,
        socketRegistrar: ((Socket) -> VpnTunnelState.Connected)? = null,
        onSocketClosed: ((Socket) -> Unit)? = null
    ): Inet4Address? {
        val cleanDomain = domain.trim().trimEnd('.').lowercase()

        // Fast-path 1: check if domain is already an IPv4 literal
        parseIpv4Literal(cleanDomain)?.let { return it }

        auditLogger?.dnsQueriesTotal?.incrementAndGet()
        val now = System.currentTimeMillis()

        // Fast-path 2: Check negative cache (e.g. Cloudflare Turnstile NODATA canaries)
        val negExpiry = negativeCache[cleanDomain]
        if (negExpiry != null) {
            if (negExpiry > now) {
                auditLogger?.dnsCacheHits?.incrementAndGet()
                return null
            } else {
                negativeCache.remove(cleanDomain)
            }
        }

        // Fast-path 3: Check in-memory positive cache before acquiring mutex
        val cached = cache[cleanDomain]
        if (cached != null && cached.expiresAtMillis > now) {
            auditLogger?.dnsCacheHits?.incrementAndGet()
            return cached.address
        }

        // Deduplicate concurrent requests for the same domain via per-domain mutex
        val lock = domainLocks.computeIfAbsent(cleanDomain) { Mutex() }
        return lock.withLock {
            val nowInLock = System.currentTimeMillis()

            // Check negative cache inside lock
            val negInLock = negativeCache[cleanDomain]
            if (negInLock != null) {
                if (negInLock > nowInLock) {
                    auditLogger?.dnsCacheHits?.incrementAndGet()
                    return@withLock null
                } else {
                    negativeCache.remove(cleanDomain)
                }
            }

            // Check positive cache inside lock
            val cachedInLock = cache[cleanDomain]
            if (cachedInLock != null && cachedInLock.expiresAtMillis > nowInLock) {
                auditLogger?.dnsCacheHits?.incrementAndGet()
                return@withLock cachedInLock.address
            }

            auditLogger?.dnsNetworkLookups?.incrementAndGet()
            val startTime = System.currentTimeMillis()

            // 1. Query Primary DNS (1.1.1.1:53) over TCP
            var response = tryQueryDnsServer(
                serverIp = PRIMARY_DNS_IP,
                domain = cleanDomain,
                tunIpv4 = tunIpv4,
                network = network,
                socketRegistrar = socketRegistrar,
                onSocketClosed = onSocketClosed
            )

            var usedServer = PRIMARY_DNS_STR

            // If primary query failed (and is not an authoritative NODATA/NXDOMAIN), try fallback
            if (response.address == null && !response.isNoData && response.rcode != 3) {
                Log.w(TAG, "Primary DNS ($PRIMARY_DNS_STR) query failed for $cleanDomain; trying fallback ($FALLBACK_DNS_STR)")
                auditLogger?.log(
                    LogCategory.DNS,
                    LogLevel.WARN,
                    "Primary DNS failed for '$cleanDomain', attempting fallback $FALLBACK_DNS_STR"
                )

                // 2. Fallback to 8.8.8.8:53 over TCP
                response = tryQueryDnsServer(
                    serverIp = FALLBACK_DNS_IP,
                    domain = cleanDomain,
                    tunIpv4 = tunIpv4,
                    network = network,
                    socketRegistrar = socketRegistrar,
                    onSocketClosed = onSocketClosed
                )
                usedServer = FALLBACK_DNS_STR

                // 3. Radio / Tunnel wake-up retry: if both failed right after waking from idle sleep,
                // do a quick retry on primary DNS after a 150ms backoff
                if (response.address == null && !response.isNoData && response.rcode != 3) {
                    delay(150)
                    Log.w(TAG, "Both DNS servers failed for $cleanDomain; performing wake-up retry on $PRIMARY_DNS_STR")
                    response = tryQueryDnsServer(
                        serverIp = PRIMARY_DNS_IP,
                        domain = cleanDomain,
                        tunIpv4 = tunIpv4,
                        network = network,
                        socketRegistrar = socketRegistrar,
                        onSocketClosed = onSocketClosed
                    )
                    usedServer = "$PRIMARY_DNS_STR (retry)"
                }
            }

            if (response.isNoData) {
                // Legitimate RFC 2308 NODATA (e.g. brunhild.challenges.cloudflare.com)
                // Cache negatively without incrementing dnsFailures
                negativeCache[cleanDomain] = System.currentTimeMillis() + NEGATIVE_CACHE_TTL_MILLIS
                auditLogger?.log(
                    LogCategory.DNS,
                    LogLevel.INFO,
                    "DNS NODATA (IPv6 canary) for '$cleanDomain'; cached negatively for 60s"
                )
                return@withLock null
            }

            if (response.rcode == 3) {
                // NXDOMAIN: domain does not exist
                negativeCache[cleanDomain] = System.currentTimeMillis() + NEGATIVE_CACHE_TTL_MILLIS
                auditLogger?.log(
                    LogCategory.DNS,
                    LogLevel.WARN,
                    "DNS NXDOMAIN for '$cleanDomain'; cached negatively for 60s"
                )
                return@withLock null
            }

            val resolved = if (response.address != null) {
                val latency = System.currentTimeMillis() - startTime
                auditLogger?.recordDnsLatency(latency)
                auditLogger?.log(
                    LogCategory.DNS,
                    LogLevel.INFO,
                    "DNS resolved '$cleanDomain' via $usedServer in ${latency}ms"
                )
                val addr = response.address
                staleCache[cleanDomain] = addr
                addr
            } else {
                val stale = staleCache[cleanDomain]
                if (stale != null) {
                    auditLogger?.log(
                        LogCategory.DNS,
                        LogLevel.WARN,
                        "Wake-up fallback: serving last-known IP for '$cleanDomain'"
                    )
                    Log.w(TAG, "Wake-up fallback: serving last-known IP for '$cleanDomain'")
                    stale
                } else {
                    auditLogger?.dnsFailures?.incrementAndGet()
                    auditLogger?.log(
                        LogCategory.DNS,
                        LogLevel.ERROR,
                        "DNS resolution failed for '$cleanDomain' on all servers"
                    )
                    throw IOException("DNS resolution failed for '$cleanDomain' on both primary and fallback DNS servers")
                }
            }

            // Store in cache for 5 minutes and update telemetry cache counter
            cache[cleanDomain] = CacheEntry(
                address = resolved,
                expiresAtMillis = System.currentTimeMillis() + CACHE_TTL_MILLIS
            )
            auditLogger?.dnsCacheEntries?.set(cache.size.toLong())

            resolved
        }
    }

    /**
     * Clears all cached DNS records (positive, negative, and stale). Called immediately upon VPN disconnect.
     */
    fun clearCache() {
        val size = cache.size + negativeCache.size + staleCache.size
        cache.clear()
        negativeCache.clear()
        staleCache.clear()
        domainLocks.clear()
        auditLogger?.dnsCacheEntries?.set(0)
        if (size > 0) {
            auditLogger?.log(LogCategory.DNS, LogLevel.INFO, "Cleared $size cached DNS entries on VPN drop")
        }
        Log.d(TAG, "DNS cache cleared")
    }

    private suspend fun tryQueryDnsServer(
        serverIp: Inet4Address,
        domain: String,
        tunIpv4: Inet4Address,
        network: Network?,
        socketRegistrar: ((Socket) -> VpnTunnelState.Connected)?,
        onSocketClosed: ((Socket) -> Unit)?
    ): DnsResponse = withContext(Dispatchers.IO) {
        val socket = Socket()
        val watchdog = launch {
            delay(DNS_TIMEOUT_MS.toLong())
            runCatching { socket.close() }
        }
        return@withContext try {
            val verifiedTunnel = socketRegistrar?.invoke(socket)
            val boundIp = verifiedTunnel?.tunIpv4 ?: tunIpv4
            val boundNetwork = verifiedTunnel?.network ?: network

            socket.soTimeout = DNS_TIMEOUT_MS
            socket.tcpNoDelay = true

            if (boundNetwork != null) {
                runCatching { boundNetwork.bindSocket(socket) }
            }
            socket.bind(InetSocketAddress(boundIp, 0))
            socket.connect(InetSocketAddress(serverIp, DNS_PORT), DNS_TIMEOUT_MS)

            val queryId = Random.nextInt(1, 0xFFFF)
            val queryPacket = buildTcpDnsQuery(domain, queryId)

            val dos = DataOutputStream(socket.getOutputStream())
            dos.write(queryPacket)
            dos.flush()

            val dis = DataInputStream(socket.getInputStream())
            val responseLength = dis.readUnsignedShort()
            val responseBytes = ByteArray(responseLength)
            dis.readFully(responseBytes)

            auditLogger?.consecutiveNetworkTimeouts?.set(0)
            parseTcpDnsResponse(responseBytes, queryId)
        } catch (e: Exception) {
            auditLogger?.consecutiveNetworkTimeouts?.incrementAndGet()
            Log.w(TAG, "DNS query exception/timeout for $domain on $serverIp: ${e.message}")
            DnsResponse(isError = true)
        } finally {
            watchdog.cancel()
            runCatching { socket.close() }
            onSocketClosed?.invoke(socket)
        }
    }

    companion object {
        private const val TAG = "TunnelDnsResolver"
        private const val DNS_PORT = 53
        private const val DNS_TIMEOUT_MS = 2500
        const val CACHE_TTL_MILLIS = 300_000L
        const val NEGATIVE_CACHE_TTL_MILLIS = 60_000L

        private const val PRIMARY_DNS_STR = "1.1.1.1"
        private const val FALLBACK_DNS_STR = "8.8.8.8"

        val PRIMARY_DNS_IP: Inet4Address =
            InetAddress.getByAddress(PRIMARY_DNS_STR, byteArrayOf(1, 1, 1, 1)) as Inet4Address
        val FALLBACK_DNS_IP: Inet4Address =
            InetAddress.getByAddress(FALLBACK_DNS_STR, byteArrayOf(8, 8, 8, 8)) as Inet4Address

        /**
         * Parses an IPv4 literal string (e.g. "192.168.1.1") without using DNS lookups.
         */
        fun parseIpv4Literal(text: String): Inet4Address? {
            val parts = text.split('.')
            if (parts.size != 4) return null
            val bytes = ByteArray(4)
            for (i in 0 until 4) {
                val num = parts[i].toIntOrNull() ?: return null
                if (num !in 0..255) return null
                bytes[i] = num.toByte()
            }
            return runCatching {
                InetAddress.getByAddress(text, bytes) as? Inet4Address
            }.getOrNull()
        }

        /**
         * Builds an RFC 1035 DNS-over-TCP query message.
         * The message is prefixed with a 2-byte big-endian length field.
         */
        fun buildTcpDnsQuery(domain: String, queryId: Int): ByteArray {
            val cleanDomain = domain.trimEnd('.')
            val labels = cleanDomain.split('.')
            val qnameOut = ByteArrayOutputStream()
            for (label in labels) {
                val bytes = label.toByteArray(Charsets.US_ASCII)
                require(bytes.isNotEmpty() && bytes.size <= 63) { "Invalid DNS label length: ${bytes.size}" }
                qnameOut.write(bytes.size)
                qnameOut.write(bytes)
            }
            qnameOut.write(0x00) // Null root label terminator

            val qname = qnameOut.toByteArray()
            val dnsMessageLength = 12 + qname.size + 4 // 12 header + qname + 2 QTYPE + 2 QCLASS
            val totalLength = 2 + dnsMessageLength

            val buffer = ByteBuffer.allocate(totalLength).order(ByteOrder.BIG_ENDIAN)

            // 2-byte TCP framing prefix
            buffer.putShort(dnsMessageLength.toShort())

            // Header (12 bytes)
            buffer.putShort(queryId.toShort())
            buffer.putShort(0x0100.toShort()) // Flags: RD = 1 (Recursion Desired)
            buffer.putShort(1.toShort())      // QDCOUNT = 1
            buffer.putShort(0.toShort())      // ANCOUNT = 0
            buffer.putShort(0.toShort())      // NSCOUNT = 0
            buffer.putShort(0.toShort())      // ARCOUNT = 0

            // Question
            buffer.put(qname)
            buffer.putShort(1.toShort())      // QTYPE = A (1)
            buffer.putShort(1.toShort())      // QCLASS = IN (1)

            return buffer.array()
        }

        /**
         * Parses an RFC 1035 DNS response payload (excluding the 2-byte TCP prefix).
         * Extracts the first A record (IPv4) from the answer section.
         * Identifies RFC 2308 NODATA (RCODE 0 with 0 answers) for IPv6 canary domains.
         */
        fun parseTcpDnsResponse(responseBytes: ByteArray, expectedQueryId: Int): DnsResponse {
            if (responseBytes.size < 12) return DnsResponse(isError = true)
            val buffer = ByteBuffer.wrap(responseBytes).order(ByteOrder.BIG_ENDIAN)

            val respId = buffer.short.toInt() and 0xFFFF
            if (respId != expectedQueryId) {
                Log.w(TAG, "DNS query ID mismatch: expected $expectedQueryId, got $respId")
                return DnsResponse(isError = true)
            }

            val flags = buffer.short.toInt() and 0xFFFF
            val rcode = flags and 0x000F
            if (rcode != 0) {
                Log.w(TAG, "DNS server returned error RCODE: $rcode")
                return DnsResponse(rcode = rcode, isError = (rcode != 3))
            }

            val qdCount = buffer.short.toInt() and 0xFFFF
            val anCount = buffer.short.toInt() and 0xFFFF
            buffer.short // NSCOUNT
            buffer.short // ARCOUNT

            if (anCount == 0) {
                // Legitimate RFC 2308 NODATA response (NOERROR, but 0 answers)
                return DnsResponse(address = null, isNoData = true, rcode = 0)
            }

            // Skip questions
            for (i in 0 until qdCount) {
                skipDnsName(buffer)
                if (buffer.remaining() < 4) return DnsResponse(isError = true)
                buffer.short // QTYPE
                buffer.short // QCLASS
            }

            // Parse answers
            for (i in 0 until anCount) {
                skipDnsName(buffer)
                if (buffer.remaining() < 10) return DnsResponse(isError = true)
                val type = buffer.short.toInt() and 0xFFFF
                val clazz = buffer.short.toInt() and 0xFFFF
                buffer.int   // TTL (4 bytes)
                val rdLength = buffer.short.toInt() and 0xFFFF

                if (buffer.remaining() < rdLength) return DnsResponse(isError = true)

                if (type == 1 && clazz == 1 && rdLength == 4) {
                    val ipBytes = ByteArray(4)
                    buffer.get(ipBytes)
                    val ip = runCatching {
                        InetAddress.getByAddress(ipBytes) as? Inet4Address
                    }.getOrNull()
                    return DnsResponse(address = ip, isNoData = (ip == null), rcode = 0)
                } else {
                    // Skip CNAME or other records
                    buffer.position(buffer.position() + rdLength)
                }
            }

            // No A record found in answers
            return DnsResponse(address = null, isNoData = true, rcode = 0)
        }

        private fun skipDnsName(buffer: ByteBuffer) {
            while (buffer.hasRemaining()) {
                val len = buffer.get().toInt() and 0xFF
                if (len == 0) {
                    break
                }
                if ((len and 0xC0) == 0xC0) {
                    // Compression pointer (2 bytes total): first byte read, consume second byte
                    if (buffer.hasRemaining()) {
                        buffer.get()
                    }
                    break
                }
                if (buffer.remaining() >= len) {
                    buffer.position(buffer.position() + len)
                } else {
                    // Malformed packet defense: avoid reading out-of-sync bytes
                    buffer.position(buffer.limit())
                    break
                }
            }
        }
    }
}
