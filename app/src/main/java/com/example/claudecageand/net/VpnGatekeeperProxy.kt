package com.example.claudecageand.net

import android.content.Context
import android.util.Log
import com.example.claudecageand.telemetry.LogCategory
import com.example.claudecageand.telemetry.LogLevel
import com.example.claudecageand.telemetry.SecurityAuditLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.isActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.asCoroutineDispatcher
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * In-process Zero-Leak Loopback SOCKS5 Gatekeeper Proxy.
 *
 * Listens strictly on 127.0.0.1:<dynamic_port>.
 *
 * CRITICAL SECURITY ARCHITECTURE:
 * 1. Fail-Closed Engine: If VPN is Disconnected, all connection attempts are rejected
 *    immediately, and every active client/remote socket is forcefully closed within milliseconds.
 * 2. Strict Interface Binding: Every outbound TCP socket created by the proxy is explicitly
 *    bound to the VPN tunnel's local IPv4 address (socket.bind(InetSocketAddress(tunIpv4, 0)))
 *    AND bound to the VPN Network object. In the Linux kernel, binding to the tun source IP
 *    guarantees packets can NEVER exit via physical interfaces (wlan0, rmnet0).
 * 3. Zero-Leak DNS: Resolves domain names (ATYP 0x03) via [TunnelDnsResolver] using raw
 *    DNS-over-TCP bound strictly to tunIpv4, bypassing Android's netd daemon.
 * 4. IPv6 Disabled: Rejects ATYP 0x04 with SOCKS5 0x08 (Address type not supported).
 * 5. Socket Registration Guard: Outbound and DNS sockets are validated through [registerSocketOrThrow].
 */
class VpnGatekeeperProxy(
    private val vpnStateMonitor: VpnStateMonitor,
    private val auditLogger: SecurityAuditLogger? = null,
    val dnsResolver: TunnelDnsResolver = TunnelDnsResolver(auditLogger)
) {

    constructor(
        context: Context,
        vpnStateMonitor: VpnStateMonitor,
        auditLogger: SecurityAuditLogger? = null,
        dnsResolver: TunnelDnsResolver = TunnelDnsResolver(auditLogger)
    ) : this(vpnStateMonitor, auditLogger, dnsResolver)

    val activeSocketCount: Int
        get() = activeSockets.size

    private val proxyJob = SupervisorJob()
    private val proxyScope = CoroutineScope(Dispatchers.IO + proxyJob)

    // Dedicated cached thread pool for relay traffic so blocking read() never starves Dispatchers.IO
    private val relayExecutor = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "VpnProxyRelay").apply { isDaemon = true }
    }
    private val relayDispatcher = relayExecutor.asCoroutineDispatcher()

    // Bind strictly to loopback 127.0.0.1 on an ephemeral dynamic port (port 0)
    private val serverSocket: ServerSocket = ServerSocket(
        0,
        50,
        InetAddress.getByAddress("127.0.0.1", byteArrayOf(127, 0, 0, 1))
    )

    val listeningPort: Int = serverSocket.localPort

    // Thread-safe pool of all active client and outbound sockets
    private val activeSockets = ConcurrentHashMap.newKeySet<Socket>()
    // Tracks outbound sockets mapped to the tunnel generation at time of creation
    private val outboundSockets = ConcurrentHashMap<Socket, Long>()
    private val isRunning = AtomicBoolean(false)

    @Volatile
    var lastTrafficTimestampMillis: Long = 0L

    /**
     * Checks whether active streaming traffic has passed through the SOCKS5 proxy within [windowMs].
     * Prevents false-positive WakeLock triggers when Chromium keeps idle HTTP/2 or Intercom WebSocket
     * connections alive in the background pool.
     */
    fun hasRecentTraffic(windowMs: Long = 15_000L): Boolean {
        return activeSockets.isNotEmpty() && (System.currentTimeMillis() - lastTrafficTimestampMillis) < windowMs
    }

    // Synchronous tunnel listener for instant kill-switch and handover tracking
    private val tunnelListener = TunnelListener { _, current ->
        when (current) {
            is VpnTunnelState.Connected -> {
                val curGen = current.generation
                val it = outboundSockets.entries.iterator()
                var killed = 0
                while (it.hasNext()) {
                    val entry = it.next()
                    if (entry.value != curGen) {
                        it.remove()
                        activeSockets.remove(entry.key)
                        runCatching { entry.key.close() }
                        killed++
                    }
                }
                if (killed > 0) {
                    auditLogger?.log(
                        LogCategory.KILLSWITCH,
                        LogLevel.BLOCK,
                        "Killed $killed outdated socket(s) on tunnel handover (gen $curGen)"
                    )
                    Log.w(TAG, "Killed $killed outdated socket(s) on tunnel handover (gen $curGen)")
                }
            }
            is VpnTunnelState.Disconnected -> {
                closeAllActiveSockets()
                dnsResolver.clearCache(clearStale = false)
            }
        }
    }

    /**
     * Starts the SOCKS5 proxy server and begins observing VPN state transitions.
     */
    fun start() {
        if (!isRunning.compareAndSet(false, true)) return
        Log.i(TAG, "Starting VpnGatekeeperProxy on 127.0.0.1:$listeningPort")
        auditLogger?.log(LogCategory.PROXY, LogLevel.INFO, "SOCKS5 Proxy started on 127.0.0.1:$listeningPort")

        vpnStateMonitor.addTunnelListener(tunnelListener)

        // Accept loop
        proxyScope.launch {
            acceptLoop()
        }
    }

    /**
     * Stops the SOCKS5 proxy server and releases all socket resources.
     */
    fun stop() {
        if (!isRunning.compareAndSet(true, false)) return
        Log.i(TAG, "Stopping VpnGatekeeperProxy on 127.0.0.1:$listeningPort")
        auditLogger?.log(LogCategory.PROXY, LogLevel.INFO, "SOCKS5 Proxy stopping")
        vpnStateMonitor.removeTunnelListener(tunnelListener)
        runCatching { serverSocket.close() }
        closeAllActiveSockets()
        dnsResolver.clearCache()
        proxyJob.cancel()
        relayExecutor.shutdownNow()
    }

    /**
     * Thread-safe helper that registers a [socket] in [activeSockets] AND immediately verifies
     * that the VPN tunnel is currently [VpnTunnelState.Connected].
     *
     * If the VPN is not connected, the socket is immediately removed from [activeSockets], closed,
     * and an [IOException] is thrown to prevent any race-condition network leaks.
     */
    @Throws(IOException::class)
    fun registerSocketOrThrow(socket: Socket, isOutbound: Boolean = false): VpnTunnelState.Connected {
        activeSockets.add(socket)
        auditLogger?.activeSocketsCount?.set(activeSockets.size)

        val current = vpnStateMonitor.getCurrentTunnelState()
        if (current !is VpnTunnelState.Connected) {
            activeSockets.remove(socket)
            auditLogger?.activeSocketsCount?.set(activeSockets.size)
            runCatching { socket.close() }
            auditLogger?.log(LogCategory.KILLSWITCH, LogLevel.BLOCK, "Socket registration aborted: VPN is disconnected")
            throw IOException("VPN disconnected during socket registration")
        }
        if (isOutbound) {
            outboundSockets[socket] = current.generation
        }
        return current
    }

    /**
     * Immediately and forcefully closes all active sockets in the pool.
     */
    fun closeAllActiveSockets() {
        outboundSockets.clear()
        val iterator = activeSockets.iterator()
        var closedCount = 0
        while (iterator.hasNext()) {
            val socket = iterator.next()
            iterator.remove()
            runCatching {
                socket.close()
                closedCount++
            }
        }
        auditLogger?.activeSocketsCount?.set(0)
        if (closedCount > 0) {
            auditLogger?.forceClosedSocketsCount?.addAndGet(closedCount.toLong())
            auditLogger?.log(LogCategory.KILLSWITCH, LogLevel.BLOCK, "Force-closed $closedCount socket(s) via kill-switch")
            Log.w(TAG, "Force-closed $closedCount active socket(s)")
        }
    }

    private suspend fun acceptLoop() {
        while (isRunning.get() && !serverSocket.isClosed && proxyScope.isActive) {
            try {
                val clientSocket = withContext(Dispatchers.IO) {
                    serverSocket.accept()
                }
                clientSocket.tcpNoDelay = true
                activeSockets.add(clientSocket)
                auditLogger?.activeSocketsCount?.set(activeSockets.size)
                auditLogger?.totalSocksRequests?.incrementAndGet()

                proxyScope.launch {
                    handleClient(clientSocket)
                }
            } catch (e: Exception) {
                if (serverSocket.isClosed || !isRunning.get()) {
                    break
                }
                Log.e(TAG, "Error in SOCKS5 accept loop", e)
            }
        }
    }

    private fun isForbiddenIp(ip: Inet4Address, vpnTunnel: VpnTunnelState?): Boolean {
        if (ip.isLoopbackAddress || ip.isLinkLocalAddress || ip.isSiteLocalAddress || ip.isMulticastAddress || ip.isAnyLocalAddress) {
            return true
        }
        if (vpnTunnel is VpnTunnelState.Connected && ip == vpnTunnel.tunIpv4) {
            return true
        }
        return false
    }

    private fun isDomainAllowed(domain: String): Boolean {
        val clean = domain.trim().trimEnd('.').lowercase(Locale.ROOT)
        return ALLOWED_DOMAIN_SUFFIXES.any { clean == it || clean.endsWith(".$it") }
    }

    private suspend fun handleClient(clientSocket: Socket) = withContext(Dispatchers.IO) {
        var remoteSocket: Socket? = null
        try {
            clientSocket.soTimeout = HANDSHAKE_TIMEOUT_MS
            val inputStream = clientSocket.getInputStream()
            val outputStream = clientSocket.getOutputStream()
            val dis = DataInputStream(inputStream)
            val dos = DataOutputStream(outputStream)

            // --- Step 1: SOCKS5 Handshake / Method Negotiation ---
            val version = dis.readUnsignedByte()
            if (version != SOCKS_VERSION.toInt()) {
                Log.w(TAG, "Invalid SOCKS version: $version")
                return@withContext
            }

            val nMethods = dis.readUnsignedByte()
            val methods = ByteArray(nMethods)
            dis.readFully(methods)

            var supportsNoAuth = false
            for (m in methods) {
                if (m == METHOD_NO_AUTH) {
                    supportsNoAuth = true
                    break
                }
            }

            if (!supportsNoAuth) {
                Log.w(TAG, "Client does not support No-Auth (0x00)")
                dos.write(byteArrayOf(SOCKS_VERSION, METHOD_NO_ACCEPTABLE))
                dos.flush()
                return@withContext
            }

            // Reply: SOCKS5, No-Auth selected
            dos.write(byteArrayOf(SOCKS_VERSION, METHOD_NO_AUTH))
            dos.flush()

            // --- Step 2: Parse Connection Request ---
            val reqVersion = dis.readUnsignedByte()
            if (reqVersion != SOCKS_VERSION.toInt()) {
                Log.w(TAG, "Invalid request version: $reqVersion")
                return@withContext
            }

            val command = dis.readUnsignedByte().toByte()
            dis.readUnsignedByte() // RSV (0x00)
            val atyp = dis.readUnsignedByte().toByte()

            if (command != CMD_CONNECT) {
                Log.w(TAG, "Unsupported command: $command (only CONNECT supported)")
                sendSocks5Reply(dos, REP_CMD_NOT_SUPPORTED)
                return@withContext
            }

            val targetIp: Inet4Address
            val targetPort: Int

            when (atyp) {
                ATYP_IPV4 -> {
                    val ipBytes = ByteArray(4)
                    dis.readFully(ipBytes)
                    targetPort = dis.readUnsignedShort()
                    val rawIp = InetAddress.getByAddress(ipBytes) as Inet4Address
                    val currentTunnel = vpnStateMonitor.getCurrentTunnelState()
                    if (isForbiddenIp(rawIp, currentTunnel)) {
                        Log.w(TAG, "Fail-closed rule: Blocked forbidden IPv4 destination: $rawIp")
                        auditLogger?.log(
                            LogCategory.SECURITY,
                            LogLevel.BLOCK,
                            "Blocked forbidden IPv4 destination: $rawIp"
                        )
                        sendSocks5Reply(dos, REP_CONN_REFUSED)
                        return@withContext
                    }
                    targetIp = rawIp
                }
                ATYP_DOMAIN -> {
                    val domainLength = dis.readUnsignedByte()
                    val domainBytes = ByteArray(domainLength)
                    dis.readFully(domainBytes)
                    targetPort = dis.readUnsignedShort()
                    val rawDomain = String(domainBytes, Charsets.US_ASCII).trim()
                    var domain = rawDomain.trimEnd('.').lowercase(Locale.ROOT)

                    // Strip square brackets if present (e.g. [2604:a880:...])
                    if (domain.startsWith("[") && domain.endsWith("]")) {
                        domain = domain.substring(1, domain.length - 1).trim()
                    }

                    // Check for IPv6 literal passed inside ATYP_DOMAIN (Stage 6 Bug #3)
                    if (domain.contains(':')) {
                        Log.w(TAG, "Fail-closed rule: IPv6 literal passed in ATYP_DOMAIN: '$domain'")
                        auditLogger?.blockedIpv6Count?.incrementAndGet()
                        auditLogger?.log(
                            LogCategory.SECURITY,
                            LogLevel.BLOCK,
                            "Blocked IPv6 literal in domain request: $domain"
                        )
                        sendSocks5Reply(dos, REP_ADDR_TYPE_NOT_SUPPORTED)
                        return@withContext
                    }

                    // Regional Domain Guard (Stage 9 & 10)
                    if (domain == "google.ru" || domain.endsWith(".google.ru")) {
                        domain = domain.removeSuffix(".google.ru") + ".google.com"
                        auditLogger?.log(
                            LogCategory.SECURITY,
                            LogLevel.INFO,
                            "Rewrote regional domain to $domain"
                        )
                        Log.i(TAG, "Rewrote regional domain to $domain")
                    } else if (domain.endsWith(".ru") || domain.endsWith(".su") || domain.endsWith(".by") || domain.endsWith(".xn--p1ai")) {
                        Log.w(TAG, "Fail-closed rule: Blocked regional CIS domain: $domain")
                        auditLogger?.log(
                            LogCategory.SECURITY,
                            LogLevel.BLOCK,
                            "Blocked regional CIS domain: $domain"
                        )
                        sendSocks5Reply(dos, REP_CONN_REFUSED)
                        return@withContext
                    }

                    // Destination Allowlist Guard (P0 Remediation)
                    if (!isDomainAllowed(domain)) {
                        Log.w(TAG, "Fail-closed rule: Blocked non-allowlisted destination domain: $domain")
                        auditLogger?.log(
                            LogCategory.SECURITY,
                            LogLevel.BLOCK,
                            "Blocked non-allowlisted destination domain: $domain"
                        )
                        sendSocks5Reply(dos, REP_CONN_REFUSED)
                        return@withContext
                    }

                    // Check VPN state before attempting DNS query
                    val vpnState = vpnStateMonitor.getCurrentTunnelState()
                    if (vpnState !is VpnTunnelState.Connected) {
                        Log.w(TAG, "Fail-closed: DNS lookup refused for '$domain', VPN is DISCONNECTED")
                        auditLogger?.blockedVpnOffCount?.incrementAndGet()
                        auditLogger?.log(LogCategory.PROXY, LogLevel.BLOCK, "Blocked domain connect to '$domain': VPN Disconnected")
                        sendSocks5Reply(dos, REP_CONN_REFUSED)
                        return@withContext
                    }

                    // Resolve domain via raw DNS-over-TCP bound strictly to tunIpv4
                    val resolved = try {
                        dnsResolver.resolve(
                            domain = domain,
                            tunIpv4 = vpnState.tunIpv4,
                            network = vpnState.network,
                            socketRegistrar = { registerSocketOrThrow(it) },
                            onSocketClosed = {
                                activeSockets.remove(it)
                                auditLogger?.activeSocketsCount?.set(activeSockets.size)
                            }
                        )
                    } catch (e: Exception) {
                        Log.e(TAG, "Fail-closed: DNS resolution failed for '$domain': ${e.message}")
                        sendSocks5Reply(dos, REP_HOST_UNREACHABLE)
                        return@withContext
                    }
                    if (resolved == null) {
                        Log.w(TAG, "DNS resolution returned null (NODATA/NXDOMAIN) for '$domain'")
                        sendSocks5Reply(dos, REP_HOST_UNREACHABLE)
                        return@withContext
                    }
                    targetIp = resolved
                }
                ATYP_IPV6 -> {
                    // Consume IPv6 address (16 bytes) + port (2 bytes)
                    val ipv6Bytes = ByteArray(16)
                    dis.readFully(ipv6Bytes)
                    dis.readUnsignedShort()
                    Log.w(TAG, "Fail-closed rule: IPv6 outbound forbidden (ATYP 0x04)")
                    auditLogger?.blockedIpv6Count?.incrementAndGet()
                    auditLogger?.log(LogCategory.SECURITY, LogLevel.BLOCK, "Rejected outbound IPv6 connection (ATYP 0x04)")
                    sendSocks5Reply(dos, REP_ADDR_TYPE_NOT_SUPPORTED)
                    return@withContext
                }
                else -> {
                    Log.w(TAG, "Unsupported ATYP: $atyp")
                    sendSocks5Reply(dos, REP_ADDR_TYPE_NOT_SUPPORTED)
                    return@withContext
                }
            }

            // --- Step 3: Create & Register Outbound Socket with Race-Condition Check ---
            val outbound = Socket()
            remoteSocket = outbound
            outbound.tcpNoDelay = true
            outbound.keepAlive = true

            val currentTunnelState = try {
                registerSocketOrThrow(outbound, isOutbound = true)
            } catch (e: Exception) {
                Log.w(TAG, "Fail-closed: Connection refused to $targetIp:$targetPort, VPN is DISCONNECTED")
                auditLogger?.blockedVpnOffCount?.incrementAndGet()
                sendSocks5Reply(dos, REP_CONN_REFUSED)
                return@withContext
            }

            // --- Step 4: Bind Outbound Socket to VPN ---
            try {
                // Resilient Android Network binding (handles third-party VPN permission quirks on One UI 9)
                try {
                    currentTunnelState.network.bindSocket(outbound)
                } catch (e: Exception) {
                    Log.w(TAG, "Network.bindSocket non-fatal warning on VPN network: ${e.message}")
                    auditLogger?.log(
                        LogCategory.PROXY,
                        LogLevel.WARN,
                        "Network.bindSocket warning: ${e.message}"
                    )
                }

                // Kernel-level fail-closed enforcement: bind socket to tunnel's local IPv4
                outbound.bind(InetSocketAddress(currentTunnelState.tunIpv4, 0))
                if (outbound.localAddress != currentTunnelState.tunIpv4) {
                    throw IOException("Outbound socket localAddress ${outbound.localAddress} != tunIpv4 ${currentTunnelState.tunIpv4}")
                }

                // Check again right before TCP SYN to defeat any microsecond races
                val verifiedTunnel = vpnStateMonitor.getCurrentTunnelState()
                if (verifiedTunnel !is VpnTunnelState.Connected || verifiedTunnel.generation != currentTunnelState.generation) {
                    throw IOException("VPN state or generation changed right before outbound connect")
                }

                outbound.connect(InetSocketAddress(targetIp, targetPort), OUTBOUND_CONNECT_TIMEOUT_MS)
                auditLogger?.consecutiveNetworkTimeouts?.set(0)
                auditLogger?.successfulConnections?.incrementAndGet()
                auditLogger?.log(
                    LogCategory.PROXY,
                    LogLevel.INFO,
                    "Established outbound TCP: $targetIp:$targetPort via ${currentTunnelState.interfaceName}"
                )
            } catch (e: Exception) {
                if (e is SocketTimeoutException) {
                    auditLogger?.consecutiveNetworkTimeouts?.incrementAndGet()
                }
                Log.e(TAG, "Outbound connection to $targetIp:$targetPort failed: ${e.message}")
                sendSocks5Reply(dos, REP_CONN_REFUSED)
                return@withContext
            }

            // --- Step 5: Send SOCKS5 Success Reply ---
            sendSocks5Success(dos, outbound)

            // Set 5-minute streaming timeouts to prevent zombie half-open sockets
            clientSocket.soTimeout = STREAMING_TIMEOUT_MS
            outbound.soTimeout = STREAMING_TIMEOUT_MS

            // --- Step 6: Relay Bidirectional Traffic ---
            relayTraffic(clientSocket, outbound)

        } catch (_: SocketException) {
            // Expected on stream close or fail-closed abort
        } catch (e: Exception) {
            Log.d(TAG, "Connection finished: ${e.message}")
        } finally {
            activeSockets.remove(clientSocket)
            if (remoteSocket != null) {
                activeSockets.remove(remoteSocket)
                outboundSockets.remove(remoteSocket)
                runCatching { remoteSocket.close() }
            }
            runCatching { clientSocket.close() }
            auditLogger?.activeSocketsCount?.set(activeSockets.size)
        }
    }

    private suspend fun relayTraffic(clientSocket: Socket, remoteSocket: Socket) = withContext(relayDispatcher) {
        val clientIn = clientSocket.getInputStream()
        val clientOut = clientSocket.getOutputStream()
        val remoteIn = remoteSocket.getInputStream()
        val remoteOut = remoteSocket.getOutputStream()

        val jobClientToRemote = launch(relayDispatcher) {
            pipe(clientIn, remoteOut) { bytes ->
                auditLogger?.totalBytesSent?.addAndGet(bytes)
            }
            runCatching { remoteSocket.shutdownOutput() }
        }

        val jobRemoteToClient = launch(relayDispatcher) {
            pipe(remoteIn, clientOut) { bytes ->
                auditLogger?.totalBytesReceived?.addAndGet(bytes)
            }
            runCatching { clientSocket.shutdownOutput() }
        }

        joinAll(jobClientToRemote, jobRemoteToClient)
    }

    private fun pipe(input: InputStream, output: OutputStream, onBytes: (Long) -> Unit) {
        val buffer = ByteArray(BUFFER_SIZE)
        try {
            while (true) {
                val bytesRead = input.read(buffer)
                if (bytesRead == -1) break
                output.write(buffer, 0, bytesRead)
                output.flush()
                lastTrafficTimestampMillis = System.currentTimeMillis()
                onBytes(bytesRead.toLong())
            }
        } catch (_: SocketException) {
            // Socket forcefully closed or reset
        } catch (_: Exception) {
            // Stream ended
        }
    }

    private fun sendSocks5Reply(dos: DataOutputStream, replyCode: Byte) {
        runCatching {
            val reply = byteArrayOf(
                SOCKS_VERSION,
                replyCode,
                0x00,              // RSV
                ATYP_IPV4,
                0, 0, 0, 0,        // BND.ADDR (0.0.0.0)
                0, 0               // BND.PORT (0)
            )
            dos.write(reply)
            dos.flush()
        }
    }

    private fun sendSocks5Success(dos: DataOutputStream, outboundSocket: Socket) {
        val localAddr = outboundSocket.localAddress
        val bndIp = if (localAddr is Inet4Address) localAddr.address else byteArrayOf(0, 0, 0, 0)
        val bndPort = outboundSocket.localPort

        val buffer = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        buffer.put(SOCKS_VERSION)
        buffer.put(REP_SUCCESS)
        buffer.put(0x00.toByte()) // RSV
        buffer.put(ATYP_IPV4)
        buffer.put(bndIp)
        buffer.putShort(bndPort.toShort())

        dos.write(buffer.array())
        dos.flush()
    }

    companion object {
        private const val TAG = "VpnGatekeeperProxy"
        private const val HANDSHAKE_TIMEOUT_MS = 15000
        private const val OUTBOUND_CONNECT_TIMEOUT_MS = 8000
        private const val STREAMING_TIMEOUT_MS = 300_000 // 5 minutes to prevent zombie half-open sockets
        private const val BUFFER_SIZE = 32768

        // SOCKS5 Constants (RFC 1928)
        private const val SOCKS_VERSION = 0x05.toByte()
        private const val METHOD_NO_AUTH = 0x00.toByte()
        private const val METHOD_NO_ACCEPTABLE = 0xFF.toByte()

        private const val CMD_CONNECT = 0x01.toByte()

        private const val ATYP_IPV4 = 0x01.toByte()
        private const val ATYP_DOMAIN = 0x03.toByte()
        private const val ATYP_IPV6 = 0x04.toByte()

        // SOCKS5 Reply Codes
        private const val REP_SUCCESS = 0x00.toByte()
        private const val REP_GENERAL_FAILURE = 0x01.toByte()
        private const val REP_HOST_UNREACHABLE = 0x04.toByte()
        private const val REP_CONN_REFUSED = 0x05.toByte()
        private const val REP_CMD_NOT_SUPPORTED = 0x07.toByte()
        private const val REP_ADDR_TYPE_NOT_SUPPORTED = 0x08.toByte()

        val ALLOWED_DOMAIN_SUFFIXES = setOf(
            "claude.ai",
            "anthropic.com",
            "claude.com",
            "cloudflare.com",
            "hcaptcha.com",
            "stripe.com",
            "stripe.network",
            "stripecdn.com",
            "withpersona.com",
            "persona.com",
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
    }
}
