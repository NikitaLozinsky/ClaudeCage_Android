package com.example.claudecageand.net

import android.content.Context
import android.net.ConnectivityManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.Socket

class VpnGatekeeperProxyTest {

    private val mockContext: Context = mock(Context::class.java)
    private val mockConnectivityManager: ConnectivityManager = mock(ConnectivityManager::class.java)

    @Before
    fun setUp() {
        `when`(mockContext.applicationContext).thenReturn(mockContext)
    }

    @Test
    fun proxyBindsToEphemeralLoopbackPort() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)

        try {
            assertTrue("Listening port should be greater than 0", proxy.listeningPort > 0)
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun failClosed_rejectsConnectionWhenVpnDisconnected() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // 1. SOCKS5 handshake: No-Auth
            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()

            val ver = dis.readUnsignedByte()
            val method = dis.readUnsignedByte()
            assertEquals(5, ver)
            assertEquals(0, method)

            // 2. Request CONNECT to 93.184.216.34:80 (IPv4)
            dos.write(byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                93.toByte(), 184.toByte(), 216.toByte(), 34.toByte(),
                0x00, 0x50 // Port 80
            ))
            dos.flush()

            // 3. Server should reply with failure (0x05 Connection refused) because VPN is Disconnected
            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x05, repCode) // REP_CONN_REFUSED

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsIpv6WithAddressTypeNotSupported() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // Handshake
            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            // SOCKS5 request with ATYP = 0x04 (IPv6)
            val ipv6Request = ByteArray(22)
            ipv6Request[0] = 0x05 // VER
            ipv6Request[1] = 0x01 // CONNECT
            ipv6Request[2] = 0x00 // RSV
            ipv6Request[3] = 0x04 // ATYP IPv6
            // 16 bytes IPv6 (all 0s)
            ipv6Request[20] = 0x00 // Port 80
            ipv6Request[21] = 0x50

            dos.write(ipv6Request)
            dos.flush()

            // Server must reject with 0x08 (Address type not supported)
            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x08, repCode) // REP_ADDR_TYPE_NOT_SUPPORTED

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsIpv6LiteralInAtypDomainWithAddressTypeNotSupported() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // Handshake
            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            // SOCKS5 request with ATYP = 0x03 (Domain), but containing IPv6 literal "2604:a880:800:10::e6:b001"
            val ipv6Domain = "2604:a880:800:10::e6:b001".toByteArray(Charsets.US_ASCII)
            val request = ByteArray(4 + 1 + ipv6Domain.size + 2)
            request[0] = 0x05 // VER
            request[1] = 0x01 // CONNECT
            request[2] = 0x00 // RSV
            request[3] = 0x03 // ATYP DOMAIN
            request[4] = ipv6Domain.size.toByte()
            System.arraycopy(ipv6Domain, 0, request, 5, ipv6Domain.size)
            request[request.size - 2] = 0x01 // Port 443
            request[request.size - 1] = 0xBB.toByte()

            dos.write(request)
            dos.flush()

            // Server must reject with 0x08 (Address type not supported)
            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x08, repCode) // REP_ADDR_TYPE_NOT_SUPPORTED

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun closeAllActiveSockets_closesTrackedSockets() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            
            // Allow acceptLoop to register the socket
            Thread.sleep(100)

            proxy.closeAllActiveSockets()

            // Wait a brief moment for socket close to propagate
            Thread.sleep(50)

            // Attempting to read from client should return EOF (-1) or throw SocketException
            val readResult = runCatching { client.getInputStream().read() }.getOrDefault(-1)
            assertEquals(-1, readResult)

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsRegionalCisDomainsWithConnectionRefused() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            // Handshake
            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            // SOCKS5 request with ATYP = 0x03 (Domain), target "yandex.ru"
            val ruDomain = "yandex.ru".toByteArray(Charsets.US_ASCII)
            val request = ByteArray(4 + 1 + ruDomain.size + 2)
            request[0] = 0x05 // VER
            request[1] = 0x01 // CONNECT
            request[2] = 0x00 // RSV
            request[3] = 0x03 // ATYP DOMAIN
            request[4] = ruDomain.size.toByte()
            System.arraycopy(ruDomain, 0, request, 5, ruDomain.size)
            request[request.size - 2] = 0x01 // Port 443
            request[request.size - 1] = 0xBB.toByte()

            dos.write(request)
            dos.flush()

            // Server must reject with 0x05 (Connection refused)
            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x05, repCode) // REP_CONN_REFUSED

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsUppercaseAndDottedCisDomains() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            val ruDomain = "YANDEX.RU.".toByteArray(Charsets.US_ASCII)
            val request = ByteArray(4 + 1 + ruDomain.size + 2)
            request[0] = 0x05
            request[1] = 0x01
            request[2] = 0x00
            request[3] = 0x03
            request[4] = ruDomain.size.toByte()
            System.arraycopy(ruDomain, 0, request, 5, ruDomain.size)
            request[request.size - 2] = 0x01
            request[request.size - 1] = 0xBB.toByte()

            dos.write(request)
            dos.flush()

            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x05, repCode)

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsNonAllowlistedDomainWithConnectionRefused() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            val evilDomain = "attacker.example.org".toByteArray(Charsets.US_ASCII)
            val request = ByteArray(4 + 1 + evilDomain.size + 2)
            request[0] = 0x05
            request[1] = 0x01
            request[2] = 0x00
            request[3] = 0x03
            request[4] = evilDomain.size.toByte()
            System.arraycopy(evilDomain, 0, request, 5, evilDomain.size)
            request[request.size - 2] = 0x01
            request[request.size - 1] = 0xBB.toByte()

            dos.write(request)
            dos.flush()

            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x05, repCode)

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun rejectsForbiddenLoopbackAndPrivateIpv4() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)
        proxy.start()

        try {
            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            val dos = DataOutputStream(client.getOutputStream())
            val dis = DataInputStream(client.getInputStream())

            dos.write(byteArrayOf(0x05, 0x01, 0x00))
            dos.flush()
            assertEquals(5, dis.readUnsignedByte())
            assertEquals(0, dis.readUnsignedByte())

            // Try connecting to 127.0.0.1:8080 via ATYP_IPV4
            dos.write(byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                127.toByte(), 0.toByte(), 0.toByte(), 1.toByte(),
                0x1F, 0x90.toByte() // 8080
            ))
            dos.flush()

            val repVer = dis.readUnsignedByte()
            val repCode = dis.readUnsignedByte()
            assertEquals(5, repVer)
            assertEquals(0x05, repCode) // REP_CONN_REFUSED

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }

    @Test
    fun allowsCloudflareTurnstileAndHcaptchaDomains() {
        val allowed = VpnGatekeeperProxy.ALLOWED_DOMAIN_SUFFIXES
        assertTrue(allowed.contains("cloudflare.com"))
        assertTrue(allowed.contains("hcaptcha.com"))
        assertTrue(allowed.contains("stripe.com"))
        assertTrue(allowed.contains("intercomcdn.com"))
        assertTrue(allowed.contains("statsigapi.net"))

        fun isAllowed(domain: String): Boolean {
            val clean = domain.trim().trimEnd('.').lowercase(java.util.Locale.ROOT)
            return allowed.any { clean == it || clean.endsWith(".$it") }
        }

        assertTrue(isAllowed("challenges.cloudflare.com"))
        assertTrue(isAllowed("js.hcaptcha.com"))
        assertTrue(isAllowed("api.stripe.com"))
        assertTrue(isAllowed("m.stripe.network"))
        assertTrue(isAllowed("nexus-websocket-a.intercom.io"))
        assertTrue(isAllowed("events.statsigapi.net"))
        assertTrue(isAllowed("claude.ai"))
        assertTrue(isAllowed("cdn.claude.ai"))
        assertFalse(isAllowed("evil.hacker.com"))
    }

    @Test
    fun hasRecentTraffic_returnsTrueOnlyWhenTrafficIsFresh() {
        val monitor = VpnStateMonitor(mockContext, mockConnectivityManager)
        val proxy = VpnGatekeeperProxy(mockContext, monitor)

        try {
            // Case 1: No active sockets -> false even if timestamp is fresh
            proxy.lastTrafficTimestampMillis = System.currentTimeMillis()
            assertFalse(proxy.hasRecentTraffic(15_000L))

            // Start proxy so server accepts connection
            proxy.start()

            val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
            val client = Socket(loopback, proxy.listeningPort)
            client.soTimeout = 3000

            // Wait briefly for accept loop to register client in activeSockets
            var attempts = 0
            while (proxy.activeSocketCount == 0 && attempts < 20) {
                Thread.sleep(25)
                attempts++
            }
            assertTrue("Client should be in activeSockets", proxy.activeSocketCount > 0)

            // Case 2: Active socket exists, but no traffic yet (timestamp = 0L)
            proxy.lastTrafficTimestampMillis = 0L
            assertFalse(proxy.hasRecentTraffic(15_000L))

            // Case 3: Active socket exists, and traffic was within window
            proxy.lastTrafficTimestampMillis = System.currentTimeMillis() - 5_000L
            assertTrue(proxy.hasRecentTraffic(15_000L))

            // Case 4: Active socket exists, but traffic is older than window (e.g. idle keep-alive socket)
            proxy.lastTrafficTimestampMillis = System.currentTimeMillis() - 25_000L
            assertFalse(proxy.hasRecentTraffic(15_000L))

            client.close()
        } finally {
            proxy.stop()
            monitor.stopMonitoring()
        }
    }
}
