package com.example.claudecageand.net

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.nio.ByteBuffer
import java.nio.ByteOrder

class TunnelDnsResolverTest {

    @Test
    fun parseIpv4Literal_validIps() {
        val ip1 = TunnelDnsResolver.parseIpv4Literal("127.0.0.1")
        assertNotNull(ip1)
        assertArrayEquals(byteArrayOf(127, 0, 0, 1), ip1!!.address)

        val ip2 = TunnelDnsResolver.parseIpv4Literal("10.8.0.2")
        assertNotNull(ip2)
        assertArrayEquals(byteArrayOf(10, 8, 0, 2), ip2!!.address)
    }

    @Test
    fun parseIpv4Literal_invalidIps() {
        assertNull(TunnelDnsResolver.parseIpv4Literal("claude.ai"))
        assertNull(TunnelDnsResolver.parseIpv4Literal("256.0.0.1"))
        assertNull(TunnelDnsResolver.parseIpv4Literal("1.2.3"))
        assertNull(TunnelDnsResolver.parseIpv4Literal(""))
    }

    @Test
    fun buildTcpDnsQuery_validStructure() {
        val queryId = 0x1234
        val packet = TunnelDnsResolver.buildTcpDnsQuery("claude.ai", queryId)

        val buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)
        val tcpLen = buffer.short.toInt() and 0xFFFF
        assertEquals(packet.size - 2, tcpLen)

        val id = buffer.short.toInt() and 0xFFFF
        assertEquals(queryId, id)

        val flags = buffer.short.toInt() and 0xFFFF
        assertEquals(0x0100, flags) // RD = 1

        val qdCount = buffer.short.toInt() and 0xFFFF
        assertEquals(1, qdCount)

        val anCount = buffer.short.toInt() and 0xFFFF
        assertEquals(0, anCount)
    }

    @Test
    fun parseTcpDnsResponse_extractsArecord() {
        val queryId = 0xABCD
        // Construct a mock DNS response for claude.ai -> 104.18.2.3
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(queryId.toShort())
        header.putShort(0x8180.toShort()) // Standard response, No error
        header.putShort(1.toShort())      // QDCOUNT = 1
        header.putShort(1.toShort())      // ANCOUNT = 1
        header.putShort(0.toShort())      // NSCOUNT = 0
        header.putShort(0.toShort())      // ARCOUNT = 0
        out.write(header.array())

        // Question: claude.ai IN A
        out.write(byteArrayOf(6, 'c'.code.toByte(), 'l'.code.toByte(), 'a'.code.toByte(), 'u'.code.toByte(), 'd'.code.toByte(), 'e'.code.toByte()))
        out.write(byteArrayOf(2, 'a'.code.toByte(), 'i'.code.toByte()))
        out.write(0) // null root
        val qtail = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
        qtail.putShort(1.toShort()) // QTYPE A
        qtail.putShort(1.toShort()) // QCLASS IN
        out.write(qtail.array())

        // Answer: pointer 0xC00C, TYPE 1, CLASS 1, TTL 300, RDLENGTH 4, IP 104.18.2.3
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val atail = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        atail.putShort(1.toShort())   // TYPE A
        atail.putShort(1.toShort())   // CLASS IN
        atail.putInt(300)             // TTL
        atail.putShort(4.toShort())   // RDLENGTH = 4
        out.write(atail.array())
        out.write(byteArrayOf(104, 18, 2, 3)) // IP

        val responseBytes = out.toByteArray()
        val parsed = TunnelDnsResolver.parseTcpDnsResponse(responseBytes, queryId)

        assertNotNull(parsed.address)
        assertFalse(parsed.isNoData)
        assertFalse(parsed.isError)
        assertArrayEquals(byteArrayOf(104, 18, 2, 3), parsed.address!!.address)
    }

    @Test
    fun parseTcpDnsResponse_skipsCnameToFindA() {
        val queryId = 0x5678
        // Construct a mock response where Answer 1 is CNAME and Answer 2 is A record
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(queryId.toShort())
        header.putShort(0x8180.toShort()) // Standard response, No error
        header.putShort(1.toShort())      // QDCOUNT = 1
        header.putShort(2.toShort())      // ANCOUNT = 2
        header.putShort(0.toShort())      // NSCOUNT = 0
        header.putShort(0.toShort())      // ARCOUNT = 0
        out.write(header.array())

        // Question: test.ai IN A
        out.write(byteArrayOf(4, 't'.code.toByte(), 'e'.code.toByte(), 's'.code.toByte(), 't'.code.toByte()))
        out.write(byteArrayOf(2, 'a'.code.toByte(), 'i'.code.toByte()))
        out.write(0)
        val qtail = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
        qtail.putShort(1.toShort()) // QTYPE A
        qtail.putShort(1.toShort()) // QCLASS IN
        out.write(qtail.array())

        // Answer 1: CNAME (type 5) pointing to target.ai
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val cnameHeader = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        cnameHeader.putShort(5.toShort()) // TYPE CNAME
        cnameHeader.putShort(1.toShort()) // CLASS IN
        cnameHeader.putInt(60)            // TTL
        val targetName = byteArrayOf(6, 't'.code.toByte(), 'a'.code.toByte(), 'r'.code.toByte(), 'g'.code.toByte(), 'e'.code.toByte(), 't'.code.toByte(), 2, 'a'.code.toByte(), 'i'.code.toByte(), 0)
        cnameHeader.putShort(targetName.size.toShort())
        out.write(cnameHeader.array())
        out.write(targetName)

        // Answer 2: A record (type 1)
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val aHeader = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        aHeader.putShort(1.toShort()) // TYPE A
        aHeader.putShort(1.toShort()) // CLASS IN
        aHeader.putInt(60)
        aHeader.putShort(4.toShort())
        out.write(aHeader.array())
        out.write(byteArrayOf(192.toByte(), 0, 2, 1))

        val parsed = TunnelDnsResolver.parseTcpDnsResponse(out.toByteArray(), queryId)
        assertNotNull(parsed.address)
        assertFalse(parsed.isNoData)
        assertArrayEquals(byteArrayOf(192.toByte(), 0, 2, 1), parsed.address!!.address)
    }

    @Test
    fun parseTcpDnsResponse_nodata_returnsIsNoDataTrue() {
        val queryId = 0x9999
        // Construct RFC 2308 NODATA response: RCODE=0, ANCOUNT=0 (e.g. brunhild.challenges.cloudflare.com)
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(queryId.toShort())
        header.putShort(0x8180.toShort()) // Standard response, No error (RCODE=0)
        header.putShort(1.toShort())      // QDCOUNT = 1
        header.putShort(0.toShort())      // ANCOUNT = 0 (NODATA!)
        header.putShort(1.toShort())      // NSCOUNT = 1 (SOA)
        header.putShort(0.toShort())      // ARCOUNT = 0
        out.write(header.array())

        val parsed = TunnelDnsResolver.parseTcpDnsResponse(out.toByteArray(), queryId)
        assertNull(parsed.address)
        assertTrue(parsed.isNoData)
        assertFalse(parsed.isError)
        assertEquals(0, parsed.rcode)
    }

    @Test
    fun parseTcpDnsResponse_queryIdMismatchReturnsError() {
        val queryId = 0x1111
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(0x2222.toShort()) // Mismatched ID
        header.putShort(0x8180.toShort())
        header.putShort(0.toShort())
        header.putShort(0.toShort())
        header.putShort(0.toShort())
        header.putShort(0.toShort())

        val result = TunnelDnsResolver.parseTcpDnsResponse(header.array(), queryId)
        assertTrue(result.isError)
        assertNull(result.address)
    }

    @Test
    fun resolve_ipv4Literal_returnsDirectlyWithoutNetworkQuery() = kotlinx.coroutines.runBlocking {
        val resolver = TunnelDnsResolver()
        val tunIp = java.net.InetAddress.getByAddress(byteArrayOf(10, 0, 0, 1)) as java.net.Inet4Address
        val result = resolver.resolve("192.168.1.100", tunIp, null)
        assertNotNull(result)
        assertArrayEquals(byteArrayOf(192.toByte(), 168.toByte(), 1, 100), result!!.address)
    }

    @Test
    fun resolve_withStaleFallback_returnsStaleWhenResolutionFails() = kotlinx.coroutines.runBlocking {
        val resolver = TunnelDnsResolver()
        val tunIp = java.net.InetAddress.getByAddress(byteArrayOf(10, 0, 0, 1)) as java.net.Inet4Address
        val staleIp = java.net.InetAddress.getByAddress(byteArrayOf(104, 18, 2, 3)) as java.net.Inet4Address

        resolver.putStaleEntryForTesting("claude.ai", staleIp)
        assertEquals(1, resolver.staleCacheSize)

        // When network queries fail (unreachable in unit test), resolver serves last-known stale IP
        val result = resolver.resolve("claude.ai", tunIp, null)
        assertNotNull(result)
        assertEquals(staleIp, result)
    }

    @Test
    fun cacheSize_and_clearCache() {
        val resolver = TunnelDnsResolver()
        assertEquals(0, resolver.cacheSize)
        assertEquals(0, resolver.negativeCacheSize)
        assertEquals(0, resolver.staleCacheSize)

        val staleIp = java.net.InetAddress.getByAddress(byteArrayOf(104, 18, 2, 3)) as java.net.Inet4Address
        resolver.putStaleEntryForTesting("claude.ai", staleIp)
        assertEquals(1, resolver.staleCacheSize)

        resolver.clearCache()
        assertEquals(0, resolver.cacheSize)
        assertEquals(0, resolver.negativeCacheSize)
        assertEquals(0, resolver.staleCacheSize)
    }

    @Test
    fun clearCache_withPreserveStale_keepsStaleEntries() {
        val resolver = TunnelDnsResolver()
        val staleIp = java.net.InetAddress.getByAddress(byteArrayOf(104, 18, 2, 3)) as java.net.Inet4Address
        resolver.putStaleEntryForTesting("claude.ai", staleIp)
        assertEquals(1, resolver.staleCacheSize)

        resolver.clearCache(clearStale = false)
        assertEquals(1, resolver.staleCacheSize)
    }

    @Test
    fun parseTcpDnsResponse_multipleArecords_picksOne() {
        val queryId = 0x3333
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        header.putShort(queryId.toShort())
        header.putShort(0x8180.toShort())
        header.putShort(1.toShort())      // QDCOUNT
        header.putShort(2.toShort())      // ANCOUNT = 2
        header.putShort(0.toShort())
        header.putShort(0.toShort())
        out.write(header.array())

        // Question
        out.write(byteArrayOf(6, 'c'.code.toByte(), 'l'.code.toByte(), 'a'.code.toByte(), 'u'.code.toByte(), 'd'.code.toByte(), 'e'.code.toByte(), 2, 'a'.code.toByte(), 'i'.code.toByte(), 0))
        val qtail = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
        qtail.putShort(1.toShort())
        qtail.putShort(1.toShort())
        out.write(qtail.array())

        // Answer 1: 104.18.2.3
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val a1 = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        a1.putShort(1.toShort())
        a1.putShort(1.toShort())
        a1.putInt(300)
        a1.putShort(4.toShort())
        out.write(a1.array())
        out.write(byteArrayOf(104, 18, 2, 3))

        // Answer 2: 104.18.3.4
        out.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        val a2 = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN)
        a2.putShort(1.toShort())
        a2.putShort(1.toShort())
        a2.putInt(300)
        a2.putShort(4.toShort())
        out.write(a2.array())
        out.write(byteArrayOf(104, 18, 3, 4))

        val parsed = TunnelDnsResolver.parseTcpDnsResponse(out.toByteArray(), queryId)
        assertNotNull(parsed.address)
        val picked = parsed.address!!.hostAddress
        assertTrue(picked == "104.18.2.3" || picked == "104.18.3.4")
    }
}
