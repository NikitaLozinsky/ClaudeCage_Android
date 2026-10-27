package com.example.claudecageand.telemetry

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock

class SecurityAuditLoggerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val mockContext: Context = mock(Context::class.java)

    @Before
    fun setUp() {
        `when`(mockContext.applicationContext).thenReturn(mockContext)
        `when`(mockContext.filesDir).thenReturn(tempFolder.root)
    }

    @Test
    fun metricCounters_incrementCorrectly() {
        val logger = SecurityAuditLogger(mockContext)

        assertEquals(0, logger.vpnConnectCount.get())
        logger.vpnConnectCount.incrementAndGet()
        assertEquals(1, logger.vpnConnectCount.get())

        logger.successfulConnections.addAndGet(5)
        logger.blockedVpnOffCount.addAndGet(2)
        logger.blockedIpv6Count.addAndGet(1)
        logger.forceClosedSocketsCount.addAndGet(3)

        val snapshot = logger.getSnapshot()
        assertEquals(5, snapshot.connectionsAccepted)
        assertEquals(3, snapshot.connectionsRejected)
        assertEquals(3, snapshot.connectionsKilled)
    }

    @Test
    fun dnsStats_trackingAndLatency() {
        val logger = SecurityAuditLogger(mockContext)

        logger.dnsQueriesTotal.set(10)
        logger.dnsCacheHits.set(4)
        logger.dnsFailures.set(1)
        logger.dnsCacheEntries.set(7)
        logger.recordDnsLatency(45)
        logger.recordDnsLatency(120)
        logger.recordDnsLatency(80)

        val stats = logger.getDnsStats()
        assertEquals(10, stats.totalQueries)
        assertEquals(4, stats.cacheHits)
        assertEquals(1, stats.resolveErrors)
        assertEquals(7, stats.cacheEntries)
        assertEquals(80, stats.averageLatencyMs)
        assertEquals(120, logger.maxDnsLatencyMs.get())
    }

    @Test
    fun ringBuffer_storesAndRollsOver() {
        val logger = SecurityAuditLogger(mockContext)

        for (i in 1..600) {
            logger.log(LogCategory.PROXY, LogLevel.INFO, "Request #$i")
        }

        val recent = logger.getRecentLogs(500)
        assertEquals(500, recent.size)
        // Earliest item in buffer should be Request #101 due to 500 entry limit
        assertTrue(recent.first().message.contains("Request #101"))
        assertTrue(recent.last().message.contains("Request #600"))
    }

    @Test
    fun markdownReport_containsEssentialSections() {
        val logger = SecurityAuditLogger(mockContext)
        logger.vpnConnectCount.set(2)
        logger.isProxyOverrideActive = true
        logger.isDocumentStartJsActive = true
        logger.log(LogCategory.VPN, LogLevel.INFO, "VPN tun0 connected 10.8.0.2")

        val report = logger.generateMarkdownReport()
        assertTrue(report.contains("# ClaudeCage Telemetry & Security Audit Report"))
        assertTrue(report.contains("Device & OS Environment"))
        assertTrue(report.contains("Security Invariant Self-Checks"))
        assertTrue(report.contains("Active (No Fallback)"))
        assertTrue(report.contains("Injected"))
        assertTrue(report.contains("✅ SECURE"))
        assertTrue(report.contains("Network & Gatekeeper Telemetry Metrics"))
        assertTrue(report.contains("VPN Connect Count"))
        assertTrue(report.contains("Chronological Event Log"))
        assertTrue(report.contains("VPN tun0 connected 10.8.0.2"))
    }

    @Test
    fun clearLogs_emptiesBuffer() {
        val logger = SecurityAuditLogger(mockContext)
        logger.log(LogCategory.SECURITY, LogLevel.INFO, "Test event")
        assertTrue(logger.getRecentLogs(10).isNotEmpty())

        logger.clearLogs()
        val afterClear = logger.getRecentLogs(10)
        // After clear, only the "Audit logs cleared" event remains
        assertEquals(1, afterClear.size)
        assertTrue(afterClear.first().message.contains("cleared"))
    }
}
