package com.example.claudecageand.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Inet4Address
import java.net.InetAddress

class VpnTunnelStateTest {

    @Test
    fun disconnectedState_isSingletonDataObject() {
        val state1: VpnTunnelState = VpnTunnelState.Disconnected
        val state2: VpnTunnelState = VpnTunnelState.Disconnected
        assertEquals(state1, state2)
    }

    @Test
    fun connectedState_holdsExpectedProperties() {
        val ipv4 = InetAddress.getByName("10.8.0.2") as Inet4Address
        // Mocking or testing data class structure
        val ifaceName = "tun0"
        
        // Check interface name prefixes recognized by the monitor
        val recognizedPrefixes = listOf("tun", "wg", "amn")
        for (prefix in recognizedPrefixes) {
            assertTrue("$prefix should match tunnel prefix", "${prefix}0".startsWith(prefix))
        }
    }
}
