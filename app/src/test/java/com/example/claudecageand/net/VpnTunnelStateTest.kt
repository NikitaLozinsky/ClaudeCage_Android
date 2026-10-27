package com.example.claudecageand.net

import android.net.Network
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.mock
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
        val mockNet = mock(Network::class.java)
        val conn1 = VpnTunnelState.Connected(
            network = mockNet,
            interfaceName = "tun0",
            tunIpv4 = ipv4,
            generation = 1L
        )
        val conn2 = VpnTunnelState.Connected(
            network = mockNet,
            interfaceName = "tun0",
            tunIpv4 = ipv4,
            generation = 2L
        )

        assertTrue(conn1.sameTunnel(conn2))
        assertEquals(1L, conn1.generation)
        assertEquals(2L, conn2.generation)

        val otherNet = mock(Network::class.java)
        val conn3 = VpnTunnelState.Connected(
            network = otherNet,
            interfaceName = "tun0",
            tunIpv4 = ipv4,
            generation = 3L
        )
        assertFalse(conn1.sameTunnel(conn3))
    }
}
