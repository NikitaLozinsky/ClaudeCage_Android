package com.example.claudecageand.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import com.example.claudecageand.telemetry.LogCategory
import com.example.claudecageand.telemetry.LogLevel
import com.example.claudecageand.telemetry.SecurityAuditLogger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Sealed interface representing the state of the active VPN tunnel.
 */
sealed interface VpnTunnelState {
    data object Disconnected : VpnTunnelState

    data class Connected(
        val network: Network,
        val interfaceName: String,
        val tunIpv4: Inet4Address,
        val generation: Long = 0L
    ) : VpnTunnelState {
        fun sameTunnel(other: Connected): Boolean {
            return network == other.network &&
                    interfaceName == other.interfaceName &&
                    tunIpv4 == other.tunIpv4
        }
    }
}

/**
 * Synchronous listener for instant fail-closed tunnel transitions and handover handling.
 */
fun interface TunnelListener {
    fun onTunnelChanged(previous: VpnTunnelState, current: VpnTunnelState)
}

/**
 * Real-time monitor for active system VPN tunnels (e.g. Amnezia VPN on One UI 9 / Android 16).
 *
 * Listens for VPN transport events via [ConnectivityManager] and verifies
 * that the underlying network interface (tun*, wg*, amn*, v4-tun*, ppp*, ipsec*)
 * is up and holds a valid IPv4 address.
 */
class VpnStateMonitor(
    context: Context,
    private val connectivityManager: ConnectivityManager =
        context.applicationContext.getSystemService(ConnectivityManager::class.java)
            ?: error("ConnectivityManager system service is unavailable"),
    private val auditLogger: SecurityAuditLogger? = null
) {

    private val stateLock = Any()
    private val _vpnState = MutableStateFlow<VpnTunnelState>(VpnTunnelState.Disconnected)
    val vpnState: StateFlow<VpnTunnelState> = _vpnState.asStateFlow()

    private var isRegistered = false
    private var currentGeneration = 0L
    private val tunnelListeners = CopyOnWriteArrayList<TunnelListener>()

    fun addTunnelListener(listener: TunnelListener) {
        tunnelListeners.add(listener)
    }

    fun removeTunnelListener(listener: TunnelListener) {
        tunnelListeners.remove(listener)
    }

    // Critical Android API rule: default NetworkRequest filters out VPNs.
    // Explicitly add TRANSPORT_VPN and remove NET_CAPABILITY_NOT_VPN.
    private val vpnNetworkRequest: NetworkRequest? by lazy {
        runCatching {
            NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
        }.getOrNull()
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.d(TAG, "VPN network available: $network")
            handleNetworkUpdate(network)
        }

        override fun onCapabilitiesChanged(
            network: Network,
            networkCapabilities: NetworkCapabilities
        ) {
            Log.d(TAG, "VPN capabilities changed: $network")
            handleNetworkUpdate(network)
        }

        override fun onLinkPropertiesChanged(
            network: Network,
            linkProperties: LinkProperties
        ) {
            Log.d(TAG, "VPN link properties changed: $network, iface=${linkProperties.interfaceName}")
            handleNetworkUpdate(network, linkProperties)
        }

        override fun onLost(network: Network) {
            Log.d(TAG, "VPN network lost: $network")
            handleNetworkLost(network)
        }
    }

    init {
        // Trigger an immediate state check on initialization so the app knows at launch
        // whether VPN is ON or OFF before the first callback fires.
        val initialState = scanActiveVpn()
        publishState(initialState)
        startMonitoring()
    }

    /**
     * Publishes tunnel state synchronously under [stateLock], updating generation,
     * binding or unbinding process network via [ConnectivityManager.bindProcessToNetwork],
     * and immediately notifying all [TunnelListener]s.
     */
    private fun publishState(next: VpnTunnelState) {
        synchronized(stateLock) {
            val prev = _vpnState.value
            if (next is VpnTunnelState.Connected) {
                if (prev is VpnTunnelState.Connected && prev.sameTunnel(next)) {
                    return
                }
                currentGeneration++
                val updated = next.copy(generation = currentGeneration)
                _vpnState.value = updated
                recordStateTelemetry(updated)
                runCatching { connectivityManager.bindProcessToNetwork(updated.network) }
                for (listener in tunnelListeners) {
                    runCatching { listener.onTunnelChanged(prev, updated) }
                }
            } else {
                if (prev is VpnTunnelState.Disconnected) {
                    return
                }
                _vpnState.value = VpnTunnelState.Disconnected
                recordStateTelemetry(VpnTunnelState.Disconnected)
                runCatching { connectivityManager.bindProcessToNetwork(null) }
                for (listener in tunnelListeners) {
                    runCatching { listener.onTunnelChanged(prev, VpnTunnelState.Disconnected) }
                }
            }
        }
    }

    /**
     * Registers the network callback for VPN events. Idempotent.
     */
    fun startMonitoring() {
        synchronized(stateLock) {
            if (isRegistered) return
            val request = vpnNetworkRequest ?: return
            try {
                connectivityManager.registerNetworkCallback(request, networkCallback)
                isRegistered = true
                val scanned = scanActiveVpn()
                publishState(scanned)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to register VPN NetworkCallback", e)
            }
        }
    }

    /**
     * Unregisters the network callback. Idempotent.
     */
    fun stopMonitoring() {
        synchronized(stateLock) {
            if (!isRegistered) return
            try {
                connectivityManager.unregisterNetworkCallback(networkCallback)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to unregister VPN NetworkCallback", e)
            } finally {
                isRegistered = false
                publishState(VpnTunnelState.Disconnected)
            }
        }
    }

    /**
     * Synchronously retrieves the current VPN tunnel state.
     * Double-checks in real time that the underlying [NetworkInterface] is still
     * up and holds the exact [Inet4Address] to defeat callback latency and race conditions.
     */
    fun getCurrentTunnelState(): VpnTunnelState {
        synchronized(stateLock) {
            val current = _vpnState.value
            if (current is VpnTunnelState.Connected) {
                val isStillAlive = isInterfaceUpAndHoldsAddress(current.interfaceName, current.tunIpv4)
                if (isStillAlive) {
                    val caps = connectivityManager.getNetworkCapabilities(current.network)
                    if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                        return current
                    }
                }
            }

            // If disconnected or the previous interface died, perform an immediate scan
            val freshState = scanActiveVpn()
            publishState(freshState)
            return _vpnState.value
        }
    }

    private fun handleNetworkUpdate(network: Network, linkProperties: LinkProperties? = null) {
        val evaluated = evaluateNetwork(network, linkProperties)
        if (evaluated is VpnTunnelState.Connected) {
            publishState(evaluated)
        } else {
            val current = _vpnState.value
            if (current is VpnTunnelState.Connected && current.network == network) {
                publishState(scanActiveVpn())
            }
        }
    }

    private fun handleNetworkLost(network: Network) {
        val current = _vpnState.value
        if (current is VpnTunnelState.Connected && current.network == network) {
            publishState(scanActiveVpn())
        }
    }

    private fun evaluateNetwork(network: Network, providedLp: LinkProperties? = null): VpnTunnelState {
        val caps = connectivityManager.getNetworkCapabilities(network) ?: return VpnTunnelState.Disconnected
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return VpnTunnelState.Disconnected
        }

        val lp = providedLp ?: connectivityManager.getLinkProperties(network)
        val lpInterfaceName = lp?.interfaceName

        var chosenInterfaceName: String? = null
        var chosenIpv4: Inet4Address? = null

        if (isValidVpnTransportInterface(lpInterfaceName)) {
            chosenInterfaceName = lpInterfaceName
            chosenIpv4 = extractIpv4(lp) ?: getIpv4FromInterfaceName(lpInterfaceName!!)
        } else {
            // Fallback: search NetworkInterface.getNetworkInterfaces() strictly with known VPN prefixes
            val fallback = findFallbackTunnelInterface()
            if (fallback != null) {
                chosenInterfaceName = fallback.first
                chosenIpv4 = fallback.second
            }
        }

        if (chosenInterfaceName == null || chosenIpv4 == null) {
            return VpnTunnelState.Disconnected
        }

        val isInterfaceValid = isInterfaceUpAndHoldsAddress(chosenInterfaceName, chosenIpv4)
        return if (isInterfaceValid) {
            VpnTunnelState.Connected(
                network = network,
                interfaceName = chosenInterfaceName,
                tunIpv4 = chosenIpv4
            )
        } else {
            VpnTunnelState.Disconnected
        }
    }

    private fun scanActiveVpn(): VpnTunnelState {
        try {
            // 1. Check activeNetwork if it has VPN transport
            val active = connectivityManager.activeNetwork
            if (active != null) {
                val caps = connectivityManager.getNetworkCapabilities(active)
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                    val state = evaluateNetwork(active)
                    if (state is VpnTunnelState.Connected) {
                        return state
                    }
                }
            }

            // 2. Iterate through allNetworks
            for (network in getAllNetworks()) {
                val caps = connectivityManager.getNetworkCapabilities(network)
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                    val state = evaluateNetwork(network)
                    if (state is VpnTunnelState.Connected) {
                        return state
                    }
                }
            }

            // 3. Fallback: match discovered tunnel interface against allNetworks link properties
            val fallback = findFallbackTunnelInterface()
            if (fallback != null) {
                var matchedNetwork: Network? = null
                for (network in getAllNetworks()) {
                    val lp = connectivityManager.getLinkProperties(network)
                    if (lp?.interfaceName == fallback.first) {
                        val caps = connectivityManager.getNetworkCapabilities(network)
                        if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                            matchedNetwork = network
                            break
                        }
                    }
                }

                if (matchedNetwork != null) {
                    return VpnTunnelState.Connected(
                        network = matchedNetwork,
                        interfaceName = fallback.first,
                        tunIpv4 = fallback.second
                    )
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error scanning for active VPN", e)
        }

        return VpnTunnelState.Disconnected
    }

    @Suppress("DEPRECATION")
    private fun getAllNetworks(): Array<Network> {
        return runCatching { connectivityManager.allNetworks }.getOrDefault(emptyArray())
    }

    private fun isKnownVpnInterfacePrefix(name: String?): Boolean {
        if (name.isNullOrBlank()) return false
        val lower = name.lowercase()
        return lower.startsWith("tun") ||
                lower.startsWith("wg") ||
                lower.startsWith("amn") ||
                lower.startsWith("v4-tun") ||
                lower.startsWith("ppp") ||
                lower.startsWith("ipsec")
    }

    private fun isValidVpnTransportInterface(name: String?): Boolean {
        if (name.isNullOrBlank()) return false
        val lower = name.lowercase()
        if (isKnownVpnInterfacePrefix(lower)) return true
        return !lower.startsWith("wlan") &&
                !lower.startsWith("rmnet") &&
                !lower.startsWith("ccmni") &&
                !lower.startsWith("eth") &&
                !lower.startsWith("lo") &&
                !lower.startsWith("dummy") &&
                !lower.startsWith("sit") &&
                !lower.startsWith("p2p")
    }

    private fun extractIpv4(linkProperties: LinkProperties?): Inet4Address? {
        if (linkProperties == null) return null
        return linkProperties.linkAddresses
            .map { it.address }
            .filterIsInstance<Inet4Address>()
            .firstOrNull()
    }

    private fun getIpv4FromInterfaceName(interfaceName: String): Inet4Address? {
        return runCatching {
            val iface = NetworkInterface.getByName(interfaceName) ?: return null
            if (!iface.isUp) return null
            iface.inetAddresses.asSequence()
                .filterIsInstance<Inet4Address>()
                .firstOrNull()
        }.getOrNull()
    }

    private fun findFallbackTunnelInterface(): Pair<String, Inet4Address>? {
        return runCatching {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return null
            for (iface in interfaces) {
                if (iface.isUp && !iface.isLoopback && isKnownVpnInterfacePrefix(iface.name)) {
                    val ipv4 = iface.inetAddresses.asSequence()
                        .filterIsInstance<Inet4Address>()
                        .firstOrNull()
                    if (ipv4 != null) {
                        return Pair(iface.name, ipv4)
                    }
                }
            }
            null
        }.getOrNull()
    }

    private fun isInterfaceUpAndHoldsAddress(interfaceName: String, address: Inet4Address): Boolean {
        return runCatching {
            val iface = NetworkInterface.getByName(interfaceName) ?: return false
            iface.isUp && iface.inetAddresses.asSequence()
                .filterIsInstance<Inet4Address>()
                .any { it == address }
        }.getOrDefault(false)
    }

    private var lastReportedState: VpnTunnelState? = null

    private fun recordStateTelemetry(state: VpnTunnelState) {
        val logger = auditLogger ?: return
        val prev = lastReportedState
        if (state == prev) return

        when (state) {
            is VpnTunnelState.Connected -> {
                if (prev !is VpnTunnelState.Connected ||
                    prev.interfaceName != state.interfaceName ||
                    prev.tunIpv4 != state.tunIpv4
                ) {
                    lastReportedState = state
                    logger.vpnConnectCount.incrementAndGet()
                    logger.log(
                        LogCategory.VPN,
                        LogLevel.INFO,
                        "VPN Connected: iface=${state.interfaceName}, tunIpv4=${state.tunIpv4.hostAddress}, net=${state.network}"
                    )
                }
            }
            is VpnTunnelState.Disconnected -> {
                if (prev !is VpnTunnelState.Disconnected) {
                    lastReportedState = state
                    logger.vpnDisconnectCount.incrementAndGet()
                    logger.log(
                        LogCategory.VPN,
                        LogLevel.WARN,
                        "VPN Disconnected: fail-closed active"
                    )
                }
            }
        }
    }

    companion object {
        private const val TAG = "VpnStateMonitor"
    }
}
