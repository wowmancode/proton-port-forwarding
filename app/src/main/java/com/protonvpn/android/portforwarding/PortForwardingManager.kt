/*
 * Copyright (c) 2026 Proton AG and contributors
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.protonvpn.android.portforwarding

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import android.os.SystemClock
import com.protonvpn.android.auth.usecase.CurrentUser
import com.protonvpn.android.logging.LogCategory
import com.protonvpn.android.logging.ProtonLogger
import com.protonvpn.android.redesign.vpn.usecases.SettingsForConnection
import com.protonvpn.android.utils.Constants
import com.protonvpn.android.vpn.VpnState
import com.protonvpn.android.vpn.VpnStatusProviderUI
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.PortUnreachableException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

enum class PortForwardingInactiveReason {
    SettingOff, NotConnected, FreePlan, ModerateNat, NotP2pServer
}

sealed interface PortForwardingStatus {
    data class Inactive(val reason: PortForwardingInactiveReason) : PortForwardingStatus
    data object Starting : PortForwardingStatus
    data class Active(
        val port: Int,
        /** Public IPv4 reported by the NAT-PMP gateway, kept in memory only (never logged). */
        val gatewayPublicIp: String?,
        val lifetimeS: Long,
        val renewedAtElapsedMs: Long,
        val serverName: String,
        val connectionId: String,
    ) : PortForwardingStatus {
        fun isLeaseFresh(nowElapsedMs: Long = SystemClock.elapsedRealtime()) =
            nowElapsedMs - renewedAtElapsedMs < lifetimeS * 1000
    }
    data class Failed(val message: String, val retryInS: Int) : PortForwardingStatus
}

/**
 * Requests and keeps renewing a forwarded port from the Proton NAT-PMP gateway while connected to a P2P
 * server with port forwarding enabled.
 *
 * Hardening:
 *  - NAT-PMP traffic is sent only over a UDP socket explicitly bound to this app's own VPN network and
 *    connected to the in-tunnel gateway (10.2.0.1). If that network can't be found, nothing is sent: there
 *    is no fallback to Wi-Fi/mobile, so the request can't leak to (or be answered by) the local network.
 *  - Replies are validated strictly (see [NatPmp]); TCP and UDP must map to the same port.
 *  - The mapping is tied to one connection id: any disconnect, server switch, setting change or plan change
 *    cancels it immediately and the port is cleared from the UI, so a stale port is never shown.
 *  - When the user turns the feature off while connected, the mapping is actively deleted (lifetime 0)
 *    instead of being left open until the lease expires. The server-side feature flag is also cleared.
 *  - Failures back off exponentially (max 60s) — no tight retry loops.
 *  - The port is never broadcast to other apps; the public IP is never written to logs.
 */
@Singleton
class PortForwardingManager @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val mainScope: CoroutineScope,
    private val vpnStatusProviderUI: VpnStatusProviderUI,
    private val settingsForConnection: SettingsForConnection,
    private val currentUser: CurrentUser,
) {
    private val statusFlow =
        MutableStateFlow<PortForwardingStatus>(PortForwardingStatus.Inactive(PortForwardingInactiveReason.NotConnected))
    val status: StateFlow<PortForwardingStatus> = statusFlow.asStateFlow()

    /** Number of spoofed or malformed NAT-PMP datagrams dropped during the current session. */
    private val rejectedDatagramsFlow = MutableStateFlow(0)
    val rejectedDatagrams: StateFlow<Int> = rejectedDatagramsFlow.asStateFlow()

    private val gateway: InetAddress = InetAddress.getByName(Constants.VPN_SERVER_IP)

    private data class Inputs(
        val connectionId: String?,
        val serverName: String?,
        val isConnected: Boolean,
        val settingOn: Boolean,
        val strictNat: Boolean,
        val isP2p: Boolean,
        val isPaid: Boolean,
    )

    private var started = false

    fun start() {
        if (started) return
        started = true
        mainScope.launch {
            combine(
                vpnStatusProviderUI.uiStatus,
                settingsForConnection.getFlowForCurrentConnection(),
                currentUser.vpnUserFlow,
            ) { vpnStatus, settings, vpnUser ->
                val params = vpnStatus.connectionParams
                Inputs(
                    connectionId = params?.uuid?.toString(),
                    serverName = params?.server?.serverName,
                    isConnected = vpnStatus.state == VpnState.Connected && params != null,
                    settingOn = settings.connectionSettings.portForwarding,
                    strictNat = settings.connectionSettings.randomizedNat,
                    isP2p = params?.server?.isP2pServer == true,
                    isPaid = vpnUser?.isFreeUser == false,
                )
            }
                .distinctUntilChanged()
                .collectLatest { inputs -> handle(inputs) }
        }
    }

    private suspend fun handle(inputs: Inputs) {
        val inactiveReason = when {
            !inputs.settingOn -> PortForwardingInactiveReason.SettingOff
            !inputs.isPaid -> PortForwardingInactiveReason.FreePlan
            !inputs.isConnected -> PortForwardingInactiveReason.NotConnected
            !inputs.strictNat -> PortForwardingInactiveReason.ModerateNat
            !inputs.isP2p -> PortForwardingInactiveReason.NotP2pServer
            else -> null
        }
        if (inactiveReason != null) {
            statusFlow.value = PortForwardingStatus.Inactive(inactiveReason)
            return
        }
        runSession(requireNotNull(inputs.connectionId), inputs.serverName.orEmpty())
    }

    private suspend fun runSession(connectionId: String, serverName: String) = withContext(Dispatchers.IO) {
        statusFlow.value = PortForwardingStatus.Starting
        rejectedDatagramsFlow.value = 0
        var failures = 0
        var lastPort = 0
        // Give the server a moment to apply the "port-forwarding" feature sent by the local agent.
        delay(INITIAL_DELAY_MS)
        while (true) {
            coroutineContext.ensureActive()
            try {
                val network = findOwnVpnNetwork()
                    ?: throw NatPmpException("VPN network not available, refusing to send NAT-PMP outside the tunnel")
                VpnNetworkUdpTransport(network, gateway).use { transport ->
                    val client = NatPmpClient(transport, gateway)
                    var mappedPort = 0
                    var cancelled = false
                    try {
                        val publicIp = runCatching { client.publicAddress().address.hostAddress }.getOrNull()
                        while (true) {
                            coroutineContext.ensureActive()
                            val tcp = client.map(NatPmp.Protocol.TCP, lastPort, REQUESTED_LIFETIME_S)
                            mappedPort = tcp.externalPort
                            val udp = client.map(NatPmp.Protocol.UDP, tcp.externalPort, REQUESTED_LIFETIME_S)
                            if (udp.externalPort != tcp.externalPort)
                                throw NatPmpException("TCP and UDP were given different ports")
                            if (lastPort != 0 && lastPort != tcp.externalPort)
                                log("forwarded port changed $lastPort -> ${tcp.externalPort}")
                            else if (lastPort == 0)
                                log("forwarded port ${tcp.externalPort} active")
                            lastPort = tcp.externalPort
                            failures = 0
                            rejectedDatagramsFlow.value = client.rejectedDatagrams
                            val lifetime = minOf(tcp.lifetimeS, udp.lifetimeS)
                            statusFlow.value = PortForwardingStatus.Active(
                                port = lastPort,
                                gatewayPublicIp = publicIp,
                                lifetimeS = lifetime,
                                renewedAtElapsedMs = SystemClock.elapsedRealtime(),
                                serverName = serverName,
                                connectionId = connectionId,
                            )
                            delay(renewDelayMs(lifetime))
                        }
                    } catch (e: CancellationException) {
                        // Inputs changed (disconnect, setting off, server switch, plan change).
                        cancelled = true
                        throw e
                    } finally {
                        rejectedDatagramsFlow.value = client.rejectedDatagrams
                        // On transient errors keep the lease so the same port can be renewed on retry.
                        if (cancelled && mappedPort != 0) {
                            // Close the hole right away instead of waiting for the lease to run out.
                            withContext(NonCancellable) {
                                client.unmap(NatPmp.Protocol.TCP, mappedPort)
                                client.unmap(NatPmp.Protocol.UDP, mappedPort)
                            }
                            log("forwarded port closed")
                        }
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                failures++
                val retryS = (2 shl minOf(failures, 5)).coerceAtMost(MAX_BACKOFF_S) // 4, 8, 16, 32, 60...
                log("NAT-PMP failed (${e.message}), retry in ${retryS}s")
                statusFlow.value = PortForwardingStatus.Failed(e.message ?: e.javaClass.simpleName, retryS)
                delay(retryS * 1000L)
            }
        }
    }

    /**
     * Finds the VPN network created by this app. Requires the VPN transport, our UID as owner (Android 10+)
     * and the Proton tunnel addressing, so another VPN app or a LAN network can never be picked.
     */
    fun findOwnVpnNetwork(): Network? {
        val cm = appContext.getSystemService(ConnectivityManager::class.java) ?: return null
        @Suppress("DEPRECATION")
        return cm.allNetworks.firstOrNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@firstOrNull false
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@firstOrNull false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val owner = caps.ownerUid
                if (owner != Process.INVALID_UID && owner != Process.myUid()) return@firstOrNull false
            }
            val lp = cm.getLinkProperties(network) ?: return@firstOrNull false
            val hasTunnelAddress = lp.linkAddresses.any { it.address.hostAddress == Constants.VPN_CLIENT_IP }
            val routesGateway = lp.routes.any { it.matches(gateway) }
            hasTunnelAddress || routesGateway
        }
    }

    private fun log(message: String) = ProtonLogger.logCustom(LogCategory.CONN, "Port forwarding: $message")

    companion object {
        /** Proton documents 60s leases renewed regularly. */
        const val REQUESTED_LIFETIME_S = 60L
        private const val INITIAL_DELAY_MS = 1_500L
        private const val MAX_BACKOFF_S = 60

        fun renewDelayMs(lifetimeS: Long): Long = (lifetimeS / 2).coerceIn(10, 45) * 1000L
    }
}

/** UDP transport bound to the VPN [Network] and connected to the gateway (kernel drops other sources). */
private class VpnNetworkUdpTransport(network: Network, gateway: InetAddress) : NatPmpTransport {
    private val socket = DatagramSocket(null as java.net.SocketAddress?)
    private val buffer = ByteArray(64) // Larger replies are truncated and then rejected by the strict parser.

    init {
        try {
            socket.bind(InetSocketAddress(0))
            network.bindSocket(socket)
            socket.connect(InetSocketAddress(gateway, NatPmp.SERVER_PORT))
        } catch (e: Exception) {
            socket.close()
            throw e
        }
    }

    override fun send(data: ByteArray) {
        socket.send(DatagramPacket(data, data.size))
    }

    override fun receive(timeoutMs: Int): Datagram? {
        socket.soTimeout = timeoutMs.coerceAtLeast(1)
        val packet = DatagramPacket(buffer, buffer.size)
        return try {
            socket.receive(packet)
            Datagram(packet.data.copyOf(packet.length), packet.address, packet.port)
        } catch (e: SocketTimeoutException) {
            null
        } catch (e: PortUnreachableException) {
            null
        }
    }

    override fun close() = socket.close()
}
