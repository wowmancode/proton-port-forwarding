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
import android.net.LinkProperties
import android.os.Build
import android.os.PowerManager
import com.protonvpn.android.api.ProtonApiRetroFit
import com.protonvpn.android.logging.LogCategory
import com.protonvpn.android.logging.ProtonLogger
import com.protonvpn.android.redesign.vpn.usecases.SettingsForConnection
import com.protonvpn.android.settings.data.SplitTunnelingMode
import com.protonvpn.android.utils.Constants
import com.protonvpn.android.vpn.CurrentVpnServiceProvider
import com.protonvpn.android.vpn.VpnState
import com.protonvpn.android.vpn.VpnStateMonitor
import com.protonvpn.android.vpn.VpnStatusProviderUI
import com.protonvpn.android.vpn.alwayson.VpnAlwaysOnStorage
import dagger.Reusable
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import me.proton.core.network.domain.ApiResult
import java.net.BindException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import javax.inject.Inject

enum class CheckStatus { Pass, Warn, Fail, Info }

enum class CheckGroup { Traffic, PortForwarding }

data class SecurityCheckItem(
    val group: CheckGroup,
    val title: String,
    val status: CheckStatus,
    val detail: String,
    val fix: SecurityFix? = null,
)

enum class SecurityFix { OpenVpnSystemSettings, OpenBatterySettings, EnableStrictNat, Reconnect }

/**
 * On-device checks for "is my traffic protected" and "is port forwarding safe". Everything runs locally,
 * except one request to the Proton API (through the tunnel) to see which public IP Proton observes.
 * No third-party port-check or IP-check services are contacted.
 */
@Reusable
class PortForwardingSecurityCheck @Inject constructor(
    @param:ApplicationContext private val appContext: Context,
    private val vpnStatusProviderUI: VpnStatusProviderUI,
    private val vpnStateMonitor: VpnStateMonitor,
    private val settingsForConnection: SettingsForConnection,
    private val portForwardingManager: PortForwardingManager,
    private val currentVpnServiceProvider: CurrentVpnServiceProvider,
    private val vpnAlwaysOnStorage: VpnAlwaysOnStorage,
    private val api: ProtonApiRetroFit,
) {
    private val probeV4 = InetAddress.getByName("1.1.1.1")
    private val probeV6 = InetAddress.getByName("2606:4700:4700::1111")
    private val gateway = InetAddress.getByName(Constants.VPN_SERVER_IP)

    suspend fun run(): List<SecurityCheckItem> = withContext(Dispatchers.IO) {
        val results = mutableListOf<SecurityCheckItem>()
        val status = vpnStatusProviderUI.uiStatus.value
        val connected = status.state == VpnState.Connected && status.connectionParams != null
        val settings = settingsForConnection.getFlowForCurrentConnection().first().connectionSettings
        val cm = appContext.getSystemService(ConnectivityManager::class.java)
        val vpnNetwork = portForwardingManager.findOwnVpnNetwork()
        val lp: LinkProperties? = vpnNetwork?.let { cm?.getLinkProperties(it) }
        val exitIp = vpnStateMonitor.exitIp.value?.ipV4

        fun traffic(title: String, s: CheckStatus, detail: String, fix: SecurityFix? = null) =
            results.add(SecurityCheckItem(CheckGroup.Traffic, title, s, detail, fix))
        fun pf(title: String, s: CheckStatus, detail: String, fix: SecurityFix? = null) =
            results.add(SecurityCheckItem(CheckGroup.PortForwarding, title, s, detail, fix))

        // ---------- Traffic ----------
        if (!connected) {
            traffic("VPN connection", CheckStatus.Fail, "Not connected. Your traffic is not protected.")
            return@withContext results
        }
        traffic("VPN connection", CheckStatus.Pass, "Connected to ${status.connectionParams?.server?.serverName}.")

        if (vpnNetwork == null || lp == null) {
            traffic("Tunnel interface", CheckStatus.Fail,
                "Android doesn't report Proton VPN's tunnel as active.", SecurityFix.Reconnect)
        } else {
            val activeIsVpn = cm?.activeNetwork == vpnNetwork
            traffic("Tunnel interface",
                if (activeIsVpn) CheckStatus.Pass else CheckStatus.Warn,
                if (activeIsVpn) "Android routes traffic through Proton VPN's tunnel."
                else "The tunnel exists but isn't the default network right now.")

            val v4InTunnel = lp.routes.any { it.matches(probeV4) }
            traffic("IPv4 traffic", if (v4InTunnel) CheckStatus.Pass else CheckStatus.Fail,
                if (v4InTunnel) "Internet IPv4 traffic goes through the tunnel."
                else "Internet IPv4 traffic is NOT routed through the tunnel.")

            val v6InTunnel = lp.routes.any { it.matches(probeV6) }
            traffic("IPv6 leak protection", if (v6InTunnel) CheckStatus.Pass else CheckStatus.Warn,
                if (v6InTunnel) "IPv6 traffic is routed into the tunnel (sent through it or blocked), not leaked."
                else "IPv6 isn't routed into the tunnel. If your network has IPv6, it could leak.")

            val dns = lp.dnsServers
            val dnsInTunnel = dns.isNotEmpty() && dns.all { d -> lp.routes.any { it.matches(d) } }
            traffic("DNS", if (dnsInTunnel) CheckStatus.Pass else CheckStatus.Warn,
                if (dnsInTunnel) "DNS requests go through the tunnel (${dns.size} server(s))."
                else "Some DNS servers aren't reachable through the tunnel, so lookups could leak.")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && lp.isPrivateDnsActive) {
                traffic("Private DNS", CheckStatus.Info,
                    "Android Private DNS is on. It still runs inside the tunnel but bypasses NetShield.")
            }
        }

        if (exitIp != null) {
            traffic("Exit server confirmed", CheckStatus.Pass, "The VPN server confirmed your exit IP over its control channel.")
        } else {
            traffic("Exit server confirmed", CheckStatus.Warn, "The VPN server hasn't confirmed your exit IP yet. Try again in a minute.")
        }

        // Proton's app normally calls this endpoint only while disconnected, so through the tunnel it can be slow.
        // Retry once with a longer timeout and keep the reason (never the IP) for the UI and logs.
        var observed: String? = null
        var failureReason: String? = null
        for (attempt in 1..2) {
            when (val result = withTimeoutOrNull(15_000) { api.getLocation() }) {
                is ApiResult.Success -> {
                    observed = result.value.ipAddress.takeIf { it.isNotBlank() }
                    failureReason = if (observed == null) "empty response" else null
                }
                is ApiResult.Error.Http -> failureReason = "HTTP ${result.httpCode}"
                is ApiResult.Error -> failureReason = result.javaClass.simpleName.ifBlank { "network error" }
                null -> failureReason = "timed out"
            }
            if (observed != null) break
        }
        if (failureReason != null) {
            ProtonLogger.logCustom(LogCategory.CONN, "Security check: public IP lookup failed ($failureReason)")
        }
        when {
            observed == null -> traffic(
                "Public IP check",
                // The server already confirmed the exit IP over its control channel, so a failed lookup is
                // informational rather than a sign of a leak.
                if (exitIp != null) CheckStatus.Info else CheckStatus.Warn,
                "Couldn't ask Proton which IP it sees ($failureReason). " +
                    if (exitIp != null) "This doesn't mean a leak: the VPN server already confirmed your exit IP above."
                    else "Try again in a minute."
            )
            exitIp != null && observed == exitIp ->
                traffic("Public IP check", CheckStatus.Pass, "Proton sees your traffic coming from the VPN server's exit IP.")
            exitIp == null -> traffic("Public IP check", CheckStatus.Info, "Proton sees an IP, but it can't be matched against an exit IP yet.")
            else -> traffic("Public IP check", CheckStatus.Warn,
                "Proton saw a different IP than this server's exit IP. This can happen with alternative routing; if it persists, reconnect.",
                SecurityFix.Reconnect)
        }

        val service = currentVpnServiceProvider.getCurrentVpnService()
        val alwaysOn: Boolean
        val lockdown: Boolean
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && service != null) {
            alwaysOn = service.isAlwaysOn
            lockdown = service.isLockdownEnabled
        } else {
            val stored = vpnAlwaysOnStorage.getLastKnownVpnAlwaysOn()
            alwaysOn = stored?.isEnabled == true
            lockdown = stored?.isLockdownEnabled == true
        }
        traffic("Kill switch",
            when { lockdown -> CheckStatus.Pass; alwaysOn -> CheckStatus.Warn; else -> CheckStatus.Fail },
            when {
                lockdown -> "Always-on VPN and \"Block connections without VPN\" are on. If the VPN drops, nothing leaks."
                alwaysOn -> "Always-on VPN is on, but \"Block connections without VPN\" is off, so traffic can leak while reconnecting."
                else -> "No kill switch. If the VPN drops, your torrent app will keep running on your real IP."
            },
            SecurityFix.OpenVpnSystemSettings.takeUnless { lockdown })

        with(settings.splitTunneling) {
            if (isEnabled && !isEmpty()) {
                val detail = when (mode) {
                    SplitTunnelingMode.EXCLUDE_ONLY ->
                        "${excludedApps.size} app(s) and ${excludedIps.size} IP range(s) bypass the VPN. Make sure your torrent app isn't one of them."
                    SplitTunnelingMode.INCLUDE_ONLY ->
                        "Only selected apps use the VPN. Make sure your torrent app is included."
                }
                traffic("Split tunneling", CheckStatus.Warn, detail)
            } else {
                traffic("Split tunneling", CheckStatus.Pass, "Off. All apps use the VPN.")
            }
        }
        if (settings.lanConnections && settings.lanConnectionsAllowDirect) {
            traffic("LAN direct connections", CheckStatus.Info,
                "Some system apps may connect to your local network directly, outside the VPN.")
        }

        // ---------- Port forwarding ----------
        val server = status.connectionParams?.server
        val pfStatus = portForwardingManager.status.value
        if (!settings.portForwarding) {
            pf("Port forwarding", CheckStatus.Info, "Off. No ports are open to the internet.")
            return@withContext results
        }
        pf("P2P server", if (server?.isP2pServer == true) CheckStatus.Pass else CheckStatus.Fail,
            if (server?.isP2pServer == true) "${server.serverName} supports P2P and port forwarding."
            else "This server doesn't support port forwarding. Connect to a P2P (⇄) server.")
        pf("NAT type", if (settings.randomizedNat) CheckStatus.Pass else CheckStatus.Fail,
            if (settings.randomizedNat) "Strict NAT: only the forwarded port is reachable."
            else "Moderate NAT is on. Port forwarding is disabled until you switch back to strict.",
            SecurityFix.EnableStrictNat.takeUnless { settings.randomizedNat })

        val gatewayInTunnel = lp?.routes?.any { it.matches(gateway) } == true
        pf("NAT-PMP stays inside the tunnel", if (gatewayInTunnel) CheckStatus.Pass else CheckStatus.Fail,
            if (gatewayInTunnel) "Port requests go only to Proton's gateway, over the encrypted tunnel, never to your local network."
            else "The gateway isn't routed through the tunnel, so no port requests will be sent.")

        val serverAck = PortForwardingServerAck.serverPortForwarding.value
        val reportedCount = PortForwardingServerAck.lastReportedFeatureCount
        pf("Server enabled port forwarding",
            when (serverAck) { true -> CheckStatus.Pass; false -> CheckStatus.Fail; null -> CheckStatus.Warn },
            when (serverAck) {
                true -> "The VPN server confirmed port forwarding is on for this connection."
                false -> "The VPN server reports port forwarding as OFF for this connection, so incoming connections are blocked. Reconnect to retry."
                null -> if (reportedCount < 0) "The VPN server hasn't sent its feature status yet. Try again in a minute."
                    else "The VPN server reported $reportedCount feature(s) but didn't include port forwarding, so it may not be applied."
            },
            SecurityFix.Reconnect.takeIf { serverAck == false })

        when (pfStatus) {
            is PortForwardingStatus.Active -> {
                pf("Forwarded port", CheckStatus.Pass, "Port ${pfStatus.port} (TCP and UDP) is open on ${pfStatus.serverName}.")
                pf("Lease", if (pfStatus.isLeaseFresh()) CheckStatus.Pass else CheckStatus.Warn,
                    if (pfStatus.isLeaseFresh()) "Renewed automatically every ${PortForwardingManager.renewDelayMs(pfStatus.lifetimeS) / 1000}s."
                    else "The lease wasn't renewed in time. The port may change.")
                val gwIp = pfStatus.gatewayPublicIp
                pf("Gateway authenticity",
                    if (gwIp != null && gwIp == exitIp) CheckStatus.Pass else CheckStatus.Warn,
                    when {
                        gwIp == null || exitIp == null -> "Couldn't compare the gateway's public IP with the VPN exit IP yet."
                        gwIp == exitIp -> "The port gateway reports the same public IP as your VPN server, so it's the real Proton gateway."
                        else -> "The port gateway reports a different public IP than your VPN server. Reconnect; if it keeps happening, turn port forwarding off."
                    },
                    SecurityFix.Reconnect.takeIf { gwIp != null && exitIp != null && gwIp != exitIp })
                val rejected = portForwardingManager.rejectedDatagrams.value
                pf("Spoofed replies", if (rejected == 0) CheckStatus.Pass else CheckStatus.Warn,
                    if (rejected == 0) "No fake or malformed port replies received."
                    else "$rejected unexpected reply packet(s) were rejected. The port shown is still the verified one.")
                val listening = isSomethingListening(pfStatus.port)
                pf("Torrent app listening", when (listening) { true -> CheckStatus.Pass; false -> CheckStatus.Warn; null -> CheckStatus.Info },
                    when (listening) {
                        true -> "An app on this phone is listening on port ${pfStatus.port}."
                        false -> "Nothing is listening on port ${pfStatus.port}. Enter this port in your torrent app and turn off its UPnP/NAT-PMP."
                        null -> "Couldn't check whether an app is listening on the port."
                    })
                pf("Exposure", CheckStatus.Info,
                    "Only port ${pfStatus.port} is reachable from the internet; all other ports stay blocked by Proton's firewall. " +
                        "Use this port only for your torrent app, and don't run servers (SSH, file sharing, remote access) on it.")
            }
            is PortForwardingStatus.Failed ->
                pf("Forwarded port", CheckStatus.Fail, "Couldn't get a port: ${pfStatus.message}. Retrying in ${pfStatus.retryInS}s.")
            PortForwardingStatus.Starting ->
                pf("Forwarded port", CheckStatus.Info, "Requesting a port…")
            is PortForwardingStatus.Inactive ->
                pf("Forwarded port", CheckStatus.Info, "Not active (${pfStatus.reason.name}).")
        }

        val pm = appContext.getSystemService(PowerManager::class.java)
        val unrestricted = pm?.isIgnoringBatteryOptimizations(appContext.packageName) == true
        pf("Background renewal", if (unrestricted) CheckStatus.Pass else CheckStatus.Warn,
            if (unrestricted) "Battery optimization is off for Proton VPN, so the port keeps renewing with the screen off."
            else "Battery optimization can delay renewals with the screen off, and the port may change. Set Proton VPN to \"Unrestricted\".",
            SecurityFix.OpenBatterySettings.takeUnless { unrestricted })

        results
    }

    /**
     * Returns true if another app already listens on [port] (bind fails), false if the port is free.
     * The probe socket is closed immediately and never accepts connections.
     */
    private fun isSomethingListening(port: Int): Boolean? = try {
        ServerSocket().use { s ->
            s.reuseAddress = false
            s.bind(InetSocketAddress(port), 1)
        }
        false
    } catch (e: BindException) {
        true
    } catch (e: Exception) {
        null
    }
}
