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

import com.protonvpn.android.logging.LogCategory
import com.protonvpn.android.logging.ProtonLogger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * What the VPN server reported back, over the local agent, for the "port-forwarding" feature on the current
 * connection. null = not reported (yet). Used for diagnostics in the security check.
 */
object PortForwardingServerAck {
    private val state = MutableStateFlow<Boolean?>(null)
    val serverPortForwarding: StateFlow<Boolean?> = state.asStateFlow()

    /** Number of features the server reported in its last status (diagnostics; -1 = no status yet). */
    @Volatile
    var lastReportedFeatureCount: Long = -1
        private set

    fun reset() {
        state.value = null
        lastReportedFeatureCount = -1
    }

    fun update(value: Boolean?, featureCount: Long) {
        lastReportedFeatureCount = featureCount
        if (state.value != value) {
            ProtonLogger.logCustom(LogCategory.CONN, "Port forwarding: server reports port-forwarding=$value")
        }
        state.value = value
    }
}
