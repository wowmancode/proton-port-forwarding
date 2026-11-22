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

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.protonvpn.android.auth.usecase.CurrentUser
import com.protonvpn.android.settings.data.CurrentUserLocalSettingsManager
import com.protonvpn.android.vpn.VpnConnectionManager
import com.protonvpn.android.vpn.VpnUiDelegate
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class PortForwardingViewModel @Inject constructor(
    private val settingsManager: CurrentUserLocalSettingsManager,
    private val portForwardingManager: PortForwardingManager,
    private val securityCheck: PortForwardingSecurityCheck,
    private val vpnConnectionManager: VpnConnectionManager,
    currentUser: CurrentUser,
) : ViewModel() {

    data class CheckState(val isRunning: Boolean = false, val results: List<SecurityCheckItem>? = null)

    data class ViewState(
        val isEnabled: Boolean,
        val isRestricted: Boolean,
        val isStrictNat: Boolean,
        val isKeepAwake: Boolean,
        val status: PortForwardingStatus,
        val check: CheckState,
    )

    private val checkState = MutableStateFlow(CheckState())

    val viewState: StateFlow<ViewState?> = combine(
        settingsManager.rawCurrentUserSettingsFlow,
        currentUser.vpnUserFlow,
        portForwardingManager.status,
        checkState,
    ) { settings, vpnUser, status, check ->
        ViewState(
            isEnabled = settings.portForwarding,
            isRestricted = vpnUser?.isUserPlusOrAbove != true,
            isStrictNat = settings.randomizedNat,
            isKeepAwake = settings.portForwardingKeepAwake,
            status = status,
            check = check,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    fun setEnabled(enabled: Boolean) {
        viewModelScope.launch {
            settingsManager.setPortForwardingEnabled(enabled)
            checkState.value = CheckState() // Old results no longer apply.
        }
    }

    fun setKeepAwake(value: Boolean) {
        viewModelScope.launch { settingsManager.setPortForwardingKeepAwake(value) }
    }

    fun enableStrictNat() {
        viewModelScope.launch { settingsManager.setRandomizedNat(true) }
    }

    fun runSecurityCheck() {
        if (checkState.value.isRunning) return
        viewModelScope.launch {
            checkState.value = checkState.value.copy(isRunning = true)
            val results = runCatching { securityCheck.run() }.getOrElse { e ->
                listOf(SecurityCheckItem(CheckGroup.Traffic, "Security check", CheckStatus.Fail,
                    "The check couldn't run: ${e.message}"))
            }
            checkState.value = CheckState(isRunning = false, results = results)
        }
    }

    fun reconnect(uiDelegate: VpnUiDelegate) {
        vpnConnectionManager.reconnect("port forwarding security check", uiDelegate)
    }
}
