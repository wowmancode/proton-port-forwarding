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

package com.protonvpn.android.redesign.settings.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.PersistableBundle
import android.provider.Settings
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.protonvpn.android.R
import com.protonvpn.android.base.ui.ProtonOutlinedButton
import com.protonvpn.android.base.ui.ProtonSolidButton
import com.protonvpn.android.portforwarding.CheckGroup
import com.protonvpn.android.portforwarding.CheckStatus
import com.protonvpn.android.portforwarding.PortForwardingInactiveReason
import com.protonvpn.android.portforwarding.PortForwardingStatus
import com.protonvpn.android.portforwarding.PortForwardingViewModel
import com.protonvpn.android.portforwarding.SecurityCheckItem
import com.protonvpn.android.portforwarding.SecurityFix
import com.protonvpn.android.redesign.base.ui.SettingsToggleItem
import com.protonvpn.android.utils.openVpnSettings
import me.proton.core.compose.theme.ProtonTheme
import me.proton.core.compose.theme.captionWeak
import me.proton.core.compose.theme.defaultSmallWeak

@Composable
fun PortForwardingSettings(
    onClose: () -> Unit,
    state: PortForwardingViewModel.ViewState,
    onToggle: (Boolean) -> Unit,
    onKeepAwakeToggle: (Boolean) -> Unit,
    onUpgrade: () -> Unit,
    onRunCheck: () -> Unit,
    onEnableStrictNat: () -> Unit,
    onReconnect: () -> Unit,
) {
    val context = LocalContext.current
    SubSetting(
        title = stringResource(R.string.settings_port_forwarding_title),
        onClose = onClose
    ) {
        SettingsToggleItem(
            name = stringResource(R.string.settings_port_forwarding_title),
            description = stringResource(R.string.settings_port_forwarding_description),
            value = state.isEnabled && !state.isRestricted,
            needsUpgrade = state.isRestricted,
            onToggle = { if (state.isRestricted) onUpgrade() else onToggle(it) },
            onUpgrade = onUpgrade,
        )

        if (state.isEnabled && !state.isRestricted) {
            SettingsToggleItem(
                name = stringResource(R.string.settings_port_forwarding_keep_awake_title),
                description = stringResource(R.string.settings_port_forwarding_keep_awake_description),
                value = state.isKeepAwake,
                onToggle = { onKeepAwakeToggle(!state.isKeepAwake) },
            )
            StatusCard(state.status, onCopy = { port -> copyPort(context, port) })
            Text(
                text = stringResource(R.string.settings_port_forwarding_how_to),
                style = ProtonTheme.typography.defaultSmallWeak,
                modifier = Modifier.padding(16.dp)
            )
        }

        SettingsSectionHeading(
            stringResource(R.string.settings_port_forwarding_security_heading),
            Modifier.padding(horizontal = 16.dp)
        )
        Text(
            text = stringResource(R.string.settings_port_forwarding_security_description),
            style = ProtonTheme.typography.defaultSmallWeak,
            modifier = Modifier.padding(horizontal = 16.dp)
        )
        ProtonSolidButton(
            onClick = onRunCheck,
            loading = state.check.isRunning,
            modifier = Modifier.fillMaxWidth().padding(16.dp)
        ) {
            Text(stringResource(R.string.settings_port_forwarding_run_check))
        }

        state.check.results?.let { results ->
            val fails = results.count { it.status == CheckStatus.Fail }
            val warns = results.count { it.status == CheckStatus.Warn }
            Text(
                text = when {
                    fails > 0 -> stringResource(R.string.settings_port_forwarding_check_summary_fail, fails)
                    warns > 0 -> stringResource(R.string.settings_port_forwarding_check_summary_warn, warns)
                    else -> stringResource(R.string.settings_port_forwarding_check_summary_ok)
                },
                style = ProtonTheme.typography.body1Medium,
                color = when { fails > 0 -> ProtonTheme.colors.notificationError
                    warns > 0 -> ProtonTheme.colors.notificationWarning
                    else -> ProtonTheme.colors.notificationSuccess },
                modifier = Modifier.padding(horizontal = 16.dp)
            )
            CheckGroup.entries.forEach { group ->
                val items = results.filter { it.group == group }
                if (items.isNotEmpty()) {
                    Text(
                        text = stringResource(
                            if (group == CheckGroup.Traffic) R.string.settings_port_forwarding_group_traffic
                            else R.string.settings_port_forwarding_group_pf
                        ),
                        style = ProtonTheme.typography.body2Medium,
                        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp)
                    )
                    items.forEach { item ->
                        CheckRow(item) { fix ->
                            when (fix) {
                                SecurityFix.OpenVpnSystemSettings -> context.openVpnSettings()
                                SecurityFix.OpenBatterySettings -> context.startActivity(
                                    Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                )
                                SecurityFix.EnableStrictNat -> onEnableStrictNat()
                                SecurityFix.Reconnect -> onReconnect()
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun StatusCard(status: PortForwardingStatus, onCopy: (Int) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(ProtonTheme.colors.backgroundSecondary)
            .padding(16.dp)
    ) {
        when (status) {
            is PortForwardingStatus.Active -> {
                Text(stringResource(R.string.settings_port_forwarding_active_port), style = ProtonTheme.typography.captionWeak)
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    Text(status.port.toString(), style = ProtonTheme.typography.hero, modifier = Modifier.weight(1f))
                    ProtonOutlinedButton(onClick = { onCopy(status.port) }) {
                        Text(stringResource(R.string.settings_port_forwarding_copy))
                    }
                }
                Text(
                    stringResource(R.string.settings_port_forwarding_active_detail, status.serverName),
                    style = ProtonTheme.typography.defaultSmallWeak
                )
            }
            PortForwardingStatus.Starting ->
                Text(stringResource(R.string.settings_port_forwarding_status_starting), style = ProtonTheme.typography.body2Regular)
            is PortForwardingStatus.Failed ->
                Text(
                    stringResource(R.string.settings_port_forwarding_status_failed, status.retryInS),
                    style = ProtonTheme.typography.body2Regular,
                    color = ProtonTheme.colors.notificationError
                )
            is PortForwardingStatus.Inactive ->
                Text(
                    stringResource(
                        when (status.reason) {
                            PortForwardingInactiveReason.NotConnected -> R.string.settings_port_forwarding_status_not_connected
                            PortForwardingInactiveReason.NotP2pServer -> R.string.settings_port_forwarding_status_not_p2p
                            PortForwardingInactiveReason.ModerateNat -> R.string.settings_port_forwarding_status_moderate_nat
                            PortForwardingInactiveReason.FreePlan -> R.string.settings_port_forwarding_status_free
                            PortForwardingInactiveReason.SettingOff -> R.string.settings_port_forwarding_status_off
                        }
                    ),
                    style = ProtonTheme.typography.body2Regular
                )
        }
    }
}

@Composable
private fun CheckRow(item: SecurityCheckItem, onFix: (SecurityFix) -> Unit) {
    val symbol = when (item.status) {
        CheckStatus.Pass -> "✓"
        CheckStatus.Warn -> "!"
        CheckStatus.Fail -> "✕"
        CheckStatus.Info -> "i"
    }
    val color = when (item.status) {
        CheckStatus.Pass -> ProtonTheme.colors.notificationSuccess
        CheckStatus.Warn -> ProtonTheme.colors.notificationWarning
        CheckStatus.Fail -> ProtonTheme.colors.notificationError
        CheckStatus.Info -> ProtonTheme.colors.textWeak
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.Start
    ) {
        Text(symbol, color = color, style = ProtonTheme.typography.body1Bold, modifier = Modifier.width(24.dp))
        Column(Modifier.weight(1f)) {
            Text(item.title, style = ProtonTheme.typography.body2Medium)
            Text(item.detail, style = ProtonTheme.typography.defaultSmallWeak)
            item.fix?.let { fix ->
                ProtonOutlinedButton(onClick = { onFix(fix) }, modifier = Modifier.padding(top = 4.dp)) {
                    Text(
                        stringResource(
                            when (fix) {
                                SecurityFix.OpenVpnSystemSettings -> R.string.settings_port_forwarding_fix_kill_switch
                                SecurityFix.OpenBatterySettings -> R.string.settings_port_forwarding_fix_battery
                                SecurityFix.EnableStrictNat -> R.string.settings_port_forwarding_fix_strict_nat
                                SecurityFix.Reconnect -> R.string.settings_port_forwarding_fix_reconnect
                            }
                        )
                    )
                }
            }
        }
    }
}

/** Copies the port and marks the clip as sensitive so Android 13+ doesn't show it in the clipboard preview. */
private fun copyPort(context: Context, port: Int) {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return
    val clip = ClipData.newPlainText("Forwarded port", port.toString())
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    cm.setPrimaryClip(clip)
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU)
        Toast.makeText(context, R.string.settings_port_forwarding_copied, Toast.LENGTH_SHORT).show()
}

