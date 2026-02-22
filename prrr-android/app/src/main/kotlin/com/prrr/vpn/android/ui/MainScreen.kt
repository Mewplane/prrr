// FRD: specs/frds/FRD-M012-main-ui-compose.md
package com.prrr.vpn.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.prrr.vpn.android.viewmodel.ConnectionStatus
import com.prrr.vpn.android.viewmodel.VpnManager

/**
 * Main screen for VPN connection control.
 * Displays status, connection button, and statistics.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    vpnManager: VpnManager,
    onSettingsClick: () -> Unit = {}
) {
    val status by vpnManager.status.collectAsState()
    val config by vpnManager.config.collectAsState()
    val stats by vpnManager.stats.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("prrr VPN") },
                actions = {
                    IconButton(onClick = onSettingsClick) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Spacer(modifier = Modifier.height(60.dp))

            // Status icon (large, centered)
            StatusIcon(status = status)

            // Status text
            Text(
                text = getStatusText(status),
                style = MaterialTheme.typography.headlineMedium
            )

            // Server endpoint (if config exists)
            config?.let { cfg ->
                Text(
                    text = "via ${cfg.serverEndpoint}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.weight(1f))

            // Connection toggle button
            Button(
                onClick = { toggleConnection(vpnManager, status) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 40.dp)
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = getButtonColor(status)
                ),
                enabled = isButtonEnabled(status)
            ) {
                Text(
                    text = getButtonText(status),
                    style = MaterialTheme.typography.titleMedium
                )
            }

            // Stats card (when connected)
            if (status == ConnectionStatus.CONNECTED && stats != null) {
                Spacer(modifier = Modifier.height(24.dp))
                StatsCard(stats = stats!!)
            }

            Spacer(modifier = Modifier.height(60.dp))
        }
    }
}

private fun getStatusText(status: ConnectionStatus): String {
    return when (status) {
        ConnectionStatus.DISCONNECTED -> "Not Connected"
        ConnectionStatus.CONNECTING -> "Connecting..."
        ConnectionStatus.CONNECTED -> "Connected"
        ConnectionStatus.ERROR -> "Connection Error"
    }
}

private fun getButtonText(status: ConnectionStatus): String {
    return when (status) {
        ConnectionStatus.CONNECTED -> "Disconnect"
        ConnectionStatus.CONNECTING -> "Connecting..."
        else -> "Connect"
    }
}

private fun getButtonColor(status: ConnectionStatus): Color {
    return when (status) {
        ConnectionStatus.CONNECTED -> Color(0xFFEF5350) // Red for disconnect
        else -> Color(0xFF66BB6A) // Green for connect
    }
}

private fun isButtonEnabled(status: ConnectionStatus): Boolean {
    return status != ConnectionStatus.CONNECTING
}

private fun toggleConnection(vpnManager: VpnManager, status: ConnectionStatus) {
    when (status) {
        ConnectionStatus.CONNECTED -> vpnManager.disconnect()
        ConnectionStatus.DISCONNECTED, ConnectionStatus.ERROR -> vpnManager.connect()
        ConnectionStatus.CONNECTING -> { /* Do nothing */ }
    }
}
