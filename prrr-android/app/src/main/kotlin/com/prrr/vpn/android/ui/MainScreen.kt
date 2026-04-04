package com.prrr.vpn.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.prrr.vpn.android.ui.theme.PrrrBlack
import com.prrr.vpn.android.ui.theme.PrrrDanger
import com.prrr.vpn.android.ui.theme.PrrrTextDim
import com.prrr.vpn.android.ui.theme.PrrrWhite
import com.prrr.vpn.android.viewmodel.ConnectionStatus
import com.prrr.vpn.android.viewmodel.VpnManager

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    vpnManager: VpnManager,
    onSettingsClick: () -> Unit = {},
    onConnect: () -> Unit = { vpnManager.connect() }
) {
    val status by vpnManager.status.collectAsState()
    val config by vpnManager.config.collectAsState()
    val stats by vpnManager.stats.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Prrr") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = PrrrBlack,
                    titleContentColor = PrrrWhite,
                    actionIconContentColor = PrrrWhite
                ),
                actions = {
                    IconButton(onClick = onSettingsClick) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                }
            )
        },
        containerColor = PrrrBlack
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Spacer(modifier = Modifier.height(40.dp))

            // Animated cat status icon
            StatusIcon(status = status)

            // Status text
            Text(
                text = getStatusText(status),
                style = MaterialTheme.typography.headlineMedium,
                color = PrrrWhite
            )

            // Server endpoint
            config?.let { cfg ->
                Text(
                    text = "via ${cfg.serverEndpoint}",
                    style = MaterialTheme.typography.bodySmall,
                    color = PrrrTextDim
                )
            }

            Spacer(modifier = Modifier.weight(1f))

            // Connection toggle button
            Button(
                onClick = { toggleConnection(vpnManager, status, onConnect) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 40.dp)
                    .height(56.dp),
                shape = RoundedCornerShape(8.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = getButtonColor(status),
                    contentColor = getButtonTextColor(status),
                    disabledContainerColor = PrrrTextDim.copy(alpha = 0.3f)
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
        ConnectionStatus.CONNECTED -> PrrrDanger
        else -> PrrrWhite
    }
}

private fun getButtonTextColor(status: ConnectionStatus): Color {
    return when (status) {
        ConnectionStatus.CONNECTED -> PrrrWhite
        else -> PrrrBlack
    }
}

private fun isButtonEnabled(status: ConnectionStatus): Boolean {
    return status != ConnectionStatus.CONNECTING
}

private fun toggleConnection(vpnManager: VpnManager, status: ConnectionStatus, onConnect: () -> Unit) {
    when (status) {
        ConnectionStatus.CONNECTED -> vpnManager.disconnect()
        ConnectionStatus.DISCONNECTED, ConnectionStatus.ERROR -> onConnect()
        ConnectionStatus.CONNECTING -> { /* Do nothing */ }
    }
}
