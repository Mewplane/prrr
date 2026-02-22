// FRD: specs/frds/FRD-M013-settings-battery-errors.md
package com.prrr.vpn.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.prrr.vpn.android.util.BatteryOptimizationHelper
import com.prrr.vpn.android.viewmodel.VpnManager

private const val APP_VERSION = "1.0.0"

/**
 * Settings screen displaying configuration, management actions,
 * battery optimization guidance, and app information.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    vpnManager: VpnManager,
    onNavigateBack: () -> Unit,
    onNavigateToScanner: () -> Unit
) {
    val config by vpnManager.config.collectAsState()
    val context = LocalContext.current
    var showDeleteConfirmation by remember { mutableStateOf(false) }
    val isIgnoringBatteryOptimizations = remember {
        BatteryOptimizationHelper.isIgnoringBatteryOptimizations(context)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Navigate back"
                        )
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
        ) {
            // Connection Section
            SectionHeader("Connection")

            if (config != null) {
                val cfg = config!!
                SettingRow(label = "Client Name", value = cfg.clientName)
                SettingRow(label = "Server", value = cfg.serverEndpoint)
                SettingRow(label = "IP Address", value = cfg.assignedIp)
                SettingRow(label = "DNS", value = cfg.dnsServers.joinToString(", "))
                SettingRow(label = "MTU", value = cfg.mtu.toString())
            } else {
                Text(
                    text = "No configuration",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Configuration Section
            SectionHeader("Configuration")

            Button(
                onClick = onNavigateToScanner,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp)
            ) {
                Text("Import New Configuration")
            }

            Button(
                onClick = { showDeleteConfirmation = true },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                ),
                enabled = config != null
            ) {
                Text("Delete Configuration")
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Battery Section
            SectionHeader("Battery")

            if (!isIgnoringBatteryOptimizations) {
                BatteryWarningCard(
                    onOpenSettings = {
                        val intent = BatteryOptimizationHelper
                            .createBatteryOptimizationIntent(context)
                        context.startActivity(intent)
                    }
                )
            } else {
                Text(
                    text = "Battery optimization is disabled for this app.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // About Section
            SectionHeader("About")
            SettingRow(label = "Version", value = APP_VERSION)

            Spacer(modifier = Modifier.height(24.dp))
        }
    }

    // Delete confirmation dialog
    if (showDeleteConfirmation) {
        DeleteConfirmationDialog(
            onConfirm = {
                vpnManager.deleteConfiguration()
                showDeleteConfirmation = false
                onNavigateToScanner()
            },
            onDismiss = { showDeleteConfirmation = false }
        )
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(vertical = 8.dp)
    )
}

@Composable
private fun SettingRow(label: String, value: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .semantics { contentDescription = "$label: $value" }
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyLarge
        )
    }
}

@Composable
private fun BatteryWarningCard(onOpenSettings: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Battery Optimization Enabled",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            Text(
                text = "For reliable VPN connections, disable battery optimization for this app. " +
                    "Otherwise, the system may stop the VPN service to save battery.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            Button(onClick = onOpenSettings) {
                Text("Open Battery Settings")
            }
        }
    }
}

@Composable
private fun DeleteConfirmationDialog(
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Delete Configuration?") },
        text = {
            Text("This will remove your VPN configuration. You will need to scan a new QR code to reconnect.")
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(
                    "Delete",
                    color = MaterialTheme.colorScheme.error
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}
