// FRD: specs/frds/FRD-M012-main-ui-compose.md
package com.prrr.vpn.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import uniffi.prrr_mobile.ConnectionStats

/**
 * Card displaying connection statistics.
 * Shows duration, bytes sent/received, and latency.
 */
@Composable
fun StatsCard(stats: ConnectionStats) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            StatRow("Transport", stats.activeTransport.uppercase())
            StatRow("Duration", formatDuration(stats.durationSecs))
            StatRow("Sent", formatBytes(stats.bytesSent))
            StatRow("Received", formatBytes(stats.bytesReceived))
            if (stats.serverLatencyMs > 0u) {
                StatRow("Latency", "${stats.serverLatencyMs}ms")
            }
        }
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium
        )
    }
}

private fun formatDuration(seconds: ULong): String {
    val hours = seconds / 3600u
    val minutes = (seconds % 3600u) / 60u
    return "${hours}h ${minutes}m"
}

private fun formatBytes(bytes: ULong): String {
    return when {
        bytes < 1024u -> "$bytes B"
        bytes < 1024u * 1024u -> "${bytes / 1024u} KB"
        bytes < 1024u * 1024u * 1024u -> "${bytes / (1024u * 1024u)} MB"
        else -> {
            val gb = bytes.toDouble() / (1024.0 * 1024.0 * 1024.0)
            "%.1f GB".format(gb)
        }
    }
}
