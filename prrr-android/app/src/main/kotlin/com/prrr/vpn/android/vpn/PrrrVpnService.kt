// FRD: specs/frds/FRD-M011-vpnservice-foundation.md
package com.prrr.vpn.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.prrr.vpn.android.MainActivity
import com.prrr.vpn.android.R
import com.prrr.vpn.android.storage.ConfigurationManager
import uniffi.prrr_mobile.ConnectionStatus
import uniffi.prrr_mobile.VpnConnection
import java.io.FileInputStream
import java.io.FileOutputStream

private const val TAG = "PrrrVpnService"
private const val NOTIFICATION_ID = 1
private const val CHANNEL_ID = "vpn_service"
private const val CHANNEL_NAME = "VPN Service"

/**
 * Android VpnService implementation that manages system VPN interface.
 *
 * **Current Limitations:**
 * - Packet processing is a stub (reads from TUN but doesn't forward)
 * - No actual internet connectivity (requires Rust transport integration)
 * - This is foundation infrastructure for UI development
 *
 * **Future Work:**
 * - Integrate real QUIC/MASQUE transport
 * - Implement packet encryption/decryption
 * - Wire up actual tunneling
 */
class PrrrVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var connection: VpnConnection? = null
    private var packetThread: Thread? = null

    companion object {
        const val ACTION_CONNECT = "com.prrr.vpn.android.CONNECT"
        const val ACTION_DISCONNECT = "com.prrr.vpn.android.DISCONNECT"
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "VpnService onCreate")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand: action=${intent?.action}")

        when (intent?.action) {
            ACTION_CONNECT -> connect()
            ACTION_DISCONNECT -> disconnect()
            else -> {
                Log.w(TAG, "Unknown action: ${intent?.action}")
                stopSelf()
            }
        }

        return START_STICKY
    }

    override fun onDestroy() {
        Log.i(TAG, "VpnService onDestroy")
        disconnect()
        super.onDestroy()
    }

    @Synchronized
    private fun connect() {
        Log.i(TAG, "connect() called")

        // Check if already connected
        if (vpnInterface != null) {
            Log.w(TAG, "Already connected, ignoring")
            return
        }

        // Promote to foreground immediately (required for API 26+)
        val notification = createNotification("Connecting...")
        startForeground(NOTIFICATION_ID, notification)

        try {
            // Load configuration from storage
            val config = ConfigurationManager.loadConfiguration(this)
            if (config == null) {
                Log.e(TAG, "No configuration found")
                updateNotification("Error: No configuration")
                stopSelf()
                return
            }

            Log.i(TAG, "Loaded config for: ${config.clientName}")

            // Create VPN interface
            val builder = Builder()
                .setSession("prrr VPN")
                .addAddress(extractIp(config.assignedIp), 32)
                .setMtu(config.mtu.toInt())

            // Add DNS servers
            config.dnsServers.forEach { dns ->
                builder.addDnsServer(dns)
            }

            // Route all traffic through VPN
            builder.addRoute("0.0.0.0", 0)

            // Establish interface
            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                updateNotification("Error: VPN setup failed")
                stopSelf()
                return
            }

            Log.i(TAG, "VPN interface established")

            // Initialize Rust VPN connection
            connection = VpnConnection(config)
            connection?.connect()

            Log.i(TAG, "Rust connection initiated")

            // Check connection status
            val status = connection?.status()
            Log.i(TAG, "Connection status: $status")

            // Update notification
            when (status) {
                ConnectionStatus.CONNECTED -> updateNotification("Connected (Demo Mode)")
                ConnectionStatus.CONNECTING -> updateNotification("Connecting...")
                else -> updateNotification("Disconnected")
            }

            // Start packet processing (stub implementation)
            startPacketProcessing()

        } catch (e: Exception) {
            Log.e(TAG, "Connection failed", e)
            updateNotification("Error: ${e.message}")
            disconnect()
        }
    }

    @Synchronized
    private fun disconnect() {
        Log.i(TAG, "disconnect() called")

        // Stop packet processing thread
        packetThread?.interrupt()
        packetThread = null

        // Disconnect Rust connection
        connection?.disconnect()
        connection = null

        // Close VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        // Remove foreground notification
        stopForeground(STOP_FOREGROUND_REMOVE)

        // Stop service
        stopSelf()

        Log.i(TAG, "Disconnected")
    }

    /**
     * Start packet processing thread.
     *
     * **STUB IMPLEMENTATION:**
     * - Reads packets from TUN interface
     * - Logs packet size
     * - Discards packets (no forwarding)
     * - No internet connectivity will work
     *
     * **TODO:** Replace with real packet handling:
     * 1. Encrypt packets via Rust
     * 2. Send via QUIC to server
     * 3. Receive from server
     * 4. Decrypt via Rust
     * 5. Write back to TUN
     */
    private fun startPacketProcessing() {
        val fd = vpnInterface?.fileDescriptor
        if (fd == null) {
            Log.w(TAG, "No file descriptor, skipping packet processing")
            return
        }

        packetThread = Thread {
            val inputStream = FileInputStream(fd)
            // val outputStream = FileOutputStream(fd) // TODO: Use for writing packets back to TUN
            val buffer = ByteArray(32767) // Max IP packet size

            Log.i(TAG, "Packet processing thread started (STUB MODE)")

            try {
                while (!Thread.interrupted()) {
                    // Read packet from TUN interface
                    val length = inputStream.read(buffer)
                    if (length > 0) {
                        // In stub mode, just log and discard
                        Log.d(TAG, "Received packet from TUN: $length bytes (discarded)")

                        // TODO: Real implementation:
                        // val packet = buffer.copyOf(length)
                        // val encrypted = connection?.encryptPacket(packet)
                        // sendToServer(encrypted)
                    }

                    // TODO: Receive packets from server and write to TUN
                    // val received = receiveFromServer()
                    // val decrypted = connection?.decryptPacket(received)
                    // outputStream.write(decrypted)
                }
            } catch (e: InterruptedException) {
                Log.i(TAG, "Packet processing thread interrupted")
            } catch (e: Exception) {
                Log.e(TAG, "Error in packet processing", e)
            }

            Log.i(TAG, "Packet processing thread stopped")
        }

        packetThread?.start()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            CHANNEL_NAME,
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Shows VPN connection status"
            setShowBadge(false)
        }

        val manager = getSystemService(NotificationManager::class.java)
        manager?.createNotificationChannel(channel)
    }

    private fun createNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("prrr VPN")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        val notification = createNotification(text)
        val manager = getSystemService(NotificationManager::class.java)
        manager?.notify(NOTIFICATION_ID, notification)
    }

    /**
     * Extract IP address from CIDR notation.
     * Example: "10.66.66.2/32" -> "10.66.66.2"
     */
    private fun extractIp(cidr: String): String {
        return cidr.split("/").first()
    }
}
