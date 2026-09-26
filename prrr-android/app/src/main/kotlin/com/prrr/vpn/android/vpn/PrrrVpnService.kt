// FRD: specs/frds/FRD-M025-android-vpnservice-real-flow.md
package com.prrr.vpn.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.prrr.vpn.android.MainActivity
import com.prrr.vpn.android.R
import com.prrr.vpn.android.storage.ConfigurationManager
import com.prrr.vpn.android.viewmodel.PrrrVpnServiceAccessor
import uniffi.prrr_mobile.VpnConnection

private const val TAG = "PrrrVpnService"
private const val NOTIFICATION_ID = 1
private const val CHANNEL_ID = "vpn_service"
private const val CHANNEL_NAME = "VPN Service"
private const val VPN_SUBNET = "10.66.66.0"
private const val VPN_SUBNET_PREFIX = 24

/**
 * Android VpnService that delegates packet processing to the Rust tunnel pipeline.
 *
 * Flow:
 * 1. Load configuration from encrypted storage
 * 2. Create VPN interface via Builder (assigns IP, MTU, DNS, routes)
 * 3. Detach TUN fd and pass to Rust VpnConnection.connect(tunFd)
 * 4. Rust creates AndroidTun + EncryptedChannel + TunnelPipeline
 * 5. Pipeline runs until disconnect() cancels the CancellationToken
 */
class PrrrVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    var connection: VpnConnection? = null
        private set

    companion object {
        const val ACTION_CONNECT = "com.prrr.vpn.android.CONNECT"
        const val ACTION_DISCONNECT = "com.prrr.vpn.android.DISCONNECT"
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "VpnService onCreate")
        createNotificationChannel()
        PrrrVpnServiceAccessor.register(this)
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
        PrrrVpnServiceAccessor.unregister()
        super.onDestroy()
    }

    @Synchronized
    private fun connect() {
        Log.i(TAG, "connect() called")

        // If a previous connection exists, check if it's still active
        connection?.let { conn ->
            val status = conn.status()
            if (status == uniffi.prrr_mobile.ConnectionStatus.CONNECTED ||
                status == uniffi.prrr_mobile.ConnectionStatus.CONNECTING ||
                status == uniffi.prrr_mobile.ConnectionStatus.RECONNECTING) {
                Log.w(TAG, "Already connected (status=$status), ignoring")
                return
            }
            // Previous connection is in Error or Disconnected state — clean up
            Log.i(TAG, "Cleaning up stale connection (status=$status)")
            conn.disconnect()
            connection = null
            try { vpnInterface?.close() } catch (_: Exception) {}
            vpnInterface = null
        }

        // Promote to foreground immediately (required for API 26+)
        val notification = createNotification("Resolving server...")
        startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)

        // Load configuration from storage
        val config = ConfigurationManager.loadConfiguration(this)
        if (config == null) {
            Log.e(TAG, "No configuration found")
            updateNotification("Error: No configuration")
            stopSelf()
            return
        }

        Log.i(TAG, "Loaded config for: ${config.clientName}")

        // Resolve DNS on a background thread (Android blocks network on main thread),
        // then establish the VPN interface on the main thread.
        val serverHost = config.serverEndpoint.substringBeforeLast(":")
        Thread {
            val serverAddr = try {
                java.net.InetAddress.getByName(serverHost)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to resolve server: $serverHost: ${e.message}")
                android.os.Handler(mainLooper).post {
                    updateNotification("Error: DNS resolution failed")
                    stopSelf()
                }
                return@Thread
            }
            Log.i(TAG, "Resolved server $serverHost -> ${serverAddr.hostAddress}")

            // Post back to main thread to set up VPN interface (requires main thread)
            android.os.Handler(mainLooper).post {
                establishVpn(config, serverAddr)
            }
        }.start()
    }

    @Synchronized
    private fun establishVpn(config: uniffi.prrr_mobile.VpnConfig, serverAddr: java.net.InetAddress) {
        if (connection != null) {
            Log.w(TAG, "Already connected, ignoring")
            return
        }

        updateNotification("Connecting...")

        try {

            // Create VPN interface
            val builder = Builder()
                .setSession("Prrr")
                .addAddress(extractIp(config.assignedIp), extractPrefix(config.assignedIp))
                .setMtu(config.mtu.toInt())

            // Add DNS servers from config
            config.dnsServers.forEach { dns ->
                builder.addDnsServer(dns)
            }

            // Route all traffic through tunnel
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)

            // Exclude the server IP from the tunnel to prevent routing loop.
            builder.excludeRoute(android.net.IpPrefix(
                serverAddr, if (serverAddr is java.net.Inet6Address) 128 else 32
            ))
            Log.i(TAG, "Excluded server ${serverAddr.hostAddress} from VPN routes")

            // Local-LAN auto-exclusion (split-tunnel courtesy, FRD-001): keep the
            // active LAN subnet on the local link by default so a sibling on the
            // same Wi-Fi stays reachable. The Rust core is the single source of
            // truth for which prefixes to exclude. When full_tunnel is set, this
            // returns an empty list and the LAN is captured by the tunnel.
            val fullTunnel = config.fullTunnel == true
            uniffi.prrr_mobile.lanExcludedCidrs(fullTunnel).forEach { cidr ->
                val parts = cidr.split("/")
                val prefix = android.net.IpPrefix(
                    java.net.InetAddress.getByName(parts[0]),
                    parts.getOrNull(1)?.toIntOrNull() ?: 32
                )
                builder.excludeRoute(prefix)
                Log.i(TAG, "Excluded LAN prefix $cidr from VPN routes")
            }

            // Check VPN consent
            val prepareIntent = prepare(this)
            if (prepareIntent != null) {
                Log.e(TAG, "VPN consent not granted — prepare() returned non-null intent")
                Log.e(TAG, "Grant consent via: adb shell cmd appops set --uid <uid> ACTIVATE_VPN allow")
                updateNotification("Error: VPN consent required")
                stopSelf()
                return
            }

            // Establish VPN interface
            val iface = builder.establish()
            if (iface == null) {
                Log.e(TAG, "Failed to establish VPN interface (establish returned null)")
                updateNotification("Error: VPN setup failed")
                stopSelf()
                return
            }
            vpnInterface = iface

            Log.i(TAG, "VPN interface established")

            // Detach fd — transfers ownership to Rust (Rust will close it)
            val tunFd = iface.detachFd()

            // Initialize Rust VPN connection and start tunnel pipeline
            val conn = VpnConnection(config)
            conn.connect(tunFd)
            connection = conn

            Log.i(TAG, "Rust tunnel pipeline started with fd=$tunFd")

            updateNotification("Connecting...")

        } catch (e: Exception) {
            Log.e(TAG, "Connection failed", e)
            updateNotification("Error: ${e.message}")
            disconnect()
        }
    }

    @Synchronized
    private fun disconnect() {
        Log.i(TAG, "disconnect() called")

        // Disconnect Rust connection (cancels pipeline via CancellationToken)
        connection?.disconnect()
        connection = null

        // Close VPN interface (fd already detached, so this is a no-op on the fd)
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
            .setContentTitle("Prrr")
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

    /**
     * Extract prefix length from CIDR notation.
     * Example: "10.66.66.2/32" -> 32
     */
    private fun extractPrefix(cidr: String): Int {
        return cidr.split("/").getOrNull(1)?.toIntOrNull() ?: 32
    }
}
