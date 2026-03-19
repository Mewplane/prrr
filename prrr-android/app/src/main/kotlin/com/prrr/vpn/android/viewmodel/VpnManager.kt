// FRD: specs/frds/FRD-M025-android-vpnservice-real-flow.md
package com.prrr.vpn.android.viewmodel

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.IBinder
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.prrr.vpn.android.storage.ConfigurationManager
import com.prrr.vpn.android.vpn.PrrrVpnService
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import uniffi.prrr_mobile.ConnectionStats
import uniffi.prrr_mobile.VpnConfig

private const val TAG = "VpnManager"
private const val STATUS_POLL_INTERVAL_MS = 1000L

/**
 * ViewModel for VPN connection management.
 * Bridges UI and VpnService, manages connection state via status polling.
 */
class VpnManager(application: Application) : AndroidViewModel(application) {

    private val _status = MutableStateFlow(ConnectionStatus.DISCONNECTED)
    val status: StateFlow<ConnectionStatus> = _status.asStateFlow()

    private val _config = MutableStateFlow<VpnConfig?>(null)
    val config: StateFlow<VpnConfig?> = _config.asStateFlow()

    private val _stats = MutableStateFlow<ConnectionStats?>(null)
    val stats: StateFlow<ConnectionStats?> = _stats.asStateFlow()

    private var statusPollJob: Job? = null
    private var boundService: PrrrVpnService? = null

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            // PrrrVpnService doesn't use binding — connection field is accessed directly
            // via the service instance. We use startService pattern instead.
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            boundService = null
        }
    }

    init {
        loadConfiguration()
    }

    private fun loadConfiguration() {
        _config.value = ConfigurationManager.loadConfiguration(getApplication())
    }

    /**
     * Re-read configuration from encrypted storage and update the StateFlow.
     * Call after QR scan imports a new configuration.
     */
    fun reloadConfiguration() {
        _config.value = ConfigurationManager.loadConfiguration(getApplication())
    }

    /**
     * Delete stored configuration from encrypted storage and clear the StateFlow.
     * Always clears the in-memory config state, even if storage deletion fails.
     * Returns true if storage deletion succeeded.
     */
    fun deleteConfiguration(): Boolean {
        val deleted = ConfigurationManager.deleteConfiguration(getApplication())
        _config.value = null
        return deleted
    }

    /**
     * Check if VPN consent is needed. Returns the prepare Intent if consent is required,
     * or null if already granted. The caller (Activity) must launch this intent
     * via ActivityResultLauncher and call [connect] again when granted.
     */
    fun prepareVpn(): Intent? {
        return VpnService.prepare(getApplication())
    }

    /**
     * Start VPN connection via PrrrVpnService.
     * Caller MUST check [prepareVpn] first and obtain consent if needed.
     */
    fun connect() {
        _status.value = ConnectionStatus.CONNECTING
        val intent = Intent(getApplication(), PrrrVpnService::class.java).apply {
            action = PrrrVpnService.ACTION_CONNECT
        }
        getApplication<Application>().startForegroundService(intent)
        startStatusPolling()
    }

    /**
     * Stop VPN connection via PrrrVpnService.
     * The service cancels the Rust pipeline and tears down the VPN interface.
     */
    fun disconnect() {
        stopStatusPolling()
        val intent = Intent(getApplication(), PrrrVpnService::class.java).apply {
            action = PrrrVpnService.ACTION_DISCONNECT
        }
        getApplication<Application>().startService(intent)
        _status.value = ConnectionStatus.DISCONNECTED
        _stats.value = null
    }

    /**
     * Start polling the Rust VpnConnection for status and stats updates.
     * Runs every [STATUS_POLL_INTERVAL_MS] while connected.
     */
    private fun startStatusPolling() {
        stopStatusPolling()
        statusPollJob = viewModelScope.launch {
            while (true) {
                delay(STATUS_POLL_INTERVAL_MS)
                pollConnectionState()
            }
        }
    }

    private fun stopStatusPolling() {
        statusPollJob?.cancel()
        statusPollJob = null
    }

    /**
     * Poll the VpnService's Rust connection for current status and stats.
     * Maps Rust ConnectionStatus to Android ConnectionStatus enum.
     */
    private fun pollConnectionState() {
        // Access the service's connection directly via the companion-visible field
        // This works because VpnManager and PrrrVpnService are in the same process
        try {
            val conn = PrrrVpnServiceAccessor.getConnection()
            if (conn == null) {
                // Service not running or no connection
                if (_status.value != ConnectionStatus.DISCONNECTED) {
                    _status.value = ConnectionStatus.DISCONNECTED
                    _stats.value = null
                    stopStatusPolling()
                }
                return
            }

            val rustStatus = conn.status()
            _status.value = mapRustStatus(rustStatus)

            when (rustStatus) {
                uniffi.prrr_mobile.ConnectionStatus.CONNECTED -> {
                    _stats.value = conn.stats()
                }
                uniffi.prrr_mobile.ConnectionStatus.ERROR -> {
                    val errorMsg = conn.errorMessage()
                    Log.e(TAG, "Connection error: $errorMsg")
                    _stats.value = null
                    stopStatusPolling()
                }
                uniffi.prrr_mobile.ConnectionStatus.DISCONNECTED -> {
                    _stats.value = null
                    stopStatusPolling()
                }
                else -> {
                    // CONNECTING, RECONNECTING — keep polling
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error polling connection state", e)
        }
    }

    private fun mapRustStatus(rustStatus: uniffi.prrr_mobile.ConnectionStatus): ConnectionStatus {
        return when (rustStatus) {
            uniffi.prrr_mobile.ConnectionStatus.DISCONNECTED -> ConnectionStatus.DISCONNECTED
            uniffi.prrr_mobile.ConnectionStatus.CONNECTING -> ConnectionStatus.CONNECTING
            uniffi.prrr_mobile.ConnectionStatus.CONNECTED -> ConnectionStatus.CONNECTED
            uniffi.prrr_mobile.ConnectionStatus.RECONNECTING -> ConnectionStatus.CONNECTING
            uniffi.prrr_mobile.ConnectionStatus.ERROR -> ConnectionStatus.ERROR
        }
    }

    override fun onCleared() {
        super.onCleared()
        stopStatusPolling()
    }
}

/**
 * Static accessor for the VpnService's connection object.
 * Used by VpnManager to poll status without binding to the service.
 * Safe because VpnService and VpnManager run in the same process.
 */
object PrrrVpnServiceAccessor {
    private var service: PrrrVpnService? = null

    fun register(service: PrrrVpnService) {
        this.service = service
    }

    fun unregister() {
        service = null
    }

    fun getConnection(): uniffi.prrr_mobile.VpnConnection? {
        return service?.connection
    }
}
