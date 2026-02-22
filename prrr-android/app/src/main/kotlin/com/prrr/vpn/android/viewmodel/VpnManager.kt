// FRD: specs/frds/FRD-M012-main-ui-compose.md
// FRD: specs/frds/FRD-M013-settings-battery-errors.md
package com.prrr.vpn.android.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import com.prrr.vpn.android.storage.ConfigurationManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import uniffi.prrr_mobile.VpnConfig
import uniffi.prrr_mobile.ConnectionStats

/**
 * ViewModel for VPN connection management.
 * Bridges UI and VpnService, manages connection state.
 */
class VpnManager(application: Application) : AndroidViewModel(application) {

    private val _status = MutableStateFlow(ConnectionStatus.DISCONNECTED)
    val status: StateFlow<ConnectionStatus> = _status.asStateFlow()

    private val _config = MutableStateFlow<VpnConfig?>(null)
    val config: StateFlow<VpnConfig?> = _config.asStateFlow()

    private val _stats = MutableStateFlow<ConnectionStats?>(null)
    val stats: StateFlow<ConnectionStats?> = _stats.asStateFlow()

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

    fun connect() {
        // TODO: Start VpnService
    }

    fun disconnect() {
        // TODO: Stop VpnService
    }
}
