// FRD: specs/frds/FRD-M008-android-project-setup.md
// FRD: specs/frds/FRD-M009-qr-code-scanner.md
// FRD: specs/frds/FRD-M010-configuration-storage.md
// FRD: specs/frds/FRD-M011-vpnservice-foundation.md
// FRD: specs/frds/FRD-M012-main-ui-compose.md
// FRD: specs/frds/FRD-M013-settings-battery-errors.md
package com.prrr.vpn.android

import android.app.Application
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import com.prrr.vpn.android.scanner.RustConfigParser
import com.prrr.vpn.android.scanner.QRScannerScreen
import com.prrr.vpn.android.storage.ConfigurationManager
import com.prrr.vpn.android.storage.SaveResult
import com.prrr.vpn.android.ui.MainScreen
import com.prrr.vpn.android.ui.SettingsScreen
import com.prrr.vpn.android.ui.theme.PrrrVPNTheme
import com.prrr.vpn.android.viewmodel.VpnManager

private const val TAG = "MainActivity"
private const val DEEP_LINK_IMPORT_PREFIX = "prrr://import?"
private const val DEEP_LINK_CONNECT = "prrr://connect"

/** Monotonically increasing counter — bumped each time a deep link saves a config. */
private val configReloadTrigger = mutableIntStateOf(0)

/** Bumped when a prrr://connect deep link requests VPN connect. */
private val connectTrigger = mutableIntStateOf(0)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        Log.i(TAG, "prrr VPN MainActivity onCreate")

        handleIntent(intent)

        setContent {
            PrrrVPNTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainNavigation()
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val data = intent?.data?.toString() ?: return

        if (data.startsWith(DEEP_LINK_CONNECT)) {
            Log.i(TAG, "Connect deep link received")
            connectTrigger.intValue++
            return
        }

        if (!data.startsWith(DEEP_LINK_IMPORT_PREFIX)) return

        Log.i(TAG, "Deep link received: ${data.take(80)}...")

        try {
            val config = RustConfigParser().parse(data)
            val result = ConfigurationManager.saveConfiguration(this, config)
            when (result) {
                is SaveResult.Success -> {
                    Log.i(TAG, "Deep link config saved: ${config.clientName}")
                    configReloadTrigger.intValue++
                }
                is SaveResult.ValidationFailed -> {
                    Log.w(TAG, "Deep link config validation failed: ${result.reason}")
                }
                is SaveResult.EncryptionFailed -> {
                    Log.e(TAG, "Deep link config encryption failed")
                }
                is SaveResult.Error -> {
                    Log.e(TAG, "Deep link config save error: ${result.message}")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Deep link config parse failed: ${e.message}")
        }
    }
}

@Composable
fun MainNavigation() {
    val context = LocalContext.current
    val vpnManager: VpnManager = viewModel(
        factory = VpnManagerFactory(context.applicationContext as Application)
    )
    var currentScreen by remember { mutableStateOf("main") }

    // Reload config when a deep link imports a new one (including via onNewIntent)
    val reloadTrigger by configReloadTrigger
    LaunchedEffect(reloadTrigger) {
        vpnManager.reloadConfiguration()
    }

    // Trigger VPN connect when prrr://connect deep link is received.
    // Waits for config to be loaded (handles race with concurrent import).
    val connectTriggerValue by connectTrigger
    val currentConfig by vpnManager.config.collectAsState()
    var lastHandledConnect by remember { mutableIntStateOf(0) }
    LaunchedEffect(connectTriggerValue, currentConfig) {
        if (connectTriggerValue > lastHandledConnect && currentConfig != null) {
            lastHandledConnect = connectTriggerValue
            vpnManager.connect()
        }
    }

    // VPN consent launcher — shows system dialog, then connects on approval
    val vpnConsentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            vpnManager.connect()
        } else {
            Log.w("MainNavigation", "VPN consent denied")
        }
    }

    val connectWithConsent: () -> Unit = {
        val prepareIntent = vpnManager.prepareVpn()
        if (prepareIntent != null) {
            vpnConsentLauncher.launch(prepareIntent)
        } else {
            vpnManager.connect()
        }
    }

    when (currentScreen) {
        "main" -> MainScreen(
            vpnManager = vpnManager,
            onSettingsClick = { currentScreen = "settings" },
            onConnect = connectWithConsent
        )
        "settings" -> SettingsScreen(
            vpnManager = vpnManager,
            onNavigateBack = { currentScreen = "main" },
            onNavigateToScanner = { currentScreen = "scanner" }
        )
        "scanner" -> QRScannerScreen(
            onConfigScanned = { config ->
                // Auto-save configuration
                val saveResult = ConfigurationManager.saveConfiguration(context, config)
                when (saveResult) {
                    is SaveResult.Success -> {
                        Log.i("prrr", "Configuration saved successfully")
                        vpnManager.reloadConfiguration()
                    }
                    is SaveResult.ValidationFailed -> {
                        Log.w("prrr", "Config validation failed: ${saveResult.reason}")
                    }
                    is SaveResult.EncryptionFailed -> {
                        Log.e("prrr", "Failed to initialize encryption")
                    }
                    is SaveResult.Error -> {
                        Log.e("prrr", "Save error: ${saveResult.message}")
                    }
                }
                currentScreen = "main"
            },
            onNavigateBack = {
                currentScreen = if (vpnManager.config.value != null) "main" else "settings"
            }
        )
    }
}

// ViewModelFactory for VpnManager
class VpnManagerFactory(private val application: Application) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(VpnManager::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return VpnManager(application) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}
