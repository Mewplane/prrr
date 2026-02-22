// FRD: specs/frds/FRD-M008-android-project-setup.md
// FRD: specs/frds/FRD-M009-qr-code-scanner.md
// FRD: specs/frds/FRD-M010-configuration-storage.md
// FRD: specs/frds/FRD-M011-vpnservice-foundation.md
// FRD: specs/frds/FRD-M012-main-ui-compose.md
// FRD: specs/frds/FRD-M013-settings-battery-errors.md
package com.prrr.vpn.android

import android.app.Application
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import com.prrr.vpn.android.scanner.QRScannerScreen
import com.prrr.vpn.android.storage.ConfigurationManager
import com.prrr.vpn.android.storage.SaveResult
import com.prrr.vpn.android.ui.MainScreen
import com.prrr.vpn.android.ui.SettingsScreen
import com.prrr.vpn.android.ui.theme.PrrrVPNTheme
import com.prrr.vpn.android.viewmodel.VpnManager

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        Log.i("prrr", "prrr VPN MainActivity onCreate")

        // Test Rust FFI integration
        testRustIntegration()

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

    private fun testRustIntegration() {
        try {
            // Test parsing a dummy QR config (will fail with invalid data)
            val testQrData = "prrr://import?config=dGVzdA=="
            val config = uniffi.prrr_mobile.parseQrConfig(testQrData)
            Log.i("prrr", "✅ Rust FFI works! Parsed config: ${config.clientName}")
        } catch (e: uniffi.prrr_mobile.MobileException.InvalidConfig) {
            Log.i("prrr", "✅ Rust FFI works! Expected error for invalid data: ${e.reason}")
        } catch (e: Exception) {
            Log.e("prrr", "❌ Rust FFI error: ${e.message}", e)
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

    when (currentScreen) {
        "main" -> MainScreen(
            vpnManager = vpnManager,
            onSettingsClick = { currentScreen = "settings" }
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
