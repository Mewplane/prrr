// FRD: specs/frds/FRD-M009-qr-code-scanner.md
package com.prrr.vpn.android.scanner

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import uniffi.prrr_mobile.MobileException
import uniffi.prrr_mobile.parseQrConfig

private const val PRRR_URL_PREFIX = "prrr://import"
private const val ERROR_NOT_PRRR_QR = "This is not a prrr VPN config QR code"

class QRScanViewModel : ViewModel() {
    private val _scanState = MutableStateFlow<ScanState>(ScanState.Idle)
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()

    fun onQRCodeDetected(rawValue: String) {
        if (!rawValue.startsWith(PRRR_URL_PREFIX)) {
            _scanState.value = ScanState.Error(ERROR_NOT_PRRR_QR)
            return
        }

        _scanState.value = ScanState.Scanning

        viewModelScope.launch {
            try {
                val config = parseQrConfig(rawValue)
                _scanState.value = ScanState.Success(config)
            } catch (e: MobileException.InvalidConfig) {
                _scanState.value = ScanState.Error(e.reason)
            } catch (e: Exception) {
                _scanState.value = ScanState.Error("Failed to parse QR code: ${e.message}")
            }
        }
    }

    fun resetState() {
        _scanState.value = ScanState.Idle
    }
}
