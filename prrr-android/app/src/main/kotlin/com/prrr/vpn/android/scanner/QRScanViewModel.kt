// FRD: specs/frds/FRD-M009-qr-code-scanner.md
package com.prrr.vpn.android.scanner

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import uniffi.prrr_mobile.MobileException

private const val TAG = "QRScanVM"

class QRScanViewModel(
    private val configParser: ConfigParser = RustConfigParser(),
    private val frameCollector: FrameCollector = FrameCollector()
) : ViewModel() {
    private val _scanState = MutableStateFlow<ScanState>(ScanState.Idle)
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()

    fun onQRCodeDetected(rawValue: String) {
        val result = frameCollector.submit(rawValue) ?: run {
            Log.d(TAG, "Ignoring non-prrr QR (${rawValue.length} chars): ${rawValue.take(80)}")
            return
        }

        when (result) {
            is FrameCollector.Result.SingleFrame -> parseConfig(result.url)
            is FrameCollector.Result.Complete -> {
                Log.i(TAG, "Multi-frame complete: ${result.assembledUrl.length} chars")
                parseConfig(result.assembledUrl)
            }
            is FrameCollector.Result.NeedMore -> {
                Log.i(TAG, "Multi-frame: ${result.received}/${result.total} collected")
                _scanState.value = ScanState.Collecting(
                    received = result.received,
                    total = result.total
                )
            }
            is FrameCollector.Result.Error -> {
                _scanState.value = ScanState.Error(result.message)
            }
        }
    }

    private fun parseConfig(url: String) {
        _scanState.value = ScanState.Scanning
        viewModelScope.launch {
            try {
                val config = configParser.parse(url)
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
        frameCollector.reset()
    }
}
