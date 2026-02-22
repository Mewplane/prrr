// FRD: specs/frds/FRD-M009-qr-code-scanner.md
package com.prrr.vpn.android.scanner

import uniffi.prrr_mobile.VpnConfig

sealed class ScanState {
    data object Idle : ScanState()
    data object Scanning : ScanState()
    data class Success(val config: VpnConfig) : ScanState()
    data class Error(val message: String) : ScanState()
}
