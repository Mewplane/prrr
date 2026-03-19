package com.prrr.vpn.android.scanner

import uniffi.prrr_mobile.VpnConfig

/**
 * Abstraction over config parsing from QR data URL.
 * Decouples ViewModel from Rust FFI for testability.
 */
interface ConfigParser {
    /** Parse a prrr://import?z=... URL into VpnConfig. Throws on invalid data. */
    fun parse(qrData: String): VpnConfig
}

/** Production implementation — delegates to Rust via UniFFI. */
class RustConfigParser : ConfigParser {
    override fun parse(qrData: String): VpnConfig =
        uniffi.prrr_mobile.parseQrConfig(qrData)
}
