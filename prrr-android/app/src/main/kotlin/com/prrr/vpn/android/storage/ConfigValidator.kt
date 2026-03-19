package com.prrr.vpn.android.storage

import uniffi.prrr_mobile.VpnConfig

/**
 * Abstraction over config validation.
 * Decouples ConfigurationManager from Rust FFI for testability.
 */
interface ConfigValidator {
    /** Validate a VPN config. Throws on invalid data. */
    fun validate(config: VpnConfig)
}

/** Production implementation — delegates to Rust via UniFFI. */
class RustConfigValidator : ConfigValidator {
    override fun validate(config: VpnConfig) =
        uniffi.prrr_mobile.validateConfig(config)
}
