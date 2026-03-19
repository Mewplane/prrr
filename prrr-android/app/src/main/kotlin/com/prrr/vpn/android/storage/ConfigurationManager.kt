// FRD: specs/frds/FRD-M010-configuration-storage.md
package com.prrr.vpn.android.storage

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import uniffi.prrr_mobile.MobileException
import uniffi.prrr_mobile.VpnConfig

private const val TAG = "ConfigurationManager"
private const val PREFS_NAME = "prrr_vpn_config"
private const val STORAGE_VERSION = 1

private const val KEY_STORAGE_VERSION = "storage_version"
private const val KEY_CLIENT_NAME = "client_name"
private const val KEY_SERVER_ENDPOINT = "server_endpoint"
private const val KEY_SERVER_PUBLIC_KEY = "server_public_key"
private const val KEY_SERVER_PQ_PUBLIC_KEY = "server_pq_public_key"
private const val KEY_CLIENT_PRIVATE_KEY = "client_private_key"
private const val KEY_ASSIGNED_IP = "assigned_ip"
private const val KEY_DNS_SERVERS = "dns_servers"
private const val KEY_MTU = "mtu"
private const val KEY_PREFERRED_BINDING = "preferred_binding"
private const val KEY_TRANSPORT_PROTOCOL = "transport_protocol"

/**
 * Manages secure persistent storage of VPN configuration.
 * Uses Android Keystore + EncryptedSharedPreferences for maximum security.
 */
object ConfigurationManager {

    /** Validator for config validation. Replaceable for testing. */
    var validator: ConfigValidator = RustConfigValidator()

    /**
     * Save VPN configuration to encrypted storage.
     * All data is encrypted using AES-256-GCM with keys from Android Keystore.
     */
    @Synchronized
    fun saveConfiguration(context: Context, config: VpnConfig): SaveResult {
        return try {
            // Validate configuration before saving
            try {
                validator.validate(config)
            } catch (e: MobileException.InvalidConfig) {
                Log.w(TAG, "Configuration validation failed: ${e.reason}")
                return SaveResult.ValidationFailed(e.reason)
            }

            val prefs = getEncryptedPreferences(context) ?: return SaveResult.EncryptionFailed

            prefs.edit().apply {
                putInt(KEY_STORAGE_VERSION, STORAGE_VERSION)
                putString(KEY_CLIENT_NAME, config.clientName)
                putString(KEY_SERVER_ENDPOINT, config.serverEndpoint)
                putString(KEY_SERVER_PUBLIC_KEY, config.serverPublicKey.toBase64())
                putString(KEY_SERVER_PQ_PUBLIC_KEY, config.serverPqPublicKey.toBase64())
                putString(KEY_CLIENT_PRIVATE_KEY, config.clientPrivateKey.toBase64())
                putString(KEY_ASSIGNED_IP, config.assignedIp)
                putString(KEY_DNS_SERVERS, config.dnsServers.joinToString(","))
                putInt(KEY_MTU, config.mtu.toInt())
                putString(KEY_PREFERRED_BINDING, config.preferredBinding)
                putString(KEY_TRANSPORT_PROTOCOL, config.transportProtocol)
                apply()
            }

            Log.i(TAG, "Configuration saved successfully for client: ${config.clientName}")
            SaveResult.Success
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save configuration", e)
            SaveResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Load VPN configuration from encrypted storage.
     * Returns null if no configuration is stored or if decryption fails.
     */
    @Synchronized
    fun loadConfiguration(context: Context): VpnConfig? {
        return try {
            val prefs = getEncryptedPreferences(context) ?: return null

            // Check if configuration exists
            if (!prefs.contains(KEY_CLIENT_NAME)) {
                return null
            }

            // Check storage version for future migrations
            val version = prefs.getInt(KEY_STORAGE_VERSION, 0)
            if (version != STORAGE_VERSION) {
                Log.w(TAG, "Storage version mismatch. Expected $STORAGE_VERSION, got $version")
                deleteConfiguration(context)
                return null
            }

            val config = VpnConfig(
                clientName = prefs.getString(KEY_CLIENT_NAME, null) ?: return null,
                serverEndpoint = prefs.getString(KEY_SERVER_ENDPOINT, null) ?: return null,
                serverPublicKey = prefs.getString(KEY_SERVER_PUBLIC_KEY, null)?.fromBase64() ?: return null,
                serverPqPublicKey = prefs.getString(KEY_SERVER_PQ_PUBLIC_KEY, null)?.fromBase64() ?: return null,
                clientPrivateKey = prefs.getString(KEY_CLIENT_PRIVATE_KEY, null)?.fromBase64() ?: return null,
                assignedIp = prefs.getString(KEY_ASSIGNED_IP, null) ?: return null,
                dnsServers = prefs.getString(KEY_DNS_SERVERS, null)?.split(",") ?: return null,
                mtu = prefs.getInt(KEY_MTU, 1280).toUShort(),
                preferredBinding = prefs.getString(KEY_PREFERRED_BINDING, null),
                transportProtocol = prefs.getString(KEY_TRANSPORT_PROTOCOL, null)
            )

            // Validate loaded configuration
            try {
                validator.validate(config)
            } catch (e: MobileException.InvalidConfig) {
                Log.w(TAG, "Loaded configuration is invalid: ${e.reason}")
                deleteConfiguration(context)
                return null
            }

            Log.i(TAG, "Configuration loaded successfully for client: ${config.clientName}")
            config
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load configuration", e)
            // If decryption fails (corrupted data), wipe storage
            deleteConfiguration(context)
            null
        }
    }

    /**
     * Delete all stored configuration data.
     */
    @Synchronized
    fun deleteConfiguration(context: Context): Boolean {
        return try {
            val prefs = getEncryptedPreferences(context) ?: return false
            prefs.edit().clear().apply()
            Log.i(TAG, "Configuration deleted successfully")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete configuration", e)
            false
        }
    }

    /**
     * Check if a configuration is currently stored.
     */
    @Synchronized
    fun hasConfiguration(context: Context): Boolean {
        return try {
            val prefs = getEncryptedPreferences(context) ?: return false
            prefs.contains(KEY_CLIENT_NAME)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to check configuration existence", e)
            false
        }
    }

    /**
     * Get EncryptedSharedPreferences instance.
     * Returns null if encryption setup fails.
     */
    private fun getEncryptedPreferences(context: Context): SharedPreferences? {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize encrypted preferences", e)
            null
        }
    }

    /**
     * Convert byte array to Base64 string.
     */
    private fun ByteArray.toBase64(): String {
        return Base64.encodeToString(this, Base64.NO_WRAP)
    }

    /**
     * Convert Base64 string to byte array.
     */
    private fun String.fromBase64(): ByteArray {
        return Base64.decode(this, Base64.NO_WRAP)
    }
}

/**
 * Result of save operation.
 */
sealed class SaveResult {
    data object Success : SaveResult()
    data class ValidationFailed(val reason: String) : SaveResult()
    data object EncryptionFailed : SaveResult()
    data class Error(val message: String) : SaveResult()
}
