// FRD: specs/frds/FRD-M006-mobile-documentation.md
//
// prrr Mobile Library - Kotlin Integration Example
//
// This file demonstrates how to integrate the prrr-mobile Rust library
// into an Android application using the generated UniFFI Kotlin bindings.
//
// NOTE: This is a demonstration file showing API usage patterns.
// It is not meant to compile standalone - copy relevant sections into
// your Android app project.

package com.prrr.mobile.examples

import prrr_mobile.*
import kotlinx.coroutines.*

// MARK: - Example 1: QR Code Parsing

/**
 * Demonstrates parsing a VPN configuration from a QR code.
 *
 * The QR code format is: prrr://import?config=<base64-encoded-toml>
 * This is the primary way mobile clients receive configuration from the server.
 */
fun example1ParseQRConfiguration() {
    println("\n=== Example 1: QR Code Parsing ===\n")

    // This would normally come from scanning a QR code with the camera
    val qrData = """
        prrr://import?config=W2NsaWVudF0KbmFtZSA9ICJteS1hbmRyb2lkIgoKW3NlcnZlcl0KZW5kcG9pbnQgPSAidnBuLmV4YW1wbGUuY29tOjQ0MyIKcHVibGljX2tleSA9ICJ3RzVrYUZHTEFIemtkS3IvOExMWHUwSzFOaFZZWVEzZHFwN0EzUV94ajNrPSIKcHFfcHVibGljX2tleSA9ICJBUUlEQkFVR0J3Z0pDZ3NNRFE0UEVCRVRFEFVSUZGY1lHUm9iR0E9PSIKCltpbnRlcmZhY2VdCnByaXZhdGVfa2V5ID0gIllYRVFVNjhmUmtmQ3RwVWNlTE05RHorSGhLanlHQnBaeXBJWGs1VXBHCZZVT0iCmFkZHJlc3MgPSAiMTAuNjYuNjYuMi8zMiIKZG5zID0gWyIxLjEuMS4xIiwgIjguOC44LjgiXQptdHUgPSAxMjgw
    """.trimIndent()

    try {
        // Parse the QR code data into a VpnConfig object
        val config = parseQrConfig(qrData)

        println("✓ Successfully parsed configuration:")
        println("  Client name: ${config.clientName}")
        println("  Server endpoint: ${config.serverEndpoint}")
        println("  Assigned IP: ${config.assignedIp}")
        println("  DNS servers: ${config.dnsServers.joinToString(", ")}")
        println("  MTU: ${config.mtu}")
        println("  Server public key: ${config.serverPublicKey.size} bytes")
        println("  Server PQ public key: ${config.serverPqPublicKey.size} bytes")
        println("  Client private key: ${config.clientPrivateKey.size} bytes")

    } catch (e: MobileException.InvalidConfig) {
        // Handle specific error type
        println("✗ Invalid configuration: ${e.reason}")
        println("  Possible causes:")
        println("  - QR code format is incorrect")
        println("  - Base64 decoding failed")
        println("  - TOML structure is malformed")
        println("  - Required fields are missing")
    } catch (e: MobileException) {
        println("✗ Unexpected error: $e")
    } catch (e: Exception) {
        println("✗ System error: ${e.message}")
    }
}

// MARK: - Example 2: Configuration Validation

/**
 * Demonstrates validating a VPN configuration.
 *
 * Validation checks:
 * - Server endpoint is not empty
 * - Cryptographic keys have correct lengths
 * - IP address is in CIDR format
 * - DNS servers list is not empty
 * - MTU is in valid range (1280-1500)
 */
fun example2ValidateConfiguration() {
    println("\n=== Example 2: Configuration Validation ===\n")

    // Create a test configuration (normally from QR parsing)
    val validConfig = VpnConfig(
        clientName = "test-android",
        serverEndpoint = "vpn.example.com:443",
        serverPublicKey = UByteArray(32) { 0u },  // X25519 key
        serverPqPublicKey = UByteArray(1184) { 0u },  // ML-KEM-768 key
        clientPrivateKey = UByteArray(32) { 0u },  // X25519 key
        assignedIp = "10.66.66.2/32",
        dnsServers = listOf("1.1.1.1", "8.8.8.8"),
        mtu = 1100u
    )

    try {
        validateConfig(validConfig)
        println("✓ Configuration is valid")
    } catch (e: MobileException.InvalidConfig) {
        println("✗ Validation failed: ${e.reason}")
    } catch (e: MobileException) {
        println("✗ Unexpected error: $e")
    }

    // Example of invalid configuration
    val invalidConfig = VpnConfig(
        clientName = "test",
        serverEndpoint = "",  // Empty endpoint - invalid!
        serverPublicKey = UByteArray(32) { 0u },
        serverPqPublicKey = UByteArray(1184) { 0u },
        clientPrivateKey = UByteArray(32) { 0u },
        assignedIp = "10.66.66.2/32",
        dnsServers = listOf("1.1.1.1"),
        mtu = 1100u
    )

    try {
        validateConfig(invalidConfig)
        println("✓ Configuration is valid")
    } catch (e: MobileException.InvalidConfig) {
        println("✓ Correctly caught validation error: ${e.reason}")
    } catch (e: MobileException) {
        println("✗ Unexpected error: $e")
    }
}

// MARK: - Example 3: VPN Connection Lifecycle

/**
 * Demonstrates the complete VPN connection lifecycle.
 *
 * States:
 * - Disconnected: Initial state, no active connection
 * - Connecting: Connection attempt in progress
 * - Connected: VPN tunnel is active (stub simulation in this version)
 */
fun example3ConnectionLifecycle() {
    println("\n=== Example 3: VPN Connection Lifecycle ===\n")

    // Create a valid configuration
    val config = VpnConfig(
        clientName = "my-android",
        serverEndpoint = "vpn.example.com:443",
        serverPublicKey = UByteArray(32) { 0u },
        serverPqPublicKey = UByteArray(1184) { 0u },
        clientPrivateKey = UByteArray(32) { 0u },
        assignedIp = "10.66.66.2/32",
        dnsServers = listOf("1.1.1.1", "8.8.8.8"),
        mtu = 1100u
    )

    try {
        // Create VPN connection manager
        val connection = VpnConnection(config)
        println("✓ Created VPN connection")

        // Check initial status
        var status = connection.status()
        println("  Initial status: ${statusString(status)}")

        // Initiate connection
        connection.connect()
        println("✓ Connection initiated")

        // Check status immediately after connect()
        status = connection.status()
        println("  Status after connect(): ${statusString(status)}")

        // In a real Android app, you would use coroutines or callbacks for async operations
        // For this example, we'll simulate waiting for the async transition
        println("  Waiting for async connection simulation...")
        Thread.sleep(200)  // 200ms

        // Check status after async transition
        status = connection.status()
        println("  Status after 200ms: ${statusString(status)}")

        // Get connection statistics
        val stats = connection.stats()
        if (stats != null) {
            println("✓ Connection statistics:")
            println("  Bytes sent: ${stats.bytesSent}")
            println("  Bytes received: ${stats.bytesReceived}")
            println("  Duration: ${stats.durationSecs} seconds")
            println("  Server latency: ${stats.serverLatencyMs} ms")
        } else {
            println("  (No statistics available - not connected)")
        }

        // Disconnect
        connection.disconnect()
        println("✓ Disconnected")

        // Verify disconnected state
        status = connection.status()
        println("  Final status: ${statusString(status)}")

    } catch (e: MobileException.InvalidConfig) {
        println("✗ Invalid config: ${e.reason}")
    } catch (e: MobileException.ConnectionFailed) {
        println("✗ Connection failed: ${e.reason}")
    } catch (e: MobileException) {
        println("✗ Error: $e")
    } catch (e: Exception) {
        println("✗ System error: ${e.message}")
    }
}

// MARK: - Example 4: Error Handling Patterns

/**
 * Demonstrates comprehensive error handling for all error types.
 */
fun example4ErrorHandling() {
    println("\n=== Example 4: Error Handling ===\n")

    // Example 1: Parse error (invalid QR code)
    try {
        parseQrConfig("invalid-qr-code")
    } catch (e: MobileException.InvalidConfig) {
        println("✓ Caught InvalidConfig: ${e.reason}")
    } catch (e: MobileException) {
        println("✗ Unexpected error type: $e")
    } catch (e: Exception) {
        println("✗ System error: ${e.message}")
    }

    // Example 2: Connection while already connecting (would fail)
    val config = VpnConfig(
        clientName = "test",
        serverEndpoint = "vpn.example.com:443",
        serverPublicKey = UByteArray(32) { 0u },
        serverPqPublicKey = UByteArray(1184) { 0u },
        clientPrivateKey = UByteArray(32) { 0u },
        assignedIp = "10.66.66.2/32",
        dnsServers = listOf("1.1.1.1"),
        mtu = 1100u
    )

    try {
        val connection = VpnConnection(config)
        connection.connect()
        connection.connect()  // Second connect should fail
    } catch (e: MobileException.InvalidConfig) {
        println("✓ Caught InvalidConfig (expected for double-connect): ${e.reason}")
    } catch (e: MobileException.ConnectionFailed) {
        println("Connection failed: ${e.reason}")
    } catch (e: MobileException) {
        println("Error: $e")
    } catch (e: Exception) {
        println("System error: ${e.message}")
    }
}

// MARK: - Example 5: Android App Integration Pattern with Coroutines

/**
 * Demonstrates a realistic Android app integration pattern using Kotlin coroutines.
 *
 * This shows how to integrate prrr-mobile into an Android ViewModel with:
 * - StateFlow for reactive state management
 * - Coroutines for async operations
 * - User feedback
 * - Error handling
 */
class VPNViewModel {
    private val _status = MutableStateFlow<ConnectionStatus>(ConnectionStatus.DISCONNECTED)
    val status: StateFlow<ConnectionStatus> = _status

    private val _stats = MutableStateFlow<ConnectionStats?>(null)
    val stats: StateFlow<ConnectionStats?> = _stats

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage

    private var connection: VpnConnection? = null
    private var statusCheckJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    fun importConfiguration(qrData: String) {
        try {
            val config = parseQrConfig(qrData)
            validateConfig(config)

            // Save config and create connection
            connection = VpnConnection(config)
            _errorMessage.value = null

            println("✓ Configuration imported successfully")
        } catch (e: MobileException.InvalidConfig) {
            _errorMessage.value = "Invalid configuration: ${e.reason}"
        } catch (e: MobileException) {
            _errorMessage.value = "Import failed: $e"
        } catch (e: Exception) {
            _errorMessage.value = "System error: ${e.message}"
        }
    }

    fun connect() {
        val conn = connection
        if (conn == null) {
            _errorMessage.value = "No configuration loaded"
            return
        }

        try {
            conn.connect()
            _status.value = conn.status()
            _errorMessage.value = null

            // Start polling for status updates
            startStatusPolling()

        } catch (e: MobileException.InvalidConfig) {
            _errorMessage.value = "Connection failed: ${e.reason}"
        } catch (e: MobileException.ConnectionFailed) {
            _errorMessage.value = "Connection failed: ${e.reason}"
        } catch (e: MobileException) {
            _errorMessage.value = "Error: $e"
        } catch (e: Exception) {
            _errorMessage.value = "System error: ${e.message}"
        }
    }

    fun disconnect() {
        connection?.disconnect()
        _status.value = ConnectionStatus.DISCONNECTED
        _stats.value = null
        stopStatusPolling()
    }

    private fun startStatusPolling() {
        stopStatusPolling()

        statusCheckJob = scope.launch {
            while (isActive) {
                val conn = connection ?: break

                _status.value = conn.status()
                _stats.value = conn.stats()

                // Stop polling once connected or in error state
                if (_status.value == ConnectionStatus.CONNECTED ||
                    _status.value == ConnectionStatus.DISCONNECTED) {
                    break
                }

                delay(100)  // Check every 100ms
            }
        }
    }

    private fun stopStatusPolling() {
        statusCheckJob?.cancel()
        statusCheckJob = null
    }

    fun onCleared() {
        scope.cancel()
    }
}

// MARK: - Example 6: Jetpack Compose Integration

/**
 * Example of using VPNViewModel in a Jetpack Compose UI.
 *
 * This shows reactive state updates and user interaction.
 */
@Composable
fun VPNScreen(viewModel: VPNViewModel) {
    val status by viewModel.status.collectAsState()
    val stats by viewModel.stats.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Status display
        Text(
            text = statusString(status),
            style = MaterialTheme.typography.h4,
            modifier = Modifier.padding(bottom = 16.dp)
        )

        // Error message
        errorMessage?.let { message ->
            Text(
                text = message,
                color = MaterialTheme.colors.error,
                modifier = Modifier.padding(bottom = 16.dp)
            )
        }

        // Connection button
        Button(
            onClick = {
                when (status) {
                    ConnectionStatus.DISCONNECTED -> viewModel.connect()
                    ConnectionStatus.CONNECTED -> viewModel.disconnect()
                    else -> {} // Disabled during transition
                }
            },
            enabled = status == ConnectionStatus.DISCONNECTED ||
                     status == ConnectionStatus.CONNECTED
        ) {
            Text(
                when (status) {
                    ConnectionStatus.CONNECTED -> "Disconnect"
                    else -> "Connect"
                }
            )
        }

        // Statistics
        stats?.let { s ->
            Column(
                modifier = Modifier.padding(top = 16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("Bytes sent: ${s.bytesSent}")
                Text("Bytes received: ${s.bytesReceived}")
                Text("Duration: ${s.durationSecs}s")
                Text("Latency: ${s.serverLatencyMs}ms")
            }
        }
    }
}

// MARK: - Helper Functions

/**
 * Convert ConnectionStatus to human-readable string
 */
fun statusString(status: ConnectionStatus): String {
    return when (status) {
        ConnectionStatus.DISCONNECTED -> "Disconnected"
        ConnectionStatus.CONNECTING -> "Connecting..."
        ConnectionStatus.CONNECTED -> "Connected"
    }
}

// MARK: - Main Entry Point

/**
 * Run all examples
 */
fun runAllExamples() {
    println("========================================")
    println("prrr Mobile Library - Kotlin Examples")
    println("========================================")

    example1ParseQRConfiguration()
    example2ValidateConfiguration()
    example3ConnectionLifecycle()
    example4ErrorHandling()

    println("\n========================================")
    println("All examples completed!")
    println("========================================\n")
}

// Uncomment to run examples (when integrated into Android app):
// fun main() {
//     runAllExamples()
// }
