// FRD: specs/frds/FRD-M006-mobile-documentation.md
//
// prrr Mobile Library - Swift Integration Example
//
// This file demonstrates how to integrate the prrr-mobile Rust library
// into an iOS application using the generated UniFFI Swift bindings.
//
// NOTE: This is a demonstration file showing API usage patterns.
// It is not meant to compile standalone - copy relevant sections into
// your iOS app project.

import Foundation
import prrr_mobile  // Generated UniFFI bindings

// MARK: - Example 1: QR Code Parsing

/// Demonstrates parsing a VPN configuration from a QR code.
///
/// The QR code format is: prrr://import?config=<base64-encoded-toml>
/// This is the primary way mobile clients receive configuration from the server.
func example1_parseQRConfiguration() {
    print("\n=== Example 1: QR Code Parsing ===\n")

    // This would normally come from scanning a QR code with the camera
    let qrData = """
    prrr://import?config=W2NsaWVudF0KbmFtZSA9ICJteS1pcGhvbmUiCgpbc2VydmVyXQplbmRwb2ludCA9ICJ2cG4uZXhhbXBsZS5jb206NDQzIgpwdWJsaWNfa2V5ID0gIndHNWthRkdMQUh6a2RLci84TExYdTBLMU5oVllZUTNkcXA3QTNRX3hqM2s9IgpwcV9wdWJsaWNfa2V5ID0gIkFRSURCQVVHQndnSkNnc01EUTRQRUJFU0V4UVZGaGNZR1JvYkdBPT0iCgpbaW50ZXJmYWNlXQpwcml2YXRlX2tleSA9ICJZWEVRVTY4ZlJrZkN0cFVjZUxNOUR6K0hoS2p5R0JwWnlwSVhrNVVwR3M2VT0iCmFkZHJlc3MgPSAiMTAuNjYuNjYuMi8zMiIKZG5zID0gWyIxLjEuMS4xIiwgIjguOC44LjgiXQptdHUgPSAxMjgw
    """

    do {
        // Parse the QR code data into a VpnConfig struct
        let config = try parseQrConfig(qrData: qrData)

        print("✓ Successfully parsed configuration:")
        print("  Client name: \(config.clientName)")
        print("  Server endpoint: \(config.serverEndpoint)")
        print("  Assigned IP: \(config.assignedIp)")
        print("  DNS servers: \(config.dnsServers.joined(separator: ", "))")
        print("  MTU: \(config.mtu)")
        print("  Server public key: \(config.serverPublicKey.count) bytes")
        print("  Server PQ public key: \(config.serverPqPublicKey.count) bytes")
        print("  Client private key: \(config.clientPrivateKey.count) bytes")

    } catch let error as MobileError {
        // Handle specific error types
        switch error {
        case .InvalidConfig(let reason):
            print("✗ Invalid configuration: \(reason)")
            print("  Possible causes:")
            print("  - QR code format is incorrect")
            print("  - Base64 decoding failed")
            print("  - TOML structure is malformed")
            print("  - Required fields are missing")
        default:
            print("✗ Unexpected error: \(error)")
        }
    } catch {
        print("✗ System error: \(error)")
    }
}

// MARK: - Example 2: Configuration Validation

/// Demonstrates validating a VPN configuration.
///
/// Validation checks:
/// - Server endpoint is not empty
/// - Cryptographic keys have correct lengths
/// - IP address is in CIDR format
/// - DNS servers list is not empty
/// - MTU is in valid range (1280-1500)
func example2_validateConfiguration() {
    print("\n=== Example 2: Configuration Validation ===\n")

    // Create a test configuration (normally from QR parsing)
    let validConfig = VpnConfig(
        clientName: "test-iphone",
        serverEndpoint: "vpn.example.com:443",
        serverPublicKey: [UInt8](repeating: 0, count: 32),  // X25519 key
        serverPqPublicKey: [UInt8](repeating: 0, count: 1184),  // ML-KEM-768 key
        clientPrivateKey: [UInt8](repeating: 0, count: 32),  // X25519 key
        assignedIp: "10.66.66.2/32",
        dnsServers: ["1.1.1.1", "8.8.8.8"],
        mtu: 1100
    )

    do {
        try validateConfig(config: validConfig)
        print("✓ Configuration is valid")
    } catch let error as MobileError {
        switch error {
        case .InvalidConfig(let reason):
            print("✗ Validation failed: \(reason)")
        default:
            print("✗ Unexpected error: \(error)")
        }
    }

    // Example of invalid configuration
    let invalidConfig = VpnConfig(
        clientName: "test",
        serverEndpoint: "",  // Empty endpoint - invalid!
        serverPublicKey: [UInt8](repeating: 0, count: 32),
        serverPqPublicKey: [UInt8](repeating: 0, count: 1184),
        clientPrivateKey: [UInt8](repeating: 0, count: 32),
        assignedIp: "10.66.66.2/32",
        dnsServers: ["1.1.1.1"],
        mtu: 1100
    )

    do {
        try validateConfig(config: invalidConfig)
        print("✓ Configuration is valid")
    } catch let error as MobileError {
        switch error {
        case .InvalidConfig(let reason):
            print("✓ Correctly caught validation error: \(reason)")
        default:
            print("✗ Unexpected error: \(error)")
        }
    }
}

// MARK: - Example 3: VPN Connection Lifecycle

/// Demonstrates the complete VPN connection lifecycle.
///
/// States:
/// - Disconnected: Initial state, no active connection
/// - Connecting: Connection attempt in progress
/// - Connected: VPN tunnel is active (stub simulation in this version)
func example3_connectionLifecycle() {
    print("\n=== Example 3: VPN Connection Lifecycle ===\n")

    // Create a valid configuration
    let config = VpnConfig(
        clientName: "my-iphone",
        serverEndpoint: "vpn.example.com:443",
        serverPublicKey: [UInt8](repeating: 0, count: 32),
        serverPqPublicKey: [UInt8](repeating: 0, count: 1184),
        clientPrivateKey: [UInt8](repeating: 0, count: 32),
        assignedIp: "10.66.66.2/32",
        dnsServers: ["1.1.1.1", "8.8.8.8"],
        mtu: 1100
    )

    do {
        // Create VPN connection manager
        let connection = try VpnConnection(config: config)
        print("✓ Created VPN connection")

        // Check initial status
        var status = connection.status()
        print("  Initial status: \(statusString(status))")

        // Initiate connection
        try connection.connect()
        print("✓ Connection initiated")

        // Check status immediately after connect()
        status = connection.status()
        print("  Status after connect(): \(statusString(status))")

        // In a real iOS app, you would poll or use notifications to detect state changes
        // For this example, we'll simulate waiting for the async transition
        print("  Waiting for async connection simulation...")
        Thread.sleep(forTimeInterval: 0.2)  // 200ms

        // Check status after async transition
        status = connection.status()
        print("  Status after 200ms: \(statusString(status))")

        // Get connection statistics
        if let stats = connection.stats() {
            print("✓ Connection statistics:")
            print("  Bytes sent: \(stats.bytesSent)")
            print("  Bytes received: \(stats.bytesReceived)")
            print("  Duration: \(stats.durationSecs) seconds")
            print("  Server latency: \(stats.serverLatencyMs) ms")
        } else {
            print("  (No statistics available - not connected)")
        }

        // Disconnect
        connection.disconnect()
        print("✓ Disconnected")

        // Verify disconnected state
        status = connection.status()
        print("  Final status: \(statusString(status))")

    } catch let error as MobileError {
        switch error {
        case .InvalidConfig(let reason):
            print("✗ Invalid config: \(reason)")
        case .ConnectionFailed(let reason):
            print("✗ Connection failed: \(reason)")
        default:
            print("✗ Error: \(error)")
        }
    } catch {
        print("✗ System error: \(error)")
    }
}

// MARK: - Example 4: Error Handling Patterns

/// Demonstrates comprehensive error handling for all error types.
func example4_errorHandling() {
    print("\n=== Example 4: Error Handling ===\n")

    // Example 1: Parse error (invalid QR code)
    do {
        _ = try parseQrConfig(qrData: "invalid-qr-code")
    } catch let error as MobileError {
        switch error {
        case .InvalidConfig(let reason):
            print("✓ Caught InvalidConfig: \(reason)")
        default:
            print("✗ Unexpected error type: \(error)")
        }
    } catch {
        print("✗ System error: \(error)")
    }

    // Example 2: Connection while already connecting (would fail)
    let config = VpnConfig(
        clientName: "test",
        serverEndpoint: "vpn.example.com:443",
        serverPublicKey: [UInt8](repeating: 0, count: 32),
        serverPqPublicKey: [UInt8](repeating: 0, count: 1184),
        clientPrivateKey: [UInt8](repeating: 0, count: 32),
        assignedIp: "10.66.66.2/32",
        dnsServers: ["1.1.1.1"],
        mtu: 1100
    )

    do {
        let connection = try VpnConnection(config: config)
        try connection.connect()
        try connection.connect()  // Second connect should fail
    } catch let error as MobileError {
        switch error {
        case .InvalidConfig(let reason):
            print("✓ Caught InvalidConfig (expected for double-connect): \(reason)")
        case .ConnectionFailed(let reason):
            print("Connection failed: \(reason)")
        default:
            print("Error: \(error)")
        }
    } catch {
        print("System error: \(error)")
    }
}

// MARK: - Example 5: iOS App Integration Pattern

/// Demonstrates a realistic iOS app integration pattern using SwiftUI.
///
/// This shows how to integrate prrr-mobile into a SwiftUI view with:
/// - Observable state management
/// - User feedback
/// - Error handling
/// - Async state transitions
class VPNViewModel: ObservableObject {
    @Published var status: ConnectionStatus = .Disconnected
    @Published var stats: ConnectionStats?
    @Published var errorMessage: String?

    private var connection: VpnConnection?
    private var statusCheckTimer: Timer?

    func importConfiguration(from qrData: String) {
        do {
            let config = try parseQrConfig(qrData: qrData)
            try validateConfig(config: config)

            // Save config and create connection
            self.connection = try VpnConnection(config: config)
            self.errorMessage = nil

            print("✓ Configuration imported successfully")
        } catch let error as MobileError {
            switch error {
            case .InvalidConfig(let reason):
                self.errorMessage = "Invalid configuration: \(reason)"
            default:
                self.errorMessage = "Import failed: \(error)"
            }
        } catch {
            self.errorMessage = "System error: \(error)"
        }
    }

    func connect() {
        guard let connection = connection else {
            self.errorMessage = "No configuration loaded"
            return
        }

        do {
            try connection.connect()
            self.status = connection.status()
            self.errorMessage = nil

            // Start polling for status updates
            startStatusPolling()

        } catch let error as MobileError {
            switch error {
            case .InvalidConfig(let reason):
                self.errorMessage = "Connection failed: \(reason)"
            case .ConnectionFailed(let reason):
                self.errorMessage = "Connection failed: \(reason)"
            default:
                self.errorMessage = "Error: \(error)"
            }
        } catch {
            self.errorMessage = "System error: \(error)"
        }
    }

    func disconnect() {
        connection?.disconnect()
        self.status = .Disconnected
        self.stats = nil
        stopStatusPolling()
    }

    private func startStatusPolling() {
        stopStatusPolling()

        statusCheckTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            guard let self = self, let connection = self.connection else { return }

            self.status = connection.status()
            self.stats = connection.stats()

            // Stop polling once connected or in error state
            if self.status == .Connected || self.status == .Disconnected {
                self.stopStatusPolling()
            }
        }
    }

    private func stopStatusPolling() {
        statusCheckTimer?.invalidate()
        statusCheckTimer = nil
    }
}

// MARK: - Helper Functions

/// Convert ConnectionStatus to human-readable string
func statusString(_ status: ConnectionStatus) -> String {
    switch status {
    case .Disconnected:
        return "Disconnected"
    case .Connecting:
        return "Connecting..."
    case .Connected:
        return "Connected"
    }
}

// MARK: - Main Entry Point

/// Run all examples
func runAllExamples() {
    print("========================================")
    print("prrr Mobile Library - Swift Examples")
    print("========================================")

    example1_parseQRConfiguration()
    example2_validateConfiguration()
    example3_connectionLifecycle()
    example4_errorHandling()

    print("\n========================================")
    print("All examples completed!")
    print("========================================\n")
}

// Uncomment to run examples (when integrated into iOS app):
// runAllExamples()
