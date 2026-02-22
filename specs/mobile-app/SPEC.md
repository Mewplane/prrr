# Mobile Application Specification

**Version:** 1.0  
**Date:** 2026-02-21  
**Status:** Draft

## Executive Summary

This specification defines the development of native mobile applications for iOS and Android that provide VPN connectivity using the prrr protocol. The applications will share a common Rust core while implementing platform-native UI and system integrations.

## 1. Overview

### 1.1 Goals

- Provide native mobile VPN clients for prrr on iOS and Android
- Maximize code reuse through shared Rust core
- Deliver platform-native user experience
- Enable simple onboarding via QR code scanning
- Maintain security and performance characteristics of prrr protocol

### 1.2 Non-Goals

- Web-based or hybrid mobile UI (WebView)
- Cross-platform UI framework (e.g., React Native, Flutter)
- Desktop mobile emulation
- Tablet-optimized layouts (phone-first design)

### 1.3 Success Criteria

- Single Rust codebase for protocol implementation (>85% code reuse)
- QR code onboarding flow completed in <30 seconds
- Connection establishment in <3 seconds on typical networks
- Native platform integration (NetworkExtension on iOS, VpnService on Android)
- App Store and Play Store approval on first submission
- Battery consumption comparable to WireGuard (<5% battery drain per hour of active use)

## 2. Architecture

### 2.1 Technology Stack Selection

After comprehensive evaluation of Rust-based mobile frameworks, the **Crux + UniFFI architecture** is selected as the optimal approach for prrr mobile applications.

**Rationale:**

1. **Maximum Platform Integration**: Full native access to NetworkExtension (iOS) and VpnService (Android) APIs
2. **Code Reuse**: Entire prrr protocol stack (QUIC/MASQUE, crypto, handshake) shared via Rust core
3. **Production Proven**: Used by Mozilla (Firefox components), Matrix SDK, and Lightning Network implementations
4. **Type Safety**: UniFFI provides type-safe FFI bindings with automatic generation
5. **Native Performance**: Zero WebView overhead, native compilation for both platforms
6. **Security Alignment**: Clean separation between core protocol and UI reduces attack surface

**Alternative Approaches Considered:**

| Framework | Pros | Cons | Decision |
|-----------|------|------|----------|
| **Tauri Mobile** | Web tech skills, single UI | WebView overhead, less mature mobile support, larger binaries | Rejected: Performance concerns for VPN |
| **Dioxus** | Single UI codebase, native perf | Pre-1.0, breaking changes expected, smaller ecosystem | Rejected: Stability concerns |
| **Crux + UniFFI** | ✓ Native UI, proven in production, full platform access | Requires Swift/Kotlin UI dev | **Selected** |

### 2.2 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    iOS Application                      │
│  ┌───────────────────────────────────────────────────┐  │
│  │          SwiftUI User Interface                   │  │
│  │  - Connection toggle                              │  │
│  │  - QR code scanner                                │  │
│  │  - Status display                                 │  │
│  │  - Settings screen                                │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │    Network Extension Target (App Extension)       │  │
│  │  - PacketTunnelProvider implementation            │  │
│  │  - System VPN integration                         │  │
│  │  - Lifecycle management                           │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│                    UniFFI Bindings (Swift)              │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│              Shared Rust Core Library                   │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Protocol Implementation (from existing prrr)     │  │
│  │  - QUIC/MASQUE transport                          │  │
│  │  - ML-KEM-768 + X25519 hybrid handshake          │  │
│  │  - ChaCha20-Poly1305 encryption                   │  │
│  │  - Traffic obfuscation                            │  │
│  │  - Probe resistance                               │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Mobile-Specific Components (new)                 │  │
│  │  - Configuration parsing/validation                │  │
│  │  - QR code data decoding                          │  │
│  │  - Connection state management                     │  │
│  │  - Statistics collection                          │  │
│  │  - Error handling & recovery                      │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  UniFFI Interface Definitions                     │  │
│  │  - #[uniffi::export] public API                   │  │
│  │  - Type-safe bindings generation                  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           │
                    UniFFI Bindings (Kotlin)
┌─────────────────────────────────────────────────────────┐
│                  Android Application                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │       Jetpack Compose User Interface              │  │
│  │  - Connection toggle                              │  │
│  │  - QR code scanner (CameraX + ML Kit)             │  │
│  │  - Status display                                 │  │
│  │  - Settings screen                                │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │       VpnService Implementation                   │  │
│  │  - Extends android.net.VpnService                 │  │
│  │  - Foreground service with notification           │  │
│  │  - Network change handling                        │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### 2.3 Component Responsibilities

#### 2.3.1 Shared Rust Core

**Scope:** All protocol logic, cryptography, and VPN functionality

**Components:**
- QUIC/MASQUE transport layer (quinn, existing `transport/` module)
- Hybrid key exchange (ML-KEM-768 + X25519, existing `crypto/` module)
- Noise IK handshake protocol (existing `handshake/` module)
- Packet encryption/decryption (ChaCha20-Poly1305, existing `crypto/aead.rs`)
- Traffic obfuscation (existing `obfuscation/` module)
- Configuration management (parse/validate TOML configs)
- QR code data decoding (base64url → TOML config)
- Connection state machine
- Error types and recovery strategies

**New Modules to Create:**
```
src/
  mobile/
    mod.rs              # Mobile API facade
    config.rs           # Mobile config parsing/validation
    qr.rs               # QR code data decoding
    connection.rs       # Connection state management
    stats.rs            # Statistics tracking
    ffi.rs              # UniFFI interface definitions
```

**UniFFI Exported API (preliminary):**
```rust
#[uniffi::export]
pub struct VpnConnection {
    // Connection management
    pub fn new(config: VpnConfig) -> Result<Self, VpnError>;
    pub fn connect(&self) -> Result<(), VpnError>;
    pub fn disconnect(&self) -> Result<(), VpnError>;
    pub fn status(&self) -> ConnectionStatus;
    
    // Configuration
    pub fn import_config_from_qr(qr_data: String) -> Result<VpnConfig, VpnError>;
    pub fn validate_config(config: VpnConfig) -> Result<(), VpnError>;
    
    // Statistics
    pub fn get_stats(&self) -> ConnectionStats;
}

#[derive(uniffi::Record)]
pub struct VpnConfig {
    pub client_name: String,
    pub server_endpoint: String,
    pub server_public_key: Vec<u8>,
    pub server_pq_public_key: Vec<u8>,
    pub client_private_key: Vec<u8>,
    pub assigned_ip: String,
    pub dns_servers: Vec<String>,
    pub mtu: u16,
}

#[derive(uniffi::Enum)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected { duration_secs: u64 },
    Reconnecting,
    Error { message: String },
}

#[derive(uniffi::Record)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_secs: u64,
    pub server_latency_ms: u32,
}

#[derive(uniffi::Error)]
pub enum VpnError {
    InvalidConfig { reason: String },
    ConnectionFailed { reason: String },
    HandshakeFailed { reason: String },
    NetworkError { reason: String },
    NotConnected,
}
```

#### 2.3.2 iOS Application

**Platform:** iOS 15.0+  
**Language:** Swift 5.9+  
**UI Framework:** SwiftUI

**Components:**

1. **Main App Target**
   - SwiftUI views for UI
   - QR code scanner (AVFoundation)
   - Settings persistence (UserDefaults/Keychain)
   - App lifecycle management

2. **Network Extension Target**
   - Subclass `NEPacketTunnelProvider`
   - Implement `startTunnel(options:completionHandler:)`
   - Implement `stopTunnel(with:completionHandler:)`
   - Interface with Rust core via UniFFI
   - Handle packet flow from `packetFlow` property

**Required Entitlements:**
- Network Extensions
- Personal VPN
- Keychain Sharing (for config/keys)

**App Store Requirements:**
- Privacy Policy URL
- Data collection disclosure (none expected)
- NetworkExtension permission justification

#### 2.3.3 Android Application

**Platform:** Android 8.0+ (API 26+)  
**Language:** Kotlin 1.9+  
**UI Framework:** Jetpack Compose

**Components:**

1. **Main App**
   - Jetpack Compose UI
   - QR scanner (CameraX + ML Kit Barcode Scanning)
   - Settings persistence (DataStore)
   - Permission management

2. **VPN Service**
   - Extends `android.net.VpnService`
   - Foreground service with non-dismissible notification
   - VPN interface configuration (`VpnService.Builder`)
   - Interface with Rust core via UniFFI
   - Handle network changes (ConnectivityManager)

**Required Permissions:**
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
```

**Play Store Requirements:**
- VpnService declaration form
- Data Safety disclosure
- Privacy policy
- Prominent disclosure of VPN usage

## 3. User Experience Design

### 3.1 Design Principles

1. **Simplicity First**: Minimize cognitive load; primary action (connect/disconnect) should be obvious
2. **Invisible Navigation**: Users should never question where to go next
3. **Progressive Disclosure**: Show complexity only when needed
4. **Platform Conventions**: Follow iOS Human Interface Guidelines and Material Design 3
5. **Accessibility**: Support VoiceOver, TalkBack, dynamic type, and high contrast

### 3.2 Onboarding Flow

**Target:** <30 seconds from app launch to first connection

**Flow:**
```
Step 1: Welcome Screen
├─ App logo and name
├─ Value proposition: "Secure, private VPN"
├─ Primary action: "Scan QR Code"
└─ Secondary action: "Import from File" (advanced)

Step 2: QR Code Scanner
├─ Camera viewfinder with scanning frame
├─ Instructions: "Point camera at QR code from server"
├─ Auto-detect and parse QR code
└─ On success → Step 3

Step 3: Configuration Review
├─ Display: Server name, assigned IP
├─ Store configuration securely (Keychain/Keystore)
├─ Request VPN permission (iOS: VPNManager, Android: VpnService.prepare())
└─ Primary action: "Connect Now"

Step 4: First Connection
├─ Show connecting animation
├─ Display progress: "Establishing secure tunnel..."
├─ On success: "Connected" confirmation
└─ Transition to main screen
```

**QR Code Format:**

The QR code contains a `prrr://import?config=<base64url>` URL where `<base64url>` is the URL-safe base64 encoding of a TOML configuration:

```toml
[client]
name = "alice-iphone"

[server]
endpoint = "vpn.example.com:443"
public_key = "wG5kaFGLAHzkdKr/8LLXu0K1NhVYYQ3dqp7A3Qwxj3k="
pq_public_key = "AQIDBA...1184 bytes base64..."

[interface]
private_key_path = "embedded"  # Special value for mobile
private_key = "base64_encoded_private_key"  # Embedded in QR for mobile
address = "10.66.66.2/32"
dns = ["1.1.1.1", "8.8.8.8"]
mtu = 1280
```

**Security Note:** Private keys in QR codes are acceptable for mobile onboarding because:
1. QR codes are typically displayed on secure admin panels
2. Alternative (manual key entry) is error-prone and poor UX
3. Keys are immediately stored in secure storage (Keychain/Keystore)
4. QR codes can be ephemeral (time-limited tokens)

### 3.3 Main Screen Design

**Layout (both platforms):**

```
┌─────────────────────────────────────┐
│  Status Bar                         │
├─────────────────────────────────────┤
│                                     │
│  ┌───────────────────────────────┐  │
│  │                               │  │
│  │    Connection Status Icon     │  │
│  │    (Large, Centered)          │  │
│  │                               │  │
│  │    ● Disconnected (gray)      │  │
│  │    ◐ Connecting (animated)    │  │
│  │    ● Connected (green)        │  │
│  │                               │  │
│  └───────────────────────────────┘  │
│                                     │
│  Status Text: "Connected"           │
│  Subtext: "via vpn.example.com"     │
│                                     │
│  ┌───────────────────────────────┐  │
│  │    [Connection Toggle]        │  │
│  │    (Large, thumb-zone)        │  │
│  └───────────────────────────────┘  │
│                                     │
│  Connection Stats (when connected): │
│  ├─ Duration: 2h 34m               │
│  ├─ Sent: 124 MB                   │
│  ├─ Received: 892 MB               │
│  └─ Latency: 45ms                  │
│                                     │
│  [Settings Icon]    [Help Icon]     │
│                                     │
└─────────────────────────────────────┘
```

**Connection States:**

1. **Disconnected**
   - Gray status icon
   - Text: "Not Connected"
   - Button: "Connect" (green)
   
2. **Connecting**
   - Animated spinner icon
   - Text: "Connecting..."
   - Subtext: "Establishing secure tunnel"
   - Button: "Cancel" (gray)
   
3. **Connected**
   - Green checkmark icon
   - Text: "Connected"
   - Subtext: Server name and IP
   - Stats visible
   - Button: "Disconnect" (red)
   
4. **Reconnecting**
   - Animated spinner icon (yellow)
   - Text: "Reconnecting..."
   - Subtext: "Connection interrupted"
   - Button: "Disconnect" (red)
   
5. **Error**
   - Red error icon
   - Text: Error message (user-friendly)
   - Subtext: Suggested action
   - Button: "Retry" / "Settings"

### 3.4 Settings Screen

**Categories:**

1. **Connection**
   - Server configuration (read-only, display only)
   - Auto-connect on app launch (toggle)
   - Auto-reconnect on network change (toggle)
   - Kill switch (iOS 14+: native, Android 7+: guide user to system settings)

2. **Configuration**
   - Import new configuration (QR / File)
   - Export configuration (for backup, excludes private key)
   - Remove configuration (confirmation required)

3. **Advanced**
   - DNS servers (display from config)
   - MTU (display from config)
   - Protocol details (read-only: MASQUE/QUIC)
   - Server public keys (display for verification)

4. **About**
   - App version
   - Privacy policy link
   - Open source licenses
   - Support / Contact

### 3.5 Error Handling

**Principles:**
- Clear, non-technical language
- Actionable suggestions
- Contextual help links

**Common Errors:**

| Error | User Message | Suggested Action |
|-------|--------------|------------------|
| Invalid QR code | "Unable to read QR code" | "Ensure the QR code is from the prrr server admin panel" |
| Network unreachable | "Cannot reach VPN server" | "Check your internet connection and try again" |
| Handshake failure | "Connection security check failed" | "Server may have changed configuration. Re-import settings." |
| Authentication failed | "Server rejected connection" | "Your access may have been revoked. Contact administrator." |
| Timeout | "Connection timed out" | "Server may be offline. Try again later." |
| Permission denied | "VPN permission required" | "Enable VPN permission in system settings" → deep link |

**Error Recovery:**
- Auto-retry with exponential backoff (1s, 2s, 4s, 8s, max 30s)
- Switch to reconnecting state after first retry
- Transition to error state after 5 failed attempts
- User can manually retry at any time

### 3.6 Network Switching

**Behavior:**
- WiFi ↔ Cellular transitions should be seamless (QUIC connection migration)
- Show brief "Reconnecting..." status during transition
- No user interruption required
- Log network changes for debugging

**Implementation:**
- iOS: Monitor `NWPathMonitor` for network changes
- Android: Monitor `ConnectivityManager.NetworkCallback`
- Notify Rust core to migrate QUIC connection to new network path

### 3.7 Battery Optimization

**Strategy:**

1. **Protocol Level:**
   - Leverage QUIC's efficient congestion control
   - Use connection migration instead of reconnection
   - Minimize keepalive frequency (25s default, acceptable for mobile)

2. **Platform Level:**
   - iOS: Leverage NetworkExtension's optimized packet handling
   - Android: Request battery optimization exemption during onboarding
   - Use foreground service on Android (required, but also keeps process alive)

3. **User Guidance:**
   - Android: Prompt user to disable battery optimization for the app
   - Provide in-app instructions with screenshots
   - Deep link to system battery settings

**Target:** <5% battery drain per hour of active VPN use

## 4. Platform-Specific Requirements

### 4.1 iOS Requirements

#### 4.1.1 NetworkExtension Integration

**PacketTunnelProvider Implementation:**

```swift
import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var connection: VpnConnection?
    
    override func startTunnel(
        options: [String : NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // 1. Load configuration from persistent storage
        guard let config = loadConfiguration() else {
            completionHandler(VpnError.invalidConfig("No configuration found"))
            return
        }
        
        // 2. Initialize Rust VPN connection via UniFFI
        do {
            self.connection = try VpnConnection(config: config)
        } catch {
            completionHandler(error)
            return
        }
        
        // 3. Configure tunnel network settings
        let networkSettings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: config.serverEndpoint
        )
        networkSettings.ipv4Settings = /* ... */
        networkSettings.dnsSettings = /* ... */
        
        setTunnelNetworkSettings(networkSettings) { error in
            guard error == nil else {
                completionHandler(error)
                return
            }
            
            // 4. Start VPN connection
            self.connection?.connect()
            
            // 5. Start packet processing loop
            self.startPacketProcessing()
            
            completionHandler(nil)
        }
    }
    
    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        connection?.disconnect()
        completionHandler()
    }
    
    private func startPacketProcessing() {
        // Read packets from packetFlow and send to Rust core
        packetFlow.readPackets { packets, protocols in
            // Process via Rust VPN connection
            self.startPacketProcessing() // Continue reading
        }
    }
}
```

#### 4.1.2 Always-On VPN

**Implementation:**
```swift
// Enable always-on VPN (iOS 14+)
let manager = NEVPNManager.shared()
manager.protocolConfiguration?.includeAllNetworks = true // Kill switch
manager.isOnDemandEnabled = true

// On-demand rules (auto-connect)
let rule = NEOnDemandRuleConnect()
rule.interfaceTypeMatch = .any
manager.onDemandRules = [rule]
```

#### 4.1.3 Privacy Manifest

Required `PrivacyInfo.xcprivacy`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>NSPrivacyCollectedDataTypes</key>
    <array>
        <!-- No data collection -->
    </array>
    <key>NSPrivacyTracking</key>
    <false/>
    <key>NSPrivacyTrackingDomains</key>
    <array>
        <!-- No tracking domains -->
    </array>
</dict>
</plist>
```

#### 4.1.4 App Store Submission

**Requirements:**
1. Privacy Policy URL (must state: no third-party data sharing)
2. App Review Notes: Explain VPN functionality and test credentials
3. Test Account: Provide working QR code or config file for reviewer
4. Screenshots: Show connection flow and main screen

### 4.2 Android Requirements

#### 4.2.1 VpnService Implementation

```kotlin
import android.net.VpnService
import android.os.ParcelFileDescriptor

class PrrrVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var connection: VpnConnection? = null
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Promote to foreground service (required Android 8+)
        val notification = createNotification()
        startForeground(NOTIFICATION_ID, notification)
        
        // Load configuration
        val config = loadConfiguration() ?: run {
            stopSelf()
            return START_NOT_STICKY
        }
        
        // Create VPN interface
        vpnInterface = Builder()
            .setSession("prrr VPN")
            .addAddress(config.assignedIp, 32)
            .addDnsServer(config.dnsServers[0])
            .addRoute("0.0.0.0", 0)  // Route all traffic
            .setMtu(config.mtu.toInt())
            .establish()
        
        // Initialize Rust VPN connection via UniFFI
        connection = VpnConnection(config)
        connection?.connect()
        
        // Start packet processing
        startPacketProcessing()
        
        return START_STICKY
    }
    
    override fun onDestroy() {
        connection?.disconnect()
        vpnInterface?.close()
        super.onDestroy()
    }
    
    private fun startPacketProcessing() {
        // Read packets from vpnInterface FileDescriptor
        // Send to Rust core for encryption and transmission
    }
}
```

#### 4.2.2 Permission Handling

**VPN Permission Flow:**
```kotlin
// In Activity
val intent = VpnService.prepare(this)
if (intent != null) {
    // User must grant VPN permission
    startActivityForResult(intent, REQUEST_VPN_PERMISSION)
} else {
    // Already granted, start service
    startVpnService()
}

override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    if (requestCode == REQUEST_VPN_PERMISSION) {
        if (resultCode == RESULT_OK) {
            startVpnService()
        } else {
            // Permission denied, show explanation
        }
    }
}
```

#### 4.2.3 Battery Optimization

**Request Exemption:**
```kotlin
// Prompt user to disable battery optimization
val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
    data = Uri.parse("package:$packageName")
}
startActivity(intent)
```

**Guidance UI:**
- Show in onboarding or first connection
- Explain why exemption is needed: "To maintain VPN connection in background"
- Optional skip (app will work but may disconnect)

#### 4.2.4 Always-On VPN

**User Configuration:**
- Cannot be programmatically enabled
- Provide in-app instructions:
  1. Open Settings → Network & Internet → VPN
  2. Tap prrr VPN → Settings (gear icon)
  3. Enable "Always-on VPN"
  4. Enable "Block connections without VPN" (kill switch)

**Service Implementation:**
- Handle `VpnService.SERVICE_INTERFACE` intent filter
- Start service on boot if always-on is enabled

#### 4.2.5 Play Store Submission

**Requirements:**
1. Complete VpnService declaration form
2. Data Safety section: No data collected/shared
3. Privacy Policy URL
4. Prominent disclosure: "This app uses VpnService to provide VPN functionality"
5. Test account or demo server for review

## 5. Security Considerations

### 5.1 Key Storage

**iOS:**
- Store private keys in Keychain with `kSecAttrAccessibleAfterFirstUnlock`
- Use Keychain Access Groups for sharing between app and extension
- Enable Keychain data protection

**Android:**
- Store private keys in Android Keystore (hardware-backed if available)
- Use EncryptedSharedPreferences for configuration
- Minimum API 26 ensures hardware-backed keystore on most devices

### 5.2 Configuration Security

**Principles:**
1. Never log private keys or secrets
2. Validate all configuration inputs before use
3. Sanitize user-facing error messages (no internal details)
4. Use secure random for any generated values (session IDs, nonces)

**QR Code Security:**
- Validate structure before parsing
- Reject configs with missing required fields
- Verify key lengths match expected sizes
- Warn user if config contains unexpected fields

### 5.3 Network Security

**TLS/QUIC:**
- Rust core handles all TLS/QUIC configuration
- No custom certificate validation in mobile layer
- Trust system certificate stores

**Certificate Pinning:**
- Not implemented (allows server certificate rotation)
- Server identity verified via Noise IK protocol, not TLS certificates

### 5.4 Code Security

**Rust Core:**
- Maintain `#![deny(unsafe_code)]` in shared core
- Regular dependency audits (`cargo audit`)
- Fuzzing of parser and protocol logic

**Mobile Code:**
- Code review for all platform-specific implementations
- Static analysis (SwiftLint, Android Lint)
- No WebView or JavaScript execution

## 6. Development Roadmap

### Phase 1: Core Library (Weeks 1-4)

**Deliverables:**
- [ ] Extract prrr core into mobile-friendly library crate
- [ ] Add UniFFI annotations and interface definitions
- [ ] Implement mobile-specific APIs (connection management, stats)
- [ ] QR code parsing and validation
- [ ] Configuration import/export
- [ ] Unit tests for mobile API surface
- [ ] Build iOS framework (via `cargo-xcode`)
- [ ] Build Android AAR (via `cargo-ndk`)

**Tasks:**
1. Create `prrr-mobile` crate in workspace
2. Move relevant modules from `prrr` binary to library
3. Define UniFFI interface in `src/mobile/ffi.udl`
4. Implement `VpnConnection`, `VpnConfig`, etc.
5. Add integration tests
6. Set up CI for cross-compilation (iOS aarch64, Android aarch64/x86_64)

### Phase 2: iOS Application (Weeks 5-8)

**Deliverables:**
- [ ] iOS app target with SwiftUI UI
- [ ] NetworkExtension target with PacketTunnelProvider
- [ ] QR code scanner implementation
- [ ] Configuration persistence (Keychain)
- [ ] Connection lifecycle management
- [ ] Settings screen
- [ ] Error handling and user feedback
- [ ] TestFlight beta build

**Tasks:**
1. Create Xcode project
2. Integrate Rust framework via UniFFI-generated Swift bindings
3. Implement UI screens (SwiftUI)
4. Implement NetworkExtension provider
5. Handle VPN permissions and entitlements
6. Testing on physical devices (Network Extensions don't work in simulator)
7. App Store Connect setup

### Phase 3: Android Application (Weeks 9-12)

**Deliverables:**
- [ ] Android app with Jetpack Compose UI
- [ ] VpnService implementation
- [ ] QR code scanner (CameraX + ML Kit)
- [ ] Configuration persistence (DataStore + Keystore)
- [ ] Connection lifecycle management
- [ ] Settings screen
- [ ] Error handling and user feedback
- [ ] Internal testing track build

**Tasks:**
1. Create Android Studio project
2. Integrate Rust AAR via UniFFI-generated Kotlin bindings
3. Implement UI (Jetpack Compose)
4. Implement VpnService
5. Handle permissions (VPN, Camera, Battery)
6. Testing on physical devices and emulators
7. Play Console setup

### Phase 4: Testing & Polish (Weeks 13-16)

**Deliverables:**
- [ ] End-to-end testing on real server
- [ ] Battery usage profiling
- [ ] Performance benchmarks (connection time, throughput)
- [ ] Accessibility testing (VoiceOver, TalkBack)
- [ ] Security audit of mobile components
- [ ] Beta testing with external users (TestFlight, Internal Testing)
- [ ] App Store and Play Store submissions
- [ ] User documentation and support materials

**Tasks:**
1. E2E testing: QR scan → connect → data transfer → disconnect
2. Network transition testing (WiFi ↔ Cellular)
3. Kill switch verification
4. Battery profiling (iOS Instruments, Android Battery Historian)
5. Accessibility audit
6. Security review (focus on FFI boundary, key storage)
7. Beta testing and feedback incorporation
8. Final polish and submission

## 7. Testing Strategy

### 7.1 Unit Tests

**Rust Core:**
- Configuration parsing (valid, invalid, edge cases)
- QR code decoding (valid, malformed, missing fields)
- Error handling (all error paths)
- State machine transitions
- Statistics calculation

**Target:** >85% code coverage in mobile-specific modules

### 7.2 Integration Tests

**Rust ↔ Platform:**
- UniFFI binding correctness (type safety, null handling)
- Call Rust functions from Swift/Kotlin test code
- Verify error propagation across FFI boundary

**Platform Integration:**
- iOS: NetworkExtension lifecycle (start, stop, crash recovery)
- Android: VpnService lifecycle (start, stop, system kill)

### 7.3 End-to-End Tests

**Scenarios:**
1. Fresh install → QR scan → first connection → disconnect
2. Connection during network switch (WiFi → Cellular)
3. Connection interruption (server offline, network loss)
4. Kill switch activation (verify traffic blocked on disconnect)
5. Always-on VPN (iOS: system reconnect, Android: boot reconnect)
6. Configuration import from file (backup/restore)

**Environment:**
- Test against live prrr server (staging instance)
- Automated via XCUITest (iOS) and Espresso (Android) where possible
- Manual testing for edge cases and UX validation

### 7.4 Performance Tests

**Metrics:**
1. Connection establishment time (target: <3s)
2. Throughput (target: >80% of baseline network speed)
3. Battery drain (target: <5% per hour)
4. Memory usage (target: <50MB resident)
5. CPU usage during idle (target: <1%)

**Tools:**
- iOS: Instruments (Network, Energy, Allocations)
- Android: Profiler (CPU, Memory, Network, Energy)

### 7.5 Accessibility Tests

**Requirements:**
- VoiceOver (iOS) and TalkBack (Android) navigation
- Dynamic Type support (iOS) and font scaling (Android)
- High contrast mode compatibility
- Touch target sizes (minimum 44x44 pt on iOS, 48x48 dp on Android)

## 8. Deployment & Distribution

### 8.1 iOS App Store

**Preparation:**
1. Developer account enrollment ($99/year)
2. NetworkExtension entitlement request (email `networkextension@apple.com`)
3. App Store Connect setup
4. Privacy Policy hosted URL
5. Screenshots (6.5", 6.7", 12.9" iPad Pro)

**Submission Checklist:**
- [ ] App privacy details (no data collection)
- [ ] Export compliance (encryption usage declaration)
- [ ] Test account or demo configuration
- [ ] App Review notes explaining VPN functionality
- [ ] Marketing materials (description, keywords, screenshots)

**Review Time:** Typically 24-48 hours

### 8.2 Google Play Store

**Preparation:**
1. Developer account enrollment ($25 one-time)
2. Play Console setup
3. VpnService declaration form completion
4. Privacy Policy hosted URL
5. Screenshots (phone and tablet)

**Submission Checklist:**
- [ ] Data Safety section (no data collected/shared)
- [ ] VpnService declaration submitted
- [ ] Test account or demo configuration
- [ ] Store listing (description, screenshots, categorization)
- [ ] Content rating questionnaire

**Review Time:** Typically 3-7 days (first submission), 1-3 days (updates)

### 8.3 Versioning Strategy

**Semantic Versioning:** `MAJOR.MINOR.PATCH`

- **MAJOR:** Breaking protocol changes (rare)
- **MINOR:** New features, non-breaking changes
- **PATCH:** Bug fixes, performance improvements

**Build Numbers:** Increment on every build (required by stores)

**Release Cadence:**
- Patch releases: As needed (hotfixes)
- Minor releases: Monthly (feature additions)
- Major releases: Annually or as protocol evolves

## 9. Metrics & Analytics

### 9.1 Privacy-Preserving Metrics

**Principles:**
- No user tracking or identifiable information
- No third-party analytics SDKs (Google Analytics, etc.)
- Optional telemetry (opt-in, disabled by default)

**Collected Metrics (if enabled):**
- Connection success rate (percentage)
- Average connection duration
- Network type distribution (WiFi vs. Cellular)
- Error frequency by type (e.g., handshake failures)
- Platform/OS version distribution
- App version distribution

**Storage:** Aggregated server-side, no per-user data

### 9.2 Crash Reporting

**iOS:** Xcode Organizer crash reports (automatic)  
**Android:** Play Console crash reports (automatic)

**No third-party crash reporting** (respects privacy)

## 10. Maintenance & Support

### 10.1 Support Channels

1. **In-App Help:** FAQ and troubleshooting guide
2. **GitHub Issues:** Bug reports and feature requests
3. **Email Support:** For sensitive or complex issues

### 10.2 Update Strategy

**Critical Updates (security):** Within 24-48 hours  
**Bug Fixes:** Within 1-2 weeks  
**Feature Updates:** Monthly releases

**Backward Compatibility:**
- Maintain protocol compatibility with older clients
- Support iOS N-1 and Android API 26+
- Deprecation notices for major changes (6-month notice)

### 10.3 Monitoring

**Server-Side:**
- Mobile client connection success rate
- Average handshake duration for mobile clients
- Error frequency by mobile OS version

**Client-Side:**
- Connection state logging (local only, not sent)
- Crash logs (automatic via app stores)

## 11. Open Questions & Future Considerations

### 11.1 Open Questions

1. **WireGuard Compatibility:** Should the app support standard WireGuard configs in addition to prrr?
   - **Recommendation:** Phase 2 feature, focus on prrr protocol first

2. **Multi-Server Support:** Allow users to configure multiple VPN servers?
   - **Recommendation:** Phase 2 feature, single server for MVP

3. **Split Tunneling:** Allow selective app routing (Android) or domain-based routing?
   - **Recommendation:** Phase 3 feature, adds UI complexity

4. **Widgets:** iOS Home Screen widget showing connection status?
   - **Recommendation:** Nice-to-have, not critical for MVP

### 11.2 Future Features

**Phase 2 (Post-Launch):**
- Multi-server configuration support
- Connection profiles (work, home, travel)
- Network-based auto-switching (connect to VPN when on untrusted WiFi)
- Export/import encrypted backups

**Phase 3 (Advanced):**
- Split tunneling (Android)
- Per-app VPN (Android)
- Shortcuts integration (iOS)
- Tasker integration (Android)

### 11.3 Internationalization

**Launch Languages:** English only  
**Future:** Localize to top 5 languages based on user base
- Spanish (es)
- Chinese Simplified (zh-Hans)
- French (fr)
- German (de)
- Russian (ru)

**Localization Scope:**
- All UI strings
- Error messages
- App Store descriptions
- In-app help content

## 12. Success Metrics

### 12.1 Development Metrics

- [ ] Code reuse: >85% protocol code shared via Rust core
- [ ] Test coverage: >80% in mobile-specific modules
- [ ] Build time: <5 minutes for full cross-compilation (iOS + Android)
- [ ] Binary size: <15MB per platform (after App Thinning/App Bundles)

### 12.2 User Experience Metrics

- [ ] Onboarding completion: >90% of users who scan QR complete first connection
- [ ] Connection success rate: >95% of connection attempts succeed
- [ ] Connection establishment time: <3 seconds (p95)
- [ ] App Store rating: >4.5 stars within 3 months

### 12.3 Performance Metrics

- [ ] Battery drain: <5% per hour of active use
- [ ] Throughput: >80% of baseline network speed
- [ ] Memory usage: <50MB resident
- [ ] Crash-free rate: >99.5%

### 12.4 Business Metrics

- [ ] App Store approval: First submission (no rejections)
- [ ] Play Store approval: First submission (no rejections)
- [ ] User adoption: 1000+ downloads within first month
- [ ] Retention: >70% 7-day retention rate

## 13. Risks & Mitigations

### 13.1 Technical Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| UniFFI performance overhead | High | Low | Benchmark early; FFI calls are infrequent (connection management, not per-packet) |
| NetworkExtension entitlement delay | High | Medium | Request early in Phase 1; have backup plan (TestFlight-only beta) |
| App Store rejection | High | Low | Follow guidelines strictly; provide detailed review notes; test credentials |
| Battery drain exceeds target | Medium | Medium | Profile early; optimize keepalive intervals; leverage platform optimizations |
| QR code UX confusion | Low | Medium | User testing; clear instructions; fallback to file import |

### 13.2 Operational Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Protocol changes break mobile clients | High | Low | Maintain backward compatibility; version negotiation in handshake |
| Store policy changes | Medium | Low | Monitor policy updates; have direct distribution option (APK/IPA) |
| Security vulnerability in mobile code | High | Low | Security audit; code review; fuzzing; responsible disclosure program |

## 14. Appendices

### Appendix A: Technology References

**Rust Mobile Development:**
- [UniFFI Book](https://mozilla.github.io/uniffi-rs/)
- [Crux Framework](https://github.com/redbadger/crux)
- [cargo-xcode](https://github.com/brendanzab/cargo-xcode)
- [cargo-ndk](https://github.com/bbqsrc/cargo-ndk)

**iOS Development:**
- [NetworkExtension Framework](https://developer.apple.com/documentation/networkextension)
- [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
- [SimpleTunnel Sample Code](https://developer.apple.com/library/archive/samplecode/SimpleTunnel/)

**Android Development:**
- [VpnService API](https://developer.android.com/reference/android/net/VpnService)
- [Jetpack Compose](https://developer.android.com/jetpack/compose)
- [CameraX](https://developer.android.com/training/camerax)

**VPN UX Design:**
- [iOS Human Interface Guidelines - VPN](https://developer.apple.com/design/human-interface-guidelines/)
- [Material Design 3](https://m3.material.io/)
- [WireGuard Mobile Apps](https://www.wireguard.com/install/) (reference implementation)

### Appendix B: Configuration Examples

**Server-Generated QR Code Config:**
```toml
[client]
name = "alice-iphone"

[server]
endpoint = "vpn.example.com:443"
public_key = "wG5kaFGLAHzkdKr/8LLXu0K1NhVYYQ3dqp7A3Qwxj3k="
pq_public_key = "AQIDBA...1184-byte-base64..."

[interface]
private_key = "YXGQV8fXw7CtpUceLM9Dz+HhKjyGBpZypIXk5UpGs6U="
address = "10.66.66.2/32"
dns = ["1.1.1.1", "8.8.8.8"]
mtu = 1280
```

**Minimal Valid Config:**
```toml
[server]
endpoint = "10.0.0.1:443"
public_key = "base64..."
pq_public_key = "base64..."

[interface]
private_key = "base64..."
address = "10.66.66.2/32"
```

### Appendix C: Error Code Reference

| Code | Message | User-Facing Text | Recovery |
|------|---------|------------------|----------|
| `E001` | Invalid configuration | "Configuration error" | Re-import config |
| `E002` | Network unreachable | "Cannot reach server" | Check internet |
| `E003` | Handshake timeout | "Connection timed out" | Retry |
| `E004` | Authentication failed | "Server rejected connection" | Contact admin |
| `E005` | Permission denied | "VPN permission required" | Grant permission |
| `E006` | Invalid QR code | "Cannot read QR code" | Rescan or import file |

---

**Document Control:**
- **Author:** AI Assistant (based on research and analysis)
- **Reviewers:** [TBD]
- **Approval:** [TBD]
- **Next Review:** [TBD]
