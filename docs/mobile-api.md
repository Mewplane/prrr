# prrr Mobile API Documentation

**Status**: Phase 1 Complete, Phase 3 (Android) Complete  
**Latest FRD**: [specs/frds/FRD-M014-android-internal-testing.md](../specs/frds/FRD-M014-android-internal-testing.md)  
**Target Platforms**: iOS 13+, Android API 26+

## Overview

The prrr mobile library provides a cross-platform API for iOS and Android to integrate with the prrr VPN protocol. It uses Mozilla's UniFFI to generate type-safe Swift and Kotlin bindings from a Rust implementation.

**Implemented Features:**

Phase 1 - Mobile Core Library:
- ✅ Feature 1.1: Mobile workspace setup
- ✅ Feature 1.2: UniFFI interface definitions
- ✅ Feature 1.3: Configuration parsing and validation
- ✅ Feature 1.4: Connection state management
- ✅ Feature 1.5: Core connection (stub with async runtime)
- ✅ Feature 1.6: Mobile documentation

Phase 3 - Android Application:
- ✅ Feature 3.1: Android project setup
- ✅ Feature 3.2: QR code scanner with CameraX and ML Kit
- ✅ Feature 3.3: Configuration storage with Android Keystore
- ✅ Feature 3.4: VpnService foundation (stub packet loop)
- ✅ Feature 3.5: Main UI with Jetpack Compose
- ✅ Feature 3.6: Settings, battery optimization & error handling
- ✅ Feature 3.7: Android internal testing track (release build, ProGuard/R8, adaptive icons)

## API Surface

### Configuration Management (Features 1.2-1.3)

### Types

#### `VpnConfig`

VPN configuration parameters.

**Fields:**
- `client_name: String` - Human-readable client name
- `server_endpoint: String` - Server address (e.g. "vpn.example.com:443")
- `server_public_key: [UInt8]` (Swift) / `List<UByte>` (Kotlin) - Server X25519 public key (32 bytes)
- `server_pq_public_key: [UInt8]` / `List<UByte>` - Server ML-KEM-768 public key (1184 bytes)
- `client_private_key: [UInt8]` / `List<UByte>` - Client X25519 private key (32 bytes)
- `assigned_ip: String` - Client IP address in CIDR format (e.g. "10.66.66.2/32")
- `dns_servers: [String]` / `List<String>` - DNS server addresses
- `mtu: UInt16` / `UShort` - Maximum Transmission Unit (1280-1500)

#### `MobileError`

Error types for mobile operations.

**Variants:**
- `InvalidConfig(reason: String)` - Configuration validation failed
- `ConnectionFailed(reason: String)` - Connection attempt failed (Feature 1.4)
- `HandshakeFailed(reason: String)` - Cryptographic handshake failed (Feature 1.4)
- `NetworkError(reason: String)` - Network operation failed (Feature 1.4)
- `NotConnected` - Operation requires active connection (Feature 1.4)

### Functions

#### `parse_qr_config(qr_data: String) throws -> VpnConfig`

Parse VPN configuration from a QR code URL.

**Parameters:**
- `qr_data` - QR code content (format: `prrr://import?config=<base64>`)

**Returns:** Parsed `VpnConfig`

**Throws:** `MobileError.InvalidConfig` if:
- URL prefix is missing or incorrect
- Base64 decoding fails
- TOML parsing fails
- Required fields are missing

**Example (Swift):**
```swift
import prrr_mobile

do {
    let qrData = "prrr://import?config=W2NsaWVudF0KbmFtZSA9ICJ0ZXN0Ig..."
    let config = try parseQrConfig(qrData: qrData)
    print("Client: \(config.clientName)")
    print("Server: \(config.serverEndpoint)")
} catch let error as MobileError {
    switch error {
    case .InvalidConfig(let reason):
        print("Invalid config: \(reason)")
    default:
        print("Error: \(error)")
    }
}
```

**Example (Kotlin):**
```kotlin
import prrr_mobile.*

try {
    val qrData = "prrr://import?config=W2NsaWVudF0KbmFtZSA9ICJ0ZXN0Ig..."
    val config = parseQrConfig(qrData)
    println("Client: ${config.clientName}")
    println("Server: ${config.serverEndpoint}")
} catch (e: MobileException.InvalidConfig) {
    println("Invalid config: ${e.reason}")
}
```

#### `validate_config(config: VpnConfig) throws`

Validate VPN configuration fields.

**Parameters:**
- `config` - Configuration to validate

**Throws:** `MobileError.InvalidConfig` if:
- `server_endpoint` is empty
- `server_public_key` is not 32 bytes
- `server_pq_public_key` is not 1184 bytes
- `client_private_key` is not 32 bytes
- `assigned_ip` is not in CIDR format
- `dns_servers` is empty
- `mtu` is not in range 1280-1500

**Example (Swift):**
```swift
do {
    try validateConfig(config: config)
    // Config is valid, proceed to connect
} catch {
    print("Validation failed: \(error)")
}
```

**Example (Kotlin):**
```kotlin
try {
    validateConfig(config)
    // Config is valid, proceed to connect
} catch (e: MobileException) {
    println("Validation failed: $e")
}
```

### Connection State Management (Feature 1.4)

#### Types

**`VpnConnection`** - VPN connection manager with state tracking

**`ConnectionStatus`** - Connection state enum:
- `Disconnected` - No active connection
- `Connecting` - Connection attempt in progress  
- `Connected` - Active VPN tunnel (simulated in stub)

**`ConnectionStats`** - Connection statistics:
- `bytes_sent: u64` - Total bytes uploaded
- `bytes_received: u64` - Total bytes downloaded
- `duration_secs: u64` - Connection duration
- `server_latency_ms: u32` - Server round-trip time

#### Methods

**`VpnConnection.new(config: VpnConfig) throws -> VpnConnection`**

Create a new VPN connection manager with validated configuration.

**Example (Swift):**
```swift
do {
    let config = try parseQrConfig(qrData: qrData)
    let connection = try VpnConnection(config: config)
    print("Connection created")
} catch {
    print("Failed to create connection: \(error)")
}
```

**`connection.connect() throws`**

Initiate VPN connection attempt. Transitions from `Disconnected` to `Connecting`, then asynchronously to `Connected`.

**Behavior (Stub Implementation):**
- Validates current state (must be `Disconnected`)
- Spawns background task to simulate connection
- Returns immediately after transitioning to `Connecting`
- After ~100ms, transitions to `Connected` state

**Example (Swift):**
```swift
do {
    try connection.connect()
    print("Connecting... Status: \(connection.status())")
    
    // Poll for connection completion
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
        if connection.status() == .Connected {
            print("Connected!")
            if let stats = connection.stats() {
                print("Duration: \(stats.durationSecs)s")
            }
        }
    }
} catch {
    print("Connect failed: \(error)")
}
```

**`connection.disconnect()`**

Tear down VPN connection. Always succeeds, transitions to `Disconnected`.

**`connection.status() -> ConnectionStatus`**

Get current connection state.

**`connection.stats() -> ConnectionStats?`**

Get connection statistics. Returns `None`/`nil` when not connected.

**Stub Behavior:**
- Returns `None` when `Disconnected` or `Connecting`
- Returns stub stats when `Connected`:
  - `bytes_sent`: 0
  - `bytes_received`: 0  
  - `duration_secs`: seconds since connection started
  - `server_latency_ms`: 0

**Note:** Feature 1.5 implements async connection simulation. Real VPN tunneling (QUIC/MASQUE transport, hybrid handshake) will be integrated in future features when the core `src/client.rs` connection logic is wired in.

## Building and Integration

### Generate Bindings

```bash
# From project root
./scripts/generate-bindings.sh
```

This generates:
- `prrr-mobile/bindings/swift/prrr_mobile.swift`
- `prrr-mobile/bindings/swift/prrr_mobileFFI.modulemap`
- `prrr-mobile/bindings/kotlin/prrr_mobile.kt`

### iOS Integration

1. Build the iOS library:
   ```bash
   ./scripts/build-ios.sh
   ```

2. In Xcode, add to your project:
   - `prrr-mobile/target/ios/prrr_mobile.xcframework`
   - `prrr-mobile/bindings/swift/prrr_mobile.swift`
   - `prrr-mobile/bindings/swift/prrr_mobileFFI.modulemap`

3. Import in Swift:
   ```swift
   import prrr_mobile
   ```

### Android Integration

1. Build the Android library:
   ```bash
   ./scripts/build-android.sh
   ```

2. In Android Studio, add to `build.gradle.kts`:
   ```kotlin
   dependencies {
       implementation(files("libs/prrr_mobile.aar"))
       implementation("net.java.dev.jna:jna:5.14.0@aar")
       
       // For QR Scanner (Feature 3.2)
       implementation("androidx.camera:camera-core:1.3.1")
       implementation("androidx.camera:camera-camera2:1.3.1")
       implementation("androidx.camera:camera-lifecycle:1.3.1")
       implementation("androidx.camera:camera-view:1.3.1")
       implementation("com.google.mlkit:barcode-scanning:17.2.0")
   }
   ```

3. Import in Kotlin:
   ```kotlin
   import uniffi.prrr_mobile.*
   ```

## Android QR Scanner (Feature 3.2)

The Android app includes a complete QR code scanner implementation that integrates with the Rust core library.

### Architecture

```
QRScannerScreen (Compose UI)
    ├─> CameraPreviewView (CameraX wrapper)
    │       └─> QRCodeAnalyzer (ML Kit barcode scanning)
    └─> QRScanViewModel (State management + Rust integration)
            └─> uniffi.prrr_mobile.parseQrConfig()
```

### Components

**QRScannerScreen**: Main Compose screen with:
- Camera permission handling (runtime + settings)
- Navigation control
- Error state UI
- Success callback with parsed `VpnConfig`

**CameraPreviewView**: CameraX integration:
- Preview use case for camera display
- ImageAnalysis use case for QR detection
- Lifecycle-aware camera management

**QRCodeAnalyzer**: ML Kit integration:
- Real-time barcode scanning
- QR code format filtering
- Debouncing (prevents duplicate scans)

**QRScanViewModel**: State management:
- Validates `prrr://import` URL prefix
- Calls Rust `parseQrConfig()` function
- Handles `MobileException.InvalidConfig` errors
- Manages scan states: Idle → Scanning → Success/Error

### Usage Example

```kotlin
import com.prrr.vpn.android.scanner.QRScannerScreen

@Composable
fun MyApp() {
    var scannedConfig by remember { mutableStateOf<VpnConfig?>(null) }
    var showScanner by remember { mutableStateOf(false) }
    
    if (showScanner) {
        QRScannerScreen(
            onConfigScanned = { config ->
                scannedConfig = config
                showScanner = false
                // Connect to VPN with config
            },
            onNavigateBack = { showScanner = false }
        )
    } else {
        Button(onClick = { showScanner = true }) {
            Text("Scan QR Code")
        }
    }
}
```

### Permissions

Add to `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.CAMERA" />
<uses-feature android:name="android.hardware.camera" android:required="true" />
```

The scanner handles runtime permission requests automatically with:
- Explanatory dialog before requesting
- "Open Settings" option if permanently denied
- Graceful fallback UI when denied

### Testing

The scanner validates QR codes through the Rust parser, ensuring:
- Only `prrr://import?config=<base64>` format accepted
- Base64 decoding and TOML parsing validated
- Configuration fields validated before use
- Clear error messages for invalid QR codes

**APK Size**: ~38 MB (includes Rust library, CameraX, ML Kit, Compose UI)

## Android Main UI (Feature 3.5)

The Android app includes a complete Material Design 3 UI built with Jetpack Compose.

### Architecture

```
MainActivity
    └─> MainScreen (Compose)
            ├─> VpnManager (ViewModel)
            │       ├─> StateFlow<ConnectionStatus>
            │       ├─> StateFlow<VpnConfig?>
            │       └─> StateFlow<ConnectionStats?>
            ├─> StatusIcon (120dp visual indicator)
            ├─> Connection Button (connect/disconnect)
            └─> StatsCard (when connected)
```

### Components

**MainScreen**: Primary UI with:
- Top app bar with settings button
- Centered status icon (color-coded by state)
- Status text and server endpoint display
- Large connection button in thumb zone
- Statistics card (conditional on Connected state)

**StatusIcon**: Visual status indicator:
- Disconnected: Gray circle with close icon
- Connecting: Orange circle with refresh icon
- Connected: Green circle with checkmark
- Error: Red circle with warning icon

**StatsCard**: Connection statistics display:
- Duration (hours and minutes)
- Bytes sent/received (formatted KB/MB/GB)
- Server latency (when available)

**VpnManager**: ViewModel for state management:
- Loads configuration from storage on init
- Provides `connect()` and `disconnect()` methods
- Exposes reactive StateFlows for UI observation
- Uses AndroidViewModel to avoid context leaks

### Usage Example

```kotlin
import androidx.compose.runtime.Composable
import androidx.lifecycle.viewmodel.compose.viewModel
import com.prrr.vpn.android.ui.MainScreen
import com.prrr.vpn.android.viewmodel.VpnManager

@Composable
fun App(application: android.app.Application) {
    val vpnManager: VpnManager = viewModel(
        factory = VpnManagerFactory(application)
    )
    
    MainScreen(
        vpnManager = vpnManager,
        onSettingsClick = { /* Navigate to settings */ }
    )
}
```

### State Management

The UI automatically reacts to state changes:

```kotlin
val status by vpnManager.status.collectAsState()
val config by vpnManager.config.collectAsState()
val stats by vpnManager.stats.collectAsState()

// UI re-renders when any StateFlow emits new value
```

### Testing

- 7 unit tests for VpnManager (100% pass)
- Tests verify initial state, configuration loading, method existence
- Uses Robolectric for Android framework mocking
- APK builds successfully at 38 MB

## Android Settings & Error Handling (Feature 3.6)

The Android app includes a settings screen, battery optimization guidance, and error dialog system.

### Architecture

```
MainActivity NavHost
    ├─> "main"     -> MainScreen (settings button)
    ├─> "settings" -> SettingsScreen
    │                   ├─> Connection section (config display)
    │                   ├─> Configuration section (import/delete)
    │                   ├─> Battery section (optimization warning)
    │                   └─> About section (version)
    └─> "scanner"  -> QRScannerScreen

Error Handling:
    MobileException -> mapErrorToContent() -> ErrorContent
                                                ├─> title
                                                ├─> message
                                                └─> retryLabel?
```

### Components

**SettingsScreen**: Settings UI with 4 sections:
- **Connection**: Displays client name, server, IP, DNS, MTU (read-only)
- **Configuration**: "Import New Configuration" and "Delete Configuration" (with confirmation)
- **Battery**: Warning card when optimization is enabled, with system intent to request exemption
- **About**: App version display

**ErrorDialog**: Maps `MobileException` variants to user-friendly dialogs:
| Error | Title | Retry? |
|-------|-------|--------|
| InvalidConfig | Invalid Configuration | No |
| ConnectionFailed | Connection Failed | Yes |
| HandshakeFailed | Security Check Failed | No |
| NetworkException | Network Error | Yes |
| NotConnected | Not Connected | No |

**BatteryOptimizationHelper**: Utility for battery optimization:
- `isIgnoringBatteryOptimizations(context)` - Check if app is exempt
- `createBatteryOptimizationIntent(context)` - Intent to request exemption

### VpnManager Extensions

```kotlin
// Reload configuration after QR scan
vpnManager.reloadConfiguration()

// Delete configuration (clears storage + StateFlow)
val deleted: Boolean = vpnManager.deleteConfiguration()
```

### Testing

- 15 unit tests for ErrorContent mapping (all 5 variants, title/message/action)
- 4 unit tests for BatteryOptimizationHelper intent creation
- 5 unit tests for VpnManager reload/delete methods
- APK builds successfully

## Android Release Build (Feature 3.7)

The Android app is configured for Play Store distribution with R8 minification and signing.

### Build Commands

```bash
# Debug APK (no minification)
make android-debug
# Output: prrr-android/app/build/outputs/apk/debug/app-debug.apk (~38 MB)

# Release APK (R8 minified, unsigned unless keystore configured)
make android-release
# Output: prrr-android/app/build/outputs/apk/release/app-release-unsigned.apk (~27 MB)

# Run unit tests
make android-test
```

### Signing Configuration

Release signing reads credentials from two sources (in priority order):

1. **local.properties** (for local development):
   ```properties
   signing.storeFile=/path/to/keystore.jks
   signing.storePassword=your-store-password
   signing.keyAlias=prrr-vpn
   signing.keyPassword=your-key-password
   ```

2. **Environment variables** (for CI/CD):
   ```bash
   export PRRR_KEYSTORE_PATH=/path/to/keystore.jks
   export PRRR_KEYSTORE_PASSWORD=your-store-password
   export PRRR_KEY_ALIAS=prrr-vpn
   export PRRR_KEY_PASSWORD=your-key-password
   ```

When no signing is configured, the release build produces an unsigned APK.

### Generating a Signing Key

```bash
keytool -genkey -v \
  -keystore prrr-vpn.jks \
  -keyalg RSA -keysize 2048 \
  -validity 10000 \
  -alias prrr-vpn
```

### ProGuard/R8 Rules

The release build uses R8 with comprehensive keep rules for:
- **UniFFI**: All generated binding classes (`uniffi.**`)
- **JNA**: Native access classes and Library implementors
- **Kotlin coroutines**: Volatile fields and dispatcher infrastructure
- **AndroidX ViewModel**: All ViewModel subclasses
- **Mapping file**: Output for crash report deobfuscation

### Adaptive Launcher Icons

The app uses adaptive icons (Android 8.0+) with:
- **Foreground**: White shield with teal lock symbol (vector drawable)
- **Background**: Solid teal (#00897B)
- **Fallback**: Bitmap PNGs for devices below API 26

## Roadmap

- ✅ Feature 1.2: UniFFI Interface Definition (parse_qr_config, validate_config)
- ✅ Feature 1.3: QR Code Parsing Integration (implemented in 1.2)
- ✅ Feature 1.4: Connection State Management (VpnConnection, state machine foundation)
- ✅ Feature 1.5: Core VPN Connection (async stub with simulated transitions)
- ⏳ Feature 1.6: Mobile Library Documentation & Examples

## See Also

- [Mobile Build Guide](mobile-build.md) - Prerequisites and build instructions
- [FRD-M002](../specs/frds/FRD-M002-uniffi-interface.md) - UniFFI Interface technical specification
- [FRD-M005](../specs/frds/FRD-M005-core-connection.md) - Core VPN Connection stub implementation
- [FRD-M013](../specs/frds/FRD-M013-settings-battery-errors.md) - Settings, Battery & Error Handling specification
- [FRD-M014](../specs/frds/FRD-M014-android-internal-testing.md) - Android Internal Testing Track specification
- [Roadmap](../specs/mobile-app/ROADMAP.md) - Full mobile implementation roadmap
