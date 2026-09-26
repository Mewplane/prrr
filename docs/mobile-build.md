# Mobile Build Guide

This guide describes how to build the prrr mobile library for iOS and Android platforms.

## Overview

The `prrr-mobile` library provides the core prrr VPN protocol implementation compiled for mobile platforms. It can be consumed by native iOS (Swift) and Android (Kotlin) applications via FFI (Foreign Function Interface).

**Current Status**: Feature 1.1 (Project Setup & Build Infrastructure) is complete. The library is a minimal stub. UniFFI bindings and mobile API will be added in Feature 1.2.

## Prerequisites

### All Platforms

- **Rust**: 1.85 or later (edition 2024)
- **Cargo**: Latest stable version

Install Rust via [rustup](https://rustup.rs/):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### iOS Development

**Requirements**:
- **Platform**: macOS only (cross-compilation from Linux/Windows not yet supported)
- **Xcode**: 14.0 or later
- **Xcode Command Line Tools**: Required for `lipo` and other build tools

Install Command Line Tools:
```bash
xcode-select --install
```

Install iOS targets:
```bash
rustup target add aarch64-apple-ios          # iOS devices (ARM64)
rustup target add x86_64-apple-ios           # iOS simulator (Intel)
rustup target add aarch64-apple-ios-sim      # iOS simulator (Apple Silicon)
```

### Android Development

**Requirements**:
- **Platform**: Any (Linux, macOS, Windows with bash)
- **Android NDK**: r25 or later
- **Build Tools**: `zip` utility

Download Android NDK from [developer.android.com/ndk/downloads](https://developer.android.com/ndk/downloads)

Or install via Android Studio:
1. Open Android Studio → SDK Manager
2. SDK Tools tab → Check "NDK (Side by side)"
3. Apply changes

Set `NDK_HOME` environment variable:
```bash
# Linux/macOS
export NDK_HOME=/path/to/android-ndk

# macOS with Android Studio
export NDK_HOME=~/Library/Android/sdk/ndk/25.2.9519653

# Linux with Android Studio
export NDK_HOME=~/Android/Sdk/ndk/25.2.9519653
```

Add to your shell profile (`.bashrc`, `.zshrc`, etc.) to persist across sessions.

Install Android targets:
```bash
rustup target add aarch64-linux-android      # ARM64 devices (most modern)
rustup target add armv7-linux-androideabi    # ARMv7 devices (older)
rustup target add x86_64-linux-android       # x86_64 emulator
rustup target add i686-linux-android         # x86 emulator
```

## Building for iOS

Navigate to the project root and run the iOS build script:

```bash
cd /path/to/prrr

# Release build (recommended for distribution)
./scripts/build-ios.sh

# Debug build (for development/debugging)
DEBUG=1 ./scripts/build-ios.sh
```

**Output**: `prrr-mobile/target/universal/prrr_mobile.xcframework/`

The script performs the following:
1. Verifies all iOS targets are installed
2. Builds for each target: `aarch64-apple-ios`, `x86_64-apple-ios`, `aarch64-apple-ios-sim`
3. Creates a universal simulator binary combining Intel and Apple Silicon
4. Packages everything as an XCFramework

**Build Time**: ~30 seconds on a modern Mac (release build)

### Using the XCFramework in Xcode

1. **Add to Project**:
   - Drag `prrr_mobile.xcframework` from Finder into your Xcode project navigator
   - Check "Copy items if needed"

2. **Configure Target**:
   - Select your app target
   - General tab → "Frameworks, Libraries, and Embedded Content"
   - Ensure `prrr_mobile.xcframework` is set to "Embed & Sign"

3. **Import in Swift**:
   ```swift
   // Once UniFFI bindings are added (Feature 1.2):
   import prrr_mobile
   ```

## Building for Android

Set `NDK_HOME` environment variable, then run the Android build script:

```bash
cd /path/to/prrr

# Set NDK path (if not already in environment)
export NDK_HOME=/path/to/android-ndk

# Release build (recommended for distribution)
./scripts/build-android.sh

# Debug build (for development/debugging)
DEBUG=1 ./scripts/build-android.sh
```

**Output**: `prrr-mobile/target/prrr_mobile.aar`

The script performs the following:
1. Verifies `NDK_HOME` is set and valid
2. Verifies all Android targets are installed
3. Configures NDK linkers in `.cargo/config.toml` (temporary)
4. Builds for each target: `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android`
5. Creates AAR structure with native libraries for each architecture
6. Packages as `.aar` file (Android Archive)

**Build Time**: ~1-2 minutes (release build, all architectures)

### Using the AAR in Android Studio

1. **Copy AAR to Project**:
   ```bash
   mkdir -p /path/to/android-project/app/libs
   cp prrr-mobile/target/prrr_mobile.aar /path/to/android-project/app/libs/
   ```

2. **Add Dependency** (`app/build.gradle` or `app/build.gradle.kts`):
   ```gradle
   dependencies {
       implementation(files("libs/prrr_mobile.aar"))
   }
   ```

3. **Sync Gradle** and build your app

4. **Import in Kotlin**:
   ```kotlin
   // Once UniFFI bindings are added (Feature 1.2):
   import uniffi.prrr_mobile.*
   ```

## Verification

After building, verify the artifacts exist:

```bash
# iOS
ls -lh prrr-mobile/target/universal/prrr_mobile.xcframework/

# Android
ls -lh prrr-mobile/target/prrr_mobile.aar
```

Verify library compiles and tests pass:
```bash
cargo test -p prrr-mobile
```

## Troubleshooting

### iOS: "Target not installed"

**Problem**: Build script exits with error about missing targets.

**Solution**: Install the missing target:
```bash
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
```

### iOS: "lipo: command not found"

**Problem**: `lipo` tool not found (used to create universal binaries).

**Solution**: Install Xcode Command Line Tools:
```bash
xcode-select --install
```

### iOS: "Error: iOS builds require macOS"

**Problem**: Running build script on Linux or Windows.

**Solution**: iOS cross-compilation from non-macOS platforms is complex and not yet supported. Use a macOS machine or VM, or use cloud CI (GitHub Actions with macOS runner).

### Android: "NDK_HOME environment variable not set"

**Problem**: Build script can't find the Android NDK.

**Solution**: Set the environment variable:
```bash
export NDK_HOME=/path/to/android-ndk
```

Make it permanent by adding to your shell profile:
```bash
echo 'export NDK_HOME=/path/to/android-ndk' >> ~/.bashrc
source ~/.bashrc
```

### Android: "linker `cc` not found"

**Problem**: NDK toolchain not found or incorrect NDK version.

**Solution**:
1. Verify NDK_HOME points to a valid NDK installation
2. Check that the toolchain exists: `ls ${NDK_HOME}/toolchains/llvm/prebuilt/`
3. Ensure NDK version is r25 or later
4. Re-download NDK if necessary

### Build Failures

**Problem**: Build fails with cryptic errors.

**Solution**: Clean and rebuild:
```bash
cargo clean -p prrr-mobile
./scripts/build-ios.sh     # or build-android.sh
```

### Large Binary Sizes

**Problem**: Release builds are larger than expected.

**Solution**: This is normal for the initial implementation. Binary size optimization will be addressed in later features. Debug builds are even larger (includes debug symbols).

## Sharing-Toggle Coordination Surface (FRD-004)

The "Enable sharing" toggle is coordinated through a signature-protected
`ContentProvider` (SPEC §3/§9.3, decision §9.4):

- **Kotlin** — `com.prrr.vpn.android.ecosystem.SharingProvider` is a *thin*
  `ContentProvider`. `query()` returns a one-row cursor with `enabled` (0/1) and
  `peer_mesh_addr` (null until Step 5); `update()` reads an `enabled` (0/1)
  `ContentValues` and flips the toggle. It holds no state of its own — it
  marshals to the Rust core.
- **Rust/UniFFI seam** — the provider calls `sharingGetState(statePath)` and
  `sharingSetEnabled(statePath, enabled)` (exported from `prrr-mobile`; see
  `docs/mobile-api.md`). The Rust core (`prrr::sharing`) is the single source of
  truth and the enforcement point, so the phone and laptop honor one consistent
  state. `statePath` is `<filesDir>/sharing.json`.
- **Signature protection** — the manifest declares a `signature`-`protectionLevel`
  permission `com.prrr.vpn.android.permission.ECOSYSTEM_COORDINATE`, set as the
  provider's `readPermission`/`writePermission`. Only apps co-signed with the
  same developer key (the `sy`/cathouse siblings) may read or flip the toggle;
  no user setup is required.

The enforcement logic (server-side pair auth + per-use biometric signature for an
authorized remote enable) stays in testable Rust — the Kotlin provider never
authorizes a remote enable on its own. The Rust seam is covered by
`prrr-mobile/src/sharing.rs::mobile_seam_toggle_drives_state`.

## Development Workflow

For local development (without cross-compilation):

```bash
# Build for host platform
cargo build -p prrr-mobile

# Run tests
cargo test -p prrr-mobile

# Run linter
cargo clippy -p prrr-mobile -- -D warnings

# Format code
cargo fmt --package prrr-mobile
```

## Next Steps

**Feature 1.2** (UniFFI Interface Definition) will add:
- `.udl` file defining the mobile API
- Swift and Kotlin bindings generation
- `scripts/generate-bindings.sh` implementation
- Mobile-specific types (VpnConfig, VpnConnection, etc.)

Once Feature 1.2 is complete, the build workflow will be:
```bash
# 1. Build native libraries
./scripts/build-ios.sh
./scripts/build-android.sh

# 2. Generate FFI bindings
./scripts/generate-bindings.sh

# 3. Distribute
# - Copy xcframework to iOS project
# - Copy AAR to Android project
# - Copy generated Swift/Kotlin bindings
```

## References

- [prrr Mobile README](../prrr-mobile/README.md)
- [Rust Mobile Book](https://rust-mobile.github.io/book/)
- [iOS Development Guide](https://developer.apple.com/documentation/)
- [Android NDK Guide](https://developer.android.com/ndk/guides)
- [Cargo Book - Build Scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
