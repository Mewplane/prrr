# FRD-M001: Mobile Workspace & Build Infrastructure

**Feature:** Feature 1.1 - Project Setup & Build Infrastructure  
**Status:** Complete  
**Created:** 2026-02-22  
**Updated:** 2026-02-22  
**Completed:** 2026-02-22

## Overview

Establish build infrastructure for cross-platform mobile development by creating a separate `prrr-mobile` library crate within the existing workspace, configuring cargo for iOS/Android cross-compilation, and providing build scripts for generating platform-specific artifacts (iOS frameworks and Android AARs).

## Motivation

The prrr VPN protocol must be accessible from native mobile applications (iOS and Android). To maximize code reuse and minimize duplication, the core protocol implementation (QUIC/MASQUE, crypto, handshake) should be compiled as a shared Rust library that can be consumed by platform-native UI code via FFI (Foreign Function Interface).

This FRD focuses exclusively on the **build infrastructure** required to:
1. Create a workspace member for mobile library code
2. Configure cross-compilation for mobile targets
3. Provide build scripts that produce distributable artifacts
4. Verify the build pipeline works end-to-end

## Goals

1. **Workspace Structure**: Add `prrr-mobile` as a workspace member alongside the existing `prrr` binary crate
2. **Cross-Compilation**: Support building for iOS (aarch64-apple-ios, x86_64-apple-ios-sim, aarch64-apple-ios-sim) and Android (aarch64-linux-android, armv7-linux-androideabi, x86_64-linux-android)
3. **Build Automation**: Provide shell scripts that automate the build process for each platform
4. **Artifact Generation**: Produce iOS xcframework and Android AAR files
5. **Documentation**: Document the build process in the mobile library README

## Non-Goals

- Implementing actual mobile API or UniFFI bindings (covered in Feature 1.2)
- Setting up CI/CD pipelines (mentioned but not implemented in this FRD)
- Writing iOS or Android application code
- Performance optimization of mobile builds

## Requirements

### Functional Requirements

**FR-M001-01**: Root `Cargo.toml` SHALL declare a workspace with members `["."]` (existing prrr binary) and `["prrr-mobile"]`

**FR-M001-02**: `prrr-mobile/Cargo.toml` SHALL define a library crate with:
- Name: `prrr-mobile`
- Edition: `2024`
- Rust version: `1.85`
- Library type: `cdylib` and `staticlib` for FFI compatibility

**FR-M001-03**: `scripts/build-ios.sh` SHALL:
- Build for all required iOS targets (aarch64-apple-ios, x86_64-apple-ios-sim, aarch64-apple-ios-sim)
- Use `lipo` or `xcodebuild` to create universal binaries
- Package output as `.xcframework`
- Place xcframework in `prrr-mobile/target/universal/`

**FR-M001-04**: `scripts/build-android.sh` SHALL:
- Build for all required Android targets (aarch64-linux-android, armv7-linux-androideabi, x86_64-linux-android)
- Package output as `.aar` file
- Place AAR in `prrr-mobile/target/`

**FR-M001-05**: `scripts/generate-bindings.sh` SHALL be a placeholder script that echoes "UniFFI bindings generation - to be implemented in Feature 1.2"

**FR-M001-06**: `prrr-mobile/README.md` SHALL document:
- Purpose of the mobile library
- Build instructions for iOS and Android
- Prerequisites (Rust version, platform SDKs)
- Output artifact locations

### Non-Functional Requirements

**NFR-M001-01**: Build scripts SHALL be idempotent (safe to run multiple times)

**NFR-M001-02**: Build scripts SHALL validate prerequisites (Rust targets installed, NDK configured) and fail fast with clear error messages

**NFR-M001-03**: Build time for full cross-platform build SHALL be under 10 minutes on a modern development machine

**NFR-M001-04**: Build scripts SHALL support `DEBUG=1` environment variable for debug builds

## Design

### Workspace Structure

```
prrr/
├── Cargo.toml          # Workspace root with members
├── src/                # Existing prrr binary
├── prrr-mobile/
│   ├── Cargo.toml      # Mobile library crate
│   ├── src/
│   │   └── lib.rs      # Minimal library stub
│   ├── README.md       # Build documentation
│   └── target/         # Build artifacts (gitignored)
│       ├── universal/  # iOS xcframeworks
│       └── *.aar       # Android AARs
└── scripts/
    ├── build-ios.sh
    ├── build-android.sh
    └── generate-bindings.sh
```

### Build Script Design

#### iOS Build Script (`scripts/build-ios.sh`)

**Inputs:**
- `DEBUG=1` env var (optional): build debug instead of release

**Algorithm:**
1. Verify iOS targets installed: `rustup target list --installed | grep ios`
2. Build for each iOS target with `cargo build --target <TARGET> --profile <PROFILE>`
3. Create universal binary with `lipo -create` for simulator architectures
4. Create xcframework directory structure manually (or use `xcodebuild -create-xcframework` if available)
5. Copy binaries and headers into xcframework bundle

**Outputs:**
- `prrr-mobile/target/universal/prrr_mobile.xcframework/`

**Error Handling:**
- Exit with code 1 if targets not installed, print installation command
- Exit with code 1 if build fails for any target
- Exit with code 1 if lipo/xcodebuild fails

#### Android Build Script (`scripts/build-android.sh`)

**Inputs:**
- `NDK_HOME` env var: path to Android NDK
- `DEBUG=1` env var (optional): build debug instead of release

**Algorithm:**
1. Verify `NDK_HOME` is set and valid
2. Verify Android targets installed
3. For each target, set appropriate linker in `.cargo/config.toml` (temporary or pre-configured)
4. Build for each Android target with `cargo build --target <TARGET> --profile <PROFILE>`
5. Create AAR structure:
   - `jni/<arch>/libprrr_mobile.so` for each architecture
   - `AndroidManifest.xml` stub
   - Package as ZIP with `.aar` extension

**Outputs:**
- `prrr-mobile/target/prrr_mobile.aar`

**Error Handling:**
- Exit with code 1 if NDK_HOME not set or invalid
- Exit with code 1 if targets not installed
- Exit with code 1 if build fails for any target

### Library Stub

For Feature 1.1, `prrr-mobile/src/lib.rs` contains only:
```rust
//! prrr mobile library stub
//!
//! This module will be populated with UniFFI interface in Feature 1.2.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_exists() {
        assert!(!VERSION.is_empty());
    }
}
```

## Acceptance Criteria

**AC-M001-01**: Root `Cargo.toml` includes workspace configuration with `prrr-mobile` member

**AC-M001-02**: `cargo build -p prrr-mobile` succeeds on host platform

**AC-M001-03**: `./scripts/build-ios.sh` produces `prrr-mobile/target/universal/prrr_mobile.xcframework/` (on macOS or with appropriate SDK)

**AC-M001-04**: `./scripts/build-android.sh` produces `prrr-mobile/target/prrr_mobile.aar` (with NDK installed)

**AC-M001-05**: Build scripts fail fast with clear error messages when prerequisites are missing

**AC-M001-06**: `prrr-mobile/README.md` documents build process with examples

**AC-M001-07**: `make lint` passes for `prrr-mobile` crate

**AC-M001-08**: All clippy warnings resolved in `prrr-mobile` stub

## Testing Strategy

Since this is build infrastructure, testing is verification-based:

### Build Verification Tests

**Test 1: Workspace Configuration**
```bash
# Verify workspace members
cargo metadata --no-deps --format-version 1 | jq '.workspace_members'
# Expected: contains prrr and prrr-mobile
```

**Test 2: Library Compiles**
```bash
cargo build -p prrr-mobile
cargo test -p prrr-mobile
# Expected: both succeed with exit code 0
```

**Test 3: iOS Build Script (macOS only)**
```bash
./scripts/build-ios.sh
test -d prrr-mobile/target/universal/prrr_mobile.xcframework
# Expected: directory exists
```

**Test 4: Android Build Script**
```bash
export NDK_HOME=/path/to/ndk
./scripts/build-android.sh
test -f prrr-mobile/target/prrr_mobile.aar
# Expected: file exists
```

**Test 5: Prerequisite Validation**
```bash
# Remove iOS targets
rustup target remove aarch64-apple-ios
./scripts/build-ios.sh
# Expected: exits with code 1 and helpful error message

# Unset NDK_HOME
unset NDK_HOME
./scripts/build-android.sh
# Expected: exits with code 1 and helpful error message
```

**Test 6: Lint Compliance**
```bash
cargo clippy -p prrr-mobile -- -D warnings
cargo fmt --package prrr-mobile --check
# Expected: both succeed
```

### Coverage Target

Since this is infrastructure code:
- Build scripts: 100% of error paths tested manually
- Library stub: 100% coverage (single test)
- No integration tests needed for this feature

## Dependencies

- Rust 1.85+
- iOS targets: `aarch64-apple-ios`, `x86_64-apple-ios-sim`, `aarch64-apple-ios-sim`
- Android targets: `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`
- macOS with Xcode Command Line Tools (for iOS builds)
- Android NDK r25 or later (for Android builds)
- `lipo` (part of Xcode)
- `zip` utility (for AAR packaging)

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| iOS build only works on macOS | High | Document platform requirement; consider cross-compilation alternatives (not in scope for M001) |
| NDK version incompatibility | Medium | Document required NDK version; test with multiple versions |
| Build script portability (bash on Windows) | Low | Document bash requirement; consider PowerShell scripts in future |
| Large binary sizes | Low | Not optimized in M001; defer to later features |

## Implementation Checklist

Following the 14-step workflow from AGENTS.md:

- [x] Step 1-2: Read docs and take roadmap item
- [x] Step 3: Read all docs/
- [x] Step 4: Write this FRD
- [x] Step 5: Re-read FRD
- [x] Step 6: Write verification tests (lib.rs test, build script verification)
- [x] Step 7: Implement (Cargo.toml, lib.rs stub, build scripts)
- [x] Step 8: Run cargo clippy -p prrr-mobile -- -D warnings (PASS)
- [x] Step 9: Run make lint (PASS)
- [x] Step 10: Fix all warnings (None found)
- [x] Step 11: Iterate until all tests pass (1/1 tests passing)
- [x] Step 12: (No profiling needed for build infrastructure)
- [x] Step 13: Close roadmap item (marked complete in ROADMAP.md)
- [x] Step 14: Update docs/ (added mobile-build.md)
- [x] Step 15: Update AGENTS.md if needed (no changes required)
- [x] Step 16: Add traceability links (added to FRD, ROADMAP, source files)

## Traceability

**Roadmap**: `specs/mobile-app/ROADMAP.md` - Feature 1.1

**Related Specs**:
- Next: FRD-M002 (Feature 1.2 - UniFFI Interface Definition)

**Implementation** (Complete):
- [x] `Cargo.toml` - Workspace configuration with `prrr-mobile` member
- [x] `prrr-mobile/Cargo.toml` - Library crate manifest (cdylib, staticlib, lib)
- [x] `prrr-mobile/src/lib.rs` - Library stub with VERSION constant and test
- [x] `prrr-mobile/README.md` - Build documentation with prerequisites and usage
- [x] `scripts/build-ios.sh` - iOS build automation (creates xcframework)
- [x] `scripts/build-android.sh` - Android build automation (creates AAR)
- [x] `scripts/generate-bindings.sh` - Bindings placeholder for Feature 1.2
- [x] `docs/mobile-build.md` - User-facing build documentation with troubleshooting

## Open Questions

1. **Q**: Should we vendor the NDK or require users to install it?
   **A**: Require installation. Vendoring would bloat the repo.

2. **Q**: Should build scripts use `cargo-xcode` and `cargo-ndk` instead of raw cargo?
   **A**: Start with raw cargo for transparency. Can adopt specialized tools later.

3. **Q**: Should we set up GitHub Actions in this FRD?
   **A**: No. Feature 1.1 focuses on local build. CI is mentioned in DoD but deferred.

## References

- [Rust Mobile Book](https://rust-mobile.github.io/book/)
- [cargo-xcode](https://github.com/ohmyplatypus/cargo-xcode)
- [cargo-ndk](https://github.com/bbqsrc/cargo-ndk)
- [Creating XCFrameworks](https://developer.apple.com/documentation/xcode/creating-a-multi-platform-binary-framework-bundle)
- [Android NDK Rust Support](https://source.android.com/docs/setup/build/rust/building-rust-modules/overview)
