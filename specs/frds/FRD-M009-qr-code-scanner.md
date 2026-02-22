# FRD-M009: QR Code Scanner (Android)

## Roadmap Link
- Source roadmap: `ROADMAP.md`
- Feature: Phase 3, Feature 3.2: QR Code Scanner (Android)

## Problem
Users need a convenient way to import VPN configuration into the mobile app without manually entering connection details. Manual entry is error-prone and tedious, especially for complex configurations with encryption keys and server endpoints.

## Context
The prrr mobile app requires users to configure VPN connections. The Rust core library already provides `parseQrConfig()` and `validateConfig()` functions that can parse QR code data in the format `prrr://import?config=<base64>`. The Android app needs a camera-based QR scanner to read these codes and pass them to the Rust parsing logic through the UniFFI bindings.

## Goal
Implement a QR code scanner for Android that:
1. Requests and handles camera permissions properly
2. Displays a camera preview with scanning UI
3. Uses Google ML Kit to detect and decode QR codes
4. Integrates with Rust `parseQrConfig()` to validate and parse scanned data
5. Provides clear feedback to users during scanning
6. Handles errors gracefully (invalid QR codes, camera failures, permissions denied)

## In Scope
- Camera permission request and handling (AndroidManifest.xml + runtime)
- QR scanner screen using Jetpack Compose
- CameraX integration for camera preview
- ML Kit Barcode Scanning for QR code detection
- Integration with `uniffi.prrr_mobile.parseQrConfig()`
- Error handling for invalid QR codes and camera failures
- Navigation to QR scanner from main screen
- Visual feedback (scanning indicator, success/error states)

## Out of Scope
- Generating QR codes (desktop app feature)
- Scanning from image gallery (camera-only for now)
- Manual configuration entry screen (future feature)
- Multi-QR code batch scanning
- QR code format other than `prrr://import?config=<base64>`
- Torch/flashlight toggle (can add later)
- iOS implementation (separate feature)

## Functional Requirements

### Must Have
- **REQ-M009-001**: App MUST request CAMERA permission before accessing camera
- **REQ-M009-002**: App MUST handle permission denial gracefully with user-friendly message
- **REQ-M009-003**: Scanner MUST use CameraX for camera preview
- **REQ-M009-004**: Scanner MUST use ML Kit Barcode Scanning API for QR detection
- **REQ-M009-005**: Scanner MUST call `uniffi.prrr_mobile.parseQrConfig()` with scanned data
- **REQ-M009-006**: Scanner MUST display error message for invalid QR codes
- **REQ-M009-007**: Scanner MUST stop camera when leaving the screen
- **REQ-M009-008**: Scanner MUST handle `MobileException.InvalidConfig` from Rust parsing
- **REQ-M009-009**: Scanner MUST navigate to configuration screen on successful parse
- **REQ-M009-010**: Scanner UI MUST show visual feedback during scanning (crosshair, overlay)

### Should Have
- **REQ-M009-011**: Scanner SHOULD provide haptic feedback on successful scan
- **REQ-M009-012**: Scanner SHOULD show preview of parsed config before saving
- **REQ-M009-013**: Scanner SHOULD prevent multiple scans of the same QR code in quick succession
- **REQ-M009-014**: Scanner SHOULD display instructions ("Point camera at QR code")

### Could Have
- **REQ-M009-015**: Scanner COULD support pinch-to-zoom
- **REQ-M009-016**: Scanner COULD show scan history
- **REQ-M009-017**: Scanner COULD auto-focus on QR codes

### Won't Have
- **REQ-M009-018**: Won't support non-QR barcodes (1D barcodes, Aztec, etc.)
- **REQ-M009-019**: Won't support scanning from gallery in this iteration

## Non-Functional Requirements

### Performance
- **NFR-M009-001**: Camera preview MUST start within 1 second of opening scanner
- **NFR-M009-002**: QR code detection latency MUST be < 500ms from frame to parse
- **NFR-M009-003**: Scanner MUST maintain 30 FPS camera preview on mid-range devices

### Security
- **NFR-M009-004**: Scanned QR data MUST be validated by Rust parser before use
- **NFR-M009-005**: Camera frames MUST NOT be stored or logged
- **NFR-M009-006**: Invalid QR data MUST NOT crash the app

### Usability
- **NFR-M009-007**: Permission denial message MUST include instructions to enable in Settings
- **NFR-M009-008**: Error messages MUST be clear and actionable
- **NFR-M009-009**: Scanner UI MUST work in both portrait and landscape orientations

### Reliability
- **NFR-M009-010**: Scanner MUST gracefully handle camera hardware failures
- **NFR-M009-011**: Scanner MUST release camera resources when app goes to background
- **NFR-M009-012**: Scanner MUST recover if ML Kit initialization fails

## Stressors (Residuality Step 1)

1. **Camera Permission Denial**: User denies camera permission or revokes it in settings
2. **Camera Hardware Failure**: Device camera is broken, in use by another app, or doesn't exist
3. **ML Kit Initialization Failure**: Google Play Services unavailable or outdated
4. **Invalid QR Code Format**: User scans wrong type of QR code (URL, contact, etc.)
5. **Malformed prrr:// URL**: QR contains `prrr://` but with invalid structure
6. **Invalid Base64 Data**: Config parameter is not valid base64 or decodes to garbage
7. **Rust Parser Rejection**: Valid base64 but config validation fails in Rust
8. **Network Dependency**: ML Kit downloads models over network, may fail offline
9. **Memory Pressure**: Camera preview + ML Kit consume significant memory
10. **Rapid Screen Rotation**: User rotates device while camera is initializing
11. **App Backgrounding During Scan**: User switches apps mid-scan
12. **Multiple QR Codes in Frame**: ML Kit detects multiple barcodes simultaneously
13. **Poor Lighting Conditions**: Dark environment makes QR code unreadable
14. **Blurry/Damaged QR Code**: Physical QR code is smudged, wrinkled, or low-quality
15. **Extremely Large QR Code**: Config data results in QR too dense to scan reliably

## Residue-First Design (Step 2)

### Architecture Components

```
┌─────────────────────────────────────────────────────────┐
│ QRScannerScreen.kt (Compose UI)                        │
│  - Camera permission handling                          │
│  - Navigation control                                  │
│  - Error state UI                                      │
└─────────────────┬───────────────────────────────────────┘
                  │
                  v
┌─────────────────────────────────────────────────────────┐
│ CameraPreviewView.kt (AndroidView wrapper)             │
│  - CameraX Preview + ImageAnalysis use cases           │
│  - Lifecycle management                                │
│  - Camera release on cleanup                           │
└─────────────────┬───────────────────────────────────────┘
                  │
                  v
┌─────────────────────────────────────────────────────────┐
│ QRCodeAnalyzer.kt (ImageAnalysis.Analyzer)            │
│  - ML Kit BarcodeScanner                               │
│  - QR format filtering (TYPE_QR_CODE only)             │
│  - Debouncing (prevent duplicate scans)                │
└─────────────────┬───────────────────────────────────────┘
                  │
                  v
┌─────────────────────────────────────────────────────────┐
│ QRScanViewModel.kt (State management)                  │
│  - Scan state (Idle, Scanning, Success, Error)        │
│  - Call uniffi.prrr_mobile.parseQrConfig()             │
│  - Error handling and retry logic                      │
└─────────────────┬───────────────────────────────────────┘
                  │
                  v
┌─────────────────────────────────────────────────────────┐
│ uniffi.prrr_mobile.parseQrConfig() [Rust FFI]         │
│  - Validates prrr:// URL format                        │
│  - Decodes base64 config data                          │
│  - Returns VpnConfig or throws MobileException         │
└─────────────────────────────────────────────────────────┘
```

### Stressor Mitigations

1. **Camera Permission Denial**
   - Show explanatory dialog before requesting permission
   - Provide "Open Settings" button if permission permanently denied
   - Graceful fallback UI: "Camera access required to scan QR codes"

2. **Camera Hardware Failure**
   - Catch `CameraAccessException` and show actionable error
   - Check camera availability before initializing CameraX
   - Provide "Retry" button for transient failures

3. **ML Kit Initialization Failure**
   - Use offline model bundled with app (no network dependency)
   - Catch initialization exceptions and fall back to error state
   - Log ML Kit version and failure details for debugging

4. **Invalid QR Code Format**
   - Filter by `Barcode.TYPE_QR_CODE` in ML Kit scanner
   - Check for `prrr://import` prefix before calling Rust parser
   - Show helpful error: "This is not a prrr VPN config QR code"

5. **Malformed prrr:// URL**
   - Rust parser validates URL structure
   - Catch `MobileException.InvalidConfig` and display reason
   - Show error with QR data preview (first 50 chars)

6. **Invalid Base64 Data**
   - Rust parser handles base64 decode failures
   - Return `InvalidConfig` with reason "Invalid base64 encoding"
   - UI shows: "QR code contains invalid data"

7. **Rust Parser Rejection**
   - Catch `MobileException.InvalidConfig` separately from other errors
   - Display validation failure reason from Rust (e.g., "Missing server address")
   - Provide "Scan Again" button

8. **Network Dependency**
   - Use `BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()`
   - This bundles QR decoder model with app (no download needed)
   - Test offline mode explicitly

9. **Memory Pressure**
   - Use `ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST` to drop frames under load
   - Set reasonable preview resolution (not max camera resolution)
   - Release camera immediately when leaving screen

10. **Rapid Screen Rotation**
    - CameraX handles orientation changes automatically
    - Use `rememberLauncherForActivityResult` to survive config changes
    - ViewModel preserves scan state across rotations

11. **App Backgrounding During Scan**
    - Bind camera to lifecycle (`lifecycleOwner` in CameraX)
    - Camera auto-releases when lifecycle stops
    - Reset scan state when returning to foreground

12. **Multiple QR Codes in Frame**
    - Process only first detected QR code in frame
    - Show error if multiple prrr:// QR codes detected (ambiguous)
    - Filter for prrr:// prefix before counting

13. **Poor Lighting Conditions**
    - Enable auto-exposure and auto-focus in CameraX
    - Show hint: "Move to a well-lit area" if no QR detected for 10s
    - (Future: add flashlight toggle)

14. **Blurry/Damaged QR Code**
    - ML Kit handles error correction in QR codes automatically
    - Show hint: "Hold steady and ensure QR code is clear"
    - Provide "Enter Manually" fallback (future feature)

15. **Extremely Large QR Code**
    - ML Kit supports high-density QR codes
    - If parsing succeeds but QR is visually large, it's fine
    - Rust parser validates config size limits

### Data Flow

```
User opens scanner
    → Check CAMERA permission
        → Denied: Show permission rationale + request
            → Still denied: Show "Open Settings" UI
        → Granted: Initialize CameraX
            → Start Preview + ImageAnalysis
                → ML Kit processes frames
                    → QR code detected
                        → Filter TYPE_QR_CODE
                            → Check prrr://import prefix
                                → Call uniffi.prrr_mobile.parseQrConfig(rawValue)
                                    → Success: Navigate to config screen with VpnConfig
                                    → InvalidConfig: Show error with reason
                                    → Other error: Show generic error + retry
```

## Acceptance Criteria

1. **AC-M009-001**: User can open QR scanner from main screen
2. **AC-M009-002**: Scanner requests camera permission on first use
3. **AC-M009-003**: Scanner shows camera preview after permission granted
4. **AC-M009-004**: Scanner detects valid prrr:// QR code within 2 seconds
5. **AC-M009-005**: Scanner successfully parses QR data using Rust parseQrConfig()
6. **AC-M009-006**: Scanner navigates to config screen with parsed VpnConfig
7. **AC-M009-007**: Scanner shows error message for invalid QR codes
8. **AC-M009-008**: Scanner shows error message for non-prrr QR codes (e.g., URLs)
9. **AC-M009-009**: Scanner releases camera when user navigates away
10. **AC-M009-010**: Scanner handles permission denial gracefully
11. **AC-M009-011**: Scanner works in both portrait and landscape orientations
12. **AC-M009-012**: Scanner prevents scanning same QR code multiple times rapidly

## Test Matrix

### Unit Tests

| Test Case | Input | Expected Output |
|-----------|-------|-----------------|
| `test_qr_analyzer_filters_qr_codes` | Barcode with TYPE_URL | Ignored (no callback) |
| `test_qr_analyzer_accepts_qr` | Barcode with TYPE_QR_CODE | Callback invoked |
| `test_qr_analyzer_debounce` | Same QR scanned 2x in 1s | Callback invoked once |
| `test_viewmodel_parse_valid_qr` | `prrr://import?config=<valid>` | Success state with VpnConfig |
| `test_viewmodel_parse_invalid_prefix` | `https://example.com` | Error state "Not a prrr QR code" |
| `test_viewmodel_parse_invalid_config` | `prrr://import?config=invalid` | Error state with Rust reason |
| `test_viewmodel_reset_state` | After error, call reset() | State returns to Idle |

### Integration Tests

| Test Case | Setup | Action | Expected Result |
|-----------|-------|--------|-----------------|
| `test_permission_request_flow` | Mock permission denied | Open scanner | Permission dialog shown |
| `test_camera_initialization` | Permission granted | Open scanner | Camera preview visible |
| `test_scan_success_navigation` | Valid QR code | Scan QR | Navigate to config screen |
| `test_scan_invalid_qr` | Non-prrr QR code | Scan QR | Error message displayed |
| `test_camera_release` | Scanner open | Navigate back | Camera released |
| `test_rotation_handling` | Scanner running | Rotate device | Scanner continues working |

### Manual Tests

| Test Case | Steps | Expected Result |
|-----------|-------|-----------------|
| Real QR scan | Generate real prrr:// QR, scan with device | Config imported successfully |
| Poor lighting | Test in dark room | Hint shown after 10s or scan succeeds when moved to light |
| Blurry QR | Shake device while scanning | Error or success when steadied |
| Permission denial | Deny permission permanently | "Open Settings" button shown |
| Multiple QRs | Show 2 QR codes at once | First one scanned or error shown |
| App backgrounding | Scan, switch app, return | Camera restarted, state preserved |

## Risks & Mitigation Strategies

- **Risk 1**: ML Kit requires Google Play Services, may not be available on all devices
  - Mitigation Strategy 1: Use bundled model (no GMS download required for QR codes)
  - Mitigation Strategy 2: Check Play Services availability and show clear error if missing
  - Mitigation Strategy 3: Future: Add fallback to ZXing library for non-GMS devices

- **Risk 2**: Camera access conflicts with other apps or system issues
  - Mitigation Strategy 1: Always release camera in `onPause()` lifecycle event
  - Mitigation Strategy 2: Show actionable error message with "Retry" button
  - Mitigation Strategy 3: Log camera errors to help diagnose device-specific issues

- **Risk 3**: Users may scan QR codes from untrusted sources
  - Mitigation Strategy 1: Rust parser validates all config data before use
  - Mitigation Strategy 2: Show preview of parsed config before connecting
  - Mitigation Strategy 3: Future: Add "Trust this config?" confirmation dialog

- **Risk 4**: Performance issues on low-end devices (slow camera init, frame drops)
  - Mitigation Strategy 1: Use lower preview resolution on low-memory devices
  - Mitigation Strategy 2: Test on Android SDK 26 devices (minimum supported)
  - Mitigation Strategy 3: Use `STRATEGY_KEEP_ONLY_LATEST` to avoid frame queue buildup

- **Risk 5**: QR codes may be too large or complex for reliable scanning
  - Mitigation Strategy 1: Document maximum config size in desktop QR generator
  - Mitigation Strategy 2: Test with real-world config sizes (likely < 1KB)
  - Mitigation Strategy 3: Future: Add "Enter code manually" fallback

## Rollback

**Rollback Strategy**: 
- Feature is additive (no existing functionality modified)
- If critical bugs found post-release, hide QR scanner button via feature flag
- Users can still manually enter configs (future feature to be added)
- Remove scanner screen from navigation and dependencies from build.gradle.kts
- No data migration needed (scanner doesn't store persistent data)

## Implementation Checklist for Agent

- [ ] Step 1: Add CameraX and ML Kit dependencies to `prrr-android/app/build.gradle.kts`
- [ ] Step 2: Add CAMERA permission to `prrr-android/app/src/main/AndroidManifest.xml`
- [ ] Step 3: Create `QRScanViewModel.kt` with scan state management
- [ ] Step 4: Create `QRCodeAnalyzer.kt` implementing `ImageAnalysis.Analyzer` with ML Kit
- [ ] Step 5: Create `CameraPreviewView.kt` wrapping CameraX in Compose AndroidView
- [ ] Step 6: Create `QRScannerScreen.kt` with permission handling and UI
- [ ] Step 7: Add navigation route to QR scanner in navigation graph
- [ ] Step 8: Write unit tests for QRCodeAnalyzer (QR filtering, debouncing)
- [ ] Step 9: Write unit tests for QRScanViewModel (parse valid/invalid QR codes)
- [ ] Step 10: Write integration tests for permission flow and camera initialization
- [ ] Step 11: Test with real prrr:// QR codes on physical device
- [ ] Step 12: Test error cases (invalid QR, permission denial, camera failure)
- [ ] Step 13: Update `docs/mobile-api.md` with QR scanner documentation
- [ ] Step 14: Update `ROADMAP.md` to mark Feature 3.2 as complete
- [ ] Step 15: Add traceability links to FRD and implementation files

## Traceability
- Roadmap item: [specs/mobile-app/ROADMAP.md](../../specs/mobile-app/ROADMAP.md#feature-32-qr-code-scanner-android-) - Phase 3, Feature 3.2: QR Code Scanner (Android)
- Implementation files:
  - `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/scanner/QRScanViewModel.kt` - State management with Rust integration
  - `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/scanner/QRCodeAnalyzer.kt` - ML Kit barcode scanning with debouncing
  - `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/scanner/CameraPreviewView.kt` - CameraX Compose wrapper
  - `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/scanner/QRScannerScreen.kt` - Main screen with permission handling
  - `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/scanner/ScanState.kt` - State sealed class
  - `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/MainActivity.kt` - Navigation integration
  - `prrr-android/app/build.gradle.kts` - CameraX and ML Kit dependencies
  - `prrr-android/app/src/main/AndroidManifest.xml` - Camera permissions
- Test files:
  - `prrr-android/app/src/test/kotlin/com/prrr/vpn/android/scanner/QRScanViewModelTest.kt` - ViewModel unit tests
- Documentation:
  - [docs/mobile-api.md](../../docs/mobile-api.md#android-qr-scanner-feature-32) - API documentation with usage examples
