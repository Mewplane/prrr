# FRD-M013: Settings, Battery Optimization & Error Handling - Android

## Roadmap Link
- Source roadmap: `specs/mobile-app/ROADMAP.md`
- Feature: Phase 3, Feature 3.6: Settings, Battery Optimization & Error Handling

## Problem
The Android app has a functional main UI (Feature 3.5), QR scanner (Feature 3.2), and configuration storage (Feature 3.3), but lacks:
1. A dedicated Settings screen for viewing/managing configuration
2. Battery optimization guidance to ensure stable VPN connections
3. User-friendly error dialogs that explain failures and offer recovery actions

Users cannot view their current configuration, delete it to re-import, or understand why connections fail. Android's aggressive battery optimization can kill VPN services without user awareness.

## Context
**Current State:**
- MainScreen settings button navigates to QR scanner (placeholder)
- ConfigurationManager supports save/load/delete/has operations
- VpnManager has ConnectionStatus enum with ERROR state
- No Settings UI, no error dialogs, no battery optimization guidance
- PrrrVpnService runs as foreground service but can still be killed by battery optimization

**Dependencies:**
- FRD-M012 (Main UI) - Provides navigation scaffold and VpnManager
- FRD-M010 (Configuration Storage) - Provides ConfigurationManager API
- FRD-M009 (QR Scanner) - Navigation target for re-import
- FRD-M011 (VpnService) - Service affected by battery optimization

## Goal
Implement:
1. Settings screen showing current configuration, import/delete actions, battery guidance, and app info
2. Error dialog system that maps MobileError variants to user-friendly messages with recovery actions
3. Battery optimization detection and guidance to exempt the app from Doze/App Standby

## In Scope
- `SettingsScreen.kt` composable with configuration display, actions, battery guidance, about section
- `ErrorDialog.kt` composable for displaying MobileError variants with contextual actions
- `BatteryOptimizationHelper.kt` utility for detecting and requesting battery optimization exemption
- Navigation integration (settings route in MainNavigation)
- VpnManager enhancement: `reloadConfiguration()`, `deleteConfiguration()`, error state flow
- Unit tests for BatteryOptimizationHelper, ErrorDialog content mapping, VpnManager new methods
- String resources for all user-facing text

## Out of Scope
- Advanced settings (DNS override, MTU tuning, kill switch toggle)
- In-app FAQ or help content beyond error messages
- Connection log viewer
- Manual configuration entry (only QR import)
- Split tunnel configuration
- Widget or Quick Settings tile
- ProGuard/R8 configuration for release builds

## Functional Requirements

### Must Have
- **FR-M013-001**: Settings screen MUST display current configuration details (client name, server endpoint, assigned IP, DNS servers, MTU)
- **FR-M013-002**: Settings screen MUST provide "Import New Configuration" action navigating to QR scanner
- **FR-M013-003**: Settings screen MUST provide "Delete Configuration" with confirmation dialog
- **FR-M013-004**: Configuration deletion MUST clear storage and navigate to QR scanner
- **FR-M013-005**: Settings screen MUST detect battery optimization status and show warning when enabled
- **FR-M013-006**: Battery warning MUST provide action to open system battery optimization settings
- **FR-M013-007**: Error dialog MUST map each MobileError variant to a user-friendly title and message
- **FR-M013-008**: Error dialog for ConnectionFailed MUST offer "Retry" action
- **FR-M013-009**: Error dialog for NetworkError MUST offer "Retry" action
- **FR-M013-010**: Settings screen MUST display app version
- **FR-M013-011**: Settings screen MUST be accessible via settings button on MainScreen
- **FR-M013-012**: VpnManager MUST expose methods to reload and delete configuration

### Should Have
- **FR-M013-013**: Settings screen SHOULD show section headers for grouping (Connection, Configuration, Battery, About)
- **FR-M013-014**: Delete confirmation dialog SHOULD use Material 3 AlertDialog
- **FR-M013-015**: Error dialog SHOULD be dismissible with "OK" button
- **FR-M013-016**: Settings screen SHOULD show "No configuration" state when config is null

### Could Have
- **FR-M013-017**: Settings COULD show configuration import timestamp
- **FR-M013-018**: Settings COULD show privacy policy link

## Non-Functional Requirements

### Performance
- **NFR-M013-001**: Settings screen MUST render within 100ms
- **NFR-M013-002**: Battery optimization check MUST complete within 50ms
- **NFR-M013-003**: Configuration deletion MUST complete within 200ms

### Usability
- **NFR-M013-004**: All text MUST support dynamic font scaling
- **NFR-M013-005**: All interactive elements MUST have TalkBack content descriptions
- **NFR-M013-006**: Color contrast MUST meet WCAG AA standards
- **NFR-M013-007**: Error messages MUST be actionable (tell user what to do)

### Compatibility
- **NFR-M013-008**: MUST work on Android 8.0+ (API 26+)
- **NFR-M013-009**: Battery optimization API MUST handle all Android versions gracefully
- **NFR-M013-010**: MUST render correctly in light and dark modes

## Stressors (Residuality Step 1)

1. **No configuration stored**: User opens settings before scanning QR
2. **Battery optimization varies by OEM**: Samsung, Xiaomi have extra restrictions
3. **Permission request denied**: User denies battery exemption request
4. **Configuration deleted while connected**: VPN service running during deletion
5. **Rapid navigation**: User taps settings/back rapidly
6. **Process death**: System kills app while on settings screen
7. **Concurrent deletion**: Two threads try to delete config simultaneously
8. **Error during deletion**: EncryptedSharedPreferences throws exception
9. **Theme change on settings**: Light/dark mode switch while viewing
10. **Large font scaling**: Accessibility font size 200%

## Design

### Architecture

```
MainNavigation
    ├─> "main"     -> MainScreen (existing)
    ├─> "scanner"  -> QRScannerScreen (existing)
    └─> "settings" -> SettingsScreen (NEW)
                          ├─> ConnectionSection (config display)
                          ├─> ConfigurationSection (import/delete)
                          ├─> BatterySection (optimization warning)
                          └─> AboutSection (version info)

Error Handling:
    VpnManager._error: MutableStateFlow<MobileError?>
        └─> MainScreen observes error state
                └─> ErrorDialog composable renders on non-null error
```

### Component Specifications

#### SettingsScreen

```kotlin
@Composable
fun SettingsScreen(
    vpnManager: VpnManager,
    onNavigateBack: () -> Unit,
    onNavigateToScanner: () -> Unit
)
```

**Sections:**
1. **Connection** - Display config fields (read-only LabeledContent rows)
2. **Configuration** - Import button, Delete button (with confirmation)
3. **Battery** - Warning card when optimization is enabled, "Open Settings" action
4. **About** - App version display

#### ErrorDialog

```kotlin
@Composable
fun ErrorDialog(
    error: MobileError,
    onDismiss: () -> Unit,
    onRetry: (() -> Unit)?
)
```

**Error Mapping:**
| MobileError Variant | Title | Message | Action |
|---------------------|-------|---------|--------|
| InvalidConfig | Invalid Configuration | The QR code or configuration is invalid. Please scan a valid prrr VPN QR code. | None |
| ConnectionFailed | Connection Failed | Unable to reach the VPN server. Check your internet connection and try again. | Retry |
| HandshakeFailed | Security Check Failed | The server's security credentials could not be verified. Your access may have been revoked. | None |
| NetworkError | Network Error | A network error occurred. Please check your connection and try again. | Retry |
| NotConnected | Not Connected | VPN is not currently connected. | None |

#### BatteryOptimizationHelper

```kotlin
object BatteryOptimizationHelper {
    fun isIgnoringBatteryOptimizations(context: Context): Boolean
    fun createBatteryOptimizationIntent(context: Context): Intent
}
```

## Acceptance Criteria

### Functional
- AC-M013-01: Settings screen displays all configuration fields when config exists
- AC-M013-02: Settings screen shows "No configuration" when config is null
- AC-M013-03: "Import" navigates to QR scanner
- AC-M013-04: "Delete" shows confirmation dialog, on confirm deletes config and navigates to scanner
- AC-M013-05: Battery warning appears when optimization is enabled
- AC-M013-06: Battery "Open Settings" launches system intent
- AC-M013-07: ErrorDialog shows correct title/message for each MobileError variant
- AC-M013-08: ErrorDialog "Retry" calls onRetry callback
- AC-M013-09: MainScreen settings button navigates to settings screen
- AC-M013-10: VpnManager.deleteConfiguration() clears config and updates StateFlow

### Non-Functional
- AC-M013-11: All unit tests pass
- AC-M013-12: Build passes with zero warnings
- AC-M013-13: Dark mode renders correctly
- AC-M013-14: TalkBack announces all elements

### Testing
- AC-M013-15: Unit tests for BatteryOptimizationHelper
- AC-M013-16: Unit tests for error-to-message mapping
- AC-M013-17: Unit tests for VpnManager.reloadConfiguration() and deleteConfiguration()
- AC-M013-18: Coverage >= 90% for new code

## Testing Strategy

### Unit Tests
- `BatteryOptimizationHelperTest.kt` - Battery optimization detection
- `ErrorMappingTest.kt` - Error variant to title/message mapping
- `VpnManagerTest.kt` (extend) - New methods: reloadConfiguration(), deleteConfiguration()

### Integration Tests
- Settings navigation flow (manual - requires device)
- Delete configuration flow (manual)
- Battery optimization intent launch (manual)

## Dependencies
- `android.os.PowerManager` - Battery optimization detection (API 23+, required API 26+)
- `android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` - Battery exemption
- `androidx.compose.material3` - AlertDialog, Card, ListItem components
- Existing: ConfigurationManager, VpnManager, MainNavigation

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| OEM-specific battery restrictions beyond standard Doze | VPN killed despite exemption | Document OEM-specific steps in error messages |
| EncryptedSharedPreferences corruption on delete | Config not fully cleared | Catch exceptions, attempt context.deleteFile() as fallback |
| Navigation state loss on process death | User returns to wrong screen | Use savedStateHandle in ViewModel |

## Implementation Checklist
1. [x] Read AGENTS.md and docs/
2. [x] Take first incomplete roadmap item (Feature 3.6)
3. [x] Write FRD (this document)
4. [x] Re-read FRD
5. [x] Write tests first
6. [x] Implement minimal code
7. [x] Run clippy and lint
8. [x] Iterate until clean
9. [x] Iterate until all tests pass
10. [x] Close roadmap item
11. [x] Update docs/
12. [x] Update AGENTS.md if needed (no changes needed)
13. [x] Add traceability links

## Traceability

### Forward Links
- Implementation files:
  - [x] `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/ui/SettingsScreen.kt` - NEW
  - [x] `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/ui/ErrorDialog.kt` - NEW
  - [x] `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/ui/ErrorContent.kt` - NEW
  - [x] `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/util/BatteryOptimizationHelper.kt` - NEW
  - [x] `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/viewmodel/VpnManager.kt` - MODIFIED (reloadConfiguration, deleteConfiguration)
  - [x] `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/MainActivity.kt` - MODIFIED (settings navigation)
- Tests:
  - [x] `prrr-android/app/src/test/kotlin/com/prrr/vpn/android/util/BatteryOptimizationHelperTest.kt` - 4 tests
  - [x] `prrr-android/app/src/test/kotlin/com/prrr/vpn/android/ui/ErrorMappingTest.kt` - 15 tests
  - [x] `prrr-android/app/src/test/kotlin/com/prrr/vpn/android/viewmodel/VpnManagerTest.kt` - extended with 5 tests
- Documentation:
  - [x] `docs/mobile-api.md` - Updated with Feature 3.6 section
  - [x] `specs/mobile-app/ROADMAP.md` - Feature 3.6 marked complete

### Backward Links
- Roadmap: `specs/mobile-app/ROADMAP.md` Feature 3.6
- Dependencies:
  - FRD-M012 (Main UI) - Navigation scaffold and VpnManager
  - FRD-M010 (Configuration Storage) - ConfigurationManager API
  - FRD-M009 (QR Scanner) - Import flow target
  - FRD-M011 (VpnService) - Battery optimization target

## Change Log

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| 2026-02-22 | 1.0 | AI Agent | Initial FRD for Feature 3.6 |
| 2026-02-22 | 1.1 | AI Agent | Implementation complete, all tests passing |

## Approval

- [ ] Technical Lead
- [ ] Product Owner
- [ ] QA Lead

---

**Status**: Complete
**Completed**: 2026-02-22
