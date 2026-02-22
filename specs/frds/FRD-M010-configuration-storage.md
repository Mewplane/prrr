# FRD-M010: Configuration Storage (Android Keystore)

## Roadmap Link
- Source roadmap: `specs/mobile-app/ROADMAP.md`
- Feature: Phase 3, Feature 3.3: Configuration Storage (Android Keystore)

## Problem
After scanning a QR code and parsing VPN configuration, the app needs to securely persist the configuration data, especially the client's private key (32 bytes of sensitive cryptographic material). Without persistent storage, users would need to re-scan the QR code every time they open the app, and the VPN connection cannot be maintained across app restarts.

## Context
The prrr Android app receives `VpnConfig` objects from the Rust core library via UniFFI. This configuration includes:
- Client name (user-facing identifier)
- Server endpoint (network address)
- Server public keys (X25519 + ML-KEM-768)
- **Client private key** (X25519, 32 bytes - highly sensitive)
- Assigned IP address
- DNS servers
- MTU

Android provides two secure storage mechanisms:
1. **Android Keystore System**: Hardware-backed cryptographic key storage (API 23+)
2. **EncryptedSharedPreferences**: Jetpack Security library that encrypts data at rest using keys from Keystore

The client private key must never be stored in plain text or logged. All configuration data should be encrypted at rest to protect against unauthorized access if the device is compromised.

## Goal
Implement secure, persistent storage for VPN configuration that:
1. Stores the client private key in Android Keystore (hardware-backed when available)
2. Encrypts all other configuration data using EncryptedSharedPreferences
3. Provides simple save/load/delete API for the app
4. Ensures data survives app restarts but is wiped on app uninstall
5. Works reliably on Android 8.0+ (API 26+)

## In Scope
- Saving `VpnConfig` to encrypted storage
- Loading `VpnConfig` from storage
- Deleting stored configuration
- Checking if configuration exists
- Android Keystore integration for private key storage
- EncryptedSharedPreferences for non-sensitive config fields
- Unit tests for save/load/delete operations
- Error handling for storage failures
- Integration with QR scanner (auto-save after successful scan)

## Out of Scope
- Multi-profile support (only one config at a time)
- Configuration backup/export (security risk)
- Cloud synchronization
- Migration from plain text storage (fresh install only)
- Biometric authentication for config access (future feature)
- Configuration editing UI (future feature)
- iOS implementation (separate feature)

## Functional Requirements

### Must Have
- **REQ-M010-001**: App MUST save `VpnConfig` to persistent storage
- **REQ-M010-002**: App MUST encrypt client private key using Android Keystore
- **REQ-M010-003**: App MUST encrypt all other config fields using EncryptedSharedPreferences
- **REQ-M010-004**: App MUST load saved configuration on app restart
- **REQ-M010-005**: App MUST provide delete operation to wipe all stored config
- **REQ-M010-006**: App MUST verify configuration exists before attempting to load
- **REQ-M010-007**: App MUST handle storage failures gracefully (return null, not crash)
- **REQ-M010-008**: App MUST use AES-256-GCM encryption for all stored data
- **REQ-M010-009**: App MUST use hardware-backed Keystore when available
- **REQ-M010-010**: Storage MUST survive app process death and device reboot

### Should Have
- **REQ-M010-011**: App SHOULD log storage operations (success/failure) for debugging
- **REQ-M010-012**: App SHOULD validate loaded config using Rust `validateConfig()`
- **REQ-M010-013**: App SHOULD auto-save configuration after successful QR scan
- **REQ-M010-014**: App SHOULD provide getter for individual config fields

### Could Have
- **REQ-M010-015**: App COULD cache loaded config in memory to reduce I/O
- **REQ-M010-016**: App COULD provide config update operation (without full replace)
- **REQ-M010-017**: App COULD track last modified timestamp

### Won't Have
- **REQ-M010-018**: Won't support multiple configurations (single profile only)
- **REQ-M010-019**: Won't encrypt storage key with user password (Keystore only)
- **REQ-M010-020**: Won't store connection history or statistics

## Non-Functional Requirements

### Security
- **NFR-M010-001**: Private key MUST NEVER be logged, even in debug builds
- **NFR-M010-002**: Private key MUST be stored in hardware-backed Keystore when available
- **NFR-M010-003**: Encryption keys MUST be generated and stored in Android Keystore
- **NFR-M010-004**: All sensitive data MUST be encrypted with AES-256-GCM
- **NFR-M010-005**: Storage MUST be cleared on app uninstall (no data persistence)
- **NFR-M010-006**: Configuration MUST NOT be accessible to other apps

### Reliability
- **NFR-M010-007**: Storage operations MUST succeed >99.9% of the time
- **NFR-M010-008**: Load operation MUST complete within 100ms
- **NFR-M010-009**: Save operation MUST complete within 200ms
- **NFR-M010-010**: Storage MUST handle concurrent access safely

### Compatibility
- **NFR-M010-011**: MUST work on Android 8.0+ (API 26+)
- **NFR-M010-012**: MUST work on devices without hardware-backed Keystore (fallback to software)
- **NFR-M010-013**: MUST work across app updates (storage format stable)

### Usability
- **NFR-M010-014**: API MUST be simple (save/load/delete/exists)
- **NFR-M010-015**: Errors MUST provide actionable messages

## Stressors (Residuality Step 1)

1. **Keystore Initialization Failure**: Android Keystore unavailable or corrupted
2. **Encryption Key Generation Failure**: MasterKey creation fails due to device issues
3. **Storage Permission Denied**: App lacks necessary permissions (shouldn't happen, but edge case)
4. **Corrupted Encrypted Data**: EncryptedSharedPreferences file corrupted on disk
5. **Invalid Decryption**: Data modified externally, decryption fails with authentication error
6. **Out of Storage Space**: Device storage full, write operations fail
7. **Private Key Extraction Attack**: Malicious app attempts to read Keystore
8. **Root/Debug Attack**: Rooted device with debugger attached tries to dump memory
9. **App Upgrade Migration**: Old app version stored data in incompatible format
10. **Concurrent Access**: Multiple threads try to read/write storage simultaneously
11. **Device Locked**: User locks device during save operation
12. **Battery Death**: Device dies mid-write, partial data saved
13. **Factory Reset Recovery**: User expects data gone after reset, but it persists somehow
14. **Backup/Restore**: Android backup agent tries to restore old config
15. **Hardware Failure**: Secure Element chip fails, Keystore inaccessible

## Residue-First Design (Step 2)

### Architecture

```
ConfigurationManager (Singleton)
    ├─> Android Keystore (Private Key Storage)
    │       └─> AES-256 Master Key (hardware-backed)
    └─> EncryptedSharedPreferences (Config Storage)
            └─> Encrypted with Master Key
                ├─> client_name: String
                ├─> server_endpoint: String
                ├─> server_public_key: Base64
                ├─> server_pq_public_key: Base64
                ├─> assigned_ip: String
                ├─> dns_servers: CSV String
                └─> mtu: Int
```

### Storage Strategy

**Private Key Storage (Android Keystore):**
- Use `KeyGenParameterSpec` to generate AES-256 key in Keystore
- Store encrypted private key in EncryptedSharedPreferences under special key
- Mark key as `PURPOSE_ENCRYPT | PURPOSE_DECRYPT`
- Use `BLOCK_MODE_GCM` with `ENCRYPTION_PADDING_NONE`
- Enable `setUserAuthenticationRequired(false)` for background VPN

**Non-Sensitive Config Storage (EncryptedSharedPreferences):**
- Use Jetpack Security `EncryptedSharedPreferences`
- MasterKey scheme: `AES256_GCM`
- PrefKey encryption: `AES256_SIV`
- PrefValue encryption: `AES256_GCM`
- File name: `prrr_vpn_config` (app-private storage)

### Stressor Mitigations

1. **Keystore Initialization Failure**
   - Catch `KeyStoreException` during initialization
   - Return `StorageResult.Error` with reason
   - Log error for debugging (no sensitive data)
   - UI shows: "Failed to initialize secure storage"

2. **Encryption Key Generation Failure**
   - Wrap `MasterKey.Builder().build()` in try-catch
   - Fall back to returning null config if irrecoverable
   - Log exception for diagnostics
   - UI prompts user to re-scan QR code

3. **Storage Permission Denied**
   - Shouldn't happen (app-private storage requires no permissions)
   - If `SecurityException` caught, log and return error
   - UI shows: "Storage access denied"

4. **Corrupted Encrypted Data**
   - Catch `GeneralSecurityException` during load
   - Treat as "no config available"
   - Delete corrupted preferences file
   - Return null, forcing re-scan

5. **Invalid Decryption**
   - EncryptedSharedPreferences throws on tampered data
   - Clear all storage and return null
   - Log event (possible attack or corruption)

6. **Out of Storage Space**
   - Catch `IOException` during save
   - Return `SaveResult.InsufficientStorage`
   - UI shows: "Not enough storage space"

7. **Private Key Extraction Attack**
   - Keystore prevents key extraction by design
   - Keys marked `setExportable(false)` implicitly on API 26+
   - Even with root, hardware-backed keys can't be extracted

8. **Root/Debug Attack**
   - Hardware-backed Keystore resists memory dumps
   - Software-backed keys still encrypted at rest
   - ProGuard obfuscation adds minor deterrent

9. **App Upgrade Migration**
   - Version storage format in preferences (`storage_version = 1`)
   - On version mismatch, delete old data and start fresh
   - Log migration event

10. **Concurrent Access**
    - Use `@Synchronized` on save/load/delete methods
    - EncryptedSharedPreferences internally thread-safe
    - Single-writer principle (only ConfigurationManager writes)

11. **Device Locked**
    - Operations complete before screen lock takes effect
    - If interrupted, next save retries
    - No user authentication required for Keystore access

12. **Battery Death**
    - EncryptedSharedPreferences uses `commit()` for synchronous writes
    - Ensures data flushed to disk before returning
    - If power lost, file either fully written or not at all (atomic)

13. **Factory Reset Recovery**
    - Keystore and app-private storage wiped on factory reset
    - No persistence mechanism outside app scope

14. **Backup/Restore**
    - Exclude `prrr_vpn_config` from Android backup
    - Add `android:allowBackup="false"` to manifest
    - Keystore keys never backed up by default

15. **Hardware Failure**
    - Fall back to software-backed Keystore
    - Detect hardware failure via exception
    - Log event, continue operation

### Data Flow

```
QR Scan Success
    → parseQrConfig() returns VpnConfig
        → ConfigurationManager.saveConfiguration(config)
            → Generate/retrieve MasterKey from Keystore
                → Encrypt private key separately
                → Store encrypted private key in prefs["_private_key"]
                → Store other fields in EncryptedSharedPreferences
                    → commit() to disk
                        → Return SaveResult.Success
                            → Navigate to home screen

App Restart
    → ConfigurationManager.loadConfiguration()
        → Check if prefs["client_name"] exists
            → Retrieve MasterKey from Keystore
                → Decrypt private key from prefs["_private_key"]
                → Decrypt other fields from EncryptedSharedPreferences
                    → Construct VpnConfig object
                        → Call validateConfig() via Rust
                            → Return validated VpnConfig or null
```

## Acceptance Criteria

1. **AC-M010-001**: Configuration saved via QR scanner persists across app restarts
2. **AC-M010-002**: `loadConfiguration()` returns null when no config stored
3. **AC-M010-003**: `deleteConfiguration()` wipes all stored data
4. **AC-M010-004**: `hasConfiguration()` accurately reports storage state
5. **AC-M010-005**: Private key never appears in logs (verified via Logcat)
6. **AC-M010-006**: Configuration wiped on app uninstall
7. **AC-M010-007**: Load operation completes within 100ms
8. **AC-M010-008**: Save operation completes within 200ms
9. **AC-M010-009**: Concurrent save/load operations don't corrupt data
10. **AC-M010-010**: Corrupted storage file handled gracefully (returns null)

## Test Matrix

### Unit Tests

| Test Case | Setup | Action | Expected Result |
|-----------|-------|--------|-----------------|
| `test_save_and_load_config` | Empty storage | Save valid config, load | Loaded config equals saved config |
| `test_load_without_save` | Empty storage | Load config | Returns null |
| `test_delete_configuration` | Config saved | Delete, then load | Returns null |
| `test_has_configuration_true` | Config saved | Call hasConfiguration() | Returns true |
| `test_has_configuration_false` | Empty storage | Call hasConfiguration() | Returns false |
| `test_private_key_encrypted` | Config saved | Inspect prefs file | Private key not in plain text |
| `test_overwrite_configuration` | Config saved | Save different config | New config loaded correctly |
| `test_invalid_config_rejected` | Empty storage | Save invalid config | validateConfig() throws, not saved |

### Integration Tests

| Test Case | Setup | Action | Expected Result |
|-----------|-------|--------|-----------------|
| `test_qr_scan_auto_save` | QR scanner | Scan valid QR | Config auto-saved, loaded on restart |
| `test_storage_survives_restart` | Config saved | Kill app process, restart | Config still available |
| `test_concurrent_access` | Config saved | 10 threads read simultaneously | All reads succeed, no crashes |
| `test_keystore_failure_handling` | Mock Keystore fail | Attempt save | Graceful error, no crash |

### Manual Tests

| Test Case | Steps | Expected Result |
|-----------|-------|-----------------|
| Hardware-backed Keystore | Save on Pixel device, check Keystore | Key stored in hardware |
| App uninstall wipe | Save config, uninstall app, reinstall | No config available |
| Storage full | Fill device storage, attempt save | Error message shown |
| Rooted device | Save on rooted device | Still works, key protected |

## Risks & Mitigation Strategies

- **Risk 1**: Keystore API fragmentation across Android versions/OEMs
  - Mitigation Strategy 1: Test on multiple devices (Samsung, Pixel, OnePlus)
  - Mitigation Strategy 2: Use Jetpack Security library (handles compatibility)
  - Mitigation Strategy 3: Graceful fallback to software-backed Keystore

- **Risk 2**: EncryptedSharedPreferences corruption in the wild
  - Mitigation Strategy 1: Catch all `GeneralSecurityException` and wipe storage
  - Mitigation Strategy 2: Treat corruption as "no config" state
  - Mitigation Strategy 3: Log corruption events for monitoring

- **Risk 3**: Performance degradation on low-end devices
  - Mitigation Strategy 1: Profile on Android 8.0 low-end device (2GB RAM)
  - Mitigation Strategy 2: Use asynchronous save if needed (unlikely)
  - Mitigation Strategy 3: Cache loaded config in memory after first load

- **Risk 4**: User frustration from re-scanning QR after storage failure
  - Mitigation Strategy 1: Show clear error messages with remediation steps
  - Mitigation Strategy 2: Provide manual config entry as fallback (future)
  - Mitigation Strategy 3: Monitor storage failure rate via analytics

- **Risk 5**: Private key leakage via logs or memory dumps
  - Mitigation Strategy 1: Never log private key, even in debug builds
  - Mitigation Strategy 2: Zero out private key byte arrays after use
  - Mitigation Strategy 3: Use hardware-backed Keystore when available

## Rollback

**Rollback Strategy**:
- Feature is additive (no existing storage to migrate)
- If critical bug found, disable auto-save and force re-scan on each launch
- Delete all stored configs via app settings
- No data migration needed (users re-scan QR codes)
- Remove ConfigurationManager calls from codebase and force in-memory config only

## Implementation Checklist for Agent

- [ ] Step 1: Add `androidx.security:security-crypto` dependency to `build.gradle.kts`
- [ ] Step 2: Create `ConfigurationManager.kt` singleton object
- [ ] Step 3: Implement `saveConfiguration(context, config)` with Keystore + EncryptedPrefs
- [ ] Step 4: Implement `loadConfiguration(context): VpnConfig?`
- [ ] Step 5: Implement `deleteConfiguration(context)`
- [ ] Step 6: Implement `hasConfiguration(context): Boolean`
- [ ] Step 7: Add `android:allowBackup="false"` to AndroidManifest.xml
- [ ] Step 8: Write unit tests for ConfigurationManager
- [ ] Step 9: Integrate auto-save into QRScannerScreen on successful scan
- [ ] Step 10: Update MainActivity to load config on startup
- [ ] Step 11: Add configuration state to app UI
- [ ] Step 12: Test on physical device with app restart
- [ ] Step 13: Verify private key not in logs
- [ ] Step 14: Update documentation
- [ ] Step 15: Update ROADMAP.md to mark Feature 3.3 complete

## Traceability
- Roadmap item: [specs/mobile-app/ROADMAP.md](../../specs/mobile-app/ROADMAP.md#feature-33-configuration-storage-android-keystore-) - Phase 3, Feature 3.3: Configuration Storage (Android Keystore)
- Implementation files:
  - `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/storage/ConfigurationManager.kt` - Main storage manager
  - `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/MainActivity.kt` - QR scanner integration + UI
  - `prrr-android/app/build.gradle.kts` - Security Crypto dependency
  - `prrr-android/app/src/main/AndroidManifest.xml` - Backup disabled
- Test files:
  - `prrr-android/app/src/test/kotlin/com/prrr/vpn/android/storage/ConfigurationManagerTest.kt` - Unit tests
- Documentation:
  - Updated [docs/mobile-api.md](../../docs/mobile-api.md) - Configuration storage API
