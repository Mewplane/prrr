# FRD-M011: VpnService Foundation (Android)

## Roadmap Link
- Source roadmap: `specs/mobile-app/ROADMAP.md`
- Feature: Phase 3, Feature 3.4: VpnService Implementation

## Problem
The Android app can scan QR codes and store VPN configurations, but cannot actually establish a VPN connection at the system level. Android requires a `VpnService` subclass to create a VPN tunnel interface and route traffic. Without this, the app cannot function as a VPN client.

Additionally, the current Rust `VpnConnection` in `prrr-mobile` is a stub implementation that simulates connection states but does not perform actual packet encryption, QUIC/MASQUE transport, or hybrid handshake. Real packet handling requires integrating the existing transport code from `src/transport/`, `src/crypto/`, and `src/handshake/` into the mobile library.

## Context
Android's VPN framework requires:
1. **VpnService subclass**: Manages VPN lifecycle and creates TUN interface
2. **Foreground service**: VpnService must run as foreground service with notification (API 26+)
3. **VPN permission**: User must grant VPN permission before establishing connection
4. **TUN interface**: Virtual network interface for routing IP packets
5. **Packet processing**: Read from TUN, encrypt/send via VPN, receive/decrypt, write to TUN

**Current State:**
- prrr-mobile `VpnConnection` is a stub (async state simulation only)
- No packet encryption/decryption in mobile library
- No QUIC/MASQUE transport in mobile library
- Desktop prrr has all required components in `src/` but they're not wired to mobile

**This FRD's Scope:**
This implements a **foundation VpnService** that:
- Establishes VPN interface properly
- Integrates with stub `VpnConnection` for state management
- Provides notification and foreground service
- **Stub packet loop** (reads from TUN but doesn't forward - no internet will work)
- Provides hooks for real packet handling when Rust transport is integrated

**Future Work** (out of scope for this FRD):
- Integrate real transport into prrr-mobile
- Wire up packet encryption/decryption
- Implement actual QUIC/MASQUE tunneling

## Goal
Implement Android VpnService that:
1. Requests VPN permission from user
2. Establishes system VPN interface with correct network settings
3. Runs as foreground service with proper notification
4. Integrates with Rust `VpnConnection` for state tracking
5. Provides foundation for packet handling (stub loop for now)
6. Manages service lifecycle (start/stop/restart)
7. Shows VPN status in Android system UI (key icon)

## In Scope
- `PrrrVpnService` class extending `VpnService`
- VPN permission request flow
- Foreground service with notification channel
- VPN interface creation (`Builder` API)
- Integration with `ConfigurationManager` to load config
- Integration with stub `VpnConnection` for state tracking
- Service start/stop actions
- Notification updates (connecting/connected/disconnected/error)
- Stub packet processing thread (foundation for real implementation)
- Service lifecycle management
- Error handling and cleanup
- System VPN indicator (key icon in status bar)

## Out of Scope
- Real packet encryption/decryption (requires Rust transport integration)
- QUIC/MASQUE transport implementation
- Hybrid handshake implementation
- Actual internet connectivity (stub loop doesn't forward packets)
- Packet routing/NAT traversal
- Reconnection logic on network changes
- Battery optimization exemption request
- Always-on VPN support
- Split tunneling
- Kill switch
- Connection statistics UI
- iOS Network Extension (separate feature)

## Functional Requirements

### Must Have
- **REQ-M011-001**: App MUST request VPN permission before establishing connection
- **REQ-M011-002**: Service MUST run as foreground service with notification (API 26+)
- **REQ-M011-003**: Service MUST create VPN interface with config from storage
- **REQ-M011-004**: Service MUST configure interface with assigned IP, DNS, routes, MTU
- **REQ-M011-005**: Service MUST integrate with Rust `VpnConnection` for state management
- **REQ-M011-006**: Service MUST show notification with current status
- **REQ-M011-007**: Service MUST handle START and STOP actions
- **REQ-M011-008**: Service MUST clean up resources on stop (close FD, stop threads)
- **REQ-M011-009**: Service MUST show system VPN indicator when active
- **REQ-M011-010**: Service MUST prevent starting without stored configuration

### Should Have
- **REQ-M011-011**: Service SHOULD log connection state changes
- **REQ-M011-012**: Service SHOULD update notification on state changes
- **REQ-M011-013**: Service SHOULD survive configuration changes (screen rotation)
- **REQ-M011-014**: Service SHOULD provide notification action to disconnect

### Could Have
- **REQ-M011-015**: Service COULD show connection duration in notification
- **REQ-M011-016**: Service COULD provide quick settings tile
- **REQ-M011-017**: Service COULD show data usage in notification

### Won't Have (This Release)
- **REQ-M011-018**: Won't implement actual packet forwarding (stub only)
- **REQ-M011-019**: Won't provide internet connectivity (requires Rust transport)
- **REQ-M011-020**: Won't implement always-on VPN
- **REQ-M011-021**: Won't implement split tunneling

## Non-Functional Requirements

### Performance
- **NFR-M011-001**: Service MUST start within 2 seconds
- **NFR-M011-002**: VPN interface MUST be created within 500ms
- **NFR-M011-003**: Service MUST stop within 1 second
- **NFR-M011-004**: Notification updates MUST not cause UI jank

### Security
- **NFR-M011-005**: Service MUST validate configuration before use
- **NFR-M011-006**: Service MUST NOT log sensitive data (keys, packets)
- **NFR-M011-007**: Service MUST prevent unauthorized access to VPN interface
- **NFR-M011-008**: Service MUST use secure notification (no sensitive info displayed)

### Reliability
- **NFR-M011-009**: Service MUST handle missing configuration gracefully
- **NFR-M011-010**: Service MUST handle VPN permission denial gracefully
- **NFR-M011-011**: Service MUST survive process death (sticky service)
- **NFR-M011-012**: Service MUST clean up on crash (try-catch in critical sections)

### Compatibility
- **NFR-M011-013**: MUST work on Android 8.0+ (API 26+)
- **NFR-M011-014**: MUST comply with foreground service requirements (API 34)
- **NFR-M011-015**: MUST handle different Android versions gracefully

### Usability
- **NFR-M011-016**: Notification MUST show clear status (connecting/connected/error)
- **NFR-M011-017**: VPN permission dialog MUST be shown before connection attempt
- **NFR-M011-018**: Error messages MUST be actionable

## Stressors (Residuality Step 1)

1. **VPN Permission Denied**: User denies VPN permission or revokes it later
2. **Missing Configuration**: Service started without stored config
3. **Invalid Configuration**: Stored config is corrupted or invalid
4. **Interface Creation Failure**: `Builder.establish()` returns null
5. **Rust Connection Failure**: `VpnConnection.connect()` throws exception
6. **Service Killed by System**: Android kills service due to memory pressure
7. **Service Started Twice**: Multiple start intents received concurrently
8. **Thread Interruption**: Packet processing thread interrupted unexpectedly
9. **File Descriptor Leak**: VPN interface not closed properly
10. **Notification Channel Missing**: Notification channel deleted by user
11. **Foreground Service Timeout**: Service takes too long to call `startForeground()`
12. **Network Configuration Change**: WiFi/mobile network changes during "connection"
13. **App Force Stopped**: User force-stops app while VPN is active
14. **Battery Optimization**: System restricts background execution
15. **Concurrent Stop/Start**: Stop and start called in quick succession

## Residue-First Design (Step 2)

### Architecture

```
MainActivity
    ├─> Request VPN Permission
    │       └─> VpnService.prepare()
    └─> Start/Stop Service
            └─> Intent(ACTION_CONNECT/DISCONNECT)

PrrrVpnService (VpnService)
    ├─> Foreground Notification
    │       ├─> Notification Channel
    │       ├─> Status Text (Connecting/Connected/Error)
    │       └─> Tap Action → MainActivity
    │
    ├─> VPN Interface (Builder)
    │       ├─> Session Name
    │       ├─> IP Address (from config.assignedIp)
    │       ├─> DNS Servers
    │       ├─> Routes (0.0.0.0/0 - all traffic)
    │       ├─> MTU
    │       └─> establish() → ParcelFileDescriptor
    │
    ├─> Rust VpnConnection (Stub)
    │       ├─> connect() - simulates connection
    │       ├─> status() - returns ConnectionStatus
    │       └─> disconnect()
    │
    └─> Packet Processing Thread (Stub)
            ├─> Read from TUN interface (FileInputStream)
            ├─> [TODO] Encrypt & send via QUIC
            ├─> [TODO] Receive & decrypt from QUIC
            └─> Write to TUN interface (FileOutputStream)
```

### Service Lifecycle

```
User taps "Connect"
    → Check VPN permission
        → If not granted: Show system VPN permission dialog
            → User grants: Continue
            → User denies: Show error, return
        → If granted: Start service
            → Intent(ACTION_CONNECT) → PrrrVpnService
                → onCreate()
                    → Create notification channel
                → onStartCommand(ACTION_CONNECT)
                    → Start foreground with "Connecting..." notification
                    → Load configuration from storage
                        → If null: Stop service, show error
                    → Create VPN interface via Builder
                        → If null: Stop service, show "VPN setup failed"
                    → Create Rust VpnConnection
                    → Call connection.connect()
                        → Update notification to "Connected"
                    → Start packet processing thread (stub loop)
                        → Read from TUN, log, discard
                    → Service runs until stopped

User taps "Disconnect"
    → Intent(ACTION_DISCONNECT) → PrrrVpnService
        → onStartCommand(ACTION_DISCONNECT)
            → Interrupt packet thread
            → Disconnect Rust connection
            → Close VPN interface (ParcelFileDescriptor)
            → stopForeground(REMOVE)
            → stopSelf()
```

### Stressor Mitigations

1. **VPN Permission Denied**
   - Check `VpnService.prepare()` before starting service
   - If returns Intent, show system dialog
   - If user denies, show error: "VPN permission required"
   - Don't attempt to start service without permission

2. **Missing Configuration**
   - Check `ConfigurationManager.hasConfiguration()` before requesting permission
   - In service, `loadConfiguration()` returns null → immediate stopSelf()
   - Show error notification before stopping

3. **Invalid Configuration**
   - Configuration is validated by `ConfigurationManager` on load
   - Rust `VpnConnection` validates in constructor
   - Catch `MobileException.InvalidConfig`, show error, stop service

4. **Interface Creation Failure**
   - `Builder.establish()` can return null if permission revoked or conflict
   - Check for null, log error, show notification "VPN setup failed", stop service
   - Don't proceed to connection if interface is null

5. **Rust Connection Failure**
   - Wrap `connection.connect()` in try-catch
   - Catch all exceptions, update notification with error message
   - Close interface and stop service

6. **Service Killed by System**
   - Return `START_STICKY` from `onStartCommand`
   - Android will restart service after killing
   - On restart, re-establish connection automatically
   - (Note: Stub implementation won't auto-reconnect, just restart service)

7. **Service Started Twice**
   - Check if `vpnInterface` is already non-null in `connect()`
   - If already connected, log and return (idempotent)
   - Use `@Synchronized` on connect/disconnect methods

8. **Thread Interruption**
   - Packet thread checks `Thread.interrupted()` in loop
   - Catch `InterruptedException`, log, exit cleanly
   - Don't restart thread if interrupted intentionally

9. **File Descriptor Leak**
   - Always call `vpnInterface?.close()` in disconnect
   - Use try-finally to ensure cleanup
   - Set to null after closing

10. **Notification Channel Missing**
    - Recreate channel in `onCreate()` every time
    - Handle `null` from `getSystemService` gracefully
    - Use fallback notification if channel creation fails

11. **Foreground Service Timeout**
    - Call `startForeground()` immediately in `onStartCommand`
    - Create notification synchronously (no async loading)
    - Start with "Connecting..." notification before doing work

12. **Network Configuration Change**
    - Stub implementation doesn't handle this
    - Future: Listen to `ConnectivityManager` broadcasts
    - For now: Service continues running (no actual traffic)

13. **App Force Stopped**
    - Android automatically disconnects VPN when app force-stopped
    - Interface is cleaned up by system
    - Document this as expected behavior

14. **Battery Optimization**
    - Foreground service is exempt from battery optimization
    - VpnService is system-level, less likely to be killed
    - Document that users should whitelist app if issues occur

15. **Concurrent Stop/Start**
    - Use `@Synchronized` on connect/disconnect
    - Check state before proceeding (if already connected, skip)
    - Service stops only after disconnect completes

### Data Flow

```
Configuration Flow:
    ConfigurationManager.loadConfiguration()
        → VpnConfig
            → Builder.addAddress(config.assignedIp)
            → Builder.addDnsServer(config.dnsServers[0])
            → Builder.setMtu(config.mtu)
            → Builder.establish()
                → ParcelFileDescriptor (TUN interface)

Connection Flow:
    VpnConnection(config)
        → connection.connect()
            → Rust async state machine
                → Transitions to Connected (simulated)
                    → Update notification
                        → Start packet thread

Packet Flow (Stub):
    TUN interface (vpnInterface.fileDescriptor)
        → FileInputStream.read(buffer)
            → packet bytes (IP packet from Android)
                → [TODO] Encrypt via Rust
                    → [TODO] Send via QUIC to server
    
    [TODO] Receive from server via QUIC
        → [TODO] Decrypt via Rust
            → packet bytes (IP packet to Android)
                → FileOutputStream.write(packet)
                    → TUN interface
```

## Acceptance Criteria

1. **AC-M011-001**: User can request VPN permission from app
2. **AC-M011-002**: System VPN permission dialog shown on first connection
3. **AC-M011-003**: Service starts and shows foreground notification
4. **AC-M011-004**: Notification shows "Connecting..." initially
5. **AC-M011-005**: VPN interface created with correct IP address
6. **AC-M011-006**: System VPN indicator (key icon) appears in status bar
7. **AC-M011-007**: Notification updates to "Connected" after Rust connection succeeds
8. **AC-M011-008**: Service can be stopped via disconnect action
9. **AC-M011-009**: VPN indicator disappears when disconnected
10. **AC-M011-010**: Service cleans up resources on stop (no FD leaks)
11. **AC-M011-011**: Error shown if no configuration stored
12. **AC-M011-012**: App works across app restarts (service persists or restarts)

## Test Matrix

### Unit Tests

| Test Case | Setup | Action | Expected Result |
|-----------|-------|--------|-----------------|
| `test_extract_ip_from_cidr` | CIDR "10.66.66.2/32" | Extract IP | Returns "10.66.66.2" |
| `test_notification_channel_created` | Service onCreate | Check NotificationManager | Channel exists |
| `test_connect_without_config` | No stored config | Connect | Service stops immediately |
| `test_disconnect_cleans_up` | Service connected | Disconnect | Interface closed, thread stopped |

### Integration Tests (Manual)

| Test Case | Setup | Action | Expected Result |
|-----------|-------|--------|-----------------|
| `test_vpn_permission_flow` | Fresh install | Tap Connect | System permission dialog shown |
| `test_vpn_permission_granted` | Grant permission | Tap Connect | Service starts, notification shown |
| `test_vpn_indicator_shown` | Service connected | Check status bar | VPN key icon visible |
| `test_service_survives_rotation` | Service connected | Rotate device | Service still running, notification persists |
| `test_notification_tap_opens_app` | Service connected | Tap notification | MainActivity opens |
| `test_disconnect_button_works` | Service connected | Tap Disconnect | Service stops, notification removed |

### Manual Tests

| Test Case | Steps | Expected Result |
|-----------|-------|-----------------|
| Full connection flow | 1. Scan QR, 2. Tap Connect, 3. Grant permission | VPN connected, key icon shown |
| Internet connectivity | Connect VPN, open browser | **No internet (stub implementation)** - document expected |
| Service persistence | Connect VPN, kill app, reopen | Service still running |
| Error handling | Delete config, tap Connect | Error shown, service doesn't start |
| Battery impact | Connect VPN for 1 hour | Service not killed, notification persists |

## Risks & Mitigation Strategies

- **Risk 1**: Users expect working internet but stub implementation doesn't forward packets
  - Mitigation Strategy 1: Update UI to show "Demo Mode - No Internet" in notification
  - Mitigation Strategy 2: Add dialog explaining this is foundation, real traffic coming later
  - Mitigation Strategy 3: Document in release notes that this is infrastructure-only

- **Risk 2**: Android kills VPN service due to battery optimization
  - Mitigation Strategy 1: Use foreground service (exempt from most restrictions)
  - Mitigation Strategy 2: Request battery optimization exemption (future)
  - Mitigation Strategy 3: Document that VpnService is system-protected

- **Risk 3**: VPN permission revoked while service running
  - Mitigation Strategy 1: Service will fail on next operation, catch and stop
  - Mitigation Strategy 2: Monitor permission state (future enhancement)
  - Mitigation Strategy 3: Show notification if permission lost

- **Risk 4**: Configuration changed while VPN connected
  - Mitigation Strategy 1: Don't allow config changes while connected
  - Mitigation Strategy 2: Disconnect before allowing re-scan
  - Mitigation Strategy 3: Future: Support config reload without disconnect

- **Risk 5**: Service crashes leave VPN interface in bad state
  - Mitigation Strategy 1: Android auto-cleans up VPN interfaces on service death
  - Mitigation Strategy 2: Use try-finally for all resource cleanup
  - Mitigation Strategy 3: System will disconnect VPN automatically

## Rollback

**Rollback Strategy**:
- Feature is additive (no existing VPN functionality to break)
- If critical bugs found, disable "Connect" button in UI
- Service can be stopped manually via Android settings
- Uninstall app to fully remove VPN service
- No data loss (configuration storage is separate)
- Future: Add "Reset VPN" button to clear service state

## Implementation Checklist for Agent

- [ ] Step 1: Create `PrrrVpnService.kt` class extending `VpnService`
- [ ] Step 2: Implement notification channel creation
- [ ] Step 3: Implement `onStartCommand` with ACTION_CONNECT and ACTION_DISCONNECT
- [ ] Step 4: Implement `connect()` method (load config, create interface, start connection)
- [ ] Step 5: Implement `disconnect()` method (cleanup resources)
- [ ] Step 6: Implement stub packet processing thread
- [ ] Step 7: Add VPN permission request to MainActivity
- [ ] Step 8: Add Connect/Disconnect buttons to UI
- [ ] Step 9: Update service declaration in AndroidManifest.xml
- [ ] Step 10: Create notification icon drawable
- [ ] Step 11: Write unit tests for service helper methods
- [ ] Step 12: Build and verify compilation
- [ ] Step 13: Test on physical device (VPN indicator, notification)
- [ ] Step 14: Update documentation (note stub limitations)
- [ ] Step 15: Update ROADMAP.md to mark Feature 3.4 complete

## Traceability
- Roadmap item: [specs/mobile-app/ROADMAP.md](../../specs/mobile-app/ROADMAP.md#feature-34-vpnservice-implementation-) - Phase 3, Feature 3.4: VpnService Implementation
- Implementation files:
  - `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/vpn/PrrrVpnService.kt` - Main VpnService implementation
  - `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/MainActivity.kt` - VPN permission request + UI controls
  - `prrr-android/app/src/main/res/drawable/ic_vpn_key.xml` - VPN notification icon
  - `prrr-android/app/src/main/AndroidManifest.xml` - Service declaration (already present from Feature 3.1)
- Test files:
  - Manual testing required (VPN services difficult to unit test)
  - Physical device testing needed for VPN indicator verification
- Documentation:
  - FRD clearly documents stub limitations and future work needed
