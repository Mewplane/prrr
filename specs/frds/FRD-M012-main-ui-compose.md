# FRD-M012: Main UI (Jetpack Compose) - Android

## Roadmap Link
- Source roadmap: `specs/mobile-app/ROADMAP.md`
- Feature: Phase 3, Feature 3.5: Main UI (Jetpack Compose)

## Problem
The Android app has a functional VpnService foundation, QR scanner, and configuration storage, but lacks a main user interface for controlling the VPN connection. Users need a clear, intuitive UI to:
- See current connection status at a glance
- Connect and disconnect with a single tap
- View connection statistics (when connected)
- Access settings and configuration management
- Receive clear feedback on connection state changes

Without a main UI, the app's features are not accessible to users.

## Context
**Current State:**
- ✅ VpnService implemented (Feature 3.4) with foundation for packet handling
- ✅ QR scanner working (Feature 3.2) and can import configurations
- ✅ Configuration storage implemented (Feature 3.3) with encrypted storage
- ✅ Rust VpnConnection provides state management (ConnectionStatus, ConnectionStats)
- ❌ No main screen to display status or control connection
- ❌ No UI integration with VpnService
- ❌ No real-time status updates

**UI Design Requirements (from SPEC.md §3.3):**
- Large, centered status icon (green/orange/gray/red)
- Clear status text (Not Connected, Connecting, Connected, Error)
- Server endpoint display when configured
- Large connect/disconnect button in thumb zone (bottom third)
- Connection statistics when connected (duration, sent, received, latency)
- Material Design 3 styling
- Dark mode support
- Accessibility (TalkBack) support

**Technical Stack:**
- Jetpack Compose for declarative UI
- ViewModel + StateFlow for state management
- Material 3 theming
- Android Navigation Compose for routing

## Goal
Implement the main UI screen that:
1. Displays current VPN connection status with visual feedback
2. Allows users to connect/disconnect with single button tap
3. Shows connection statistics when connected
4. Integrates with VpnService for state synchronization
5. Provides responsive, accessible UI following Material Design 3
6. Handles all connection states (disconnected, connecting, connected, error)
7. Updates UI in real-time as connection state changes

## In Scope
- `MainScreen.kt` composable with full UI layout
- `VpnManager` ViewModel for state management
- `StatusIcon` composable for visual status indication
- `StatsCard` composable for connection statistics
- Navigation scaffold with settings button
- VpnService integration via ViewModel
- State observation using Kotlin StateFlow
- Connection control (connect/disconnect actions)
- Real-time UI updates on state changes
- Material 3 theming (light/dark mode)
- Accessibility labels and semantics
- Unit tests for ViewModel logic

## Out of Scope
- Settings screen (Feature 3.6)
- Battery optimization UI (Feature 3.6)
- Error dialogs (Feature 3.6)
- Help/FAQ screen
- Onboarding flow
- Widget/Quick Settings tile
- Split tunnel configuration
- Kill switch UI
- Advanced settings (DNS override, MTU tuning)
- Connection logs/debugging UI
- Real packet forwarding (VpnService stub limitation)

## Functional Requirements

### Must Have
- **REQ-M012-001**: UI MUST display current connection status (Disconnected, Connecting, Connected, Error)
- **REQ-M012-002**: UI MUST show status icon matching current state (color-coded)
- **REQ-M012-003**: UI MUST show connect button when disconnected
- **REQ-M012-004**: UI MUST show disconnect button when connected
- **REQ-M012-005**: UI MUST disable connection button while connecting
- **REQ-M012-006**: UI MUST display server endpoint when configuration exists
- **REQ-M012-007**: UI MUST show connection statistics when connected (duration, bytes sent/received)
- **REQ-M012-008**: UI MUST handle VPN permission request flow
- **REQ-M012-009**: UI MUST navigate to QR scanner if no configuration exists
- **REQ-M012-010**: UI MUST update in real-time when connection state changes

### Should Have
- **REQ-M012-011**: UI SHOULD show latency in statistics (when available)
- **REQ-M012-012**: UI SHOULD provide settings button to access configuration
- **REQ-M012-013**: UI SHOULD use Material 3 design language
- **REQ-M012-014**: UI SHOULD support dark mode automatically
- **REQ-M012-015**: UI SHOULD provide haptic feedback on button press

### Could Have
- **REQ-M012-016**: UI COULD show connection duration ticker (updates every second)
- **REQ-M012-017**: UI COULD animate status icon transitions
- **REQ-M012-018**: UI COULD show data usage graph
- **REQ-M012-019**: UI COULD display connection quality indicator

### Won't Have (This Release)
- **REQ-M012-020**: Won't show split tunnel configuration
- **REQ-M012-021**: Won't show kill switch toggle
- **REQ-M012-022**: Won't display connection logs
- **REQ-M012-023**: Won't implement widget

## Non-Functional Requirements

### Performance
- **NFR-M012-001**: UI MUST render within 100ms of state change
- **NFR-M012-002**: Button presses MUST respond within 50ms
- **NFR-M012-003**: UI MUST not block main thread during state updates
- **NFR-M012-004**: APK size increase MUST be <5 MB (Compose overhead)

### Usability
- **NFR-M012-005**: Status icon MUST be recognizable at 120dp size
- **NFR-M012-006**: Connect/disconnect button MUST be in thumb-reachable zone
- **NFR-M012-007**: Status text MUST be readable at minimum font size
- **NFR-M012-008**: UI MUST support dynamic font scaling (accessibility)
- **NFR-M012-009**: Color contrast MUST meet WCAG AA standards
- **NFR-M012-010**: TalkBack MUST announce all state changes

### Reliability
- **NFR-M012-011**: UI MUST handle missing configuration gracefully
- **NFR-M012-012**: UI MUST survive process death (state restoration)
- **NFR-M012-013**: UI MUST handle VpnService crashes gracefully
- **NFR-M012-014**: UI MUST not crash on rapid connect/disconnect

### Compatibility
- **NFR-M012-015**: UI MUST work on Android 8.0+ (API 26+)
- **NFR-M012-016**: UI MUST render correctly on screens 4"-7"
- **NFR-M012-017**: UI MUST support landscape orientation
- **NFR-M012-018**: UI MUST work with system font scaling (100%-200%)

## Stressors (Residuality Step 1)

1. **Missing Configuration**: User opens app without scanning QR code first
2. **VPN Permission Denied**: User denies VPN permission when connecting
3. **VpnService Crash**: Service crashes while UI is active
4. **Rapid State Changes**: User taps connect/disconnect rapidly
5. **Process Death**: Android kills app process, user returns
6. **Configuration Changes**: Screen rotation while connecting
7. **Service Not Responding**: VpnService doesn't update status
8. **Network Loss**: Network becomes unavailable while "connected" (stub)
9. **Battery Optimization**: System restricts background service
10. **Concurrent Access**: Multiple activities try to control VpnService
11. **Stats Overflow**: Byte counters exceed display format limits
12. **Theme Change**: User switches light/dark mode
13. **Font Scaling**: Accessibility font size too large
14. **Slow Rendering**: UI jank on low-end devices
15. **Notification Conflict**: User interacts with notification and UI concurrently

## Residue-First Design (Step 2)

### Architecture

```
MainActivity (ComponentActivity)
    └─> NavHost
            └─> MainScreen (Composable)
                    ├─> Scaffold
                    │       ├─> TopAppBar (Settings button)
                    │       └─> Content
                    │               ├─> StatusIcon (120dp)
                    │               ├─> StatusText (headline)
                    │               ├─> ServerText (caption)
                    │               ├─> ConnectionButton (56dp height)
                    │               └─> StatsCard (when connected)
                    │
                    └─> ViewModel Integration
                            └─> VpnManager (ViewModel)
                                    ├─> StateFlow<ConnectionStatus>
                                    ├─> StateFlow<VpnConfig?>
                                    ├─> StateFlow<ConnectionStats?>
                                    ├─> connect() -> starts VpnService
                                    └─> disconnect() -> stops VpnService
```

### State Flow

```
App Launch
    → MainActivity onCreate
        → VpnManager init
            → Load config from ConfigurationManager
            → Observe VpnService state (via BroadcastReceiver)
            → Initialize StateFlows
    → MainScreen composable
        → collectAsState() on StateFlows
        → Render UI based on current state

User Taps "Connect"
    → VpnManager.connect()
        → Check if config exists
            → No: Navigate to QR scanner
            → Yes: Check VPN permission
                → Not granted: Request permission (Activity result)
                    → Denied: Show error, return
                    → Granted: Continue
                → Start VpnService (foreground)
        → Update status to Connecting
        → UI re-renders automatically

VpnService Updates
    → Service broadcasts status change
        → VpnManager receives broadcast
        → Update StateFlow<ConnectionStatus>
        → Compose observes StateFlow
        → UI re-renders with new status

User Taps "Disconnect"
    → VpnManager.disconnect()
        → Send stop intent to VpnService
        → Update status to Disconnected
        → UI re-renders
```

### Component Specifications

#### VpnManager (ViewModel)

**Responsibility**: Bridge between UI and VpnService

**State:**
```kotlin
class VpnManager(private val context: Context) : ViewModel() {
    private val _status = MutableStateFlow(ConnectionStatus.Disconnected)
    val status: StateFlow<ConnectionStatus> = _status.asStateFlow()
    
    private val _config = MutableStateFlow<VpnConfig?>(null)
    val config: StateFlow<VpnConfig?> = _config.asStateOf()
    
    private val _stats = MutableStateFlow<ConnectionStats?>(null)
    val stats: StateFlow<ConnectionStats?> = _stats.asStateFlow()
    
    private var statusReceiver: BroadcastReceiver? = null
}
```

**Methods:**
- `init`: Load config, register broadcast receiver for service updates
- `connect()`: Validate config, request VPN permission (if needed), start service
- `disconnect()`: Stop service, update state
- `onCleared()`: Unregister broadcast receiver

**Error Handling:**
- Missing config → Navigate to QR scanner (emit navigation event)
- VPN permission denied → Update status to Error with reason
- Service start failure → Update status to Error, log exception

#### MainScreen (Composable)

**Layout (Vertical Column):**
1. **Spacer** (60dp top padding)
2. **StatusIcon** (120dp, centered)
3. **StatusText** (headline, centered)
4. **ServerText** (caption, centered, optional)
5. **Spacer** (flexible weight)
6. **ConnectionButton** (56dp height, 40dp horizontal padding)
7. **StatsCard** (conditional on Connected state)
8. **Spacer** (60dp bottom padding)

**State Observation:**
```kotlin
@Composable
fun MainScreen(vpnManager: VpnManager, navController: NavController) {
    val status by vpnManager.status.collectAsState()
    val config by vpnManager.config.collectAsState()
    val stats by vpnManager.stats.collectAsState()
    
    // Handle missing config
    LaunchedEffect(config) {
        if (config == null) {
            navController.navigate("qr_scanner")
        }
    }
    
    // UI rendering...
}
```

**Interaction Handlers:**
- `onConnectClick`: Call `vpnManager.connect()`, handle permission result
- `onDisconnectClick`: Call `vpnManager.disconnect()`
- `onSettingsClick`: Navigate to settings screen

#### StatusIcon (Composable)

**Props:**
- `status: ConnectionStatus`

**Visual Mapping:**
| Status | Color | Icon | Description |
|--------|-------|------|-------------|
| Disconnected | Gray | shield.slash | Not connected |
| Connecting | Orange | refresh/loading | Establishing connection |
| Connected | Green | checkmark.shield | Active VPN tunnel |
| Error | Red | exclamation.triangle | Connection failed |

**Implementation:**
- 120dp circle with solid color fill
- 60dp icon (Material Icons) centered
- Smooth color transitions (animateColorAsState)
- Content description for accessibility

#### StatsCard (Composable)

**Props:**
- `stats: ConnectionStats`

**Fields Displayed:**
- **Duration**: formatDuration(stats.durationSecs) → "1h 23m"
- **Sent**: formatBytes(stats.bytesSent) → "142 MB"
- **Received**: formatBytes(stats.bytesReceived) → "1.2 GB"
- **Latency**: "${stats.serverLatencyMs}ms" (if non-zero)

**Layout:**
- Material Card with rounded corners
- 16dp padding
- Vertical list of StatRow items
- 8dp spacing between rows

**Formatting Utilities:**
```kotlin
fun formatDuration(seconds: ULong): String {
    val hours = seconds / 3600u
    val minutes = (seconds % 3600u) / 60u
    return "${hours}h ${minutes}m"
}

fun formatBytes(bytes: ULong): String {
    return when {
        bytes < 1024u -> "$bytes B"
        bytes < 1024u * 1024u -> "${bytes / 1024u} KB"
        bytes < 1024u * 1024u * 1024u -> "${bytes / (1024u * 1024u)} MB"
        else -> "%.1f GB".format(bytes.toDouble() / (1024.0 * 1024.0 * 1024.0))
    }
}
```

### Testing Strategy

#### Unit Tests (VpnManagerTest.kt)

**Scenarios:**
1. **Initial state**: Status=Disconnected, config loaded from storage
2. **Connect with missing config**: Navigate to QR scanner
3. **Connect with valid config**: Start VpnService, transition to Connecting
4. **VPN permission denied**: Status transitions to Error
5. **Service update**: Broadcast received, status updated, UI notified
6. **Disconnect**: Service stopped, status=Disconnected
7. **Stats update**: Stats received from service, StateFlow updated
8. **Process death recovery**: ViewModel recreated, state restored

**Test Tools:**
- JUnit 4
- Robolectric for Android framework mocking
- Turbine for StateFlow testing
- MockK for service mocking

#### UI Tests (MainScreenTest.kt)

**Scenarios:**
1. **Render disconnected state**: Icon gray, text "Not Connected", button "Connect"
2. **Render connecting state**: Icon orange, text "Connecting...", button disabled
3. **Render connected state**: Icon green, text "Connected", button "Disconnect", stats visible
4. **Render error state**: Icon red, text "Error", button "Connect"
5. **Button click**: Connect button calls vpnManager.connect()
6. **Settings navigation**: Settings icon navigates to settings screen
7. **Accessibility**: TalkBack reads all UI elements correctly

**Test Tools:**
- Compose UI Test
- ComposeTestRule
- Semantics matchers

## Acceptance Criteria

### Functional
1. ✅ Main screen displays connection status with color-coded icon
2. ✅ Connect button starts VpnService and transitions to Connecting state
3. ✅ Disconnect button stops VpnService and transitions to Disconnected
4. ✅ Connection statistics are displayed when status=Connected
5. ✅ Settings button navigates to settings screen
6. ✅ UI updates in real-time when VpnService state changes
7. ✅ Missing configuration redirects to QR scanner
8. ✅ VPN permission request flow works correctly

### Non-Functional
1. ✅ UI renders within 100ms of state change
2. ✅ No UI jank on low-end devices (maintain 60fps)
3. ✅ Dark mode renders correctly
4. ✅ TalkBack announces all state changes
5. ✅ UI survives screen rotation without state loss
6. ✅ APK size increase <5 MB
7. ✅ Zero Compose lint warnings

### Testing
1. ✅ Unit tests pass for VpnManager (coverage ≥90%)
2. ✅ UI tests pass for MainScreen
3. ✅ Manual testing on Android 8.0 and 14.0
4. ✅ Manual testing in light and dark modes
5. ✅ Manual testing with TalkBack enabled
6. ✅ `./gradlew lint` passes with zero warnings

## Implementation Plan

### Step 1: ViewModel Foundation
- Create `VpnManager.kt` with StateFlow properties
- Implement `loadConfiguration()` from ConfigurationManager
- Add broadcast receiver for VpnService status updates
- Unit tests for state management

### Step 2: Basic UI Structure
- Create `MainScreen.kt` with Scaffold layout
- Implement vertical column with spacers
- Add TopAppBar with settings button
- Test rendering in preview

### Step 3: Status Display
- Create `StatusIcon.kt` composable
- Implement status text logic
- Add server endpoint display (conditional)
- Test all connection states

### Step 4: Connection Control
- Implement connection button
- Add VPN permission request flow
- Wire up VpnManager.connect()/disconnect()
- Handle button state (enabled/disabled)

### Step 5: Statistics Display
- Create `StatsCard.kt` composable
- Implement formatting utilities
- Add conditional rendering (only when Connected)
- Test with sample stats

### Step 6: State Integration
- Connect StateFlows to UI (collectAsState)
- Test real-time updates
- Handle edge cases (missing config, permissions)

### Step 7: Testing & Polish
- Write unit tests for VpnManager
- Write UI tests for MainScreen
- Run lint and fix warnings
- Manual QA on physical device

## Implementation Files

- `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/ui/MainScreen.kt`
- `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/ui/StatusIcon.kt`
- `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/ui/StatsCard.kt`
- `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/ui/theme/Theme.kt`
- `prrr-android/app/src/main/kotlin/com/prrr/vpn/android/viewmodel/VpnManager.kt`
- `prrr-android/app/src/test/kotlin/com/prrr/vpn/android/viewmodel/VpnManagerTest.kt`
- `prrr-android/app/src/androidTest/kotlin/com/prrr/vpn/android/ui/MainScreenTest.kt`

## Traceability

### Forward Links
- Implementation: See "Implementation Files" section above
- Tests: VpnManagerTest.kt, MainScreenTest.kt
- Documentation: Will update docs/mobile-api.md with UI usage guide

### Backward Links
- Roadmap: `specs/mobile-app/ROADMAP.md` Feature 3.5
- Dependencies:
  - FRD-M011 (VpnService Foundation) - Provides service to control
  - FRD-M010 (Configuration Storage) - Provides config loading
  - FRD-M009 (QR Scanner) - Fallback when config missing
  - FRD-M004 (Connection State) - Provides ConnectionStatus enum

## Glossary

- **Compose**: Jetpack Compose, Android's modern declarative UI toolkit
- **StateFlow**: Kotlin coroutine-based state holder for reactive UI
- **ViewModel**: Android Architecture Component for UI state management
- **VpnService**: Android system service for creating VPN tunnels
- **TalkBack**: Android screen reader for accessibility
- **Material 3**: Google's latest design system
- **Thumb zone**: Lower third of screen, easily reachable with thumb
- **WCAG AA**: Web Content Accessibility Guidelines level AA

## Change Log

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| 2026-02-22 | 1.0 | AI Agent | Initial FRD for Feature 3.5 Main UI |

## Approval

- [ ] Technical Lead
- [ ] Product Owner
- [ ] QA Lead

---

**Status**: Draft  
**Next Steps**: Begin implementation with Step 1 (ViewModel Foundation)
