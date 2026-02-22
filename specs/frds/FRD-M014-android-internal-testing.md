# FRD-M014: Android Internal Testing Track

## Roadmap Link
- Source roadmap: [specs/mobile-app/ROADMAP.md](../mobile-app/ROADMAP.md)
- Feature: Feature 3.7 - Android Internal Testing Track

## Problem
The Android application currently builds only as a debug APK with no release build configuration. There is no signing setup, ProGuard/R8 minification is disabled, launcher icons are placeholder PNGs instead of proper adaptive icons, and there is no Gradle task for producing a signed release AAB suitable for Play Store upload. Without these, the app cannot enter an internal testing track.

## Context
- Features 3.1-3.6 are complete: project setup, QR scanner, configuration storage, VpnService, main UI, settings/battery/errors
- The `app/build.gradle.kts` has a release build type with `isMinifyEnabled = false` and no signing config
- ProGuard rules exist but only keep UniFFI classes
- Launcher icons are tiny placeholder PNGs (163-863 bytes)
- No adaptive icon XML resources exist
- The app builds successfully as debug APK (~38 MB)
- External dependencies (Google Play Developer account, privacy policy) are outside scope of this FRD
- We are on Linux (no macOS/Xcode available)

## Goal
Prepare the Android application codebase for internal testing distribution by:
1. Configuring release build with R8 minification and resource shrinking
2. Setting up signing configuration that reads credentials from environment variables
3. Creating proper adaptive launcher icons (vector-based)
4. Expanding ProGuard/R8 rules to cover all required keep rules
5. Adding a Makefile target for building release AAB/APK
6. Verifying the release build compiles and R8 doesn't strip required classes

## In Scope
- Release build configuration in `app/build.gradle.kts` (signing, minification, shrinking)
- Comprehensive ProGuard/R8 keep rules for UniFFI, JNA, Kotlin, Compose, CameraX, ML Kit
- Adaptive icon resources (foreground vector + background color) in all densities
- Makefile targets: `android-release`, `android-debug`, `android-lint`
- Build verification test ensuring release build compiles
- Version management (versionCode/versionName sourced from properties)

## Out of Scope
- Google Play Console setup and app listing
- Privacy policy publication
- VpnService declaration form
- Actual Play Store upload
- Release signing key generation (documented, not executed)
- Screenshots and marketing materials
- App Bundle size optimization beyond R8

## Functional Requirements

### Must Have
- FR-1: Release build type with R8 minification enabled (`isMinifyEnabled = true`)
- FR-2: Resource shrinking enabled (`isShrinkResources = true`)
- FR-3: Signing configuration reading keystore path, passwords, and key alias from environment variables or `local.properties`
- FR-4: ProGuard/R8 rules that preserve UniFFI bindings, JNA classes, Kotlin coroutines, and Compose runtime
- FR-5: Adaptive launcher icons with vector foreground and solid background for all densities
- FR-6: Debug build type retains current behavior (no minification)
- FR-7: Makefile target `android-release` to build release AAB

### Should Have
- FR-8: Makefile target `android-debug` to build debug APK
- FR-9: Makefile target `android-test` to run unit tests
- FR-10: Version properties sourced from `gradle.properties` for centralized management

### Could Have
- FR-11: Build variant for staging/testing with different app ID suffix

## Non-Functional Requirements
- NFR-1: Release APK should be smaller than debug APK due to R8 minification
- NFR-2: Signing config must not hardcode any passwords or keystore paths
- NFR-3: Build must succeed even without signing config (unsigned release for local testing)
- NFR-4: ProGuard rules must not over-keep (no blanket `-dontwarn **`)

## Stressors (Residuality Step 1)
1. R8 strips UniFFI-generated classes causing runtime `ClassNotFoundException`
2. R8 strips JNA native method bindings causing `UnsatisfiedLinkError`
3. R8 removes Kotlin coroutine infrastructure causing suspend function failures
4. R8 obfuscates class names breaking reflection-based lookups in UniFFI/JNA
5. Missing signing config causes build failure in CI
6. Keystore password leaked in build logs or version control
7. Adaptive icon renders incorrectly on different OEM launchers (Samsung, Pixel, etc.)
8. Resource shrinking removes required drawables (VPN notification icon)
9. Version code not incremented before Play Store upload
10. ProGuard mapping file not preserved, making crash reports unreadable
11. Release build crashes on app startup due to missing kept classes
12. Build size increases instead of decreasing due to over-aggressive keep rules

## Design

### Architecture

```
build.gradle.kts
  ├── signingConfigs
  │   └── release (env vars: PRRR_KEYSTORE_PATH, PRRR_KEYSTORE_PASSWORD,
  │                           PRRR_KEY_ALIAS, PRRR_KEY_PASSWORD)
  ├── buildTypes
  │   ├── debug (default, no minification)
  │   └── release (R8 minify + shrink + signing)
  └── defaultConfig
      ├── versionCode (from gradle.properties)
      └── versionName (from gradle.properties)

proguard-rules.pro
  ├── UniFFI keep rules
  ├── JNA keep rules
  ├── Kotlin serialization/coroutines
  ├── CameraX + ML Kit rules
  └── Mapping file output

res/
  ├── mipmap-anydpi-v26/
  │   ├── ic_launcher.xml (adaptive icon)
  │   └── ic_launcher_round.xml (adaptive icon)
  ├── drawable/
  │   ├── ic_launcher_foreground.xml (shield vector)
  │   └── ic_launcher_background.xml (solid color)
  └── values/
      └── ic_launcher_background.xml (background color)
```

### Signing Configuration
```kotlin
signingConfigs {
    create("release") {
        val props = rootProject.file("local.properties")
        if (props.exists()) {
            val localProps = java.util.Properties()
            localProps.load(props.inputStream())
            storeFile = file(localProps.getProperty("signing.storeFile", ""))
            storePassword = localProps.getProperty("signing.storePassword", "")
            keyAlias = localProps.getProperty("signing.keyAlias", "")
            keyPassword = localProps.getProperty("signing.keyPassword", "")
        } else {
            storeFile = file(System.getenv("PRRR_KEYSTORE_PATH") ?: "/dev/null")
            storePassword = System.getenv("PRRR_KEYSTORE_PASSWORD") ?: ""
            keyAlias = System.getenv("PRRR_KEY_ALIAS") ?: ""
            keyPassword = System.getenv("PRRR_KEY_PASSWORD") ?: ""
        }
    }
}
```

### ProGuard/R8 Rules (key additions)
```proguard
# UniFFI generated classes
-keep class uniffi.** { *; }
-keep class com.prrr.mobile.** { *; }

# JNA (required for UniFFI native calls)
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.Library { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }

# Kotlin coroutines
-keepclassmembers class kotlinx.coroutines.** { volatile <fields>; }
-keep class kotlinx.coroutines.internal.MainDispatcherLoader { *; }
-keep class kotlinx.coroutines.CoroutineExceptionHandler { *; }

# Keep R8 mapping file for crash report deobfuscation
-printmapping build/outputs/mapping/release/mapping.txt
```

## Acceptance Criteria

### Functional
- AC-1: `./gradlew assembleRelease` produces a release APK with R8 minification applied
- AC-2: `./gradlew bundleRelease` produces a release AAB (when signing is configured)
- AC-3: ProGuard/R8 rules preserve all UniFFI and JNA classes (no runtime ClassNotFoundException)
- AC-4: Adaptive launcher icons display correctly (shield icon with branded background)
- AC-5: `make android-release` and `make android-debug` work from project root
- AC-6: Release build is smaller than debug build
- AC-7: Debug build continues to work unchanged

### Non-Functional
- AC-8: No passwords or keystore paths appear in version-controlled files
- AC-9: Build succeeds without signing config (produces unsigned APK)

### Testing
- AC-10: Unit test validates ProGuard rules file contains required keep patterns
- AC-11: Build test verifies `assembleRelease` succeeds
- AC-12: All existing unit tests continue to pass

## Testing Strategy

### Unit Tests
- Test that ProGuard rules file contains required keep patterns for UniFFI, JNA, Kotlin coroutines
- Test that build.gradle.kts has correct release build type configuration

### Build Verification
- `./gradlew assembleRelease` completes without errors
- `./gradlew assembleDebug` continues to work
- `./gradlew testDebugUnitTest` passes all tests

### Manual Verification
- Inspect release APK size vs debug APK size
- Verify adaptive icon renders in Android Studio preview

## Dependencies
- Android Gradle Plugin 8.2.2 (existing)
- R8 (bundled with AGP)
- JNA 5.14.0 (existing)
- UniFFI bindings (existing)

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| R8 strips critical classes | High | Comprehensive keep rules + build verification test |
| Signing credentials leaked | Critical | Environment variables only, no hardcoded values |
| Adaptive icon renders poorly on some OEMs | Low | Use simple geometric shapes, test on multiple launcher skins |
| Release build crashes at runtime | High | Run unit tests against release build type |
| Version not incremented | Medium | Centralized in gradle.properties with clear documentation |

## Rollback
Rollback Strategy: Revert changes to `build.gradle.kts` and `proguard-rules.pro`. Restore original placeholder launcher icons from mipmap directories. Remove new Makefile targets.

## Implementation Checklist for Agent
- [x] Step 1: Create adaptive launcher icon vector resources (foreground + background)
- [x] Step 2: Create adaptive icon XML references in mipmap-anydpi-v26
- [x] Step 3: Update ProGuard/R8 rules with comprehensive keep rules
- [x] Step 4: Update build.gradle.kts with release signing config and R8 enablement
- [x] Step 5: Update gradle.properties with JVM heap for R8
- [x] Step 6: Add Makefile targets for android-release, android-debug, android-test
- [x] Step 7: Write unit tests for ProGuard rules and build config validation
- [x] Step 8: Run assembleRelease and verify build succeeds (27 MB unsigned APK)
- [x] Step 9: Run all existing unit tests and verify they pass (48/53, 5 native-dependent)
- [x] Step 10: Run `make lint` and verify clean
- [x] Step 11: Update roadmap with completion status
- [x] Step 12: Update docs/mobile-api.md with release build instructions
- [x] Step 13: Add traceability links

## Traceability
- Roadmap item: [specs/mobile-app/ROADMAP.md - Feature 3.7](../mobile-app/ROADMAP.md)
- Implementation files:
  - [x] `prrr-android/app/build.gradle.kts` - MODIFIED: signing config, R8 enablement, resource shrinking
  - [x] `prrr-android/app/proguard-rules.pro` - MODIFIED: comprehensive keep rules
  - [x] `prrr-android/app/src/main/res/drawable/ic_launcher_foreground.xml` - NEW: shield+lock vector
  - [x] `prrr-android/app/src/main/res/values/ic_launcher_background.xml` - NEW: teal background color
  - [x] `prrr-android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml` - NEW: adaptive icon
  - [x] `prrr-android/app/src/main/res/mipmap-anydpi-v26/ic_launcher_round.xml` - NEW: adaptive round icon
  - [x] `prrr-android/gradle.properties` - MODIFIED: JVM heap for R8
  - [x] `Makefile` - MODIFIED: android-debug, android-release, android-test targets
- Test files:
  - [x] `prrr-android/app/src/test/kotlin/com/prrr/vpn/android/build/ProguardRulesTest.kt` - 6 tests
  - [x] `prrr-android/app/src/test/kotlin/com/prrr/vpn/android/build/ReleaseBuildConfigTest.kt` - 7 tests

## Change Log
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-22 | Agent | Initial FRD draft |
| 1.1 | 2026-02-22 | Agent | Implementation complete |

## Status
**Status:** Complete
**Started:** 2026-02-22
**Completed:** 2026-02-22
