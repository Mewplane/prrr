# iOS Build Options on Linux

**Context:** Phase 2 of the mobile app roadmap requires macOS + Xcode for iOS development. We're currently on Linux (Fedora).

**Created:** 2026-02-22  
**Current Environment:** Linux 6.18.10-200.fc43.x86_64, Docker 5.7.1, Hardware virtualization enabled (AMD SVM)

## Problem Statement

iOS application development traditionally requires:
- macOS operating system (13.0+)
- Xcode 15+
- Apple Developer account
- Physical iOS device for testing

We need to evaluate alternatives for building iOS apps from our Linux environment.

## Options Analysis

### Option 1: Docker-OSX (macOS in Docker)

**Overview:**
Run macOS VM inside Docker container using [sickcodes/Docker-OSX](https://github.com/sickcodes/Docker-OSX).

**Technical Details:**
- Uses OSX-KVM with QEMU
- Supports X11 forwarding for GUI
- Can run Xcode inside the container
- Supports signing into Xcode and Transporter
- Requires hardware virtualization (✅ Available - AMD SVM)

**Pros:**
✅ Full macOS environment  
✅ Can run real Xcode  
✅ Docker-based workflow (fits existing infrastructure)  
✅ Good for CI/CD pipelines  
✅ Hardware virtualization available  
✅ Docker already installed (5.7.1)

**Cons:**
❌ **Legal concerns** - Apple EULA prohibits macOS on non-Apple hardware  
❌ Performance overhead (VM layer)  
❌ Large disk space requirements (macOS image ~20-50GB)  
❌ Complex setup and maintenance  
❌ May be unstable for production builds  
❌ Requires significant RAM (8GB+ recommended)

**Resources:**
- [GitHub: sickcodes/Docker-OSX](https://github.com/sickcodes/Docker-OSX)
- [Docker Hub: sickcodes/docker-osx](https://hub.docker.com/r/sickcodes/docker-osx)
- [Issue #92: Container for iOS build system for CI/CD](https://github.com/sickcodes/Docker-OSX/issues/92)
- [Issue #707: Running Xcode build](https://github.com/sickcodes/Docker-OSX/issues/707)

**Feasibility:** 🟡 **Possible but risky**

**Legal Status:** 🔴 **Violates Apple EULA** - Using macOS on non-Apple hardware is against Apple's terms of service.

---

### Option 2: Cloud macOS Build Services

**Overview:**
Use cloud-based macOS instances for builds.

**Providers:**
1. **GitHub Actions** (macOS runners)
   - Free tier: Limited minutes
   - Paid: $0.08/minute for macOS
   - Native Xcode environment
   - Good CI/CD integration

2. **CircleCI** (macOS executors)
   - Paid plans only
   - Xcode pre-installed
   - Good performance

3. **MacStadium** (Dedicated macOS cloud)
   - Starting ~$79/month
   - Full macOS VMs
   - Root access

4. **Codemagic** (Mobile CI/CD)
   - Free tier for open source
   - Built specifically for iOS/Android
   - Good for mobile apps

**Pros:**
✅ **Legal** - Running on Apple hardware  
✅ Real macOS environment  
✅ No local resource usage  
✅ Professional/stable  
✅ Good for CI/CD  
✅ Pre-configured Xcode

**Cons:**
❌ Costs money (after free tier)  
❌ Requires internet connection  
❌ Less control than local  
❌ May have build time limits  
❌ Not suitable for interactive development

**Feasibility:** 🟢 **Recommended for CI/CD**

**Legal Status:** 🟢 **Fully compliant** with Apple's terms

---

### Option 3: Cross-Compilation Tools

**Overview:**
Tools that claim to build iOS apps without macOS.

**Tools:**
- **Darling** - macOS compatibility layer (Linux)
- **React Native** with cloud build services
- **Flutter** with Codemagic/similar

**Pros:**
✅ No macOS needed locally

**Cons:**
❌ **Not viable for native iOS** - We're building native Swift/SwiftUI app  
❌ Limited to specific frameworks  
❌ Poor Xcode integration  
❌ Can't run Xcode Interface Builder

**Feasibility:** 🔴 **Not suitable** - We need native Xcode for SwiftUI development

---

### Option 4: Buy/Rent Mac Hardware

**Overview:**
Acquire actual Apple hardware.

**Options:**
1. **Mac Mini** (~$599 new, ~$300-400 used)
2. **MacBook Air** (~$999 new)
3. **Rent Mac** (services like MacInCloud ~$20-50/month)
4. **CI Mac Mini** (dedicated for builds only)

**Pros:**
✅ **Legal** and fully supported  
✅ Best performance  
✅ Full control  
✅ Can do interactive development  
✅ Long-term investment  
✅ Supports all iOS development workflows

**Cons:**
❌ Upfront cost ($300-999)  
❌ Physical hardware to manage  
❌ Not available immediately

**Feasibility:** 🟢 **Best long-term solution**

**Legal Status:** 🟢 **Fully compliant**

---

### Option 5: Proceed with Android Only (Phase 3)

**Overview:**
Complete Android development on Linux, defer iOS until macOS available.

**Technical Details:**
- Android SDK/NDK works natively on Linux
- Android Studio available for Linux
- No legal concerns
- Phase 1 (Rust core) is complete and iOS-ready

**Pros:**
✅ **Can start immediately**  
✅ No legal issues  
✅ No additional cost  
✅ Validates mobile architecture  
✅ Delivers Android app  
✅ iOS can be added later (Rust core is ready)

**Cons:**
❌ iOS development delayed  
❌ Can't test iOS-specific issues

**Feasibility:** 🟢 **Immediately viable**

---

## Recommendations

### For Immediate Progress: **Option 5 (Android First)**

**Rationale:**
1. Phase 1 Rust core is complete and iOS-ready
2. Android can be developed on Linux immediately
3. No legal or financial blockers
4. Validates the mobile architecture
5. iOS can be added later when macOS is available

**Action Plan:**
```bash
# Start Android development immediately
1. Install Android SDK/NDK
2. Implement Phase 3, Feature 3.1 (Android Project Setup)
3. Continue through Android features
4. Defer iOS until macOS solution is available
```

### For iOS Development: **Option 4 (Cloud Services) or Option 4 (Mac Hardware)**

**Short-term (CI/CD):**
- Use **GitHub Actions** with macOS runners for builds
- Free tier sufficient for initial development
- Can build/test iOS app in CI
- Cost: Free (with limits) or ~$0.08/min

**Long-term (Interactive Development):**
- Acquire **used Mac Mini** (~$300-400)
- Enables full iOS development workflow
- One-time investment
- Best developer experience

### NOT Recommended: **Option 1 (Docker-OSX)**

**Reasons:**
- ❌ Violates Apple EULA (legal risk)
- ❌ Complex and potentially unstable
- ❌ Not worth the legal/technical risk when alternatives exist
- ❌ May cause issues with App Store submission

---

## Decision Matrix

| Option | Cost | Legal | Setup Time | Viability | Recommended |
|--------|------|-------|------------|-----------|-------------|
| Docker-OSX | Free | ❌ No | High | Low | ❌ No |
| Cloud (GitHub Actions) | Free-Low | ✅ Yes | Low | High | ✅ Yes (CI) |
| Cross-compilation | Free | ✅ Yes | N/A | None | ❌ No |
| Mac Hardware | $300-999 | ✅ Yes | Medium | High | ✅ Yes (Dev) |
| Android First | Free | ✅ Yes | Low | High | ✅✅ **Best** |

---

## Proposed Implementation Strategy

### Phase A: Android Development (Immediate)
**Timeline:** 2-3 weeks  
**Platform:** Linux (current)

1. Install Android SDK/NDK
2. Implement Phase 3 features (Android app)
3. Validate mobile architecture
4. Deliver working Android VPN app

### Phase B: iOS CI Setup (Parallel)
**Timeline:** 1 week  
**Platform:** GitHub Actions (cloud)

1. Create GitHub Actions workflow for iOS builds
2. Set up signing with GitHub secrets
3. Automate build/test for iOS
4. TestFlight upload automation

### Phase C: iOS Development (When macOS Available)
**Timeline:** 2-3 weeks  
**Platform:** Mac hardware or cloud

1. Implement Phase 2 features (iOS app)
2. Interactive development and testing
3. TestFlight beta testing
4. App Store submission

---

## Immediate Next Steps

### Recommended: Start Android Development

```bash
# 1. Install Android tools
sudo dnf install android-tools android-ndk

# 2. Install Android Studio (optional but recommended)
# Download from: https://developer.android.com/studio

# 3. Start Feature 3.1: Android Project Setup
# Follow FRD-M008 (to be created)

# 4. Build Android app through Phase 3
```

### Alternative: Setup GitHub Actions for iOS (CI only)

```yaml
# .github/workflows/ios-build.yml
name: iOS Build
on: [push]
jobs:
  build:
    runs-on: macos-14  # macOS runner with Xcode
    steps:
      - uses: actions/checkout@v4
      - name: Build iOS Framework
        run: |
          cd prrr-mobile
          ./scripts/build-ios.sh
      # Future: Build iOS app when Phase 2 code exists
```

---

## Conclusion

**Recommended Path:** Proceed with **Option 5 (Android First)** immediately, then address iOS via **Option 4 (Cloud CI + eventual Mac hardware)** when needed.

This approach:
- ✅ Maintains momentum (start Android now)
- ✅ Stays legal (no EULA violations)
- ✅ Validates architecture (Android tests mobile core)
- ✅ Delivers value (working Android app)
- ✅ Defers iOS cost until needed
- ✅ Allows iOS development when macOS available

**Phase 1 is complete and iOS-ready.** When macOS becomes available (cloud or hardware), iOS development can proceed immediately using the completed Rust core library.

---

## References

### Docker-OSX Resources
- [GitHub: sickcodes/Docker-OSX](https://github.com/sickcodes/Docker-OSX)
- [Container for iOS build system for CI/CD](https://github.com/sickcodes/Docker-OSX/issues/92)
- [Running Xcode build](https://github.com/sickcodes/Docker-OSX/issues/707)
- [Docker Hub: sickcodes/docker-osx](https://hub.docker.com/r/sickcodes/docker-osx)

### Cloud Services
- [GitHub Actions: macOS Runners](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners)
- [Codemagic: Mobile CI/CD](https://codemagic.io/)
- [CircleCI: macOS Executors](https://circleci.com/docs/executor-intro/#macos)

### Legal Information
- Apple EULA prohibits macOS on non-Apple hardware
- [Discussion: Build iOS Apps on Linux](https://news.ycombinator.com/item?id=43952239)

### Mobile Build Strategies
- [How to Use Containers to Build iOS Apps in Cloud](https://smartbear.com/blog/how-to-use-containers-to-build-ios-apps-in-cloud/)
- [Docker-First Mobile Build Pipelines](https://dzone.com/articles/beyond-containers-docker-first-mobile-build-pipeli)
- [Building Flutter for iOS on Linux](https://medium.com/@gregmus/building-flutter-for-ios-on-linux-589a3b395808)

---

**Last Updated:** 2026-02-22  
**Environment:** Linux 6.18.10-200.fc43.x86_64, Docker 5.7.1, AMD CPU with SVM virtualization
