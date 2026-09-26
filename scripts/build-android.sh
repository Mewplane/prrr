#!/usr/bin/env bash
# FRD: specs/frds/FRD-M001-mobile-workspace.md
#
# Build prrr-mobile for Android targets and create AAR
#
# Usage:
#   export NDK_HOME=/path/to/ndk
#   ./scripts/build-android.sh              # Build release
#   DEBUG=1 ./scripts/build-android.sh      # Build debug
#
# The per-target native builds are driven by cargo-ndk, which configures the
# correct cc-rs environment (CC_*, AR_*, and the cargo linker) for each Android
# target using the versioned NDK clang wrappers. This avoids the cc-rs failure
# "failed to find tool aarch64-linux-android-clang" that occurs when only the
# linker is set in .cargo/config.toml (the NDK ships versioned wrappers such as
# aarch64-linux-android21-clang, not the unversioned name cc-rs looks for).

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/target"

PROFILE="${DEBUG:+debug}"
PROFILE="${PROFILE:-release}"
PROFILE_FLAG=""
if [ "${PROFILE}" = "release" ]; then
    PROFILE_FLAG="--release"
fi

# Android targets and their JNI architecture names.
# The cargo-ndk -t flags use the JNI/ABI names; the .so artifacts land under
# target/<rust-triple>/<profile>/ which the Makefile consumes.
declare -A ANDROID_TARGETS=(
    ["aarch64-linux-android"]="arm64-v8a"
    ["armv7-linux-androideabi"]="armeabi-v7a"
    ["x86_64-linux-android"]="x86_64"
    ["i686-linux-android"]="x86"
)

LIB_NAME="libprrr_mobile.so"
AAR_NAME="prrr_mobile.aar"

echo "==> Building prrr-mobile for Android (${PROFILE} profile)"

# Check NDK_HOME
if [ -z "${NDK_HOME:-}" ]; then
    echo "Error: NDK_HOME environment variable not set" >&2
    echo "" >&2
    echo "Set NDK_HOME to your Android NDK installation:" >&2
    echo "  export NDK_HOME=/path/to/android-ndk" >&2
    echo "" >&2
    echo "Download NDK from:" >&2
    echo "  https://developer.android.com/ndk/downloads" >&2
    exit 1
fi

if [ ! -d "${NDK_HOME}" ]; then
    echo "Error: NDK_HOME directory does not exist: ${NDK_HOME}" >&2
    exit 1
fi

# cargo-ndk reads the NDK location from ANDROID_NDK_HOME.
export ANDROID_NDK_HOME="${NDK_HOME}"

# Verify cargo-ndk is available (it is the supported toolchain for native
# Android builds in this repo).
if ! cargo ndk --version >/dev/null 2>&1; then
    echo "Error: cargo-ndk is not installed" >&2
    echo "Install with: cargo install cargo-ndk" >&2
    exit 1
fi

# Detect NDK toolchain path (for the existence check below). cargo-ndk does its
# own toolchain resolution; this is only a fail-fast sanity check.
NDK_HOST=$(find "${NDK_HOME}/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | head -1)
TOOLCHAIN="${NDK_HOME}/toolchains/llvm/prebuilt/${NDK_HOST}/bin"

if [ ! -d "${TOOLCHAIN}" ]; then
    echo "Error: Android toolchain not found at ${TOOLCHAIN}" >&2
    exit 1
fi

# Verify Android targets are installed
echo "==> Checking Android targets..."
for target in "${!ANDROID_TARGETS[@]}"; do
    if ! rustup target list --installed | grep -q "^${target}$"; then
        echo "Error: Target ${target} not installed" >&2
        echo "Install with: rustup target add ${target}" >&2
        exit 1
    fi
done

# Build for all targets via cargo-ndk. cargo-ndk sets CC_*/AR_*/CXX_* and the
# cargo target linker env vars from the versioned NDK clang wrappers, so cc-rs
# can compile C dependencies (e.g. ring) for every Android ABI.
echo "==> Building for Android targets via cargo-ndk..."
cd "${PROJECT_ROOT}"

NDK_TARGET_FLAGS=()
for jni_arch in "${ANDROID_TARGETS[@]}"; do
    NDK_TARGET_FLAGS+=("-t" "${jni_arch}")
done

if [ -n "${PROFILE_FLAG}" ]; then
    cargo ndk "${NDK_TARGET_FLAGS[@]}" build -p prrr-mobile "${PROFILE_FLAG}"
else
    cargo ndk "${NDK_TARGET_FLAGS[@]}" build -p prrr-mobile
fi

# Regenerate the Kotlin UniFFI bindings from the freshly-built library.
#
# prrr-mobile uses mixed UniFFI: UDL scaffolding plus #[uniffi::export] proc
# macros. The proc-macro exports (e.g. lanExcludedCidrs, sharingGetState) are
# only discoverable from the compiled library metadata, not from the UDL, so we
# generate in --library mode against a built .so. This keeps the checked-in
# bindings in lockstep with the Rust API instead of drifting out of date.
BINDGEN_TARGET="aarch64-linux-android"
BINDGEN_LIB="${OUTPUT_DIR}/${BINDGEN_TARGET}/${PROFILE}/${LIB_NAME}"
KOTLIN_BINDINGS_DIR="${PROJECT_ROOT}/prrr-mobile/bindings/kotlin"

if ! command -v uniffi-bindgen >/dev/null 2>&1; then
    echo "Error: uniffi-bindgen is not installed (needed to regenerate Kotlin bindings)" >&2
    echo "Install with: cargo install uniffi-bindgen --version 0.29" >&2
    exit 1
fi

echo "==> Regenerating Kotlin UniFFI bindings from ${BINDGEN_TARGET} library..."
rm -rf "${KOTLIN_BINDINGS_DIR}"
mkdir -p "${KOTLIN_BINDINGS_DIR}"
uniffi-bindgen generate \
    --library "${BINDGEN_LIB}" \
    --language kotlin \
    --no-format \
    --out-dir "${KOTLIN_BINDINGS_DIR}"
echo "    Kotlin bindings: ${KOTLIN_BINDINGS_DIR}/uniffi/prrr_mobile/prrr_mobile.kt"

# Create AAR structure
echo "==> Creating AAR..."
AAR_BUILD_DIR="${OUTPUT_DIR}/aar-build"
rm -rf "${AAR_BUILD_DIR}"
mkdir -p "${AAR_BUILD_DIR}"

# Copy native libraries from target/<triple>/<profile>/ into the AAR jni tree.
for target in "${!ANDROID_TARGETS[@]}"; do
    jni_arch="${ANDROID_TARGETS[$target]}"
    jni_dir="${AAR_BUILD_DIR}/jni/${jni_arch}"
    mkdir -p "${jni_dir}"
    cp "${OUTPUT_DIR}/${target}/${PROFILE}/${LIB_NAME}" "${jni_dir}/"
done

# Create AndroidManifest.xml
cat > "${AAR_BUILD_DIR}/AndroidManifest.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.prrr.mobile">
    <uses-sdk android:minSdkVersion="26" />
</manifest>
EOF

# Create classes.jar (empty for native-only library)
mkdir -p "${AAR_BUILD_DIR}/classes"
(cd "${AAR_BUILD_DIR}/classes" && jar cf ../classes.jar .)

# Create R.txt (empty)
touch "${AAR_BUILD_DIR}/R.txt"

# Package as AAR (AAR is just a ZIP with specific structure)
AAR_PATH="${OUTPUT_DIR}/${AAR_NAME}"
echo "  -> Packaging AAR..."
rm -f "${AAR_PATH}"
(cd "${AAR_BUILD_DIR}" && zip -q -r "${AAR_PATH}" .)

# Cleanup
rm -rf "${AAR_BUILD_DIR}"

echo "==> Build complete!"
echo "    AAR: ${AAR_PATH}"
echo ""
echo "To use in Android Studio:"
echo "  1. Copy ${AAR_NAME} to your project's libs/ directory"
echo "  2. Add to build.gradle:"
echo "     implementation files('libs/${AAR_NAME}')"
