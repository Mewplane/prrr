#!/usr/bin/env bash
# FRD: specs/frds/FRD-M001-mobile-workspace.md
#
# Build prrr-mobile for iOS targets and create xcframework
#
# Usage:
#   ./scripts/build-ios.sh              # Build release
#   DEBUG=1 ./scripts/build-ios.sh      # Build debug

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MOBILE_DIR="${PROJECT_ROOT}/prrr-mobile"
OUTPUT_DIR="${MOBILE_DIR}/target/universal"

PROFILE="${DEBUG:+debug}"
PROFILE="${PROFILE:-release}"
PROFILE_FLAG=""
if [ "${PROFILE}" = "release" ]; then
    PROFILE_FLAG="--release"
fi

# iOS targets
IOS_TARGETS=(
    "aarch64-apple-ios"           # iOS devices (ARM64)
    "x86_64-apple-ios"            # iOS simulator (Intel)
    "aarch64-apple-ios-sim"       # iOS simulator (Apple Silicon)
)

LIB_NAME="libprrr_mobile.a"
FRAMEWORK_NAME="prrr_mobile.xcframework"

echo "==> Building prrr-mobile for iOS (${PROFILE} profile)"

# Check if running on macOS
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Error: iOS builds require macOS" >&2
    exit 1
fi

# Verify iOS targets are installed
echo "==> Checking iOS targets..."
for target in "${IOS_TARGETS[@]}"; do
    if ! rustup target list --installed | grep -q "^${target}$"; then
        echo "Error: Target ${target} not installed" >&2
        echo "Install with: rustup target add ${target}" >&2
        exit 1
    fi
done

# Build for each target
echo "==> Building for iOS targets..."
cd "${PROJECT_ROOT}"
for target in "${IOS_TARGETS[@]}"; do
    echo "  -> Building for ${target}..."
    cargo build -p prrr-mobile --target "${target}" ${PROFILE_FLAG}
done

# Create output directory
mkdir -p "${OUTPUT_DIR}"
rm -rf "${OUTPUT_DIR}/${FRAMEWORK_NAME}"

# Create xcframework structure
echo "==> Creating xcframework..."
XCFRAMEWORK_PATH="${OUTPUT_DIR}/${FRAMEWORK_NAME}"
mkdir -p "${XCFRAMEWORK_PATH}"

# For iOS device (aarch64-apple-ios)
DEVICE_DIR="${XCFRAMEWORK_PATH}/ios-arm64"
mkdir -p "${DEVICE_DIR}"
cp "${MOBILE_DIR}/target/aarch64-apple-ios/${PROFILE}/${LIB_NAME}" "${DEVICE_DIR}/"

# For iOS simulator (universal binary: x86_64 + aarch64)
SIM_DIR="${XCFRAMEWORK_PATH}/ios-arm64_x86_64-simulator"
mkdir -p "${SIM_DIR}"

# Create universal simulator library with lipo
echo "==> Creating universal simulator binary..."
lipo -create \
    "${MOBILE_DIR}/target/x86_64-apple-ios/${PROFILE}/${LIB_NAME}" \
    "${MOBILE_DIR}/target/aarch64-apple-ios-sim/${PROFILE}/${LIB_NAME}" \
    -output "${SIM_DIR}/${LIB_NAME}"

# Create Info.plist for xcframework
cat > "${XCFRAMEWORK_PATH}/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AvailableLibraries</key>
    <array>
        <dict>
            <key>LibraryIdentifier</key>
            <string>ios-arm64</string>
            <key>LibraryPath</key>
            <string>${LIB_NAME}</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
        </dict>
        <dict>
            <key>LibraryIdentifier</key>
            <string>ios-arm64_x86_64-simulator</string>
            <key>LibraryPath</key>
            <string>${LIB_NAME}</string>
            <key>SupportedArchitectures</key>
            <array>
                <string>arm64</string>
                <string>x86_64</string>
            </array>
            <key>SupportedPlatform</key>
            <string>ios</string>
            <key>SupportedPlatformVariant</key>
            <string>simulator</string>
        </dict>
    </array>
    <key>CFBundlePackageType</key>
    <string>XFWK</string>
    <key>XCFrameworkFormatVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF

echo "==> Build complete!"
echo "    XCFramework: ${XCFRAMEWORK_PATH}"
echo ""
echo "To use in Xcode:"
echo "  1. Drag ${FRAMEWORK_NAME} into your Xcode project"
echo "  2. Add to 'Frameworks, Libraries, and Embedded Content'"
echo "  3. Select 'Embed & Sign'"
