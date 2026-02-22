#!/usr/bin/env bash
# FRD: specs/frds/FRD-M002-uniffi-interface.md
#
# Generate UniFFI bindings for Swift and Kotlin

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MOBILE_DIR="${PROJECT_ROOT}/prrr-mobile"
UDL_FILE="${MOBILE_DIR}/src/mobile.udl"
BINDINGS_DIR="${MOBILE_DIR}/bindings"

echo "==> UniFFI Bindings Generation"

# Check if uniffi-bindgen is installed
if ! command -v uniffi-bindgen &> /dev/null; then
    echo "ERROR: uniffi-bindgen not found"
    echo "Install with: cargo install uniffi-bindgen --version 0.28"
    exit 1
fi

# Verify UDL file exists
if [ ! -f "${UDL_FILE}" ]; then
    echo "ERROR: UDL file not found: ${UDL_FILE}"
    exit 1
fi

# Create bindings directory
mkdir -p "${BINDINGS_DIR}/swift"
mkdir -p "${BINDINGS_DIR}/kotlin"

# Generate Swift bindings
echo "Generating Swift bindings..."
cd "${MOBILE_DIR}"
uniffi-bindgen generate src/mobile.udl --language swift --out-dir bindings/swift
echo "✓ Swift bindings: bindings/swift/prrr_mobile.swift"
echo "✓ Swift module map: bindings/swift/prrr_mobileFFI.modulemap"

# Generate Kotlin bindings
echo "Generating Kotlin bindings..."
uniffi-bindgen generate src/mobile.udl --language kotlin --out-dir bindings/kotlin
echo "✓ Kotlin bindings: bindings/kotlin/prrr_mobile.kt"

echo ""
echo "==> Bindings generated successfully!"
echo ""
echo "Swift usage:"
echo "  1. Add bindings/swift/*.swift to your Xcode project"
echo "  2. Add bindings/swift/*.modulemap"
echo "  3. Link with the XCFramework from scripts/build-ios.sh"
echo ""
echo "Kotlin usage:"
echo "  1. Add bindings/kotlin/*.kt to your Android project"
echo "  2. Include the AAR from scripts/build-android.sh"
