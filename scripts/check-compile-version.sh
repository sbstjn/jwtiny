#!/bin/bash
set -euo pipefail

# Script to check if jwtiny compiles on a specific Rust version
# Usage: ./check-compile-version.sh <rust-version>

# Store original toolchain to restore later
ORIGINAL_TOOLCHAIN=""

# Cleanup function to restore original toolchain
cleanup() {
    local exit_code=$?
    if [ -n "$ORIGINAL_TOOLCHAIN" ]; then
        echo "🔄 Restoring original toolchain..."
        rustup default "$ORIGINAL_TOOLCHAIN" >/dev/null 2>&1 || true
    fi
    exit $exit_code
}

# Set up trap to ensure cleanup runs on exit
trap cleanup EXIT INT TERM

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Parse arguments
TARGET_VERSION="${1:-}"

if [ -z "$TARGET_VERSION" ]; then
    echo "Usage: $0 <rust-version>"
    echo "Example: $0 1.84.0"
    exit 1
fi

echo "🔍 Checking compilation on Rust $TARGET_VERSION..."

# Store current toolchain
ORIGINAL_TOOLCHAIN=$(rustup show | grep "Default host" | awk '{print $3}' || echo "stable")

# Install target version if not present
echo "📦 Ensuring Rust $TARGET_VERSION is installed..."
if ! rustup toolchain list | grep -q "^$TARGET_VERSION"; then
    echo "   Installing Rust $TARGET_VERSION..."
    rustup install "$TARGET_VERSION"
else
    echo "   Rust $TARGET_VERSION already installed"
fi

# Switch to target version
echo "🔧 Switching to Rust $TARGET_VERSION..."
rustup default "$TARGET_VERSION" >/dev/null 2>&1

# Verify the switch
ACTUAL_VERSION=$(rustc --version | awk '{print $2}')
echo "   Current rustc version: $ACTUAL_VERSION"

if [[ ! "$ACTUAL_VERSION" == "$TARGET_VERSION"* ]]; then
    echo "❌ Warning: Version mismatch. Expected $TARGET_VERSION, got $ACTUAL_VERSION"
fi

# Run cargo check
echo "🔨 Running cargo check --all-targets..."
if cargo check --all-targets 2>&1; then
    echo ""
    echo "✅ Success! jwtiny compiles successfully on Rust $TARGET_VERSION"
    exit 0
else
    echo ""
    echo "❌ Failure! jwtiny does NOT compile on Rust $TARGET_VERSION"
    exit 1
fi

