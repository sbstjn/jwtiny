#!/bin/bash
set -euo pipefail

# Script to measure bundle size of compiled library artifact
# Outputs size information to GitHub Actions outputs and JSON file

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Parse arguments
FEATURE_NAME="${1:-}"
FEATURE_LABEL="${2:-}"
FEATURES="${3:-}"

if [ -z "$FEATURE_NAME" ] || [ -z "$FEATURE_LABEL" ]; then
    echo "Usage: $0 <feature-name> <feature-label> [features]"
    exit 1
fi

RLIB_PATH="target/release/libjwtiny.rlib"

if [ ! -f "$RLIB_PATH" ]; then
    echo "❌ Error: Library artifact not found at $RLIB_PATH"
    exit 1
fi

# Measure file size (works on both macOS and Linux)
SIZE_BYTES=$(stat -f%z "$RLIB_PATH" 2>/dev/null || stat -c%s "$RLIB_PATH" 2>/dev/null || echo "0")

if [ "$SIZE_BYTES" = "0" ]; then
    echo "❌ Error: Failed to determine file size"
    exit 1
fi

# Calculate sizes (using awk for portability, no bc dependency)
SIZE_KB=$(awk "BEGIN {printf \"%.2f\", $SIZE_BYTES / 1024}")
SIZE_MB=$(awk "BEGIN {printf \"%.3f\", $SIZE_BYTES / 1024 / 1024}")

# Output to GitHub Actions (if GITHUB_OUTPUT is set)
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "size_bytes=$SIZE_BYTES" >> "$GITHUB_OUTPUT"
    echo "size_kb=$SIZE_KB" >> "$GITHUB_OUTPUT"
    echo "size_mb=$SIZE_MB" >> "$GITHUB_OUTPUT"
fi

# Output to console
echo "📦 Bundle size for $FEATURE_LABEL:"
echo "   Size: ${SIZE_KB} KB (${SIZE_MB} MB)"
echo "   Bytes: ${SIZE_BYTES}"

# Output JSON to file using jq if available, otherwise use printf (safer than heredoc)
mkdir -p bundle-sizes
JSON_FILE="bundle-sizes/${FEATURE_NAME}.json"

if command -v jq >/dev/null 2>&1; then
    jq -n \
        --arg name "$FEATURE_NAME" \
        --arg label "$FEATURE_LABEL" \
        --arg features "$FEATURES" \
        --argjson size_bytes "$SIZE_BYTES" \
        --arg size_kb "$SIZE_KB" \
        --arg size_mb "$SIZE_MB" \
        '{name: $name, label: $label, features: $features, size_bytes: $size_bytes, size_kb: $size_kb, size_mb: $size_mb}' \
        > "$JSON_FILE"
else
    # Fallback: use printf with JSON escaping for safety
    # Escape quotes and backslashes in string values
    ESCAPED_NAME=$(printf '%s\n' "$FEATURE_NAME" | sed 's/["\\]/\\&/g')
    ESCAPED_LABEL=$(printf '%s\n' "$FEATURE_LABEL" | sed 's/["\\]/\\&/g')
    ESCAPED_FEATURES=$(printf '%s\n' "$FEATURES" | sed 's/["\\]/\\&/g')
    
    printf '{\n  "name": "%s",\n  "label": "%s",\n  "features": "%s",\n  "size_bytes": %d,\n  "size_kb": "%s",\n  "size_mb": "%s"\n}\n' \
        "$ESCAPED_NAME" "$ESCAPED_LABEL" "$ESCAPED_FEATURES" "$SIZE_BYTES" "$SIZE_KB" "$SIZE_MB" \
        > "$JSON_FILE"
fi

echo "✓ Size data written to $JSON_FILE"

