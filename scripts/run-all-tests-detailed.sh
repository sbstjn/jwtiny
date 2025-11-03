#!/bin/bash
set -euo pipefail

# Script to run all tests (unit and integration) with all feature combinations
# and detailed output

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Test result tracking
TOTAL_COMBINATIONS=0
PASSED_COMBINATIONS=0
FAILED_COMBINATIONS=0
FAILED_FEATURES=()

# Function to run tests with a specific feature combination
run_tests() {
    local features="$1"
    local description="$2"
    
    TOTAL_COMBINATIONS=$((TOTAL_COMBINATIONS + 1))
    
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Testing: ${description}${NC}"
    echo -e "${BLUE}Features: ${features:-default}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [ -z "$features" ]; then
        if cargo test --all-targets -- --nocapture 2>&1; then
            echo -e "${GREEN}✓ PASSED: ${description}${NC}"
            PASSED_COMBINATIONS=$((PASSED_COMBINATIONS + 1))
            return 0
        else
            echo -e "${RED}✗ FAILED: ${description}${NC}"
            FAILED_COMBINATIONS=$((FAILED_COMBINATIONS + 1))
            FAILED_FEATURES+=("${description} (${features})")
            return 1
        fi
    else
        if cargo test --all-targets --features "$features" -- --nocapture 2>&1; then
            echo -e "${GREEN}✓ PASSED: ${description}${NC}"
            PASSED_COMBINATIONS=$((PASSED_COMBINATIONS + 1))
            return 0
        else
            echo -e "${RED}✗ FAILED: ${description}${NC}"
            FAILED_COMBINATIONS=$((FAILED_COMBINATIONS + 1))
            FAILED_FEATURES+=("${description} (${features})")
            return 1
        fi
    fi
}

# Count total tests
echo -e "${MAGENTA}Counting total feature combinations...${NC}"
NUM_TOTAL=0
# We'll count as we go, so initialize to the known number
NUM_TOTAL=17  # Based on the combinations below

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              Running All Tests with Maximum Detail                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}This will test all feature combinations with detailed output (--nocapture)${NC}"
echo -e "${YELLOW}This may take a considerable amount of time.${NC}"
echo ""

# Core algorithm features
run_tests "" "default (HMAC only)"
run_tests "rsa" "RSA (ring)"
run_tests "ecdsa" "ECDSA (ring)"

# aws-lc-rs backend combinations
run_tests "rsa,aws-lc-rs" "RSA (aws-lc-rs)"
run_tests "ecdsa,aws-lc-rs" "ECDSA (aws-lc-rs)"

# All algorithms combinations
run_tests "all-algorithms" "All algorithms (ring)"
run_tests "all-algorithms,aws-lc-rs" "All algorithms (aws-lc-rs)"

# Remote features
run_tests "remote" "Remote (HTTPS via rustls)"

# Remote with algorithms
run_tests "rsa,remote" "RSA (ring) + remote"
run_tests "ecdsa,remote" "ECDSA (ring) + remote"
run_tests "all-algorithms,remote" "All algorithms (ring) + remote"
run_tests "rsa,aws-lc-rs,remote" "RSA (aws-lc-rs) + remote"
run_tests "all-algorithms,aws-lc-rs,remote" "All algorithms (aws-lc-rs) + remote"

# Remote (alias kept but unnecessary) combinations

# Summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                              Test Summary                                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Total feature combinations tested: ${TOTAL_COMBINATIONS}"
echo -e "${GREEN}Passed: ${PASSED_COMBINATIONS}${NC}"
if [ "$FAILED_COMBINATIONS" -gt 0 ]; then
    echo -e "${RED}Failed: ${FAILED_COMBINATIONS}${NC}"
    echo ""
    echo -e "${RED}Failed test combinations:${NC}"
    for feature in "${FAILED_FEATURES[@]}"; do
        echo -e "${RED}  - ${feature}${NC}"
    done
else
    echo -e "${GREEN}Failed: ${FAILED_COMBINATIONS}${NC}"
fi
echo ""

if [ "$FAILED_COMBINATIONS" -eq 0 ]; then
    echo -e "${GREEN}✓ All test combinations passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some test combinations failed!${NC}"
    exit 1
fi
