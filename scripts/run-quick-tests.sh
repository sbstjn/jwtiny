#!/bin/bash
set -euo pipefail

# Script to run quick tests for common use cases
# This provides fast feedback for the majority of cases

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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
    echo -e "${CYAN}Quick Test ${TOTAL_COMBINATIONS}/6: ${description}${NC}"
    echo -e "${YELLOW}Features: ${features:-default}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [ -z "$features" ]; then
        if cargo test --lib --tests 2>&1; then
            echo -e "${GREEN}✓ PASSED: ${description}${NC}"
            PASSED_COMBINATIONS=$((PASSED_COMBINATIONS + 1))
            return 0
        else
            echo -e "${RED}✗ FAILED: ${description}${NC}"
            FAILED_COMBINATIONS=$((FAILED_COMBINATIONS + 1))
            FAILED_FEATURES+=("${description} (${features:-default})")
            return 1
        fi
    else
        if cargo test --lib --tests --features "$features" 2>&1; then
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

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                     Running Quick Tests                                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}This runs the most common test combinations for fast feedback${NC}"
echo ""

# Core tests - most commonly used
run_tests "" "default (HMAC only)"

# RSA tests - popular choice
run_tests "rsa" "RSA (ring)"

# ECDSA tests - growing in popularity
run_tests "ecdsa" "ECDSA (ring)"

# All algorithms - comprehensive
run_tests "all-algorithms" "All algorithms (ring)"

# All algorithms with aws-lc-rs backend
run_tests "all-algorithms,aws-lc-rs" "All algorithms (aws-lc-rs)"

# All algorithms with remote - most complete
run_tests "all-algorithms,remote" "All algorithms (ring) + remote"

# Summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                          Quick Test Summary                               ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Total test combinations: ${TOTAL_COMBINATIONS}"
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
    echo -e "${GREEN}✓ All quick tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some quick tests failed!${NC}"
    exit 1
fi
