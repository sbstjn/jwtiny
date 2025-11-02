#!/bin/bash
set -euo pipefail

# Script to run all integration tests
# These tests verify end-to-end functionality

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

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Running Integration Tests                              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if jwkserve is running on localhost:3000
echo -e "${YELLOW}Checking if jwkserve is running on localhost:3000...${NC}"
if curl -sf http://localhost:3000/.well-known/openid-configuration >/dev/null 2>&1; then
    echo -e "${GREEN}✓ jwkserve is running${NC}"
    JWKSERVE_AVAILABLE=true
else
    echo -e "${RED}✗ jwkserve is not available on localhost:3000${NC}"
    echo -e "${YELLOW}  Start jwkserve manually or use docker-compose up -d${NC}"
    JWKSERVE_AVAILABLE=false
fi
echo ""

# Integration tests with features that enable them
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
FAILED_TEST_NAMES=()

run_integration_test() {
    local features="$1"
    local description="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}Integration Test ${TOTAL_TESTS}: ${description}${NC}"
    echo -e "${YELLOW}Features: ${features}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if cargo test --test '*' --features "$features" 2>&1; then
        echo -e "${GREEN}✓ PASSED: ${description}${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "${RED}✗ FAILED: ${description}${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("${description}")
        return 1
    fi
}

# Run integration tests
# Test 1: Algorithm round trips (comprehensive algorithm testing)
run_integration_test "all-algorithms" "algorithm_round_trips (all algorithms)"

# Test 2: Custom headers (header field preservation)
run_integration_test "" "custom_headers (hmac)"

# Test 3: Edge cases (robustness testing)
run_integration_test "" "edge_cases (hmac)"

# Test 4: JWK support (key format handling)
run_integration_test "all-algorithms" "jwk_support (all algorithms)"

# Test 5: Key formats (key encoding formats)
run_integration_test "all-algorithms" "key_formats (all algorithms)"

# Test 6: JWT.io compatibility
run_integration_test "" "jwtio_compatibility (hmac)"

# Test 7: JWKServe integration (remote JWKS)
if [ "$JWKSERVE_AVAILABLE" = true ]; then
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}Integration Test: jwkserve_integration (remote JWKS)${NC}"
    echo -e "${YELLOW}Features: remote,rsa,aws-lc-rs${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if cargo test --test jwkserve_integration --features "remote,rsa,aws-lc-rs" 2>&1; then
        echo -e "${GREEN}✓ PASSED: jwkserve_integration (remote JWKS)${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED: jwkserve_integration (remote JWKS)${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("jwkserve_integration")
    fi
else
    echo -e "${RED}✗ FAILED: jwkserve_integration (jwkserve not available on localhost:3000)${NC}"
    echo -e "${YELLOW}  Integration tests require jwkserve to be running${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
    FAILED_TEST_NAMES+=("jwkserve_integration (not available)")
fi

# Summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                      Integration Test Summary                             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Total integration tests: ${TOTAL_TESTS}"
echo -e "${GREEN}Passed: ${PASSED_TESTS}${NC}"
if [ "$FAILED_TESTS" -gt 0 ]; then
    echo -e "${RED}Failed: ${FAILED_TESTS}${NC}"
    echo ""
    echo -e "${RED}Failed integration tests:${NC}"
    for test_name in "${FAILED_TEST_NAMES[@]}"; do
        echo -e "${RED}  - ${test_name}${NC}"
    done
else
    echo -e "${GREEN}Failed: ${FAILED_TESTS}${NC}"
fi
echo ""

if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "${GREEN}✓ All integration tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some integration tests failed!${NC}"
    exit 1
fi
