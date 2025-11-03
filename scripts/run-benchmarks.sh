#!/bin/bash
set -euo pipefail

# Script to run all benchmark tests
# These tests measure performance characteristics

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                      Running Benchmark Tests                              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

TOTAL_BENCHMARKS=0
PASSED_BENCHMARKS=0
FAILED_BENCHMARKS=0
FAILED_BENCHMARK_NAMES=()

run_benchmark() {
    local bench_name="$1"
    local features="$2"
    local description="$3"
    
    TOTAL_BENCHMARKS=$((TOTAL_BENCHMARKS + 1))
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}Benchmark ${TOTAL_BENCHMARKS}: ${description}${NC}"
    echo -e "${YELLOW}Features: ${features:-default}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [ -z "$features" ]; then
        if cargo bench --bench "$bench_name" 2>&1; then
            echo -e "${GREEN}✓ PASSED: ${description}${NC}"
            PASSED_BENCHMARKS=$((PASSED_BENCHMARKS + 1))
            return 0
        else
            echo -e "${RED}✗ FAILED: ${description}${NC}"
            FAILED_BENCHMARKS=$((FAILED_BENCHMARKS + 1))
            FAILED_BENCHMARK_NAMES+=("${description}")
            return 1
        fi
    else
        if cargo bench --bench "$bench_name" --features "$features" 2>&1; then
            echo -e "${GREEN}✓ PASSED: ${description}${NC}"
            PASSED_BENCHMARKS=$((PASSED_BENCHMARKS + 1))
            return 0
        else
            echo -e "${RED}✗ FAILED: ${description}${NC}"
            FAILED_BENCHMARKS=$((FAILED_BENCHMARKS + 1))
            FAILED_BENCHMARK_NAMES+=("${description}")
            return 1
        fi
    fi
}

# RSA Benchmarks
echo -e "${MAGENTA}Running RSA benchmarks...${NC}"
run_benchmark "rsa_signature_verification" "rsa" "RSA signature verification"
run_benchmark "rsa_end_to_end" "rsa" "RSA end-to-end"

# HMAC Benchmarks
echo ""
echo -e "${MAGENTA}Running HMAC benchmarks...${NC}"
run_benchmark "hmac_algorithms" "" "HMAC algorithms (HS256, HS384, HS512)"

# ECDSA Benchmarks
echo ""
echo -e "${MAGENTA}Running ECDSA benchmarks...${NC}"
run_benchmark "ecdsa_algorithms" "ecdsa" "ECDSA algorithms"

# Summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                        Benchmark Summary                                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Total benchmarks: ${TOTAL_BENCHMARKS}"
echo -e "${GREEN}Passed: ${PASSED_BENCHMARKS}${NC}"
if [ "$FAILED_BENCHMARKS" -gt 0 ]; then
    echo -e "${RED}Failed: ${FAILED_BENCHMARKS}${NC}"
    echo ""
    echo -e "${RED}Failed benchmarks:${NC}"
    for bench_name in "${FAILED_BENCHMARK_NAMES[@]}"; do
        echo -e "${RED}  - ${bench_name}${NC}"
    done
else
    echo -e "${GREEN}Failed: ${FAILED_BENCHMARKS}${NC}"
fi
echo ""
echo -e "${YELLOW}Note: Benchmark results are saved to target/criterion/${NC}"
echo -e "${YELLOW}View HTML reports at: target/criterion/report/index.html${NC}"
echo ""

if [ "$FAILED_BENCHMARKS" -eq 0 ]; then
    echo -e "${GREEN}✓ All benchmarks completed successfully!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some benchmarks failed!${NC}"
    exit 1
fi
