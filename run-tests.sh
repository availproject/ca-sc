#!/bin/bash

# Vault.sol Test Suite Runner
# Runs all test types with detailed logging

set -e # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="test-run-$(date +%Y%m%d-%H%M%S).log"

# Logging function
log() {
	echo -e "$1" | tee -a "$LOG_FILE"
}

# Header
log "${BLUE}══════════════════════════════════════════════════════════════${NC}"
log "${BLUE}  Vault.sol Test Suite - $(date)${NC}"
log "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo "" | tee -a "$LOG_FILE"

# Function to run tests with error handling
run_test_suite() {
	local name=$1
	local pattern=$2
	local extra_args=${3:-""}

	log "${YELLOW}▶ Running $name...${NC}"
	echo "" | tee -a "$LOG_FILE"

	if forge test --match-contract "$pattern" $extra_args 2>&1 | tee -a "$LOG_FILE"; then
		log "${GREEN}✓ $name passed${NC}"
		echo "" | tee -a "$LOG_FILE"
		return 0
	else
		log "${RED}✗ $name failed${NC}"
		echo "" | tee -a "$LOG_FILE"
		return 1
	fi
}

# Run all test suites
FAILED=0

# 1. Unit Tests (44 tests)
run_test_suite "Unit Tests" "VaultUnitTest" "-vvv" || FAILED=$((FAILED + 1))

# 2. Fuzz Tests (7 tests, 256 runs each)
run_test_suite "Fuzz Tests" "VaultFuzzTest" "-vvv" || FAILED=$((FAILED + 1))

# 3. Invariant Tests (4 invariants, 128K calls)
run_test_suite "Invariant Tests" "VaultInvariantTest" "-vvv" || FAILED=$((FAILED + 1))

# 4. Integration Tests (7 tests)
run_test_suite "Integration Tests" "VaultIntegrationTest" "-vvv" || FAILED=$((FAILED + 1))

# Summary
echo "" | tee -a "$LOG_FILE"
log "${BLUE}══════════════════════════════════════════════════════════════${NC}"
log "${BLUE}  Test Summary${NC}"
log "${BLUE}══════════════════════════════════════════════════════════════${NC}"

if [ $FAILED -eq 0 ]; then
	log "${GREEN}✓ All test suites passed!${NC}"
	log "${GREEN}✓ Log saved to: $LOG_FILE${NC}"
	exit 0
else
	log "${RED}✗ $FAILED test suite(s) failed${NC}"
	log "${RED}✗ Check log: $LOG_FILE${NC}"
	exit 1
fi
