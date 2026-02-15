#!/bin/bash
#
# Test Coverage Requirement Checker
# ==================================
#
# Validates test coverage meets minimum requirements
# Supports: Jest, PyTest, Go test, Istanbul/nyc
#
# Usage:
#   ./scripts/check-coverage.sh [--strict]
#
# Options:
#   --strict    Fail if coverage is below threshold
#
# Exit codes:
#   0 - Coverage meets requirements
#   1 - Coverage below threshold
#   2 - No coverage report found
#

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

# Coverage thresholds (can be overridden by project)
LINE_COVERAGE_THRESHOLD=${LINE_COVERAGE_THRESHOLD:-80}
BRANCH_COVERAGE_THRESHOLD=${BRANCH_COVERAGE_THRESHOLD:-75}
FUNCTION_COVERAGE_THRESHOLD=${FUNCTION_COVERAGE_THRESHOLD:-100}
STATEMENT_COVERAGE_THRESHOLD=${STATEMENT_COVERAGE_THRESHOLD:-80}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Modes
STRICT_MODE=false
if [ "$1" = "--strict" ]; then
  STRICT_MODE=true
fi

# ============================================================================
# FUNCTIONS
# ============================================================================

print_header() {
  echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║          Test Coverage Requirement Checker                ║${NC}"
  echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

print_thresholds() {
  echo -e "${BLUE}Coverage Thresholds:${NC}"
  echo -e "  Line Coverage:      ${LINE_COVERAGE_THRESHOLD}%"
  echo -e "  Branch Coverage:    ${BRANCH_COVERAGE_THRESHOLD}%"
  echo -e "  Function Coverage:  ${FUNCTION_COVERAGE_THRESHOLD}%"
  echo -e "  Statement Coverage: ${STATEMENT_COVERAGE_THRESHOLD}%"
  echo ""
}

check_coverage_value() {
  local metric=$1
  local value=$2
  local threshold=$3

  if (( $(echo "$value >= $threshold" | bc -l) )); then
    echo -e "  ${GREEN}✓${NC} $metric: ${GREEN}${value}%${NC} (threshold: ${threshold}%)"
    return 0
  else
    echo -e "  ${RED}✗${NC} $metric: ${RED}${value}%${NC} (threshold: ${threshold}%)"
    return 1
  fi
}

# ============================================================================
# JEST/ISTANBUL COVERAGE CHECK
# ============================================================================

check_jest_coverage() {
  local coverage_file="coverage/coverage-summary.json"

  if [ ! -f "$coverage_file" ]; then
    return 1
  fi

  echo -e "${BLUE}Checking Jest/Istanbul coverage...${NC}"
  echo ""

  # Extract coverage percentages using jq
  if command -v jq &> /dev/null; then
    local lines=$(jq -r '.total.lines.pct' "$coverage_file")
    local branches=$(jq -r '.total.branches.pct' "$coverage_file")
    local functions=$(jq -r '.total.functions.pct' "$coverage_file")
    local statements=$(jq -r '.total.statements.pct' "$coverage_file")

    local all_passed=true

    check_coverage_value "Lines" "$lines" "$LINE_COVERAGE_THRESHOLD" || all_passed=false
    check_coverage_value "Branches" "$branches" "$BRANCH_COVERAGE_THRESHOLD" || all_passed=false
    check_coverage_value "Functions" "$functions" "$FUNCTION_COVERAGE_THRESHOLD" || all_passed=false
    check_coverage_value "Statements" "$statements" "$STATEMENT_COVERAGE_THRESHOLD" || all_passed=false

    echo ""

    if [ "$all_passed" = true ]; then
      echo -e "${GREEN}✓ Jest coverage meets all requirements${NC}"
      return 0
    else
      echo -e "${RED}✗ Jest coverage below threshold${NC}"
      return 1
    fi
  else
    echo -e "${YELLOW}⚠ jq not found, cannot parse coverage JSON${NC}"
    return 2
  fi
}

# ============================================================================
# PYTEST COVERAGE CHECK
# ============================================================================

check_pytest_coverage() {
  local coverage_file="coverage.xml"

  if [ ! -f "$coverage_file" ]; then
    coverage_file=".coverage"
    if [ ! -f "$coverage_file" ]; then
      return 1
    fi
  fi

  echo -e "${BLUE}Checking PyTest coverage...${NC}"
  echo ""

  # Run coverage report
  if command -v coverage &> /dev/null; then
    # Get coverage percentage
    local coverage_output=$(coverage report 2>&1)
    local total_coverage=$(echo "$coverage_output" | grep "TOTAL" | awk '{print $NF}' | tr -d '%')

    if [ -z "$total_coverage" ]; then
      echo -e "${YELLOW}⚠ Could not parse coverage percentage${NC}"
      return 2
    fi

    check_coverage_value "Total Coverage" "$total_coverage" "$LINE_COVERAGE_THRESHOLD"
    local result=$?

    echo ""

    if [ $result -eq 0 ]; then
      echo -e "${GREEN}✓ PyTest coverage meets requirements${NC}"
      echo ""
      echo -e "Detailed report:"
      echo "$coverage_output"
      return 0
    else
      echo -e "${RED}✗ PyTest coverage below threshold${NC}"
      echo ""
      echo -e "Detailed report:"
      echo "$coverage_output"
      return 1
    fi
  else
    echo -e "${YELLOW}⚠ coverage command not found${NC}"
    return 2
  fi
}

# ============================================================================
# GO TEST COVERAGE CHECK
# ============================================================================

check_go_coverage() {
  local coverage_file="coverage.out"

  if [ ! -f "$coverage_file" ]; then
    return 1
  fi

  echo -e "${BLUE}Checking Go test coverage...${NC}"
  echo ""

  # Calculate coverage percentage
  local coverage_output=$(go tool cover -func="$coverage_file")
  local total_coverage=$(echo "$coverage_output" | grep "total:" | awk '{print $NF}' | tr -d '%')

  if [ -z "$total_coverage" ]; then
    echo -e "${YELLOW}⚠ Could not parse coverage percentage${NC}"
    return 2
  fi

  check_coverage_value "Total Coverage" "$total_coverage" "$LINE_COVERAGE_THRESHOLD"
  local result=$?

  echo ""

  if [ $result -eq 0 ]; then
    echo -e "${GREEN}✓ Go test coverage meets requirements${NC}"
    echo ""
    echo -e "Detailed report:"
    echo "$coverage_output"
    return 0
  else
    echo -e "${RED}✗ Go test coverage below threshold${NC}"
    echo ""
    echo -e "Detailed report:"
    echo "$coverage_output"
    return 1
  fi
}

# ============================================================================
# GENERIC COVERAGE CHECK (tries to detect coverage format)
# ============================================================================

detect_and_check_coverage() {
  # Try Jest/Istanbul first
  if check_jest_coverage; then
    return 0
  fi

  # Try PyTest
  if check_pytest_coverage; then
    return 0
  fi

  # Try Go
  if check_go_coverage; then
    return 0
  fi

  # No coverage found
  echo -e "${RED}✗ No coverage report found${NC}"
  echo ""
  echo -e "Searched for:"
  echo -e "  • coverage/coverage-summary.json (Jest/Istanbul)"
  echo -e "  • coverage.xml or .coverage (PyTest)"
  echo -e "  • coverage.out (Go)"
  echo ""
  echo -e "Run tests with coverage first:"
  echo -e "  ${YELLOW}Jest:${NC}   npm test -- --coverage"
  echo -e "  ${YELLOW}PyTest:${NC} pytest --cov=src --cov-report=xml"
  echo -e "  ${YELLOW}Go:${NC}     go test -coverprofile=coverage.out ./..."
  echo ""
  return 2
}

# ============================================================================
# MAIN
# ============================================================================

main() {
  print_header
  print_thresholds

  # Detect and check coverage
  detect_and_check_coverage
  local coverage_status=$?

  echo ""
  echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

  if [ $coverage_status -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage check PASSED${NC}"
    exit 0
  elif [ $coverage_status -eq 2 ]; then
    echo -e "${YELLOW}⚠ Coverage check SKIPPED (no report found)${NC}"
    if [ "$STRICT_MODE" = true ]; then
      exit 1
    else
      exit 0
    fi
  else
    echo -e "${RED}✗ Coverage check FAILED${NC}"
    if [ "$STRICT_MODE" = true ]; then
      exit 1
    else
      echo ""
      echo -e "${YELLOW}Running in non-strict mode - not failing build${NC}"
      echo -e "Use ${BLUE}--strict${NC} to enforce coverage requirements"
      exit 0
    fi
  fi
}

main
