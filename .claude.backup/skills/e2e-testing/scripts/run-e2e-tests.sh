#!/bin/bash
#
# E2E Test Runner
# ===============
#
# Comprehensive E2E test runner with environment setup, test execution, and reporting
#
# Usage:
#   ./run-e2e-tests.sh                     # Run all E2E tests
#   ./run-e2e-tests.sh --env=staging       # Run against staging environment
#   ./run-e2e-tests.sh --headed            # Run with visible browser
#   ./run-e2e-tests.sh --pattern=login     # Run specific test pattern
#   ./run-e2e-tests.sh --ci                # Run in CI mode
#
# Options:
#   --env=<environment>    Target environment (local|staging|production)
#   --headed               Run browser in headed mode (visible)
#   --pattern=<pattern>    Run tests matching pattern (regex)
#   --ci                   CI mode (headless, minimal output)
#   --verbose              Show detailed output
#   --debug                Enable debug mode
#   --skip-setup           Skip environment setup
#   --keep-artifacts       Keep screenshots and videos after success
#

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

ENVIRONMENT="local"
HEADED=false
PATTERN=""
CI_MODE=false
VERBOSE=false
DEBUG=false
SKIP_SETUP=false
KEEP_ARTIFACTS=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================================
# PARSE ARGUMENTS
# ============================================================================

for arg in "$@"; do
  case $arg in
    --env=*)
      ENVIRONMENT="${arg#*=}"
      ;;
    --headed)
      HEADED=true
      ;;
    --pattern=*)
      PATTERN="${arg#*=}"
      ;;
    --ci)
      CI_MODE=true
      ;;
    --verbose)
      VERBOSE=true
      ;;
    --debug)
      DEBUG=true
      ;;
    --skip-setup)
      SKIP_SETUP=true
      ;;
    --keep-artifacts)
      KEEP_ARTIFACTS=true
      ;;
    *)
      echo "Unknown option: $arg"
      echo "Usage: $0 [--env=<env>] [--headed] [--pattern=<pattern>] [--ci] [--verbose] [--debug]"
      exit 1
      ;;
  esac
done

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

log_info() {
  echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
  echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
  echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
  echo -e "${RED}✗${NC} $1"
}

print_header() {
  echo ""
  echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║              E2E Test Runner                               ║${NC}"
  echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================

setup_environment() {
  log_info "Setting up environment: $ENVIRONMENT"

  # Load environment variables
  case $ENVIRONMENT in
    local)
      export BASE_URL="http://localhost:3000"
      export API_URL="http://localhost:3000/api"
      export DB_HOST="localhost"
      export DB_PORT="5432"
      export DB_NAME="test_db"
      ;;
    staging)
      export BASE_URL="https://staging.example.com"
      export API_URL="https://staging.example.com/api"
      export DB_HOST="staging-db.example.com"
      export DB_PORT="5432"
      export DB_NAME="staging_db"
      ;;
    production)
      log_warning "Running E2E tests against PRODUCTION!"
      read -p "Are you sure? (yes/no): " confirm
      if [ "$confirm" != "yes" ]; then
        log_error "Aborted"
        exit 1
      fi
      export BASE_URL="https://example.com"
      export API_URL="https://example.com/api"
      # Production DB should be read-only for tests
      ;;
    *)
      log_error "Unknown environment: $ENVIRONMENT"
      exit 1
      ;;
  esac

  # Set browser mode
  if [ "$HEADED" = true ]; then
    export HEADLESS=false
    log_info "Running in HEADED mode (visible browser)"
  else
    export HEADLESS=true
    log_info "Running in HEADLESS mode"
  fi

  # Set CI-specific settings
  if [ "$CI_MODE" = true ]; then
    export CI=true
    export HEADLESS=true
    log_info "Running in CI mode"
  fi

  log_success "Environment setup complete"
}

# ============================================================================
# PRE-TEST CHECKS
# ============================================================================

check_dependencies() {
  log_info "Checking dependencies..."

  # Check Node.js
  if ! command -v node &> /dev/null; then
    log_error "Node.js is not installed"
    exit 1
  fi

  # Check npm packages
  if [ ! -d "node_modules" ]; then
    log_warning "node_modules not found, running npm install..."
    npm install
  fi

  # Check if puppeteer is installed
  if ! npm list puppeteer &> /dev/null; then
    log_error "Puppeteer is not installed. Run: npm install --save-dev puppeteer jest-puppeteer"
    exit 1
  fi

  log_success "Dependencies check passed"
}

check_services() {
  log_info "Checking required services..."

  if [ "$ENVIRONMENT" = "local" ]; then
    # Check if app is running
    if ! curl -sf "$BASE_URL/health" > /dev/null 2>&1; then
      log_error "Application is not running at $BASE_URL"
      log_info "Start the application with: npm start"
      exit 1
    fi

    # Check database connection
    if command -v psql &> /dev/null; then
      if ! PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1" > /dev/null 2>&1; then
        log_warning "Database connection check failed"
      fi
    fi
  fi

  log_success "Services check passed"
}

# ============================================================================
# TEST EXECUTION
# ============================================================================

run_tests() {
  log_info "Running E2E tests..."

  # Create directories for artifacts
  mkdir -p screenshots
  mkdir -p videos
  mkdir -p test-results

  # Build Jest command
  JEST_CMD="npx jest"

  # Add test pattern
  if [ -n "$PATTERN" ]; then
    JEST_CMD="$JEST_CMD --testNamePattern='$PATTERN'"
    log_info "Running tests matching pattern: $PATTERN"
  fi

  # Add configuration
  JEST_CMD="$JEST_CMD --config=jest-puppeteer.config.js"

  # Add test directory
  JEST_CMD="$JEST_CMD tests/e2e"

  # Add verbose flag
  if [ "$VERBOSE" = true ]; then
    JEST_CMD="$JEST_CMD --verbose"
  fi

  # Add CI flags
  if [ "$CI_MODE" = true ]; then
    JEST_CMD="$JEST_CMD --ci --coverage --maxWorkers=2"
  fi

  # Add JSON reporter for CI
  JEST_CMD="$JEST_CMD --json --outputFile=test-results/results.json"

  # Run tests
  echo ""
  echo "Command: $JEST_CMD"
  echo ""

  if [ "$DEBUG" = true ]; then
    export PWDEBUG=1
  fi

  if $JEST_CMD; then
    log_success "All tests passed!"
    return 0
  else
    log_error "Some tests failed"
    return 1
  fi
}

# ============================================================================
# POST-TEST CLEANUP
# ============================================================================

cleanup_artifacts() {
  if [ "$KEEP_ARTIFACTS" = false ]; then
    log_info "Cleaning up test artifacts..."

    # Keep screenshots only if tests failed
    if [ $1 -eq 0 ]; then
      rm -rf screenshots/*
      log_info "Removed screenshots (tests passed)"
    else
      log_warning "Keeping screenshots (tests failed)"
    fi

    # Clean up old videos
    find videos/ -type f -mtime +7 -delete 2>/dev/null || true
  else
    log_info "Keeping all artifacts (--keep-artifacts flag set)"
  fi
}

generate_report() {
  log_info "Generating test report..."

  if [ -f "test-results/results.json" ]; then
    # Parse JSON results
    TOTAL_TESTS=$(jq '.numTotalTests' test-results/results.json)
    PASSED_TESTS=$(jq '.numPassedTests' test-results/results.json)
    FAILED_TESTS=$(jq '.numFailedTests' test-results/results.json)
    DURATION=$(jq '.testResults[0].perfStats.runtime' test-results/results.json)

    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    Test Results                            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Total Tests:  $TOTAL_TESTS"
    echo -e "Passed:       ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed:       ${RED}$FAILED_TESTS${NC}"
    echo "Duration:     ${DURATION}ms"
    echo ""

    if [ "$FAILED_TESTS" -gt 0 ]; then
      echo -e "${RED}Failed Tests:${NC}"
      jq -r '.testResults[].testResults[] | select(.status == "failed") | "  - \(.ancestorTitles[0]) > \(.title)"' test-results/results.json
      echo ""
    fi
  fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
  print_header

  # Environment setup
  if [ "$SKIP_SETUP" = false ]; then
    setup_environment
  fi

  # Pre-test checks
  check_dependencies
  check_services

  # Run tests
  TEST_EXIT_CODE=0
  run_tests || TEST_EXIT_CODE=$?

  # Generate report
  generate_report

  # Cleanup
  cleanup_artifacts $TEST_EXIT_CODE

  # Exit with test status
  if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo ""
    log_success "E2E tests completed successfully"
    exit 0
  else
    echo ""
    log_error "E2E tests failed"
    exit 1
  fi
}

# Run main function
main
