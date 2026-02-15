#!/bin/bash
#
# Smoke Tests - Post-Deployment Validation
# =========================================
#
# Quick validation tests to verify critical functionality after deployment
#
# Usage:
#   ./smoke-tests.sh --target=https://api.example.com
#   ./smoke-tests.sh --target=staging.example.com --timeout=30
#
# Options:
#   --target      Target environment URL (required)
#   --timeout     Timeout per test in seconds (default: 10)
#   --critical    Run only critical tests
#   --verbose     Show detailed output
#

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

TARGET_URL=""
TIMEOUT=10
CRITICAL_ONLY=false
VERBOSE=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# ============================================================================
# PARSE ARGUMENTS
# ============================================================================

for arg in "$@"; do
  case $arg in
    --target=*)
      TARGET_URL="${arg#*=}"
      ;;
    --timeout=*)
      TIMEOUT="${arg#*=}"
      ;;
    --critical)
      CRITICAL_ONLY=true
      ;;
    --verbose)
      VERBOSE=true
      ;;
    *)
      echo "Unknown option: $arg"
      exit 1
      ;;
  esac
done

if [ -z "$TARGET_URL" ]; then
  echo "Error: --target is required"
  echo "Usage: $0 --target=https://api.example.com"
  exit 1
fi

# Ensure URL has protocol
if [[ ! $TARGET_URL =~ ^https?:// ]]; then
  TARGET_URL="https://$TARGET_URL"
fi

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

print_header() {
  echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║              Smoke Tests - Post-Deployment                 ║${NC}"
  echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "Target:  ${BLUE}$TARGET_URL${NC}"
  echo -e "Timeout: ${BLUE}${TIMEOUT}s${NC}"
  echo ""
}

run_test() {
  local test_name=$1
  local test_function=$2
  local is_critical=${3:-false}

  # Skip non-critical tests if --critical flag set
  if [ "$CRITICAL_ONLY" = true ] && [ "$is_critical" = false ]; then
    return 0
  fi

  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  echo -n "Testing: $test_name... "

  # Run test function
  if $test_function; then
    echo -e "${GREEN}✓ PASS${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    return 0
  else
    echo -e "${RED}✗ FAIL${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
    return 1
  fi
}

http_get() {
  local url=$1
  local expected_status=${2:-200}

  response=$(curl -s -w "\n%{http_code}" --max-time $TIMEOUT "$url" 2>&1)
  status_code=$(echo "$response" | tail -n 1)
  body=$(echo "$response" | sed '$d')

  if [ "$VERBOSE" = true ]; then
    echo ""
    echo "  URL: $url"
    echo "  Status: $status_code"
    echo "  Body: ${body:0:100}..."
  fi

  if [ "$status_code" = "$expected_status" ]; then
    return 0
  else
    echo "  Expected: $expected_status, Got: $status_code" >&2
    return 1
  fi
}

http_post() {
  local url=$1
  local data=$2
  local expected_status=${3:-200}

  response=$(curl -s -w "\n%{http_code}" --max-time $TIMEOUT \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$data" \
    "$url" 2>&1)

  status_code=$(echo "$response" | tail -n 1)

  if [ "$VERBOSE" = true ]; then
    echo ""
    echo "  URL: $url"
    echo "  Data: $data"
    echo "  Status: $status_code"
  fi

  [ "$status_code" = "$expected_status" ]
}

check_json_field() {
  local json=$1
  local field=$2
  local expected=$3

  if command -v jq &> /dev/null; then
    actual=$(echo "$json" | jq -r ".$field")
    [ "$actual" = "$expected" ]
  else
    # Fallback without jq
    echo "$json" | grep -q "\"$field\".*\"$expected\""
  fi
}

# ============================================================================
# SMOKE TESTS
# ============================================================================

test_health_endpoint() {
  http_get "$TARGET_URL/health" 200
}

test_health_response_format() {
  response=$(curl -s --max-time $TIMEOUT "$TARGET_URL/health")

  if command -v jq &> /dev/null; then
    echo "$response" | jq -e '.status == "healthy"' > /dev/null
  else
    echo "$response" | grep -q '"status".*"healthy"'
  fi
}

test_version_endpoint() {
  response=$(curl -s --max-time $TIMEOUT "$TARGET_URL/version")

  # Check that version field exists
  if command -v jq &> /dev/null; then
    echo "$response" | jq -e '.version' > /dev/null
  else
    echo "$response" | grep -q '"version"'
  fi
}

test_database_connection() {
  response=$(curl -s --max-time $TIMEOUT "$TARGET_URL/health/db")

  if command -v jq &> /dev/null; then
    echo "$response" | jq -e '.database == "connected"' > /dev/null
  else
    echo "$response" | grep -q '"database".*"connected"'
  fi
}

test_cache_connection() {
  response=$(curl -s --max-time $TIMEOUT "$TARGET_URL/health/cache")

  if command -v jq &> /dev/null; then
    echo "$response" | jq -e '.cache == "connected"' > /dev/null
  else
    echo "$response" | grep -q '"cache".*"connected"'
  fi
}

test_api_root() {
  http_get "$TARGET_URL/api" 200
}

test_authentication() {
  # Try to access protected endpoint without auth
  response=$(curl -s -w "\n%{http_code}" --max-time $TIMEOUT "$TARGET_URL/api/protected")
  status_code=$(echo "$response" | tail -n 1)

  # Should return 401 Unauthorized
  [ "$status_code" = "401" ]
}

test_cors_headers() {
  response=$(curl -s -I --max-time $TIMEOUT \
    -H "Origin: https://example.com" \
    -H "Access-Control-Request-Method: GET" \
    "$TARGET_URL/api")

  echo "$response" | grep -q "Access-Control-Allow-Origin"
}

test_rate_limiting() {
  # Make multiple requests quickly
  for i in {1..10}; do
    curl -s --max-time $TIMEOUT "$TARGET_URL/api" > /dev/null
  done

  # Next request should work (or be rate-limited gracefully)
  response=$(curl -s -w "\n%{http_code}" --max-time $TIMEOUT "$TARGET_URL/api")
  status_code=$(echo "$response" | tail -n 1)

  # Should be 200 or 429
  [ "$status_code" = "200" ] || [ "$status_code" = "429" ]
}

test_error_handling() {
  # Request non-existent resource
  response=$(curl -s -w "\n%{http_code}" --max-time $TIMEOUT "$TARGET_URL/api/nonexistent")
  status_code=$(echo "$response" | tail -n 1)

  # Should return 404
  [ "$status_code" = "404" ]
}

test_response_time() {
  # Measure response time
  time=$(curl -s -w "%{time_total}" --max-time $TIMEOUT -o /dev/null "$TARGET_URL/health")

  # Should respond in less than 2 seconds
  if command -v bc &> /dev/null; then
    (( $(echo "$time < 2.0" | bc -l) ))
  else
    # Fallback: just check it didn't timeout
    [ -n "$time" ]
  fi
}

test_ssl_certificate() {
  if [[ $TARGET_URL =~ ^https:// ]]; then
    curl -s --max-time $TIMEOUT "$TARGET_URL/health" > /dev/null 2>&1
  else
    # Skip if not HTTPS
    return 0
  fi
}

test_security_headers() {
  response=$(curl -s -I --max-time $TIMEOUT "$TARGET_URL/")

  # Check for security headers
  echo "$response" | grep -q "X-Content-Type-Options: nosniff" || return 1
  echo "$response" | grep -q "X-Frame-Options" || return 1
  return 0
}

test_content_type_headers() {
  response=$(curl -s -I --max-time $TIMEOUT "$TARGET_URL/api")

  echo "$response" | grep -q "Content-Type: application/json"
}

test_metrics_endpoint() {
  # Prometheus metrics endpoint
  http_get "$TARGET_URL/metrics" 200
}

test_readiness_probe() {
  http_get "$TARGET_URL/ready" 200
}

test_liveness_probe() {
  http_get "$TARGET_URL/live" 200
}

# ============================================================================
# RUN TESTS
# ============================================================================

print_header

echo -e "${BLUE}═══ Critical Tests ═══${NC}"
echo ""

run_test "Health endpoint" test_health_endpoint true
run_test "Health response format" test_health_response_format true
run_test "Database connection" test_database_connection true
run_test "API root accessible" test_api_root true
run_test "Response time < 2s" test_response_time true

echo ""
echo -e "${BLUE}═══ Functionality Tests ═══${NC}"
echo ""

run_test "Version endpoint" test_version_endpoint false
run_test "Cache connection" test_cache_connection false
run_test "Authentication" test_authentication false
run_test "Error handling (404)" test_error_handling false
run_test "Readiness probe" test_readiness_probe false
run_test "Liveness probe" test_liveness_probe false

echo ""
echo -e "${BLUE}═══ Security Tests ═══${NC}"
echo ""

run_test "SSL certificate" test_ssl_certificate false
run_test "CORS headers" test_cors_headers false
run_test "Security headers" test_security_headers false
run_test "Rate limiting" test_rate_limiting false

echo ""
echo -e "${BLUE}═══ Performance Tests ═══${NC}"
echo ""

run_test "Content-Type headers" test_content_type_headers false
run_test "Metrics endpoint" test_metrics_endpoint false

# ============================================================================
# SUMMARY
# ============================================================================

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Test Summary                            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Total Tests:  $TOTAL_TESTS"
echo -e "Passed:       ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed:       ${RED}$FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
  echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
  echo ""
  echo "Deployment appears healthy. Safe to proceed."
  exit 0
else
  echo -e "${RED}✗ $FAILED_TESTS TEST(S) FAILED${NC}"
  echo ""
  echo "⚠ Deployment may have issues. Investigate failures before proceeding."
  exit 1
fi
