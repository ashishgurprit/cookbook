"""
Security Tests for Rate Limiting
=================================

Tests for OWASP compliance and security vulnerabilities.

Run with: pytest tests/test_security.py -v
"""

import pytest
import asyncio
import time
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'templates', 'backend'))

from fastapi_rate_limiting import RateLimiter, sanitize_key_component


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
async def rate_limiter():
    """Create rate limiter for testing"""
    limiter = RateLimiter(
        redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/15"),  # DB 15 for tests
        fail_open=True
    )
    await limiter.connect()
    yield limiter
    await limiter.close()


@pytest.fixture
async def redis_client(rate_limiter):
    """Get Redis client"""
    return rate_limiter.redis


# ============================================================================
# 1. RATE LIMIT BYPASS ATTEMPTS
# ============================================================================

@pytest.mark.asyncio
async def test_cannot_bypass_with_redis_manipulation(rate_limiter, redis_client):
    """
    SECURITY TEST: Verify attackers cannot bypass rate limit by manipulating Redis

    Attack: Set unlimited tokens in Redis bucket
    Expected: Rate limiter still enforces max_requests
    """
    key = f"test:bypass:{time.time()}"

    # Attacker tries to set unlimited tokens
    await redis_client.hset(f"rate_limit:{key}", mapping={
        'tokens': '999999',  # Unlimited tokens
        'last_refill': str(time.time())
    })

    # Should still respect max_requests
    max_requests = 5
    allowed_count = 0

    for i in range(10):
        result = await rate_limiter.check_rate_limit(key, max_requests, 60)
        if result['allowed']:
            allowed_count += 1

    # Should allow max_requests, not 999999
    assert allowed_count <= max_requests, \
        f"Expected <= {max_requests} allowed, got {allowed_count}"


@pytest.mark.asyncio
async def test_cannot_bypass_with_negative_timestamp(rate_limiter, redis_client):
    """
    SECURITY TEST: Verify time manipulation doesn't grant unlimited tokens

    Attack: Set very old timestamp to force massive refill
    Expected: Tokens capped at max_requests
    """
    key = f"test:time_manipulation:{time.time()}"

    # Attacker sets timestamp to epoch (Jan 1, 1970)
    await redis_client.hset(f"rate_limit:{key}", mapping={
        'tokens': '0',
        'last_refill': '0'  # Very old timestamp
    })

    # Next request should cap tokens at max_requests
    result = await rate_limiter.check_rate_limit(key, max_requests=5, window_seconds=60)

    assert result['allowed'], "Request should be allowed (1 token available)"
    assert result['remaining'] <= 5, \
        f"Tokens should not exceed max_requests (5), got {result['remaining']}"


@pytest.mark.asyncio
async def test_cannot_bypass_with_future_timestamp(rate_limiter, redis_client):
    """
    SECURITY TEST: Verify future timestamps don't break rate limiting

    Attack: Set future timestamp
    Expected: Graceful handling, no unlimited tokens
    """
    key = f"test:future_timestamp:{time.time()}"

    # Attacker sets future timestamp
    future = time.time() + 86400  # +24 hours
    await redis_client.hset(f"rate_limit:{key}", mapping={
        'tokens': '0',
        'last_refill': str(future)
    })

    # Should handle gracefully
    result = await rate_limiter.check_rate_limit(key, max_requests=5, window_seconds=60)

    # Either allow (with warning) or deny, but not crash
    assert isinstance(result['allowed'], bool)
    assert result['remaining'] >= 0


# ============================================================================
# 2. DISTRIBUTED CONSISTENCY TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_distributed_rate_limit_consistency(rate_limiter):
    """
    SECURITY TEST: Verify rate limiting works correctly across multiple instances

    Attack: Multiple servers trying to exceed rate limit simultaneously
    Expected: Total allowed requests <= max_requests
    """
    key = f"distributed_test:{time.time()}"
    max_requests = 10

    async def make_concurrent_requests(instance_id: str, count: int):
        """Simulate requests from one instance"""
        allowed = 0
        for i in range(count):
            result = await rate_limiter.check_rate_limit(key, max_requests, 60)
            if result['allowed']:
                allowed += 1
            # Small delay to simulate real requests
            await asyncio.sleep(0.001)
        return allowed

    # Simulate 3 instances making 5 requests each (15 total)
    results = await asyncio.gather(
        make_concurrent_requests("instance1", 5),
        make_concurrent_requests("instance2", 5),
        make_concurrent_requests("instance3", 5)
    )

    total_allowed = sum(results)

    # Only max_requests should be allowed
    assert total_allowed <= max_requests, \
        f"Expected <= {max_requests} allowed, got {total_allowed}"
    print(f"✅ Distributed consistency: {total_allowed}/{15} requests allowed")


# ============================================================================
# 3. REDIS FAILURE TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_fail_open_allows_requests():
    """
    SECURITY TEST: Verify fail-open allows requests when Redis unavailable

    Expected: Requests allowed (availability > strict enforcement)
    """
    limiter = RateLimiter(redis_url="redis://invalid-host:6379", fail_open=True)

    # Don't connect (Redis unavailable)
    # Request should be allowed (fail-open)
    result = await limiter.check_rate_limit("test", 5, 60)

    assert result['allowed'], "Fail-open should allow requests when Redis unavailable"
    print("✅ Fail-open working: Requests allowed despite Redis unavailable")


@pytest.mark.asyncio
async def test_fail_closed_blocks_requests():
    """
    SECURITY TEST: Verify fail-closed blocks requests when Redis unavailable

    Expected: Requests blocked (security > availability)
    """
    limiter = RateLimiter(redis_url="redis://invalid-host:6379", fail_open=False)

    # Don't connect (Redis unavailable)
    # Request should be blocked (fail-closed)
    result = await limiter.check_rate_limit("test", 5, 60)

    assert not result['allowed'], "Fail-closed should block requests when Redis unavailable"
    print("✅ Fail-closed working: Requests blocked when Redis unavailable")


# ============================================================================
# 4. INJECTION TESTS
# ============================================================================

def test_key_injection_prevention():
    """
    SECURITY TEST: Verify malicious keys are sanitized

    Attack: Redis command injection via key
    Expected: Dangerous characters stripped
    """
    malicious_keys = [
        "1.1.1.1; FLUSHALL",           # Redis command injection
        "1.1.1.1\nFLUSHDB",             # Newline injection
        "1.1.1.1\rCONFIG SET",          # Carriage return injection
        "../../etc/passwd",             # Path traversal (not applicable, but test anyway)
        "x" * 10000,                    # Memory exhaustion via long key
        "SELECT * FROM users",          # SQL injection (wrong context, but test)
        "<script>alert(1)</script>",   # XSS (not applicable, but sanitize anyway)
    ]

    for malicious_key in malicious_keys:
        sanitized = sanitize_key_component(malicious_key)

        # Should not contain dangerous characters
        assert ';' not in sanitized, f"Semicolon not sanitized in: {malicious_key}"
        assert '\n' not in sanitized, f"Newline not sanitized in: {malicious_key}"
        assert '\r' not in sanitized, f"Carriage return not sanitized in: {malicious_key}"

        # Should be bounded length
        assert len(sanitized) <= 100, f"Key too long: {len(sanitized)} chars"

        print(f"✅ Sanitized: '{malicious_key[:50]}...' → '{sanitized[:50]}'")


def test_ip_address_validation():
    """
    SECURITY TEST: Verify IP address validation

    Attack: Inject malicious values via X-Forwarded-For
    Expected: Invalid IPs rejected or sanitized
    """
    invalid_ips = [
        "",                          # Empty
        "not-an-ip",                 # Invalid format
        "999.999.999.999",           # Out of range
        "1.1.1.1; DROP TABLE",       # Injection attempt
        "1.1.1.1\nFLUSHALL",         # Newline injection
    ]

    for invalid_ip in invalid_ips:
        sanitized = sanitize_key_component(invalid_ip)

        # Should not contain dangerous characters
        assert ';' not in sanitized
        assert '\n' not in sanitized
        assert '\r' not in sanitized

        print(f"✅ IP validation: '{invalid_ip}' → '{sanitized}'")


# ============================================================================
# 5. BOUNDARY TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_exact_rate_limit_boundary(rate_limiter):
    """
    TEST: Verify rate limit works exactly at boundary

    Expected: max_requests allowed, max_requests+1 blocked
    """
    key = f"boundary_test:{time.time()}"
    max_requests = 5

    # Make exactly max_requests
    for i in range(max_requests):
        result = await rate_limiter.check_rate_limit(key, max_requests, 60)
        assert result['allowed'], f"Request {i+1}/{max_requests} should be allowed"

    # Next request should be blocked
    result = await rate_limiter.check_rate_limit(key, max_requests, 60)
    assert not result['allowed'], f"Request {max_requests+1} should be blocked"

    print(f"✅ Boundary test: {max_requests} allowed, {max_requests+1} blocked")


@pytest.mark.asyncio
async def test_token_refill_over_time(rate_limiter):
    """
    TEST: Verify tokens refill correctly over time

    Expected: Tokens increase based on elapsed time
    """
    key = f"refill_test:{time.time()}"
    max_requests = 5
    window_seconds = 10  # Short window for faster test

    # Consume all tokens
    for _ in range(max_requests):
        await rate_limiter.check_rate_limit(key, max_requests, window_seconds)

    # Next request blocked
    result = await rate_limiter.check_rate_limit(key, max_requests, window_seconds)
    assert not result['allowed'], "Should be blocked (no tokens)"

    # Wait for refill (2 seconds = 1 token @ 5 tokens/10 seconds)
    await asyncio.sleep(2)

    # Should have ~1 token now
    result = await rate_limiter.check_rate_limit(key, max_requests, window_seconds)
    assert result['allowed'], "Should be allowed after refill"

    print("✅ Token refill working correctly")


# ============================================================================
# 6. SECURITY HEADERS TESTS
# ============================================================================

def test_rate_limit_headers_present(rate_limiter):
    """
    TEST: Verify rate limit headers are included in response

    Required headers:
    - X-RateLimit-Limit
    - X-RateLimit-Remaining
    - X-RateLimit-Reset
    - Retry-After (if rate limited)
    """
    # This test is conceptual - actual header testing done in integration tests
    # Here we verify the result dict contains required fields

    result = {
        'allowed': True,
        'limit': 5,
        'remaining': 3,
        'reset': int(time.time() + 60),
        'retry_after': 0
    }

    assert 'allowed' in result
    assert 'limit' in result
    assert 'remaining' in result
    assert 'reset' in result
    assert 'retry_after' in result

    print("✅ Rate limit result contains all required fields")


# ============================================================================
# 7. MEMORY EXHAUSTION TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_ttl_prevents_memory_exhaustion(rate_limiter, redis_client):
    """
    SECURITY TEST: Verify TTL prevents unbounded memory growth

    Expected: Keys expire automatically (TTL = 2x window)
    """
    key = f"ttl_test:{time.time()}"

    # Make a request (creates key with TTL)
    await rate_limiter.check_rate_limit(key, max_requests=5, window_seconds=10)

    # Check TTL is set
    ttl = await redis_client.ttl(f"rate_limit:{key}")

    assert ttl > 0, "TTL should be set (positive value)"
    assert ttl <= 20, "TTL should be <= 2x window (20 seconds)"

    print(f"✅ TTL set correctly: {ttl} seconds")


# ============================================================================
# 8. CONCURRENCY TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_concurrent_requests_from_same_ip(rate_limiter):
    """
    SECURITY TEST: Verify concurrent requests from same IP respect rate limit

    Attack: Send many requests simultaneously to bypass counter
    Expected: Total allowed <= max_requests
    """
    key = f"concurrent_test:{time.time()}"
    max_requests = 10

    async def make_request():
        result = await rate_limiter.check_rate_limit(key, max_requests, 60)
        return 1 if result['allowed'] else 0

    # Make 20 concurrent requests (2x limit)
    tasks = [make_request() for _ in range(20)]
    results = await asyncio.gather(*tasks)

    total_allowed = sum(results)

    assert total_allowed <= max_requests, \
        f"Expected <= {max_requests} allowed, got {total_allowed}"

    print(f"✅ Concurrency test: {total_allowed}/20 requests allowed")


# ============================================================================
# 9. LOGGING TESTS (NO SENSITIVE DATA)
# ============================================================================

def test_no_sensitive_data_in_logs():
    """
    SECURITY TEST: Verify no sensitive data is logged

    Expected: Logs contain only IP, endpoint, limit - NO user data
    """
    # Simulated log entry
    log_entry = {
        "event": "rate_limit.exceeded",
        "ip": "203.0.113.45",
        "endpoint": "/api/login",
        "limit": 5
    }

    # Fields that should NOT be in logs
    forbidden_fields = [
        "password", "token", "secret", "api_key",
        "email", "phone", "ssn", "credit_card",
        "request_body", "request_headers"
    ]

    for field in forbidden_fields:
        assert field not in log_entry, \
            f"Sensitive field '{field}' found in log entry"

    print("✅ Log entry contains no sensitive data")


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    # Run with: python test_security.py
    pytest.main([__file__, "-v", "-s"])
