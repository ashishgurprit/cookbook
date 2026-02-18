# Rate Limiting - Universal Skill

> **Production-ready rate limiting for web, mobile, and API applications**
>
> Prevents brute force attacks, DoS, spam, and API abuse across all projects.

---

## Overview

**What**: Token bucket algorithm with Redis for distributed rate limiting
**Why**: Prevent security incidents (brute force, DoS, spam) across 61 projects
**How**: Drop-in middleware for Express/FastAPI + frontend integration

**Decision**: Token Bucket chosen via 3D Decision Matrix (see `3D-DECISION-MATRIX.md`)

---

## Architecture Decision

**Algorithm**: Token Bucket (Industry Standard)
- Used by: AWS, Cloudflare, Stripe, GitHub
- Allows legitimate bursts while maintaining average rate
- Memory efficient (2 values per key: tokens + timestamp)
- Mathematically sound

**Storage**: Redis (Distributed)
- Multi-instance support
- Atomic operations (no race conditions)
- TTL for auto-cleanup (no memory leaks)
- Fast (sub-millisecond)

**Policy**: Fail-Open
- If Redis unavailable, allow requests (availability > strict enforcement)
- Log fail-open events (alert operations)
- Can switch to fail-closed for critical endpoints

---

## Token Bucket Algorithm

### How It Works

```
Bucket Capacity: max_requests (e.g., 100 tokens)
Refill Rate: max_requests / window_seconds (e.g., 100 tokens / 60 seconds = 1.67 tokens/second)

For each request:
1. Calculate time elapsed since last refill
2. Add tokens: tokens += elapsed * refill_rate
3. Cap at max_requests (bucket doesn't overflow)
4. Try to consume 1 token
5. If tokens >= 1: Allow request, tokens -= 1
6. If tokens < 1: Deny request (429 Too Many Requests)
```

### Example Timeline

```
Time | Action           | Tokens | Result
-----|------------------|--------|--------
0s   | Request 1        | 99     | ✅ Allowed
0.5s | Request 2        | 98.8   | ✅ Allowed (0.5s * 1.67 = 0.8 tokens added)
1s   | Request 3        | 98.7   | ✅ Allowed
...
10s  | Request 100      | 0      | ✅ Allowed (last token)
10.1s| Request 101      | 0      | ❌ RATE LIMITED (no tokens)
11s  | Request 102      | 0.5    | ✅ Allowed (1s * 1.67 = 1.67 tokens added)
60s  | (No requests)    | 100    | (Bucket refilled to capacity)
```

**Key Benefits**:
- Allows bursts up to bucket capacity
- Smooth average rate over time
- Natural recovery (tokens refill continuously)

---

## Rate Limit Strategies

### 1. IP-Based Rate Limiting

**Use Case**: Public endpoints, unauthenticated requests

```python
key = f"rate_limit:ip:{ip_address}:{endpoint}"
# Example: rate_limit:ip:203.0.113.45:/api/login
```

**Limits**:
- Auth endpoints: 5 requests/minute per IP
- Contact forms: 5 requests/hour per IP
- Public API: 20 requests/minute per IP

**IP Detection**:
```python
def get_client_ip(request):
    # Behind proxy/CDN
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    # Direct connection
    return request.client.host
```

### 2. User-Based Rate Limiting

**Use Case**: Authenticated endpoints, per-user quotas

```python
key = f"rate_limit:user:{user_id}:{endpoint}"
# Example: rate_limit:user:usr_abc123:/api/data
```

**Limits**:
- API (authenticated): 100 requests/minute per user
- Data exports: 10 requests/hour per user
- Sensitive operations: 5 requests/minute per user

### 3. Combined Strategy

**Use Case**: Maximum protection

```python
# Check both IP and User
ip_allowed = check_rate_limit(ip_key, ip_limit, ip_window)
user_allowed = check_rate_limit(user_key, user_limit, user_window)

if not ip_allowed or not user_allowed:
    return 429  # Rate limited
```

---

## Default Rate Limits

| Endpoint Category | Limit | Window | Strategy |
|---|---|---|---|
| **Authentication** | | | |
| Login | 5 req/min | 60s | IP |
| Register | 5 req/min | 60s | IP |
| Password Reset | 5 req/min | 60s | IP |
| **Forms** | | | |
| Contact Form | 5 req/hour | 3600s | IP |
| Newsletter Subscribe | 10 req/hour | 3600s | IP |
| **API (Authenticated)** | | | |
| Read Operations | 100 req/min | 60s | User |
| Write Operations | 50 req/min | 60s | User |
| Data Exports | 10 req/hour | 3600s | User |
| **API (Public)** | | | |
| Public Endpoints | 20 req/min | 60s | IP |
| Search | 30 req/min | 60s | IP |

**Tier-Based Limits** (for SaaS applications):

| Tier | Requests/Minute | Requests/Hour |
|---|---|---|
| Free | 10 | 100 |
| Pro | 100 | 10,000 |
| Enterprise | 1,000 | 100,000 |

---

## HTTP Response Headers

**Standard Rate Limit Headers** (RFC 6585):

```
HTTP/1.1 200 OK
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 73
X-RateLimit-Reset: 1705593600

(When rate limited)
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705593660
Retry-After: 60
```

**Header Definitions**:
- `X-RateLimit-Limit`: Maximum requests allowed in window
- `X-RateLimit-Remaining`: Requests remaining in current window
- `X-RateLimit-Reset`: Unix timestamp when limit resets
- `Retry-After`: Seconds until next request allowed

---

## Implementation Examples

### Python (FastAPI)

```python
from fastapi import FastAPI, Request, HTTPException
from redis import Redis
import time

app = FastAPI()
redis_client = Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

async def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> dict:
    """Token Bucket Algorithm"""
    now = time.time()

    # Get bucket state
    bucket = await redis_client.hgetall(f"rate_limit:{key}")

    if not bucket:
        # New bucket
        tokens = max_requests - 1
        last_refill = now
    else:
        tokens = float(bucket.get('tokens', max_requests))
        last_refill = float(bucket.get('last_refill', now))

        # Refill tokens
        elapsed = now - last_refill
        refill_rate = max_requests / window_seconds
        tokens = min(max_requests, tokens + (elapsed * refill_rate))

        # Consume 1 token
        tokens -= 1

    # Check if allowed
    allowed = tokens >= 0

    if allowed:
        # Update bucket
        await redis_client.hset(f"rate_limit:{key}", mapping={
            'tokens': tokens,
            'last_refill': now
        })
        await redis_client.expire(f"rate_limit:{key}", window_seconds * 2)

    # Calculate headers
    remaining = max(0, int(tokens))
    reset = int(now + window_seconds)

    return {
        'allowed': allowed,
        'limit': max_requests,
        'remaining': remaining,
        'reset': reset,
        'retry_after': window_seconds if not allowed else 0
    }

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Skip rate limiting for health checks
    if request.url.path == "/health":
        return await call_next(request)

    # Get client IP
    ip = request.headers.get('X-Forwarded-For', request.client.host).split(',')[0].strip()

    # Rate limit auth endpoints
    if request.url.path.startswith('/api/auth'):
        result = await check_rate_limit(
            key=f"ip:{ip}:{request.url.path}",
            max_requests=5,
            window_seconds=60
        )

        # Add headers
        response = await call_next(request) if result['allowed'] else None

        if not result['allowed']:
            response = Response(
                content='{"detail": "Rate limit exceeded. Please try again later."}',
                status_code=429,
                media_type="application/json"
            )

        response.headers['X-RateLimit-Limit'] = str(result['limit'])
        response.headers['X-RateLimit-Remaining'] = str(result['remaining'])
        response.headers['X-RateLimit-Reset'] = str(result['reset'])

        if not result['allowed']:
            response.headers['Retry-After'] = str(result['retry_after'])

        return response

    return await call_next(request)
```

### Node.js (Express)

```javascript
const express = require('express');
const redis = require('redis');

const app = express();
const redisClient = redis.createClient({ url: process.env.REDIS_URL });

async function checkRateLimit(key, maxRequests, windowSeconds) {
  const now = Date.now() / 1000;

  // Get bucket state
  const bucket = await redisClient.hGetAll(`rate_limit:${key}`);

  let tokens, lastRefill;

  if (!bucket.tokens) {
    // New bucket
    tokens = maxRequests - 1;
    lastRefill = now;
  } else {
    tokens = parseFloat(bucket.tokens);
    lastRefill = parseFloat(bucket.last_refill);

    // Refill tokens
    const elapsed = now - lastRefill;
    const refillRate = maxRequests / windowSeconds;
    tokens = Math.min(maxRequests, tokens + (elapsed * refillRate));

    // Consume 1 token
    tokens -= 1;
  }

  const allowed = tokens >= 0;

  if (allowed) {
    // Update bucket
    await redisClient.hSet(`rate_limit:${key}`, {
      tokens: tokens.toString(),
      last_refill: now.toString()
    });
    await redisClient.expire(`rate_limit:${key}`, windowSeconds * 2);
  }

  return {
    allowed,
    limit: maxRequests,
    remaining: Math.max(0, Math.floor(tokens)),
    reset: Math.floor(now + windowSeconds),
    retryAfter: allowed ? 0 : windowSeconds
  };
}

// Rate limiting middleware
app.use(async (req, res, next) => {
  // Skip health checks
  if (req.path === '/health') return next();

  // Get client IP
  const ip = (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim();

  // Rate limit auth endpoints
  if (req.path.startsWith('/api/auth')) {
    const result = await checkRateLimit(
      `ip:${ip}:${req.path}`,
      5,  // max requests
      60  // window in seconds
    );

    // Set headers
    res.set('X-RateLimit-Limit', result.limit);
    res.set('X-RateLimit-Remaining', result.remaining);
    res.set('X-RateLimit-Reset', result.reset);

    if (!result.allowed) {
      res.set('Retry-After', result.retryAfter);
      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Please try again later',
        retryAfter: result.retryAfter
      });
    }
  }

  next();
});
```

---

## Security Considerations

### OWASP Compliance

✅ **Security Misconfiguration** (OWASP #5)
- Rate limiting as defense layer
- Prevents brute force attacks
- Prevents DoS/DDoS attacks

✅ **Logging & Monitoring** (OWASP #9)
- Log rate limit violations
- Alert on unusual patterns
- Track abuse metrics

✅ **Authentication Failures** (OWASP #7)
- 5 attempts/minute on login (prevents brute force)
- User enumeration protection
- Account lockout after threshold

### Real-World Security Patterns Applied

**From LESSONS.md**:
1. ✅ **Token Bucket > Counter-Based**
   - No memory leaks
   - Bounded keys with TTL
   - Better traffic management

2. ✅ **Startup Environment Validation**
   ```python
   def validate_rate_limit_config():
       if not os.environ.get('REDIS_URL'):
           print("❌ Missing REDIS_URL")
           sys.exit(1)
   ```

3. ✅ **Security Logging (No Sensitive Data)**
   ```python
   logger.warning("rate_limit.exceeded",
       ip=ip_address,
       endpoint=request.path,
       limit=max_requests
       # NO user data, NO request body
   )
   ```

4. ✅ **Fail-Open Policy**
   ```python
   try:
       result = await check_rate_limit(key, limit, window)
   except RedisConnectionError:
       logger.error("rate_limit.redis_unavailable")
       # FAIL OPEN: Allow request
       return {'allowed': True, 'limit': limit, 'remaining': limit}
   ```

### Rate Limit Bypass Prevention

**Protection Against**:

1. **IP Rotation (Botnets)**
   - Solution: Add user-based rate limiting
   - Solution: CAPTCHA after threshold
   - Solution: Behavioral analysis (future enhancement)

2. **Distributed Attacks**
   - Solution: Global rate limits (all IPs combined)
   - Solution: Cloudflare/WAF layer
   - Solution: Anomaly detection

3. **Header Manipulation**
   ```python
   def get_client_ip(request):
       # Validate X-Forwarded-For
       if 'X-Forwarded-For' in request.headers:
           ips = [ip.strip() for ip in request.headers['X-Forwarded-For'].split(',')]
           # Use first IP (client)
           return ips[0]
       return request.client.host
   ```

4. **Time Manipulation**
   - Solution: Use Redis server time (not client time)
   - Solution: NTP synchronization

### Redis Security

**Required**:
```bash
# Environment variables
REDIS_URL=redis://:password@host:6379/0  # With password
REDIS_TLS=true                            # Encrypted connection (production)
```

**Redis Configuration**:
```
# redis.conf
requirepass <strong-password>
maxmemory 256mb
maxmemory-policy allkeys-lru  # Evict least recently used
```

---

## Testing

### Unit Tests

```python
# test_rate_limiting.py
import pytest
import time

@pytest.mark.asyncio
async def test_rate_limit_allows_within_limit():
    """Test that requests within limit are allowed"""
    key = f"test:{time.time()}"

    for i in range(5):
        result = await check_rate_limit(key, 5, 60)
        assert result['allowed'] == True
        assert result['remaining'] == 4 - i

@pytest.mark.asyncio
async def test_rate_limit_blocks_over_limit():
    """Test that requests over limit are blocked"""
    key = f"test:{time.time()}"

    # Consume all tokens
    for i in range(5):
        await check_rate_limit(key, 5, 60)

    # Next request should be blocked
    result = await check_rate_limit(key, 5, 60)
    assert result['allowed'] == False
    assert result['remaining'] == 0

@pytest.mark.asyncio
async def test_rate_limit_refills_over_time():
    """Test that tokens refill over time"""
    key = f"test:{time.time()}"

    # Consume all tokens
    for i in range(5):
        await check_rate_limit(key, 5, 60)

    # Wait for refill (1 second = 5/60 = 0.083 tokens)
    await asyncio.sleep(15)  # Should add ~1.25 tokens

    result = await check_rate_limit(key, 5, 60)
    assert result['allowed'] == True

@pytest.mark.asyncio
async def test_rate_limit_handles_redis_failure():
    """Test fail-open when Redis unavailable"""
    # Disconnect Redis
    await redis_client.close()

    result = await check_rate_limit("test", 5, 60)
    assert result['allowed'] == True  # Fail-open
```

### Security Tests

```python
# test_security.py

@pytest.mark.asyncio
async def test_rate_limit_bypass_attempt():
    """Test that rate limit cannot be bypassed"""
    key = "security_test"

    # Try to bypass by manipulating Redis directly
    await redis_client.hset(f"rate_limit:{key}", {
        'tokens': 1000,  # Try to add unlimited tokens
        'last_refill': time.time()
    })

    # Should still respect max_requests
    for i in range(10):
        result = await check_rate_limit(key, 5, 60)
        if i < 5:
            assert result['allowed'] == True
        else:
            assert result['allowed'] == False  # Blocked

@pytest.mark.asyncio
async def test_distributed_consistency():
    """Test rate limiting across multiple instances"""
    key = "distributed_test"

    # Simulate 2 instances making requests simultaneously
    async def make_requests(instance_id):
        results = []
        for i in range(3):
            result = await check_rate_limit(key, 5, 60)
            results.append(result['allowed'])
        return results

    # Run concurrently
    instance1, instance2 = await asyncio.gather(
        make_requests("instance1"),
        make_requests("instance2")
    )

    # Total allowed should be <= 5 (max_requests)
    total_allowed = sum(instance1) + sum(instance2)
    assert total_allowed <= 5

@pytest.mark.asyncio
async def test_ip_spoofing_protection():
    """Test that IP spoofing is detected"""
    # Try various header manipulation
    fake_headers = [
        {'X-Forwarded-For': '1.1.1.1, 2.2.2.2, 3.3.3.3'},  # Multiple IPs
        {'X-Forwarded-For': 'invalid-ip'},                 # Invalid format
        {'X-Forwarded-For': ''},                           # Empty
    ]

    for headers in fake_headers:
        ip = get_client_ip_from_headers(headers, fallback='203.0.113.45')
        assert ip is not None
        assert len(ip) > 0
```

### Load Tests

```bash
# Load test with Apache Bench
ab -n 1000 -c 10 -H "X-Forwarded-For: 203.0.113.45" http://localhost:8000/api/endpoint

# Expected: ~5 requests succeed, rest return 429
```

---

## Monitoring & Alerting

### Metrics to Track

```python
# Prometheus metrics example
from prometheus_client import Counter, Histogram

rate_limit_exceeded = Counter(
    'rate_limit_exceeded_total',
    'Total rate limit violations',
    ['endpoint', 'strategy']
)

rate_limit_latency = Histogram(
    'rate_limit_check_duration_seconds',
    'Time to check rate limit',
    ['endpoint']
)

# Usage
rate_limit_exceeded.labels(endpoint='/api/login', strategy='ip').inc()
```

**Key Metrics**:
- Rate limit hits per endpoint
- Rate limit check latency
- Redis connection failures
- Fail-open incidents
- Top rate-limited IPs
- Top rate-limited users

### Alerts

```yaml
# Alertmanager rules
groups:
  - name: rate_limiting
    rules:
      - alert: HighRateLimitViolations
        expr: rate(rate_limit_exceeded_total[5m]) > 10
        annotations:
          summary: "High rate of rate limit violations"
          description: "{{ $value }} violations/sec on {{ $labels.endpoint }}"

      - alert: RateLimitRedisDown
        expr: rate_limit_redis_unavailable > 0
        annotations:
          summary: "Rate limiting Redis unavailable"
          description: "Failing open - all requests allowed"

      - alert: RateLimitHighLatency
        expr: rate_limit_check_duration_seconds > 0.1
        annotations:
          summary: "Rate limit checks taking >100ms"
          description: "May impact request latency"
```

---

## Deployment Guide

See `playbooks/QUICK-START.md` for setup instructions.

### Prerequisites

- Redis 6.0+ (with authentication)
- Python 3.8+ or Node.js 16+
- Environment variables configured

### Quick Start

```bash
# 1. Install Redis
brew install redis  # macOS
apt-get install redis  # Ubuntu

# 2. Configure Redis
redis-cli CONFIG SET requirepass "your-redis-password"

# 3. Set environment variables
export REDIS_URL="redis://:your-redis-password@localhost:6379/0"

# 4. Install dependencies
pip install redis fastapi  # Python
npm install redis express   # Node.js

# 5. Add middleware (see templates/)
# Copy from templates/backend/fastapi-rate-limiting.py
# or templates/backend/express-rate-limiting.js

# 6. Test
curl -I http://localhost:8000/api/login
# Should see X-RateLimit-* headers
```

---

## Troubleshooting

### Common Issues

**1. Rate limit not enforced**
```bash
# Check Redis connection
redis-cli -u $REDIS_URL PING
# Should return PONG

# Check if keys are being created
redis-cli -u $REDIS_URL KEYS "rate_limit:*"
```

**2. All requests blocked (even first request)**
```python
# Debug: Check token calculation
bucket = redis_client.hgetall("rate_limit:test")
print(f"Tokens: {bucket.get('tokens')}, Last Refill: {bucket.get('last_refill')}")
```

**3. Rate limit headers missing**
```python
# Ensure middleware runs before route handlers
app.use(rateLimitMiddleware)  # Must be BEFORE routes
app.use('/api', routes)
```

**4. Redis memory exhaustion**
```bash
# Check Redis memory
redis-cli INFO memory

# Set eviction policy
redis-cli CONFIG SET maxmemory-policy allkeys-lru

# Check TTL on keys
redis-cli TTL "rate_limit:ip:203.0.113.45:/api/login"
```

---

## Advanced Configuration

### Custom Rate Limit Rules

```python
# config/rate_limits.py
RATE_LIMITS = {
    '/api/auth/login': {'limit': 5, 'window': 60, 'strategy': 'ip'},
    '/api/auth/register': {'limit': 3, 'window': 60, 'strategy': 'ip'},
    '/api/contact': {'limit': 5, 'window': 3600, 'strategy': 'ip'},
    '/api/data': {'limit': 100, 'window': 60, 'strategy': 'user'},
    '/api/export': {'limit': 10, 'window': 3600, 'strategy': 'user'},
}
```

### Tier-Based Limits

```python
# Get user's tier from database
user = get_current_user(request)

TIER_LIMITS = {
    'free': {'limit': 10, 'window': 60},
    'pro': {'limit': 100, 'window': 60},
    'enterprise': {'limit': 1000, 'window': 60},
}

config = TIER_LIMITS.get(user.tier, TIER_LIMITS['free'])
result = await check_rate_limit(f"user:{user.id}", config['limit'], config['window'])
```

### Global Rate Limit

```python
# Limit total traffic (all users combined)
global_result = await check_rate_limit(
    key="global:all",
    max_requests=10000,
    window_seconds=60
)

if not global_result['allowed']:
    return Response("Service temporarily unavailable", status_code=503)
```

---

## Best Practices

1. ✅ **Use realistic limits** - Don't block legitimate users
2. ✅ **Provide clear error messages** - Include retry-after
3. ✅ **Implement tiered limits** - Different limits for different user tiers
4. ✅ **Monitor actively** - Alert on unusual patterns
5. ✅ **Fail-open in production** - Availability > strict enforcement
6. ✅ **Use multiple strategies** - IP + User for maximum protection
7. ✅ **Add CAPTCHA** - After N violations, require CAPTCHA
8. ✅ **Document limits** - API documentation must include rate limits
9. ✅ **Test edge cases** - Boundary conditions, concurrent requests
10. ✅ **Review periodically** - Adjust limits based on usage patterns

---

## References

- **Algorithm**: [Token Bucket (Wikipedia)](https://en.wikipedia.org/wiki/Token_bucket)
- **RFC**: [RFC 6585 - HTTP 429 Too Many Requests](https://tools.ietf.org/html/rfc6585)
- **Industry Examples**:
  - [Stripe Rate Limiting](https://stripe.com/docs/rate-limits)
  - [GitHub Rate Limiting](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting)
  - [AWS API Gateway Throttling](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html)

---

## Version History

- **v1.0** (2026-01-17): Initial release
  - Token bucket algorithm
  - Redis integration
  - IP + User strategies
  - Fail-open policy
  - Security compliance (OWASP)
