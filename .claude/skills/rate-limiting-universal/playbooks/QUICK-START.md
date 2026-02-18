# Rate Limiting - Quick Start Guide

> Get rate limiting running in your project in 15 minutes

---

## Prerequisites

- Redis 6.0+ (with authentication)
- Python 3.8+ or Node.js 16+
- Running application (FastAPI, Express, etc.)

---

## Step 1: Install Redis (5 minutes)

### macOS

```bash
brew install redis
brew services start redis
```

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install redis-server
sudo systemctl start redis
sudo systemctl enable redis
```

### Docker

```bash
docker run -d \
  --name redis \
  -p 6379:6379 \
  redis:7-alpine \
  redis-server --requirepass your-redis-password
```

### Configure Redis

```bash
# Set password
redis-cli CONFIG SET requirepass "your-redis-password"

# Set memory limit
redis-cli CONFIG SET maxmemory 256mb

# Set eviction policy (remove least recently used when full)
redis-cli CONFIG SET maxmemory-policy allkeys-lru

# Test connection
redis-cli -a "your-redis-password" PING
# Should return: PONG
```

---

## Step 2: Environment Variables (2 minutes)

Create or update `.env`:

```bash
# Redis connection
REDIS_URL=redis://:your-redis-password@localhost:6379/0

# Alternative: Redis without password (development only!)
# REDIS_URL=redis://localhost:6379/0
```

**Production (with TLS)**:
```bash
REDIS_URL=rediss://:your-redis-password@production-redis.com:6380/0
# Note: rediss:// (double 's') = TLS enabled
```

---

## Step 3: Install Dependencies (1 minute)

### Python (FastAPI)

```bash
pip install redis fastapi
```

### Node.js (Express)

```bash
npm install redis express
```

---

## Step 4: Add Rate Limiting (5 minutes)

### Python (FastAPI)

```python
# Copy template
cp .claude/skills/rate-limiting-universal/templates/backend/fastapi-rate-limiting.py ./app/rate_limiting.py

# app/main.py
from fastapi import FastAPI
from app.rate_limiting import RateLimiter, RateLimitMiddleware
import os

app = FastAPI()

# Initialize rate limiter
rate_limiter = RateLimiter(redis_url=os.environ["REDIS_URL"])

# Store in app state (for decorator access)
app.state.rate_limiter = rate_limiter

# Add middleware
app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)

@app.on_event("startup")
async def startup():
    await rate_limiter.connect()
    print("✅ Rate limiting enabled")

@app.on_event("shutdown")
async def shutdown():
    await rate_limiter.close()
```

### Node.js (Express)

```javascript
// Copy template
// cp .claude/skills/rate-limiting-universal/templates/backend/express-rate-limiting.js ./src/rate-limiting.js

// app.js
const express = require('express');
const { RateLimiter, rateLimitMiddleware } = require('./rate-limiting');

const app = express();

// Initialize rate limiter
const rateLimiter = new RateLimiter(process.env.REDIS_URL);

// Store in app.locals (for route-level access)
app.locals.rateLimiter = rateLimiter;

// Add middleware
app.use(rateLimitMiddleware(rateLimiter));

// Start server
async function start() {
  await rateLimiter.connect();
  console.log('✅ Rate limiting enabled');

  app.listen(3000, () => {
    console.log('Server running on port 3000');
  });
}

start();

// Graceful shutdown
process.on('SIGINT', async () => {
  await rateLimiter.close();
  process.exit(0);
});
```

---

## Step 5: Test Rate Limiting (2 minutes)

### Test Authentication Endpoint

```bash
# Make 6 requests quickly (should block after 5)
for i in {1..6}; do
  echo "Request $i:"
  curl -i http://localhost:8000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"test"}'
  echo ""
done
```

**Expected Output**:
```
Request 1: HTTP/1.1 200 OK (or 401 if credentials invalid)
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 4
...

Request 5: HTTP/1.1 200 OK (or 401)
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0

Request 6: HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705593660
Retry-After: 60
```

### Verify Redis Keys

```bash
# Check if rate limit keys are being created
redis-cli -a "your-redis-password" KEYS "rate_limit:*"

# Example output:
# 1) "rate_limit:ip:127.0.0.1:/api/auth/login"

# Check bucket state
redis-cli -a "your-redis-password" HGETALL "rate_limit:ip:127.0.0.1:/api/auth/login"

# Example output:
# 1) "tokens"
# 2) "0"
# 3) "last_refill"
# 4) "1705593600.123"
```

---

## Configuration Options

### Custom Rate Limits Per Endpoint

**Python**:
```python
RATE_LIMITS = {
    '/api/auth/login': {'limit': 5, 'window': 60, 'strategy': 'ip'},
    '/api/contact': {'limit': 5, 'window': 3600, 'strategy': 'ip'},
    '/api/data': {'limit': 100, 'window': 60, 'strategy': 'user'},
}

app.add_middleware(
    RateLimitMiddleware,
    rate_limiter=rate_limiter,
    rate_limits=RATE_LIMITS
)
```

**Node.js**:
```javascript
const RATE_LIMITS = {
  '/api/auth/login': { limit: 5, window: 60, strategy: 'ip' },
  '/api/contact': { limit: 5, window: 3600, strategy: 'ip' },
  '/api/data': { limit: 100, window: 60, strategy: 'user' },
};

app.use(rateLimitMiddleware(rateLimiter, RATE_LIMITS));
```

### Route-Level Rate Limiting

**Python**:
```python
from app.rate_limiting import rate_limit

@app.post("/api/custom")
@rate_limit(max_requests=10, window_seconds=60, strategy="ip")
async def custom_endpoint(request: Request):
    return {"message": "Success"}
```

**Node.js**:
```javascript
const { rateLimit } = require('./rate-limiting');

app.post('/api/custom', rateLimit({ limit: 10, window: 60 }), (req, res) => {
  res.json({ message: 'Success' });
});
```

---

## Common Rate Limit Configurations

| Endpoint Type | Limit | Window | Strategy | Reason |
|---|---|---|---|---|
| Login | 5 req | 60s | IP | Prevent brute force |
| Register | 5 req | 60s | IP | Prevent spam accounts |
| Password Reset | 5 req | 60s | IP | Prevent enumeration |
| Contact Form | 5 req | 3600s | IP | Prevent spam |
| API (Auth) | 100 req | 60s | User | Fair usage |
| API (Public) | 20 req | 60s | IP | Prevent abuse |
| Data Export | 10 req | 3600s | User | Expensive operation |

---

## Security Checklist

Before deploying to production:

- [ ] Redis password set (NOT empty)
  ```bash
  redis-cli CONFIG GET requirepass
  # Should return your password
  ```

- [ ] Redis TLS enabled (production)
  ```bash
  REDIS_URL=rediss://...  # Note the double 's'
  ```

- [ ] Redis memory limit configured
  ```bash
  redis-cli CONFIG GET maxmemory
  # Should return 256mb or similar
  ```

- [ ] Redis eviction policy set
  ```bash
  redis-cli CONFIG GET maxmemory-policy
  # Should return 'allkeys-lru'
  ```

- [ ] Rate limit headers present in responses
  ```bash
  curl -I http://localhost:8000/api/endpoint
  # Should see X-RateLimit-* headers
  ```

- [ ] Rate limiting tested (see Step 5)

- [ ] Monitoring configured (see below)

---

## Monitoring

### Health Check Endpoint

**Python**:
```python
from app.rate_limiting import health_check

@app.get("/health")
async def health():
    rate_limit_health = await health_check(rate_limiter)
    return {
        "status": "healthy",
        "rate_limiting": rate_limit_health
    }
```

**Node.js**:
```javascript
const { healthCheck } = require('./rate-limiting');

app.get('/health', async (req, res) => {
  const rateLimitHealth = await healthCheck(rateLimiter);
  res.json({
    status: 'healthy',
    rateLimiting: rateLimitHealth
  });
});
```

### Log Rate Limit Violations

Already built into templates:
```python
logger.warning("rate_limit.exceeded",
    ip=ip_address,
    endpoint=request.path,
    limit=max_requests
)
```

### Prometheus Metrics (Optional)

**Python**:
```python
from prometheus_client import Counter, Histogram

rate_limit_exceeded = Counter(
    'rate_limit_exceeded_total',
    'Total rate limit violations',
    ['endpoint']
)

# In middleware, after rate limit check
if not result['allowed']:
    rate_limit_exceeded.labels(endpoint=request.url.path).inc()
```

**Node.js**:
```javascript
const promClient = require('prom-client');

const rateLimitExceeded = new promClient.Counter({
  name: 'rate_limit_exceeded_total',
  help: 'Total rate limit violations',
  labelNames: ['endpoint']
});

// In middleware
if (!result.allowed) {
  rateLimitExceeded.labels(req.path).inc();
}
```

---

## Troubleshooting

### Issue: Rate limit not working (all requests allowed)

**Check Redis connection**:
```bash
redis-cli -u $REDIS_URL PING
# Should return: PONG
```

**Check if keys are created**:
```bash
redis-cli -u $REDIS_URL KEYS "rate_limit:*"
# Should list keys after making requests
```

**Check middleware order** (must be before routes):
```python
# CORRECT
app.add_middleware(RateLimitMiddleware, ...)
app.include_router(router)

# WRONG
app.include_router(router)
app.add_middleware(RateLimitMiddleware, ...)  # Too late!
```

### Issue: All requests blocked (even first request)

**Check bucket initialization**:
```bash
redis-cli -u $REDIS_URL HGETALL "rate_limit:ip:127.0.0.1:/api/endpoint"
```

Should show positive tokens on first request.

**Check for negative tokens bug**:
```python
# Make sure tokens calculation is correct
tokens = max_requests - 1  # Consume 1 for this request
# NOT: tokens = max_requests - 1 - 1 (double consumption!)
```

### Issue: Rate limit headers missing

**Check response headers**:
```bash
curl -I http://localhost:8000/api/endpoint | grep -i ratelimit
```

Should see:
```
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 4
X-RateLimit-Reset: 1705593600
```

**Check middleware returns response with headers**:
```python
# Make sure headers are added BEFORE returning response
response.headers['X-RateLimit-Limit'] = str(result['limit'])
return response  # Headers must be set before this
```

### Issue: Redis memory growing unbounded

**Check TTL on keys**:
```bash
redis-cli -u $REDIS_URL TTL "rate_limit:ip:127.0.0.1:/api/endpoint"
# Should return positive number (seconds until expiration)
# -1 = no expiration (BUG!)
# -2 = key doesn't exist
```

**Fix: Ensure TTL is set**:
```python
await redis.expire(f"rate_limit:{key}", window_seconds * 2)
```

**Set eviction policy**:
```bash
redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

---

## Production Deployment

### Redis High Availability

**Option 1: Redis Sentinel** (automatic failover)
```bash
# Sentinel monitors Redis and promotes replicas on failure
REDIS_URL=redis-sentinel://sentinel1,sentinel2,sentinel3/mymaster
```

**Option 2: Redis Cluster** (distributed)
```bash
# Distributed across multiple nodes
REDIS_URL=redis-cluster://node1,node2,node3
```

**Option 3: Managed Redis** (recommended)
- AWS ElastiCache
- Google Cloud Memorystore
- Azure Cache for Redis
- Redis Cloud

### Environment Variables (Production)

```bash
# .env.production
REDIS_URL=rediss://:strong-password@prod-redis.com:6380/0  # TLS enabled
REDIS_TLS=true
RATE_LIMIT_FAIL_OPEN=true  # Allow requests if Redis down (recommended)
```

### Monitoring Alerts

```yaml
# Alertmanager rules
alerts:
  - name: HighRateLimitViolations
    condition: rate_limit_exceeded_total > 100 per minute
    action: Alert DevOps

  - name: RateLimitRedisDown
    condition: redis_connection_failed
    action: Page On-Call Engineer
```

---

## Next Steps

1. **Customize rate limits** for your endpoints
2. **Add monitoring** (Prometheus, Datadog, etc.)
3. **Configure alerts** for high violation rates
4. **Test load** with realistic traffic patterns
5. **Review** `playbooks/SECURITY.md` for security hardening
6. **Enable** tiered limits for paid vs free users

---

## Support

- **Documentation**: See `SKILL.md` for complete reference
- **Security**: See `playbooks/SECURITY.md` for security guide
- **Examples**: See `examples/` for complete working examples

---

**Total Setup Time**: ~15 minutes for development, ~1 hour for production-ready deployment
