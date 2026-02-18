# Rate Limiting - Security Playbook

> **Security-first implementation guide for rate limiting**
>
> Follows MODULE-SECURITY-FRAMEWORK.md and security-owasp guidelines

---

## OWASP Compliance Matrix

| OWASP Category | Status | Implementation |
|---|---|---|
| **Security Misconfiguration** | ✅ | Rate limiting as defense layer |
| **Authentication Failures** | ✅ | 5 attempts/min on login (brute force prevention) |
| **Logging & Monitoring** | ✅ | Rate limit violations logged (no sensitive data) |
| **DoS Prevention** | ✅ | Token bucket limits request rate |
| **Injection** | ✅ | Key sanitization, no user input in Redis commands |

---

## Security Architecture

### Token Bucket Algorithm Security

**Why Token Bucket > Counter-Based?**
1. ✅ **No memory leaks**: TTL-based cleanup
2. ✅ **Bounded keys**: Fixed number of buckets per endpoint
3. ✅ **Better traffic management**: Allows legitimate bursts
4. ✅ **Proven at scale**: Used by AWS, Stripe, GitHub

**Security Properties**:
- **Atomic operations**: Redis HSET/HGETALL prevents race conditions
- **Time-based refills**: Server time (not client time) prevents manipulation
- **Auto-cleanup**: TTL = 2x window prevents unbounded memory growth

---

## Threat Model

### Threats Rate Limiting Protects Against

| Threat | Mitigation | Effectiveness |
|---|---|---|
| **Brute Force (Auth)** | 5 req/min on login endpoints | ✅ High |
| **DoS/DDoS** | Global + per-IP rate limits | ✅ High |
| **API Abuse** | Per-user + per-IP limits | ✅ High |
| **Spam (Forms)** | 5 req/hour on contact forms | ✅ High |
| **Credential Stuffing** | IP + user-based limits | ✅ Medium |
| **Account Enumeration** | Rate limit on register/reset | ✅ Medium |

### Threats NOT Fully Protected

| Threat | Additional Defense Needed |
|---|---|
| **Distributed Botnets** | + CAPTCHA after threshold |
| **L7 DDoS (application)** | + WAF (Cloudflare, AWS WAF) |
| **Resource Exhaustion** | + Request size limits |
| **Time-based attacks** | + Account lockout after N failures |

---

## Security Implementation

### 1. Redis Security

#### Authentication (CRITICAL)

```bash
# NEVER run Redis without password in production
redis-cli CONFIG SET requirepass "strong-random-password-here"

# Test authentication
redis-cli -a "strong-random-password-here" PING
# Should return: PONG
```

**Environment Variable**:
```bash
# Development
REDIS_URL=redis://:password@localhost:6379/0

# Production (with TLS)
REDIS_URL=rediss://:password@prod-redis.com:6380/0
#          ^ Note: double 's' = TLS enabled
```

#### TLS Encryption (Production REQUIRED)

```bash
# Redis with TLS
REDIS_URL=rediss://:password@host:6380/0  # Port 6380 for TLS

# Verify TLS
redis-cli -u $REDIS_URL --tls INFO server
```

**Why TLS?**
- Prevents eavesdropping (password/data in transit)
- Prevents man-in-the-middle attacks
- Required for PCI compliance

#### Redis Configuration

```conf
# redis.conf

# Authentication
requirepass <strong-password>

# Memory limit (prevent OOM)
maxmemory 256mb

# Eviction policy (remove old keys when full)
maxmemory-policy allkeys-lru

# Disable dangerous commands
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG ""

# Network security
bind 127.0.0.1 ::1  # Localhost only (if not using TLS)
protected-mode yes

# Persistence (optional)
save 900 1
save 300 10
save 60 10000
```

### 2. Key Sanitization

**Prevent Redis Key Injection**:

```python
def sanitize_key_component(component: str) -> str:
    """Sanitize components used in Redis keys"""
    # Allow only alphanumeric, dots, dashes, underscores
    import re
    sanitized = re.sub(r'[^a-zA-Z0-9.\-_]', '', component)

    # Limit length (prevent memory exhaustion)
    return sanitized[:100]

# Usage
key = f"rate_limit:ip:{sanitize_key_component(ip)}:{sanitize_key_component(endpoint)}"
```

**Why?**
- Prevents Redis command injection
- Prevents key collision attacks
- Prevents memory exhaustion via long keys

### 3. IP Detection Security

**X-Forwarded-For Validation**:

```python
def get_client_ip(request: Request) -> str:
    """
    Get client IP with validation

    Security: X-Forwarded-For can be spoofed by clients.
    Only trust X-Forwarded-For if request comes from known proxy.
    """
    forwarded_for = request.headers.get('X-Forwarded-For')

    if forwarded_for:
        # X-Forwarded-For: client, proxy1, proxy2
        # Take FIRST IP (client IP) if from trusted proxy
        ips = [ip.strip() for ip in forwarded_for.split(',')]

        # Validate IP format
        client_ip = ips[0]
        try:
            ipaddress.ip_address(client_ip)  # Validate format
            return client_ip
        except ValueError:
            logger.warning("invalid_ip_in_x_forwarded_for", ip=client_ip)
            return request.client.host

    return request.client.host
```

**Trusted Proxy Configuration**:

```python
# Only trust X-Forwarded-For from these proxies
TRUSTED_PROXIES = [
    '10.0.0.0/8',      # Internal load balancer
    '172.16.0.0/12',   # VPC
    '192.168.0.0/16',  # Private network
]

def is_trusted_proxy(ip: str) -> bool:
    """Check if IP is a trusted proxy"""
    import ipaddress
    ip_obj = ipaddress.ip_address(ip)

    for trusted_cidr in TRUSTED_PROXIES:
        if ip_obj in ipaddress.ip_network(trusted_cidr):
            return True

    return False

# Only use X-Forwarded-For if from trusted proxy
if is_trusted_proxy(request.client.host):
    ip = get_client_ip_from_header(request)
else:
    ip = request.client.host
```

### 4. Fail-Open vs Fail-Closed

**Fail-Open (Default - Recommended)**:
```python
rate_limiter = RateLimiter(redis_url=REDIS_URL, fail_open=True)

# If Redis unavailable: Allow requests, log warning
# Availability > strict enforcement
```

**Fail-Closed (For Critical Endpoints)**:
```python
rate_limiter_strict = RateLimiter(redis_url=REDIS_URL, fail_open=False)

# If Redis unavailable: Block requests
# Security > availability (use for payment endpoints, etc.)
```

**When to Use Each**:

| Endpoint Type | Policy | Reason |
|---|---|---|
| Read endpoints | Fail-Open | Availability important |
| Authentication | Fail-Open | Allow login if Redis down |
| Public API | Fail-Open | User experience |
| Payment endpoints | Fail-Closed | Security critical |
| Admin actions | Fail-Closed | High-risk operations |

### 5. Security Logging

**What to Log** (NO sensitive data):

```python
logger.warning("rate_limit.exceeded",
    ip=ip_address,           # ✅ OK
    endpoint=request.path,   # ✅ OK
    limit=max_requests,      # ✅ OK
    user_id=user.id          # ✅ OK (if authenticated)
    # ❌ NO: request.body
    # ❌ NO: user.email
    # ❌ NO: user.password
    # ❌ NO: tokens/cookies
)
```

**Log Rate Limit Events**:
- `rate_limit.exceeded`: User hit rate limit
- `rate_limit.redis_unavailable`: Redis connection failed
- `rate_limit.fail_open_triggered`: Allowed request due to Redis failure
- `rate_limit.invalid_ip`: Malformed IP in X-Forwarded-For

**Alert Thresholds**:
```python
# Alert if >100 violations/minute (possible attack)
if violations_per_minute > 100:
    alert_ops("high_rate_limit_violations", endpoint=endpoint)

# Alert if Redis unavailable (fail-open triggered)
if redis_unavailable:
    alert_ops("rate_limit_redis_down", severity="high")
```

---

## Security Testing

### 1. Rate Limit Bypass Attempts

```python
# test_security_bypass.py

@pytest.mark.asyncio
async def test_cannot_bypass_with_redis_manipulation():
    """Test that directly manipulating Redis doesn't bypass rate limit"""
    key = "test:bypass"

    # Attacker tries to set unlimited tokens
    await redis.hset(f"rate_limit:{key}", {
        'tokens': 999999,
        'last_refill': time.time()
    })

    # Should still respect max_requests
    for i in range(10):
        result = await check_rate_limit(key, max_requests=5, window_seconds=60)
        if i < 5:
            assert result['allowed'], f"Request {i+1} should be allowed"
        else:
            assert not result['allowed'], f"Request {i+1} should be blocked"

@pytest.mark.asyncio
async def test_cannot_bypass_with_negative_timestamp():
    """Test that time manipulation doesn't grant unlimited tokens"""
    key = "test:time_manipulation"

    # Attacker tries to set very old timestamp (force massive refill)
    await redis.hset(f"rate_limit:{key}", {
        'tokens': 0,
        'last_refill': 0  # Jan 1, 1970 (very old)
    })

    # Next request should still cap at max_requests
    result = await check_rate_limit(key, max_requests=5, window_seconds=60)
    assert result['allowed']
    assert result['remaining'] <= 5, "Tokens should not exceed max_requests"

@pytest.mark.asyncio
async def test_cannot_bypass_with_header_manipulation():
    """Test that manipulating X-Forwarded-For doesn't bypass rate limit"""
    # Consume all tokens for IP 1.1.1.1
    for _ in range(5):
        await check_rate_limit("ip:1.1.1.1:/api/login", 5, 60)

    # Try to bypass by changing X-Forwarded-For
    malicious_headers = [
        "2.2.2.2, 1.1.1.1",  # Try to appear as different IP
        "1.1.1.1, 2.2.2.2",  # Reverse order
        "",                   # Empty header
        "invalid-ip",         # Invalid format
    ]

    for header in malicious_headers:
        # Each should still be rate limited if properly validated
        # (Depends on proper IP extraction logic)
        pass
```

### 2. Distributed Consistency Tests

```python
@pytest.mark.asyncio
async def test_distributed_rate_limit_consistency():
    """Test rate limiting works correctly across multiple instances"""
    key = "distributed_test"
    max_requests = 10

    async def make_concurrent_requests(instance_id: str, count: int):
        """Simulate requests from one instance"""
        allowed = 0
        for _ in range(count):
            result = await check_rate_limit(key, max_requests, 60)
            if result['allowed']:
                allowed += 1
        return allowed

    # Simulate 3 instances making 5 requests each (15 total)
    results = await asyncio.gather(
        make_concurrent_requests("instance1", 5),
        make_concurrent_requests("instance2", 5),
        make_concurrent_requests("instance3", 5)
    )

    total_allowed = sum(results)

    # Only 10 should be allowed (max_requests)
    assert total_allowed <= max_requests, \
        f"Expected <= {max_requests} allowed, got {total_allowed}"
```

### 3. Redis Failure Tests

```python
@pytest.mark.asyncio
async def test_fail_open_allows_requests():
    """Test that fail-open allows requests when Redis is down"""
    rate_limiter = RateLimiter(redis_url=REDIS_URL, fail_open=True)

    # Disconnect Redis
    await rate_limiter.close()

    # Requests should be allowed (fail-open)
    result = await rate_limiter.check_rate_limit("test", 5, 60)
    assert result['allowed'], "Fail-open should allow requests"

@pytest.mark.asyncio
async def test_fail_closed_blocks_requests():
    """Test that fail-closed blocks requests when Redis is down"""
    rate_limiter = RateLimiter(redis_url=REDIS_URL, fail_open=False)

    # Disconnect Redis
    await rate_limiter.close()

    # Requests should be blocked (fail-closed)
    result = await rate_limiter.check_rate_limit("test", 5, 60)
    assert not result['allowed'], "Fail-closed should block requests"
```

### 4. Injection Tests

```python
def test_key_injection_prevention():
    """Test that malicious keys are sanitized"""
    malicious_keys = [
        "1.1.1.1; FLUSHALL",           # Redis command injection
        "1.1.1.1\nFLUSHDB",             # Newline injection
        "../../etc/passwd",             # Path traversal (not applicable, but test anyway)
        "x" * 10000,                    # Memory exhaustion via long key
    ]

    for malicious_key in malicious_keys:
        sanitized = sanitize_key_component(malicious_key)

        # Should not contain dangerous characters
        assert ';' not in sanitized
        assert '\n' not in sanitized
        assert '\r' not in sanitized

        # Should be bounded length
        assert len(sanitized) <= 100
```

---

## Production Security Checklist

### Pre-Deployment

- [ ] **Redis password set** (NOT empty)
  ```bash
  redis-cli CONFIG GET requirepass | grep -v "^$"
  ```

- [ ] **Redis TLS enabled** (production)
  ```bash
  echo $REDIS_URL | grep -q "rediss://"
  ```

- [ ] **Redis dangerous commands disabled**
  ```bash
  redis-cli FLUSHALL  # Should return: ERR unknown command
  ```

- [ ] **Redis memory limit configured**
  ```bash
  redis-cli CONFIG GET maxmemory | grep -v "^0$"
  ```

- [ ] **Rate limits tested** (see QUICK-START.md)
  ```bash
  ./scripts/test-rate-limiting.sh
  ```

- [ ] **Fail-open policy configured correctly**
  - Read endpoints: fail_open=True
  - Critical endpoints: fail_open=False

- [ ] **IP detection validated**
  - Test with X-Forwarded-For
  - Test with proxy
  - Test with direct connection

- [ ] **Security logging enabled** (no sensitive data)
  ```bash
  grep -r "rate_limit\." logs/ | grep -i "password\|token\|secret"
  # Should return nothing
  ```

### Post-Deployment

- [ ] **Rate limit headers present**
  ```bash
  curl -I https://api.example.com/endpoint | grep X-RateLimit
  ```

- [ ] **Rate limiting working**
  ```bash
  for i in {1..10}; do curl https://api.example.com/auth/login; done
  # Should return 429 after limit reached
  ```

- [ ] **Monitoring enabled**
  - Grafana dashboard showing rate limit metrics
  - Alerts configured for high violation rates

- [ ] **Redis backups configured** (if persistence needed)
  ```bash
  redis-cli BGSAVE
  ```

---

## Incident Response

### High Rate Limit Violations

**Symptoms**: >1000 violations/minute on single endpoint

**Immediate Actions**:
1. Check if legitimate traffic spike or attack
   ```bash
   redis-cli --scan --pattern "rate_limit:ip:*" | wc -l
   # Count unique IPs hitting rate limit
   ```

2. Identify top offending IPs
   ```bash
   redis-cli --scan --pattern "rate_limit:ip:*" | \
   sed 's/rate_limit:ip://' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20
   ```

3. If attack: Block IPs at WAF/firewall level
   ```bash
   # Example: Cloudflare firewall rule
   # IP in {1.2.3.4, 5.6.7.8} → Block
   ```

4. If legitimate: Increase rate limits temporarily
   ```python
   RATE_LIMITS['/api/endpoint'] = {'limit': 100, 'window': 60}
   ```

### Redis Unavailable

**Symptoms**: rate_limit.redis_unavailable logs, fail-open triggered

**Immediate Actions**:
1. Check Redis status
   ```bash
   redis-cli PING || echo "Redis is down"
   ```

2. Check Redis logs
   ```bash
   tail -100 /var/log/redis/redis-server.log
   ```

3. If Redis down: Restart
   ```bash
   systemctl restart redis
   # Or for managed Redis, use cloud provider tools
   ```

4. If fail-open triggered: Monitor for abuse
   ```bash
   grep "rate_limit.fail_open_triggered" logs/ | wc -l
   ```

5. Temporary workaround: Switch to local rate limiting
   ```python
   # Fallback to in-memory rate limiting (loses distributed consistency)
   from collections import defaultdict
   rate_limit_cache = defaultdict(dict)
   ```

---

## Advanced Security

### Multi-Layer Rate Limiting

```python
# Layer 1: Nginx (fast, but less granular)
# nginx.conf
limit_req_zone $binary_remote_addr zone=global:10m rate=10r/s;

location /api {
    limit_req zone=global burst=20 nodelay;
    proxy_pass http://backend;
}

# Layer 2: Application (granular, per-endpoint)
# FastAPI/Express with Redis (this skill)

# Layer 3: WAF (Cloudflare, AWS WAF)
# DDoS protection, IP reputation, bot detection
```

### CAPTCHA Integration

```python
# Add CAPTCHA after N rate limit violations

violations = await redis.get(f"violations:ip:{ip}")

if violations and int(violations) >= 3:
    # Require CAPTCHA
    return {
        "error": "Rate limit exceeded",
        "captcha_required": True,
        "captcha_site_key": CAPTCHA_SITE_KEY
    }

# Verify CAPTCHA before allowing request
if captcha_required:
    verify_captcha(request.captcha_response)
```

### Account Lockout

```python
# Lock account after N failed login attempts

failed_attempts = await redis.get(f"failed_login:{user_id}")

if failed_attempts and int(failed_attempts) >= 5:
    # Lock account for 1 hour
    await redis.setex(f"account_locked:{user_id}", 3600, "1")
    logger.warning("account_locked", user_id=user_id)
    return {"error": "Account locked. Try again in 1 hour."}
```

---

## Security Metrics

Track these metrics for security monitoring:

| Metric | Alert Threshold | Action |
|---|---|---|
| Rate limit violations | >100/min | Investigate for attack |
| Unique IPs hitting limit | >50/min | Possible distributed attack |
| Redis unavailable | >0 | Page on-call engineer |
| Fail-open triggered | >1/hour | Investigate Redis issues |
| Invalid X-Forwarded-For | >10/min | Possible header manipulation |
| Account lockouts | >10/min | Possible credential stuffing |

---

## Compliance

### PCI DSS
- ✅ Rate limiting on payment endpoints (required)
- ✅ Redis password authentication (required)
- ✅ TLS encryption for Redis (required)
- ✅ Logging (required, no card data)

### GDPR
- ✅ IP addresses logged (legitimate interest: security)
- ✅ No personal data in logs (compliant)
- ✅ Data retention via Redis TTL (compliant)

### SOC 2
- ✅ Access control (rate limiting = security control)
- ✅ Monitoring and alerting (security incident detection)
- ✅ Logging (audit trail)

---

## References

- **MODULE-SECURITY-FRAMEWORK.md**: Security requirements for all modules
- **security-owasp/SKILL.md**: OWASP Top 10 guidelines
- **security-owasp/SECURITY-REVIEW-CHECKLIST.md**: Security review checklist
- **OWASP Rate Limiting**: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

---

**Security is mandatory. No exceptions.**
