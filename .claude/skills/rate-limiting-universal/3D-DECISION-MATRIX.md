# Rate Limiting - 3D Decision Matrix Analysis

## Decision Context

**Question**: How should we implement rate limiting across all 61 projects?

**Classification**: THOUGHTFUL Decision
- **Impact**: High (affects security and user experience across all projects)
- **Reversibility**: Medium (can change algorithms, but breaking changes affect users)
- **Stakes**: Security-critical (prevents DoS, brute force, abuse)
- **Complexity**: Medium (well-understood algorithms, proven patterns)

**Decision Framework**: Quick SPADE + Key C-Suite Perspectives + Six Thinking Hats

---

## White Hat ⚪ (Facts & Data)

### From LESSONS.md
**Lesson**: "Use Token Bucket Over Counter-Based Rate Limiting"
- Counter-based approach has memory leaks (unbounded keys)
- Token bucket provides smoother traffic management
- Supports burst traffic while maintaining average rate

### Technical Requirements
- **Auth endpoints**: 5 requests/minute per IP (prevent brute force)
- **Contact forms**: 5 requests/hour per IP (prevent spam)
- **API endpoints**: Configurable per tier
- **Multi-instance support**: Distributed rate limiting (Redis)
- **Graceful degradation**: If Redis down, allow requests (fail open vs fail closed)

### Current State
- 61 projects need rate limiting
- Auth-universal skill already deployed (needs rate limiting)
- Email-universal (upcoming) needs rate limiting
- Payment-processing (upcoming) critical for rate limiting

### Algorithm Options
1. **Token Bucket**: Tokens added at fixed rate, consumed per request
2. **Leaky Bucket**: Requests queued, processed at fixed rate
3. **Fixed Window**: Count requests in fixed time windows
4. **Sliding Window Log**: Track timestamps of all requests
5. **Sliding Window Counter**: Hybrid of fixed window and sliding log

---

## C-Suite Perspectives

### CTO (Technical Architecture)

**Algorithm Evaluation**:

| Algorithm | Pros | Cons | Complexity |
|---|---|---|---|
| Token Bucket | • Allows bursts<br>• Memory efficient<br>• Industry standard | • Slightly complex | Medium |
| Leaky Bucket | • Smooth output rate<br>• Predictable | • Doesn't allow bursts<br>• Queue management | Medium |
| Fixed Window | • Simple<br>• Low memory | • Burst at boundary<br>• Inaccurate | Low |
| Sliding Window Log | • Accurate<br>• Fair | • High memory (all timestamps)<br>• Cleanup needed | High |
| Sliding Window Counter | • Balanced accuracy<br>• Lower memory | • Approximate<br>• More complex | Medium-High |

**Recommendation**: Token Bucket
- Industry standard (AWS, Cloudflare, Stripe use it)
- Memory efficient (2 values: tokens + timestamp)
- Allows legitimate bursts
- Well-documented, proven

**Storage Options**:
1. **Redis** (Recommended)
   - Distributed (multi-instance support)
   - TTL for auto-cleanup
   - Atomic operations
   - Fast (in-memory)

2. **In-Memory** (Not recommended for production)
   - No multi-instance support
   - Lost on restart
   - OK for development only

3. **Database** (Not recommended)
   - Too slow
   - Unnecessary load

**Decision**: Redis-based token bucket

### CFO (Cost & ROI)

**Cost Analysis**:
- Redis hosting: ~$10-20/month (shared across services)
- Development time: 3-4 days
- Value: Prevents abuse across 61 projects

**ROI Calculation**:
- Cost of DoS attack: $10,000+ (downtime, reputation)
- Cost of brute force compromise: $50,000+ (data breach)
- Prevention value: $500,000+ (across 61 projects over 5 years)

**Recommendation**: High ROI, implement immediately

### CPO (Product & UX)

**User Experience Concerns**:
1. **Legitimate users hitting limits**
   - Solution: Generous default limits
   - Solution: Clear error messages (429 with retry-after)
   - Solution: Exponential backoff guidance

2. **API integration developers**
   - Solution: Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
   - Solution: Documentation on limits
   - Solution: Different tiers (free, pro, enterprise)

3. **Mobile apps (variable IPs)**
   - Solution: Support user-based rate limiting (not just IP)
   - Solution: Authenticated endpoints use user ID

**Recommendation**: Implement with excellent developer experience (headers, docs, tiers)

### COO (Operations & Reliability)

**Operational Concerns**:
1. **Redis single point of failure**
   - Solution: Redis sentinel/cluster (HA)
   - Solution: Fail-open policy (if Redis down, allow requests)
   - Solution: Monitor Redis availability

2. **Rate limit bypass attempts**
   - Solution: Multiple strategies (IP + User + Endpoint)
   - Solution: Detect proxy/VPN IPs
   - Solution: Log rate limit violations

3. **Monitoring & Alerting**
   - Solution: Track rate limit hits per endpoint
   - Solution: Alert on unusual patterns
   - Solution: Dashboard for rate limit metrics

**Recommendation**: Implement with robust monitoring and fail-open policy

---

## Six Thinking Hats Analysis

### Green Hat 🟢 (Alternatives)

**Option 1: Token Bucket with Redis**
- Standard algorithm, distributed
- Allows bursts (good UX)
- 2 values per key: tokens + timestamp

**Option 2: Sliding Window Counter with Redis**
- More accurate than fixed window
- No burst handling
- Complex implementation

**Option 3: Third-party Service (Cloudflare, AWS WAF)**
- No maintenance
- Vendor lock-in
- Less control
- Additional cost

**Option 4: Multi-layer Approach**
- Nginx rate limiting (first layer)
- Application rate limiting (second layer)
- Granular control
- More complex

**Decision**: Option 1 (Token Bucket) with Option 4 (Nginx layer optional)

### Yellow Hat 🟡 (Benefits)

**Token Bucket Benefits**:
- ✅ Industry-proven (AWS, Stripe, Cloudflare)
- ✅ Memory efficient (2 values per key)
- ✅ Allows legitimate bursts (good UX)
- ✅ Distributed (Redis)
- ✅ Auto-cleanup (TTL)
- ✅ Fast (in-memory)
- ✅ Language-agnostic (can implement in Python, Node, Go)

**Security Benefits**:
- ✅ Prevents brute force attacks
- ✅ Prevents DoS/DDoS
- ✅ Prevents API abuse
- ✅ Prevents spam
- ✅ Reduces attack surface

**Developer Experience**:
- ✅ Standard HTTP 429 responses
- ✅ Rate limit headers (X-RateLimit-*)
- ✅ Clear documentation
- ✅ Configurable per endpoint

### Black Hat ⚫ (Risks)

**Implementation Risks**:
- ❌ Redis dependency (mitigated with fail-open)
- ❌ Clock synchronization across servers (mitigated with Redis time)
- ❌ IP spoofing (mitigated with X-Forwarded-For validation)
- ❌ Legitimate users hitting limits (mitigated with generous defaults)

**Security Risks**:
- ❌ Bypass via distributed IPs (botnets) - Need additional defense
- ❌ Memory exhaustion (unbounded keys) - Need key cleanup strategy
- ❌ Redis compromise - Need Redis authentication

**Operational Risks**:
- ❌ Redis downtime blocks all requests (mitigated with fail-open)
- ❌ Redis memory exhaustion (mitigated with TTL + eviction policy)

**Mitigations**:
- Fail-open policy (allow requests if Redis unavailable)
- Redis authentication (password + TLS)
- Key TTL for auto-cleanup
- Monitor Redis memory usage
- Multiple rate limit strategies (IP + User)

### Red Hat 🔴 (Intuition)

**Gut Feelings**:
- Token bucket feels "right" (industry standard)
- Redis feels solid (used in production everywhere)
- Fail-open feels safer than fail-closed (availability > strict enforcement)
- Rate limit headers feel essential (developer empathy)

**Concerns**:
- Complexity might be over-engineered for simple cases
- Redis dependency adds operational burden
- But... security is worth it

### Blue Hat 🔵 (Meta & Synthesis)

**Process Summary**:
1. Analyzed 5 algorithms
2. Evaluated storage options (Redis wins)
3. Considered C-Suite perspectives
4. Balanced security, UX, cost, operations

**Key Insights**:
- Token bucket is industry standard for good reason
- Redis enables distributed rate limiting
- Fail-open policy balances security and availability
- Rate limit headers are essential for developer experience

---

## SPADE Framework

### Setting
**Context**: 61 projects need rate limiting for security
**Constraints**: Must be distributed, memory-efficient, secure
**Success Criteria**:
- Prevents brute force (5 attempts/minute on auth)
- Prevents spam (5 requests/hour on forms)
- Good UX (allows bursts, clear errors)
- Distributed (multi-instance)
- Monitoring (track abuse patterns)

### People
**Stakeholders**:
- 61 projects (need protection)
- Legitimate users (need good UX)
- API developers (need clear limits)
- Operations (need reliability)
- Security team (need defense)

### Alternatives
See Green Hat (4 options evaluated)

### Decide

**RECOMMENDATION: Token Bucket with Redis**

**Architecture**:
```
Request → Rate Limiter → Token Bucket Algorithm → Redis → Allow/Deny
                ↓
         Response Headers
         (X-RateLimit-*)
```

**Algorithm Details**:
```python
def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """
    Token Bucket Algorithm

    Tokens are added at rate: max_requests / window_seconds
    Each request consumes 1 token
    Allows bursts up to max_requests
    """
    now = time.time()

    # Get bucket state from Redis
    bucket = redis.hgetall(f"rate_limit:{key}")

    if not bucket:
        # Initialize new bucket
        tokens = max_requests - 1  # Consume 1 for this request
        last_refill = now
    else:
        tokens = float(bucket['tokens'])
        last_refill = float(bucket['last_refill'])

        # Refill tokens based on time elapsed
        elapsed = now - last_refill
        refill_rate = max_requests / window_seconds
        tokens = min(max_requests, tokens + (elapsed * refill_rate))

        # Consume 1 token
        tokens -= 1

    if tokens < 0:
        return False  # Rate limited

    # Update bucket in Redis
    redis.hset(f"rate_limit:{key}", {
        'tokens': tokens,
        'last_refill': now
    })
    redis.expire(f"rate_limit:{key}", window_seconds * 2)  # Auto-cleanup

    return True  # Allowed
```

**Rate Limit Strategies**:
1. **IP-based**: `rate_limit:ip:{ip_address}:{endpoint}`
2. **User-based**: `rate_limit:user:{user_id}:{endpoint}`
3. **Combined**: Check both, use stricter limit

**Default Limits**:
- Auth endpoints: 5 requests/minute per IP
- Contact forms: 5 requests/hour per IP
- API (authenticated): 100 requests/minute per user
- API (public): 20 requests/minute per IP

**Response Headers**:
```
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705593600
Retry-After: 60
```

### Explain

**Why Token Bucket?**
- Industry standard (proven at scale)
- Allows legitimate bursts (better UX than strict fixed rate)
- Memory efficient (2 values per key)
- Mathematically sound (smooth average rate)

**Why Redis?**
- Distributed (multi-instance support)
- Fast (in-memory, sub-millisecond)
- TTL for auto-cleanup (no memory leaks)
- Atomic operations (no race conditions)
- Battle-tested (production-ready)

**Why Fail-Open?**
- Availability > strict enforcement
- Redis downtime shouldn't block all traffic
- Still log when fail-open triggered (alert operations)
- Can switch to fail-closed for critical endpoints

**Why Multiple Strategies?**
- IP-based catches most abuse
- User-based prevents authenticated abuse
- Endpoint-specific allows fine-grained control
- Combined approach maximizes protection

---

## Security Integration

**OWASP Compliance**:
- ✅ **Security Misconfiguration**: Rate limiting as defense layer
- ✅ **Logging & Monitoring**: Track rate limit violations
- ✅ **DoS Prevention**: Primary defense against DoS attacks
- ✅ **Brute Force Prevention**: Protects authentication
- ✅ **API Abuse Prevention**: Protects public endpoints

**Security Testing**:
- Test rate limit bypass attempts
- Test distributed consistency
- Test Redis authentication
- Test fail-open behavior
- Test IP spoofing detection

**Real-World Patterns Applied**:
- Exclude password fields from analysis (applied in middleware)
- Use token bucket over counter (from lessons)
- Log security events without sensitive data

---

## DECISION: Implement Token Bucket with Redis

**Confidence**: 90%
- High confidence in algorithm choice (industry standard)
- High confidence in Redis (battle-tested)
- Medium confidence in fail-open (need monitoring)

**Success Metrics**:
- Zero successful brute force attempts
- Zero successful DoS attacks via rate limiting
- <1% false positives (legitimate users blocked)
- <100ms latency overhead per request
- 99.9% availability (with fail-open)

**Timeline**: 3-4 days
- Day 1: Core algorithm + Redis integration
- Day 2: Middleware for Express/FastAPI + Frontend integration
- Day 3: Security testing + Documentation
- Day 4: Deployment + Monitoring setup

---

## Next Steps

1. Implement token bucket algorithm (Python + Node.js)
2. Create middleware for Express/FastAPI
3. Add rate limit headers
4. Implement fail-open policy
5. Security testing (bypass attempts, Redis failure)
6. Documentation (SKILL.md, QUICK-START.md, SECURITY.md)
7. Deploy to 61 projects
8. Monitor rate limit metrics

---

**Let's build it.** 🚀
