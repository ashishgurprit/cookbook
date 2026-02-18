"""
Rate Limiting - FastAPI Implementation
=======================================

Production-ready token bucket rate limiting with Redis.

Features:
- Token bucket algorithm (allows bursts)
- IP-based and user-based rate limiting
- Configurable per-endpoint limits
- Rate limit headers (X-RateLimit-*)
- Fail-open policy (availability > strict enforcement)
- Security logging (no sensitive data)
- OWASP compliant

Usage:
    from fastapi import FastAPI
    from rate_limiting import RateLimiter, rate_limit

    app = FastAPI()
    rate_limiter = RateLimiter(redis_url=os.environ["REDIS_URL"])

    # Apply to specific endpoint
    @app.post("/api/login")
    @rate_limit(max_requests=5, window_seconds=60, strategy="ip")
    async def login():
        ...

    # Or use middleware for all endpoints
    app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)
"""

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from redis.asyncio import Redis, ConnectionError as RedisConnectionError
from typing import Optional, Dict, Literal
import time
import os
import sys
import structlog
from functools import wraps

# ============================================================================
# CONFIGURATION
# ============================================================================

logger = structlog.get_logger()

# Startup validation
def validate_environment():
    """Validate required environment variables at startup"""
    required = ["REDIS_URL"]
    missing = [var for var in required if not os.environ.get(var)]

    if missing:
        print(f"❌ Missing required environment variables: {', '.join(missing)}")
        print("   Set REDIS_URL=redis://:password@host:6379/0")
        sys.exit(1)

    print("✅ Rate limiting configuration validated")

validate_environment()

# Default rate limits
DEFAULT_RATE_LIMITS = {
    '/api/auth/login': {'limit': 5, 'window': 60, 'strategy': 'ip'},
    '/api/auth/register': {'limit': 5, 'window': 60, 'strategy': 'ip'},
    '/api/auth/reset-password': {'limit': 5, 'window': 60, 'strategy': 'ip'},
    '/api/contact': {'limit': 5, 'window': 3600, 'strategy': 'ip'},
    '/api/newsletter': {'limit': 10, 'window': 3600, 'strategy': 'ip'},
}

# Paths to skip rate limiting
SKIP_PATHS = ['/health', '/metrics', '/docs', '/openapi.json']

# ============================================================================
# RATE LIMITER CLASS
# ============================================================================

class RateLimiter:
    """Token Bucket Rate Limiter with Redis"""

    def __init__(self, redis_url: str, fail_open: bool = True):
        """
        Initialize rate limiter

        Args:
            redis_url: Redis connection URL
            fail_open: Allow requests if Redis unavailable (default: True)
        """
        self.redis_url = redis_url
        self.fail_open = fail_open
        self.redis: Optional[Redis] = None

    async def connect(self):
        """Connect to Redis"""
        try:
            self.redis = await Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1
            )
            await self.redis.ping()
            logger.info("rate_limit.redis_connected")
        except Exception as e:
            logger.error("rate_limit.redis_connection_failed", error=str(e))
            if not self.fail_open:
                raise

    async def close(self):
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int
    ) -> Dict:
        """
        Token Bucket Algorithm

        Args:
            key: Rate limit key (e.g., "ip:203.0.113.45:/api/login")
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds

        Returns:
            {
                'allowed': bool,
                'limit': int,
                'remaining': int,
                'reset': int (unix timestamp),
                'retry_after': int (seconds)
            }
        """
        now = time.time()

        try:
            # Get bucket state from Redis
            bucket = await self.redis.hgetall(f"rate_limit:{key}")

            if not bucket or 'tokens' not in bucket:
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

            # Check if allowed
            allowed = tokens >= 0

            if allowed:
                # Update bucket state in Redis
                await self.redis.hset(f"rate_limit:{key}", mapping={
                    'tokens': str(tokens),
                    'last_refill': str(now)
                })
                # Set TTL for auto-cleanup (2x window to handle refills)
                await self.redis.expire(f"rate_limit:{key}", window_seconds * 2)

            # Calculate response values
            remaining = max(0, int(tokens))
            reset = int(now + window_seconds)
            retry_after = window_seconds if not allowed else 0

            return {
                'allowed': allowed,
                'limit': max_requests,
                'remaining': remaining,
                'reset': reset,
                'retry_after': retry_after
            }

        except RedisConnectionError as e:
            logger.error("rate_limit.redis_unavailable", error=str(e))

            if self.fail_open:
                # Fail-open: Allow request when Redis unavailable
                logger.warning("rate_limit.fail_open_triggered", key=key)
                return {
                    'allowed': True,
                    'limit': max_requests,
                    'remaining': max_requests,
                    'reset': int(now + window_seconds),
                    'retry_after': 0
                }
            else:
                # Fail-closed: Block request when Redis unavailable
                return {
                    'allowed': False,
                    'limit': max_requests,
                    'remaining': 0,
                    'reset': int(now + window_seconds),
                    'retry_after': window_seconds
                }

    def get_client_ip(self, request: Request) -> str:
        """
        Get client IP address

        Handles X-Forwarded-For header from proxies/CDN.
        Takes first IP in X-Forwarded-For (client IP).
        """
        # Check X-Forwarded-For header (from proxy/CDN)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # X-Forwarded-For: client, proxy1, proxy2
            # We want the client IP (first one)
            return forwarded_for.split(',')[0].strip()

        # Fallback to direct connection IP
        return request.client.host

    async def get_rate_limit_key(
        self,
        request: Request,
        strategy: Literal['ip', 'user', 'combined'],
        user_id: Optional[str] = None
    ) -> str:
        """
        Generate rate limit key based on strategy

        Args:
            request: FastAPI request object
            strategy: 'ip', 'user', or 'combined'
            user_id: User ID (required for 'user' strategy)

        Returns:
            Rate limit key (e.g., "ip:203.0.113.45:/api/login")
        """
        path = request.url.path

        if strategy == 'ip':
            ip = self.get_client_ip(request)
            return f"ip:{ip}:{path}"

        elif strategy == 'user':
            if not user_id:
                raise ValueError("user_id required for 'user' strategy")
            return f"user:{user_id}:{path}"

        elif strategy == 'combined':
            ip = self.get_client_ip(request)
            if not user_id:
                return f"ip:{ip}:{path}"
            return f"combined:{user_id}:{ip}:{path}"

        else:
            raise ValueError(f"Invalid strategy: {strategy}")

# ============================================================================
# MIDDLEWARE
# ============================================================================

class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for rate limiting"""

    def __init__(self, app, rate_limiter: RateLimiter, rate_limits: Dict = None):
        super().__init__(app)
        self.rate_limiter = rate_limiter
        self.rate_limits = rate_limits or DEFAULT_RATE_LIMITS

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for certain paths
        if any(request.url.path.startswith(skip) for skip in SKIP_PATHS):
            return await call_next(request)

        # Get rate limit configuration for this endpoint
        config = self.rate_limits.get(request.url.path)

        if not config:
            # No rate limit configured, allow request
            return await call_next(request)

        # Get rate limit key
        strategy = config.get('strategy', 'ip')
        user_id = None  # TODO: Get from auth middleware if 'user' strategy

        key = await self.rate_limiter.get_rate_limit_key(
            request,
            strategy=strategy,
            user_id=user_id
        )

        # Check rate limit
        result = await self.rate_limiter.check_rate_limit(
            key=key,
            max_requests=config['limit'],
            window_seconds=config['window']
        )

        # Add rate limit headers to response
        if result['allowed']:
            response = await call_next(request)
        else:
            # Rate limited - return 429
            logger.warning("rate_limit.exceeded",
                ip=self.rate_limiter.get_client_ip(request),
                endpoint=request.url.path,
                limit=result['limit']
                # NO user data, NO request body
            )

            response = JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Please try again in {result['retry_after']} seconds.",
                    "retry_after": result['retry_after']
                }
            )

        # Add rate limit headers
        response.headers['X-RateLimit-Limit'] = str(result['limit'])
        response.headers['X-RateLimit-Remaining'] = str(result['remaining'])
        response.headers['X-RateLimit-Reset'] = str(result['reset'])

        if not result['allowed']:
            response.headers['Retry-After'] = str(result['retry_after'])

        return response

# ============================================================================
# DECORATOR
# ============================================================================

def rate_limit(
    max_requests: int,
    window_seconds: int,
    strategy: Literal['ip', 'user', 'combined'] = 'ip'
):
    """
    Decorator for rate limiting specific endpoints

    Usage:
        @app.post("/api/login")
        @rate_limit(max_requests=5, window_seconds=60, strategy="ip")
        async def login():
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            # Get rate limiter from app state
            rate_limiter: RateLimiter = request.app.state.rate_limiter

            # Get user ID if using 'user' strategy
            user_id = None
            if strategy in ['user', 'combined']:
                # TODO: Get user from auth dependency
                # user = await get_current_user(request)
                # user_id = user.id
                pass

            # Get rate limit key
            key = await rate_limiter.get_rate_limit_key(
                request,
                strategy=strategy,
                user_id=user_id
            )

            # Check rate limit
            result = await rate_limiter.check_rate_limit(
                key=key,
                max_requests=max_requests,
                window_seconds=window_seconds
            )

            if not result['allowed']:
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "Rate limit exceeded",
                        "retry_after": result['retry_after']
                    },
                    headers={
                        'X-RateLimit-Limit': str(result['limit']),
                        'X-RateLimit-Remaining': '0',
                        'X-RateLimit-Reset': str(result['reset']),
                        'Retry-After': str(result['retry_after'])
                    }
                )

            # Call the endpoint
            return await func(request, *args, **kwargs)

        return wrapper
    return decorator

# ============================================================================
# EXAMPLE USAGE
# ============================================================================

"""
# main.py

from fastapi import FastAPI
from rate_limiting import RateLimiter, RateLimitMiddleware, rate_limit
import os

app = FastAPI()

# Initialize rate limiter
rate_limiter = RateLimiter(redis_url=os.environ["REDIS_URL"])

# Store in app state for decorator access
app.state.rate_limiter = rate_limiter

# Add middleware for automatic rate limiting
app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)

# Or use decorator for specific endpoints
@app.post("/api/custom")
@rate_limit(max_requests=10, window_seconds=60, strategy="ip")
async def custom_endpoint(request: Request):
    return {"message": "Success"}

@app.on_event("startup")
async def startup():
    await rate_limiter.connect()

@app.on_event("shutdown")
async def shutdown():
    await rate_limiter.close()
"""

# ============================================================================
# HEALTH CHECK
# ============================================================================

async def health_check(rate_limiter: RateLimiter) -> Dict:
    """Check rate limiting health"""
    try:
        await rate_limiter.redis.ping()
        return {
            "rate_limiting": "healthy",
            "redis": "connected"
        }
    except Exception as e:
        return {
            "rate_limiting": "degraded",
            "redis": "unavailable",
            "error": str(e),
            "fail_open": rate_limiter.fail_open
        }

# ============================================================================
# MONITORING
# ============================================================================

"""
# Add Prometheus metrics

from prometheus_client import Counter, Histogram

rate_limit_exceeded = Counter(
    'rate_limit_exceeded_total',
    'Total rate limit violations',
    ['endpoint', 'strategy']
)

rate_limit_latency = Histogram(
    'rate_limit_check_duration_seconds',
    'Time to check rate limit'
)

# Usage in middleware
with rate_limit_latency.time():
    result = await rate_limiter.check_rate_limit(...)

if not result['allowed']:
    rate_limit_exceeded.labels(
        endpoint=request.url.path,
        strategy=strategy
    ).inc()
"""
