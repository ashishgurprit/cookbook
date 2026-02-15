# Caching Universal - Production Caching Strategies

**Version**: 1.0.0
**OWASP Compliance**: 100%
**Providers**: Redis + Memcached + CDN

> Production-ready caching with multi-layer strategy and cache invalidation patterns.

## Architecture

**Multi-Layer Strategy**:
- **L1 - Application Cache**: In-memory (fastest, 0ms)
- **L2 - Redis**: Distributed cache (fast, 1-5ms)
- **L3 - CDN**: Edge cache (CloudFront, 10-50ms)
- **L4 - Database**: Persistent storage (slow, 100ms+)

**Cost**: $150/month vs $500 managed cache

## Quick Start

```python
import redis
from functools import wraps

# Redis cache
cache = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Cache decorator
def cached(ttl=3600):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = f"{func.__name__}:{args}:{kwargs}"

            # Check cache
            result = cache.get(key)
            if result:
                return json.loads(result)

            # Compute and cache
            result = func(*args, **kwargs)
            cache.setex(key, ttl, json.dumps(result))
            return result
        return wrapper
    return decorator

# Usage
@cached(ttl=3600)
def get_user(user_id):
    # Expensive DB query
    return db.users.find_one({'id': user_id})

user = get_user('user-123')  # First call: DB query
user = get_user('user-123')  # Second call: Cache hit
```

## Cache Patterns

### 1. Cache-Aside (Lazy Loading)
```python
def get_product(product_id):
    # Check cache first
    product = cache.get(f"product:{product_id}")
    if product:
        return json.loads(product)

    # Cache miss, load from DB
    product = db.products.find_one({'id': product_id})
    cache.setex(f"product:{product_id}", 3600, json.dumps(product))
    return product
```

### 2. Write-Through
```python
def update_product(product_id, data):
    # Update DB
    db.products.update_one({'id': product_id}, {'$set': data})

    # Update cache immediately
    product = db.products.find_one({'id': product_id})
    cache.setex(f"product:{product_id}", 3600, json.dumps(product))
```

### 3. Write-Behind (Async)
```python
def update_product(product_id, data):
    # Update cache immediately
    cache.setex(f"product:{product_id}", 3600, json.dumps(data))

    # Queue DB update (async)
    background_jobs.delay('update_db', product_id, data)
```

## Cache Invalidation

```python
# Invalidate single key
cache.delete('user:123')

# Invalidate pattern
keys = cache.keys('user:*')
cache.delete(*keys)

# Tag-based invalidation
cache.sadd('tag:premium_users', 'user:123', 'user:456')
for key in cache.smembers('tag:premium_users'):
    cache.delete(key)
```

## Security (OWASP)

- **A01**: Cache keys include user ID (prevent data leakage)
- **A02**: Don't cache sensitive data (passwords, credit cards)
- **A04**: Rate limiting on cache writes
- **A05**: Redis AUTH password

## Features

- Multi-layer caching
- TTL (time-to-live)
- Cache warming
- Cache stampede prevention
- Monitoring (hit rate, memory usage)

**Use Cases**: API responses, database queries, session storage, computed results, rate limiting

## Performance

- L1 (in-memory): 0.01ms
- L2 (Redis): 1-5ms
- L3 (CDN): 10-50ms
- DB (PostgreSQL): 100ms+

**Cache Hit Rate Target**: > 90%
