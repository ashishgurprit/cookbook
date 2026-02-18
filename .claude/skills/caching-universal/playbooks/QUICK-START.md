# Caching Universal - Quick Start (10 min)

## Setup

```bash
# Install Redis
brew install redis
brew services start redis

# Install Python client
pip install redis

# Verify
redis-cli ping  # Should return PONG
```

## Basic Usage

```python
import redis
import json

cache = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Set/Get
cache.set('key', 'value')
value = cache.get('key')

# Set with TTL (expires in 1 hour)
cache.setex('session:123', 3600, json.dumps({'user_id': 'user-456'}))

# Hash (for objects)
cache.hset('user:123', mapping={'name': 'John', 'email': 'john@example.com'})
user = cache.hgetall('user:123')

# Delete
cache.delete('key')

# Check exists
exists = cache.exists('key')
```

## Cache Patterns

```python
# Cache-Aside
def get_user(user_id):
    key = f"user:{user_id}"
    user = cache.get(key)

    if not user:
        user = db.users.find_one({'id': user_id})
        cache.setex(key, 3600, json.dumps(user))
    else:
        user = json.loads(user)

    return user

# Write-Through
def update_user(user_id, data):
    db.users.update_one({'id': user_id}, {'$set': data})
    cache.setex(f"user:{user_id}", 3600, json.dumps(data))
```

## Cost

- Redis (self-hosted): $150/month
- **Total**: $150/month

## Performance

- Cache hit: 1-5ms
- Cache miss + DB: 100ms+
- **Speedup**: 20-100x
