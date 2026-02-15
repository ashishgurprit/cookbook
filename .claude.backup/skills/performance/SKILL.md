# Performance Optimization Patterns

> Best practices for application performance.
> Auto-discovered when performance work detected.

## Core Principles

```
┌─────────────────────────────────────────────────────────────┐
│              PERFORMANCE GOLDEN RULES                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Measure first, optimize second                          │
│  2. Optimize the critical path                              │
│  3. Cache expensive operations                              │
│  4. Minimize I/O operations                                 │
│  5. Load only what you need                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Frontend Performance

### 1. Bundle Optimization

```javascript
// Code splitting by route
const Dashboard = lazy(() => import('./Dashboard'));
const Settings = lazy(() => import('./Settings'));

// Named chunks for better caching
const Analytics = lazy(() =>
  import(/* webpackChunkName: "analytics" */ './Analytics')
);

// Tree shaking - import only what you need
// BAD
import _ from 'lodash';
_.map(arr, fn);

// GOOD
import { map } from 'lodash-es';
map(arr, fn);
```

### 2. Image Optimization

```html
<!-- Responsive images -->
<picture>
  <source
    srcset="hero-400.webp 400w, hero-800.webp 800w, hero-1200.webp 1200w"
    type="image/webp"
  />
  <img
    src="hero-800.jpg"
    alt="Hero"
    loading="lazy"
    decoding="async"
    width="800"
    height="600"
  />
</picture>

<!-- Modern formats with fallback -->
<picture>
  <source srcset="image.avif" type="image/avif" />
  <source srcset="image.webp" type="image/webp" />
  <img src="image.jpg" alt="..." />
</picture>
```

### 3. Rendering Performance

```javascript
// Virtualization for long lists
import { FixedSizeList } from 'react-window';

const VirtualList = ({ items }) => (
  <FixedSizeList
    height={600}
    itemCount={items.length}
    itemSize={50}
    width="100%"
  >
    {({ index, style }) => (
      <div style={style}>{items[index].name}</div>
    )}
  </FixedSizeList>
);

// Memoization
const ExpensiveComponent = memo(({ data }) => {
  const processed = useMemo(
    () => heavyComputation(data),
    [data]
  );

  const handleClick = useCallback(
    () => onClick(data.id),
    [data.id, onClick]
  );

  return <div onClick={handleClick}>{processed}</div>;
});

// Debounce expensive operations
const debouncedSearch = useMemo(
  () => debounce(handleSearch, 300),
  [handleSearch]
);
```

### 4. Core Web Vitals

| Metric | Target | How to Improve |
|--------|--------|----------------|
| **LCP** (Largest Contentful Paint) | < 2.5s | Optimize images, preload critical resources |
| **FID** (First Input Delay) | < 100ms | Break up long tasks, defer non-critical JS |
| **CLS** (Cumulative Layout Shift) | < 0.1 | Set image dimensions, avoid inserting content above |

```javascript
// Measure Core Web Vitals
import { getLCP, getFID, getCLS } from 'web-vitals';

getLCP(console.log);
getFID(console.log);
getCLS(console.log);
```

## Backend Performance

### 1. Database Optimization

```python
# N+1 Query Problem
# BAD - N+1 queries
users = User.query.all()
for user in users:
    print(user.orders)  # Each access = new query!

# GOOD - Eager loading
users = User.query.options(joinedload(User.orders)).all()
for user in users:
    print(user.orders)  # No additional queries

# GOOD - Select only needed columns
users = User.query.with_entities(User.id, User.name).all()

# Pagination
users = User.query.paginate(page=1, per_page=20)

# Indexing
class User(db.Model):
    email = db.Column(db.String, index=True)  # Add index
    created_at = db.Column(db.DateTime, index=True)

# Composite index for common queries
__table_args__ = (
    db.Index('idx_user_status_date', 'status', 'created_at'),
)
```

### 2. Caching Strategies

```python
# In-memory cache (Redis)
import redis
from functools import wraps

cache = redis.Redis()

def cached(ttl=300):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"

            # Try cache first
            result = cache.get(key)
            if result:
                return json.loads(result)

            # Compute and cache
            result = func(*args, **kwargs)
            cache.setex(key, ttl, json.dumps(result))
            return result
        return wrapper
    return decorator

@cached(ttl=60)
def get_user_stats(user_id):
    # Expensive computation
    return compute_stats(user_id)

# Cache invalidation
def update_user(user_id, data):
    db.update_user(user_id, data)
    cache.delete(f"get_user_stats:{hash(str((user_id,)))}")
```

### 3. Async Operations

```python
# Async I/O
import asyncio
import aiohttp

async def fetch_all(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_one(session, url) for url in urls]
        return await asyncio.gather(*tasks)

async def fetch_one(session, url):
    async with session.get(url) as response:
        return await response.json()

# Background tasks
from fastapi import BackgroundTasks

@app.post("/send-email")
async def send_email(
    email: str,
    background_tasks: BackgroundTasks
):
    background_tasks.add_task(send_email_task, email)
    return {"status": "queued"}
```

### 4. Connection Pooling

```python
# Database connection pool
from sqlalchemy import create_engine

engine = create_engine(
    DATABASE_URL,
    pool_size=10,           # Maintain 10 connections
    max_overflow=20,        # Allow 20 more under load
    pool_timeout=30,        # Wait 30s for connection
    pool_recycle=1800,      # Recycle connections after 30m
)

# HTTP connection pool
import httpx

# Reuse client (don't create per request)
client = httpx.AsyncClient(
    limits=httpx.Limits(max_connections=100)
)

async def fetch(url):
    return await client.get(url)
```

## API Performance

### 1. Response Optimization

```python
# Pagination
@app.get("/items")
def get_items(page: int = 1, limit: int = 20):
    offset = (page - 1) * limit
    items = db.query(Item).offset(offset).limit(limit).all()
    total = db.query(Item).count()

    return {
        "data": items,
        "meta": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": ceil(total / limit)
        }
    }

# Field selection
@app.get("/users")
def get_users(fields: str = None):
    query = User.query

    if fields:
        columns = [getattr(User, f) for f in fields.split(",")]
        query = query.with_entities(*columns)

    return query.all()

# Compression
from fastapi.middleware.gzip import GZipMiddleware
app.add_middleware(GZipMiddleware, minimum_size=1000)
```

### 2. Caching Headers

```python
from fastapi.responses import Response

@app.get("/static-data")
def get_static_data():
    return Response(
        content=json.dumps(data),
        headers={
            "Cache-Control": "public, max-age=3600",
            "ETag": compute_etag(data),
        }
    )

@app.get("/user-data")
def get_user_data():
    return Response(
        content=json.dumps(data),
        headers={
            "Cache-Control": "private, no-cache",
        }
    )
```

## Performance Checklist

```markdown
## Performance Review Checklist

### Frontend
- [ ] Bundle size analyzed (webpack-bundle-analyzer)
- [ ] Code splitting implemented
- [ ] Images optimized (WebP/AVIF, lazy loading)
- [ ] Core Web Vitals passing
- [ ] No layout shifts

### Backend
- [ ] Database queries optimized (no N+1)
- [ ] Proper indexes in place
- [ ] Caching implemented for hot paths
- [ ] Connection pooling configured
- [ ] Async where beneficial

### API
- [ ] Pagination on list endpoints
- [ ] Response compression enabled
- [ ] Proper cache headers
- [ ] Field selection available

### Monitoring
- [ ] Performance metrics tracked
- [ ] Alerts on degradation
- [ ] Slow query logging enabled
```

## Measurement Tools

| Tool | Purpose |
|------|---------|
| Lighthouse | Frontend audit |
| WebPageTest | Real-world loading |
| Chrome DevTools | Profiling |
| EXPLAIN ANALYZE | SQL query analysis |
| py-spy / node --prof | Backend profiling |
| Prometheus + Grafana | Metrics & dashboards |
