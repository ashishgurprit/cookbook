# Health Check Examples

Complete health check implementations for Railway deployments across different frameworks.

---

## Table of Contents

1. [Flask Health Checks](#flask-health-checks)
2. [FastAPI Health Checks](#fastapi-health-checks)
3. [Django Health Checks](#django-health-checks)
4. [Express.js Health Checks](#expressjs-health-checks)
5. [Advanced Patterns](#advanced-patterns)

---

## Flask Health Checks

### Basic Health Check

```python
from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route("/health")
def health():
    """Simple health check for Railway."""
    return jsonify({
        "status": "healthy"
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
```

---

### Health Check with Feature Detection

```python
from flask import Flask, jsonify
import os

app = Flask(__name__)

def check_required_env_vars():
    """Check if all required environment variables are set."""
    required = ["DATABASE_URL", "SECRET_KEY"]
    return all(os.getenv(var) for var in required)

def check_optional_features():
    """Check if optional features are enabled."""
    optional = {
        "wordpress": all([
            os.getenv("WORDPRESS_API_URL"),
            os.getenv("WORDPRESS_API_USER"),
            os.getenv("WORDPRESS_API_PASS")
        ]),
        "analytics": all([
            os.getenv("GA4_CREDENTIALS_BASE64"),
            os.getenv("GA4_PROPERTY_ID")
        ]),
        "email": bool(os.getenv("SENDGRID_API_KEY"))
    }
    return optional

@app.route("/health")
def health():
    """
    Health check endpoint for Railway.

    Returns:
        - status: healthy/degraded
        - mode: full/limited
        - features: dict of enabled features
        - version: deployment ID
    """
    features = check_optional_features()
    all_features_enabled = all(features.values())

    return jsonify({
        "status": "healthy",
        "mode": "full" if all_features_enabled else "limited",
        "features": features,
        "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
    }), 200
```

---

### Health Check with Database Connection

```python
from flask import Flask, jsonify
from sqlalchemy import create_engine, text
import os
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Database connection
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL, pool_pre_ping=True) if DATABASE_URL else None

@app.route("/health")
def health():
    """Health check with database validation."""
    db_healthy = False
    db_error = None

    if engine:
        try:
            # Quick DB ping (< 1 second timeout)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            db_healthy = True
        except Exception as e:
            db_error = str(e)
            logger.error(f"Health check DB error: {e}")

    # Return 503 if database is down
    status_code = 200 if db_healthy else 503

    response = {
        "status": "healthy" if db_healthy else "degraded",
        "database": {
            "status": "connected" if db_healthy else "disconnected",
            "error": db_error if db_error else None
        },
        "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
    }

    return jsonify(response), status_code

@app.route("/health/ready")
def ready():
    """Readiness check - only returns 200 when app is ready to serve traffic."""
    # Check if all critical services are available
    if not engine:
        return jsonify({"status": "not ready", "reason": "database not configured"}), 503

    return jsonify({"status": "ready"}), 200

@app.route("/health/live")
def live():
    """Liveness check - returns 200 if app is running (doesn't check dependencies)."""
    return jsonify({"status": "alive"}), 200
```

---

## FastAPI Health Checks

### Basic Health Check

```python
from fastapi import FastAPI, status
from pydantic import BaseModel
import os

app = FastAPI()

class HealthResponse(BaseModel):
    status: str
    version: str

@app.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check():
    """Health check endpoint for Railway."""
    return {
        "status": "healthy",
        "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
    }
```

---

### Advanced Health Check with Dependencies

```python
from fastapi import FastAPI, status
from pydantic import BaseModel
from typing import Dict, Optional
import os
from sqlalchemy import create_engine, text
from redis import Redis
import logging

app = FastAPI()
logger = logging.getLogger(__name__)

# Initialize dependencies
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")

engine = create_engine(DATABASE_URL, pool_pre_ping=True) if DATABASE_URL else None
redis_client = Redis.from_url(REDIS_URL) if REDIS_URL else None

class HealthResponse(BaseModel):
    status: str
    mode: str
    database: Dict[str, Optional[str]]
    redis: Dict[str, Optional[str]]
    features: Dict[str, bool]
    version: str

async def check_database() -> Dict[str, Optional[str]]:
    """Check database connectivity."""
    if not engine:
        return {"status": "not_configured", "error": None}

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "connected", "error": None}
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {"status": "disconnected", "error": str(e)}

async def check_redis() -> Dict[str, Optional[str]]:
    """Check Redis connectivity."""
    if not redis_client:
        return {"status": "not_configured", "error": None}

    try:
        redis_client.ping()
        return {"status": "connected", "error": None}
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return {"status": "disconnected", "error": str(e)}

def check_features() -> Dict[str, bool]:
    """Check optional feature availability."""
    return {
        "wordpress": all([
            os.getenv("WORDPRESS_API_URL"),
            os.getenv("WORDPRESS_API_USER"),
            os.getenv("WORDPRESS_API_PASS")
        ]),
        "analytics": all([
            os.getenv("GA4_CREDENTIALS_BASE64"),
            os.getenv("GA4_PROPERTY_ID")
        ]),
        "email": bool(os.getenv("SENDGRID_API_KEY"))
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Comprehensive health check endpoint.

    Returns service status, dependency health, and feature flags.
    """
    db_status = await check_database()
    redis_status = await check_redis()
    features = check_features()

    # Determine overall status
    all_critical_healthy = (
        db_status["status"] == "connected" and
        redis_status["status"] in ["connected", "not_configured"]
    )

    status_code = status.HTTP_200_OK if all_critical_healthy else status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if all_critical_healthy else "degraded",
        "mode": "full" if all(features.values()) else "limited",
        "database": db_status,
        "redis": redis_status,
        "features": features,
        "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
    }

@app.get("/health/ready")
async def readiness_check():
    """Readiness check - returns 200 only when ready to serve traffic."""
    db_status = await check_database()

    if db_status["status"] != "connected":
        return {
            "status": "not ready",
            "reason": "database not connected"
        }, status.HTTP_503_SERVICE_UNAVAILABLE

    return {"status": "ready"}, status.HTTP_200_OK

@app.get("/health/live")
async def liveness_check():
    """Liveness check - returns 200 if app is running."""
    return {"status": "alive"}, status.HTTP_200_OK
```

---

## Django Health Checks

### Basic Health Check View

```python
# health/views.py
from django.http import JsonResponse
from django.views import View
import os

class HealthCheckView(View):
    """Health check endpoint for Railway."""

    def get(self, request):
        return JsonResponse({
            "status": "healthy",
            "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
        })
```

**urls.py**:
```python
from django.urls import path
from health.views import HealthCheckView

urlpatterns = [
    path('health/', HealthCheckView.as_view(), name='health'),
    # ... other URLs
]
```

---

### Django Health Check with Database

```python
# health/views.py
from django.http import JsonResponse
from django.views import View
from django.db import connection
import os
import logging

logger = logging.getLogger(__name__)

class HealthCheckView(View):
    """Health check with database validation."""

    def get(self, request):
        db_healthy = self._check_database()

        status_code = 200 if db_healthy else 503

        response_data = {
            "status": "healthy" if db_healthy else "degraded",
            "database": "connected" if db_healthy else "disconnected",
            "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
        }

        return JsonResponse(response_data, status=status_code)

    def _check_database(self):
        """Check database connectivity."""
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

class ReadinessCheckView(View):
    """Readiness check - only returns 200 when ready to serve traffic."""

    def get(self, request):
        # Check critical dependencies
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            return JsonResponse({"status": "ready"})
        except Exception:
            return JsonResponse(
                {"status": "not ready", "reason": "database unavailable"},
                status=503
            )

class LivenessCheckView(View):
    """Liveness check - returns 200 if app is running."""

    def get(self, request):
        return JsonResponse({"status": "alive"})
```

---

## Express.js Health Checks

### Basic Health Check

```javascript
const express = require('express');
const app = express();

app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        version: process.env.RAILWAY_DEPLOYMENT_ID || 'local'
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

---

### Health Check with Database and Redis

```javascript
const express = require('express');
const { Pool } = require('pg');
const redis = require('redis');

const app = express();

// Initialize connections
const pgPool = new Pool({
    connectionString: process.env.DATABASE_URL
});

const redisClient = redis.createClient({
    url: process.env.REDIS_URL
});

redisClient.connect().catch(err => {
    console.error('Redis connection failed:', err);
});

// Helper functions
async function checkDatabase() {
    try {
        const client = await pgPool.connect();
        await client.query('SELECT 1');
        client.release();
        return { status: 'connected', error: null };
    } catch (error) {
        console.error('Database health check failed:', error);
        return { status: 'disconnected', error: error.message };
    }
}

async function checkRedis() {
    try {
        await redisClient.ping();
        return { status: 'connected', error: null };
    } catch (error) {
        console.error('Redis health check failed:', error);
        return { status: 'disconnected', error: error.message };
    }
}

function checkFeatures() {
    return {
        wordpress: !!(
            process.env.WORDPRESS_API_URL &&
            process.env.WORDPRESS_API_USER &&
            process.env.WORDPRESS_API_PASS
        ),
        analytics: !!(
            process.env.GA4_CREDENTIALS_BASE64 &&
            process.env.GA4_PROPERTY_ID
        ),
        email: !!process.env.SENDGRID_API_KEY
    };
}

// Health check endpoint
app.get('/health', async (req, res) => {
    const database = await checkDatabase();
    const redis = await checkRedis();
    const features = checkFeatures();

    const allCriticalHealthy = (
        database.status === 'connected' &&
        redis.status === 'connected'
    );

    const statusCode = allCriticalHealthy ? 200 : 503;

    res.status(statusCode).json({
        status: allCriticalHealthy ? 'healthy' : 'degraded',
        mode: Object.values(features).every(v => v) ? 'full' : 'limited',
        database,
        redis,
        features,
        version: process.env.RAILWAY_DEPLOYMENT_ID || 'local',
        timestamp: new Date().toISOString()
    });
});

// Readiness check
app.get('/health/ready', async (req, res) => {
    const database = await checkDatabase();

    if (database.status !== 'connected') {
        return res.status(503).json({
            status: 'not ready',
            reason: 'database not connected'
        });
    }

    res.json({ status: 'ready' });
});

// Liveness check
app.get('/health/live', (req, res) => {
    res.json({ status: 'alive' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

---

## Advanced Patterns

### Health Check with Metrics

```python
from flask import Flask, jsonify
from datetime import datetime, timedelta
import os
import psutil

app = Flask(__name__)
start_time = datetime.utcnow()

@app.route("/health")
def health():
    """Health check with system metrics."""
    uptime = datetime.utcnow() - start_time

    return jsonify({
        "status": "healthy",
        "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local"),
        "uptime_seconds": int(uptime.total_seconds()),
        "memory_usage_mb": psutil.Process().memory_info().rss / 1024 / 1024,
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "timestamp": datetime.utcnow().isoformat()
    }), 200
```

---

### Health Check with External Service Validation

```python
from flask import Flask, jsonify
import requests
import os

app = Flask(__name__)

def check_external_service(url, timeout=5):
    """Check if external service is reachable."""
    try:
        response = requests.get(url, timeout=timeout)
        return {
            "status": "reachable" if response.status_code < 500 else "degraded",
            "status_code": response.status_code,
            "response_time_ms": int(response.elapsed.total_seconds() * 1000)
        }
    except requests.RequestException as e:
        return {
            "status": "unreachable",
            "error": str(e)
        }

@app.route("/health")
def health():
    """Health check with external service validation."""
    wordpress_url = os.getenv("WORDPRESS_API_URL")
    wordpress_status = None

    if wordpress_url:
        wordpress_status = check_external_service(f"{wordpress_url}/wp-json/wp/v2/posts?per_page=1")

    return jsonify({
        "status": "healthy",
        "external_services": {
            "wordpress": wordpress_status
        },
        "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
    }), 200
```

---

### Cached Health Check (Reduce DB Load)

```python
from flask import Flask, jsonify
from sqlalchemy import create_engine, text
from functools import lru_cache
from datetime import datetime, timedelta
import os

app = Flask(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL, pool_pre_ping=True) if DATABASE_URL else None

# Cache health check result for 30 seconds
@lru_cache(maxsize=1)
def cached_db_check(cache_key):
    """Cache database check to reduce load."""
    if not engine:
        return {"status": "not_configured", "error": None}

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "connected", "error": None}
    except Exception as e:
        return {"status": "disconnected", "error": str(e)}

def get_cache_key():
    """Generate cache key that expires every 30 seconds."""
    now = datetime.utcnow()
    return int(now.timestamp() // 30)

@app.route("/health")
def health():
    """Health check with caching to reduce database load."""
    cache_key = get_cache_key()
    db_status = cached_db_check(cache_key)

    status_code = 200 if db_status["status"] == "connected" else 503

    return jsonify({
        "status": "healthy" if db_status["status"] == "connected" else "degraded",
        "database": db_status,
        "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
    }), status_code
```

---

## Railway Configuration

### railway.toml for Health Checks

```toml
[build]
builder = "NIXPACKS"

[deploy]
startCommand = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app"

# Health check configuration
healthcheckPath = "/health"        # Path to health endpoint
healthcheckTimeout = 300           # Timeout in seconds (5 minutes)

# Restart policy
restartPolicyType = "ON_FAILURE"   # Restart only on failure
restartPolicyMaxRetries = 10       # Maximum restart attempts
```

---

## Testing Health Checks

### Local Testing

```bash
# Test health endpoint
curl http://localhost:5000/health

# Test with verbose output
curl -v http://localhost:5000/health

# Test readiness
curl http://localhost:5000/health/ready

# Test liveness
curl http://localhost:5000/health/live

# Test health check response time
time curl http://localhost:5000/health
```

### Production Testing

```bash
# Test Railway deployment
curl https://myapp.railway.app/health

# Test with deployment verification
curl https://myapp.railway.app/health | jq '.version'

# Monitor health check
watch -n 5 'curl -s https://myapp.railway.app/health | jq'
```

---

## Best Practices

1. **Keep it fast** - Health checks should respond in < 1 second
2. **Return simple JSON** - Not HTML or complex payloads
3. **Use 200 for healthy, 503 for unhealthy** - Standard HTTP codes
4. **Include version/deployment ID** - For deployment verification
5. **Cache expensive checks** - Reduce database/external service load
6. **Separate liveness and readiness** - Different purposes
7. **Log health check failures** - For debugging
8. **Don't fail on optional services** - Use degraded mode
9. **Test locally first** - Before deploying to Railway
10. **Monitor health check response time** - In production

---

**Related**: See main skill SKILL.md for deployment patterns
