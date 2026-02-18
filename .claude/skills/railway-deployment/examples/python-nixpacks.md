# Python Nixpacks Configuration Examples

Complete Nixpacks configurations for Python applications on Railway.

---

## Table of Contents

1. [Flask Applications](#flask-applications)
2. [FastAPI Applications](#fastapi-applications)
3. [Django Applications](#django-applications)
4. [Common Patterns](#common-patterns)

---

## Flask Applications

### Basic Flask App

**Project Structure**:
```
my-flask-app/
├── app.py
├── requirements.txt
├── nixpacks.toml
└── railway.toml
```

**app.py**:
```python
from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({"status": "healthy"})

@app.route("/")
def index():
    return jsonify({"message": "Hello Railway!"})

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
```

**requirements.txt**:
```
Flask==3.0.0
gunicorn==21.2.0
```

**nixpacks.toml**:
```toml
providers = ["python"]

[phases.setup]
nixPkgs = ["python311", "python311Packages.pip", "python311Packages.virtualenv"]

[phases.install]
cmds = [
    "python -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    "/app/venv/bin/pip install -r requirements.txt"
]

[start]
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app"
```

**railway.toml**:
```toml
[build]
builder = "NIXPACKS"

[deploy]
startCommand = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app"
healthcheckPath = "/health"
healthcheckTimeout = 300
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 10
```

---

### Flask with Database

**requirements.txt**:
```
Flask==3.0.0
gunicorn==21.2.0
psycopg2-binary==2.9.9
SQLAlchemy==2.0.23
alembic==1.13.0
```

**nixpacks.toml**:
```toml
providers = ["python"]

[phases.setup]
nixPkgs = [
    "python311",
    "python311Packages.pip",
    "python311Packages.virtualenv",
    "postgresql"  # Required for psycopg2
]

[phases.install]
cmds = [
    "python -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    "/app/venv/bin/pip install -r requirements.txt"
]

# Optional: Run migrations before starting
[phases.setup.postInstall]
cmds = [
    "/app/venv/bin/alembic upgrade head"
]

[start]
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 --timeout 120 app:app"
```

---

## FastAPI Applications

### Basic FastAPI App

**Project Structure**:
```
my-fastapi-app/
├── main.py
├── requirements.txt
├── nixpacks.toml
└── railway.toml
```

**main.py**:
```python
from fastapi import FastAPI
from pydantic import BaseModel
import os

app = FastAPI()

class HealthResponse(BaseModel):
    status: str
    version: str

@app.get("/health", response_model=HealthResponse)
async def health_check():
    return {
        "status": "healthy",
        "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
    }

@app.get("/")
async def root():
    return {"message": "Hello Railway!"}
```

**requirements.txt**:
```
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
```

**nixpacks.toml**:
```toml
providers = ["python"]

[phases.setup]
nixPkgs = ["python311", "python311Packages.pip", "python311Packages.virtualenv"]

[phases.install]
cmds = [
    "python -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    "/app/venv/bin/pip install -r requirements.txt"
]

[start]
# uvicorn with auto-reload disabled for production
cmd = "/app/venv/bin/uvicorn main:app --host 0.0.0.0 --port $PORT --workers 2"
```

**railway.toml**:
```toml
[build]
builder = "NIXPACKS"

[deploy]
startCommand = "/app/venv/bin/uvicorn main:app --host 0.0.0.0 --port $PORT --workers 2"
healthcheckPath = "/health"
healthcheckTimeout = 300
```

---

### FastAPI with WebSocket Support

**requirements.txt**:
```
fastapi==0.109.0
uvicorn[standard]==0.27.0
websockets==12.0
python-socketio==5.11.0
```

**nixpacks.toml**:
```toml
providers = ["python"]

[phases.setup]
nixPkgs = ["python311", "python311Packages.pip", "python311Packages.virtualenv"]

[phases.install]
cmds = [
    "python -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    "/app/venv/bin/pip install -r requirements.txt"
]

[start]
# Use single worker for WebSocket (worker_class: uvicorn.workers.UvicornWorker)
cmd = "/app/venv/bin/uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1 --timeout-keep-alive 65"
```

**Key Points**:
- Use `--workers 1` for WebSocket (sticky sessions)
- Increase `--timeout-keep-alive` to 65s for long-polling
- Consider using Gunicorn with Uvicorn worker for production:

```toml
[start]
cmd = "/app/venv/bin/gunicorn main:app --workers 1 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 120"
```

---

## Django Applications

### Django with PostgreSQL

**requirements.txt**:
```
Django==5.0.1
gunicorn==21.2.0
psycopg2-binary==2.9.9
whitenoise==6.6.0
```

**nixpacks.toml**:
```toml
providers = ["python"]

[phases.setup]
nixPkgs = [
    "python311",
    "python311Packages.pip",
    "python311Packages.virtualenv",
    "postgresql"
]

[phases.install]
cmds = [
    "python -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    "/app/venv/bin/pip install -r requirements.txt"
]

[phases.build]
cmds = [
    "/app/venv/bin/python manage.py collectstatic --noinput"
]

[start]
cmd = "/app/venv/bin/gunicorn myproject.wsgi:application --bind 0.0.0.0:$PORT --workers 3"
```

**railway.toml**:
```toml
[build]
builder = "NIXPACKS"

[deploy]
# Run migrations before starting server
startCommand = "/app/venv/bin/python manage.py migrate && /app/venv/bin/gunicorn myproject.wsgi:application --bind 0.0.0.0:$PORT --workers 3"
healthcheckPath = "/health/"
healthcheckTimeout = 300
```

**settings.py (Railway-specific)**:
```python
import os
import dj_database_url

# Use Railway's DATABASE_URL
DATABASES = {
    'default': dj_database_url.config(
        default=os.getenv('DATABASE_URL'),
        conn_max_age=600
    )
}

# Use WhiteNoise for static files
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Add this
    # ... other middleware
]

STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
```

---

## Common Patterns

### Multi-Stage Build with Testing

```toml
providers = ["python"]

[phases.setup]
nixPkgs = ["python311", "python311Packages.pip", "python311Packages.virtualenv"]

[phases.install]
cmds = [
    "python -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    "/app/venv/bin/pip install -r requirements.txt"
]

# Optional: Run tests before deploying
[phases.test]
cmds = [
    "/app/venv/bin/pytest tests/ -v --cov=app --cov-report=term-missing"
]

[start]
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app"
```

---

### With Environment-Specific Dependencies

**requirements.txt** (production):
```
Flask==3.0.0
gunicorn==21.2.0
psycopg2-binary==2.9.9
```

**requirements-dev.txt** (development):
```
-r requirements.txt
pytest==7.4.3
pytest-cov==4.1.0
black==23.12.1
flake8==7.0.0
```

**nixpacks.toml**:
```toml
providers = ["python"]

[phases.setup]
nixPkgs = ["python311", "python311Packages.pip", "python311Packages.virtualenv"]

[phases.install]
cmds = [
    "python -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    # Only install production requirements
    "/app/venv/bin/pip install -r requirements.txt"
]

[start]
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app"
```

---

### With Custom Python Version

```toml
providers = ["python"]

[phases.setup]
# Use Python 3.12 instead of 3.11
nixPkgs = ["python312", "python312Packages.pip", "python312Packages.virtualenv"]

[phases.install]
cmds = [
    "python3.12 -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    "/app/venv/bin/pip install -r requirements.txt"
]

[start]
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app"
```

---

### With Build-Time Environment Variables

```toml
providers = ["python"]

[phases.setup]
nixPkgs = ["python311", "python311Packages.pip", "python311Packages.virtualenv"]

[phases.install]
cmds = [
    "python -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    "/app/venv/bin/pip install -r requirements.txt"
]

[phases.build]
# Set environment variable during build
cmds = [
    "export BUILD_ENV=production",
    "/app/venv/bin/python setup.py build"
]

[start]
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app"
```

---

### With Native Dependencies (e.g., Pillow, NumPy)

```toml
providers = ["python"]

[phases.setup]
nixPkgs = [
    "python311",
    "python311Packages.pip",
    "python311Packages.virtualenv",
    "libjpeg",      # For Pillow
    "zlib",         # For Pillow
    "freetype",     # For Pillow
    "gcc",          # For NumPy/SciPy
    "gfortran"      # For NumPy/SciPy
]

[phases.install]
cmds = [
    "python -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    "/app/venv/bin/pip install -r requirements.txt"
]

[start]
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 app:app"
```

---

## Gunicorn Configuration Options

### Worker Types

```toml
# Sync workers (default, CPU-bound)
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 --worker-class sync app:app"

# Async workers (I/O-bound)
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 --worker-class gevent app:app"

# Uvicorn workers (for ASGI apps)
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 --worker-class uvicorn.workers.UvicornWorker app:app"
```

### Timeouts and Limits

```toml
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT \
    --workers 2 \
    --timeout 120 \              # Request timeout (seconds)
    --graceful-timeout 30 \      # Graceful shutdown timeout
    --keep-alive 5 \             # Keep-alive connections
    --max-requests 1000 \        # Restart workers after N requests
    --max-requests-jitter 50 \   # Randomize max-requests
    app:app"
```

### Logging

```toml
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT \
    --workers 2 \
    --access-logfile - \         # Log to stdout
    --error-logfile - \          # Log errors to stdout
    --log-level info \           # info, debug, warning, error
    app:app"
```

---

## Troubleshooting

### Issue: "python: command not found"

**Cause**: Wrong Python package name
**Fix**: Use `python311` not `python` in nixPkgs

```toml
[phases.setup]
nixPkgs = ["python311"]  # Not "python"
```

### Issue: "pip install fails with permission denied"

**Cause**: Not using virtual environment
**Fix**: Add venv creation step

```toml
[phases.install]
cmds = [
    "python -m venv /app/venv",  # Create venv first
    "/app/venv/bin/pip install -r requirements.txt"
]
```

### Issue: "Module not found" errors

**Cause**: Wrong PYTHONPATH or package structure
**Fix**: Set PYTHONPATH in start command

```toml
[start]
cmd = "PYTHONPATH=/app /app/venv/bin/gunicorn app:app --bind 0.0.0.0:$PORT"
```

### Issue: Workers crashing under load

**Cause**: Not enough workers or wrong worker class
**Fix**: Tune worker count (2-4 x CPU cores) and use async workers

```toml
[start]
# For I/O-bound apps
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 4 --worker-class gevent app:app"
```

---

## Best Practices

1. **Always use virtual environment** - Required for Nix Python
2. **Match paths in both configs** - nixpacks.toml and railway.toml must match
3. **Use explicit Python version** - `python311` not `python`
4. **Add health check endpoint** - Required for Railway deployment success
5. **Set appropriate timeouts** - 120s for long-running requests
6. **Use worker limits** - Prevent memory leaks with `--max-requests`
7. **Enable logging** - Log to stdout for Railway log collection
8. **Test build locally** - `nixpacks build . --name myapp`

---

**Related**: See main skill SKILL.md for deployment patterns
