---
name: railway-deployment
description: "Production-ready Railway.app deployment patterns covering Nixpacks Python builds, health checks, environment variables, WebSocket proxy compatibility, and PaaS state management. Use when: (1) Deploying Python/Node.js apps to Railway, (2) Troubleshooting deployment failures, (3) Configuring health checks, (4) Managing secrets and credentials, (5) WebSocket/Socket.IO setup. Triggers on 'Railway', 'Nixpacks', 'PaaS deployment', 'health check', or 'deployment failure'."
license: Proprietary
---

# Railway Deployment Skill

**Production-ready patterns for Railway.app deployments with Python, Node.js, and WebSocket applications**

Comprehensive knowledge base covering 7 critical Railway deployment patterns learned from production implementations including Nixpacks configuration, health checks, environment management, and proxy compatibility.

## Value Proposition

**Time Saved**: 8-15 hours troubleshooting Railway deployment issues
**Coverage**: Python/Nixpacks, Health Checks, Environment Vars, WebSocket, State Management
**Battle-Tested**: All patterns from production Railway deployments
**Error Prevention**: Avoid common PaaS deployment pitfalls

---

## Quick Reference: Railway Operations

| Operation | Key Concerns | Critical Files |
|-----------|--------------|----------------|
| **Python Deploy** | Virtual environment required | `nixpacks.toml`, `railway.toml` |
| **Health Checks** | Simple JSON endpoint | `/health` route |
| **Secrets** | Base64 encode JSON files | Environment variables |
| **WebSocket** | Use polling transport first | Socket.IO config |
| **State Persistence** | Use external storage | Database/Redis, not class vars |
| **Manual Deploy** | Auto-deploy may fail | `railway up --service` |
| **Monitoring** | Track deployment success | Health endpoint + logs |

---

# TABLE OF CONTENTS

1. [Python & Nixpacks Configuration](#python--nixpacks-configuration)
2. [Health Checks & Monitoring](#health-checks--monitoring)
3. [Environment & Secrets Management](#environment--secrets-management)
4. [WebSocket & Proxy Compatibility](#websocket--proxy-compatibility)
5. [State Management & Worker Restarts](#state-management--worker-restarts)
6. [Deployment Troubleshooting](#deployment-troubleshooting)

---

# PYTHON & NIXPACKS CONFIGURATION

## Pattern 1: Railway Nixpacks Python Deployment Requires Virtual Environment

**Problem**: Railway deployments failing with health check timeouts, "gunicorn: command not found", or "error: externally-managed-environment".

**Root Cause**:
1. Nixpacks may auto-detect wrong provider (Node.js instead of Python)
2. Nix's Python environment is "externally managed" and blocks direct pip installs
3. `railway.toml` startCommand path doesn't match installed dependencies

**Solution**: Force Python provider and use virtual environment in both `nixpacks.toml` and `railway.toml`.

### Configuration Files

**nixpacks.toml**:
```toml
# Force Python provider (prevents Node.js auto-detection)
providers = ["python"]

[phases.setup]
# Install Python 3.11 with pip and virtualenv
nixPkgs = ["python311", "python311Packages.pip", "python311Packages.virtualenv"]

[phases.install]
# Create virtual environment and install dependencies
cmds = [
    "python -m venv /app/venv",
    "/app/venv/bin/pip install --upgrade pip",
    "/app/venv/bin/pip install -r requirements.txt"
]

[start]
# Use venv path for all executables
cmd = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 dashboard.app:app"
```

**railway.toml**:
```toml
[build]
builder = "NIXPACKS"

[deploy]
# MUST match nixpacks.toml venv path
startCommand = "/app/venv/bin/gunicorn --bind 0.0.0.0:$PORT --workers 2 dashboard.app:app"
healthcheckPath = "/health"
healthcheckTimeout = 300
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 10
```

### Key Points

- **Path Consistency**: `railway.toml` startCommand overrides `nixpacks.toml` [start].cmd - both must use `/app/venv/bin/` prefix
- **Virtual Environment**: Required to bypass Nix's externally-managed Python restriction
- **Provider Force**: Explicitly set `providers = ["python"]` to prevent Node.js detection
- **Health Check**: Required for Railway to mark deployment as successful

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `gunicorn: command not found` | Path mismatch between configs | Use `/app/venv/bin/gunicorn` in both files |
| `externally-managed-environment` | Direct pip install without venv | Add `python -m venv /app/venv` |
| Health check timeout | No `/health` endpoint | Add health route (see Pattern 2) |
| Wrong provider detected | Repo has package.json | Add `providers = ["python"]` |

### Alternative: uvicorn for FastAPI

```toml
# For FastAPI applications
[start]
cmd = "/app/venv/bin/uvicorn main:app --host 0.0.0.0 --port $PORT"

[deploy]
startCommand = "/app/venv/bin/uvicorn main:app --host 0.0.0.0 --port $PORT"
```

### Prevention Checklist

- [ ] Create both `nixpacks.toml` and `railway.toml` before first deploy
- [ ] Use virtual environment in Nix-based builds
- [ ] Ensure both config files use identical executable paths
- [ ] Add `/health` endpoint before configuring healthcheckPath
- [ ] Test build locally: `nixpacks build . --name myapp`
- [ ] Verify Railway picks up Python provider (check build logs)

**Related**: See `examples/python-nixpacks.md` for complete configurations

---

# HEALTH CHECKS & MONITORING

## Pattern 2: Flask Dashboard Health Checks Critical for Railway

**Problem**: Railway deployment stuck in "DEPLOYING" state indefinitely.

**Root Cause**: Default health check path "/" returns complex HTML, not a simple health response. Railway times out waiting for healthy status.

**Solution**: Create dedicated `/health` endpoint that returns simple JSON response.

### Flask Implementation

```python
from flask import Flask, jsonify
import os

app = Flask(__name__)

# Feature flags based on environment variables
FULL_FEATURES = all([
    os.getenv('WORDPRESS_API_URL'),
    os.getenv('WORDPRESS_API_USER'),
    os.getenv('WORDPRESS_API_PASS'),
    os.getenv('GA4_PROPERTY_ID')
])

@app.route("/health")
def health():
    """
    Health check endpoint for Railway.

    Returns simple JSON indicating service status.
    Railway polls this endpoint to determine deployment health.
    """
    return jsonify({
        "status": "healthy",
        "service": "dashboard",
        "features": "full" if FULL_FEATURES else "limited",
        "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
    }), 200

@app.route("/")
def index():
    """Main dashboard page (complex, not suitable for health checks)."""
    return render_template("dashboard.html")
```

### FastAPI Implementation

```python
from fastapi import FastAPI
from pydantic import BaseModel
import os

app = FastAPI()

class HealthResponse(BaseModel):
    status: str
    service: str
    features: str
    version: str

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for Railway."""
    return {
        "status": "healthy",
        "service": "api",
        "features": "full" if check_dependencies() else "limited",
        "version": os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
    }

def check_dependencies() -> bool:
    """Check if all required services are configured."""
    required_vars = ["DATABASE_URL", "REDIS_URL", "API_KEY"]
    return all(os.getenv(var) for var in required_vars)
```

### Railway Configuration

```toml
# railway.toml
[deploy]
healthcheckPath = "/health"
healthcheckTimeout = 300  # 5 minutes (adjust for slow cold starts)
```

### Health Check Best Practices

**DO**:
- Return status code 200 for healthy
- Return simple JSON (not HTML)
- Keep response time < 100ms
- Include version/deployment ID
- Check critical dependencies (DB, Redis, etc.)

**DON'T**:
- Use "/" route (too complex)
- Perform expensive operations (external API calls)
- Return HTML or large payloads
- Fail on non-critical service degradation

### Advanced: Database Connection Check

```python
@app.route("/health")
def health():
    """Health check with database validation."""
    db_healthy = False

    try:
        # Quick DB ping (< 1 second timeout)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_healthy = True
    except Exception as e:
        app.logger.error(f"Health check DB error: {e}")

    status_code = 200 if db_healthy else 503

    return jsonify({
        "status": "healthy" if db_healthy else "degraded",
        "database": "connected" if db_healthy else "disconnected",
        "service": "api"
    }), status_code
```

### Troubleshooting Health Checks

| Symptom | Cause | Fix |
|---------|-------|-----|
| Deployment stuck in "DEPLOYING" | No /health endpoint | Add health route |
| Health check timeout | Endpoint too slow (> 30s) | Remove external API calls |
| 404 on health check | Wrong path in railway.toml | Match route path exactly |
| Deployment fails immediately | Health returns 500 | Fix application errors first |

### Prevention Checklist

- [ ] Add `/health` endpoint to all Railway apps
- [ ] Return simple JSON with "status" field
- [ ] Set `healthcheckTimeout` appropriately (300s for slow starts)
- [ ] Test health endpoint locally: `curl http://localhost:8000/health`
- [ ] Monitor health check response time in production
- [ ] Include deployment ID in health response for debugging

**Related**: See `examples/health-checks.md` for complete implementations

---

# ENVIRONMENT & SECRETS MANAGEMENT

## Pattern 3: GA4 Service Account Credentials for PaaS via Base64 Encoding

**Problem**: Google Analytics 4 (GA4) not working on Railway/Heroku because service account JSON file can't be deployed.

**Root Cause**: PaaS platforms don't support file uploads for credentials; environment variables are the only way to pass secrets.

**Solution**: Base64 encode JSON credentials and store in environment variable, then decode in application code.

### Step-by-Step Setup

**1. Create Service Account (Local)**:
```bash
# Create service account via gcloud CLI
gcloud iam service-accounts create my-app-ga4 \
    --display-name="GA4 Analytics for My App" \
    --project=my-project-id

# Grant Analytics permissions
gcloud projects add-iam-policy-binding my-project-id \
    --member="serviceAccount:my-app-ga4@my-project-id.iam.gserviceaccount.com" \
    --role="roles/analytics.viewer"

# Generate credentials JSON file
gcloud iam service-accounts keys create ga4-credentials.json \
    --iam-account=my-app-ga4@my-project-id.iam.gserviceaccount.com
```

**2. Base64 Encode Credentials**:
```bash
# macOS/Linux
base64 -w 0 ga4-credentials.json > ga4-creds-b64.txt

# Windows PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("ga4-credentials.json")) | Out-File ga4-creds-b64.txt
```

**3. Set Railway Environment Variable**:
```bash
# Via Railway CLI
railway variables set GA4_CREDENTIALS_BASE64="$(cat ga4-creds-b64.txt)"

# Or via Railway Dashboard:
# Project → Variables → New Variable
# Name: GA4_CREDENTIALS_BASE64
# Value: <paste base64 string>
```

**4. Decode in Application Code**:

**Python Implementation**:
```python
import base64
import json
import os
from google.oauth2 import service_account
from google.analytics.data_v1beta import BetaAnalyticsDataClient

def get_ga4_client():
    """Initialize GA4 client with base64-encoded credentials."""

    # Get base64-encoded credentials from environment
    creds_base64 = os.getenv("GA4_CREDENTIALS_BASE64")

    if not creds_base64:
        raise ValueError("GA4_CREDENTIALS_BASE64 environment variable not set")

    # Decode base64 to JSON string
    creds_json = base64.b64decode(creds_base64).decode('utf-8')

    # Parse JSON to dictionary
    creds_info = json.loads(creds_json)

    # Create credentials object
    credentials = service_account.Credentials.from_service_account_info(
        creds_info,
        scopes=["https://www.googleapis.com/auth/analytics.readonly"]
    )

    # Initialize GA4 client
    client = BetaAnalyticsDataClient(credentials=credentials)

    return client

# Usage
try:
    ga4_client = get_ga4_client()
    property_id = os.getenv("GA4_PROPERTY_ID")
    # Make GA4 API calls...
except Exception as e:
    print(f"GA4 initialization failed: {e}")
    # Fall back to limited mode
```

**Node.js Implementation**:
```javascript
const { google } = require('googleapis');

function getGA4Client() {
    // Get base64-encoded credentials
    const credsBase64 = process.env.GA4_CREDENTIALS_BASE64;

    if (!credsBase64) {
        throw new Error('GA4_CREDENTIALS_BASE64 not set');
    }

    // Decode base64 to JSON string
    const credsJson = Buffer.from(credsBase64, 'base64').toString('utf-8');

    // Parse JSON
    const credentials = JSON.parse(credsJson);

    // Create JWT auth client
    const auth = new google.auth.JWT({
        email: credentials.client_email,
        key: credentials.private_key,
        scopes: ['https://www.googleapis.com/auth/analytics.readonly']
    });

    return google.analyticsdata({ version: 'v1beta', auth });
}

// Usage
const analytics = getGA4Client();
```

### Security Best Practices

**DO**:
- Add credentials files to `.gitignore` BEFORE creating them
- Use Railway's encrypted environment variables
- Rotate service account keys periodically (every 90 days)
- Use least-privilege IAM roles (analytics.viewer, not owner)
- Delete local credentials file after upload

**DON'T**:
- Commit credentials to Git (check with `git log --all --full-history -- "*credentials*"`)
- Share credentials via Slack/email
- Use personal Google account credentials
- Grant overly broad permissions

### .gitignore Protection

```gitignore
# Google Cloud credentials
ga4-credentials.json
ga4-creds-b64.txt
*-credentials.json
service-account-*.json

# AWS credentials
.aws/
*.pem

# Generic secrets
.env.local
.env.production
secrets/
```

### Validation Function

```python
def is_ga4_configured() -> bool:
    """Check if GA4 credentials are properly configured."""
    try:
        creds_base64 = os.getenv("GA4_CREDENTIALS_BASE64")
        property_id = os.getenv("GA4_PROPERTY_ID")

        if not creds_base64 or not property_id:
            return False

        # Test decode
        creds_json = base64.b64decode(creds_base64).decode('utf-8')
        creds_info = json.loads(creds_json)

        # Validate required fields
        required_fields = ['client_email', 'private_key', 'project_id']
        return all(field in creds_info for field in required_fields)

    except Exception as e:
        print(f"GA4 configuration invalid: {e}")
        return False

# Use in health check
@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "features": "full" if is_ga4_configured() else "limited"
    })
```

### Other Services Using Same Pattern

This pattern works for any JSON-based credentials:

- **Firebase Admin SDK**: `FIREBASE_ADMIN_CREDENTIALS_BASE64`
- **AWS Secrets**: `AWS_CREDENTIALS_BASE64`
- **Stripe Keys**: `STRIPE_CONFIG_BASE64`
- **Database Configs**: `DB_CONFIG_BASE64`

### Prevention Checklist

- [ ] Add credentials files to `.gitignore` BEFORE creating them
- [ ] Use base64 encoding for all JSON credentials
- [ ] Document required environment variables in `README.md`
- [ ] Add `is_configured()` validation function
- [ ] Test credentials locally before Railway deploy
- [ ] Verify Railway environment variables are set (not empty)
- [ ] Use Railway's encrypted variables (not plain text)

**Related**: See `examples/environment-vars.md` for complete credential management patterns

---

# WEBSOCKET & PROXY COMPATIBILITY

## Pattern 4: Socket.IO Transport Order for Railway/Proxy Compatibility

**Problem**: WebSocket connection fails with "Invalid frame header" error on Railway deployment (works fine locally).

**Root Cause**: Railway's proxy corrupts WebSocket upgrade requests when `websocket` transport is tried first. The proxy doesn't properly handle WebSocket handshake headers.

**Solution**: Use `polling` transport first, then upgrade to `websocket` after connection is established.

### Client Configuration

**WRONG** (fails on Railway):
```javascript
import io from 'socket.io-client';

// DEFAULT behavior - tries websocket first
const socket = io('https://myapp.railway.app', {
    transports: ['websocket']  // Fails with proxy!
});
```

**CORRECT** (works on Railway):
```javascript
import io from 'socket.io-client';

const socket = io('https://myapp.railway.app', {
    transports: ['polling', 'websocket'],  // Polling first, then upgrade!
    upgrade: true,
    forceNew: true
});
```

### Complete Socket.IO Configuration

**Client (React/Vue/vanilla JS)**:
```javascript
import io from 'socket.io-client';

const WS_BASE_URL = import.meta.env.VITE_WS_URL || 'http://localhost:3000';

// Socket.IO client with Railway-compatible settings
const socket = io(`${WS_BASE_URL}/shared-sessions`, {
    // CRITICAL: Polling first for proxy compatibility
    transports: ['polling', 'websocket'],

    // Connection behavior
    upgrade: true,              // Upgrade to WebSocket after polling connects
    forceNew: true,             // Create new connection (don't reuse)

    // Reconnection settings (see Pattern 5)
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,

    // Timeouts
    timeout: 15000,             // Initial connection timeout

    // Debugging (remove in production)
    // transports: ['polling'],  // Force polling-only for testing
});

// Event handlers
socket.on('connect', () => {
    console.log('Connected via', socket.io.engine.transport.name);
    // Will log "polling" initially, then "websocket" after upgrade
});

socket.on('upgrade', (transport) => {
    console.log('Upgraded to', transport.name);  // "websocket"
});

socket.on('connect_error', (error) => {
    console.error('Connection error:', error);
});
```

**Server (Node.js)**:
```javascript
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: process.env.FRONTEND_URL || '*',
        methods: ['GET', 'POST']
    },

    // Match client transports order
    transports: ['polling', 'websocket'],

    // Ping/pong to keep connections alive
    pingInterval: 25000,
    pingTimeout: 20000,

    // Cookie-based session affinity (for Railway multi-instance)
    cookie: {
        name: 'io',
        httpOnly: true,
        sameSite: 'lax'
    }
});

// Namespace for shared sessions
const sharedSessionsNs = io.of('/shared-sessions');

sharedSessionsNs.on('connection', (socket) => {
    console.log('Client connected:', socket.id);
    console.log('Transport:', socket.conn.transport.name);

    // Handle events
    socket.on('join_session', (sessionId) => {
        socket.join(sessionId);
        console.log(`Socket ${socket.id} joined session ${sessionId}`);
    });

    socket.on('disconnect', (reason) => {
        console.log('Client disconnected:', reason);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

### Railway-Specific Considerations

**1. Environment Variables**:
```bash
# Railway environment variables
FRONTEND_URL=https://myapp-frontend.railway.app
PORT=3000  # Railway assigns this automatically
NODE_ENV=production
```

**2. Package Versions**:
```json
{
  "dependencies": {
    "socket.io": "^4.6.0",        // Server
    "socket.io-client": "^4.6.0"  // Client (match major version!)
  }
}
```

**3. CORS Configuration**:
```javascript
// Allow Railway preview deployments
const allowedOrigins = [
    'https://myapp.railway.app',
    /\.railway\.app$/,  // All Railway preview URLs
    'http://localhost:5173'  // Local dev
];

io.on('connection', (socket) => {
    const origin = socket.handshake.headers.origin;
    if (!allowedOrigins.some(allowed =>
        typeof allowed === 'string' ? allowed === origin : allowed.test(origin)
    )) {
        socket.disconnect(true);
    }
});
```

### Testing Transport Upgrade

**Client-side logging**:
```javascript
socket.io.on("ping", () => {
    console.log(`Ping via ${socket.io.engine.transport.name}`);
});

socket.io.on("pong", (latency) => {
    console.log(`Pong latency: ${latency}ms`);
});

// Log all transport changes
socket.io.engine.on("upgrade", (transport) => {
    console.log("Transport upgraded from",
        socket.io.engine.transport.name,
        "to",
        transport.name
    );
});
```

### Debugging Connection Issues

**Force polling-only mode** (for testing):
```javascript
// Client
const socket = io(url, {
    transports: ['polling']  // Remove websocket
});
```

**Check Railway logs**:
```bash
railway logs --service backend | grep -i websocket
railway logs --service backend | grep -i socket.io
```

### Prevention Checklist

- [ ] Always use `['polling', 'websocket']` transport order for PaaS
- [ ] Match Socket.IO versions between client and server
- [ ] Test WebSocket connections on actual Railway deployment (not just localhost)
- [ ] Add transport upgrade event handlers
- [ ] Configure CORS to allow Railway preview URLs
- [ ] Monitor connection transport in production logs

**Related**: See `examples/websocket-patterns.md` for complete Socket.IO implementations

---

# STATE MANAGEMENT & WORKER RESTARTS

## Pattern 5: Class Variables Reset on Worker Restart - Use External State

**Problem**: All WordPress posts assigned to the same author (Ruby, ID 2) instead of rotating through 7 avatar authors.

**Root Cause**: Author round-robin used a class variable `_writer_index = 0` that reset to 0 whenever the worker restarted. Since PaaS platforms (Railway, Heroku) restart workers periodically (daily, on deploy, on crash), the index always started at 0.

**Solution**: Use external state (database count, API header, Redis) instead of in-memory counters for anything that must persist across restarts.

### Problem Example

**BROKEN** (resets on restart):
```python
class WordPressPublisher:
    """WordPress publisher with broken round-robin."""

    WRITER_IDS = [2, 3, 4, 5, 6, 7, 8]  # 7 avatar authors
    _writer_index = 0  # ⚠️ RESETS ON EVERY WORKER RESTART!

    def get_next_writer_id(self) -> int:
        """Get next author ID (BROKEN - always starts at index 0)."""
        writer_id = self.WRITER_IDS[self._writer_index % len(self.WRITER_IDS)]
        self._writer_index += 1
        return writer_id
```

**Result**: After every restart, index resets to 0, so Ruby (ID 2) gets assigned to every post published immediately after restart.

### Solution 1: Use External API Count

**FIXED** (persists across restarts):
```python
class WordPressPublisher:
    """WordPress publisher with persistent round-robin."""

    WRITER_IDS = [2, 3, 4, 5, 6, 7, 8]  # 7 avatar authors

    def _get_total_post_count(self) -> int:
        """Get total published count from WordPress API."""
        response = requests.head(
            f"{self.api_base}/posts",
            auth=(self.username, self.password),
            params={"status": "publish", "per_page": 1}
        )

        # WordPress returns total count in X-WP-Total header
        return int(response.headers.get('X-WP-Total', 0))

    def get_next_writer_id(self) -> int:
        """
        Get next author ID using external state.

        Uses total post count from API for deterministic round-robin
        that persists across worker restarts.
        """
        post_count = self._get_total_post_count()
        writer_index = post_count % len(self.WRITER_IDS)
        writer_id = self.WRITER_IDS[writer_index]

        logger.info(f"Post #{post_count} → Writer index {writer_index} → ID {writer_id}")

        return writer_id
```

**Why This Works**: WordPress API count is external state stored in database. Even if worker restarts, the count remains accurate.

### Solution 2: Use Database Counter

```python
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker

class RoundRobinCounter(Base):
    """Database table for persistent counters."""
    __tablename__ = 'round_robin_counters'

    name = Column(String, primary_key=True)
    count = Column(Integer, default=0)

class WordPressPublisher:
    WRITER_IDS = [2, 3, 4, 5, 6, 7, 8]

    def __init__(self, db_session):
        self.db = db_session

    def get_next_writer_id(self) -> int:
        """Get next author ID using database counter."""

        # Get or create counter
        counter = self.db.query(RoundRobinCounter).filter_by(
            name='writer_rotation'
        ).first()

        if not counter:
            counter = RoundRobinCounter(name='writer_rotation', count=0)
            self.db.add(counter)

        # Get current writer and increment
        writer_index = counter.count % len(self.WRITER_IDS)
        writer_id = self.WRITER_IDS[writer_index]

        counter.count += 1
        self.db.commit()

        return writer_id
```

### Solution 3: Use Redis

```python
import redis
from typing import List

class WordPressPublisher:
    WRITER_IDS = [2, 3, 4, 5, 6, 7, 8]

    def __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url)

    def get_next_writer_id(self) -> int:
        """Get next author ID using Redis counter."""

        # Increment counter (creates if doesn't exist, starting at 0)
        count = self.redis.incr('writer_rotation_count')

        # Calculate index (count is 1-indexed after incr)
        writer_index = (count - 1) % len(self.WRITER_IDS)
        writer_id = self.WRITER_IDS[writer_index]

        return writer_id
```

### When to Use Each Approach

| Approach | Best For | Pros | Cons |
|----------|----------|------|------|
| **External API** | Small-scale, existing API | No extra infrastructure | API call overhead |
| **Database Counter** | Medium-scale, existing DB | Transactional, reliable | DB connection required |
| **Redis** | High-scale, low-latency | Fast, atomic operations | Extra service dependency |
| **Class Variable** | ❌ Never use for persistent state | Simple | ⚠️ Resets on restart! |

### Other State That Needs External Storage

**DO NOT use class/instance variables for**:
- Round-robin counters
- Rate limit tracking
- Session state
- Cache that must persist
- User preferences
- Feature flags
- Job queues

**OK to use class/instance variables for**:
- Configuration loaded at startup (immutable)
- Read-only reference data
- Temporary computation state (within single request)
- Logging instances

### Testing Worker Restarts

**Simulate restart locally**:
```bash
# Terminal 1: Run worker
python worker.py

# Terminal 2: Monitor state
curl http://localhost:8000/api/next-writer

# Terminal 1: Stop with Ctrl+C, restart
python worker.py

# Terminal 2: Check if state persisted
curl http://localhost:8000/api/next-writer
```

**Railway restart simulation**:
```bash
# Force restart on Railway
railway service restart --service backend

# Check logs for state continuity
railway logs --service backend | grep "Writer index"
```

### Prevention Checklist

- [ ] Never use class/instance variables for state that must persist across restarts
- [ ] Use database, Redis, or external API for counters/state
- [ ] Test worker behavior after simulated restart
- [ ] Document which state is ephemeral vs persistent
- [ ] Add startup logs showing state initialization
- [ ] Monitor state continuity in production logs

**Related**: See `examples/state-management.md` for complete patterns

---

# DEPLOYMENT TROUBLESHOOTING

## Pattern 6: Railway May Require Manual Deploy Trigger

**Problem**: Pushed changes to main branch, but Railway still shows old code/behavior.

**Root Cause**: Railway's auto-deploy can fail silently or not trigger for some commits. The dashboard may show deployment as "successful" when it didn't actually pick up latest changes.

**Solution**: Force deploy with Railway CLI and verify deployment logs.

### Force Deploy with Railway CLI

```bash
# 1. Ensure Railway CLI is installed and logged in
railway login

# 2. Link to correct project (if not already)
railway link

# 3. Force deploy with specific service
railway up --service backend --detach

# 4. Verify deployment logs
railway logs --service backend | head -50

# 5. Check deployment ID matches latest commit
railway logs --service backend | grep "RAILWAY_GIT_COMMIT_SHA"
```

### Verify Deployment Success

**Check commit hash**:
```bash
# Get latest commit hash locally
git rev-parse HEAD

# Compare with Railway deployment
railway run --service backend printenv RAILWAY_GIT_COMMIT_SHA
```

**Test health endpoint**:
```bash
# Check if deployment is actually live
curl https://myapp-backend.railway.app/health

# Expected response:
# {
#   "status": "healthy",
#   "version": "abc123def",  # Should match git commit hash
#   "deployed_at": "2026-01-15T10:30:00Z"
# }
```

### Add Deployment ID to Health Endpoint

**Enhanced health check**:
```python
import os
from datetime import datetime

@app.route("/health")
def health():
    """Health check with deployment verification."""
    return jsonify({
        "status": "healthy",
        "service": "backend",
        "deployment_id": os.getenv("RAILWAY_DEPLOYMENT_ID", "unknown"),
        "commit_sha": os.getenv("RAILWAY_GIT_COMMIT_SHA", "unknown"),
        "deployed_at": os.getenv("RAILWAY_DEPLOYMENT_DATE", "unknown"),
        "environment": os.getenv("RAILWAY_ENVIRONMENT", "unknown"),
        "timestamp": datetime.utcnow().isoformat()
    })
```

### Alternative: Redeploy via Railway Dashboard

1. Go to Railway Dashboard
2. Navigate to project
3. Click on service (e.g., "backend")
4. Go to "Deployments" tab
5. Click three dots on latest deployment
6. Select "Redeploy"

### Post-Deploy Smoke Tests

**Create post-deploy script**:
```bash
#!/bin/bash
# scripts/verify-deploy.sh

set -e

SERVICE_URL="https://myapp-backend.railway.app"
EXPECTED_COMMIT=$(git rev-parse HEAD | cut -c1-7)

echo "🔍 Verifying deployment..."

# 1. Check health endpoint
HEALTH=$(curl -s "$SERVICE_URL/health")
STATUS=$(echo $HEALTH | jq -r '.status')

if [ "$STATUS" != "healthy" ]; then
    echo "❌ Health check failed: $STATUS"
    exit 1
fi

# 2. Verify commit hash
DEPLOYED_COMMIT=$(echo $HEALTH | jq -r '.commit_sha' | cut -c1-7)

if [ "$DEPLOYED_COMMIT" != "$EXPECTED_COMMIT" ]; then
    echo "⚠️  WARNING: Deployed commit ($DEPLOYED_COMMIT) doesn't match local ($EXPECTED_COMMIT)"
    echo "📋 Triggering manual deploy..."
    railway up --service backend --detach
    exit 1
fi

echo "✅ Deployment verified: commit $DEPLOYED_COMMIT"
```

**Add to CI/CD**:
```yaml
# .github/workflows/deploy.yml
name: Deploy and Verify

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Railway CLI
        run: npm install -g @railway/cli

      - name: Deploy to Railway
        env:
          RAILWAY_TOKEN: ${{ secrets.RAILWAY_TOKEN }}
        run: railway up --service backend --detach

      - name: Wait for deployment
        run: sleep 30

      - name: Verify deployment
        run: ./scripts/verify-deploy.sh
```

### Common Auto-Deploy Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Old code still running | Auto-deploy didn't trigger | `railway up --service <name>` |
| "Successful" but wrong version | Deployment ID not incremented | Force redeploy via dashboard |
| Changes not reflected | Cached build | Clear build cache, redeploy |
| Health check passes but old code | Multiple deployments running | Check active deployment in dashboard |

### Prevention Checklist

- [ ] Always verify deployment with health endpoint after push
- [ ] Use `railway up --service <name>` for critical deploys
- [ ] Check Railway deployment logs for actual commit hash
- [ ] Add post-deploy smoke tests that hit production endpoints
- [ ] Include deployment ID in health check response
- [ ] Monitor deployment success rate
- [ ] Set up alerts for deployment failures

**Related**: See `examples/deployment-verification.md` for complete CI/CD setup

---

## Pattern 7: Graceful Degradation with Limited Mode

**Problem**: Application crashes when external dependencies (WordPress API, GA4) are unavailable.

**Root Cause**: Missing environment variables or service outages cause hard failures instead of graceful degradation.

**Solution**: Implement "limited mode" that allows core functionality to work even when optional services are down.

### Feature Flag Pattern

```python
import os
from typing import Optional

class FeatureFlags:
    """Feature flags based on environment configuration."""

    def __init__(self):
        self._wordpress_available = self._check_wordpress()
        self._ga4_available = self._check_ga4()
        self._email_available = self._check_email()

    def _check_wordpress(self) -> bool:
        """Check if WordPress is configured."""
        required = ['WORDPRESS_API_URL', 'WORDPRESS_API_USER', 'WORDPRESS_API_PASS']
        return all(os.getenv(var) for var in required)

    def _check_ga4(self) -> bool:
        """Check if GA4 is configured."""
        return bool(os.getenv('GA4_CREDENTIALS_BASE64') and os.getenv('GA4_PROPERTY_ID'))

    def _check_email(self) -> bool:
        """Check if email is configured."""
        return bool(os.getenv('SENDGRID_API_KEY'))

    @property
    def wordpress_enabled(self) -> bool:
        return self._wordpress_available

    @property
    def analytics_enabled(self) -> bool:
        return self._ga4_available

    @property
    def email_enabled(self) -> bool:
        return self._email_available

    @property
    def full_features(self) -> bool:
        """All features enabled."""
        return all([
            self._wordpress_available,
            self._ga4_available,
            self._email_available
        ])

# Global instance
features = FeatureFlags()
```

### Use in Application

```python
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route("/health")
def health():
    """Health check with feature status."""
    return jsonify({
        "status": "healthy",
        "mode": "full" if features.full_features else "limited",
        "features": {
            "wordpress": features.wordpress_enabled,
            "analytics": features.analytics_enabled,
            "email": features.email_enabled
        }
    })

@app.route("/api/publish", methods=["POST"])
def publish_content():
    """Publish content with graceful degradation."""
    data = request.json

    # Core functionality (always works)
    content_id = save_to_database(data)

    # Optional: Publish to WordPress
    if features.wordpress_enabled:
        try:
            publish_to_wordpress(data)
        except Exception as e:
            logger.error(f"WordPress publish failed: {e}")
            # Continue anyway - content is saved locally

    # Optional: Track analytics
    if features.analytics_enabled:
        try:
            track_ga4_event("content_published", {"content_id": content_id})
        except Exception as e:
            logger.warning(f"Analytics tracking failed: {e}")
            # Continue anyway

    # Optional: Send notification
    if features.email_enabled:
        try:
            send_notification_email(data)
        except Exception as e:
            logger.warning(f"Email notification failed: {e}")
            # Continue anyway

    return jsonify({
        "success": True,
        "content_id": content_id,
        "wordpress_published": features.wordpress_enabled,
        "analytics_tracked": features.analytics_enabled,
        "email_sent": features.email_enabled
    })
```

### Environment Variable Documentation

**README.md**:
```markdown
## Environment Variables

### Required (Core Functionality)
- `DATABASE_URL` - PostgreSQL connection string
- `SECRET_KEY` - Flask session secret

### Optional (Full Features)

#### WordPress Integration
- `WORDPRESS_API_URL` - WordPress REST API base URL
- `WORDPRESS_API_USER` - WordPress username
- `WORDPRESS_API_PASS` - WordPress application password

#### Google Analytics 4
- `GA4_CREDENTIALS_BASE64` - Base64-encoded service account JSON
- `GA4_PROPERTY_ID` - GA4 property ID

#### Email Notifications
- `SENDGRID_API_KEY` - SendGrid API key
- `FROM_EMAIL` - Sender email address

### Feature Modes

**Full Mode** (all optional vars set):
- Content published to WordPress
- Analytics tracking
- Email notifications

**Limited Mode** (optional vars missing):
- Content saved to local database only
- No external integrations
- Core functionality works
```

### Prevention Checklist

- [ ] Implement feature flags for all optional services
- [ ] Test application startup with missing environment variables
- [ ] Return helpful error messages in limited mode
- [ ] Document required vs optional environment variables
- [ ] Add health endpoint showing enabled features
- [ ] Log warnings (not errors) for disabled features

---

# COMPLETE IMPLEMENTATION CHECKLIST

## Pre-Deployment Checklist

**Configuration Files**:
- [ ] `nixpacks.toml` created with Python provider and venv
- [ ] `railway.toml` created with matching startCommand
- [ ] `requirements.txt` includes all dependencies
- [ ] `.gitignore` excludes credentials and secrets

**Health Checks**:
- [ ] `/health` endpoint returns simple JSON
- [ ] Health endpoint responds < 1 second
- [ ] `healthcheckPath` configured in railway.toml
- [ ] `healthcheckTimeout` set appropriately (300s for slow starts)

**Environment Variables**:
- [ ] All required vars documented in README
- [ ] Credentials base64-encoded (not committed to Git)
- [ ] Feature flags check for optional vars
- [ ] Railway variables set via CLI or dashboard

**WebSocket (if applicable)**:
- [ ] Transport order: `['polling', 'websocket']`
- [ ] Socket.IO versions match between client/server
- [ ] CORS configured for Railway URLs
- [ ] Reconnection handlers implemented

**State Management**:
- [ ] No class variables for persistent state
- [ ] External storage (DB/Redis/API) used for counters
- [ ] Tested after worker restart simulation

**Deployment Verification**:
- [ ] `railway up --service <name>` tested
- [ ] Health endpoint includes deployment ID
- [ ] Post-deploy smoke tests pass
- [ ] Logs show correct commit hash

---

# TROUBLESHOOTING GUIDE

## Common Railway Deployment Issues

### Issue 1: Health Check Timeout
```
Symptom: Deployment stuck in "DEPLOYING" indefinitely
Solution: Add /health endpoint, set healthcheckTimeout=300
Reference: Pattern 2
```

### Issue 2: gunicorn: command not found
```
Symptom: Build succeeds but startup fails
Solution: Use /app/venv/bin/gunicorn in both nixpacks.toml and railway.toml
Reference: Pattern 1
```

### Issue 3: WebSocket Invalid Frame Header
```
Symptom: Socket.IO works locally but fails on Railway
Solution: Change transports to ['polling', 'websocket']
Reference: Pattern 4
```

### Issue 4: State Resets After Deploy
```
Symptom: Round-robin counters, session state resets
Solution: Use database/Redis instead of class variables
Reference: Pattern 5
```

### Issue 5: Old Code Still Running
```
Symptom: Pushed changes but Railway shows old behavior
Solution: railway up --service <name> to force deploy
Reference: Pattern 6
```

### Issue 6: Credentials Not Loading
```
Symptom: GA4/Firebase fails with authentication errors
Solution: Base64 encode JSON and set GA4_CREDENTIALS_BASE64
Reference: Pattern 3
```

---

# FILE REFERENCES

- `examples/python-nixpacks.md` - Complete Nixpacks configurations for Python/FastAPI
- `examples/health-checks.md` - Health check implementations for all frameworks
- `examples/environment-vars.md` - Complete credential management patterns
- `examples/websocket-patterns.md` - Socket.IO configuration examples
- `examples/state-management.md` - External state management patterns
- `examples/deployment-verification.md` - CI/CD and smoke test setups

---

# ADDITIONAL RESOURCES

## Official Documentation
- [Railway Docs](https://docs.railway.app/)
- [Nixpacks Documentation](https://nixpacks.com/)
- [Socket.IO Documentation](https://socket.io/docs/v4/)
- [Google Cloud Service Accounts](https://cloud.google.com/iam/docs/service-accounts)

## Related Skills
- `error-handling-excellence` - Error handling and retries
- `api-patterns` - Generic API integration patterns
- `security-owasp` - Security best practices
- `deployment-lifecycle` - General deployment workflows

---

**End of Railway Deployment Skill**

*Last Updated: 2026-02-06*
*Source: 7 production lessons from multi-agent-flow-content-pipeline and enterprise-translation-system*
