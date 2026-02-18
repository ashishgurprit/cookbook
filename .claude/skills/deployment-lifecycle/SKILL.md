# Deployment Lifecycle - Expert Production Regimen

> Expert-recommended practices for development, testing, staging, production deployment, and post-production operations.

**Version**: 1.0.0
**Last Updated**: 2026-01-18
**Applies To**: All production applications

---

## Table of Contents

1. [Development Environment](#1-development-environment)
2. [Testing Strategy](#2-testing-strategy)
3. [Staging Environment](#3-staging-environment)
4. [Production Deployment](#4-production-deployment)
5. [Post-Production Operations](#5-post-production-operations)
6. [Version Control](#6-version-control)
7. [Rollback Procedures](#7-rollback-procedures)
8. [CI/CD Pipeline](#8-cicd-pipeline)
9. [Troubleshooting Guide](#9-troubleshooting-guide)
10. [Checklists](#10-checklists)

---

## 1. Development Environment

### 1.1 Local Development Setup

**Goal**: Identical to production environment (parity)

**12-Factor App Principles**:
```bash
# Development should match production
- Same OS (use Docker/containers)
- Same runtime versions (Node 18.x, Python 3.11, etc.)
- Same database (PostgreSQL 15, not SQLite)
- Same cache (Redis, not in-memory)
- Same environment variables (.env.local)
```

**Environment Parity Checklist**:
- [ ] Use Docker Compose for local development
- [ ] Pin all dependency versions (package-lock.json, poetry.lock)
- [ ] Use production-like database locally
- [ ] Mock external APIs with identical contracts
- [ ] Use environment variables for all configuration
- [ ] Never commit .env files (use .env.example)

**Example Docker Compose**:
```yaml
version: '3.8'
services:
  app:
    build: .
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://user:pass@db:5432/myapp_dev
    volumes:
      - .:/app
      - /app/node_modules
    ports:
      - "3000:3000"

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: myapp_dev
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### 1.2 Feature Development Workflow

**Branch Strategy** (Git Flow):
```
main (production)
├── develop (integration)
│   ├── feature/user-auth (feature branches)
│   ├── feature/payment-gateway
│   └── bugfix/login-error
└── hotfix/critical-security-patch (emergency fixes)
```

**Development Process**:
1. **Create feature branch**:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/user-authentication
   ```

2. **Write failing test first (TDD)**:
   ```python
   def test_user_can_login():
       """User should be able to login with email and password"""
       response = client.post('/auth/login', json={
           'email': 'user@example.com',
           'password': 'SecurePass123!'
       })
       assert response.status_code == 200
       assert 'access_token' in response.json()
   ```

3. **Implement feature**:
   ```python
   @app.post('/auth/login')
   def login(credentials: LoginRequest):
       user = authenticate(credentials.email, credentials.password)
       if not user:
           raise HTTPException(status_code=401, detail="Invalid credentials")
       token = generate_jwt(user.id)
       return {'access_token': token}
   ```

4. **Verify test passes**:
   ```bash
   pytest tests/test_auth.py -v
   ```

5. **Commit with conventional commits**:
   ```bash
   git add .
   git commit -m "feat: add user authentication endpoint

   - Implement JWT-based authentication
   - Add password hashing with bcrypt
   - Add rate limiting (5 attempts per minute)
   - Add security tests

   Closes #123"
   ```

### 1.3 Code Quality Gates

**Pre-commit Checks**:
```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: detect-private-key  # CRITICAL: No secrets in code

  - repo: https://github.com/psf/black
    hooks:
      - id: black  # Code formatting

  - repo: https://github.com/pycqa/flake8
    hooks:
      - id: flake8  # Linting
        args: ['--max-line-length=88']

  - repo: local
    hooks:
      - id: unit-tests
        name: Run unit tests
        entry: pytest tests/unit -v
        language: system
        pass_filenames: false
```

**Quality Metrics**:
- [ ] Test coverage ≥ 80% (critical paths = 100%)
- [ ] No linting errors
- [ ] No security vulnerabilities (npm audit, pip-audit)
- [ ] No secrets in code (git-secrets, detect-secrets)
- [ ] Documentation updated

---

## 2. Testing Strategy

### 2.1 Testing Pyramid

```
        /\
       /E2E\        10% - End-to-End (UI, user flows)
      /______\
     /        \
    /Integration\ 20% - Integration (API, DB, external services)
   /____________\
  /              \
 /  Unit Tests    \ 70% - Unit (functions, classes, logic)
/__________________\
```

### 2.2 Unit Tests (70% of tests)

**Goal**: Test individual functions/methods in isolation

**Example**:
```python
# tests/unit/test_password_validator.py
import pytest
from app.utils.validators import validate_password

def test_password_too_short():
    """Password must be at least 8 characters"""
    assert validate_password("short") == False

def test_password_missing_uppercase():
    """Password must contain uppercase letter"""
    assert validate_password("lowercase123!") == False

def test_password_missing_special_char():
    """Password must contain special character"""
    assert validate_password("Uppercase123") == False

def test_valid_password():
    """Valid password passes all criteria"""
    assert validate_password("SecurePass123!") == True

@pytest.mark.parametrize("password,expected", [
    ("", False),
    ("1234567", False),
    ("SecurePass123!", True),
    ("P@ssw0rd", True),
])
def test_password_validation_cases(password, expected):
    """Test multiple password scenarios"""
    assert validate_password(password) == expected
```

**Run Unit Tests**:
```bash
# Fast, run on every save
pytest tests/unit -v --cov=app --cov-report=html

# Coverage report
open htmlcov/index.html
```

### 2.3 Integration Tests (20% of tests)

**Goal**: Test how components work together (API + DB, API + external service)

**Example**:
```python
# tests/integration/test_user_registration.py
import pytest
from app.main import app
from app.database import database

@pytest.fixture
def client():
    """Test client with clean database"""
    database.drop_all()
    database.create_all()
    yield app.test_client()
    database.drop_all()

def test_user_registration_creates_database_record(client):
    """Registration should create user in database"""
    # Make API request
    response = client.post('/auth/register', json={
        'email': 'newuser@example.com',
        'password': 'SecurePass123!',
        'name': 'Test User'
    })

    # Verify API response
    assert response.status_code == 201
    assert response.json()['user']['email'] == 'newuser@example.com'

    # Verify database record created
    from app.database.models import User
    user = User.query.filter_by(email='newuser@example.com').first()
    assert user is not None
    assert user.name == 'Test User'
    assert user.password_hash != 'SecurePass123!'  # Password hashed

def test_duplicate_email_returns_error(client):
    """Cannot register with existing email"""
    # Create first user
    client.post('/auth/register', json={
        'email': 'duplicate@example.com',
        'password': 'Pass123!',
        'name': 'First User'
    })

    # Try to create duplicate
    response = client.post('/auth/register', json={
        'email': 'duplicate@example.com',
        'password': 'DifferentPass123!',
        'name': 'Second User'
    })

    assert response.status_code == 409
    assert 'already exists' in response.json()['detail']
```

**Run Integration Tests**:
```bash
# Slower, run before commit
pytest tests/integration -v

# With database cleanup
pytest tests/integration -v --db-cleanup
```

### 2.4 End-to-End Tests (10% of tests)

**Goal**: Test complete user flows through UI

**Example (Playwright)**:
```javascript
// tests/e2e/test_user_login.spec.js
const { test, expect } = require('@playwright/test');

test('user can login and see dashboard', async ({ page }) => {
  // Navigate to login page
  await page.goto('http://localhost:3000/login');

  // Fill login form
  await page.fill('input[name="email"]', 'testuser@example.com');
  await page.fill('input[name="password"]', 'SecurePass123!');

  // Submit form
  await page.click('button[type="submit"]');

  // Verify redirect to dashboard
  await expect(page).toHaveURL('http://localhost:3000/dashboard');

  // Verify user name displayed
  await expect(page.locator('.user-name')).toHaveText('Test User');

  // Take screenshot for visual regression
  await page.screenshot({ path: 'screenshots/dashboard.png' });
});

test('invalid credentials show error message', async ({ page }) => {
  await page.goto('http://localhost:3000/login');
  await page.fill('input[name="email"]', 'wrong@example.com');
  await page.fill('input[name="password"]', 'WrongPassword');
  await page.click('button[type="submit"]');

  // Verify error message
  await expect(page.locator('.error-message')).toHaveText('Invalid credentials');

  // Verify still on login page
  await expect(page).toHaveURL('http://localhost:3000/login');
});
```

**Run E2E Tests**:
```bash
# Run in headless mode
npx playwright test

# Run with UI (debugging)
npx playwright test --ui

# Run specific browser
npx playwright test --project=chromium
```

### 2.5 Test Data Management

**Fixtures** (reusable test data):
```python
# tests/fixtures.py
import pytest
from app.database.models import User
from app.database import db

@pytest.fixture
def sample_user():
    """Create a sample user for testing"""
    user = User(
        email='testuser@example.com',
        password_hash='hashed_password',
        name='Test User',
        role='user'
    )
    db.session.add(user)
    db.session.commit()
    yield user
    db.session.delete(user)
    db.session.commit()

@pytest.fixture
def admin_user():
    """Create an admin user for testing"""
    user = User(
        email='admin@example.com',
        password_hash='hashed_password',
        name='Admin User',
        role='admin'
    )
    db.session.add(user)
    db.session.commit()
    yield user
    db.session.delete(user)
    db.session.commit()

@pytest.fixture
def auth_headers(sample_user):
    """Generate auth headers for testing"""
    token = generate_jwt(sample_user.id)
    return {'Authorization': f'Bearer {token}'}
```

**Usage**:
```python
def test_user_can_access_profile(client, sample_user, auth_headers):
    """Authenticated user can access their profile"""
    response = client.get('/users/me', headers=auth_headers)
    assert response.status_code == 200
    assert response.json()['email'] == sample_user.email
```

---

## 3. Staging Environment

### 3.1 Purpose of Staging

**Staging = Production Clone**:
- Same infrastructure (AWS, GCP, Azure)
- Same database (PostgreSQL, not SQLite)
- Same services (Redis, S3, CDN)
- Same environment variables
- Same deployment process
- Different data (anonymized production data or synthetic)

**What Staging Tests**:
- ✅ Deployment process works
- ✅ Database migrations run successfully
- ✅ Environment variables configured correctly
- ✅ External API integrations work
- ✅ Performance under realistic load
- ✅ Security configurations (HTTPS, CORS, CSP)

### 3.2 Staging Deployment

**Automated Staging Deployment** (on merge to develop):
```yaml
# .github/workflows/deploy-staging.yml
name: Deploy to Staging

on:
  push:
    branches: [develop]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run tests
        run: |
          npm install
          npm run test:unit
          npm run test:integration

      - name: Build Docker image
        run: |
          docker build -t myapp:staging-${{ github.sha }} .

      - name: Push to registry
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker push myapp:staging-${{ github.sha }}

      - name: Deploy to staging
        run: |
          kubectl set image deployment/myapp myapp=myapp:staging-${{ github.sha }} -n staging
          kubectl rollout status deployment/myapp -n staging

      - name: Run smoke tests
        run: |
          npm run test:smoke -- --url=https://staging.example.com

      - name: Notify team
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: 'Staging deployment completed'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### 3.3 Staging Testing Checklist

**Before Approving for Production**:
- [ ] All automated tests pass
- [ ] Manual smoke testing complete
- [ ] Database migrations tested
- [ ] External API integrations verified
- [ ] Performance testing complete (load, stress)
- [ ] Security scan passed (OWASP ZAP, Snyk)
- [ ] Accessibility testing (WCAG 2.1 AA)
- [ ] Browser compatibility tested (Chrome, Firefox, Safari, Edge)
- [ ] Mobile responsiveness verified
- [ ] Error tracking configured (Sentry, Rollbar)
- [ ] Monitoring configured (Datadog, New Relic)
- [ ] Logs aggregated (CloudWatch, ELK stack)

**Smoke Tests** (quick sanity checks):
```python
# tests/smoke/test_staging.py
import requests
import pytest

STAGING_URL = "https://staging.example.com"

def test_homepage_loads():
    """Homepage should return 200"""
    response = requests.get(f"{STAGING_URL}/")
    assert response.status_code == 200
    assert "<title>My App</title>" in response.text

def test_api_health_check():
    """Health check endpoint should return OK"""
    response = requests.get(f"{STAGING_URL}/health")
    assert response.status_code == 200
    assert response.json()['status'] == 'healthy'

def test_database_connection():
    """Database should be accessible"""
    response = requests.get(f"{STAGING_URL}/health/db")
    assert response.status_code == 200
    assert response.json()['database'] == 'connected'

def test_external_api_integration():
    """External APIs should be reachable"""
    response = requests.get(f"{STAGING_URL}/health/integrations")
    assert response.status_code == 200
    assert response.json()['stripe'] == 'connected'
    assert response.json()['sendgrid'] == 'connected'

def test_authentication_works():
    """User can authenticate"""
    response = requests.post(f"{STAGING_URL}/auth/login", json={
        'email': 'testuser@staging.com',
        'password': 'StagingPassword123!'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json()
```

---

## 4. Production Deployment

### 4.1 Pre-Deployment Checklist

**24 Hours Before Deployment**:
- [ ] All tests passing (unit, integration, E2E)
- [ ] Staging environment verified
- [ ] Database migrations tested in staging
- [ ] Rollback plan documented
- [ ] Feature flags configured (gradual rollout)
- [ ] Monitoring alerts configured
- [ ] Error tracking configured
- [ ] Backup taken
- [ ] Team notified (Slack, email)
- [ ] Deployment window scheduled (off-peak hours)
- [ ] On-call engineer assigned

**Security Checklist**:
- [ ] Dependencies updated (no critical CVEs)
- [ ] Security headers configured (CSP, HSTS, X-Frame-Options)
- [ ] HTTPS enforced
- [ ] API rate limiting configured
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention verified
- [ ] XSS prevention verified
- [ ] CSRF protection enabled
- [ ] Secrets rotated (API keys, database passwords)
- [ ] Access logs enabled

### 4.2 Deployment Process

**Blue-Green Deployment** (zero-downtime):
```
Current Production (Blue)          New Version (Green)
├── Load Balancer                  ├── Load Balancer
├── App Server 1                   ├── App Server 1 (new)
├── App Server 2                   ├── App Server 2 (new)
└── Database (shared)              └── Database (shared)

Step 1: Deploy green
Step 2: Run smoke tests on green
Step 3: Switch traffic to green (load balancer)
Step 4: Monitor for 30 minutes
Step 5: If OK, decommission blue. If issues, rollback to blue
```

**Deployment Script**:
```bash
#!/bin/bash
# deploy-production.sh

set -e  # Exit on error

# Configuration
ENVIRONMENT="production"
IMAGE_TAG="$1"
SLACK_WEBHOOK="$SLACK_WEBHOOK_URL"

# Validate
if [ -z "$IMAGE_TAG" ]; then
  echo "Error: Image tag required"
  echo "Usage: ./deploy-production.sh v1.2.3"
  exit 1
fi

# Notify start
curl -X POST $SLACK_WEBHOOK -d '{"text":"🚀 Production deployment started: '"$IMAGE_TAG"'"}'

# Backup database
echo "Creating database backup..."
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql
aws s3 cp backup_*.sql s3://myapp-backups/

# Run database migrations
echo "Running database migrations..."
python manage.py migrate --check
python manage.py migrate

# Deploy new version
echo "Deploying new version..."
kubectl set image deployment/myapp myapp=myapp:$IMAGE_TAG -n production
kubectl rollout status deployment/myapp -n production --timeout=5m

# Smoke tests
echo "Running smoke tests..."
npm run test:smoke -- --url=https://api.example.com

# Monitor for errors
echo "Monitoring for errors (30 seconds)..."
sleep 30

ERROR_COUNT=$(curl -s "https://api.example.com/health/errors" | jq '.count')
if [ "$ERROR_COUNT" -gt 10 ]; then
  echo "Error count too high ($ERROR_COUNT), rolling back..."
  kubectl rollout undo deployment/myapp -n production
  curl -X POST $SLACK_WEBHOOK -d '{"text":"❌ Deployment failed, rolled back"}'
  exit 1
fi

# Success
curl -X POST $SLACK_WEBHOOK -d '{"text":"✅ Production deployment successful: '"$IMAGE_TAG"'"}'
echo "Deployment complete!"
```

### 4.3 Feature Flags (Gradual Rollout)

**LaunchDarkly / Unleash Pattern**:
```python
from launchdarkly import LDClient

ld_client = LDClient(os.getenv('LAUNCHDARKLY_SDK_KEY'))

@app.post('/payments')
def create_payment(request: PaymentRequest, user: User):
    # Feature flag: new payment gateway
    use_new_gateway = ld_client.variation(
        'new-payment-gateway',
        {
            'key': user.id,
            'email': user.email,
            'custom': {'plan': user.plan}
        },
        default=False
    )

    if use_new_gateway:
        return new_payment_gateway.process(request)
    else:
        return legacy_payment_gateway.process(request)
```

**Rollout Strategy**:
```
Day 1: 5% of users    (canary release)
Day 2: 25% of users   (if no issues)
Day 3: 50% of users   (if no issues)
Day 4: 100% of users  (full rollout)

If issues detected at any stage → rollback immediately
```

### 4.4 Database Migration Strategy

**Zero-Downtime Migrations** (Expand-Contract Pattern):

**Bad** (causes downtime):
```sql
-- Don't do this in production!
ALTER TABLE users RENAME COLUMN name TO full_name;
```

**Good** (zero downtime):
```sql
-- Phase 1: Add new column
ALTER TABLE users ADD COLUMN full_name VARCHAR(255);

-- Phase 2: Backfill data (in batches)
UPDATE users SET full_name = name WHERE full_name IS NULL LIMIT 1000;
-- Repeat until all rows updated

-- Deploy code that writes to both columns
-- Monitor for 24 hours

-- Phase 3: Stop writing to old column
-- Deploy code that only uses full_name

-- Phase 4: Drop old column (after 7 days)
ALTER TABLE users DROP COLUMN name;
```

---

## 5. Post-Production Operations

### 5.1 Monitoring & Alerting

**Key Metrics to Track**:

**Application Metrics**:
- [ ] Request rate (requests/second)
- [ ] Error rate (errors/total requests)
- [ ] Response time (p50, p95, p99)
- [ ] Database query time
- [ ] Cache hit rate
- [ ] Queue depth (background jobs)

**Infrastructure Metrics**:
- [ ] CPU usage
- [ ] Memory usage
- [ ] Disk I/O
- [ ] Network bandwidth
- [ ] Database connections

**Business Metrics**:
- [ ] User registrations
- [ ] Successful payments
- [ ] Failed payments
- [ ] Active users
- [ ] Conversion rate

**Example Datadog Dashboard**:
```yaml
# datadog-dashboard.json
{
  "title": "Production Monitoring",
  "widgets": [
    {
      "definition": {
        "type": "timeseries",
        "requests": [
          {
            "q": "sum:http.requests{env:production}",
            "display_type": "line"
          }
        ],
        "title": "Request Rate"
      }
    },
    {
      "definition": {
        "type": "query_value",
        "requests": [
          {
            "q": "sum:http.errors{env:production}/sum:http.requests{env:production}*100",
            "aggregator": "avg"
          }
        ],
        "title": "Error Rate %",
        "autoscale": true,
        "precision": 2
      }
    }
  ]
}
```

**Alerting Rules**:
```yaml
# alerts.yml
alerts:
  - name: High Error Rate
    condition: error_rate > 1%
    duration: 5 minutes
    severity: critical
    channels:
      - pagerduty
      - slack
    message: "Error rate is {{ error_rate }}% (threshold: 1%)"

  - name: Slow Response Time
    condition: p95_response_time > 2000ms
    duration: 10 minutes
    severity: warning
    channels:
      - slack
    message: "P95 response time is {{ p95_response_time }}ms"

  - name: Database Connection Pool Exhausted
    condition: db_connections > 90% of max
    duration: 2 minutes
    severity: critical
    channels:
      - pagerduty
      - slack
    message: "Database connections at {{ db_connections }}"
```

### 5.2 Error Tracking

**Sentry Integration**:
```python
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

sentry_sdk.init(
    dsn=os.getenv('SENTRY_DSN'),
    environment=os.getenv('ENVIRONMENT'),
    release=os.getenv('APP_VERSION'),
    integrations=[FlaskIntegration()],
    traces_sample_rate=0.1,  # 10% of transactions for performance monitoring
    profiles_sample_rate=0.1,  # 10% for profiling
)

@app.post('/payments')
def create_payment(request: PaymentRequest):
    try:
        # Business logic
        payment = process_payment(request)
        return payment
    except PaymentError as e:
        # Send to Sentry with context
        sentry_sdk.capture_exception(e)
        sentry_sdk.set_context("payment", {
            "amount": request.amount,
            "currency": request.currency,
            "user_id": request.user_id
        })
        raise HTTPException(status_code=400, detail=str(e))
```

### 5.3 Logging Strategy

**Structured Logging**:
```python
import structlog
import logging

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()

# Usage
logger.info(
    "payment_processed",
    user_id=user.id,
    amount=payment.amount,
    currency=payment.currency,
    payment_id=payment.id,
    gateway="stripe",
    duration_ms=duration
)

# Output (JSON):
{
  "event": "payment_processed",
  "user_id": "user_123",
  "amount": 99.99,
  "currency": "USD",
  "payment_id": "pay_abc123",
  "gateway": "stripe",
  "duration_ms": 245,
  "timestamp": "2026-01-18T10:30:00.123Z",
  "level": "info",
  "logger": "payment_service"
}
```

**Log Levels**:
- **DEBUG**: Detailed diagnostic info (disabled in production)
- **INFO**: General informational messages (user actions, events)
- **WARNING**: Unexpected but handled situations (deprecated API used)
- **ERROR**: Errors that prevented operation (payment failed)
- **CRITICAL**: System-level failures (database down)

**What to Log**:
```python
# ✅ GOOD - Log business events
logger.info("user_registered", user_id=user.id, email=user.email)
logger.info("payment_completed", payment_id=payment.id, amount=payment.amount)
logger.warning("deprecated_api_used", endpoint="/v1/users", user_id=user.id)
logger.error("payment_failed", error=str(e), payment_id=payment.id)

# ❌ BAD - Don't log sensitive data
logger.info("user_password", password=request.password)  # NEVER
logger.info("credit_card", card_number=request.card)     # NEVER
logger.info("api_key", key=api_key)                      # NEVER

# ✅ GOOD - Mask sensitive data
logger.info("payment_attempt", card_last4=card[-4:])
logger.info("user_login", email=mask_email(user.email))  # u***@example.com
```

### 5.4 Performance Monitoring

**APM (Application Performance Monitoring)**:
```python
from ddtrace import tracer

@tracer.wrap(service="payment-service", resource="process_payment")
def process_payment(request: PaymentRequest):
    with tracer.trace("validate_card"):
        validate_card(request.card)

    with tracer.trace("call_stripe_api"):
        stripe_response = stripe.PaymentIntent.create(
            amount=request.amount,
            currency=request.currency
        )

    with tracer.trace("save_to_database"):
        payment = Payment.create(
            user_id=request.user_id,
            amount=request.amount,
            stripe_id=stripe_response.id
        )

    return payment
```

**Database Query Optimization**:
```python
# ❌ BAD - N+1 query problem
users = User.query.all()
for user in users:
    print(user.posts)  # Separate query for each user!

# ✅ GOOD - Eager loading
users = User.query.options(joinedload(User.posts)).all()
for user in users:
    print(user.posts)  # Single query with join

# Monitor slow queries
from sqlalchemy import event
from sqlalchemy.engine import Engine

@event.listens_for(Engine, "before_cursor_execute")
def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    conn.info.setdefault('query_start_time', []).append(time.time())

@event.listens_for(Engine, "after_cursor_execute")
def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    total = time.time() - conn.info['query_start_time'].pop()
    if total > 1.0:  # Slow query threshold
        logger.warning("slow_query", query=statement, duration_ms=total*1000)
```

---

## 6. Version Control

### 6.1 Semantic Versioning

**Format**: `MAJOR.MINOR.PATCH` (e.g., `2.3.1`)

**Rules**:
- **MAJOR**: Breaking changes (v1.x.x → v2.0.0)
  - API endpoint removed
  - Database schema changed incompatibly
  - Config format changed

- **MINOR**: New features (backward compatible) (v1.2.x → v1.3.0)
  - New API endpoint added
  - New feature added
  - Deprecation warnings added

- **PATCH**: Bug fixes (v1.2.3 → v1.2.4)
  - Security patch
  - Bug fix
  - Performance improvement

**Examples**:
```
v1.0.0 → Initial release
v1.0.1 → Fix: Login bug
v1.1.0 → Feature: Add password reset
v1.2.0 → Feature: Add 2FA
v2.0.0 → Breaking: Change API response format
```

### 6.2 Conventional Commits

**Format**:
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, no logic change)
- `refactor`: Code restructuring (no behavior change)
- `perf`: Performance improvement
- `test`: Add tests
- `chore`: Build process, dependencies

**Examples**:
```bash
# Feature
git commit -m "feat(auth): add OAuth2 login

- Implement Google OAuth2 integration
- Add Facebook OAuth2 integration
- Add user account linking

Closes #234"

# Bug fix
git commit -m "fix(payment): handle Stripe webhook timeout

Stripe webhooks can timeout after 30s. Increase timeout to 90s
and add retry logic for failed webhooks.

Fixes #567"

# Breaking change
git commit -m "feat(api): change user response format

BREAKING CHANGE: User API now returns camelCase instead of snake_case.

Before:
{\"user_id\": 123, \"first_name\": \"John\"}

After:
{\"userId\": 123, \"firstName\": \"John\"}

Closes #890"
```

### 6.3 Tagging Releases

```bash
# Create annotated tag
git tag -a v1.2.3 -m "Release v1.2.3

Features:
- Add password reset
- Add email verification

Bug Fixes:
- Fix login redirect
- Fix session timeout

Security:
- Update dependencies (CVE-2024-1234)
"

# Push tag to remote
git push origin v1.2.3

# List tags
git tag -l

# Show tag details
git show v1.2.3
```

### 6.4 Changelog Management

**CHANGELOG.md**:
```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- OAuth2 login integration

### Changed
- Increased session timeout to 24 hours

### Fixed
- Login redirect on mobile devices

## [1.2.3] - 2026-01-18

### Added
- Password reset via email
- Email verification for new accounts
- Two-factor authentication (TOTP)

### Fixed
- Fix session timeout after 30 minutes
- Fix login redirect after password change

### Security
- Update dependencies to patch CVE-2024-1234
- Add rate limiting to login endpoint (5 attempts per minute)

## [1.2.2] - 2026-01-10

### Fixed
- Fix payment webhook timeout
- Fix database connection pool exhaustion

### Performance
- Optimize database queries (reduce N+1 queries)
- Add Redis caching for user sessions

## [1.2.1] - 2026-01-05

### Security
- Emergency patch for XSS vulnerability (CVE-2024-5678)

## [1.2.0] - 2026-01-01

### Added
- Payment gateway integration (Stripe)
- Subscription management
- Invoice generation

### Changed
- Update UI design (new dashboard)

[Unreleased]: https://github.com/myapp/compare/v1.2.3...HEAD
[1.2.3]: https://github.com/myapp/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/myapp/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/myapp/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/myapp/releases/tag/v1.2.0
```

---

## 7. Rollback Procedures

### 7.1 When to Rollback

**Immediate Rollback Triggers**:
- ❌ Error rate > 5% (5 minutes sustained)
- ❌ P95 response time > 5 seconds
- ❌ Database migration failed
- ❌ Critical security vulnerability discovered
- ❌ Data corruption detected
- ❌ Payment processing broken

**Rollback Decision Tree**:
```
Issue Detected
├── Can fix forward quickly? (<5 minutes)
│   └── YES → Apply hotfix
│   └── NO → Rollback
├── Affects <1% of users?
│   └── YES → Apply feature flag to disable
│   └── NO → Rollback
└── Data corrupted?
    └── YES → Rollback + restore database backup
```

### 7.2 Rollback Process

**Application Rollback** (Kubernetes):
```bash
# View deployment history
kubectl rollout history deployment/myapp -n production

# Rollback to previous version
kubectl rollout undo deployment/myapp -n production

# Rollback to specific version
kubectl rollout undo deployment/myapp --to-revision=3 -n production

# Check rollback status
kubectl rollout status deployment/myapp -n production

# Verify
kubectl get pods -n production
```

**Database Rollback**:
```bash
# List recent backups
aws s3 ls s3://myapp-backups/ | tail -10

# Restore specific backup
aws s3 cp s3://myapp-backups/backup_20260118_103000.sql .
psql $DATABASE_URL < backup_20260118_103000.sql

# Verify restore
psql $DATABASE_URL -c "SELECT COUNT(*) FROM users;"
```

**Feature Flag Rollback**:
```python
# Disable feature immediately via API
curl -X PATCH https://app.launchdarkly.com/api/v2/flags/my-project/new-payment-gateway \
  -H "Authorization: $LD_API_KEY" \
  -d '{"variations": [{"value": false}]}'

# Or via dashboard: LaunchDarkly → Features → new-payment-gateway → Turn Off
```

### 7.3 Post-Rollback Actions

1. **Notify stakeholders**:
   ```
   Subject: Production Rollback - v1.2.3

   We rolled back production from v1.2.3 to v1.2.2 at 10:45 AM UTC.

   Reason: Error rate spiked to 8% after deployment
   Impact: 5 minutes of elevated errors (500ms to 5s response time)
   Current Status: Stable on v1.2.2
   Next Steps: Root cause analysis, fix, re-test in staging

   Incident Report: https://incidents.example.com/INC-1234
   ```

2. **Post-mortem** (within 24 hours):
   ```markdown
   # Post-Mortem: Production Rollback (2026-01-18)

   ## Summary
   Deployed v1.2.3 to production at 10:30 AM UTC. Error rate spiked from 0.1% to 8% within 5 minutes. Rolled back to v1.2.2 at 10:45 AM.

   ## Timeline
   - 10:30 AM: Deployment started
   - 10:35 AM: Error alerts triggered (error rate > 5%)
   - 10:40 AM: Team investigated, identified database query issue
   - 10:45 AM: Rollback initiated
   - 10:50 AM: Rollback complete, error rate back to 0.1%

   ## Root Cause
   New database query introduced N+1 query problem, causing 100x more DB queries than expected.

   ## Impact
   - 15 minutes of elevated errors
   - ~500 users affected
   - No data loss
   - No payment failures

   ## Action Items
   - [ ] Add database query performance test (@john, 2026-01-19)
   - [ ] Add query count monitoring (@jane, 2026-01-20)
   - [ ] Update staging environment to match prod data volume (@bob, 2026-01-21)
   - [ ] Add alerting for query count spike (@alice, 2026-01-22)

   ## Prevention
   - Use eager loading for all user queries
   - Add APM traces to identify N+1 queries in staging
   - Require database query review before production deployment
   ```

---

## 8. CI/CD Pipeline

### 8.1 Complete Pipeline

```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  # Job 1: Linting & Security
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: npm install

      - name: Run linter
        run: npm run lint

      - name: Check formatting
        run: npm run format:check

      - name: Security scan
        run: |
          npm audit --audit-level=high
          npx snyk test

      - name: Detect secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./

  # Job 2: Unit Tests
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: npm install

      - name: Run unit tests
        run: npm run test:unit

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info
          flags: unittests

  # Job 3: Integration Tests
  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: npm install

      - name: Run migrations
        env:
          DATABASE_URL: postgresql://postgres:test@localhost:5432/test
        run: npm run migrate

      - name: Run integration tests
        env:
          DATABASE_URL: postgresql://postgres:test@localhost:5432/test
          REDIS_URL: redis://localhost:6379
        run: npm run test:integration

  # Job 4: E2E Tests
  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: npm install

      - name: Install Playwright
        run: npx playwright install --with-deps

      - name: Start application
        run: npm run start &

      - name: Wait for app
        run: npx wait-on http://localhost:3000

      - name: Run E2E tests
        run: npm run test:e2e

      - name: Upload screenshots
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: playwright-screenshots
          path: test-results/

  # Job 5: Build & Push Docker Image
  build:
    runs-on: ubuntu-latest
    needs: [lint, unit-tests, integration-tests, e2e-tests]
    if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'
    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Login to DockerHub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: |
            myapp:${{ github.sha }}
            myapp:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max

  # Job 6: Deploy to Staging
  deploy-staging:
    runs-on: ubuntu-latest
    needs: [build]
    if: github.ref == 'refs/heads/develop'
    steps:
      - uses: actions/checkout@v3

      - name: Configure kubectl
        run: |
          echo "${{ secrets.KUBE_CONFIG_STAGING }}" > kubeconfig
          export KUBECONFIG=./kubeconfig

      - name: Deploy to staging
        run: |
          kubectl set image deployment/myapp myapp=myapp:${{ github.sha }} -n staging
          kubectl rollout status deployment/myapp -n staging --timeout=5m

      - name: Run smoke tests
        run: npm run test:smoke -- --url=https://staging.example.com

      - name: Notify Slack
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: 'Staging deployment: ${{ github.sha }}'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}

  # Job 7: Deploy to Production
  deploy-production:
    runs-on: ubuntu-latest
    needs: [build]
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
      url: https://app.example.com
    steps:
      - uses: actions/checkout@v3

      - name: Create database backup
        run: |
          pg_dump ${{ secrets.DATABASE_URL }} > backup.sql
          aws s3 cp backup.sql s3://myapp-backups/backup_$(date +%Y%m%d_%H%M%S).sql

      - name: Run migrations
        run: |
          python manage.py migrate --check
          python manage.py migrate

      - name: Configure kubectl
        run: |
          echo "${{ secrets.KUBE_CONFIG_PRODUCTION }}" > kubeconfig
          export KUBECONFIG=./kubeconfig

      - name: Deploy to production
        run: |
          kubectl set image deployment/myapp myapp=myapp:${{ github.sha }} -n production
          kubectl rollout status deployment/myapp -n production --timeout=10m

      - name: Run smoke tests
        run: npm run test:smoke -- --url=https://app.example.com

      - name: Monitor for errors
        run: |
          sleep 60
          ERROR_COUNT=$(curl -s "https://app.example.com/health/errors" | jq '.count')
          if [ "$ERROR_COUNT" -gt 10 ]; then
            echo "Error count too high, rolling back"
            kubectl rollout undo deployment/myapp -n production
            exit 1
          fi

      - name: Create GitHub Release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tag_name: v${{ github.sha }}
          release_name: Release v${{ github.sha }}
          body: |
            Production deployment successful
            Commit: ${{ github.sha }}
            Deployed at: $(date)

      - name: Notify Slack
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: '🚀 Production deployment: ${{ github.sha }}'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

---

## 9. Troubleshooting Guide

### 9.1 High Error Rate

**Symptom**: Error rate > 1%

**Investigation Steps**:
1. **Check Sentry** for recent errors:
   ```bash
   # Via Sentry API
   curl "https://sentry.io/api/0/projects/myorg/myapp/events/" \
     -H "Authorization: Bearer $SENTRY_TOKEN" | jq '.[] | .title'
   ```

2. **Check logs** for error patterns:
   ```bash
   # CloudWatch Insights
   aws logs tail /aws/ecs/myapp --follow --filter-pattern "ERROR"

   # Or via kubectl
   kubectl logs -l app=myapp -n production --tail=100 | grep ERROR
   ```

3. **Check database** for issues:
   ```sql
   -- Active queries
   SELECT pid, usename, query, state, wait_event_type
   FROM pg_stat_activity
   WHERE state != 'idle'
   ORDER BY query_start DESC;

   -- Lock contention
   SELECT blocked_locks.pid AS blocked_pid,
          blocking_locks.pid AS blocking_pid,
          blocked_activity.query AS blocked_query
   FROM pg_locks blocked_locks
   JOIN pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
   JOIN pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype
   WHERE NOT blocked_locks.granted;
   ```

4. **Check external APIs**:
   ```bash
   # Test Stripe API
   curl https://api.stripe.com/v1/charges \
     -u $STRIPE_SECRET_KEY: \
     -d amount=100 \
     -d currency=usd

   # Test SendGrid API
   curl https://api.sendgrid.com/v3/mail/send \
     -H "Authorization: Bearer $SENDGRID_API_KEY" \
     -H "Content-Type: application/json"
   ```

5. **Rollback if unresolved** within 15 minutes

### 9.2 Slow Response Time

**Symptom**: P95 response time > 2 seconds

**Investigation Steps**:
1. **Check APM traces** (Datadog, New Relic):
   ```
   Find slowest endpoints:
   - /api/users → 3.2s (p95)
   - /api/payments → 1.8s (p95)

   Drill down into /api/users:
   - Database query: 2.8s (90% of time)
   - API call: 0.3s
   - Business logic: 0.1s

   Conclusion: Database query is bottleneck
   ```

2. **Check database slow queries**:
   ```sql
   -- PostgreSQL slow query log
   SELECT query, calls, mean_exec_time, max_exec_time
   FROM pg_stat_statements
   WHERE mean_exec_time > 1000  -- >1 second
   ORDER BY mean_exec_time DESC
   LIMIT 10;
   ```

3. **Check for N+1 queries**:
   ```python
   # Enable SQL logging
   app.config['SQLALCHEMY_ECHO'] = True

   # Look for patterns like:
   SELECT * FROM users;
   SELECT * FROM posts WHERE user_id = 1;
   SELECT * FROM posts WHERE user_id = 2;
   SELECT * FROM posts WHERE user_id = 3;
   # ... (N+1 problem!)
   ```

4. **Optimize query**:
   ```python
   # Before (N+1)
   users = User.query.all()
   for user in users:
       print(user.posts)  # Separate query each time!

   # After (1 query)
   users = User.query.options(joinedload(User.posts)).all()
   for user in users:
       print(user.posts)  # Already loaded
   ```

5. **Add caching**:
   ```python
   from flask_caching import Cache

   cache = Cache(app, config={'CACHE_TYPE': 'redis'})

   @app.get('/api/users/<user_id>')
   @cache.cached(timeout=300, key_prefix='user')
   def get_user(user_id):
       user = User.query.get(user_id)
       return jsonify(user.to_dict())
   ```

### 9.3 Database Connection Pool Exhausted

**Symptom**: "ConnectionPoolExhausted" errors

**Investigation Steps**:
1. **Check active connections**:
   ```sql
   SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active';
   SELECT MAX_CONNECTIONS FROM pg_settings WHERE name = 'max_connections';
   ```

2. **Identify long-running queries**:
   ```sql
   SELECT pid, usename, query_start, state, query
   FROM pg_stat_activity
   WHERE state != 'idle'
   AND query_start < NOW() - INTERVAL '5 minutes'
   ORDER BY query_start;
   ```

3. **Kill long-running queries** (if safe):
   ```sql
   SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE state = 'active'
   AND query_start < NOW() - INTERVAL '30 minutes';
   ```

4. **Fix connection leaks** in code:
   ```python
   # ❌ BAD - Connection leak
   conn = db.get_connection()
   result = conn.execute(query)
   # Connection never returned!

   # ✅ GOOD - Use context manager
   with db.get_connection() as conn:
       result = conn.execute(query)
   # Connection automatically returned
   ```

5. **Increase pool size** (temporary fix):
   ```python
   # config.py
   SQLALCHEMY_POOL_SIZE = 20  # Increase from 10
   SQLALCHEMY_MAX_OVERFLOW = 40  # Increase from 20
   SQLALCHEMY_POOL_PRE_PING = True  # Check connections before use
   ```

### 9.4 Memory Leak

**Symptom**: Memory usage increases over time, OOM kills

**Investigation Steps**:
1. **Monitor memory over time**:
   ```bash
   # Kubernetes
   kubectl top pods -n production | grep myapp

   # Docker
   docker stats myapp
   ```

2. **Profile memory usage** (Python):
   ```python
   from memory_profiler import profile

   @profile
   def process_large_file(file_path):
       with open(file_path) as f:
           data = f.read()  # Loads entire file into memory!
           process(data)

   # Run with:
   python -m memory_profiler app.py
   ```

3. **Find memory leaks**:
   ```python
   # Common culprits:
   # 1. Global caches that grow unbounded
   cache = {}  # ❌ Grows forever

   # Fix: Use LRU cache with max size
   from functools import lru_cache
   @lru_cache(maxsize=1000)
   def expensive_function(x):
       return x ** 2

   # 2. Event listeners not cleaned up
   event_emitter.on('event', handler)  # ❌ Handler never removed

   # Fix: Clean up listeners
   event_emitter.off('event', handler)

   # 3. Database connections not closed
   conn = db.connect()  # ❌ Never closed

   # Fix: Use context manager
   with db.connect() as conn:
       pass
   ```

4. **Increase memory limit** (temporary):
   ```yaml
   # kubernetes deployment
   resources:
     limits:
       memory: "2Gi"  # Increase from 1Gi
     requests:
       memory: "1Gi"
   ```

---

## 10. Checklists

### 10.1 Pre-Commit Checklist

- [ ] All tests pass locally
- [ ] Code linted (no errors)
- [ ] Code formatted (prettier, black)
- [ ] No console.log / print statements
- [ ] No commented-out code
- [ ] No secrets in code (.env in .gitignore)
- [ ] Commit message follows conventional commits
- [ ] Branch up to date with develop

### 10.2 Pull Request Checklist

- [ ] Title describes the change
- [ ] Description explains why (not just what)
- [ ] Tests added for new functionality
- [ ] Tests pass in CI/CD
- [ ] Documentation updated
- [ ] Breaking changes noted
- [ ] Screenshots attached (for UI changes)
- [ ] Reviewed own code first
- [ ] Assigned reviewers
- [ ] Linked to issue/ticket

### 10.3 Pre-Deployment Checklist

- [ ] All tests passing (unit, integration, E2E)
- [ ] Staging environment verified
- [ ] Database migrations tested
- [ ] Feature flags configured
- [ ] Monitoring configured
- [ ] Error tracking configured
- [ ] Backup taken
- [ ] Rollback plan documented
- [ ] Team notified
- [ ] Deployment window scheduled

### 10.4 Post-Deployment Checklist

- [ ] Smoke tests passed
- [ ] Error rate normal (<1%)
- [ ] Response time normal (<2s p95)
- [ ] No alerts triggered
- [ ] Database migrations successful
- [ ] Monitoring dashboards checked
- [ ] User-facing features tested
- [ ] Payment processing tested
- [ ] Email delivery tested
- [ ] Team notified of success

### 10.5 Incident Response Checklist

- [ ] Incident acknowledged (<5 minutes)
- [ ] Severity assessed (P1/P2/P3/P4)
- [ ] On-call engineer paged (for P1/P2)
- [ ] War room created (Slack, Zoom)
- [ ] Status page updated
- [ ] Investigation started
- [ ] Rollback initiated (if applicable)
- [ ] Issue mitigated
- [ ] Customers notified
- [ ] Post-mortem scheduled (<24 hours)

---

## Best Practices Summary

### Development
✅ Use Docker for local development (environment parity)
✅ Write tests before code (TDD)
✅ Use conventional commits
✅ Use pre-commit hooks
✅ Never commit secrets

### Testing
✅ 70% unit, 20% integration, 10% E2E
✅ Test real APIs in integration tests
✅ Use fixtures for test data
✅ Mock external APIs
✅ Aim for 80%+ coverage

### Deployment
✅ Deploy to staging first
✅ Run smoke tests after deployment
✅ Use feature flags for gradual rollout
✅ Monitor for 30 minutes post-deploy
✅ Have rollback plan ready

### Production
✅ Monitor error rate, response time, throughput
✅ Use structured logging (JSON)
✅ Set up alerts (error rate, slow queries)
✅ Profile performance (APM)
✅ Backup before deployment

### Version Control
✅ Use semantic versioning
✅ Use Git Flow branching
✅ Tag releases
✅ Maintain changelog
✅ Write descriptive commit messages

---

## Additional Resources

- [12-Factor App](https://12factor.net/)
- [Google SRE Book](https://sre.google/books/)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Keep a Changelog](https://keepachangelog.com/)
