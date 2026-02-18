# Environment Variables and Secrets Management

Complete patterns for managing environment variables and secrets in Railway deployments.

---

## Table of Contents

1. [Base64 Encoding for JSON Credentials](#base64-encoding-for-json-credentials)
2. [Environment Variable Best Practices](#environment-variable-best-practices)
3. [Feature Flags Pattern](#feature-flags-pattern)
4. [Multi-Environment Configuration](#multi-environment-configuration)
5. [Security Best Practices](#security-best-practices)

---

## Base64 Encoding for JSON Credentials

### Google Analytics 4 (GA4) Credentials

**Step 1: Create Service Account**:
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

**Step 2: Base64 Encode**:
```bash
# macOS/Linux
base64 -w 0 ga4-credentials.json > ga4-creds-b64.txt

# Windows PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("ga4-credentials.json")) | Out-File ga4-creds-b64.txt

# Windows Git Bash
base64 -w 0 ga4-credentials.json > ga4-creds-b64.txt
```

**Step 3: Set Railway Variable**:
```bash
# Via Railway CLI
railway variables set GA4_CREDENTIALS_BASE64="$(cat ga4-creds-b64.txt)"

# Or manually via Railway Dashboard:
# Project → Variables → New Variable
# Name: GA4_CREDENTIALS_BASE64
# Value: <paste base64 string>
```

**Step 4: Decode in Application**:

**Python**:
```python
import base64
import json
import os
from google.oauth2 import service_account
from google.analytics.data_v1beta import BetaAnalyticsDataClient

def get_ga4_client():
    """Initialize GA4 client with base64-encoded credentials."""
    creds_base64 = os.getenv("GA4_CREDENTIALS_BASE64")

    if not creds_base64:
        raise ValueError("GA4_CREDENTIALS_BASE64 not set")

    # Decode base64 → JSON string → dict
    creds_json = base64.b64decode(creds_base64).decode('utf-8')
    creds_info = json.loads(creds_json)

    # Create credentials object
    credentials = service_account.Credentials.from_service_account_info(
        creds_info,
        scopes=["https://www.googleapis.com/auth/analytics.readonly"]
    )

    # Initialize client
    client = BetaAnalyticsDataClient(credentials=credentials)
    return client

# Usage
try:
    ga4_client = get_ga4_client()
    property_id = os.getenv("GA4_PROPERTY_ID")
    # Make API calls...
except Exception as e:
    print(f"GA4 initialization failed: {e}")
```

**Node.js**:
```javascript
const { google } = require('googleapis');

function getGA4Client() {
    const credsBase64 = process.env.GA4_CREDENTIALS_BASE64;

    if (!credsBase64) {
        throw new Error('GA4_CREDENTIALS_BASE64 not set');
    }

    // Decode base64 → JSON string → object
    const credsJson = Buffer.from(credsBase64, 'base64').toString('utf-8');
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

---

### Firebase Admin SDK Credentials

**Python**:
```python
import base64
import json
import os
import firebase_admin
from firebase_admin import credentials

def initialize_firebase():
    """Initialize Firebase Admin SDK with base64 credentials."""
    creds_base64 = os.getenv("FIREBASE_ADMIN_CREDENTIALS_BASE64")

    if not creds_base64:
        raise ValueError("FIREBASE_ADMIN_CREDENTIALS_BASE64 not set")

    # Decode credentials
    creds_json = base64.b64decode(creds_base64).decode('utf-8')
    creds_info = json.loads(creds_json)

    # Initialize Firebase
    cred = credentials.Certificate(creds_info)
    firebase_admin.initialize_app(cred)

# Call at app startup
initialize_firebase()
```

**Node.js**:
```javascript
const admin = require('firebase-admin');

function initializeFirebase() {
    const credsBase64 = process.env.FIREBASE_ADMIN_CREDENTIALS_BASE64;

    if (!credsBase64) {
        throw new Error('FIREBASE_ADMIN_CREDENTIALS_BASE64 not set');
    }

    const credsJson = Buffer.from(credsBase64, 'base64').toString('utf-8');
    const serviceAccount = JSON.parse(credsJson);

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

initializeFirebase();
```

---

### AWS Credentials

**Python**:
```python
import base64
import json
import os
import boto3

def get_aws_session():
    """Create AWS session from base64-encoded credentials."""
    creds_base64 = os.getenv("AWS_CREDENTIALS_BASE64")

    if not creds_base64:
        raise ValueError("AWS_CREDENTIALS_BASE64 not set")

    # Decode credentials
    creds_json = base64.b64decode(creds_base64).decode('utf-8')
    creds_info = json.loads(creds_json)

    # Create session
    session = boto3.Session(
        aws_access_key_id=creds_info['access_key_id'],
        aws_secret_access_key=creds_info['secret_access_key'],
        region_name=creds_info.get('region', 'us-east-1')
    )

    return session

# Usage
session = get_aws_session()
s3 = session.client('s3')
```

**credentials.json format**:
```json
{
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "region": "us-east-1"
}
```

---

## Environment Variable Best Practices

### Required vs Optional Variables

**Example .env.example**:
```bash
# ============================================
# REQUIRED ENVIRONMENT VARIABLES
# ============================================

# Database
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Application
SECRET_KEY=your-secret-key-here
PORT=8000

# ============================================
# OPTIONAL ENVIRONMENT VARIABLES
# ============================================

# WordPress Integration (optional - enables full mode)
WORDPRESS_API_URL=https://yourblog.com
WORDPRESS_API_USER=admin
WORDPRESS_API_PASS=your-app-password

# Google Analytics 4 (optional - enables analytics)
GA4_CREDENTIALS_BASE64=base64-encoded-json-here
GA4_PROPERTY_ID=123456789

# Email Notifications (optional - enables email)
SENDGRID_API_KEY=SG.your-api-key
FROM_EMAIL=noreply@yourdomain.com

# Redis Cache (optional - improves performance)
REDIS_URL=redis://localhost:6379

# ============================================
# RAILWAY-PROVIDED VARIABLES (auto-set)
# ============================================
# RAILWAY_DEPLOYMENT_ID
# RAILWAY_GIT_COMMIT_SHA
# RAILWAY_DEPLOYMENT_DATE
# RAILWAY_ENVIRONMENT
```

---

### Validation Function

**Python**:
```python
import os
from typing import List, Dict, Optional

class EnvironmentValidator:
    """Validate environment variables on startup."""

    REQUIRED_VARS = [
        "DATABASE_URL",
        "SECRET_KEY"
    ]

    OPTIONAL_GROUPS = {
        "wordpress": [
            "WORDPRESS_API_URL",
            "WORDPRESS_API_USER",
            "WORDPRESS_API_PASS"
        ],
        "analytics": [
            "GA4_CREDENTIALS_BASE64",
            "GA4_PROPERTY_ID"
        ],
        "email": [
            "SENDGRID_API_KEY",
            "FROM_EMAIL"
        ]
    }

    @classmethod
    def validate_required(cls) -> Dict[str, bool]:
        """Check required environment variables."""
        missing = []
        for var in cls.REQUIRED_VARS:
            if not os.getenv(var):
                missing.append(var)

        if missing:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing)}\n"
                f"Please set these before starting the application."
            )

        return True

    @classmethod
    def check_optional_features(cls) -> Dict[str, bool]:
        """Check which optional features are enabled."""
        enabled_features = {}

        for feature, vars_list in cls.OPTIONAL_GROUPS.items():
            enabled_features[feature] = all(os.getenv(var) for var in vars_list)

        return enabled_features

    @classmethod
    def print_status(cls):
        """Print environment configuration status."""
        print("=" * 60)
        print("ENVIRONMENT CONFIGURATION")
        print("=" * 60)

        # Required vars
        print("\n✓ Required variables:")
        for var in cls.REQUIRED_VARS:
            value = os.getenv(var)
            masked_value = value[:10] + "..." if value and len(value) > 10 else value
            print(f"  - {var}: {masked_value}")

        # Optional features
        print("\n📦 Optional features:")
        features = cls.check_optional_features()
        for feature, enabled in features.items():
            status = "✓ ENABLED" if enabled else "✗ DISABLED"
            print(f"  - {feature}: {status}")

        # Railway deployment info
        print("\n🚂 Railway deployment:")
        deployment_id = os.getenv("RAILWAY_DEPLOYMENT_ID", "N/A (local)")
        commit_sha = os.getenv("RAILWAY_GIT_COMMIT_SHA", "N/A")
        print(f"  - Deployment ID: {deployment_id}")
        print(f"  - Commit SHA: {commit_sha[:7] if commit_sha != 'N/A' else commit_sha}")

        print("=" * 60)

# Call at app startup
EnvironmentValidator.validate_required()
EnvironmentValidator.print_status()
```

---

## Feature Flags Pattern

### Python Implementation

```python
import os
import base64
import json
from typing import Dict, Optional

class FeatureFlags:
    """Feature flags based on environment configuration."""

    def __init__(self):
        self._wordpress = self._check_wordpress()
        self._analytics = self._check_analytics()
        self._email = self._check_email()
        self._redis = self._check_redis()

    def _check_wordpress(self) -> bool:
        """Check if WordPress integration is configured."""
        required = ['WORDPRESS_API_URL', 'WORDPRESS_API_USER', 'WORDPRESS_API_PASS']
        return all(os.getenv(var) for var in required)

    def _check_analytics(self) -> bool:
        """Check if GA4 analytics is configured."""
        if not os.getenv('GA4_CREDENTIALS_BASE64') or not os.getenv('GA4_PROPERTY_ID'):
            return False

        # Validate credentials format
        try:
            creds_base64 = os.getenv('GA4_CREDENTIALS_BASE64')
            creds_json = base64.b64decode(creds_base64).decode('utf-8')
            creds = json.loads(creds_json)
            required_fields = ['client_email', 'private_key', 'project_id']
            return all(field in creds for field in required_fields)
        except Exception:
            return False

    def _check_email(self) -> bool:
        """Check if email service is configured."""
        return bool(os.getenv('SENDGRID_API_KEY') and os.getenv('FROM_EMAIL'))

    def _check_redis(self) -> bool:
        """Check if Redis is configured."""
        return bool(os.getenv('REDIS_URL'))

    @property
    def wordpress_enabled(self) -> bool:
        return self._wordpress

    @property
    def analytics_enabled(self) -> bool:
        return self._analytics

    @property
    def email_enabled(self) -> bool:
        return self._email

    @property
    def redis_enabled(self) -> bool:
        return self._redis

    @property
    def full_features(self) -> bool:
        """All optional features enabled."""
        return all([self._wordpress, self._analytics, self._email])

    @property
    def mode(self) -> str:
        """Get application mode (full/limited)."""
        return "full" if self.full_features else "limited"

    def to_dict(self) -> Dict[str, bool]:
        """Export feature flags as dictionary."""
        return {
            "wordpress": self._wordpress,
            "analytics": self._analytics,
            "email": self._email,
            "redis": self._redis,
            "mode": self.mode
        }

# Global instance
features = FeatureFlags()
```

**Usage in Application**:
```python
from flask import Flask, jsonify
from features import features

app = Flask(__name__)

@app.route("/api/publish", methods=["POST"])
def publish_content():
    """Publish content with graceful degradation."""
    data = request.json

    # Core functionality (always works)
    content_id = save_to_database(data)

    # Optional: Publish to WordPress
    wordpress_published = False
    if features.wordpress_enabled:
        try:
            publish_to_wordpress(data)
            wordpress_published = True
        except Exception as e:
            logger.error(f"WordPress publish failed: {e}")

    # Optional: Track analytics
    analytics_tracked = False
    if features.analytics_enabled:
        try:
            track_ga4_event("content_published", {"content_id": content_id})
            analytics_tracked = True
        except Exception as e:
            logger.warning(f"Analytics tracking failed: {e}")

    # Optional: Send notification
    email_sent = False
    if features.email_enabled:
        try:
            send_notification_email(data)
            email_sent = True
        except Exception as e:
            logger.warning(f"Email notification failed: {e}")

    return jsonify({
        "success": True,
        "content_id": content_id,
        "wordpress_published": wordpress_published,
        "analytics_tracked": analytics_tracked,
        "email_sent": email_sent,
        "mode": features.mode
    })
```

---

## Multi-Environment Configuration

### Environment-Specific Variables

**Local Development (.env.local)**:
```bash
DATABASE_URL=postgresql://localhost:5432/myapp_dev
SECRET_KEY=dev-secret-key-change-in-production
DEBUG=true
LOG_LEVEL=DEBUG

# Optional features disabled in local dev
# WORDPRESS_API_URL=
# GA4_CREDENTIALS_BASE64=
```

**Staging (Railway)**:
```bash
# Set via Railway CLI or Dashboard
railway variables set DATABASE_URL="postgresql://staging-db-url"
railway variables set SECRET_KEY="staging-secret-key"
railway variables set DEBUG="false"
railway variables set LOG_LEVEL="INFO"

# Enable some optional features for testing
railway variables set WORDPRESS_API_URL="https://staging.yourblog.com"
```

**Production (Railway)**:
```bash
# Production variables
railway variables set DATABASE_URL="postgresql://prod-db-url"
railway variables set SECRET_KEY="prod-secret-key-very-strong"
railway variables set DEBUG="false"
railway variables set LOG_LEVEL="WARNING"

# Enable all optional features
railway variables set WORDPRESS_API_URL="https://yourblog.com"
railway variables set GA4_CREDENTIALS_BASE64="base64-encoded-credentials"
railway variables set SENDGRID_API_KEY="SG.production-key"
```

---

### Environment Detection

**Python**:
```python
import os

class Environment:
    """Detect current environment."""

    @staticmethod
    def is_production() -> bool:
        """Check if running in production."""
        return os.getenv("RAILWAY_ENVIRONMENT") == "production"

    @staticmethod
    def is_staging() -> bool:
        """Check if running in staging."""
        return os.getenv("RAILWAY_ENVIRONMENT") == "staging"

    @staticmethod
    def is_development() -> bool:
        """Check if running locally."""
        return not os.getenv("RAILWAY_DEPLOYMENT_ID")

    @staticmethod
    def get_environment() -> str:
        """Get current environment name."""
        if Environment.is_production():
            return "production"
        elif Environment.is_staging():
            return "staging"
        else:
            return "development"

# Usage
if Environment.is_production():
    # Enable strict security
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
else:
    # Development mode - more permissive
    app.config['DEBUG'] = True
```

---

## Security Best Practices

### .gitignore Protection

```gitignore
# Environment files
.env
.env.local
.env.production
.env.staging

# Credentials
*-credentials.json
*-creds-b64.txt
service-account-*.json
ga4-credentials.json
firebase-admin-*.json

# AWS
.aws/
*.pem

# Secrets
secrets/
private/
*.key
*.p12
```

---

### Credential Rotation Script

```bash
#!/bin/bash
# scripts/rotate-credentials.sh

set -e

echo "🔄 Rotating credentials..."

# 1. Generate new service account key
gcloud iam service-accounts keys create ga4-credentials-new.json \
    --iam-account=my-app-ga4@my-project-id.iam.gserviceaccount.com

# 2. Base64 encode
base64 -w 0 ga4-credentials-new.json > ga4-creds-b64-new.txt

# 3. Update Railway variable
railway variables set GA4_CREDENTIALS_BASE64="$(cat ga4-creds-b64-new.txt)"

# 4. Trigger redeploy
railway up --service backend --detach

# 5. Wait for deployment
sleep 60

# 6. Delete old key (find key ID first)
# gcloud iam service-accounts keys delete OLD_KEY_ID --iam-account=...

# 7. Cleanup local files
rm ga4-credentials-new.json ga4-creds-b64-new.txt

echo "✅ Credentials rotated successfully"
```

---

### Secrets Scanning

```bash
# Install gitleaks (secrets scanner)
brew install gitleaks

# Scan for secrets
gitleaks detect --source . --verbose

# Pre-commit hook
# .husky/pre-commit
#!/bin/sh
gitleaks protect --staged --verbose
```

---

### Environment Variable Checklist

**Before Deployment**:
- [ ] All required variables set in Railway dashboard
- [ ] Optional variables documented in README
- [ ] Credentials base64-encoded (not plain JSON)
- [ ] .env files added to .gitignore
- [ ] No secrets committed to Git (check with gitleaks)
- [ ] Validation function tests all required vars
- [ ] Feature flags configured properly
- [ ] Health check shows enabled features
- [ ] Credentials rotated if previously committed
- [ ] Environment-specific configs separated (dev/staging/prod)

---

**Related**: See main skill SKILL.md for deployment patterns
