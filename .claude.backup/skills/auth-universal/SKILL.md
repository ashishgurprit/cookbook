# Universal Authentication System

> Production-ready authentication for web, iOS, and Android apps with email auth, MFA, and OAuth (Google/Apple)

## Overview

This skill provides a complete, secure authentication system designed using the 3D Decision Matrix framework. It includes:

✅ **Email Authentication** (username/password with Bcrypt/Argon2)
✅ **Multi-Factor Authentication** (TOTP authenticator apps)
✅ **OAuth 2.0** (Google and Apple Sign-In)
✅ **Cross-Platform** (Web, iOS, Android)
✅ **Security Hardened** (based on 30+ production incidents)
✅ **Test Coverage** (unit, integration, E2E templates)
✅ **Deployment Ready** (CI/CD pipelines, rollback procedures)

---

## Architecture Decision: Hybrid Approach

**Decision Type**: TRAPDOOR (irreversible, high-stakes)
**Process Used**: Full SPADE + Six Thinking Hats + C-Suite perspectives

### Why Hybrid?

```
Platform    | Approach          | Reason
------------|-------------------|----------------------------------
Web         | Session-based     | CSRF protection, HttpOnly cookies
Mobile      | JWT-based         | Offline support, better UX
Both        | Same API endpoints| Code reuse, consistent logic
```

**Key Insight**: Each platform has different security characteristics. Web browsers have XSS risks but offer HttpOnly cookies. Mobile apps have secure storage (Keychain/EncryptedPrefs) but need offline support. Hybrid leverages each platform's strengths.

---

## Security Principles

Based on lessons from 30+ production incidents:

### 1. Database Schema
```sql
-- User IDs must be varchar(128) NOT varchar(36)
-- Reason: Firebase UIDs are 28 chars, Auth0 uses prefixes
-- LESSON: "Firebase UID ≠ UUID"

CREATE TABLE users (
    id VARCHAR(128) PRIMARY KEY,  -- NOT uuid!
    email VARCHAR(254) UNIQUE NOT NULL,  -- RFC 5321 max
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255),  -- Bcrypt output
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(32),  -- TOTP secret
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE oauth_accounts (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(128) REFERENCES users(id),
    provider VARCHAR(20) NOT NULL,  -- 'google' | 'apple'
    provider_user_id VARCHAR(255) NOT NULL,  -- Provider's ID for user
    email VARCHAR(254),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE TABLE mfa_backup_codes (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(128) REFERENCES users(id),
    code VARCHAR(8) NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE sessions (
    id VARCHAR(128) PRIMARY KEY,  -- Session ID
    user_id VARCHAR(128) REFERENCES users(id),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(128) REFERENCES users(id),
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### 2. Password Security
```python
# GOOD - Use Bcrypt or Argon2
from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Balance security vs performance
)

# Hash password
password_hash = pwd_context.hash(plain_password)

# Verify password
is_valid = pwd_context.verify(plain_password, password_hash)

# NEVER exclude passwords from security scanning
# LESSON: "Password Fields in Security Scanning"
# But DO exclude from pattern matching in request bodies
EXCLUDED_FIELDS = ['password', 'newPassword', 'currentPassword']
```

### 3. Session Management (Web)
```python
# LESSON: "Auth Headers Lost Through Proxy"
# Configure Nginx to forward auth cookies

# Nginx config
"""
location /api {
    proxy_pass http://backend;
    proxy_set_header Cookie $http_cookie;
    proxy_pass_request_headers on;
}
"""

# Session config
SESSION_CONFIG = {
    "secret_key": os.environ["SESSION_SECRET"],  # 32+ bytes, random
    "cookie_httponly": True,  # Prevent XSS access
    "cookie_secure": True,  # HTTPS only
    "cookie_samesite": "Lax",  # CSRF protection
    "session_lifetime": timedelta(hours=24),
    "session_cookie_name": "sessionid"  # Don't use default names
}
```

### 4. JWT Security (Mobile)
```javascript
// Access token: Short-lived (15 minutes)
const accessToken = jwt.sign(
    { userId, email, role },
    process.env.JWT_SECRET,
    { expiresIn: '15m', algorithm: 'HS256' }
);

// Refresh token: Long-lived (7 days), stored in database
const refreshToken = crypto.randomBytes(32).toString('hex');
await db.refreshTokens.create({
    userId,
    token: await bcrypt.hash(refreshToken, 10),  // Hash before storing!
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
});

// Token rotation on refresh
// CRITICAL: Invalidate old refresh token when issuing new one
```

### 5. OAuth Security
```typescript
// CRITICAL: Link by provider_user_id, NOT email
// Reason: User can change email at provider

interface OAuthProfile {
    provider: 'google' | 'apple';
    providerId: string;  // Google's sub or Apple's user ID
    email: string;
    emailVerified: boolean;
}

async function linkOrCreateAccount(profile: OAuthProfile) {
    // Check if OAuth account exists
    let oauthAccount = await db.oauthAccounts.findOne({
        provider: profile.provider,
        provider_user_id: profile.providerId
    });

    if (oauthAccount) {
        // Existing OAuth account - log them in
        return oauthAccount.user_id;
    }

    // Check if email exists (account linking)
    let user = await db.users.findOne({ email: profile.email });

    if (!user) {
        // New user - create account
        user = await db.users.create({
            id: generateUserId(),  // Use UUID or similar
            email: profile.email,
            email_verified: profile.emailVerified,
            password_hash: null  // OAuth-only account
        });
    }

    // Link OAuth account to user
    await db.oauthAccounts.create({
        user_id: user.id,
        provider: profile.provider,
        provider_user_id: profile.providerId,
        email: profile.email
    });

    return user.id;
}
```

### 6. MFA Implementation
```python
# TOTP (Time-based One-Time Password) - RFC 6238
import pyotp
import qrcode
from io import BytesIO
import base64

def setup_mfa(user_id: str):
    """Generate MFA secret and QR code for user"""
    # Generate secret (32 chars base32)
    secret = pyotp.random_base32()

    # Save to database
    db.users.update(user_id, mfa_secret=secret)

    # Generate QR code URI
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="YourApp"
    )

    # Generate QR code image
    qr = qrcode.make(uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    # Generate backup codes
    backup_codes = [generate_backup_code() for _ in range(10)]
    for code in backup_codes:
        db.mfa_backup_codes.create(
            user_id=user_id,
            code=bcrypt.hashpw(code.encode(), bcrypt.gensalt())
        )

    return {
        "secret": secret,  # Show once, user must save
        "qr_code": qr_base64,
        "backup_codes": backup_codes  # Show once, user must save
    }

def verify_mfa(user_id: str, code: str) -> bool:
    """Verify TOTP code or backup code"""
    user = db.users.get(user_id)

    # Try TOTP first
    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(code, valid_window=1):  # Allow 30s clock skew
        return True

    # Try backup codes
    backup_codes = db.mfa_backup_codes.filter(user_id=user_id, used=False)
    for backup in backup_codes:
        if bcrypt.checkpw(code.encode(), backup.code.encode()):
            db.mfa_backup_codes.update(backup.id, used=True)
            return True

    return False

def generate_backup_code() -> str:
    """Generate 8-character backup code"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
```

---

## Platform-Specific Implementation

### Web (React/Vue/Vanilla JS)

**Authentication Flow**:
```
1. User submits login form
2. POST /api/auth/login with email + password (+ MFA if enabled)
3. Server creates session in Redis
4. Server sets HttpOnly cookie with session ID
5. Client redirected to /dashboard
6. Subsequent requests include cookie automatically
7. Server validates session on each request
```

**Example: React Hook**
```typescript
// See: templates/frontend/react-auth-hook.ts
import { useState, useEffect } from 'react';

export function useAuth() {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Check session on mount
        fetch('/api/auth/me', { credentials: 'include' })
            .then(res => res.json())
            .then(data => setUser(data.user))
            .catch(() => setUser(null))
            .finally(() => setLoading(false));
    }, []);

    const login = async (email: string, password: string, mfaCode?: string) => {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',  // Important for cookies!
            body: JSON.stringify({ email, password, mfaCode })
        });

        if (!res.ok) throw new Error('Login failed');

        const data = await res.json();
        setUser(data.user);
        return data;
    };

    const logout = async () => {
        await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include'
        });
        setUser(null);
    };

    return { user, loading, login, logout };
}
```

### iOS (Swift)

**Authentication Flow**:
```
1. User submits login form
2. POST /api/auth/login/mobile with email + password (+ MFA)
3. Server returns { accessToken, refreshToken }
4. App stores tokens in Keychain
5. Subsequent requests include Authorization: Bearer {accessToken}
6. When access token expires, use refresh token to get new pair
```

**Example: Auth Manager**
```swift
// See: templates/mobile/ios/AuthManager.swift
import Foundation
import KeychainAccess

class AuthManager {
    static let shared = AuthManager()
    private let keychain = Keychain(service: "com.yourapp.auth")

    private(set) var accessToken: String?
    private(set) var refreshToken: String?

    func login(email: String, password: String, mfaCode: String? = nil) async throws -> User {
        let body: [String: Any] = [
            "email": email,
            "password": password,
            "mfaCode": mfaCode as Any
        ]

        let data = try await APIClient.post("/auth/login/mobile", body: body)
        let response = try JSONDecoder().decode(LoginResponse.self, from: data)

        // Store tokens in Keychain (encrypted storage)
        try keychain.set(response.accessToken, key: "accessToken")
        try keychain.set(response.refreshToken, key: "refreshToken")

        self.accessToken = response.accessToken
        self.refreshToken = response.refreshToken

        return response.user
    }

    func refreshAccessToken() async throws {
        guard let refreshToken = try keychain.get("refreshToken") else {
            throw AuthError.notAuthenticated
        }

        let data = try await APIClient.post("/auth/refresh", body: ["refreshToken": refreshToken])
        let response = try JSONDecoder().decode(RefreshResponse.self, from: data)

        try keychain.set(response.accessToken, key: "accessToken")
        try keychain.set(response.refreshToken, key: "refreshToken")

        self.accessToken = response.accessToken
        self.refreshToken = response.refreshToken
    }

    func logout() throws {
        try keychain.remove("accessToken")
        try keychain.remove("refreshToken")
        self.accessToken = nil
        self.refreshToken = nil
    }
}
```

### Android (Kotlin)

**Authentication Flow**: Same as iOS

**Example: Auth Manager**
```kotlin
// See: templates/mobile/android/AuthManager.kt
import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys

class AuthManager(context: Context) {
    private val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

    private val sharedPreferences = EncryptedSharedPreferences.create(
        "auth_prefs",
        masterKeyAlias,
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    var accessToken: String?
        get() = sharedPreferences.getString("accessToken", null)
        private set(value) {
            sharedPreferences.edit().putString("accessToken", value).apply()
        }

    var refreshToken: String?
        get() = sharedPreferences.getString("refreshToken", null)
        private set(value) {
            sharedPreferences.edit().putString("refreshToken", value).apply()
        }

    suspend fun login(email: String, password: String, mfaCode: String? = null): User {
        val body = LoginRequest(email, password, mfaCode)
        val response = apiClient.post<LoginResponse>("/auth/login/mobile", body)

        accessToken = response.accessToken
        refreshToken = response.refreshToken

        return response.user
    }

    suspend fun refreshAccessToken() {
        val currentRefreshToken = refreshToken
            ?: throw AuthException("Not authenticated")

        val response = apiClient.post<RefreshResponse>(
            "/auth/refresh",
            RefreshRequest(currentRefreshToken)
        )

        accessToken = response.accessToken
        refreshToken = response.refreshToken
    }

    fun logout() {
        sharedPreferences.edit().clear().apply()
    }

    companion object {
        @Volatile
        private var INSTANCE: AuthManager? = null

        fun getInstance(context: Context): AuthManager {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: AuthManager(context).also { INSTANCE = it }
            }
        }
    }
}
```

---

## API Endpoints

### Email Authentication

**POST /api/auth/register**
```json
Request:
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd123",
  "name": "John Doe"
}

Response (201):
{
  "user": {
    "id": "usr_abc123",
    "email": "user@example.com",
    "name": "John Doe",
    "emailVerified": false,
    "mfaEnabled": false
  },
  "message": "Verification email sent"
}
```

**POST /api/auth/login** (Web - returns session cookie)
```json
Request:
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd123",
  "mfaCode": "123456"  // Optional, required if MFA enabled
}

Response (200):
{
  "user": {
    "id": "usr_abc123",
    "email": "user@example.com",
    "name": "John Doe",
    "emailVerified": true,
    "mfaEnabled": true
  }
}

Sets Cookie: sessionid=<session-id>; HttpOnly; Secure; SameSite=Lax
```

**POST /api/auth/login/mobile** (Mobile - returns JWT)
```json
Request:
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd123",
  "mfaCode": "123456"
}

Response (200):
{
  "user": { /* user object */ },
  "accessToken": "eyJhbGc...",  // 15min expiry
  "refreshToken": "9f7a8b3c..."  // 7day expiry
}
```

**POST /api/auth/refresh**
```json
Request:
{
  "refreshToken": "9f7a8b3c..."
}

Response (200):
{
  "accessToken": "eyJhbGc...",  // New 15min token
  "refreshToken": "2d5e9f1a..."  // New 7day token (rotation)
}
```

### OAuth Endpoints

**GET /api/auth/oauth/google**
```
Redirects to Google OAuth consent screen
Callback: /api/auth/oauth/google/callback?code=...
```

**GET /api/auth/oauth/apple**
```
Redirects to Apple Sign In
Callback: /api/auth/oauth/apple/callback
```

### MFA Endpoints

**POST /api/auth/mfa/setup**
```json
Request: {} (authenticated user)

Response (200):
{
  "secret": "JBSWY3DPEHPK3PXP",  // Base32 secret
  "qrCode": "data:image/png;base64,...",  // QR code image
  "backupCodes": [
    "A3F9K2L7",
    "B8N4P1Q6",
    // ... 8 more codes
  ]
}
```

**POST /api/auth/mfa/verify**
```json
Request:
{
  "code": "123456"  // From authenticator app
}

Response (200):
{
  "message": "MFA enabled successfully"
}
```

**POST /api/auth/mfa/disable**
```json
Request:
{
  "code": "123456",  // Confirmation code
  "password": "SecureP@ssw0rd123"  // Require password for security
}

Response (200):
{
  "message": "MFA disabled successfully"
}
```

---

## Testing Strategy

### Unit Tests

**Test Coverage Requirements**:
- Password hashing/verification: 100%
- Token generation/validation: 100%
- MFA TOTP generation/verification: 100%
- OAuth profile parsing: 100%

**Example: Password Hashing Tests**
```python
# See: templates/backend/tests/test_auth_unit.py
import pytest
from auth.password import hash_password, verify_password

def test_password_hashing():
    password = "SecureP@ssw0rd123"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong", hashed) is False

def test_password_with_special_chars():
    # LESSON: Password fields in security scanning
    password = "P@ssw0rd&$|;#"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True

def test_realistic_provider_ids():
    # LESSON: Firebase UID ≠ UUID
    firebase_id = "un42YcgdaeQreBdzKP0PAOyRD4n2"  # 28 chars
    auth0_id = "auth0|abc123def456"

    user1 = create_user(id=firebase_id)
    user2 = create_user(id=auth0_id)

    assert len(user1.id) == 28
    assert "|" in user2.id
```

### Integration Tests

**Test Coverage Requirements**:
- Full auth flow (register → verify → login): 100%
- OAuth flow (redirect → callback → account linking): 100%
- MFA flow (setup → verify → login with MFA): 100%
- Token refresh flow: 100%

**Example: Integration Tests**
```python
# See: templates/backend/tests/test_auth_integration.py
import pytest
from fastapi.testclient import TestClient

def test_full_registration_flow(client: TestClient):
    # Register
    response = client.post("/api/auth/register", json={
        "email": "test@example.com",
        "password": "SecureP@ssw0rd123",
        "name": "Test User"
    })
    assert response.status_code == 201

    # Verify email (simulate clicking verification link)
    verify_token = extract_token_from_email()
    response = client.get(f"/api/auth/verify-email?token={verify_token}")
    assert response.status_code == 200

    # Login
    response = client.post("/api/auth/login", json={
        "email": "test@example.com",
        "password": "SecureP@ssw0rd123"
    })
    assert response.status_code == 200
    assert "sessionid" in response.cookies

def test_mfa_flow(client: TestClient, authenticated_user):
    # Setup MFA
    response = client.post("/api/auth/mfa/setup")
    assert response.status_code == 200
    secret = response.json()["secret"]
    backup_codes = response.json()["backupCodes"]

    # Generate TOTP code
    import pyotp
    totp = pyotp.TOTP(secret)
    code = totp.now()

    # Verify MFA setup
    response = client.post("/api/auth/mfa/verify", json={"code": code})
    assert response.status_code == 200

    # Logout
    client.post("/api/auth/logout")

    # Login with MFA
    response = client.post("/api/auth/login", json={
        "email": authenticated_user.email,
        "password": "password",
        "mfaCode": totp.now()
    })
    assert response.status_code == 200

    # Test backup code
    response = client.post("/api/auth/login", json={
        "email": authenticated_user.email,
        "password": "password",
        "mfaCode": backup_codes[0]
    })
    assert response.status_code == 200

    # Backup code should be invalidated
    response = client.post("/api/auth/login", json={
        "email": authenticated_user.email,
        "password": "password",
        "mfaCode": backup_codes[0]  # Same code
    })
    assert response.status_code == 401
```

### E2E Tests

**Test Coverage Requirements**:
- Web: Full user journey (signup → login → use app → logout)
- iOS: Authentication flows with Keychain integration
- Android: Authentication flows with EncryptedSharedPreferences

**Example: Web E2E Tests (Playwright)**
```typescript
// See: templates/frontend/tests/auth-e2e.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Authentication Flow', () => {
    test('should register, verify email, and login', async ({ page, context }) => {
        // Register
        await page.goto('/signup');
        await page.fill('[name="email"]', 'test@example.com');
        await page.fill('[name="password"]', 'SecureP@ssw0rd123');
        await page.fill('[name="name"]', 'Test User');
        await page.click('button[type="submit"]');

        // Wait for success message
        await expect(page.locator('text=Verification email sent')).toBeVisible();

        // Simulate clicking verification link (in real test, check email)
        const verifyToken = await getVerificationToken('test@example.com');
        await page.goto(`/verify-email?token=${verifyToken}`);

        await expect(page.locator('text=Email verified')).toBeVisible();

        // Login
        await page.goto('/login');
        await page.fill('[name="email"]', 'test@example.com');
        await page.fill('[name="password"]', 'SecureP@ssw0rd123');
        await page.click('button[type="submit"]');

        // Should redirect to dashboard
        await page.waitForURL('/dashboard');

        // Verify session cookie exists
        const cookies = await context.cookies();
        const sessionCookie = cookies.find(c => c.name === 'sessionid');
        expect(sessionCookie).toBeDefined();
        expect(sessionCookie?.httpOnly).toBe(true);
        expect(sessionCookie?.secure).toBe(true);
    });

    test('should enable MFA and login with TOTP', async ({ page }) => {
        await loginAsUser(page, 'test@example.com', 'password');

        // Navigate to security settings
        await page.goto('/settings/security');
        await page.click('text=Enable Two-Factor Authentication');

        // Get QR code and secret
        const secret = await page.getAttribute('[data-mfa-secret]', 'data-value');

        // Generate TOTP code
        const totp = new TOTP(secret!);
        const code = totp.generate();

        // Verify MFA
        await page.fill('[name="mfaCode"]', code);
        await page.click('button:has-text("Verify")');

        await expect(page.locator('text=MFA enabled')).toBeVisible();

        // Logout and login with MFA
        await page.click('text=Logout');
        await page.goto('/login');
        await page.fill('[name="email"]', 'test@example.com');
        await page.fill('[name="password"]', 'password');
        await page.click('button[type="submit"]');

        // Should prompt for MFA code
        await expect(page.locator('text=Enter authentication code')).toBeVisible();

        const newCode = totp.generate();
        await page.fill('[name="mfaCode"]', newCode);
        await page.click('button[type="submit"]');

        await page.waitForURL('/dashboard');
    });
});
```

---

## Deployment Guide

### Environment Variables

**Required for all environments**:
```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Session secret (32+ random bytes)
SESSION_SECRET=your-random-secret-here-change-in-production

# JWT secret (32+ random bytes)
JWT_SECRET=your-jwt-secret-here-change-in-production

# Email service (SendGrid, AWS SES, etc.)
EMAIL_FROM=noreply@yourapp.com
EMAIL_PROVIDER=sendgrid  # or 'ses' | 'smtp'
SENDGRID_API_KEY=SG.xxx  # If using SendGrid

# OAuth - Google
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=xxx
GOOGLE_REDIRECT_URI=https://yourapp.com/api/auth/oauth/google/callback

# OAuth - Apple
APPLE_CLIENT_ID=com.yourapp.service
APPLE_TEAM_ID=xxx
APPLE_KEY_ID=xxx
APPLE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----

# Redis (for web sessions)
REDIS_URL=redis://localhost:6379

# App URLs
WEB_URL=https://yourapp.com
API_URL=https://api.yourapp.com
```

### Docker Deployment

```dockerfile
# See: playbooks/DEPLOYMENT-GUIDE.md for full Docker setup
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

FROM node:18-alpine

# Install security updates
RUN apk update && apk upgrade

WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

# Run as non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001
USER nodejs

EXPOSE 3000

CMD ["node", "dist/index.js"]
```

### Kubernetes Deployment

```yaml
# See: playbooks/K8S-DEPLOYMENT.yaml for full setup
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-api
  template:
    metadata:
      labels:
        app: auth-api
    spec:
      containers:
      - name: auth-api
        image: yourregistry/auth-api:v1.0.0
        ports:
        - containerPort: 3000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: database-url
        - name: SESSION_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: session-secret
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
```

---

## Security Checklist

Before deploying to production:

### Authentication
- [ ] Passwords hashed with Bcrypt (12+ rounds) or Argon2
- [ ] Database user ID columns: varchar(128) minimum
- [ ] Test with realistic provider IDs (Firebase, Auth0, OAuth)
- [ ] Auth headers configured in Nginx/CDN proxy
- [ ] Password fields excluded from security pattern matching
- [ ] Rate limiting: 5 attempts/minute on login endpoint
- [ ] Account lockout after 5 failed attempts (15 min lockout)

### Session Management (Web)
- [ ] HttpOnly cookies (prevents XSS access)
- [ ] Secure flag enabled (HTTPS only)
- [ ] SameSite=Lax (CSRF protection)
- [ ] Session expiry: 24 hours max
- [ ] Redis session store with replication
- [ ] Session regeneration on login (prevents fixation)

### JWT (Mobile)
- [ ] Access token expiry: 15 minutes
- [ ] Refresh token expiry: 7 days
- [ ] Refresh token rotation on use (invalidate old)
- [ ] Refresh tokens hashed in database
- [ ] JWT secret rotation strategy documented
- [ ] Tokens stored in Keychain (iOS) / EncryptedSharedPreferences (Android)

### MFA
- [ ] TOTP with 30-second window (RFC 6238)
- [ ] 10 backup codes generated at setup
- [ ] Backup codes hashed before storage
- [ ] Backup codes single-use (invalidated after use)
- [ ] QR code shown only once at setup
- [ ] MFA recovery process documented

### OAuth
- [ ] Link by provider_user_id, not email
- [ ] Email can change at provider without breaking auth
- [ ] State parameter for CSRF protection
- [ ] Redirect URI whitelist configured
- [ ] Scope minimal (email, profile only)
- [ ] Provider errors handled gracefully

### General Security
- [ ] HTTPS enforced (HSTS header)
- [ ] CSP header configured
- [ ] Rate limiting on all auth endpoints
- [ ] SQL injection tests pass (parameterized queries)
- [ ] XSS tests pass (input sanitization)
- [ ] No secrets in code/logs
- [ ] Security headers configured (X-Frame-Options, X-Content-Type-Options)

---

## Quick Start

### Backend (FastAPI/Python)
```bash
# Copy backend template
cp .claude/skills/auth-universal/templates/backend/fastapi-auth.py ./src/auth.py

# Install dependencies
pip install fastapi passlib[bcrypt] python-jose[cryptography] pyotp qrcode redis

# Set environment variables
export DATABASE_URL="postgresql://..."
export SESSION_SECRET="$(openssl rand -hex 32)"
export JWT_SECRET="$(openssl rand -hex 32)"

# Run migrations
alembic upgrade head

# Start server
uvicorn src.main:app --reload
```

### Frontend (React)
```bash
# Copy React template
cp .claude/skills/auth-universal/templates/frontend/react-auth-hook.ts ./src/hooks/useAuth.ts
cp .claude/skills/auth-universal/templates/frontend/LoginForm.tsx ./src/components/LoginForm.tsx

# Install dependencies
npm install

# Configure API URL
echo "VITE_API_URL=http://localhost:8000" > .env

# Start dev server
npm run dev
```

### Mobile (iOS)
```bash
# Copy iOS templates
cp .claude/skills/auth-universal/templates/mobile/ios/* ./YourApp/Auth/

# Install dependencies (CocoaPods)
pod 'KeychainAccess'
pod install

# Configure API URL in Config.swift
API_BASE_URL = "https://api.yourapp.com"

# Build and run
open YourApp.xcworkspace
```

### Mobile (Android)
```bash
# Copy Android templates
cp .claude/skills/auth-universal/templates/mobile/android/* ./app/src/main/java/com/yourapp/auth/

# Add dependencies to build.gradle
implementation 'androidx.security:security-crypto:1.1.0-alpha06'
implementation 'com.squareup.retrofit2:retrofit:2.9.0'

# Configure API URL in BuildConfig
buildConfigField "String", "API_BASE_URL", "\"https://api.yourapp.com\""

# Build and run
./gradlew assembleDebug
```

---

## Files Included

```
auth-universal/
├── SKILL.md (this file)
├── templates/
│   ├── backend/
│   │   ├── fastapi-auth.py (Complete FastAPI implementation)
│   │   ├── nodejs-auth.ts (Complete Node.js/Express implementation)
│   │   ├── models.py (Database models)
│   │   └── tests/
│   │       ├── test_auth_unit.py
│   │       └── test_auth_integration.py
│   ├── frontend/
│   │   ├── react-auth-hook.ts (React useAuth hook)
│   │   ├── LoginForm.tsx (React login component)
│   │   ├── SignupForm.tsx (React signup component)
│   │   ├── MFASetup.tsx (MFA setup component)
│   │   └── tests/
│   │       └── auth-e2e.spec.ts (Playwright E2E tests)
│   └── mobile/
│       ├── ios/
│       │   ├── AuthManager.swift
│       │   ├── LoginView.swift
│       │   └── MFASetupView.swift
│       └── android/
│           ├── AuthManager.kt
│           ├── LoginActivity.kt
│           └── MFASetupActivity.kt
├── playbooks/
│   ├── DEPLOYMENT-GUIDE.md (Step-by-step deployment)
│   ├── SECURITY-HARDENING.md (Production security checklist)
│   └── TROUBLESHOOTING.md (Common issues and fixes)
├── scripts/
│   └── generate-secrets.sh (Generate SESSION_SECRET and JWT_SECRET)
└── examples/
    ├── complete-app/ (Working demo app with all features)
    └── minimal-setup/ (Minimal working example)
```

---

## Support & Troubleshooting

See `playbooks/TROUBLESHOOTING.md` for:
- Common errors and solutions
- OAuth provider setup guides
- Session/JWT debugging
- MFA issues
- Mobile app-specific problems

---

## Version History

- **v1.0.0** (2026-01-17): Initial release
  - Email auth, MFA, OAuth (Google/Apple)
  - Web, iOS, Android support
  - Complete testing and deployment guides

---

## Related Skills

- **security-owasp**: Security best practices and checklists
- **testing-strategies**: Test templates and fixtures
- **deployment-patterns**: Deployment strategies and rollback procedures
- **e2e-testing**: End-to-end testing with Puppeteer/Playwright

---

**Next Steps**: Review templates in `templates/` directory and follow Quick Start guide above.
