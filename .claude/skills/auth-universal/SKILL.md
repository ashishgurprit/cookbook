# Universal Authentication System

> Production-ready authentication for web, iOS, and Android apps with email auth, MFA, and OAuth (Google/Apple)

## Overview

This skill provides a complete, secure authentication system designed using the 3D Decision Matrix framework. It includes:

✅ **Email Authentication** (username/password with Bcrypt/Argon2)
✅ **Multi-Factor Authentication** (TOTP + Email 2FA fallback + Backup codes)
✅ **MFA Enforcement** (Middleware + RBAC-based mandatory MFA)
✅ **Secret Encryption at Rest** (AES-256 Fernet for TOTP secrets)
✅ **Security Audit Logging** (12+ event types with IP, user agent, method)
✅ **Anti-Brute Force** (Progressive delays + timing attack mitigation)
✅ **OAuth 2.0** (Google and Apple Sign-In)
✅ **Cross-Platform** (Web, iOS, Android)
✅ **Security Hardened** (based on 30+ production incidents across 4 projects)
✅ **Test Coverage** (unit, integration, E2E templates)
✅ **Deployment Ready** (CI/CD pipelines, rollback procedures)

### Enhancements sourced from production projects:
- `claude-essay-agent` — AES-256 encryption, email 2FA, enforcement middleware, audit logging
- `social-media-autopost-plugin` — Temporary MFA tokens, email verification gating, JWT MFA flags
- `enterprise-translation-system` — Progressive rate limiting, timing attack prevention, IP-based token validation
- `business-thinking-frameworks` — RBAC MFA enforcement, guest-to-auth migration, custom TOTP over Firebase

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
    role VARCHAR(20) DEFAULT 'user',  -- 'user' | 'admin' | 'super_admin'

    -- MFA fields (enhanced)
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_method VARCHAR(10) DEFAULT 'totp',  -- 'totp' | 'email'
    mfa_secret_encrypted TEXT,  -- AES-256 Fernet encrypted (NOT plaintext!)
    mfa_required BOOLEAN DEFAULT FALSE,  -- Admin-enforced MFA requirement
    mfa_enrolled_at TIMESTAMPTZ,
    mfa_backup_codes_count INTEGER DEFAULT 0,

    -- Email verification
    email_verification_token VARCHAR(64) UNIQUE,
    email_verification_expires TIMESTAMPTZ,

    -- Lockout
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    last_login_ip VARCHAR(45),  -- IPv6 max length

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
    code_hash VARCHAR(255) NOT NULL,  -- SHA-256 hashed (NOT plaintext!)
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMPTZ,  -- Track when each code was consumed
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE email_2fa_codes (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(128) REFERENCES users(id),
    code_hash VARCHAR(255) NOT NULL,  -- SHA-256 hashed
    expires_at TIMESTAMPTZ NOT NULL,  -- 10 min default
    attempts INTEGER DEFAULT 0,  -- Max 5 verification attempts
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE sessions (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) REFERENCES users(id),
    ip_address VARCHAR(45),  -- For IP validation on refresh
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(128) REFERENCES users(id),
    token_hash VARCHAR(255) NOT NULL UNIQUE,  -- SHA-256 hashed
    ip_address VARCHAR(45),  -- Validate IP on token refresh
    user_agent TEXT,
    revoked BOOLEAN DEFAULT FALSE,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- NEW: Security audit log (from claude-essay-agent + enterprise-translation-system)
CREATE TABLE auth_audit_log (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(128) REFERENCES users(id),
    action VARCHAR(50) NOT NULL,  -- See audit event types below
    method VARCHAR(20),  -- 'totp' | 'backup_code' | 'email_2fa' | 'password'
    success BOOLEAN NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,  -- Flexible metadata (error messages, remaining codes, etc.)
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_user ON auth_audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_action ON auth_audit_log(action, created_at DESC);
CREATE INDEX idx_audit_ip ON auth_audit_log(ip_address, created_at DESC);

-- NEW: Security lockouts (from enterprise-translation-system)
CREATE TABLE security_lockouts (
    id SERIAL PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,  -- IP address or user_id
    identifier_type VARCHAR(10) NOT NULL,  -- 'ip' | 'user'
    reason VARCHAR(50) NOT NULL,  -- 'brute_force' | 'suspicious_activity'
    locked_until TIMESTAMPTZ NOT NULL,
    unlocked_by VARCHAR(128),  -- Admin who manually unlocked
    details JSONB,
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

### 6. MFA Implementation (Enhanced)

#### 6a. TOTP Secret Encryption at Rest (from claude-essay-agent)
```python
# CRITICAL: Never store TOTP secrets in plaintext
# Use AES-256 Fernet encryption for all stored secrets
from cryptography.fernet import Fernet
import pyotp
import qrcode
from io import BytesIO
import base64
import hashlib
import secrets
import os

# Encryption key from environment (generate once, store securely)
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
MFA_ENCRYPTION_KEY = os.environ["MFA_ENCRYPTION_KEY"]
fernet = Fernet(MFA_ENCRYPTION_KEY.encode())

def encrypt_secret(secret: str) -> str:
    """Encrypt TOTP secret with AES-256 Fernet"""
    return fernet.encrypt(secret.encode()).decode()

def decrypt_secret(encrypted: str) -> str:
    """Decrypt TOTP secret"""
    return fernet.decrypt(encrypted.encode()).decode()

def setup_mfa(user_id: str):
    """Generate MFA secret and QR code for user"""
    user = db.users.get(user_id)
    secret = pyotp.random_base32()

    # ENCRYPT before storing (never store plaintext!)
    encrypted_secret = encrypt_secret(secret)
    db.users.update(user_id, mfa_secret_encrypted=encrypted_secret)

    # Generate QR code URI
    totp = pyotp.TOTP(secret)
    issuer = os.environ.get("MFA_ISSUER_NAME", "YourApp")
    uri = totp.provisioning_uri(name=user.email, issuer_name=issuer)

    # Generate QR code image
    qr = qrcode.make(uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    # Generate backup codes (SHA-256 hashed, with individual tracking)
    backup_codes = [generate_backup_code() for _ in range(10)]
    for code in backup_codes:
        db.mfa_backup_codes.create(
            user_id=user_id,
            code_hash=hashlib.sha256(code.replace("-", "").upper().encode()).hexdigest(),
            used=False
        )
    db.users.update(user_id, mfa_backup_codes_count=10)

    # Audit log
    audit_log(user_id, "mfa.enrollment.start", success=True)

    return {
        "secret": secret,  # Show ONCE, user must save
        "qr_code": f"data:image/png;base64,{qr_base64}",
        "backup_codes": backup_codes  # Show ONCE, format: XXXX-XXXX
    }

def generate_backup_code() -> str:
    """Generate 8-character backup code in XXXX-XXXX format"""
    raw = secrets.token_hex(4).upper()  # Cryptographically secure
    return f"{raw[:4]}-{raw[4:]}"
```

#### 6b. MFA Verification with Layered Fallback
```python
def verify_mfa(user_id: str, code: str, method: str = "auto") -> dict:
    """
    Verify MFA code with 3 fallback layers:
    1. TOTP (authenticator app)
    2. Backup codes (single-use recovery)
    3. Email 2FA (ultimate fallback)

    Returns: { verified: bool, method: str, remaining_backup_codes: int }
    """
    user = db.users.get(user_id)
    clean_code = code.replace("-", "").replace(" ", "").strip()

    # Layer 1: Try TOTP
    if method in ("auto", "totp") and user.mfa_secret_encrypted:
        secret = decrypt_secret(user.mfa_secret_encrypted)
        totp = pyotp.TOTP(secret)
        if totp.verify(clean_code, valid_window=1):  # ±30s clock skew
            audit_log(user_id, "mfa.verification.success", method="totp", success=True)
            return {"verified": True, "method": "totp"}

    # Layer 2: Try backup codes (constant-time comparison)
    if method in ("auto", "backup_code"):
        code_hash = hashlib.sha256(clean_code.upper().encode()).hexdigest()
        unused_codes = db.mfa_backup_codes.filter(user_id=user_id, used=False)
        for backup in unused_codes:
            if secrets.compare_digest(code_hash, backup.code_hash):
                db.mfa_backup_codes.update(backup.id, used=True, used_at=utcnow())
                remaining = db.mfa_backup_codes.count(user_id=user_id, used=False)
                db.users.update(user_id, mfa_backup_codes_count=remaining)
                audit_log(user_id, "mfa.backup_code.used", success=True,
                          details={"remaining": remaining})
                return {"verified": True, "method": "backup_code",
                         "remaining_backup_codes": remaining}

    # Layer 3: Try email 2FA code
    if method in ("auto", "email_2fa"):
        email_code = db.email_2fa_codes.find_latest(user_id=user_id, used=False)
        if email_code and email_code.expires_at > utcnow():
            if email_code.attempts >= 5:
                db.email_2fa_codes.update(email_code.id, used=True)  # Invalidate
                audit_log(user_id, "email_2fa.max_attempts", success=False)
                return {"verified": False, "method": "email_2fa", "error": "max_attempts"}
            code_hash = hashlib.sha256(clean_code.encode()).hexdigest()
            if secrets.compare_digest(code_hash, email_code.code_hash):
                db.email_2fa_codes.update(email_code.id, used=True)
                audit_log(user_id, "email_2fa.verified", success=True)
                return {"verified": True, "method": "email_2fa"}
            else:
                db.email_2fa_codes.update(email_code.id,
                                          attempts=email_code.attempts + 1)

    audit_log(user_id, "mfa.verification.failure", success=False)
    return {"verified": False}
```

#### 6c. Email 2FA Fallback (from claude-essay-agent)
```python
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class Email2FAManager:
    """Email-based 2FA as fallback when authenticator app unavailable"""

    RATE_LIMIT = 3  # Max codes per hour per user
    EXPIRY_MINUTES = 10
    MAX_ATTEMPTS = 5

    def generate_and_send(self, user_id: str) -> dict:
        """Generate 6-digit code, hash it, store it, email it"""
        user = db.users.get(user_id)

        # Rate limit: max 3 codes per hour
        recent_count = db.email_2fa_codes.count(
            user_id=user_id,
            created_at__gte=utcnow() - timedelta(hours=1)
        )
        if recent_count >= self.RATE_LIMIT:
            return {"success": False, "error": "rate_limited",
                    "retry_after_minutes": 60}

        # Generate 6-digit code
        code = f"{secrets.randbelow(1000000):06d}"
        code_hash = hashlib.sha256(code.encode()).hexdigest()

        # Invalidate previous unused codes
        db.email_2fa_codes.update_many(
            {"user_id": user_id, "used": False},
            {"used": True}
        )

        # Store hashed code
        db.email_2fa_codes.create(
            user_id=user_id,
            code_hash=code_hash,
            expires_at=utcnow() + timedelta(minutes=self.EXPIRY_MINUTES)
        )

        # Send email
        self._send_email(user.email, code)
        audit_log(user_id, "email_2fa.sent", success=True)

        return {"success": True, "expires_in_minutes": self.EXPIRY_MINUTES}

    def _send_email(self, email: str, code: str):
        """Send 2FA code via SMTP"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"Your verification code: {code}"
        msg["From"] = os.environ["EMAIL_FROM"]
        msg["To"] = email

        html = f"""
        <div style="font-family: sans-serif; max-width: 400px; margin: 0 auto;">
            <h2>Your verification code</h2>
            <div style="font-size: 32px; font-weight: bold; letter-spacing: 4px;
                        padding: 20px; background: #f5f5f5; text-align: center;
                        border-radius: 8px; margin: 20px 0;">
                {code}
            </div>
            <p>This code expires in 10 minutes. Do not share it with anyone.</p>
            <p style="color: #666; font-size: 12px;">
                If you didn't request this, ignore this email.
            </p>
        </div>
        """
        msg.attach(MIMEText(f"Your verification code is: {code}", "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"])) as server:
            server.starttls()
            server.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            server.send_message(msg)
```

#### 6d. MFA Enforcement Middleware (from claude-essay-agent + social-media-autopost)
```python
from fastapi import Request
from fastapi.responses import JSONResponse

# Routes exempt from MFA enforcement
MFA_EXEMPT_ROUTES = {
    "/health", "/docs", "/redoc", "/openapi.json",
    "/api/auth/login", "/api/auth/register", "/api/auth/refresh",
    "/api/auth/verify-email", "/api/auth/forgot-password",
    "/api/auth/mfa/setup", "/api/auth/mfa/verify", "/api/auth/mfa/status",
    "/api/auth/mfa/email/send", "/api/auth/mfa/email/verify",
    "/api/auth/mfa/backup-codes/verify",
}

class MFAEnforcementMiddleware:
    """
    Block access to protected routes for users who have mfa_required=True
    but mfa_enabled=False. Forces them to complete MFA setup first.

    Use cases:
    - Admin creates user with force_mfa=True
    - Security policy requires MFA for all admin/super_admin roles
    - Compliance requirement for elevated privileges
    """
    async def __call__(self, request: Request, call_next):
        # Skip exempt routes
        if request.url.path in MFA_EXEMPT_ROUTES:
            return await call_next(request)

        # Skip if no auth header (unauthenticated routes handle their own)
        if not request.headers.get("Authorization"):
            return await call_next(request)

        # Check user MFA status
        user = getattr(request.state, "user", None)
        if user and user.mfa_required and not user.mfa_enabled:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "mfa_setup_required",
                    "message": "MFA must be enabled before accessing this resource",
                    "redirect": "/setup-mfa"
                }
            )

        return await call_next(request)
```

#### 6e. RBAC-Based MFA Enforcement (from business-thinking-frameworks)
```python
# Admin endpoint to force MFA for a user or role
@router.post("/api/admin/users/{user_id}/require-mfa")
async def require_mfa_for_user(user_id: str, current_user = Depends(get_admin_user)):
    """Admin forces a user to set up MFA before accessing the app"""
    user = db.users.get(user_id)
    if not user:
        raise HTTPException(404, "User not found")

    db.users.update(user_id, mfa_required=True)
    audit_log(current_user.id, "admin.mfa_enforced", success=True,
              details={"target_user": user_id})

    return {"message": f"MFA now required for {user.email}"}

@router.post("/api/admin/roles/{role}/require-mfa")
async def require_mfa_for_role(role: str, current_user = Depends(get_super_admin)):
    """Force MFA for all users with a specific role"""
    if role not in ("user", "admin", "super_admin"):
        raise HTTPException(400, "Invalid role")

    count = db.users.update_many(
        {"role": role, "mfa_required": False},
        {"mfa_required": True}
    )
    audit_log(current_user.id, "admin.mfa_enforced_role", success=True,
              details={"role": role, "affected_users": count})

    return {"message": f"MFA required for {count} users with role '{role}'"}

# CLI script for admin enforcement (from social-media-autopost)
# Usage: python manage.py require-mfa user@example.com
def cli_require_mfa(email: str):
    user = db.users.find_by_email(email)
    if not user:
        print(f"Error: User {email} not found")
        return
    db.users.update(user.id, mfa_required=True)
    print(f"MFA now required for {email}")
```

#### 6f. Disable MFA (requires password + code)
```python
@router.post("/api/auth/mfa/disable")
async def disable_mfa(request: MFADisableRequest, current_user = Depends(get_current_user)):
    """
    Disable MFA - requires BOTH password and current TOTP/backup code.
    From claude-essay-agent: prevents unauthorized MFA removal.
    """
    # Verify password first
    if not pwd_context.verify(request.password, current_user.password_hash):
        audit_log(current_user.id, "mfa.disable.failed", success=False,
                  details={"reason": "invalid_password"})
        raise HTTPException(401, "Invalid password")

    # Verify MFA code
    result = verify_mfa(current_user.id, request.code)
    if not result["verified"]:
        audit_log(current_user.id, "mfa.disable.failed", success=False,
                  details={"reason": "invalid_code"})
        raise HTTPException(401, "Invalid MFA code")

    # Disable MFA
    db.users.update(current_user.id,
        mfa_enabled=False,
        mfa_secret_encrypted=None,
        mfa_enrolled_at=None,
        mfa_backup_codes_count=0
    )
    db.mfa_backup_codes.delete_many(user_id=current_user.id)

    audit_log(current_user.id, "mfa.disabled", success=True)
    return {"message": "MFA disabled successfully"}
```

### 7. Security Audit Logging (from claude-essay-agent + enterprise-translation-system)

```python
from datetime import datetime, timezone

def utcnow():
    """Always use timezone-aware UTC timestamps"""
    return datetime.now(timezone.utc)

def audit_log(user_id: str, action: str, success: bool,
              method: str = None, details: dict = None,
              request: Request = None):
    """
    Log security events for compliance and forensics.

    Event types:
    - auth.login.success / auth.login.failure
    - auth.register
    - auth.logout
    - auth.password_changed
    - auth.password_reset_requested / auth.password_reset_completed
    - mfa.enrollment.start / mfa.enrollment.complete
    - mfa.verification.success / mfa.verification.failure
    - mfa.disabled
    - mfa.backup_code.used
    - email_2fa.sent / email_2fa.verified / email_2fa.max_attempts
    - admin.mfa_enforced / admin.mfa_enforced_role
    - security.lockout / security.suspicious_token_refresh
    """
    ip_address = None
    user_agent = None
    if request:
        ip_address = (
            request.headers.get("CF-Connecting-IP")  # Cloudflare
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.client.host
        )
        user_agent = request.headers.get("User-Agent")

    db.auth_audit_log.create(
        user_id=user_id,
        action=action,
        method=method,
        success=success,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details or {},
        created_at=utcnow()
    )
```

### 8. Anti-Brute Force: Progressive Rate Limiting (from enterprise-translation-system)

```python
import asyncio
import time
from collections import defaultdict

class ProgressiveRateLimiter:
    """
    Smart progressive delays that escalate with failed attempts.
    From enterprise-translation-system — prevents brute force without
    blocking legitimate users.
    """

    # Delay in ms after N failed attempts: [0,0,0,1000,2000,3000,5000,5000,10000,10000]
    DELAY_SCHEDULE = [0, 0, 0, 1000, 2000, 3000, 5000, 5000, 10000, 10000]
    WINDOW_SECONDS = 900  # 15-minute sliding window
    FAKE_HASH = "$2b$12$LJ3m4ks9J5dK2.fake.hash.for.timing.attack.prevention"

    def __init__(self):
        self._attempts = defaultdict(list)  # ip -> [timestamps]

    def get_delay(self, ip: str) -> float:
        """Get delay in seconds for this IP based on recent failures"""
        now = time.time()
        # Clean old attempts
        self._attempts[ip] = [
            t for t in self._attempts[ip]
            if now - t < self.WINDOW_SECONDS
        ]
        count = len(self._attempts[ip])
        idx = min(count, len(self.DELAY_SCHEDULE) - 1)
        return self.DELAY_SCHEDULE[idx] / 1000.0

    def record_failure(self, ip: str):
        self._attempts[ip].append(time.time())

    def clear(self, ip: str):
        """Clear on successful login"""
        self._attempts.pop(ip, None)

rate_limiter = ProgressiveRateLimiter()

async def login_with_protection(email: str, password: str, ip: str):
    """
    Login with timing attack mitigation and progressive delays.
    From enterprise-translation-system.
    """
    start = time.time()

    # Apply progressive delay
    delay = rate_limiter.get_delay(ip)
    if delay > 0:
        await asyncio.sleep(delay)

    user = db.users.find_by_email(email)

    # TIMING ATTACK PREVENTION: Compare against fake hash even if user not found
    # This ensures response time is consistent whether email exists or not
    if not user:
        pwd_context.verify(password, ProgressiveRateLimiter.FAKE_HASH)
        rate_limiter.record_failure(ip)
        # Ensure minimum 500ms response time
        elapsed = time.time() - start
        if elapsed < 0.5:
            await asyncio.sleep(0.5 - elapsed)
        raise HTTPException(401, "Invalid credentials")

    if not pwd_context.verify(password, user.password_hash):
        rate_limiter.record_failure(ip)
        elapsed = time.time() - start
        if elapsed < 0.5:
            await asyncio.sleep(0.5 - elapsed)
        raise HTTPException(401, "Invalid credentials")

    # Success - clear rate limiter
    rate_limiter.clear(ip)
    return user

# IP-based token validation (from enterprise-translation-system)
async def refresh_token_with_ip_check(token: str, ip: str, user_agent: str):
    """
    Validate refresh token AND check IP matches.
    Prevents stolen tokens from being used on different networks.
    """
    stored = db.refresh_tokens.find_by_hash(hashlib.sha256(token.encode()).hexdigest())
    if not stored or stored.revoked or stored.expires_at < utcnow():
        raise HTTPException(401, "Invalid refresh token")

    if stored.ip_address and stored.ip_address != ip:
        # Suspicious: token used from different IP
        audit_log(stored.user_id, "security.suspicious_token_refresh",
                  success=False, details={"original_ip": stored.ip_address,
                                           "current_ip": ip})
        db.refresh_tokens.update(stored.id, revoked=True)
        raise HTTPException(401, "Token revoked due to IP mismatch")

    # Update last used
    db.refresh_tokens.update(stored.id, last_used_at=utcnow())
    return generate_new_tokens(stored.user_id, ip, user_agent)
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
    "A3F9-K2L7",
    "B8N4-P1Q6",
    // ... 8 more codes (XXXX-XXXX format)
  ]
}
```

**POST /api/auth/mfa/verify**
```json
Request:
{
  "code": "123456"  // TOTP, backup code, or email 2FA code
}

Response (200):
{
  "verified": true,
  "method": "totp",  // "totp" | "backup_code" | "email_2fa"
  "remaining_backup_codes": 10  // Only for backup_code method
}
```

**POST /api/auth/mfa/disable**
```json
Request:
{
  "code": "123456",  // TOTP or backup code (required)
  "password": "SecureP@ssw0rd123"  // Password (required)
}

Response (200):
{
  "message": "MFA disabled successfully"
}
```

**GET /api/auth/mfa/status**
```json
Response (200):
{
  "mfaEnabled": true,
  "mfaMethod": "totp",
  "mfaRequired": false,
  "backupCodesRemaining": 8,
  "enrolledAt": "2026-01-15T10:30:00Z"
}
```

**POST /api/auth/mfa/email/send** (Email 2FA fallback)
```json
Request: {} (authenticated or pending-MFA user)

Response (200):
{
  "success": true,
  "expires_in_minutes": 10
}

Response (429):
{
  "success": false,
  "error": "rate_limited",
  "retry_after_minutes": 60
}
```

**POST /api/auth/mfa/email/verify**
```json
Request:
{
  "code": "123456"  // 6-digit code from email
}

Response (200):
{
  "verified": true,
  "method": "email_2fa"
}
```

**GET /api/auth/mfa/backup-codes/count**
```json
Response (200):
{
  "remaining": 8,
  "total": 10
}
```

**POST /api/auth/mfa/backup-codes/regenerate**
```json
Request:
{
  "password": "SecureP@ssw0rd123",  // Required
  "code": "123456"  // Current TOTP code required
}

Response (200):
{
  "backupCodes": ["A3F9-K2L7", "B8N4-P1Q6", ...],  // 10 new codes
  "message": "Previous codes invalidated"
}
```

### Admin Enforcement Endpoints

**POST /api/admin/users/{user_id}/require-mfa** (Admin only)
```json
Response (200):
{
  "message": "MFA now required for user@example.com"
}
```

**POST /api/admin/roles/{role}/require-mfa** (Super Admin only)
```json
Request URL: /api/admin/roles/admin/require-mfa

Response (200):
{
  "message": "MFA required for 12 users with role 'admin'"
}
```

### Audit Log Endpoints

**GET /api/admin/audit-log** (Admin only)
```json
Query params: ?user_id=xxx&action=mfa.verification.failure&from=2026-01-01&limit=50

Response (200):
{
  "events": [
    {
      "id": 1234,
      "user_id": "usr_abc123",
      "action": "mfa.verification.failure",
      "method": "totp",
      "success": false,
      "ip_address": "203.0.113.42",
      "user_agent": "Mozilla/5.0...",
      "details": {},
      "created_at": "2026-01-20T14:30:00Z"
    }
  ],
  "total": 156,
  "limit": 50,
  "offset": 0
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

# MFA Encryption (AES-256 Fernet key - generate once, never rotate without migration)
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
MFA_ENCRYPTION_KEY=your-fernet-key-here
MFA_ISSUER_NAME=YourApp  # Shown in authenticator apps

# Email 2FA (SMTP for sending verification codes)
EMAIL_2FA_ENABLED=true
EMAIL_2FA_EXPIRY_MINUTES=10
SMTP_HOST=smtp.gmail.com  # or your SMTP provider
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

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
- [ ] TOTP secrets encrypted at rest (AES-256 Fernet)
- [ ] 10 backup codes generated at setup
- [ ] Backup codes SHA-256 hashed before storage (NOT plaintext)
- [ ] Backup codes single-use with used_at timestamp tracking
- [ ] Backup codes compared with constant-time `secrets.compare_digest()`
- [ ] QR code shown only once at setup
- [ ] Email 2FA fallback: 6-digit codes, 10min expiry, rate limited 3/hour
- [ ] Email 2FA max 5 verification attempts per code
- [ ] MFA enforcement middleware blocks routes when mfa_required but not enabled
- [ ] RBAC MFA enforcement (admin can force per-user or per-role)
- [ ] MFA disable requires both password AND current code
- [ ] MFA recovery process documented

### Audit & Monitoring
- [ ] Security audit logging for 12+ event types
- [ ] Audit log captures IP (Cloudflare/X-Forwarded-For), user agent, method
- [ ] Audit log uses JSONB details for flexible metadata
- [ ] Indexed by user_id, action, ip_address for fast queries
- [ ] Progressive rate limiting on login (delay schedule escalates)
- [ ] Timing attack mitigation (fake hash comparison, 500ms minimum response)
- [ ] IP-based refresh token validation (revoke on IP mismatch)
- [ ] Security lockout table for IP and user-level lockouts

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

- **v1.1.0** (2026-02-11): MFA Security Enhancements
  - AES-256 Fernet encryption for TOTP secrets at rest
  - Email 2FA fallback (6-digit codes, SMTP, rate limited)
  - MFA enforcement middleware (blocks routes until MFA setup complete)
  - RBAC-based MFA enforcement (per-user and per-role)
  - Security audit logging (12+ event types with IP, user agent, JSONB details)
  - Progressive rate limiting with timing attack mitigation
  - IP-based refresh token validation
  - Constant-time backup code comparison
  - MFA disable requires both password AND code
  - New endpoints: email 2FA, backup code management, admin enforcement, audit log
  - Enhanced database schema: encrypted secrets, audit log, lockout tables
  - Sourced from: claude-essay-agent, social-media-autopost-plugin, enterprise-translation-system, business-thinking-frameworks

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

## Integrates With

| Module | Path | Description |
|--------|------|-------------|
| mobile-biometric-auth | modules/mobile-biometric-auth/ | Biometric authentication for React Native — Face ID, Touch ID, fingerprint auth, secure credential storage |
| mobile-secure-storage | modules/mobile-secure-storage/ | Secure token/credential storage on mobile — Keychain (iOS), Keystore (Android), encrypted storage |
| supabase-mobile-auth | modules/supabase-mobile-auth/ | Supabase Auth integration for React Native — magic links, social login, session management, deep link auth callbacks |

---

**Next Steps**: Review templates in `templates/` directory and follow Quick Start guide above.
