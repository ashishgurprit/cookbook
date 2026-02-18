# Security Patterns (OWASP)

> Security best practices based on OWASP Top 10.
> Auto-discovered when security-related code detected.

## OWASP Top 10 (2021)

### 1. Broken Access Control

**Vulnerability**: Users can act outside their intended permissions.

```python
# BAD - No authorization check
@app.get("/api/users/{user_id}")
def get_user(user_id: str):
    return db.get_user(user_id)  # Anyone can view any user!

# GOOD - Check authorization
@app.get("/api/users/{user_id}")
def get_user(user_id: str, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(403, "Not authorized")
    return db.get_user(user_id)
```

**Prevention Checklist**:
- [ ] Deny by default
- [ ] Check authorization on EVERY request
- [ ] Use role-based access control (RBAC)
- [ ] Log access control failures

### 2. Cryptographic Failures

**Vulnerability**: Sensitive data exposed due to weak crypto.

```python
# BAD - Storing passwords in plain text
user.password = request.password

# GOOD - Hash passwords
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
user.password_hash = pwd_context.hash(request.password)

# BAD - Weak encryption
from Crypto.Cipher import DES  # Don't use DES!

# GOOD - Strong encryption
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)
encrypted = cipher.encrypt(data)
```

**Prevention Checklist**:
- [ ] Use bcrypt/argon2 for passwords
- [ ] Use TLS 1.3 for data in transit
- [ ] Use AES-256 for data at rest
- [ ] Never commit secrets to git
- [ ] Rotate keys regularly

### 3. Injection

**Vulnerability**: Untrusted data sent to interpreter.

```python
# BAD - SQL Injection
query = f"SELECT * FROM users WHERE id = '{user_id}'"
db.execute(query)

# GOOD - Parameterized queries
query = "SELECT * FROM users WHERE id = %s"
db.execute(query, (user_id,))

# GOOD - ORM
user = User.query.filter_by(id=user_id).first()

# BAD - Command injection
os.system(f"convert {filename} output.png")

# GOOD - Use subprocess with list
subprocess.run(["convert", filename, "output.png"], check=True)
```

**Prevention Checklist**:
- [ ] Use parameterized queries ALWAYS
- [ ] Use ORM when possible
- [ ] Validate and sanitize all input
- [ ] Never build commands with string concatenation

### 4. Insecure Design

**Vulnerability**: Missing security controls in design.

```
Design Phase Security Questions:
┌─────────────────────────────────────────────────────────────┐
│ 1. What could go wrong? (Threat modeling)                  │
│ 2. What's the blast radius if compromised?                 │
│ 3. What data needs protection?                              │
│ 4. Who should have access to what?                          │
│ 5. What happens if a dependency is compromised?             │
└─────────────────────────────────────────────────────────────┘
```

**Prevention Checklist**:
- [ ] Threat model during design
- [ ] Principle of least privilege
- [ ] Defense in depth
- [ ] Secure by default

### 5. Security Misconfiguration

**Vulnerability**: Insecure default settings.

```yaml
# BAD - Debug mode in production
DEBUG: true
ALLOWED_HOSTS: ["*"]

# GOOD - Secure production config
DEBUG: false
ALLOWED_HOSTS: ["myapp.com", "www.myapp.com"]
SECURE_BROWSER_XSS_FILTER: true
SECURE_CONTENT_TYPE_NOSNIFF: true
X_FRAME_OPTIONS: "DENY"
SECURE_HSTS_SECONDS: 31536000
```

```python
# Security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
```

### 6. Vulnerable Components

**Vulnerability**: Using components with known vulnerabilities.

```bash
# Check for vulnerabilities
npm audit                    # Node.js
pip-audit                    # Python
bundle audit                 # Ruby
snyk test                    # Multi-language

# Auto-fix where possible
npm audit fix
```

**Prevention Checklist**:
- [ ] Run `npm audit` / `pip-audit` in CI
- [ ] Keep dependencies updated
- [ ] Remove unused dependencies
- [ ] Use Dependabot/Renovate

### 7. Authentication Failures

```python
# Secure authentication patterns

# 1. Rate limiting
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request):
    ...

# 2. Secure session handling
SESSION_CONFIG = {
    "secret_key": os.environ["SESSION_SECRET"],  # From env
    "cookie_httponly": True,
    "cookie_secure": True,  # HTTPS only
    "cookie_samesite": "Lax",
    "permanent_session_lifetime": timedelta(hours=1),
}

# 3. Multi-factor authentication
def verify_mfa(user, code):
    totp = pyotp.TOTP(user.mfa_secret)
    return totp.verify(code, valid_window=1)

# 4. Password requirements
def validate_password(password):
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain uppercase")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain lowercase")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain number")
```

### 8. Data Integrity Failures

```python
# Verify data integrity

# 1. Sign sensitive data
import hmac
import hashlib

def sign_data(data: str, secret: str) -> str:
    return hmac.new(
        secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()

def verify_signature(data: str, signature: str, secret: str) -> bool:
    expected = sign_data(data, secret)
    return hmac.compare_digest(signature, expected)

# 2. Verify webhooks
@app.post("/webhook")
async def webhook(request: Request):
    signature = request.headers.get("X-Signature")
    body = await request.body()

    if not verify_signature(body, signature, WEBHOOK_SECRET):
        raise HTTPException(401, "Invalid signature")
```

### 9. Logging & Monitoring Failures

```python
# Comprehensive security logging

import structlog

logger = structlog.get_logger()

# Log security events
logger.warning("auth.failed",
    user_id=user_id,
    ip=request.client.host,
    reason="invalid_password",
    attempt_count=attempts
)

logger.info("auth.success",
    user_id=user_id,
    ip=request.client.host,
    mfa_used=True
)

logger.critical("security.breach_attempt",
    user_id=user_id,
    action="privilege_escalation",
    ip=request.client.host
)

# What to log:
# - Authentication attempts (success/failure)
# - Authorization failures
# - Input validation failures
# - API rate limit hits
# - Admin actions
# - Data exports
```

### 10. Server-Side Request Forgery (SSRF)

```python
# BAD - User-controlled URL
@app.post("/fetch")
def fetch_url(url: str):
    return requests.get(url).text  # Can access internal services!

# GOOD - Validate and restrict URLs
ALLOWED_HOSTS = ["api.example.com", "cdn.example.com"]

def is_url_allowed(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ["http", "https"]:
        return False
    if parsed.hostname not in ALLOWED_HOSTS:
        return False
    # Block internal IPs
    try:
        ip = socket.gethostbyname(parsed.hostname)
        if ipaddress.ip_address(ip).is_private:
            return False
    except socket.gaierror:
        return False
    return True

@app.post("/fetch")
def fetch_url(url: str):
    if not is_url_allowed(url):
        raise HTTPException(400, "URL not allowed")
    return requests.get(url, timeout=5).text
```

---

## Real-World Security Patterns

> Lessons learned from production incidents across 30+ projects.

### Authentication: Auth Headers Lost Through Proxy

**Symptom**: 401 errors only in production, works locally

**Root Cause**: Nginx/CDN strips or doesn't forward Authorization header

**Solution**:
```nginx
location /api {
    proxy_pass http://backend;
    proxy_set_header Authorization $http_authorization;
    proxy_pass_request_headers on;
}
```

**Prevention**:
- [ ] Smoke test auth endpoint after deployment
- [ ] Test with actual proxy in staging
- [ ] Verify header passthrough in proxy config

---

### Authentication: Firebase UID ≠ UUID

**Symptom**: Unit tests pass, production fails with ID errors

**Root Cause**: Tests use `uuid.uuid4()` which produces valid UUIDs. Real auth systems use provider-specific formats.

**Solution**: Test with realistic ID formats
```python
# In tests - use REAL auth provider ID formats
SAMPLE_REALISTIC_IDS = [
    "un42YcgdaeQreBdzKP0PAOyRD4n2",  # Firebase (28 chars, alphanumeric)
    "auth0|abc123def456",             # Auth0 (prefix + hash)
    "google-oauth2|123456789",        # Google OAuth
    str(uuid.uuid4()),                # Actual UUID (36 chars with dashes)
]

# Database column must handle longest format
user_id = models.CharField(max_length=128)  # Not varchar(36)!
```

**Prevention**:
- [ ] Integration tests MUST use realistic ID formats
- [ ] Parameterize tests with all expected ID formats
- [ ] Database ID columns: varchar(128) minimum for auth provider IDs
- [ ] Add sample IDs from each auth provider to test fixtures

---

### Injection: Shell Injection in Git Commit Messages

**Attack Vector**: Blog post title like "AI in 2025; echo 'hacked' > /tmp/pwned" would execute arbitrary command

**BAD - Escaping approach (incomplete)**:
```javascript
// Missing many shell metacharacters!
const escaped = title.replace(/"/g, '\\"').replace(/\n/g, ' ');
exec(`git commit -m "${escaped}"`);
```

**GOOD - Temp file approach (bulletproof)**:
```javascript
const fs = require('fs').promises;
const { spawn } = require('child_process');

// Write to temp file - no escaping needed!
const tmpFile = `/tmp/commit-msg-${Date.now()}.txt`;
await fs.writeFile(tmpFile, commitMessage);

// Use spawn with -F flag (read message from file)
const git = spawn('git', ['commit', '-F', tmpFile]);
await new Promise((resolve, reject) => {
    git.on('close', code => code === 0 ? resolve() : reject());
});

await fs.unlink(tmpFile);  // Cleanup
```

**Prevention**:
- [ ] NEVER concatenate user input into shell commands
- [ ] Use temp files for multi-line or complex inputs
- [ ] Use `child_process.spawn()` with array args instead of `exec()`
- [ ] Test with malicious inputs: `$(whoami)`, `` `backticks` ``, `; echo pwned`, `| cat /etc/passwd`

---

### XSS Prevention: Both Server AND Client Escaping Required

**Vulnerability**: User-generated content inserted into DOM without escaping

**BAD**:
```javascript
element.innerHTML = userContent;  // XSS vulnerability!
```

**GOOD - Defense in depth**:
```javascript
// Option 1: Use textContent (safe, no HTML)
element.textContent = userContent;

// Option 2: Escape HTML entities
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
element.innerHTML = escapeHtml(userContent);

// Option 3: Use DOMPurify for rich content
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userContent);
```

**Prevention**:
- [ ] Use textContent instead of innerHTML where possible
- [ ] Escape all dynamic content inserted into HTML
- [ ] Add XSS tests to security test suite
- [ ] Set Content-Security-Policy header
- [ ] Consider using a template library with auto-escaping

---

### Security Misconfiguration: Password Fields in Security Scanning

**Symptom**: Users with complex passwords containing `&`, `|`, `;`, `$` get locked out with "SUSPICIOUS_REQUEST"

**Root Cause**: Security pattern matching scanned ALL fields including passwords

**Solution**:
```javascript
// Smart security with field exclusion
const CONFIG = {
  excludedFields: [
    'password', 'newPassword', 'currentPassword', 'oldPassword',
    'apiKey', 'token', 'secret', 'Authorization', 'authToken'
  ]
};

function sanitizeBodyForAnalysis(body) {
  if (!body || typeof body !== 'object') return body;
  const sanitized = { ...body };
  for (const field of CONFIG.excludedFields) {
    if (field in sanitized) {
      sanitized[field] = '[REDACTED]';
    }
  }
  return sanitized;
}

// Analyze only sanitized body
const sanitizedBody = sanitizeBodyForAnalysis(req.body);
if (suspiciousPattern.test(JSON.stringify(sanitizedBody))) {
  // Handle threat - passwords won't trigger false positives
}
```

**Prevention**:
- [ ] Always exclude password/token fields from security pattern matching
- [ ] Use an explicit excludedFields list, not regex exclusions
- [ ] Test security with passwords containing: `&`, `|`, `;`, `$`, `<`, `>`
- [ ] Document which fields are excluded and why

---

### Secure Configuration: Startup Validation

**Symptom**: App starts but features fail at runtime with cryptic errors

**Root Cause**: Missing/invalid env vars not caught until user hits the feature

**Solution**: Fail-fast startup validation
```python
def validate_startup_environment():
    """Validate all config at startup. Fail fast."""
    errors = []

    # Required vars
    for var in ["DATABASE_URL", "SECRET_KEY", "STRIPE_KEY"]:
        if not os.environ.get(var):
            errors.append(f"Missing required: {var}")

    # Format validation
    try:
        parse_firebase_credentials(os.environ.get("FIREBASE_CREDENTIALS", ""))
    except ValueError as e:
        errors.append(f"Invalid FIREBASE_CREDENTIALS: {e}")

    if errors:
        print("❌ STARTUP VALIDATION FAILED:")
        for error in errors:
            print(f"  • {error}")
        sys.exit(1)

    print("✅ Environment validated successfully")

# Call at app startup (before accepting requests)
validate_startup_environment()
```

**JavaScript/TypeScript variant**:
```typescript
function validateConfig() {
  const required = ['DATABASE_URL', 'JWT_SECRET', 'STRIPE_KEY'];
  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0) {
    console.error('❌ Missing required environment variables:');
    missing.forEach(key => console.error(`  • ${key}`));
    process.exit(1);
  }

  // Format validation
  if (process.env.PORT && isNaN(Number(process.env.PORT))) {
    console.error('❌ PORT must be a number');
    process.exit(1);
  }

  console.log('✅ Configuration validated');
}

// Call before starting server
validateConfig();
app.listen(PORT);
```

**Prevention**:
- [ ] Add startup validation to every project
- [ ] CI runs startup in validation mode
- [ ] Fail fast with clear error messages
- [ ] Log all config issues prominently

---

### Multi-Site Security: Template-First Approach

**Problem**: Each site's security implemented from scratch, no standard checklist

**Solution**: Security template for consistent standards across all sites

**Cloudflare Functions template**:
```typescript
// functions/api/contact.ts
const MAX_REQUEST_SIZE = 50000;
const RATE_LIMIT_WINDOW = 3600;  // 1 hour
const MAX_REQUESTS_PER_IP = 5;
const ALLOWED_ORIGINS = ['https://site.com', 'https://www.site.com'];

function sanitizeInput(input: string, maxLength: number): string {
  return input.trim().slice(0, maxLength).replace(/[<>]/g, '');
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
  const { request, env } = context;

  // 1. Size check
  const contentLength = parseInt(request.headers.get('content-length') || '0');
  if (contentLength > MAX_REQUEST_SIZE) {
    return new Response('Request too large', { status: 413 });
  }

  // 2. CORS check
  const origin = request.headers.get('origin');
  if (!ALLOWED_ORIGINS.includes(origin || '')) {
    return new Response('Forbidden', { status: 403 });
  }

  // 3. Rate limiting (using KV)
  const ip = request.headers.get('cf-connecting-ip');
  const rateLimitKey = `rate_limit:${ip}`;
  const current = await env.RATE_LIMIT.get(rateLimitKey);

  if (current && parseInt(current) >= MAX_REQUESTS_PER_IP) {
    return new Response('Too many requests', { status: 429 });
  }

  await env.RATE_LIMIT.put(rateLimitKey, String(parseInt(current || '0') + 1), {
    expirationTtl: RATE_LIMIT_WINDOW
  });

  // 4. Input validation and sanitization
  const data = await request.json();
  const sanitized = {
    name: sanitizeInput(data.name, 100),
    email: sanitizeInput(data.email, 254),  // RFC 5321 max
    message: sanitizeInput(data.message, 5000)
  };

  // ... rest of handler
};
```

**HTTP Security Headers** (`public/_headers`):
```
/*
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https://api.cloudflare.com; frame-ancestors 'none'
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  X-XSS-Protection: 1; mode=block
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: geolocation=(), microphone=(), camera=()
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Prevention**:
- [ ] Create security templates for each platform (Cloudflare, Railway, Vercel)
- [ ] Document standard security checklist for all sites
- [ ] Rate limiting: 5 requests/hour per IP for contact forms
- [ ] CORS whitelist: production domains only, localhost for dev
- [ ] HTTP security headers: CSP, X-Frame-Options, HSTS, X-XSS-Protection
- [ ] Input validation with field-specific max lengths
- [ ] CAPTCHA on all forms (Cloudflare Turnstile, reCAPTCHA)
- [ ] Create validation script: `scripts/validate-security.sh`

---

## Security Checklist

```markdown
## Pre-Deploy Security Checklist

### Authentication & Identity
- [ ] Passwords hashed with bcrypt/argon2 (min 12 chars, uppercase, lowercase, number)
- [ ] Rate limiting on auth endpoints (5/minute per IP)
- [ ] Session cookies HttpOnly + Secure + SameSite
- [ ] CSRF protection enabled
- [ ] Auth headers tested through proxy/CDN
- [ ] Database ID columns handle auth provider formats (varchar(128) minimum)
- [ ] Auth endpoints smoke tested post-deployment
- [ ] Test with realistic auth provider IDs (Firebase, Auth0, OAuth)

### Authorization
- [ ] Every endpoint checks permissions
- [ ] Principle of least privilege
- [ ] Admin actions logged
- [ ] Role-based access control (RBAC) implemented

### Data Protection
- [ ] TLS everywhere (minimum TLS 1.2, prefer 1.3)
- [ ] Sensitive data encrypted at rest (AES-256)
- [ ] No secrets in code/git
- [ ] PII handling documented
- [ ] Environment variables for all secrets
- [ ] Base64 encode JSON credentials

### Input Validation & Injection Prevention
- [ ] All input validated and sanitized
- [ ] Parameterized queries only (NEVER string concatenation)
- [ ] File uploads validated (type, size, content)
- [ ] XSS protection: textContent OR escapeHtml() OR DOMPurify
- [ ] Shell commands use spawn() with arrays, NOT exec() with strings
- [ ] User input to shell? Use temp files, not escaping
- [ ] Test with malicious inputs: `$(whoami)`, backticks, semicolons, pipes

### Security Configuration
- [ ] Startup environment validation (fail-fast)
- [ ] Debug mode OFF in production
- [ ] ALLOWED_HOSTS/CORS restricted to production domains
- [ ] Password fields excluded from security pattern matching
- [ ] Test security with special characters in passwords: &, |, ;, $, <, >

### Headers
- [ ] Content-Security-Policy: default-src 'self'
- [ ] X-Frame-Options: DENY
- [ ] X-Content-Type-Options: nosniff
- [ ] X-XSS-Protection: 1; mode=block
- [ ] Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
- [ ] Referrer-Policy: strict-origin-when-cross-origin

### Dependencies
- [ ] npm audit / pip-audit clean
- [ ] No known vulnerabilities
- [ ] Dependabot/Renovate configured
- [ ] Remove unused dependencies

### Rate Limiting
- [ ] Contact forms: 5 requests/hour per IP
- [ ] Auth endpoints: 5 requests/minute per IP
- [ ] API endpoints: Appropriate limits per tier
- [ ] Soft blocks (429) before hard blocks (403)

### Logging & Monitoring
- [ ] Security events logged (auth attempts, authorization failures)
- [ ] No sensitive data in logs (passwords, tokens, API keys)
- [ ] Alerts configured for suspicious activity
- [ ] Failed auth attempts tracked

### Multi-Site Standards
- [ ] Security template applied from master
- [ ] CAPTCHA on all forms
- [ ] Input max lengths match RFC standards (email: 254, etc.)
- [ ] Validation script run: scripts/validate-security.sh
```
