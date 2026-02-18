# Security Review Checklist

> Use this checklist when reviewing code changes for security vulnerabilities.
> Based on OWASP Top 10 + real-world incidents from 30+ production projects.

## Quick Security Scan

Run these commands first to catch obvious issues:

```bash
# Check for hardcoded secrets
grep -r "API_KEY\|SECRET\|PASSWORD" . --exclude-dir={node_modules,.git,dist,build}

# Check for SQL injection patterns
grep -r "query.*+" . --include="*.py" --include="*.js" --include="*.ts"
grep -r "execute.*f\"" . --include="*.py"

# Check for command injection
grep -r "exec\|system\|eval" . --include="*.py" --include="*.js" --include="*.ts"

# Check for XSS vulnerabilities
grep -r "innerHTML\|dangerouslySetInnerHTML" . --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx"

# Run dependency audits
npm audit                # Node.js
pip-audit                # Python
bundle audit             # Ruby
```

---

## 1. Authentication & Identity

### Auth Implementation
- [ ] **Passwords hashed** (bcrypt, argon2 - NOT md5, sha1, plain text)
  - Minimum 12 characters required
  - Requires uppercase, lowercase, number
  - Optional: special characters

- [ ] **Rate limiting on auth endpoints** (5 attempts/minute per IP)
  - Login endpoint
  - Password reset endpoint
  - Registration endpoint

- [ ] **Session handling**
  - HttpOnly cookies (prevents XSS access)
  - Secure flag (HTTPS only)
  - SameSite=Lax or Strict (CSRF protection)
  - Reasonable timeout (1-24 hours based on sensitivity)

### Auth Provider Integration
- [ ] **ID format handling** (Firebase/Auth0/OAuth)
  - Database: varchar(128) minimum for user_id columns (NOT varchar(36))
  - Test fixtures use REAL provider ID formats
  - Example Firebase: `un42YcgdaeQreBdzKP0PAOyRD4n2` (28 chars)
  - Example Auth0: `auth0|abc123def456` (prefix + hash)

- [ ] **Auth headers through proxy**
  - Nginx/CDN configured to pass Authorization header
  - `proxy_set_header Authorization $http_authorization`
  - Smoke test after deployment

### Security Testing
- [ ] **Test with special characters in passwords**
  - `&`, `|`, `;`, `$`, `<`, `>`, `'`, `"`
  - Should NOT trigger security pattern matching
  - Should NOT break authentication

---

## 2. Injection Vulnerabilities

### SQL Injection
- [ ] **Parameterized queries ALWAYS**
  ```python
  # ❌ BAD - String concatenation
  query = f"SELECT * FROM users WHERE id = '{user_id}'"

  # ✅ GOOD - Parameterized
  query = "SELECT * FROM users WHERE id = %s"
  db.execute(query, (user_id,))
  ```

- [ ] **ORM usage preferred** over raw SQL
- [ ] **No f-strings or + concatenation in queries**

### Command/Shell Injection
- [ ] **NEVER concatenate user input into shell commands**
  ```javascript
  // ❌ BAD
  exec(`git commit -m "${userInput}"`);

  // ✅ GOOD - Use spawn with arrays
  spawn('git', ['commit', '-m', userInput]);

  // ✅ BETTER - Use temp files for complex input
  await fs.writeFile(tmpFile, userInput);
  spawn('git', ['commit', '-F', tmpFile]);
  ```

- [ ] **Use subprocess.run() / spawn() with array args**
- [ ] **Use temp files for multi-line/complex inputs** (git commits, SQL, etc.)
- [ ] **Test with malicious inputs**:
  - `$(whoami)` - command substitution
  - `` `backticks` `` - command substitution
  - `; echo pwned` - command chaining
  - `| cat /etc/passwd` - piping

### XSS (Cross-Site Scripting)
- [ ] **textContent preferred over innerHTML**
  ```javascript
  // ✅ SAFE
  element.textContent = userInput;

  // ❌ DANGEROUS
  element.innerHTML = userInput;

  // ✅ OK if escaped
  element.innerHTML = escapeHtml(userInput);

  // ✅ OK with sanitization
  element.innerHTML = DOMPurify.sanitize(userInput);
  ```

- [ ] **All dynamic content escaped**
- [ ] **DOMPurify used for rich content**
- [ ] **Content-Security-Policy header set**
- [ ] **Test with XSS payloads**:
  - `<script>alert('XSS')</script>`
  - `<img src=x onerror=alert('XSS')>`
  - `<svg onload=alert('XSS')>`

---

## 3. Configuration & Environment

### Startup Validation
- [ ] **Environment validation before accepting requests**
  ```python
  def validate_startup_environment():
      required = ["DATABASE_URL", "SECRET_KEY", "STRIPE_KEY"]
      missing = [v for v in required if not os.environ.get(v)]
      if missing:
          print(f"❌ Missing: {', '.join(missing)}")
          sys.exit(1)
      print("✅ Environment validated")

  validate_startup_environment()
  ```

- [ ] **Fail-fast with clear error messages**
- [ ] **All required env vars documented in README**

### Secrets Management
- [ ] **No hardcoded secrets in code**
  - API keys
  - Database passwords
  - JWT secrets
  - OAuth client secrets

- [ ] **Secrets in environment variables only**
- [ ] **JSON credentials base64 encoded**
- [ ] **.gitignore includes credentials files**
- [ ] **Secrets rotation documented**

### Production Configuration
- [ ] **Debug mode OFF** (`DEBUG=false`)
- [ ] **ALLOWED_HOSTS restricted** (NOT `["*"]`)
- [ ] **CORS restricted to production domains**
  - Include localhost for development
  - Exact domain matching (no wildcards unless necessary)

---

## 4. Input Validation & Sanitization

### Input Validation
- [ ] **All user input validated**
  - Type checking
  - Length limits
  - Format validation (email, phone, etc.)
  - Allowed values (enums)

- [ ] **Field-specific max lengths**
  ```typescript
  const sanitized = {
    name: sanitizeInput(data.name, 100),
    email: sanitizeInput(data.email, 254),  // RFC 5321 max
    message: sanitizeInput(data.message, 5000)
  };
  ```

### Security Pattern Matching
- [ ] **Password fields EXCLUDED from pattern matching**
  ```javascript
  const excludedFields = [
    'password', 'newPassword', 'currentPassword',
    'apiKey', 'token', 'secret', 'Authorization'
  ];
  ```

- [ ] **Security scanning on sanitized request bodies only**
- [ ] **Test with complex passwords** (with special chars)

### File Uploads
- [ ] **File type validation** (not just extension)
- [ ] **File size limits enforced**
- [ ] **Content scanning** (if high-risk)
- [ ] **Storage outside web root**
- [ ] **Unique filenames** (prevent overwrites)

---

## 5. HTTP Security Headers

### Required Headers
- [ ] **Content-Security-Policy**
  ```
  default-src 'self';
  script-src 'self' 'unsafe-inline' 'unsafe-eval';
  frame-ancestors 'none'
  ```

- [ ] **X-Frame-Options: DENY** (clickjacking protection)
- [ ] **X-Content-Type-Options: nosniff** (MIME sniffing protection)
- [ ] **X-XSS-Protection: 1; mode=block** (legacy browsers)
- [ ] **Strict-Transport-Security** (HSTS)
  ```
  max-age=31536000; includeSubDomains; preload
  ```

- [ ] **Referrer-Policy: strict-origin-when-cross-origin**
- [ ] **Permissions-Policy** (restrict features)
  ```
  geolocation=(), microphone=(), camera=()
  ```

### Implementation
Check `public/_headers` (Cloudflare) or middleware (Express/FastAPI):
```typescript
// Express middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // ... other headers
  next();
});
```

---

## 6. Rate Limiting

### Endpoints to Protect
- [ ] **Auth endpoints: 5 requests/minute per IP**
  - Login
  - Register
  - Password reset

- [ ] **Contact forms: 5 requests/hour per IP**
- [ ] **API endpoints: Tier-appropriate limits**
- [ ] **Soft blocks (429) before hard blocks (403)**

### Implementation
```typescript
// Cloudflare KV-based rate limiting
const RATE_LIMIT_WINDOW = 3600;  // 1 hour
const MAX_REQUESTS_PER_IP = 5;

const ip = request.headers.get('cf-connecting-ip');
const rateLimitKey = `rate_limit:${ip}`;
const current = await env.RATE_LIMIT.get(rateLimitKey);

if (current && parseInt(current) >= MAX_REQUESTS_PER_IP) {
  return new Response('Too many requests', { status: 429 });
}

await env.RATE_LIMIT.put(
  rateLimitKey,
  String(parseInt(current || '0') + 1),
  { expirationTtl: RATE_LIMIT_WINDOW }
);
```

---

## 7. Dependencies & Supply Chain

### Dependency Audits
- [ ] **npm audit / pip-audit clean**
- [ ] **No known high/critical vulnerabilities**
- [ ] **Unused dependencies removed**
- [ ] **Dependabot/Renovate configured**

### Commands
```bash
# Check vulnerabilities
npm audit
pip-audit
bundle audit

# Fix auto-fixable issues
npm audit fix

# Check outdated packages
npm outdated
pip list --outdated
```

---

## 8. Logging & Monitoring

### Security Events to Log
- [ ] **Authentication attempts** (success and failure)
  ```python
  logger.warning("auth.failed",
      user_id=user_id,
      ip=request.client.host,
      reason="invalid_password",
      attempt_count=attempts
  )
  ```

- [ ] **Authorization failures** (403s)
- [ ] **Input validation failures**
- [ ] **Rate limit hits** (429s)
- [ ] **Admin actions** (create, update, delete)
- [ ] **Data exports/downloads**

### Sensitive Data
- [ ] **NO passwords in logs**
- [ ] **NO API keys in logs**
- [ ] **NO tokens in logs**
- [ ] **NO full credit card numbers**
- [ ] **PII redacted or masked**

### Alerts
- [ ] **Failed auth attempts > threshold**
- [ ] **Multiple 403s from same IP**
- [ ] **Unusual admin activity**
- [ ] **Spike in errors**

---

## 9. Authorization & Access Control

### Permission Checks
- [ ] **EVERY endpoint checks authorization**
  ```python
  if current_user.id != user_id and not current_user.is_admin:
      raise HTTPException(403, "Not authorized")
  ```

- [ ] **Deny by default** (explicit allow required)
- [ ] **Principle of least privilege**
- [ ] **RBAC implemented** (roles: admin, user, guest, etc.)
- [ ] **Resource ownership verified**

### Testing
- [ ] **Test as different user roles**
- [ ] **Test accessing other users' data**
- [ ] **Test privilege escalation attempts**

---

## 10. CORS & API Security

### CORS Configuration
- [ ] **Production domains only** (NOT `*`)
  ```javascript
  const ALLOWED_ORIGINS = [
    'https://site.com',
    'https://www.site.com',
    'http://localhost:3000'  // Dev only
  ];
  ```

- [ ] **Localhost allowed for development**
- [ ] **Credentials allowed only if needed**

### API Security
- [ ] **API keys in headers** (NOT query params)
- [ ] **Request size limits** (50KB for forms, etc.)
- [ ] **CAPTCHA on public forms** (Cloudflare Turnstile, reCAPTCHA)
- [ ] **Webhook signature verification**

---

## 11. Multi-Site Standards

### Template Compliance
- [ ] **Security template applied from master**
- [ ] **Standard HTTP headers configured**
- [ ] **Rate limiting implemented**
- [ ] **CAPTCHA on all forms**
- [ ] **Input validation standardized**

### Validation
Run the validation script:
```bash
./scripts/validate-security.sh
```

Expected checks:
- [ ] `_headers` file exists with all required headers
- [ ] Rate limiting configured
- [ ] CAPTCHA present on forms
- [ ] No hardcoded secrets
- [ ] Startup validation implemented

---

## 12. Testing Checklist

### Security Tests to Run
- [ ] **SQL injection payloads**
  - `' OR '1'='1`
  - `'; DROP TABLE users--`

- [ ] **Command injection payloads**
  - `$(whoami)`
  - `` `whoami` ``
  - `; ls -la`

- [ ] **XSS payloads**
  - `<script>alert('XSS')</script>`
  - `<img src=x onerror=alert(1)>`

- [ ] **Path traversal**
  - `../../etc/passwd`
  - `..\..\windows\system32\config\sam`

- [ ] **Special characters in passwords**
  - `P@ssw0rd&$|;`

- [ ] **Auth with realistic provider IDs**
  - Firebase: `un42YcgdaeQreBdzKP0PAOyRD4n2`
  - Auth0: `auth0|abc123def456`

### Automated Checks
```bash
# Run security linters
npm run lint:security
bandit -r .  # Python
semgrep --config=auto .  # Multi-language

# Run SAST tools
snyk test
horusec start -p .
```

---

## Review Sign-Off

**Reviewer**: ___________________
**Date**: ___________________
**Security Issues Found**: ___________________
**All Critical Issues Resolved**: [ ] Yes [ ] No

### Notes:
