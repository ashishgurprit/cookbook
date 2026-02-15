# Universal Authentication - Quick Start Guide

> Get authentication running in your project in 15 minutes

## Prerequisites

- PostgreSQL database
- Redis (for sessions and email MFA codes)
- Email service (SendGrid, AWS SES, or SMTP)
- (Optional) Google/Apple OAuth credentials

---

## Step 1: Generate Secrets (2 minutes)

```bash
# Generate SESSION_SECRET and JWT_SECRET
openssl rand -hex 32  # Run twice, use different values

# Sample output:
# 8f3a9b7c2e1d6f8a4b9c7e3d2f1a6b8c9d7e4f2a1b8c6d9e3f7a2b5c8d1e4f6a9

# Copy these to your .env file
```

---

## Step 2: Environment Variables (3 minutes)

Create `.env` file:

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/myapp

# Secrets (from Step 1)
SESSION_SECRET=your-session-secret-here-32-bytes
JWT_SECRET=your-jwt-secret-here-32-bytes

# Redis
REDIS_URL=redis://localhost:6379

# Email (SendGrid example)
EMAIL_FROM=noreply@yourapp.com
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=SG.your-sendgrid-api-key

# Optional: OAuth
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/auth/oauth/google/callback

# App URLs
WEB_URL=http://localhost:3000
API_URL=http://localhost:8000
```

---

## Step 3: Backend Setup (5 minutes)

### Copy Template

```bash
# Copy the FastAPI template
cp .claude/skills/auth-universal/templates/backend/fastapi-auth.py ./src/auth/

# Or for Node.js/Express (if available)
# cp .claude/skills/auth-universal/templates/backend/nodejs-auth.ts ./src/auth/
```

### Install Dependencies

**Python (FastAPI)**:
```bash
pip install fastapi uvicorn passlib[bcrypt] python-jose[cryptography] \
    pyotp qrcode redis sqlalchemy alembic python-multipart
```

**Node.js (Express)**:
```bash
npm install express bcryptjs jsonwebtoken speakeasy qrcode redis ioredis \
    express-session pg sequelize
```

### Database Migration

```bash
# Create database tables
# See schema in SKILL.md Section "Database Models"

# Example Alembic migration (Python)
alembic init alembic
alembic revision --autogenerate -m "Add auth tables"
alembic upgrade head
```

**Or use raw SQL**:
```sql
-- See SKILL.md for complete SQL schema
CREATE TABLE users (
    id VARCHAR(128) PRIMARY KEY,
    email VARCHAR(254) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255),
    name VARCHAR(100),
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_method VARCHAR(10),
    mfa_secret VARCHAR(32),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ... other tables (see SKILL.md)
```

---

## Step 4: Frontend Setup (3 minutes)

### React

```bash
# Copy React hook
cp .claude/skills/auth-universal/templates/frontend/useAuth.tsx ./src/hooks/

# Install if needed
# npm install (no extra dependencies needed)
```

### Add AuthProvider to your app

```typescript
// src/App.tsx
import { AuthProvider } from './hooks/useAuth';

function App() {
  return (
    <AuthProvider>
      <YourAppRoutes />
    </AuthProvider>
  );
}
```

### Use in components

```typescript
import { useAuth } from './hooks/useAuth';

function LoginPage() {
  const { login } = useAuth();

  async function handleLogin(email: string, password: string) {
    try {
      await login({ email, password });
      // Redirect to dashboard
    } catch (error) {
      // Show error
    }
  }

  // ... render form
}
```

---

## Step 5: Run & Test (2 minutes)

### Start Backend

```bash
# Python
uvicorn src.main:app --reload --port 8000

# Node.js
npm run dev
```

### Start Frontend

```bash
npm run dev
# Opens http://localhost:3000
```

### Test Authentication Flow

1. **Register**: POST to `http://localhost:8000/api/auth/register`
   ```bash
   curl -X POST http://localhost:8000/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "email": "test@example.com",
       "password": "SecureP@ssw0rd123",
       "name": "Test User"
     }'
   ```

2. **Check email** for verification link (or check logs in development)

3. **Login**: POST to `http://localhost:8000/api/auth/login`
   ```bash
   curl -X POST http://localhost:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "test@example.com",
       "password": "SecureP@ssw0rd123"
     }' \
     -c cookies.txt  # Save session cookie
   ```

4. **Get current user**: GET with cookie
   ```bash
   curl http://localhost:8000/api/auth/me \
     -b cookies.txt  # Use saved cookie
   ```

---

## Mobile Setup (iOS/Android)

### iOS (Swift)

```bash
# Copy template
cp .claude/skills/auth-universal/templates/mobile/ios/AuthManager.swift ./YourApp/Auth/

# Install KeychainAccess via CocoaPods
pod 'KeychainAccess'
pod install
```

### Android (Kotlin)

```bash
# Copy template
cp .claude/skills/auth-universal/templates/mobile/android/AuthManager.kt ./app/src/main/java/com/yourapp/auth/

# Add to build.gradle
implementation 'androidx.security:security-crypto:1.1.0-alpha06'
```

---

## Security Checklist

Before going to production:

- [ ] SESSION_SECRET is 32+ random bytes
- [ ] JWT_SECRET is 32+ random bytes (different from SESSION_SECRET)
- [ ] HTTPS enabled (certificates configured)
- [ ] Database backups configured
- [ ] Redis persistence configured
- [ ] Email sending verified (test transactional emails)
- [ ] Rate limiting tested (5 login attempts/minute)
- [ ] Password strength requirements enforced
- [ ] MFA tested (both TOTP and email codes)
- [ ] OAuth redirect URIs whitelisted
- [ ] Nginx/CDN configured to forward auth headers
- [ ] CSP and security headers configured
- [ ] User ID columns are varchar(128) minimum

**Test with these scenarios**:
- [ ] Register → Verify Email → Login → Logout
- [ ] Login with wrong password (should fail after 5 attempts)
- [ ] Setup TOTP MFA → Login with MFA
- [ ] Setup Email MFA → Login with email code
- [ ] OAuth login (Google/Apple)
- [ ] Password reset flow
- [ ] Token refresh (mobile)

---

## Troubleshooting

### "Invalid or expired session"
- Check Redis is running: `redis-cli ping`
- Verify SESSION_SECRET is set correctly
- Check session cookie is being sent (browser DevTools → Network → Cookies)

### "Auth headers lost through proxy"
- Add to Nginx config:
  ```nginx
  proxy_set_header Cookie $http_cookie;
  proxy_pass_request_headers on;
  ```

### "MFA code not working"
- TOTP: Check server time is synchronized (NTP)
- Email: Check Redis for code: `redis-cli GET "mfa_code:user@example.com"`
- Verify code hasn't expired (10 minutes for email codes)

### "OAuth callback failed"
- Check redirect URI matches exactly in provider console
- Verify CLIENT_ID and CLIENT_SECRET are correct
- Check state parameter for CSRF protection

---

## Next Steps

- [ ] Add to your project's `/project:pre-deploy` checklist
- [ ] Set up monitoring for failed login attempts
- [ ] Configure backup procedures for user database
- [ ] Add integration tests (see `templates/backend/tests/`)
- [ ] Add E2E tests (see `templates/frontend/tests/`)
- [ ] Set up OAuth applications for production domains
- [ ] Configure production email service (SendGrid/AWS SES)
- [ ] Plan session cleanup job (delete expired sessions daily)
- [ ] Plan refresh token cleanup job (delete expired tokens weekly)

---

## Production Deployment

See `DEPLOYMENT-GUIDE.md` for:
- Docker setup
- Kubernetes deployment
- Environment-specific configurations
- Secrets management
- Database migration strategy
- Zero-downtime deployment
- Rollback procedures

---

## Support

- **Documentation**: See `SKILL.md` for complete API reference
- **Security**: See `SECURITY-HARDENING.md` for production checklist
- **Troubleshooting**: See `TROUBLESHOOTING.md` for common issues

---

**Total Setup Time**: ~15 minutes for basic setup, ~1 hour for production-ready deployment
