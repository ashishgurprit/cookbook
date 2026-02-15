# Deployment Patterns Skill

**Purpose:** Comprehensive deployment strategies, rollback procedures, and post-deployment validation.

**When to use:** Production deployments, staging releases, infrastructure changes, CI/CD configuration.

---

## Overview

This skill provides battle-tested deployment patterns, emergency rollback procedures, and automated smoke tests to ensure reliable, safe deployments with quick recovery options.

### Key Components

1. **Deployment Patterns** - 5 proven deployment strategies
2. **Rollback Playbooks** - Emergency procedures for all patterns
3. **Smoke Tests** - Automated post-deployment validation
4. **Modern Web Auth Checklist** - OAuth, email, and social login deployment

---

## Deployment Patterns

Detailed documentation: `DEPLOYMENT-PATTERNS.md`

### Pattern Selection Matrix

| Pattern | Speed | Risk | Rollback | Cost | Best For |
|---------|-------|------|----------|------|----------|
| **Blue-Green** | Fast (< 1 min) | Low | Instant | High | Critical services, zero-downtime |
| **Canary** | Medium (5-30 min) | Very Low | Fast | Medium | Risk-averse deployments |
| **Rolling** | Slow (5-15 min) | Medium | Medium | Low | Standard deployments |
| **Dark Launch** | Instant | Very Low | Instant | Medium | New features, A/B testing |
| **Progressive** | Very Slow (hours) | Very Low | Instant | Medium | Major changes, high-traffic |

### Quick Reference

**Blue-Green Deployment:**
- Maintain two identical environments
- Deploy to inactive environment
- Switch traffic instantly
- Keep old environment for quick rollback
- See: `DEPLOYMENT-PATTERNS.md` Section 1

**Canary Deployment:**
- Deploy to small percentage of users (5-10%)
- Monitor metrics closely
- Gradually increase percentage
- Auto-rollback on errors
- See: `DEPLOYMENT-PATTERNS.md` Section 2

**Rolling Deployment:**
- Update instances incrementally
- Maintain availability during rollout
- Lower cost than blue-green
- Slower rollback process
- See: `DEPLOYMENT-PATTERNS.md` Section 3

**Dark Launch (Feature Flags):**
- Deploy code but keep features disabled
- Enable for specific users/groups
- Instant rollback via flag toggle
- No redeployment needed
- See: `DEPLOYMENT-PATTERNS.md` Section 4

**Progressive Delivery:**
- Combines canary + feature flags
- Gradual rollout with fine-grained control
- Geographic or demographic targeting
- Real-time monitoring and adjustment
- See: `DEPLOYMENT-PATTERNS.md` Section 5

---

## Emergency Rollback

Detailed playbook: `playbooks/ROLLBACK-PLAYBOOK.md`

### Rollback Decision Matrix

| Severity | Error Rate | Response Time | Action |
|----------|------------|---------------|--------|
| **P0 - Critical** | >5% errors | >3x baseline | Immediate rollback |
| **P1 - High** | 2-5% errors | 2-3x baseline | Rollback within 15 min |
| **P2 - Medium** | 1-2% errors | 1.5-2x baseline | Monitor, prepare rollback |
| **P3 - Low** | <1% errors | <1.5x baseline | Monitor, fix forward |

### Quick Rollback Commands

```bash
# Blue-Green Rollback (< 1 minute)
./scripts/blue-green-rollback.sh --env=production

# Canary Rollback (< 2 minutes)
./scripts/canary-rollback.sh --env=production

# Rolling Rollback (2-5 minutes)
kubectl rollout undo deployment/myapp

# Feature Flag Rollback (< 30 seconds)
./scripts/feature-flag-rollback.sh --feature=new-checkout

# Database Rollback (varies)
./scripts/database-rollback.sh 20260117_001
```

See `playbooks/ROLLBACK-PLAYBOOK.md` for complete procedures.

---

## Smoke Tests

Automated validation: `scripts/smoke-tests.sh`

### Running Smoke Tests

```bash
# After deploying to staging
./scripts/smoke-tests.sh --target=https://staging.example.com

# After production deployment
./scripts/smoke-tests.sh --target=https://api.example.com

# Run only critical tests
./scripts/smoke-tests.sh --target=https://api.example.com --critical

# Verbose output for debugging
./scripts/smoke-tests.sh --target=https://api.example.com --verbose
```

### Test Categories

**Critical Tests** (must pass):
- Health endpoint responds
- Database connection works
- API root accessible
- Response time < 2 seconds

**Functionality Tests:**
- Version endpoint
- Cache connection
- Authentication (401 for protected routes)
- Error handling (404 for missing routes)

**Security Tests:**
- SSL certificate valid
- CORS headers present
- Security headers (X-Frame-Options, etc.)
- Rate limiting active

**Performance Tests:**
- Content-Type headers
- Metrics endpoint accessible

---

## Core Principle: Fail Fast, Fail Loud

Every deployment issue from LESSONS.md could have been caught with:
1. Startup validation
2. Contract tests
3. Integration tests with realistic data
4. Post-deployment smoke tests

## Pre-Deploy Checklist

### Environment
- [ ] All required env vars set and validated
- [ ] Secrets in correct format
- [ ] API keys match target environment
- [ ] Feature flags configured correctly

### Identity & Auth
- [ ] Tested with REAL auth IDs (not mocks)
- [ ] UUID conversion handles all formats
- [ ] Headers pass through proxy/load balancer
- [ ] Session management tested

### Database
- [ ] Migrations tested on staging first
- [ ] Backup taken before migration
- [ ] ID types match auth provider
- [ ] Connection pool sized appropriately
- [ ] Rollback migration script ready

### API
- [ ] Contract tests pass
- [ ] Error responses properly formatted
- [ ] CORS configured for allowed origins
- [ ] Rate limiting configured
- [ ] API versioning strategy clear

### Payments (if applicable)
- [ ] Webhook handlers are transactional
- [ ] Test vs live keys correct for environment
- [ ] Idempotency keys implemented
- [ ] Refund procedures tested

### Monitoring
- [ ] Logging configured and tested
- [ ] Error tracking active (Sentry, etc.)
- [ ] Metrics collection working
- [ ] Alerts configured for critical metrics
- [ ] Dashboards updated with new metrics

### Communication
- [ ] Deployment announcement sent to team
- [ ] Stakeholders notified of deployment window
- [ ] Rollback procedure reviewed
- [ ] On-call rotation confirmed

---

## Modern Web Authentication Deployment Checklist

**For full-stack applications with OAuth, social login, and email authentication.**

### OAuth Provider Configuration

**Google OAuth:**
- [ ] Client ID and Secret configured for target environment
- [ ] Authorized redirect URIs include all production domains
- [ ] Consent screen configured with correct branding
- [ ] Scopes requested match application needs (profile, email)
- [ ] Token refresh strategy implemented
- [ ] Revocation endpoint tested

**GitHub OAuth:**
- [ ] Application registered for production domain
- [ ] Authorization callback URL matches deployment URL
- [ ] Email privacy settings handled (noreply@github.com)
- [ ] Organization access configured if needed
- [ ] Webhook secret configured securely

**Microsoft/Azure AD:**
- [ ] App registration created in correct tenant
- [ ] Redirect URIs configured for all environments
- [ ] API permissions granted and admin consented
- [ ] Token validation includes issuer and audience checks
- [ ] Multi-tenant configuration correct (if applicable)

**Facebook/Meta Login:**
- [ ] App ID and App Secret for production
- [ ] Valid OAuth Redirect URIs configured
- [ ] App Review completed for public access
- [ ] Data Use Checkup passed
- [ ] Privacy Policy and Terms of Service URLs valid

### Email Authentication & Delivery

**Email Service Provider:**
- [ ] Production API keys configured (SendGrid, Postmark, SES, Resend)
- [ ] Sender domain verified and authenticated
- [ ] SPF, DKIM, and DMARC records configured
- [ ] From address uses verified domain (no @gmail.com in prod)
- [ ] Rate limits understood and respected
- [ ] Bounce and complaint handling configured

**Magic Link / Passwordless:**
- [ ] Link expiration time appropriate (5-15 minutes)
- [ ] One-time use tokens enforced
- [ ] Link format includes security token
- [ ] Deep linking works on mobile browsers
- [ ] Expired link error message user-friendly

**Email Templates:**
- [ ] All email templates tested in major email clients
- [ ] HTML and plain text versions provided
- [ ] Unsubscribe link included (legal requirement)
- [ ] Mobile-responsive design verified
- [ ] Brand assets load correctly (logo, colors)
- [ ] CTA buttons work in all email clients

**Email Deliverability:**
- [ ] Test email delivery to Gmail, Outlook, Yahoo
- [ ] Check spam score (using mail-tester.com)
- [ ] Verify emails not landing in spam folder
- [ ] Monitor bounce rates post-deployment
- [ ] Complaint rate monitoring configured

### Social Login Testing

**Cross-Platform Testing:**
- [ ] Login works on desktop Chrome, Firefox, Safari, Edge
- [ ] Login works on mobile Safari (iOS)
- [ ] Login works on mobile Chrome (Android)
- [ ] Login works in private/incognito mode
- [ ] Login works with ad blockers enabled
- [ ] Popup blockers handled gracefully

**User Flow Testing:**
- [ ] New user registration via social login
- [ ] Existing user login via social login
- [ ] Account linking (email + social account)
- [ ] Account unlinking tested
- [ ] Profile data sync (name, avatar, email)
- [ ] Email change handling

**Edge Cases:**
- [ ] User denies OAuth permissions
- [ ] User closes OAuth popup/redirect
- [ ] User has no public email (GitHub)
- [ ] User changes email on provider side
- [ ] Provider temporary downtime handled
- [ ] Rate limiting from provider handled

### Frontend Security Headers

**Essential Headers:**
- [ ] `Content-Security-Policy` configured
  - script-src includes OAuth provider domains
  - connect-src includes API and OAuth endpoints
  - No 'unsafe-inline' or 'unsafe-eval' unless necessary
- [ ] `X-Frame-Options: DENY` or `SAMEORIGIN`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] `Permissions-Policy` configured (camera, microphone, etc.)

**HTTPS Configuration:**
- [ ] SSL certificate valid and not expiring soon
- [ ] HTTPS redirects configured (HTTP → HTTPS)
- [ ] HSTS header configured (`Strict-Transport-Security`)
- [ ] Mixed content warnings resolved
- [ ] Secure cookies with `SameSite` and `Secure` flags

**CORS Configuration:**
- [ ] CORS headers allow only trusted origins
- [ ] Credentials flag matches cookie requirements
- [ ] Preflight requests handled correctly
- [ ] OPTIONS method responses correct
- [ ] No wildcard `*` for credentials requests

### Client-Side Error Tracking

**Error Monitoring Setup:**
- [ ] Sentry/Rollbar/Bugsnag initialized with correct DSN
- [ ] Environment set correctly (production, staging)
- [ ] Release version tracked for deployments
- [ ] Source maps uploaded for production builds
- [ ] User context attached (userId, email - not PII)
- [ ] Breadcrumbs enabled for user actions

**Authentication Error Tracking:**
- [ ] OAuth errors captured with provider context
- [ ] Token refresh failures tracked
- [ ] CORS errors logged with request details
- [ ] Network timeouts tracked
- [ ] 401/403 responses logged with endpoint
- [ ] Session expiration events tracked

**Privacy & PII:**
- [ ] Sensitive data scrubbed from error reports
- [ ] Email addresses masked or hashed
- [ ] Auth tokens removed from logs
- [ ] Request bodies sanitized
- [ ] Query parameters filtered

### Third-Party Service Health Checks

**OAuth Providers:**
- [ ] Monitor Google OAuth status page
- [ ] Monitor GitHub OAuth status page
- [ ] Monitor Microsoft Azure AD status page
- [ ] Fallback message for provider outages
- [ ] Alternative login methods available

**Email Provider:**
- [ ] Monitor email service status page
- [ ] Webhook endpoints for bounce/complaint notifications
- [ ] Queuing system for failed email sends
- [ ] Retry logic with exponential backoff
- [ ] Alerts for sustained delivery failures

**CDN/Static Assets:**
- [ ] OAuth provider JavaScript SDKs load correctly
- [ ] Google Identity Services script accessible
- [ ] Font/icon CDNs responding
- [ ] Analytics scripts loading

### Mobile Browser Compatibility

**iOS Safari Specific:**
- [ ] OAuth redirects work (not blocked by popup blocker)
- [ ] Cookies persist across redirects
- [ ] localStorage/sessionStorage work correctly
- [ ] Deep links work if using mobile app
- [ ] Private browsing mode tested
- [ ] iPad Safari tested separately

**Android Chrome Specific:**
- [ ] OAuth flows work in Chrome mobile
- [ ] Third-party cookies settings don't break flow
- [ ] WebView compatibility if using in-app browser
- [ ] Intent URLs work if native app integration
- [ ] Samsung Internet browser tested

**Progressive Web App (PWA):**
- [ ] Login works in installed PWA
- [ ] OAuth redirects return to PWA correctly
- [ ] Service worker doesn't break authentication
- [ ] Offline mode handles auth gracefully

### Post-Deployment Auth Testing

**Smoke Tests (run immediately):**
```bash
# Email magic link
curl -X POST $PROD_URL/api/auth/magic-link \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'

# OAuth initiation
curl -I $PROD_URL/api/auth/google

# Token validation
curl -H "Authorization: Bearer $TEST_TOKEN" \
  $PROD_URL/api/auth/me

# Session refresh
curl -X POST $PROD_URL/api/auth/refresh \
  -H "Cookie: refresh_token=$REFRESH_TOKEN"
```

**Critical User Flows:**
- [ ] New user signup via email
- [ ] New user signup via Google
- [ ] Existing user login via email
- [ ] Existing user login via social
- [ ] Password reset flow (if applicable)
- [ ] Session refresh before expiry
- [ ] Logout and session cleanup

**Monitoring Metrics:**
- [ ] OAuth success rate > 95%
- [ ] Email delivery rate > 98%
- [ ] Login success rate > 90%
- [ ] Token refresh success rate > 99%
- [ ] Average login time < 3 seconds
- [ ] Error rate < 2%

### Common Authentication Deployment Failures

| Issue | Symptom | Prevention | Fix |
|-------|---------|------------|-----|
| OAuth redirect mismatch | "redirect_uri_mismatch" error | Verify all redirect URIs | Add missing URI to OAuth app |
| Email delivery failure | Magic links not arriving | Test with mail-tester.com | Fix SPF/DKIM records |
| CORS blocking OAuth | Network errors in browser | Test CORS headers | Add OAuth domain to CORS allow list |
| CSP blocking scripts | OAuth popup/redirect fails | Test CSP policy | Add OAuth domains to script-src |
| Session not persisting | User logged out on refresh | Test cookie settings | Fix SameSite/Secure flags |
| Mobile redirect broken | OAuth stuck on provider page | Test on real mobile devices | Fix mobile deep linking |
| Token refresh failing | Users logged out frequently | Monitor refresh endpoint | Fix refresh token rotation |
| Email in spam folder | Low open rates | Check sender reputation | Improve email authentication |

### Emergency Auth Rollback

If authentication breaks in production:

1. **Immediate Actions:**
   ```bash
   # Check OAuth provider status
   curl https://status.google.com/

   # Check email delivery
   curl -X POST $EMAIL_API/send-test

   # Verify database connectivity
   curl $PROD_URL/api/health/db
   ```

2. **Quick Fixes:**
   - Revert OAuth redirect URI changes
   - Switch to backup email provider
   - Disable new features via feature flags
   - Extend session duration temporarily

3. **Full Rollback:**
   - Rollback deployment using chosen pattern
   - Verify old OAuth configuration active
   - Test authentication flows
   - Communicate with affected users

---

## Post-Deploy Validation

### Immediate Checks (< 5 minutes)

```bash
# 1. Run automated smoke tests
./scripts/smoke-tests.sh --target=$PRODUCTION_URL --critical

# 2. Check error rates
curl "$MONITORING_URL/api/error-rate?last=5m"

# 3. Verify key metrics
curl "$PRODUCTION_URL/health"
curl "$PRODUCTION_URL/metrics"

# 4. Test critical user flow manually
# - Login
# - Core feature usage
# - Payment flow (if applicable)
```

### Monitoring Period (30 minutes)

Watch for:
- Error rate spikes
- Response time increases
- Database connection errors
- Cache misses
- Memory/CPU usage
- Queue depths

### Success Criteria

Deployment is successful when:
- [ ] All smoke tests pass
- [ ] Error rate < 1%
- [ ] Response time within 1.5x baseline
- [ ] No database errors
- [ ] Critical user flows working
- [ ] No alerts triggered
- [ ] 30 minutes of stable metrics

---

## Common Deployment Failures

| Pattern | Symptom | Prevention | Fix |
|---------|---------|------------|-----|
| Silent config fail | Feature breaks at runtime | Startup validation | Add config check on boot |
| ID format mismatch | "Invalid UUID" in prod | Test with real IDs | Convert IDs before use |
| Contract drift | UI does nothing | Contract tests | Version API, update contracts |
| Header loss | 401 only in prod | Proxy config test | Fix proxy passthrough |
| Partial webhook | Payment OK, no credits | Transactional handler | Use DB transactions |
| Database migration failure | App crashes on start | Test on staging first | Rollback migration |
| Feature flag misconfiguration | Wrong users see new feature | Review flag rules | Toggle flag off |
| Cache invalidation failure | Users see old data | Cache strategy test | Manual cache clear |

---

## Resources

### Documentation
- **DEPLOYMENT-PATTERNS.md** - Comprehensive guide to all 5 deployment patterns
- **playbooks/ROLLBACK-PLAYBOOK.md** - Emergency rollback procedures
- **scripts/smoke-tests.sh** - Automated post-deployment validation

### Related Skills
- `/testing-strategies` - Overall testing approach
- `/e2e-testing` - End-to-end testing with Puppeteer
- `/security-hardening` - Security best practices
- `/post-mortem` - Incident retrospectives

---

## Quick Start

1. **Choose deployment pattern** based on risk tolerance and requirements
2. **Review pre-deploy checklist** and ensure all items complete
3. **Deploy using chosen pattern** (see DEPLOYMENT-PATTERNS.md)
4. **Run smoke tests** immediately after deployment
5. **Monitor metrics** for 30 minutes
6. **Be ready to rollback** if metrics degrade

**Remember:** The best rollback is the one you never need. Test thoroughly before deployment!
