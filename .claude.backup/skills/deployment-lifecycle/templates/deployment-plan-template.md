# Deployment Plan: [Release Version]

**Release Version**: vX.Y.Z
**Deployment Date**: YYYY-MM-DD
**Deployment Time**: HH:MM UTC
**Deployment Window**: X hours
**Deployment Type**: [Blue-Green/Rolling/Canary]

---

## Deployment Summary

**What's Being Deployed**:
- Brief description of changes
- Key features
- Bug fixes
- Dependencies updated

**Why This Deployment**:
- Business justification
- User impact
- Technical debt addressed

---

## Pre-Deployment Checklist

### Code Quality (Completed by [Date])

- [ ] All tests passing (unit, integration, E2E)
- [ ] Code coverage ≥ 80%
- [ ] No linting errors
- [ ] Security scan passed (Snyk, OWASP ZAP)
- [ ] Dependencies updated (no critical CVEs)
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Release notes drafted

### Staging Verification (Completed by [Date])

- [ ] Deployed to staging successfully
- [ ] Smoke tests passed
- [ ] Integration tests passed
- [ ] Performance tests passed (load, stress)
- [ ] Database migrations tested
- [ ] External API integrations verified
- [ ] Browser compatibility tested
- [ ] Mobile responsiveness verified
- [ ] Accessibility tested (WCAG 2.1 AA)

### Infrastructure Preparation (Completed by [Date])

- [ ] Database backup scheduled
- [ ] Monitoring configured (Datadog, New Relic)
- [ ] Error tracking configured (Sentry)
- [ ] Logging aggregation configured
- [ ] Feature flags configured
- [ ] Rollback plan documented (see below)
- [ ] Capacity planning reviewed
- [ ] Auto-scaling configured

### Communication (Completed by [Date])

- [ ] Team notified (Slack #engineering)
- [ ] Stakeholders notified (email)
- [ ] Support team briefed
- [ ] Status page scheduled maintenance notice
- [ ] Customer communication drafted (if needed)
- [ ] On-call engineer assigned
- [ ] War room scheduled (Slack, Zoom)

---

## Database Migration Plan

### Migration Overview

**Schema Changes**:
- Table: `users`
  - Add column: `email_verified BOOLEAN DEFAULT FALSE`
  - Add index: `idx_users_email_verified`

- Table: `payments`
  - Add column: `stripe_payment_intent_id VARCHAR(255)`
  - Add index: `idx_payments_stripe_id`

**Migration Type**: [Additive/Destructive]
**Estimated Duration**: X minutes
**Downtime Required**: [Yes/No]

### Migration Strategy

**Zero-Downtime Pattern** (Expand-Contract):

1. **Phase 1** (Day 1): Add new columns
   ```sql
   ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE;
   CREATE INDEX idx_users_email_verified ON users(email_verified);
   ```

2. **Phase 2** (Day 2): Deploy code that writes to both old and new columns
   ```python
   user.is_verified = True  # Old column
   user.email_verified = True  # New column (backfill)
   ```

3. **Phase 3** (Day 3): Backfill historical data
   ```sql
   UPDATE users SET email_verified = is_verified WHERE email_verified IS NULL;
   ```

4. **Phase 4** (Day 7): Deploy code that only uses new column
   ```python
   user.email_verified = True  # Only new column
   ```

5. **Phase 5** (Day 14): Drop old column
   ```sql
   ALTER TABLE users DROP COLUMN is_verified;
   ```

### Migration Rollback Plan

**If migration fails**:
```sql
-- Rollback Phase 1
ALTER TABLE users DROP COLUMN email_verified;
DROP INDEX idx_users_email_verified;

-- Rollback Phase 5 (if needed)
ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;
UPDATE users SET is_verified = email_verified;
```

---

## Deployment Steps

### Pre-Deployment (T-1 hour)

1. **Final staging verification**
   ```bash
   npm run test:smoke -- --url=https://staging.example.com
   ```

2. **Database backup**
   ```bash
   pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql
   aws s3 cp backup_*.sql s3://myapp-backups/
   ```

3. **Notify team**
   ```
   Slack #engineering: "🚀 Production deployment starting in 60 minutes (v1.2.3)"
   ```

4. **Open monitoring dashboards**
   - Datadog: Error rate, response time, throughput
   - Sentry: Real-time error tracking
   - AWS CloudWatch: Infrastructure metrics

### Deployment (T-0)

**Step 1: Database migration** (T+0)
```bash
# Dry run first
python manage.py migrate --check

# Execute migration
python manage.py migrate

# Verify migration
psql $DATABASE_URL -c "\d users"
```

**Step 2: Deploy application** (T+5)

**Option A: Blue-Green Deployment**
```bash
# Deploy to green environment
kubectl set image deployment/myapp-green myapp=myapp:v1.2.3 -n production

# Wait for rollout
kubectl rollout status deployment/myapp-green -n production --timeout=5m

# Run smoke tests on green
npm run test:smoke -- --url=https://green.example.com

# Switch load balancer to green
kubectl patch service myapp -p '{"spec":{"selector":{"version":"green"}}}'

# Monitor for 30 minutes
# If OK, decommission blue
# If issues, switch back to blue
```

**Option B: Rolling Deployment**
```bash
kubectl set image deployment/myapp myapp=myapp:v1.2.3 -n production
kubectl rollout status deployment/myapp -n production --timeout=10m
```

**Option C: Canary Deployment**
```bash
# Deploy canary (5% traffic)
kubectl set image deployment/myapp-canary myapp=myapp:v1.2.3 -n production
kubectl scale deployment/myapp-canary --replicas=1 -n production

# Monitor canary for 30 minutes
# If OK, increase to 25%
kubectl scale deployment/myapp-canary --replicas=5 -n production

# If OK, full rollout
kubectl set image deployment/myapp myapp=myapp:v1.2.3 -n production
```

**Step 3: Run smoke tests** (T+15)
```bash
npm run test:smoke -- --url=https://api.example.com

# Test critical user flows
- User registration
- User login
- Payment processing
- Email delivery
- API health check
```

### Post-Deployment (T+30)

**Step 4: Monitor for errors** (T+30 to T+60)
```bash
# Check error rate
ERROR_RATE=$(curl -s "https://api.example.com/health/errors" | jq '.rate')
if [ "$ERROR_RATE" -gt 1 ]; then
  echo "Error rate too high: $ERROR_RATE%"
  # Consider rollback
fi

# Check response time
P95_TIME=$(curl -s "https://api.example.com/health/performance" | jq '.p95')
if [ "$P95_TIME" -gt 2000 ]; then
  echo "P95 response time too high: ${P95_TIME}ms"
  # Consider rollback
fi
```

**Step 5: Verify critical features**
- [ ] User registration works
- [ ] User login works
- [ ] Payment processing works
- [ ] Email delivery works
- [ ] API responses correct
- [ ] Database queries performant

**Step 6: Mark deployment successful** (T+60)
```bash
# Create git tag
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3

# Create GitHub release
gh release create v1.2.3 --title "v1.2.3" --notes "$(cat RELEASE_NOTES.md)"

# Notify team
curl -X POST $SLACK_WEBHOOK -d '{"text":"✅ Production deployment successful: v1.2.3"}'

# Update status page
# Remove scheduled maintenance notice
```

---

## Rollback Plan

### Rollback Triggers

**Immediate Rollback** (within 5 minutes):
- Error rate > 5%
- P95 response time > 5 seconds
- Database migration failed
- Payment processing broken
- Data corruption detected

**Rollback Within 15 Minutes**:
- Error rate > 2%
- P95 response time > 3 seconds
- User reports spike
- Support ticket spike

### Rollback Procedure

**Step 1: Decision to rollback** (T+0)
```
Slack #engineering: "🔴 ROLLBACK INITIATED - v1.2.3 → v1.2.2"
```

**Step 2: Execute rollback** (T+2)

**Application Rollback**:
```bash
# Kubernetes rollback
kubectl rollout undo deployment/myapp -n production
kubectl rollout status deployment/myapp -n production --timeout=5m

# Or specific version
kubectl rollout undo deployment/myapp --to-revision=3 -n production
```

**Database Rollback** (if migration ran):
```bash
# Restore from backup (if needed)
aws s3 cp s3://myapp-backups/backup_20260118_103000.sql .
psql $DATABASE_URL < backup_20260118_103000.sql

# Or run down migration
python manage.py migrate app_name 0042_previous_migration
```

**Feature Flag Rollback**:
```bash
# Disable feature flag
curl -X PATCH https://app.launchdarkly.com/api/v2/flags/my-project/new-feature \
  -H "Authorization: $LD_API_KEY" \
  -d '{"variations": [{"value": false}]}'
```

**Step 3: Verify rollback** (T+5)
```bash
# Run smoke tests
npm run test:smoke -- --url=https://api.example.com

# Check error rate
ERROR_RATE=$(curl -s "https://api.example.com/health/errors" | jq '.rate')
echo "Error rate after rollback: $ERROR_RATE%"

# Check response time
P95_TIME=$(curl -s "https://api.example.com/health/performance" | jq '.p95')
echo "P95 response time after rollback: ${P95_TIME}ms"
```

**Step 4: Notify stakeholders** (T+10)
```
Subject: Production Rollback - v1.2.3 → v1.2.2

We rolled back production from v1.2.3 to v1.2.2 at [TIME] UTC.

Reason: [REASON]
Impact: [IMPACT]
Current Status: Stable on v1.2.2
Next Steps: Root cause analysis, fix, re-deploy

Incident: INC-XXXX
```

**Step 5: Post-rollback** (T+30)
- [ ] Error rate back to normal
- [ ] Response time back to normal
- [ ] Status page updated
- [ ] Support team notified
- [ ] Post-mortem scheduled (within 24 hours)

---

## Monitoring & Alerting

### Key Metrics to Watch

**Application Metrics**:
- Request rate (requests/second)
- Error rate (errors/total requests) - Alert if >1%
- Response time (p50, p95, p99) - Alert if p95 >2s
- Database query time - Alert if >500ms
- Cache hit rate - Alert if <80%

**Infrastructure Metrics**:
- CPU usage - Alert if >80%
- Memory usage - Alert if >90%
- Disk I/O - Alert if >80%
- Database connections - Alert if >90% of max

**Business Metrics**:
- User registrations
- Payment success rate - Alert if <95%
- Email delivery rate - Alert if <98%

### Alerting Configuration

```yaml
# Datadog alerts
alerts:
  - name: High Error Rate
    query: "sum:http.errors{env:production}/sum:http.requests{env:production}*100"
    threshold: 1.0  # 1%
    duration: 5m
    severity: critical
    notify: ["pagerduty", "slack"]

  - name: Slow Response Time
    query: "p95:http.response_time{env:production}"
    threshold: 2000  # 2 seconds
    duration: 10m
    severity: warning
    notify: ["slack"]

  - name: Payment Failure Rate High
    query: "sum:payment.failed{env:production}/sum:payment.total{env:production}*100"
    threshold: 5.0  # 5%
    duration: 5m
    severity: critical
    notify: ["pagerduty", "slack"]
```

---

## Communication Plan

### Before Deployment

**T-24 hours**: Email to stakeholders
```
Subject: Production Deployment - v1.2.3 (Tomorrow at [TIME] UTC)

We will be deploying v1.2.3 to production tomorrow at [TIME] UTC.

What's changing:
- [Feature 1]
- [Feature 2]
- [Bug fix 1]

Expected impact:
- No downtime expected
- Database migration (non-blocking)
- Feature flags for gradual rollout

Deployment window: [TIME] to [TIME] UTC
Rollback plan: In place and tested

Questions? Reply to this email or Slack #engineering
```

**T-1 hour**: Slack #engineering
```
🚀 Production deployment starting in 1 hour (v1.2.3)
- Deployment time: [TIME] UTC
- Expected duration: X minutes
- On-call engineer: @jane
- War room: #deploy-v1-2-3
```

### During Deployment

**T+0**: Status page
```
Scheduled Maintenance: Production Deployment
Start: [TIME] UTC
End: [TIME] UTC
Impact: None expected (zero-downtime deployment)
```

**T+15**: Slack #engineering (progress update)
```
✅ Deployment in progress
- Database migration: Complete
- Application deployment: 50% complete
- Smoke tests: Pending
```

### After Deployment

**T+60**: Slack #engineering (success)
```
✅ Production deployment successful: v1.2.3
- Deployment time: X minutes
- Error rate: 0.1% (normal)
- Response time: 150ms p95 (normal)
- All smoke tests passed
- Monitoring for next 24 hours
```

**T+60**: Email to stakeholders
```
Subject: ✅ Production Deployment Complete - v1.2.3

Production deployment completed successfully at [TIME] UTC.

What changed:
- [Feature 1] - Now live
- [Feature 2] - Behind feature flag (5% rollout)
- [Bug fix 1] - Resolved

Status:
- All systems operational
- No errors detected
- Performance normal

Monitoring:
- We're monitoring closely for the next 24 hours
- Report any issues to #engineering

Release notes: https://github.com/myapp/releases/tag/v1.2.3
```

---

## Success Criteria

**Deployment is considered successful when**:

- [ ] Error rate <1% (5 minutes sustained)
- [ ] P95 response time <2 seconds
- [ ] Database migration completed successfully
- [ ] All smoke tests passed
- [ ] Critical user flows work (login, payment, etc.)
- [ ] No alerts triggered
- [ ] Feature flags configured correctly
- [ ] Monitoring shows normal metrics
- [ ] Team consensus: deployment looks good

**If any criterion fails**: Consider rollback

---

## Team Assignments

| Role | Name | Responsibilities |
|------|------|------------------|
| Deployment Lead | @john | Execute deployment, make rollback decisions |
| Database Lead | @jane | Execute migrations, verify database health |
| Monitoring Lead | @bob | Watch dashboards, trigger alerts if needed |
| Communication Lead | @alice | Update status page, notify stakeholders |
| On-Call Engineer | @charlie | Respond to incidents, support deployment |
| Backup On-Call | @dave | Secondary responder if needed |

---

## Contact Information

**War Room**: Slack #deploy-v1-2-3
**PagerDuty**: https://mycompany.pagerduty.com/incidents
**Status Page**: https://status.example.com
**Runbook**: https://wiki.example.com/deployments/v1.2.3

---

## Deployment Sign-off

- [ ] Deployment Lead: @john
- [ ] Engineering Manager: @manager
- [ ] Product Manager: @pm (if needed)

**Deployment Approved**: _______________
**Date**: _______________

---

**Note**: This is a living document. Update based on actual deployment experience.
