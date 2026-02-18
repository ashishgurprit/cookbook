# Post-Mortem: [Incident Title]

**Date**: YYYY-MM-DD
**Incident ID**: INC-XXXX
**Severity**: [P1/P2/P3/P4]
**Duration**: [X hours/minutes]
**Status**: [Resolved/Ongoing]

---

## Executive Summary

[2-3 sentences summarizing what happened, impact, and resolution]

**Example**:
> On 2026-01-18 at 10:30 AM UTC, we deployed v1.2.3 to production which introduced a database query performance issue. Error rate spiked from 0.1% to 8% affecting approximately 500 users over 15 minutes. We rolled back to v1.2.2 at 10:45 AM UTC and error rate returned to normal.

---

## Impact

**User Impact**:
- Affected users: ~500 users
- Duration: 15 minutes
- Affected regions: US-East, US-West
- Features impacted: User login, payment processing

**Business Impact**:
- Revenue loss: $X (if applicable)
- Support tickets: X tickets created
- Customer churn: X customers (if applicable)
- SLA breach: [Yes/No]

**Technical Impact**:
- Services affected: API, database
- Data loss: [None/Partial/Complete]
- Rollback required: Yes

---

## Timeline

All times in UTC. Include timestamps for every significant event.

| Time | Event | Action By |
|------|-------|-----------|
| 10:30 | Deployment to production started | @john (deploy script) |
| 10:32 | Deployment completed successfully | @john |
| 10:35 | Error rate alert triggered (>5%) | Datadog |
| 10:36 | On-call engineer acknowledged | @jane |
| 10:38 | War room created in Slack | @jane |
| 10:40 | Root cause identified (N+1 query) | @jane |
| 10:42 | Rollback decision made | @jane |
| 10:43 | Rollback initiated | @jane |
| 10:45 | Rollback completed | @jane |
| 10:47 | Error rate back to normal | Datadog |
| 10:50 | Status page updated (resolved) | @jane |
| 11:00 | Incident closed | @jane |

---

## Root Cause Analysis

### What Happened?

[Detailed technical explanation of what went wrong]

**Example**:
> The deployment introduced a new database query to fetch user posts. The query was not optimized and resulted in an N+1 query problem. For each user loaded, the system made a separate query to fetch their posts. With 1000 concurrent users, this resulted in 1000+ database queries instead of 1, causing database connection pool exhaustion and elevated error rates.

### Why Did It Happen?

[Explain the underlying reasons, not just symptoms]

**Example**:
> - The code review missed the N+1 query pattern
> - Staging environment had only 50 test users (production has 10,000+ users)
> - No database query performance tests in CI/CD pipeline
> - No alerting on query count spikes
> - Developer was not familiar with SQLAlchemy eager loading patterns

### Contributing Factors

- [ ] Code review process
- [ ] Testing gaps (staging vs production data volume)
- [ ] Monitoring gaps (no query count monitoring)
- [ ] Knowledge gaps (developer training on ORM patterns)
- [ ] Deployment process (no gradual rollout)

---

## Detection

### How Was It Detected?

- **Detection Method**: Automated alert (Datadog error rate >5%)
- **Time to Detection**: 5 minutes after deployment
- **First Reporter**: Datadog monitoring system

### Could Detection Be Improved?

[How could we detect this faster?]

**Example**:
> - Add query count monitoring (alert when query count >10x normal)
> - Add database connection pool monitoring (alert at 80% utilization)
> - Add APM traces to identify N+1 queries before production

---

## Response

### What Went Well?

- ✅ Error alert triggered within 5 minutes
- ✅ On-call engineer responded within 1 minute
- ✅ Root cause identified quickly (5 minutes)
- ✅ Rollback executed smoothly (2 minutes)
- ✅ Communication clear and timely
- ✅ Status page updated promptly

### What Could Be Improved?

- ❌ Issue should have been caught in staging
- ❌ No gradual rollout (100% deployed immediately)
- ❌ No database query performance testing
- ❌ Code review missed N+1 pattern
- ❌ Staging environment not realistic (50 users vs 10,000)

---

## Resolution

### Immediate Fix

- Rolled back to v1.2.2 at 10:45 AM UTC
- Error rate returned to normal within 2 minutes
- No manual intervention required

### Permanent Fix

- [ ] Optimize query with eager loading (PR #456)
- [ ] Add database query performance tests (PR #457)
- [ ] Update staging environment to match production data volume (INFRA-123)
- [ ] Add query count monitoring and alerting (MON-789)

---

## Action Items

**Priority Action Items** (within 7 days):

| Action Item | Owner | Due Date | Status |
|-------------|-------|----------|--------|
| Fix N+1 query with eager loading | @john | 2026-01-20 | In Progress |
| Add database query performance test to CI/CD | @jane | 2026-01-21 | Not Started |
| Add query count monitoring and alerts | @bob | 2026-01-22 | Not Started |
| Update staging to use production-like data volume | @alice | 2026-01-25 | Not Started |

**Long-term Improvements** (within 30 days):

| Action Item | Owner | Due Date | Status |
|-------------|-------|----------|--------|
| Implement gradual rollout (canary deployment) | @bob | 2026-02-15 | Not Started |
| Add APM traces for N+1 query detection | @jane | 2026-02-15 | Not Started |
| Create ORM best practices guide | @john | 2026-02-10 | Not Started |
| Conduct training on database optimization | @alice | 2026-02-20 | Not Started |

---

## Prevention

### How to Prevent This in the Future?

**Code Level**:
- [ ] Use eager loading for all associations (SQLAlchemy: `joinedload`, `selectinload`)
- [ ] Add database query linter to catch N+1 patterns
- [ ] Require database query review in code review checklist

**Testing Level**:
- [ ] Add performance tests to CI/CD pipeline
- [ ] Test with production-like data volumes in staging
- [ ] Add integration tests that count queries

**Deployment Level**:
- [ ] Implement gradual rollout (5% → 25% → 50% → 100%)
- [ ] Add automated rollback on error rate spike
- [ ] Require staging sign-off before production deployment

**Monitoring Level**:
- [ ] Add query count monitoring
- [ ] Add database connection pool monitoring
- [ ] Add APM traces to identify N+1 queries
- [ ] Alert on anomalous query patterns

---

## Lessons Learned

### Technical Lessons

1. **Always use eager loading for associations**
   - Use `joinedload()` for one-to-one/many-to-one
   - Use `selectinload()` for one-to-many/many-to-many

2. **Test with production-like data volumes**
   - N+1 queries only appear at scale
   - Staging must match production data characteristics

3. **Monitor database query patterns**
   - Track query count, not just response time
   - Alert on query count spikes (>2x normal)

### Process Lessons

1. **Code review must include database queries**
   - Add database query review to PR checklist
   - Reviewers should look for N+1 patterns

2. **Gradual rollout prevents widespread impact**
   - Start with 5% of traffic (canary)
   - Monitor for 30 minutes before increasing

3. **Automated rollback saves time**
   - Set up automated rollback on error rate >5%
   - Faster than manual rollback (2 min vs 10 min)

---

## Related Incidents

- [INC-0045] - Similar N+1 query issue (2025-11-12)
- [INC-0089] - Database connection pool exhaustion (2025-12-05)

---

## Appendices

### A. Error Logs

```
[ERROR] 2026-01-18 10:35:23 - ConnectionPoolExhausted: Could not obtain connection from pool
[ERROR] 2026-01-18 10:35:24 - HTTP 500: Internal Server Error at /api/users
[ERROR] 2026-01-18 10:35:25 - Database query timeout after 30 seconds
```

### B. Metrics Graphs

[Attach screenshots of:
- Error rate spike
- Response time spike
- Database connection count
- Query count spike]

### C. Database Query

**Before (N+1 query)**:
```python
users = User.query.all()  # 1 query
for user in users:
    print(user.posts)  # N queries (1 per user)
```

**After (Optimized)**:
```python
users = User.query.options(joinedload(User.posts)).all()  # 1 query
for user in users:
    print(user.posts)  # No additional queries
```

---

## Sign-off

**Prepared by**: @jane (Incident Commander)
**Reviewed by**: @team-lead
**Approved by**: @engineering-manager
**Date**: 2026-01-19

**Post-Mortem Completed**: ✅
**Action Items Assigned**: ✅
**Lessons Shared**: ✅

---

## Distribution

- Engineering team (Slack #engineering)
- Product team (for customer communication if needed)
- Support team (for ticket reference)
- Leadership (for awareness)

---

**Remember**: The goal of a post-mortem is learning, not blame. Focus on systems and processes, not individuals.
