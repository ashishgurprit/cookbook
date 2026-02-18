# Deployment Lifecycle - Quick Reference Checklists

> Print-friendly checklists for daily use

---

## Daily Development Checklist

**Before Starting Work**:
- [ ] Pull latest from develop branch
- [ ] Review LESSONS.md for relevant patterns
- [ ] Check project memory for context
- [ ] Verify Docker containers running

**During Development**:
- [ ] Write failing test first (TDD)
- [ ] Implement minimal code to pass test
- [ ] Refactor if needed
- [ ] Run tests locally
- [ ] Check code coverage

**Before Committing**:
- [ ] All tests pass
- [ ] Code linted (no errors)
- [ ] No console.log / print statements
- [ ] No secrets in code
- [ ] Conventional commit message

---

## Pull Request Checklist

**Before Creating PR**:
- [ ] Branch up to date with develop
- [ ] All tests pass locally
- [ ] Documentation updated
- [ ] Self-review completed

**PR Description**:
- [ ] Title: `feat/fix/docs: description`
- [ ] Explains WHY (not just what)
- [ ] Links to issue (#123)
- [ ] Screenshots (if UI change)
- [ ] Breaking changes noted

**After PR Created**:
- [ ] CI/CD pipeline passed
- [ ] Reviewers assigned
- [ ] Address feedback
- [ ] Squash commits if needed

---

## Pre-Deployment Checklist

**Code Quality** (T-24 hours):
- [ ] All tests passing (unit, integration, E2E)
- [ ] Code coverage ≥ 80%
- [ ] No linting errors
- [ ] No security vulnerabilities
- [ ] Documentation updated

**Staging Verification** (T-12 hours):
- [ ] Deployed to staging
- [ ] Smoke tests passed
- [ ] Database migrations tested
- [ ] External APIs tested
- [ ] Performance tested
- [ ] Security scan passed

**Deployment Preparation** (T-2 hours):
- [ ] Database backup taken
- [ ] Rollback plan documented
- [ ] Feature flags configured
- [ ] Monitoring configured
- [ ] Error tracking configured
- [ ] Team notified
- [ ] On-call engineer assigned

---

## Deployment Day Checklist

**T-15 minutes**:
- [ ] Verify staging green
- [ ] Verify no incidents in progress
- [ ] Notify team in Slack
- [ ] Open monitoring dashboard

**T-0 (Deployment)**:
- [ ] Start deployment
- [ ] Monitor deployment logs
- [ ] Wait for health checks

**T+5 minutes**:
- [ ] Run smoke tests
- [ ] Check error rate (<1%)
- [ ] Check response time (<2s p95)
- [ ] Check database connections
- [ ] Test critical user flows

**T+30 minutes**:
- [ ] Error rate stable
- [ ] Response time stable
- [ ] No alerts triggered
- [ ] User-facing features tested
- [ ] Payment processing tested
- [ ] Email delivery tested

**T+60 minutes**:
- [ ] Mark deployment successful
- [ ] Notify team
- [ ] Update status page
- [ ] Close deployment window

---

## Rollback Checklist

**Immediate** (0-5 minutes):
- [ ] Identify issue severity
- [ ] Decide: rollback or fix forward?
- [ ] Notify team of rollback decision
- [ ] Start rollback procedure

**Rollback Execution** (5-10 minutes):
- [ ] Execute rollback command
- [ ] Monitor rollback progress
- [ ] Verify health checks pass
- [ ] Run smoke tests

**Verification** (10-15 minutes):
- [ ] Error rate back to normal
- [ ] Response time back to normal
- [ ] Critical features working
- [ ] Database integrity verified

**Post-Rollback** (15+ minutes):
- [ ] Update status page
- [ ] Notify customers (if impacted)
- [ ] Notify team of rollback complete
- [ ] Schedule post-mortem (within 24 hours)
- [ ] Document incident

---

## Post-Deployment Checklist

**Immediate** (0-1 hour):
- [ ] Smoke tests passed
- [ ] Error rate normal
- [ ] Response time normal
- [ ] No alerts triggered
- [ ] Critical features tested

**Short-term** (1-24 hours):
- [ ] Monitor error trends
- [ ] Monitor performance trends
- [ ] Check user feedback
- [ ] Review logs for warnings
- [ ] Verify scheduled jobs running

**Long-term** (1-7 days):
- [ ] Review metrics (engagement, conversion)
- [ ] Check for memory leaks
- [ ] Verify database performance
- [ ] Check for degraded services
- [ ] Gather user feedback

---

## Security Deployment Checklist

**Before Deployment**:
- [ ] Dependencies updated (no critical CVEs)
- [ ] Security headers configured
- [ ] HTTPS enforced
- [ ] API rate limiting configured
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention verified
- [ ] XSS prevention verified
- [ ] CSRF protection enabled
- [ ] Secrets rotated
- [ ] Access logs enabled

**After Deployment**:
- [ ] Security scan passed (OWASP ZAP)
- [ ] Penetration test scheduled
- [ ] Security headers verified
- [ ] Certificate expiry checked
- [ ] Vulnerability scan scheduled

---

## Database Migration Checklist

**Pre-Migration** (T-24 hours):
- [ ] Backup database
- [ ] Test migration in staging
- [ ] Verify migration reversible
- [ ] Document rollback steps
- [ ] Estimate migration time

**Migration Execution**:
- [ ] Backup database (again)
- [ ] Run migration
- [ ] Verify migration completed
- [ ] Check data integrity
- [ ] Verify application works

**Post-Migration**:
- [ ] Monitor database performance
- [ ] Check for locked tables
- [ ] Verify indexes created
- [ ] Check query performance
- [ ] Keep backup for 7 days

---

## Incident Response Checklist

**Severity Assessment** (0-2 minutes):
- [ ] P1: Critical (production down)
- [ ] P2: Major (feature broken)
- [ ] P3: Minor (degraded performance)
- [ ] P4: Low (cosmetic issue)

**P1 Incident** (Critical):
- [ ] Page on-call engineer (immediately)
- [ ] Create war room (Slack, Zoom)
- [ ] Update status page (within 5 min)
- [ ] Identify incident commander
- [ ] Start investigation
- [ ] Consider rollback
- [ ] Communicate every 15 minutes
- [ ] Notify customers (if appropriate)

**P2 Incident** (Major):
- [ ] Notify on-call engineer (within 15 min)
- [ ] Create Slack channel
- [ ] Update status page (within 30 min)
- [ ] Start investigation
- [ ] Communicate every 30 minutes

**Post-Incident** (All Severities):
- [ ] Mark incident resolved
- [ ] Update status page
- [ ] Notify customers (if notified earlier)
- [ ] Schedule post-mortem (within 24 hours)
- [ ] Document timeline
- [ ] Create action items

---

## Post-Mortem Checklist

**Within 24 Hours**:
- [ ] Schedule post-mortem meeting
- [ ] Invite key participants
- [ ] Gather timeline data
- [ ] Gather metrics/graphs
- [ ] Review logs

**Post-Mortem Meeting**:
- [ ] Review timeline
- [ ] Identify root cause
- [ ] Discuss what went well
- [ ] Discuss what went poorly
- [ ] Create action items (with owners)
- [ ] Discuss prevention measures

**Post-Mortem Document**:
- [ ] Summary (2-3 sentences)
- [ ] Timeline (with timestamps)
- [ ] Root cause analysis
- [ ] Impact assessment
- [ ] What went well
- [ ] What went poorly
- [ ] Action items (assigned + due dates)
- [ ] Prevention measures
- [ ] Share with team

**Follow-up** (7 days):
- [ ] Review action item progress
- [ ] Update prevention documentation
- [ ] Update runbooks
- [ ] Share lessons learned

---

## Release Checklist

**Pre-Release** (T-1 week):
- [ ] Feature freeze (no new features)
- [ ] Bug fixes only
- [ ] Documentation complete
- [ ] Changelog updated
- [ ] Release notes drafted

**Release Day** (T-0):
- [ ] Create release branch
- [ ] Bump version number
- [ ] Tag release (v1.2.3)
- [ ] Deploy to production
- [ ] Smoke tests passed
- [ ] Publish release notes
- [ ] Notify customers
- [ ] Update documentation

**Post-Release** (T+1 day):
- [ ] Monitor for issues
- [ ] Address critical bugs
- [ ] Gather user feedback
- [ ] Update roadmap
- [ ] Plan next release

---

## Monitoring Checklist

**Application Metrics**:
- [ ] Request rate (requests/second)
- [ ] Error rate (errors/total requests)
- [ ] Response time (p50, p95, p99)
- [ ] Database query time
- [ ] Cache hit rate
- [ ] Queue depth

**Infrastructure Metrics**:
- [ ] CPU usage
- [ ] Memory usage
- [ ] Disk I/O
- [ ] Network bandwidth
- [ ] Database connections
- [ ] Container health

**Business Metrics**:
- [ ] User registrations
- [ ] Successful payments
- [ ] Failed payments
- [ ] Active users
- [ ] Conversion rate
- [ ] Revenue

**Alerting**:
- [ ] Error rate > 1% (5 min)
- [ ] Response time > 2s p95 (10 min)
- [ ] CPU > 80% (5 min)
- [ ] Memory > 90% (2 min)
- [ ] Disk > 85% (30 min)
- [ ] Database connections > 90% (2 min)

---

## Weekly Operations Checklist

**Every Monday**:
- [ ] Review last week's incidents
- [ ] Review deployment success rate
- [ ] Review error trends
- [ ] Review performance trends
- [ ] Update capacity planning

**Every Friday**:
- [ ] Review upcoming deployments
- [ ] Review on-call rotation
- [ ] Update runbooks
- [ ] Review action items from post-mortems
- [ ] Celebrate wins

---

## Monthly Operations Checklist

- [ ] Review and update dependencies
- [ ] Review and rotate secrets
- [ ] Review and update documentation
- [ ] Review and optimize database
- [ ] Review and optimize costs
- [ ] Review and update disaster recovery plan
- [ ] Conduct disaster recovery drill
- [ ] Review security scan results
- [ ] Schedule penetration testing
- [ ] Review compliance requirements

---

## Quarterly Operations Checklist

- [ ] Review architecture decisions
- [ ] Review technology stack
- [ ] Conduct load testing
- [ ] Review and update capacity plan
- [ ] Review and update SLAs
- [ ] Review and update runbooks
- [ ] Conduct chaos engineering exercises
- [ ] Review incident trends
- [ ] Update team training
- [ ] Plan technical debt reduction

---

**Print This Page**: Keep these checklists handy for daily use.
**Customize**: Adapt checklists to your specific environment and requirements.
**Review**: Update checklists based on post-mortem findings and lessons learned.
