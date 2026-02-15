# Rollback Playbook

Emergency rollback procedures for all deployment patterns.

---

## Rollback Decision Matrix

| Severity | Error Rate | Response Time | Action |
|----------|------------|---------------|--------|
| **P0 - Critical** | >5% errors | >3x baseline | Immediate rollback |
| **P1 - High** | 2-5% errors | 2-3x baseline | Rollback within 15 min |
| **P2 - Medium** | 1-2% errors | 1.5-2x baseline | Monitor, prepare rollback |
| **P3 - Low** | <1% errors | <1.5x baseline | Monitor, fix forward |

---

## Emergency Rollback Procedures

### 1. Blue-Green Rollback

**Time to Rollback:** < 1 minute

**Procedure:**
```bash
#!/bin/bash
# blue-green-rollback.sh

echo "🚨 EMERGENCY ROLLBACK - Blue-Green Deployment"
echo "================================================"

# Step 1: Switch load balancer back to blue environment
echo "Step 1/3: Switching load balancer to blue (old version)..."
aws elbv2 modify-target-group \
  --target-group-arn $TG_ARN \
  --targets Id=blue-instance-1 Id=blue-instance-2

if [ $? -eq 0 ]; then
  echo "✓ Load balancer switched to blue"
else
  echo "✗ FAILED to switch load balancer"
  exit 1
fi

# Step 2: Verify blue is healthy
echo "Step 2/3: Verifying blue environment health..."
./scripts/health-check.sh --env=blue --timeout=30

if [ $? -eq 0 ]; then
  echo "✓ Blue environment is healthy"
else
  echo "✗ WARNING: Blue environment health check failed"
  echo "   Manual intervention required!"
  exit 1
fi

# Step 3: Monitor error rates
echo "Step 3/3: Monitoring error rates for 2 minutes..."
sleep 120

ERROR_RATE=$(./scripts/get-error-rate.sh --duration=2m)
echo "Current error rate: $ERROR_RATE%"

if (( $(echo "$ERROR_RATE < 1" | bc -l) )); then
  echo "✓ ROLLBACK SUCCESSFUL"
  echo "   Version: reverted to blue (previous version)"
  echo "   Error rate: $ERROR_RATE% (acceptable)"
else
  echo "✗ ERROR RATE STILL HIGH: $ERROR_RATE%"
  echo "   Escalating to P0 incident response"
fi

echo "================================================"
echo "Next steps:"
echo "1. Investigate why green deployment failed"
echo "2. Update post-mortem document"
echo "3. Fix issues before next deployment attempt"
```

**Verification:**
```bash
# Check traffic distribution
aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN \
  | jq '.TargetHealthDescriptions[] | {Target: .Target.Id, Health: .TargetHealth.State}'

# Verify error rates back to normal
./scripts/compare-metrics.sh \
  --baseline=last-24h \
  --current=last-5m
```

---

### 2. Canary Rollback

**Time to Rollback:** < 2 minutes

**Procedure:**
```bash
#!/bin/bash
# canary-rollback.sh

echo "🚨 EMERGENCY ROLLBACK - Canary Deployment"
echo "=========================================="

# Step 1: Delete canary deployment
echo "Step 1/4: Removing canary deployment..."
kubectl delete deployment myapp-canary --ignore-not-found=true

if [ $? -eq 0 ]; then
  echo "✓ Canary deployment deleted"
else
  echo "✗ Failed to delete canary"
fi

# Step 2: Delete canary ingress
echo "Step 2/4: Removing canary ingress..."
kubectl delete ingress myapp-canary --ignore-not-found=true

if [ $? -eq 0 ]; then
  echo "✓ Canary ingress deleted"
else
  echo "✗ Failed to delete canary ingress"
fi

# Step 3: Verify all traffic to stable
echo "Step 3/4: Verifying traffic routing..."
STABLE_PODS=$(kubectl get pods -l app=myapp,canary!=true --no-headers | wc -l)
CANARY_PODS=$(kubectl get pods -l app=myapp,canary=true --no-headers | wc -l)

echo "  Stable pods: $STABLE_PODS"
echo "  Canary pods: $CANARY_PODS"

if [ $CANARY_PODS -eq 0 ]; then
  echo "✓ All canary resources removed"
else
  echo "⚠ Still $CANARY_PODS canary pods running"
  kubectl delete pods -l app=myapp,canary=true --force --grace-period=0
fi

# Step 4: Monitor stable deployment
echo "Step 4/4: Monitoring stable deployment..."
kubectl rollout status deployment/myapp-stable --timeout=60s

if [ $? -eq 0 ]; then
  echo "✓ ROLLBACK SUCCESSFUL"
  echo "   All traffic routed to stable version"
else
  echo "✗ Stable deployment issues detected"
  echo "   Manual intervention required!"
fi

echo "=========================================="
```

**Automated Canary Rollback (Flagger):**
```yaml
# Flagger automatically rolls back if metrics fail
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: myapp
spec:
  analysis:
    threshold: 5  # Fail after 5 bad checks
    metrics:
    - name: request-success-rate
      thresholdRange:
        min: 99  # Roll back if <99%
    - name: request-duration
      thresholdRange:
        max: 500  # Roll back if >500ms
```

---

### 3. Rolling Deployment Rollback

**Time to Rollback:** 2-5 minutes (depends on instance count)

**Procedure:**
```bash
#!/bin/bash
# rolling-rollback.sh

echo "🚨 EMERGENCY ROLLBACK - Rolling Deployment"
echo "==========================================="

# Method 1: Kubernetes rollout undo (fastest)
if command -v kubectl &> /dev/null; then
  echo "Using Kubernetes rollback..."

  # Step 1: Pause current rollout
  kubectl rollout pause deployment/myapp

  # Step 2: Undo to previous revision
  kubectl rollout undo deployment/myapp

  # Step 3: Resume and monitor
  kubectl rollout resume deployment/myapp
  kubectl rollout status deployment/myapp --timeout=5m

  if [ $? -eq 0 ]; then
    echo "✓ Kubernetes rollback complete"
  else
    echo "✗ Kubernetes rollback failed"
    exit 1
  fi

# Method 2: AWS Auto Scaling rollback
elif command -v aws &> /dev/null; then
  echo "Using AWS Auto Scaling rollback..."

  # Get previous launch configuration
  CURRENT_LC=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names myapp-asg \
    --query 'AutoScalingGroups[0].LaunchConfigurationName' \
    --output text)

  echo "Current LC: $CURRENT_LC"

  # Determine previous version
  if [[ $CURRENT_LC == *"v1.1"* ]]; then
    PREVIOUS_LC="${CURRENT_LC/v1.1/v1.0}"
  else
    echo "Cannot determine previous version"
    exit 1
  fi

  echo "Rolling back to: $PREVIOUS_LC"

  # Update ASG
  aws autoscaling update-auto-scaling-group \
    --auto-scaling-group-name myapp-asg \
    --launch-configuration-name $PREVIOUS_LC

  # Force instance refresh
  aws autoscaling start-instance-refresh \
    --auto-scaling-group-name myapp-asg \
    --preferences '{"MinHealthyPercentage": 50}'

  echo "✓ Instance refresh initiated"
  echo "  This will take 5-10 minutes to complete"
fi

echo "==========================================="
```

**Verification:**
```bash
# Kubernetes: Check rollback status
kubectl rollout history deployment/myapp
kubectl get pods -l app=myapp -o jsonpath='{.items[*].spec.containers[*].image}'

# AWS: Monitor instance refresh
aws autoscaling describe-instance-refreshes \
  --auto-scaling-group-name myapp-asg
```

---

### 4. Feature Flag Rollback (Dark Launch)

**Time to Rollback:** < 30 seconds

**Procedure:**
```bash
#!/bin/bash
# feature-flag-rollback.sh

echo "🚨 EMERGENCY ROLLBACK - Feature Flag"
echo "====================================="

FEATURE_NAME=$1

if [ -z "$FEATURE_NAME" ]; then
  echo "Usage: $0 <feature-name>"
  exit 1
fi

echo "Disabling feature: $FEATURE_NAME"

# Method 1: ConfigMap update (Kubernetes)
if command -v kubectl &> /dev/null; then
  kubectl patch configmap feature-flags \
    --type='json' \
    -p="[{'op': 'replace', 'path': '/data/$FEATURE_NAME', 'value': 'false'}]"

  echo "✓ Feature flag disabled in ConfigMap"
  echo "  Changes effective immediately (no restart needed)"

# Method 2: LaunchDarkly API
elif [ -n "$LAUNCHDARKLY_API_KEY" ]; then
  curl -X PATCH \
    "https://app.launchdarkly.com/api/v2/flags/default/$FEATURE_NAME" \
    -H "Authorization: $LAUNCHDARKLY_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"op": "replace", "path": "/environments/production/on", "value": false}'

  echo "✓ Feature flag disabled in LaunchDarkly"

# Method 3: Database flag table
else
  mysql -u $DB_USER -p$DB_PASS -h $DB_HOST -D $DB_NAME -e \
    "UPDATE feature_flags SET enabled = 0 WHERE name = '$FEATURE_NAME';"

  echo "✓ Feature flag disabled in database"
fi

# Verify
sleep 5
./scripts/verify-feature-status.sh --feature=$FEATURE_NAME --expected=disabled

echo "====================================="
```

---

### 5. Database Rollback

**Time to Rollback:** Varies (use transaction-based rollback)

**Procedure:**
```bash
#!/bin/bash
# database-rollback.sh

echo "🚨 EMERGENCY DATABASE ROLLBACK"
echo "==============================="

MIGRATION_VERSION=$1

if [ -z "$MIGRATION_VERSION" ]; then
  echo "Usage: $0 <migration-version>"
  echo "Example: $0 20260117_001"
  exit 1
fi

# Step 1: Take backup before rollback
echo "Step 1/3: Taking backup before rollback..."
BACKUP_FILE="pre-rollback-$(date +%Y%m%d_%H%M%S).sql"

mysqldump -u $DB_USER -p$DB_PASS -h $DB_HOST $DB_NAME > $BACKUP_FILE

if [ $? -eq 0 ]; then
  echo "✓ Backup saved: $BACKUP_FILE"
else
  echo "✗ Backup failed - ABORTING ROLLBACK"
  exit 1
fi

# Step 2: Run rollback migration
echo "Step 2/3: Rolling back to version $MIGRATION_VERSION..."

# Using Flyway
if command -v flyway &> /dev/null; then
  flyway -url=jdbc:mysql://$DB_HOST/$DB_NAME \
    -user=$DB_USER \
    -password=$DB_PASS \
    undo -target=$MIGRATION_VERSION

# Using Liquibase
elif command -v liquibase &> /dev/null; then
  liquibase \
    --changeLogFile=db/changelog/db.changelog-master.xml \
    --url=jdbc:mysql://$DB_HOST/$DB_NAME \
    --username=$DB_USER \
    --password=$DB_PASS \
    rollback $MIGRATION_VERSION

# Using Django
elif [ -f "manage.py" ]; then
  python manage.py migrate app_name $MIGRATION_VERSION

# Manual rollback
else
  echo "Running manual rollback script..."
  mysql -u $DB_USER -p$DB_PASS -h $DB_HOST $DB_NAME < migrations/rollback_${MIGRATION_VERSION}.sql
fi

if [ $? -eq 0 ]; then
  echo "✓ Database rolled back to $MIGRATION_VERSION"
else
  echo "✗ Rollback failed"
  echo "  Attempting restore from backup..."
  mysql -u $DB_USER -p$DB_PASS -h $DB_HOST $DB_NAME < $BACKUP_FILE
  exit 1
fi

# Step 3: Verify database state
echo "Step 3/3: Verifying database state..."
./scripts/verify-db-schema.sh --expected-version=$MIGRATION_VERSION

echo "==============================="
```

---

## Rollback Checklist

### Immediate Actions (< 5 minutes)
- [ ] Identify the issue (metrics, logs, user reports)
- [ ] Determine severity (P0/P1/P2/P3)
- [ ] Notify team via incident channel
- [ ] Execute appropriate rollback procedure
- [ ] Verify error rates returned to normal
- [ ] Verify all services are healthy

### Post-Rollback (< 30 minutes)
- [ ] Document the incident in incident log
- [ ] Preserve logs and metrics from failed deployment
- [ ] Create post-mortem document
- [ ] Notify stakeholders of rollback
- [ ] Identify root cause
- [ ] Create fix-forward plan

### Follow-Up (< 24 hours)
- [ ] Fix the issue that caused rollback
- [ ] Add tests to prevent recurrence
- [ ] Update deployment procedures if needed
- [ ] Conduct post-mortem meeting
- [ ] Update runbooks with lessons learned
- [ ] Plan next deployment attempt

---

## Rollback Scripts Location

```
.claude/skills/deployment-patterns/scripts/
├── blue-green-rollback.sh
├── canary-rollback.sh
├── rolling-rollback.sh
├── feature-flag-rollback.sh
├── database-rollback.sh
├── health-check.sh
├── get-error-rate.sh
└── verify-db-schema.sh
```

---

## Emergency Contacts

```
P0 Incidents: #incident-response (Slack)
On-Call: PagerDuty rotation
Escalation: team-lead@company.com
Database DBA: dba-team@company.com
```

---

## Rollback Anti-Patterns

### DON'T:
- ❌ Panic and rollback without checking metrics
- ❌ Deploy a "fix" without testing
- ❌ Skip the backup step
- ❌ Forget to notify the team
- ❌ Ignore error logs
- ❌ Rollback database without backup
- ❌ Mix rollback with new changes

### DO:
- ✅ Follow the playbook systematically
- ✅ Document everything
- ✅ Take backups before rollback
- ✅ Verify success after rollback
- ✅ Learn from the incident
- ✅ Update procedures
- ✅ Test rollback procedures regularly

---

## Testing Rollback Procedures

**Monthly Rollback Drill:**
```bash
# 1. Deploy test version to staging
./deploy.sh --env=staging --version=test-rollback

# 2. Verify deployment successful
./scripts/health-check.sh --env=staging

# 3. Execute rollback procedure
./scripts/blue-green-rollback.sh --env=staging

# 4. Verify rollback successful
./scripts/health-check.sh --env=staging

# 5. Document lessons learned
```

**Automated Rollback Testing:**
```yaml
# .github/workflows/test-rollback.yml
name: Test Rollback Procedures

on:
  schedule:
    - cron: '0 2 * * 1'  # Every Monday at 2 AM

jobs:
  test-rollback:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy test version
        run: ./deploy.sh --env=test --version=rollback-test

      - name: Execute rollback
        run: ./scripts/blue-green-rollback.sh --env=test

      - name: Verify health
        run: ./scripts/health-check.sh --env=test

      - name: Report results
        run: ./scripts/report-rollback-test.sh
```

---

**Remember:** The best rollback is the one you never need. Test thoroughly before deployment!
