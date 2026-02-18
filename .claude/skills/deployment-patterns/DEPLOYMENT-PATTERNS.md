# Deployment Patterns Guide

Comprehensive guide to modern deployment strategies for zero-downtime releases.

---

## Pattern Selection Matrix

| Pattern | Risk | Complexity | Rollback Speed | Best For |
|---------|------|------------|----------------|----------|
| **Blue-Green** | Low | Medium | Instant | Critical systems, databases |
| **Canary** | Very Low | High | Fast | User-facing apps, APIs |
| **Rolling** | Medium | Low | Slow | Stateless services |
| **Dark Launch** | Very Low | Very High | N/A | New features, experiments |
| **Progressive** | Low | Medium | Fast | Mobile apps, gradual rollouts |

---

## 1. Blue-Green Deployment

### Overview
Run two identical production environments ("blue" and "green"). Deploy to inactive environment, test, then switch traffic.

### Architecture
```
                    Load Balancer
                         |
              ┌──────────┴──────────┐
              │                     │
         Blue Environment      Green Environment
         (Currently Live)      (Deploying New Version)
              │                     │
         Version 1.0            Version 1.1
```

### Implementation Steps

**Step 1: Prepare Green Environment**
```bash
# 1. Deploy new version to green environment
./deploy.sh --environment=green --version=1.1

# 2. Run smoke tests on green
./scripts/smoke-tests.sh --target=green.example.com

# 3. Verify database migrations (if any)
./scripts/verify-migrations.sh --env=green
```

**Step 2: Switch Traffic**
```bash
# 4. Update load balancer to route to green
aws elbv2 modify-target-group --target-group-arn $TG_ARN \
  --health-check-path /health \
  --targets Id=green-instance-1 Id=green-instance-2

# 5. Monitor for 5-10 minutes
watch -n 5 './scripts/monitor-health.sh --env=green'

# 6. Verify no errors in logs
kubectl logs -l app=myapp --tail=100 | grep -i error
```

**Step 3: Decommission Blue (or Keep as Rollback)**
```bash
# Option A: Keep blue running for quick rollback (recommended)
echo "Blue environment kept running for 24 hours"

# Option B: Scale down blue after confirming stability
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name blue-asg \
  --min-size 0 --desired-capacity 0
```

### Rollback Procedure
```bash
# Instant rollback - just switch back to blue
aws elbv2 modify-target-group --target-group-arn $TG_ARN \
  --targets Id=blue-instance-1 Id=blue-instance-2

echo "Traffic switched back to blue (v1.0) - rollback complete"
```

### Pros & Cons

**Pros:**
- Instant rollback (just switch load balancer)
- Zero downtime
- Full environment testing before switching
- No impact on users during deployment

**Cons:**
- Requires double the infrastructure (costly)
- Database migrations must be backward-compatible
- Session management complexity
- Requires sophisticated load balancer setup

### Best Practices
1. Keep blue environment running for 24-48 hours after switch
2. Test green thoroughly before switching traffic
3. Use feature flags for database schema changes
4. Monitor error rates closely after switch
5. Have automated rollback triggers (error rate > 1%)

---

## 2. Canary Deployment

### Overview
Release to a small subset of users first, monitor, then gradually increase traffic.

### Architecture
```
                Load Balancer
                     |
         ┌───────────┴───────────┐
         │                       │
    95% Traffic              5% Traffic
         │                       │
    Stable v1.0             Canary v1.1
    (existing instances)    (1-2 instances)
```

### Implementation Steps

**Step 1: Deploy Canary**
```bash
# 1. Deploy canary with small weight
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: myapp-canary
spec:
  selector:
    app: myapp
    version: "1.1"
    canary: "true"
  ports:
    - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-canary
spec:
  replicas: 1  # Start with just 1 replica
  selector:
    matchLabels:
      app: myapp
      version: "1.1"
      canary: "true"
  template:
    metadata:
      labels:
        app: myapp
        version: "1.1"
        canary: "true"
    spec:
      containers:
      - name: myapp
        image: myapp:1.1
EOF

# 2. Configure ingress for 5% canary traffic
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myapp-canary
  annotations:
    nginx.ingress.kubernetes.io/canary: "true"
    nginx.ingress.kubernetes.io/canary-weight: "5"
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: myapp-canary
            port:
              number: 80
EOF
```

**Step 2: Monitor Canary**
```bash
# 3. Monitor error rates
./scripts/compare-metrics.sh \
  --canary=myapp-canary \
  --stable=myapp-stable \
  --duration=10m

# 4. Compare metrics
# - Error rate: canary should be < stable + 0.5%
# - Response time: canary should be < stable * 1.2
# - Success rate: canary should be > 99.5%
```

**Step 3: Gradual Rollout**
```bash
# If metrics look good, increase traffic gradually
# 5% → 10% → 25% → 50% → 100%

# Increase to 10%
kubectl annotate ingress myapp-canary \
  nginx.ingress.kubernetes.io/canary-weight=10 \
  --overwrite

# Wait 15 minutes and monitor
sleep 900
./scripts/compare-metrics.sh --canary=myapp-canary --stable=myapp-stable

# Increase to 25%
kubectl annotate ingress myapp-canary \
  nginx.ingress.kubernetes.io/canary-weight=25 \
  --overwrite

# Continue until 100%, then promote to stable
```

**Step 4: Promote or Rollback**
```bash
# If all metrics are good, promote canary to stable
kubectl set image deployment/myapp-stable myapp=myapp:1.1
kubectl delete deployment myapp-canary
kubectl delete ingress myapp-canary

# OR rollback if issues detected
kubectl delete deployment myapp-canary
kubectl delete ingress myapp-canary
```

### Automated Canary with Flagger
```yaml
# flagger-canary.yaml
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: myapp
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: myapp
  service:
    port: 80
  analysis:
    interval: 1m
    threshold: 5  # Number of checks before promotion
    maxWeight: 50
    stepWeight: 10
    metrics:
    - name: request-success-rate
      thresholdRange:
        min: 99
      interval: 1m
    - name: request-duration
      thresholdRange:
        max: 500
      interval: 1m
    webhooks:
    - name: smoke-test
      url: http://flagger-loadtester.test/
      timeout: 5s
      metadata:
        type: bash
        cmd: "curl -sd 'test' http://myapp-canary/api/info"
```

### Rollback Procedure
```bash
# Delete canary deployment - traffic returns to stable
kubectl delete deployment myapp-canary
kubectl delete ingress myapp-canary

# Verify all traffic back to stable
kubectl get pods -l app=myapp,canary!=true
```

### Pros & Cons

**Pros:**
- Minimal risk (only small % of users affected)
- Early detection of issues
- Gradual confidence building
- Can A/B test with specific user segments

**Cons:**
- Complex monitoring setup required
- Longer deployment time
- Need sophisticated traffic routing
- Metrics collection infrastructure needed

### Best Practices
1. Start with 5% or less traffic
2. Monitor for at least 10-15 minutes per stage
3. Define clear success criteria before deployment
4. Use automated rollback triggers
5. Target specific user segments (e.g., internal users first)
6. Have detailed logging and tracing enabled

---

## 3. Rolling Deployment

### Overview
Gradually replace old instances with new ones, one at a time or in small batches.

### Architecture
```
Initial:    [v1.0] [v1.0] [v1.0] [v1.0]
Step 1:     [v1.1] [v1.0] [v1.0] [v1.0]  ← Deploy to first
Step 2:     [v1.1] [v1.1] [v1.0] [v1.0]  ← Deploy to second
Step 3:     [v1.1] [v1.1] [v1.1] [v1.0]  ← Deploy to third
Complete:   [v1.1] [v1.1] [v1.1] [v1.1]  ← All updated
```

### Implementation Steps

**Kubernetes Rolling Update:**
```bash
# Configure rolling update strategy
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 4
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1       # Max 1 extra pod during update
      maxUnavailable: 1 # Max 1 pod unavailable
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp
        image: myapp:1.1
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
EOF

# Monitor the rollout
kubectl rollout status deployment/myapp

# Watch pods being replaced
watch kubectl get pods -l app=myapp
```

**Manual Rolling Update (AWS Auto Scaling):**
```bash
# 1. Update launch configuration with new AMI
aws autoscaling create-launch-configuration \
  --launch-configuration-name myapp-v1.1 \
  --image-id ami-newversion \
  --instance-type t3.medium

# 2. Update auto scaling group
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name myapp-asg \
  --launch-configuration-name myapp-v1.1

# 3. Gradually replace instances (25% at a time)
INSTANCE_COUNT=$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names myapp-asg \
  --query 'AutoScalingGroups[0].Instances | length(@)')

BATCH_SIZE=$((INSTANCE_COUNT / 4))

for batch in {1..4}; do
  echo "Replacing batch $batch of 4"

  # Terminate old instances (ASG will launch new ones)
  OLD_INSTANCES=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names myapp-asg \
    --query "AutoScalingGroups[0].Instances[?LaunchConfigurationName=='myapp-v1.0'].InstanceId" \
    --output text | head -n $BATCH_SIZE)

  for instance in $OLD_INSTANCES; do
    aws autoscaling terminate-instance-in-auto-scaling-group \
      --instance-id $instance \
      --should-decrement-desired-capacity false
  done

  # Wait for new instances to be healthy
  sleep 300
  ./scripts/verify-all-healthy.sh
done
```

### Rollback Procedure
```bash
# Kubernetes rollback
kubectl rollout undo deployment/myapp

# Or rollback to specific revision
kubectl rollout history deployment/myapp
kubectl rollout undo deployment/myapp --to-revision=2

# AWS Auto Scaling rollback
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name myapp-asg \
  --launch-configuration-name myapp-v1.0

# Force instance refresh
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name myapp-asg
```

### Pros & Cons

**Pros:**
- Simple to implement
- No extra infrastructure needed
- Gradual rollout reduces risk
- Built into Kubernetes and most platforms

**Cons:**
- Slower than blue-green
- Partial rollout state during deployment
- Both versions run simultaneously
- Rollback requires re-deployment

### Best Practices
1. Set appropriate maxSurge and maxUnavailable
2. Configure proper health checks
3. Monitor each batch before continuing
4. Keep deployments small and frequent
5. Have automated smoke tests between batches

---

## 4. Dark Launch (Feature Toggle)

### Overview
Deploy new code to production but keep it hidden behind feature flags. Enable for internal users or specific segments first.

### Architecture
```
User Request → Feature Flag Check → Route
                       |
                ┌──────┴──────┐
            Flag OFF      Flag ON
                |            |
            Old Feature  New Feature
            (v1.0)       (v1.1)
```

### Implementation

**Feature Flag Service:**
```javascript
// feature-flags.js
class FeatureFlags {
  async isEnabled(flagName, userId) {
    const flag = await this.getFlag(flagName);

    if (!flag.enabled) return false;

    // Check user segments
    if (flag.userSegments) {
      const userSegment = await this.getUserSegment(userId);
      if (!flag.userSegments.includes(userSegment)) {
        return false;
      }
    }

    // Check percentage rollout
    if (flag.percentage) {
      const hash = this.hashUserId(userId);
      return hash < flag.percentage;
    }

    return true;
  }

  hashUserId(userId) {
    // Consistent hash to determine if user in rollout %
    return (userId.charCodeAt(0) % 100);
  }
}

// Usage in application
async function getFeature(userId) {
  const flags = new FeatureFlags();

  if (await flags.isEnabled('new-checkout-flow', userId)) {
    return newCheckoutFlow(userId);  // v1.1
  } else {
    return oldCheckoutFlow(userId);  // v1.0
  }
}
```

**Configuration:**
```yaml
# feature-flags.yaml
flags:
  - name: new-checkout-flow
    enabled: true
    description: "New streamlined checkout"
    userSegments:
      - internal
      - beta-testers
    percentage: 10  # 10% of remaining users
    createdAt: "2026-01-17"
    owner: "product-team"

  - name: new-payment-gateway
    enabled: false  # Not yet released
    description: "Stripe integration"
    userSegments:
      - internal
```

### Gradual Rollout

**Week 1: Internal Only**
```yaml
new-feature:
  enabled: true
  userSegments: [internal]
  percentage: 0
```

**Week 2: Beta Testers (5%)**
```yaml
new-feature:
  enabled: true
  userSegments: [internal, beta-testers]
  percentage: 0
```

**Week 3: 10% Rollout**
```yaml
new-feature:
  enabled: true
  userSegments: [internal, beta-testers]
  percentage: 10
```

**Week 4: 50% Rollout**
```yaml
new-feature:
  enabled: true
  percentage: 50
```

**Week 5: Full Rollout**
```yaml
new-feature:
  enabled: true
  percentage: 100
```

### Rollback Procedure
```bash
# Instant rollback - just disable the flag
kubectl edit configmap feature-flags

# Change:
# new-feature:
#   enabled: false

# No redeployment needed!
```

### Pros & Cons

**Pros:**
- Instant enable/disable (no deployment)
- Test in production safely
- A/B testing capability
- Per-user or per-segment control
- Decoupled deployment from release

**Cons:**
- Code complexity (if/else everywhere)
- Technical debt (need to remove flags eventually)
- Performance overhead (flag checks)
- Testing complexity (all combinations)

### Best Practices
1. Use a feature flag management service (LaunchDarkly, Split.io)
2. Set expiration dates on flags
3. Remove flags once fully rolled out
4. Monitor flag usage and performance
5. Have kill switches for critical features
6. Document what each flag controls

---

## 5. Progressive Delivery

### Overview
Combine multiple strategies (canary + feature flags + metrics) for sophisticated rollouts.

### Implementation
```yaml
# progressive-delivery.yaml
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: myapp
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: myapp
  progressDeadlineSeconds: 600
  service:
    port: 80
  analysis:
    interval: 1m
    threshold: 10
    iterations: 10
    match:
      - headers:
          user-agent:
            regex: ".*Firefox.*"  # Start with Firefox users
    metrics:
      - name: request-success-rate
        thresholdRange:
          min: 99
        interval: 1m
      - name: request-duration
        thresholdRange:
          max: 500
        interval: 1m
    webhooks:
      - name: acceptance-test
        type: pre-rollout
        url: http://flagger-loadtester.test/
      - name: load-test
        type: rollout
        url: http://flagger-loadtester.test/
        metadata:
          cmd: "hey -z 1m -q 10 -c 2 http://myapp-canary/"
```

### Rollout Stages
1. Deploy to staging
2. Run automated tests
3. Deploy to 1% of production (internal users)
4. Monitor for 24 hours
5. Increase to 10% (early adopters)
6. A/B test metrics
7. Gradual increase: 25% → 50% → 100%
8. Monitor each stage for issues

---

## Deployment Checklist

### Pre-Deployment
- [ ] Code reviewed and approved
- [ ] All tests passing (unit, integration, E2E)
- [ ] Security scan completed
- [ ] Database migrations tested
- [ ] Rollback plan documented
- [ ] Monitoring dashboards ready
- [ ] Stakeholders notified

### During Deployment
- [ ] Monitor error rates
- [ ] Check response times
- [ ] Verify database connections
- [ ] Test critical user flows
- [ ] Check logs for errors
- [ ] Verify metrics collection

### Post-Deployment
- [ ] Run smoke tests
- [ ] Verify all services healthy
- [ ] Check error rates (< baseline)
- [ ] Monitor for 1 hour minimum
- [ ] Document any issues
- [ ] Update runbook if needed

---

## Quick Reference

| Need | Use This Pattern |
|------|------------------|
| Zero downtime | Blue-Green or Canary |
| Minimize risk | Canary or Dark Launch |
| Gradual rollout | Progressive or Canary |
| Instant rollback | Blue-Green or Feature Flags |
| A/B testing | Dark Launch |
| Simple setup | Rolling |
| Cost-effective | Rolling or Dark Launch |

---

**See also:**
- `playbooks/` - Step-by-step deployment procedures
- `scripts/` - Automation scripts
- `ROLLBACK-PLAYBOOK.md` - Detailed rollback procedures
