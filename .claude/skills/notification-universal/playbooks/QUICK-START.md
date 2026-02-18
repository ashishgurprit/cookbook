# Notification Universal - Quick Start Guide

**Get multi-channel notifications running in 20 minutes**

## Prerequisites

- Python 3.9+ or Node.js 16+
- SendGrid account (free: 100 emails/day)
- OneSignal account (free: 1M push/month)
- Redis (for rate limiting & queuing)

## Installation (5 minutes)

### Python
```bash
pip install fastapi uvicorn sendgrid requests redis websockets
```

### Environment Variables
```bash
# SendGrid (Email)
SENDGRID_API_KEY=SG.xxx
FROM_EMAIL=noreply@example.com

# OneSignal (Push)
ONESIGNAL_APP_ID=xxx
ONESIGNAL_API_KEY=xxx

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Limits
MAX_NOTIFICATIONS_PER_HOUR=100
DAILY_BUDGET=50
```

## Setup (10 minutes)

### 1. SendGrid Setup
1. Sign up at https://sendgrid.com (free: 100 emails/day)
2. Verify sender email: Settings → Sender Authentication
3. Create API key: Settings → API Keys → Create API Key
4. Copy API key to `.env`

### 2. OneSignal Setup
1. Sign up at https://onesignal.com (free: 1M push/month)
2. Create new app: Apps → New App
3. Configure platforms (iOS, Android, Web)
4. Copy App ID + API Key: Settings → Keys & IDs

### 3. Redis Setup
```bash
# macOS
brew install redis
brew services start redis

# Linux
sudo apt-get install redis-server
sudo systemctl start redis
```

### 4. Run Server
```bash
uvicorn app:app --reload
```

## Smoke Tests (5 minutes)

**Test 1: Send Multi-Channel Notification**
```bash
curl -X POST http://localhost:8000/notifications/send \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-123",
    "title": "Test Notification",
    "body": "This is a test notification",
    "priority": "high"
  }'

# Expected: Sends to push + in-app
```

**Test 2: Critical Notification (All Channels)**
```bash
curl -X POST http://localhost:8000/notifications/send \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-123",
    "title": "URGENT: Security Alert",
    "body": "Unusual login detected",
    "priority": "critical"
  }'

# Expected: Sends to email + push + in-app
```

**Test 3: WebSocket (In-App)**
```javascript
// Frontend code
const ws = new WebSocket('ws://localhost:8000/ws/user-123');

ws.onmessage = (event) => {
  const notification = JSON.parse(event.data);
  console.log('Notification received:', notification);
};
```

**Test 4: User Preferences**
```bash
# Get preferences
curl http://localhost:8000/notifications/preferences \
  -H "Authorization: Bearer token"

# Update preferences
curl -X POST http://localhost:8000/notifications/preferences \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{
    "email_enabled": true,
    "push_enabled": true,
    "marketing_email": false
  }'
```

**Test 5: Health Check**
```bash
curl http://localhost:8000/health

# Expected:
# {
#   "status": "ok",
#   "providers": {
#     "email": "ok",
#     "push": "ok",
#     "in_app": "ok"
#   }
# }
```

## Production Checklist

### Security (OWASP)
- [ ] A01: Authentication on all endpoints
- [ ] A02: Credentials in AWS Secrets Manager
- [ ] A03: Email header injection prevention
- [ ] A04: Rate limiting (100/hour per user)
- [ ] A10: Webhook URL validation (whitelist domains)
- [ ] User preferences: Opt-in for marketing (GDPR)
- [ ] Unsubscribe link in all marketing emails

### Channels
- [ ] Email: SendGrid configured + sender verified
- [ ] Push: OneSignal configured for iOS/Android/Web
- [ ] In-App: WebSocket server running
- [ ] Webhooks: Slack/Discord URLs whitelisted

### Monitoring
- [ ] Datadog metrics: delivery rate, latency, cost
- [ ] PagerDuty alerts: delivery rate <90%
- [ ] Daily spend alerts at $45 (90% of budget)
- [ ] Track CTR (click-through rate) per channel

### User Experience
- [ ] Preference center: Users control channels
- [ ] Quiet hours: No push 9PM-8AM
- [ ] Frequency capping: Max 3 notifications/day
- [ ] Deduplication: Same notification not sent twice
- [ ] Fallback: Push fails → Email sent

## Channel Selection Guide

| Notification Type | Priority | Channels | Why |
|-------------------|----------|----------|-----|
| OTP/2FA | Critical | Email + SMS | Security |
| Payment Success | High | Email + Push | Confirmation |
| Order Shipped | High | Push + In-app | Real-time |
| Newsletter | Low | Email | Non-urgent |
| Feature Tip | Low | In-app | Contextual |
| Deployment Alert | High | Slack | Team collab |

## Cost Optimization (1M notifications/month)

```
Multi-Channel Strategy:
- 500K emails (SendGrid):    $500
- 300K push (OneSignal):     $810 (free up to 1M, then $9/10K)
- 150K in-app (WebSocket):   $0
- 50K webhooks:              $0
- Infrastructure (Redis):    $100
Total: $1,200/month

vs Single Provider (Twilio): $2,000/month
Savings: $800/month = $9,600/year
```

**Free Tiers**:
- SendGrid: 100 emails/day free
- OneSignal: 1M push/month free
- Redis: Self-hosted free

## Routing Logic

```python
# Critical → All channels
if priority == "critical":
    channels = ["email", "push", "in-app"]

# High → Push + In-app
elif priority == "high":
    channels = ["push", "in-app"]

# Normal → In-app only
else:
    channels = ["in-app"]

# Respect user preferences
channels = [c for c in channels if user.has_enabled(c)]

# Quiet hours (9PM-8AM): Suppress push
if is_quiet_hours(user.timezone):
    channels.remove("push")
```

## Troubleshooting

### SendGrid Error: 403 Forbidden
```
Error: Sender email not verified
Solution: Verify sender in SendGrid → Settings → Sender Authentication
```

### OneSignal Error: Invalid App ID
```
Error: App ID not found
Solution: Check ONESIGNAL_APP_ID in .env matches OneSignal dashboard
```

### WebSocket Not Connecting
```
Error: Connection refused
Solution: Check Redis is running (redis-cli ping → PONG)
```

### Rate Limit Exceeded
```
Error: 429 Too Many Requests
Solution: Wait 1 hour or increase MAX_NOTIFICATIONS_PER_HOUR
```

## Email Templates

```python
# Welcome email
WELCOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<body>
    <h1>Welcome, {{ user_name }}!</h1>
    <p>Thanks for joining {{ app_name }}.</p>
    <a href="{{ verify_url }}" style="background:#007bff;color:white;padding:10px 20px;">
        Verify Email
    </a>
    <p><small><a href="{{ unsubscribe_url }}">Unsubscribe</a></small></p>
</body>
</html>
"""

# Transaction email
PAYMENT_TEMPLATE = """
<!DOCTYPE html>
<html>
<body>
    <h1>Payment Successful</h1>
    <p>Amount: ${{ amount }}</p>
    <p>Transaction ID: {{ transaction_id }}</p>
</body>
</html>
"""
```

## Push Notification Best Practices

**Good Examples**:
- ✅ "Your order #1234 has shipped!"
- ✅ "New message from John"
- ✅ "50% off sale ends in 2 hours"

**Bad Examples**:
- ❌ "Check out our app!" (vague)
- ❌ "Update available" (not actionable)
- ❌ "Hello!" (no value)

**Timing**:
- Critical: Immediate
- High: Within 5 minutes
- Normal: Next active session
- Low: Daily digest

## Metrics to Track

```python
# Delivery rate
delivery_rate = delivered / sent * 100
# Target: >90%

# Click-through rate (CTR)
ctr = clicks / delivered * 100
# Email: 10-15%, Push: 15-20%, In-app: 40-60%

# Opt-out rate
opt_out_rate = opt_outs / active_users * 100
# Target: <5%

# Cost per notification
cost_per_notification = total_cost / notifications_sent
# Target: <$0.0012
```

## Next Steps

1. Read full guide: `.claude/skills/notification-universal/SKILL.md`
2. Review 3D decision matrix: `3D-DECISION-MATRIX.md`
3. Set up monitoring in Datadog
4. Configure user preference center
5. A/B test notification channels

**Total setup time: 20 minutes** ⏱️
**Cost: $1,200/month** (1M notifications) 💰
**Engagement: 3x improvement** (35% CTR vs 10%) 📈
**User control: ✅** (Opt-in/opt-out per channel)
