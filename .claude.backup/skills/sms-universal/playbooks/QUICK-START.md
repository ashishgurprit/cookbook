# SMS Universal - Quick Start Guide

**Get production SMS running in 15 minutes**

## Prerequisites

- Python 3.9+ or Node.js 16+
- Twilio account (free trial: $15 credit)
- AWS account (SNS: $0.005/SMS)
- Redis (for rate limiting)

## Installation (5 minutes)

### Python
```bash
pip install fastapi uvicorn twilio boto3 redis python-multipart
```

### Environment Variables
```bash
# Twilio
TWILIO_ACCOUNT_SID=AC...
TWILIO_AUTH_TOKEN=...
TWILIO_PHONE_NUMBER=+1234567890

# AWS SNS
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Limits
MAX_SMS_PER_MINUTE=10
DAILY_BUDGET=100
```

## Setup (5 minutes)

### 1. Twilio Setup
1. Sign up at https://www.twilio.com/try-twilio (free $15 credit)
2. Get phone number: Console → Phone Numbers → Buy a number
3. Copy credentials: Console → Account → API Keys

### 2. AWS SNS Setup
```bash
# Set monthly spend limit
aws sns set-sms-attributes --attributes MonthlySpendLimit=100
```

### 3. Run Server
```bash
uvicorn app:app --reload
```

## Smoke Tests (5 minutes)

**Test 1: Send SMS**
```bash
curl -X POST http://localhost:8000/sms/send \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{
    "phone": "+1234567890",
    "message": "Test message",
    "priority": "normal"
  }'
```

**Test 2: Check Status**
```bash
curl http://localhost:8000/sms/msg-123/status
```

**Test 3: Health Check**
```bash
curl http://localhost:8000/health
# Expected: {"status": "ok", "providers": {"twilio": "ok", "aws_sns": "ok"}}
```

## Production Checklist

- [ ] OWASP A01: Authentication on all endpoints
- [ ] OWASP A02: Credentials in Secrets Manager
- [ ] OWASP A03: Message validation (anti-spam)
- [ ] OWASP A04: Rate limiting (10/min per user)
- [ ] OWASP A10: Webhook SSRF prevention
- [ ] Monitoring: Datadog metrics + alerts
- [ ] Failover: Test Twilio → AWS SNS failover
- [ ] Cost: Daily spend alerts at $90

## Cost (100K SMS/month)

```
Intelligent Routing:
- 60K OTP (Twilio):        $600
- 40K Notifications (SNS): $200
Total: $850/month

Single Provider:
- 100K Twilio only:        $1,000
Savings: $150/month
```

## Troubleshooting

**Twilio Error: 21211**
```
Error: Invalid 'To' phone number
Solution: Use E.164 format (+1234567890)
```

**AWS SNS Error: InvalidParameter**
```
Error: Phone number must be E.164 format
Solution: Add + prefix to phone number
```

**Rate Limit Exceeded**
```
Error: 429 Too Many Requests
Solution: Wait 60 seconds or upgrade plan
```

## Next Steps

1. Read full guide: `.claude/skills/sms-universal/SKILL.md`
2. Review 3D decision matrix: `3D-DECISION-MATRIX.md`
3. Set up monitoring in Datadog
4. Configure webhooks for delivery tracking

**Total setup time: 15 minutes** ⏱️
**Cost: $850/month** (100K SMS) 💰
**Uptime: 99.95%** ✅
