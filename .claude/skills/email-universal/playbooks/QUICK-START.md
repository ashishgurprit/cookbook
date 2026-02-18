# Email Universal - Quick Start Guide

Get email sending working in 15 minutes.

## Prerequisites

- Redis running locally or remote
- Python 3.9+ or Node.js 16+ (depending on your backend)
- Email provider account (SendGrid, AWS SES, or SMTP)

## Step 1: Choose Your Provider (2 minutes)

### Option A: SendGrid (Recommended for Transactional)

**Best For**: < 10k emails/month, analytics needed

1. Sign up: https://signup.sendgrid.com
2. Get API key: Settings > API Keys > Create API Key
3. Verify sender: Settings > Sender Authentication > Verify Single Sender
4. Note your API key (starts with `SG.`)

**Cost**: $19.95/month for 50k emails (Free tier: 100 emails/day)

### Option B: AWS SES (Recommended for High Volume)

**Best For**: > 10k emails/month, cost-sensitive

1. Sign up: https://aws.amazon.com/ses
2. Verify domain: SES > Verified Identities > Create Identity
3. Request production access: Account Dashboard > Request Production Access
4. Create IAM user with `ses:SendEmail` permission
5. Note your access key and secret key

**Cost**: $0.10 per 1,000 emails (cheapest option)

### Option C: SMTP (Self-Hosted)

**Best For**: Privacy-focused, self-hosted

1. Get SMTP credentials from your email provider
2. Note: host, port, username, password

## Step 2: Install Dependencies (2 minutes)

### Python (FastAPI)

```bash
pip install fastapi uvicorn redis aioredis

# Choose your provider:
pip install sendgrid              # SendGrid
pip install boto3                 # AWS SES
pip install aiosmtplib            # SMTP
```

### Node.js (Express)

```bash
npm install express redis ioredis

# Choose your provider:
npm install @sendgrid/mail        # SendGrid
npm install @aws-sdk/client-ses   # AWS SES
npm install nodemailer            # SMTP
```

## Step 3: Install Redis (3 minutes)

### macOS

```bash
brew install redis
brew services start redis
```

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install redis-server
sudo systemctl start redis
```

### Docker

```bash
docker run -d -p 6379:6379 redis:7-alpine
```

### Verify Redis

```bash
redis-cli ping
# Should return: PONG
```

## Step 4: Configure Environment (2 minutes)

Create `.env` file in your project root:

```bash
# SendGrid (Primary)
SENDGRID_API_KEY=SG.your_sendgrid_api_key_here
SENDGRID_FROM_EMAIL=noreply@yourdomain.com
SENDGRID_FROM_NAME=Your App Name

# AWS SES (Fallback - Optional)
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
AWS_REGION=us-east-1
AWS_SES_FROM_EMAIL=noreply@yourdomain.com

# SMTP (Optional)
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USER=your_smtp_username
SMTP_PASSWORD=your_smtp_password
SMTP_FROM_EMAIL=noreply@yourdomain.com

# Redis
REDIS_URL=redis://localhost:6379

# Configuration
EMAIL_TEMPLATES_DIR=./templates/email
EMAIL_DEFAULT_PROVIDER=sendgrid
EMAIL_MAX_RETRIES=3
EMAIL_ATTACHMENTS_MAX_SIZE_MB=10
```

**Security**: Never commit `.env` to git. Add to `.gitignore`.

## Step 5: Copy Email Service (2 minutes)

### Python (FastAPI)

```bash
# Copy the email service template
cp .claude/skills/email-universal/templates/backend/fastapi-email.py ./app/email_service.py
```

### Node.js (Express)

```bash
# Copy the email service template
cp .claude/skills/email-universal/templates/backend/express-email.js ./src/emailService.js
```

## Step 6: Create Email Templates (3 minutes)

Create `templates/email` directory and add templates:

```bash
mkdir -p templates/email
```

Copy template files:

```bash
# Copy all templates
cp .claude/skills/email-universal/templates/html/*.html templates/email/
cp .claude/skills/email-universal/templates/html/*.txt templates/email/
```

Or create your own (example: `password-reset.html`):

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Reset Your Password</title>
</head>
<body>
  <h1>{{ app_name }}</h1>
  <h2>Reset Your Password</h2>
  <p>Hi {{ username }},</p>
  <p>Click the link below to reset your password:</p>
  <a href="{{ reset_link }}">Reset Password</a>
  <p>This link expires in {{ expiry_hours }} hours.</p>
</body>
</html>
```

And plain text version (`password-reset.txt`):

```text
{{ app_name }}

Reset Your Password

Hi {{ username }},

Click the link below to reset your password:
{{ reset_link }}

This link expires in {{ expiry_hours }} hours.
```

## Step 7: Integrate into Your App (3 minutes)

### Python (FastAPI)

```python
from fastapi import FastAPI
from app.email_service import EmailService, EmailPriority
import os

app = FastAPI()

# Initialize email service
email_service = EmailService(
    redis_url=os.environ.get('REDIS_URL'),
    templates_dir='./templates/email'
)

@app.on_event("startup")
async def startup():
    await email_service.initialize()
    email_service.startQueueProcessor()

@app.on_event("shutdown")
async def shutdown():
    await email_service.close()

# Send email endpoint
@app.post("/api/email/send")
async def send_email(request: dict):
    result = await email_service.sendEmail(
        to=request['to'],
        subject=request['subject'],
        template=request['template'],
        variables=request['variables'],
        priority=EmailPriority.HIGH
    )
    return {"success": True, "emailId": result['emailId']}
```

### Node.js (Express)

```javascript
const express = require('express');
const { EmailService, EmailPriority } = require('./src/emailService');

const app = express();
app.use(express.json());

// Initialize email service
const emailService = new EmailService(
  process.env.REDIS_URL,
  './templates/email'
);

emailService.initialize().then(() => {
  emailService.startQueueProcessor();
  console.log('Email service initialized');
});

// Send email endpoint
app.post('/api/email/send', async (req, res) => {
  try {
    const result = await emailService.sendEmail({
      to: req.body.to,
      subject: req.body.subject,
      template: req.body.template,
      variables: req.body.variables,
      priority: EmailPriority.HIGH
    });
    res.json({ success: true, emailId: result.emailId });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## Step 8: Test Email Sending (5 minutes)

### Test 1: Send Password Reset Email

```bash
curl -X POST http://localhost:3000/api/email/send \
  -H "Content-Type: application/json" \
  -d '{
    "to": "your-email@example.com",
    "subject": "Password Reset Request",
    "template": "password-reset",
    "variables": {
      "app_name": "My App",
      "username": "John",
      "reset_link": "https://example.com/reset?token=abc123",
      "expiry_hours": "24",
      "support_link": "https://example.com/support",
      "privacy_link": "https://example.com/privacy",
      "current_year": "2026"
    },
    "priority": "high"
  }'
```

Expected response:

```json
{
  "success": true,
  "emailId": "email:1705523456789:abc123def456"
}
```

### Test 2: Check Email Status

```bash
curl http://localhost:3000/api/email/status/email:1705523456789:abc123def456
```

Expected response:

```json
{
  "success": true,
  "emailId": "email:1705523456789:abc123def456",
  "to": "your-email@example.com",
  "status": "sent",
  "queuedAt": 1705523456789,
  "sentAt": 1705523457123,
  "messageId": "msg_abc123",
  "retryCount": 0
}
```

### Test 3: Verify Email Received

Check your inbox for the email. It should:
- ✅ Have correct subject
- ✅ Have personalized content (username)
- ✅ Have working reset link
- ✅ Look good in HTML
- ✅ Have plain text fallback

## Common Issues

### Issue 1: Redis Connection Error

**Error**: `Error: Redis connection failed`

**Solution**:
```bash
# Check if Redis is running
redis-cli ping

# If not running, start it
brew services start redis  # macOS
sudo systemctl start redis  # Linux
```

### Issue 2: SendGrid API Error

**Error**: `Error: 403 Forbidden`

**Solution**:
1. Verify API key is correct
2. Check sender email is verified in SendGrid
3. Ensure API key has "Mail Send" permission

### Issue 3: Email Not Received

**Check**:
1. Spam folder
2. Email status endpoint (check for bounces)
3. Redis queue: `redis-cli LLEN queue:email:high`
4. Provider dashboard (SendGrid/SES) for delivery status

### Issue 4: Template Not Found

**Error**: `ENOENT: no such file or directory`

**Solution**:
1. Verify template files exist in `templates/email/`
2. Check `EMAIL_TEMPLATES_DIR` environment variable
3. Ensure both `.html` and `.txt` files exist

## Next Steps

1. **Set up webhooks** for bounce/complaint handling (see SECURITY.md)
2. **Run security tests**: `pytest tests/test_security.py -v`
3. **Configure SPF/DKIM/DMARC** for better deliverability (see SKILL.md)
4. **Monitor email queue**: Set up alerts for failed emails
5. **Review security playbook**: Read playbooks/SECURITY.md

## Production Checklist

Before deploying to production:

- [ ] Environment variables configured (no hardcoded secrets)
- [ ] Redis production instance (not local)
- [ ] SendGrid/SES production account (not sandbox)
- [ ] Sender domain verified
- [ ] SPF/DKIM/DMARC configured
- [ ] Webhooks configured for bounces/complaints
- [ ] Security tests passing (`pytest tests/test_security.py`)
- [ ] Rate limiting enabled (see rate-limiting-universal skill)
- [ ] Monitoring and alerts configured
- [ ] Backup email provider configured (fallback)

## Help

- **Documentation**: See `.claude/skills/email-universal/SKILL.md`
- **Security**: See `playbooks/SECURITY.md`
- **Tests**: See `tests/test_security.py`
- **Support**: Check provider documentation (SendGrid, AWS SES)

You're done! Email sending should now be working in your application.
