# Email System - Universal Skill

> **Production-ready email system for transactional and notification emails**
>
> Multi-provider support (SendGrid, AWS SES, SMTP) with queue, templates, and security-first design.

---

## Overview

**What**: Multi-provider email system with Redis queue and XSS-safe HTML templates
**Why**: Standardize email across 30 projects, prevent security issues, ensure deliverability
**How**: Provider adapter pattern + email queue + validated templates

**Decision**: Multi-Provider Adapter chosen via 3D Decision Matrix (see `3D-DECISION-MATRIX.md`)

---

## Architecture Decision

**Provider Strategy**: Multi-Provider Adapter
- **Primary**: SendGrid (transactional emails, analytics)
- **Fallback**: AWS SES (high volume, cost-effective)
- **Optional**: SMTP (self-hosted, full control)

**Why Multi-Provider?**
- ✅ No vendor lock-in
- ✅ High availability (failover)
- ✅ Cost optimization
- ✅ Better deliverability

**Email Queue**: Redis-based
- Don't block HTTP requests
- Automatic retries
- Priority handling (critical emails first)
- Rate limit compliance

**Template System**: Simple Variable Replacement
- XSS-safe (escape all user input)
- No complex logic (security)
- Responsive HTML + plain text fallback
- Reusable components

---

## Email Flow Architecture

```
┌─────────────┐
│ Application │
└──────┬──────┘
       │ send_email(to, template, vars)
       ↓
┌──────────────────┐
│  Email Service   │  ← Unified API
│  (This Skill)    │
└──────┬───────────┘
       │
       ↓
┌──────────────────┐
│  Provider Layer  │  ← Adapter Pattern
│ ┌──────────────┐ │
│ │  SendGrid    │ │  Primary (transactional)
│ │  AWS SES     │ │  Fallback (high volume)
│ │  SMTP        │ │  Optional (self-hosted)
│ └──────────────┘ │
└──────┬───────────┘
       │
       ↓
┌──────────────────┐
│   Email Queue    │  ← Redis
│  (Background)    │
└──────┬───────────┘
       │
       ↓
┌──────────────────┐
│  Queue Worker    │  ← Processes queue
│  - Retry logic   │
│  - Rate limiting │
│  - Monitoring    │
└──────────────────┘
```

---

## Provider Adapters

### SendGrid (Primary)

**Use Cases**:
- Transactional emails (password reset, verification)
- Notifications (login alerts, mentions)
- Low-to-medium volume (< 100k/month)

**Features**:
- ✅ Analytics (delivery, opens, clicks)
- ✅ Fast delivery (optimized network)
- ✅ Built-in templates (optional)
- ✅ Webhook support (bounces, complaints)

**Cost**:
- Free: 100 emails/day
- Essentials: $15/mo for 40,000 emails
- Pro: $60/mo for 100,000 emails

**Setup**:
```bash
# Get API key from SendGrid dashboard
export SENDGRID_API_KEY="SG.xxx"
export EMAIL_FROM="noreply@yourapp.com"
```

### AWS SES (Fallback)

**Use Cases**:
- High volume emails (newsletters, marketing)
- Cost-sensitive applications
- AWS ecosystem integration

**Features**:
- ✅ Very cheap ($0.10 per 1,000 emails)
- ✅ High reliability (AWS infrastructure)
- ✅ Scalable (millions of emails)
- ❌ No built-in analytics

**Cost**:
- $0.10 per 1,000 emails
- $0 first 62,000 emails/month (from EC2)

**Setup**:
```bash
# Configure AWS credentials
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="xxx"
export AWS_REGION="us-east-1"
export SES_FROM_EMAIL="noreply@yourapp.com"
```

### SMTP (Optional)

**Use Cases**:
- Self-hosted email server
- Privacy-focused applications
- Custom email infrastructure

**Features**:
- ✅ Full control
- ✅ No monthly cost (self-hosted)
- ✅ Works with any SMTP server
- ❌ Requires maintenance
- ❌ Deliverability challenges

**Setup**:
```bash
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"  # 587 for TLS, 465 for SSL
export SMTP_USER="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"
export SMTP_FROM="noreply@yourapp.com"
```

---

## Email Templates

### Template Structure

```
templates/
├── base.html              # Base layout (header, footer)
├── password-reset.html    # Password reset email
├── email-verification.html # Email verification
├── login-notification.html # New login detected
├── welcome.html           # Welcome new user
├── notification.html      # Generic notification
└── components/
    ├── header.html        # Email header
    ├── footer.html        # Email footer
    └── button.html        # CTA button component
```

### Example Template (Password Reset)

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ app_name }} - Password Reset</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <!-- Email Container -->
                <table role="presentation" width="600" cellpadding="0" cellspacing="0"
                       style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">

                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px 40px; text-align: center;">
                            <h1 style="margin: 0; color: #333; font-size: 24px;">
                                Password Reset Request
                            </h1>
                        </td>
                    </tr>

                    <!-- Body -->
                    <tr>
                        <td style="padding: 20px 40px;">
                            <p style="margin: 0 0 20px 0; color: #666; line-height: 1.6;">
                                Hi <strong>{{ user_name }}</strong>,
                            </p>
                            <p style="margin: 0 0 20px 0; color: #666; line-height: 1.6;">
                                We received a request to reset your password. Click the button below to create a new password:
                            </p>

                            <!-- CTA Button -->
                            <table role="presentation" cellpadding="0" cellspacing="0" style="margin: 30px 0;">
                                <tr>
                                    <td align="center" style="border-radius: 4px; background-color: #007bff;">
                                        <a href="{{ reset_link }}"
                                           style="display: inline-block; padding: 16px 36px; font-size: 16px; color: #ffffff; text-decoration: none; font-weight: bold;">
                                            Reset Password
                                        </a>
                                    </td>
                                </tr>
                            </table>

                            <p style="margin: 20px 0 0 0; color: #999; font-size: 14px; line-height: 1.6;">
                                If you didn't request this, you can safely ignore this email. The link will expire in <strong>{{ expiry_hours }} hours</strong>.
                            </p>

                            <p style="margin: 20px 0 0 0; color: #999; font-size: 12px;">
                                Or copy and paste this link:<br>
                                <a href="{{ reset_link }}" style="color: #007bff; word-break: break-all;">{{ reset_link }}</a>
                            </p>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="padding: 40px; background-color: #f8f9fa; border-radius: 0 0 8px 8px;">
                            <p style="margin: 0; color: #999; font-size: 12px; text-align: center;">
                                © {{ current_year }} {{ app_name }}. All rights reserved.<br>
                                <a href="{{ unsubscribe_link }}" style="color: #999;">Unsubscribe</a> |
                                <a href="{{ privacy_link }}" style="color: #999;">Privacy Policy</a>
                            </p>
                        </td>
                    </tr>

                </table>
            </td>
        </tr>
    </table>
</body>
</html>
```

### Plain Text Version (Always Include)

```
Password Reset Request

Hi {{ user_name }},

We received a request to reset your password. Click the link below to create a new password:

{{ reset_link }}

If you didn't request this, you can safely ignore this email. The link will expire in {{ expiry_hours }} hours.

---
© {{ current_year }} {{ app_name }}. All rights reserved.
Unsubscribe: {{ unsubscribe_link }}
```

---

## Security Considerations

### OWASP Compliance

✅ **Injection Prevention** (OWASP #3)
- Email header injection prevention (CRLF validation)
- Template variable escaping (XSS prevention)
- Attachment path traversal prevention

✅ **Sensitive Data Exposure** (OWASP #2)
- No PII in logs (email addresses, content redacted)
- TLS for email transmission
- Secure credential storage (env vars only)

✅ **Security Misconfiguration** (OWASP #5)
- SPF/DKIM/DMARC setup guide
- Provider authentication (API keys)
- Rate limiting (prevent abuse)

✅ **Logging & Monitoring** (OWASP #9)
- Delivery tracking (success/failure)
- Bounce/complaint handling
- No sensitive data in logs

### Email Header Injection Prevention

**Attack**: `\r\nBcc: attacker@evil.com` in subject/from/to fields

**Prevention**:
```python
def validate_email_header(value: str) -> str:
    """Prevent CRLF injection in email headers"""
    if '\r' in value or '\n' in value:
        raise ValueError("Invalid characters in email header")
    return value.strip()

# Validate all header fields
subject = validate_email_header(user_subject)
from_email = validate_email_header(from_email)
to_email = validate_email_header(to_email)
```

### Template XSS Prevention

**Attack**: `<script>alert('XSS')</script>` in user-provided variables

**Prevention**:
```python
def escape_html(text: str) -> str:
    """Escape HTML entities to prevent XSS"""
    return text.replace('&', '&amp;') \
               .replace('<', '&lt;') \
               .replace('>', '&gt;') \
               .replace('"', '&quot;') \
               .replace("'", '&#039;')

# Escape all user-provided variables
safe_vars = {
    'user_name': escape_html(user.name),
    'message': escape_html(message),
    'reset_link': escape_url(reset_link)  # URL encoding
}

html = render_template(template, safe_vars)
```

### Attachment Security

**Prevention**:
```python
ALLOWED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg', '.gif', '.txt', '.csv'}
MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10MB

def validate_attachment(file_path: str):
    """Validate attachment before sending"""
    # Check extension
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Invalid attachment type: {ext}")

    # Check size
    size = os.path.getsize(file_path)
    if size > MAX_ATTACHMENT_SIZE:
        raise ValueError(f"Attachment too large: {size} bytes")

    # Check path traversal
    if '..' in file_path or file_path.startswith('/'):
        raise ValueError("Invalid file path")

    # Validate file exists and is readable
    if not os.path.isfile(file_path):
        raise ValueError("File not found")
```

### No PII in Logs

**Bad**:
```python
# ❌ NEVER log email addresses or content
logger.info(f"Sent email to {to_email}: {subject}")
```

**Good**:
```python
# ✅ Log only metadata
logger.info("email.sent",
    email_id=email_id,
    template="password-reset",
    provider="sendgrid",
    status="delivered"
    # NO: to_email, subject, body
)
```

---

## Email Queue Implementation

### Why Queue?

1. **Don't block HTTP requests** - Returns immediately
2. **Automatic retries** - Failed sends retry with backoff
3. **Rate limit compliance** - Respect provider limits
4. **Priority handling** - Critical emails (password reset) sent first

### Queue Structure (Redis)

```python
# Queue key structure
queue:email:high      # Critical emails (password reset, verification)
queue:email:normal    # Notifications, alerts
queue:email:low       # Marketing, newsletters

# Email data (hash)
email:{email_id} = {
    'to': 'user@example.com',
    'subject': 'Password Reset',
    'template': 'password-reset',
    'variables': '{"user_name": "John", "reset_link": "..."}',
    'provider': 'sendgrid',
    'priority': 'high',
    'retry_count': 0,
    'max_retries': 3,
    'created_at': '2026-01-18T10:00:00Z'
}
```

### Queue Worker

```python
async def process_email_queue():
    """Background worker to process email queue"""
    while True:
        # Process high priority first
        for queue_key in ['queue:email:high', 'queue:email:normal', 'queue:email:low']:
            email_id = await redis.rpop(queue_key)

            if email_id:
                email_data = await redis.hgetall(f"email:{email_id}")

                try:
                    # Send email
                    await send_email_via_provider(email_data)

                    # Mark as sent
                    await redis.hset(f"email:{email_id}", 'status', 'sent')
                    logger.info("email.sent", email_id=email_id)

                except Exception as e:
                    # Retry logic
                    retry_count = int(email_data.get('retry_count', 0))
                    max_retries = int(email_data.get('max_retries', 3))

                    if retry_count < max_retries:
                        # Re-queue with backoff
                        await redis.hset(f"email:{email_id}", 'retry_count', retry_count + 1)
                        await redis.lpush(queue_key, email_id)

                        # Exponential backoff (1s, 2s, 4s)
                        await asyncio.sleep(2 ** retry_count)

                        logger.warning("email.retry",
                            email_id=email_id,
                            retry_count=retry_count + 1,
                            error=str(e)
                        )
                    else:
                        # Max retries reached
                        await redis.hset(f"email:{email_id}", 'status', 'failed')
                        logger.error("email.failed",
                            email_id=email_id,
                            error=str(e)
                        )

        # Small delay between queue checks
        await asyncio.sleep(0.1)
```

---

## Bounce and Complaint Handling

### Why Important?

- Maintain sender reputation
- Comply with email laws
- Reduce spam folder rate
- Clean email lists

### Bounce Types

**Hard Bounce**: Permanent delivery failure
- Invalid email address
- Domain doesn't exist
- Mailbox full

**Soft Bounce**: Temporary delivery failure
- Mailbox full (temporary)
- Server temporarily unavailable
- Message too large

**Action**:
- Hard bounce: Remove from email list immediately
- Soft bounce: Retry up to 3 times, then remove

### Complaint (Spam Report)

User clicked "Mark as Spam"

**Action**:
- Immediately unsubscribe
- Add to suppression list
- Review email content (why marked as spam?)

### Webhook Handlers

**SendGrid Webhook**:
```python
@app.post("/webhooks/sendgrid")
async def sendgrid_webhook(request: Request):
    """Handle SendGrid bounce/complaint webhooks"""
    events = await request.json()

    for event in events:
        email = event.get('email')
        event_type = event.get('event')  # bounce, dropped, spam_report

        if event_type in ['bounce', 'dropped']:
            # Hard bounce
            await mark_email_as_bounced(email)
            logger.warning("email.bounced", email=email, type=event_type)

        elif event_type == 'spam_report':
            # Spam complaint
            await unsubscribe_email(email)
            logger.warning("email.spam_complaint", email=email)

    return {"status": "processed"}
```

**AWS SES Webhook** (via SNS):
```python
@app.post("/webhooks/ses")
async def ses_webhook(request: Request):
    """Handle AWS SES bounce/complaint notifications"""
    message = await request.json()

    # Verify SNS signature (security)
    if not verify_sns_signature(message):
        raise HTTPException(403, "Invalid SNS signature")

    notification = json.loads(message['Message'])
    notification_type = notification['notificationType']

    if notification_type == 'Bounce':
        bounce = notification['bounce']
        for recipient in bounce['bouncedRecipients']:
            email = recipient['emailAddress']
            await mark_email_as_bounced(email)

    elif notification_type == 'Complaint':
        complaint = notification['complaint']
        for recipient in complaint['complainedRecipients']:
            email = recipient['emailAddress']
            await unsubscribe_email(email)

    return {"status": "processed"}
```

---

## Deliverability Setup

### SPF (Sender Policy Framework)

Verifies that email comes from authorized server.

**Setup**:
```
# Add to your domain's DNS (TXT record)
yourapp.com. TXT "v=spf1 include:sendgrid.net include:amazonses.com ~all"
```

### DKIM (DomainKeys Identified Mail)

Cryptographically signs emails to prove authenticity.

**Setup** (SendGrid):
1. Go to SendGrid → Settings → Sender Authentication
2. Click "Authenticate Your Domain"
3. Add CNAME records to DNS (provided by SendGrid)

**Setup** (AWS SES):
1. Go to SES → Verified identities
2. Select your domain → DKIM
3. Add CNAME records to DNS (provided by AWS)

### DMARC (Domain-based Message Authentication)

Tells receiving servers what to do with unauthenticated emails.

**Setup**:
```
# Add to DNS (TXT record)
_dmarc.yourapp.com. TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourapp.com"
```

**Policy Options**:
- `p=none`: Monitor only (no action)
- `p=quarantine`: Send to spam folder
- `p=reject`: Reject email (strictest)

### Best Practices

1. ✅ **Use dedicated sending domain** (email.yourapp.com)
2. ✅ **Warm up IP address** (gradually increase volume)
3. ✅ **Monitor sender reputation** (Google Postmaster Tools)
4. ✅ **Handle bounces promptly** (remove invalid emails)
5. ✅ **Avoid spam trigger words** (FREE, ACT NOW, LIMITED TIME)
6. ✅ **Include unsubscribe link** (required by law)
7. ✅ **Authenticate domain** (SPF, DKIM, DMARC)
8. ✅ **Maintain clean list** (remove inactive subscribers)

---

## Monitoring & Alerts

### Metrics to Track

```python
# Delivery metrics
emails_sent_total = Counter('emails_sent_total', 'Total emails sent', ['provider', 'template'])
emails_delivered = Counter('emails_delivered_total', 'Successfully delivered')
emails_bounced = Counter('emails_bounced_total', 'Bounced emails', ['type'])
emails_complained = Counter('emails_complained_total', 'Spam complaints')

# Performance metrics
email_queue_size = Gauge('email_queue_size', 'Emails in queue', ['priority'])
email_send_duration = Histogram('email_send_duration_seconds', 'Time to send email')

# Usage
emails_sent_total.labels(provider='sendgrid', template='password-reset').inc()
with email_send_duration.time():
    await send_email(...)
```

### Alert Thresholds

| Metric | Threshold | Action |
|---|---|---|
| Bounce rate | > 5% | Review email list quality |
| Complaint rate | > 0.1% | Review email content |
| Delivery rate | < 95% | Check provider status |
| Queue size | > 1000 | Scale workers or check provider |
| Send failures | > 10/min | Investigate provider issues |

---

## Testing

### Unit Tests

```python
def test_email_header_injection_prevention():
    """Test that CRLF injection is prevented"""
    malicious_subject = "Test\r\nBcc: attacker@evil.com"

    with pytest.raises(ValueError, match="Invalid characters"):
        validate_email_header(malicious_subject)

def test_template_xss_prevention():
    """Test that XSS is prevented in templates"""
    malicious_name = "<script>alert('XSS')</script>"

    result = escape_html(malicious_name)

    assert '<script>' not in result
    assert '&lt;script&gt;' in result

def test_attachment_validation():
    """Test attachment security"""
    # Invalid extension
    with pytest.raises(ValueError, match="Invalid attachment type"):
        validate_attachment("malware.exe")

    # Path traversal
    with pytest.raises(ValueError, match="Invalid file path"):
        validate_attachment("../../etc/passwd")
```

### Integration Tests

```python
@pytest.mark.asyncio
async def test_send_email_via_sendgrid():
    """Test sending email via SendGrid"""
    result = await send_email(
        to="test@example.com",
        subject="Test Email",
        template="password-reset",
        variables={'user_name': 'Test User', 'reset_link': 'https://...'}
    )

    assert result['status'] == 'queued'
    assert result['email_id'] is not None

@pytest.mark.asyncio
async def test_email_queue_processing():
    """Test email queue worker"""
    # Queue email
    email_id = await queue_email(
        to="test@example.com",
        template="welcome",
        priority=EmailPriority.HIGH
    )

    # Process queue
    await process_email_queue()

    # Check sent
    status = await redis.hget(f"email:{email_id}", 'status')
    assert status == 'sent'
```

---

## Troubleshooting

### Issue: Emails going to spam

**Causes**:
- Missing SPF/DKIM/DMARC
- Poor sender reputation
- Spam trigger words
- Low engagement (no opens/clicks)

**Solutions**:
1. Verify SPF/DKIM/DMARC setup
2. Check sender reputation (Google Postmaster Tools)
3. Review email content (avoid spam words)
4. Clean email list (remove bounces)
5. Warm up new IP address (gradual volume increase)

### Issue: High bounce rate

**Causes**:
- Invalid email addresses
- Old email list
- Typos in email addresses

**Solutions**:
1. Validate email format before adding to list
2. Use double opt-in (confirm email address)
3. Remove hard bounces immediately
4. Clean list regularly (remove inactive)

### Issue: Provider rate limit hit

**Causes**:
- Sending too fast
- Spike in email volume
- Exceeded plan limit

**Solutions**:
1. Implement rate limiting in queue worker
2. Upgrade provider plan
3. Distribute across multiple providers
4. Batch emails (send in waves)

### Issue: Email queue growing

**Causes**:
- Provider outage
- Worker not running
- Rate limit hit

**Solutions**:
1. Check provider status
2. Verify worker is running
3. Scale workers (add more instances)
4. Check provider rate limits

---

## Best Practices

1. ✅ **Always include plain text version** (accessibility, spam filters)
2. ✅ **Mobile-responsive templates** (50%+ opens on mobile)
3. ✅ **Clear unsubscribe link** (required by law, reduces spam complaints)
4. ✅ **Test templates before sending** (preview, send test email)
5. ✅ **Monitor deliverability** (bounce rate, complaint rate)
6. ✅ **Handle bounces promptly** (clean list, maintain reputation)
7. ✅ **Use email queue** (don't block HTTP requests)
8. ✅ **Escape all user input** (XSS prevention)
9. ✅ **Validate email headers** (injection prevention)
10. ✅ **No PII in logs** (GDPR compliance)

---

## References

- **RFC 5321**: SMTP Protocol
- **RFC 5322**: Internet Message Format
- **CAN-SPAM Act**: Commercial email requirements
- **GDPR**: Email consent and privacy
- **SendGrid Docs**: https://docs.sendgrid.com
- **AWS SES Docs**: https://docs.aws.amazon.com/ses/

---

## Version History

- **v1.0** (2026-01-18): Initial release
  - Multi-provider support (SendGrid, AWS SES, SMTP)
  - Email queue (Redis-based)
  - XSS-safe templates
  - Bounce/complaint handling
  - Security compliance (OWASP)
