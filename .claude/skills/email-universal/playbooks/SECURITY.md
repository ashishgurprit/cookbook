# Email Universal - Security Playbook

Production security guide for email system.

## OWASP Compliance Matrix

| Category | Description | Implementation | Status |
|----------|-------------|----------------|--------|
| **A01:2021** | Broken Access Control | Attachment path validation | ✅ Implemented |
| **A03:2021** | Injection | Email header CRLF validation | ✅ Implemented |
| **A07:2021** | XSS | Template variable escaping | ✅ Implemented |
| **A09:2021** | Logging Failures | No PII in logs | ✅ Implemented |
| **A05:2021** | Security Misconfiguration | Secure defaults | ✅ Implemented |

## Security Features

### 1. Email Header Injection Prevention (CRLF)

**Vulnerability**: Attackers inject additional email headers via CRLF characters

**Attack Example**:
```python
# Malicious input
to = "victim@example.com\nBcc: attacker@evil.com"

# Without validation: Email sent to both victim and attacker
# With validation: Rejected with error
```

**Implementation**:

```python
def validate_email_header(value: str) -> str:
    """Prevent CRLF injection in email headers"""
    if '\r' in value or '\n' in value:
        raise ValueError("Invalid characters in email header (CRLF injection attempt)")
    return value.strip()

# Validate all header fields
to = validate_email_header(user_input_email)
subject = validate_email_header(user_input_subject)
```

**Testing**:
```bash
# Should be rejected
curl -X POST /api/email/send -d '{
  "to": "victim@example.com\nBcc: attacker@evil.com"
}'
# Expected: 400 error
```

### 2. XSS Prevention in Email Templates

**Vulnerability**: JavaScript injection in email content

**Attack Example**:
```html
<!-- Malicious input -->
username = "<script>alert('XSS')</script>"

<!-- Without escaping -->
<p>Hello <script>alert('XSS')</script></p>

<!-- With escaping -->
<p>Hello &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
```

**Implementation**:

```python
def escape_html(text: str) -> str:
    """Escape HTML entities to prevent XSS"""
    return str(text).replace('&', '&amp;') \
                    .replace('<', '&lt;') \
                    .replace('>', '&gt;') \
                    .replace('"', '&quot;') \
                    .replace("'", '&#039;')

# Escape all template variables
safe_username = escape_html(username)
safe_content = escape_html(message)
```

**URL Validation**:

```python
def escape_url(url: str) -> str:
    """Prevent javascript: protocol injection"""
    if not url.startswith('http://') and not url.startswith('https://'):
        raise ValueError("Invalid URL protocol (only http/https allowed)")
    return url

# Validate all URLs in templates
safe_reset_link = escape_url(reset_link)
```

**Testing**:
```bash
# Should be escaped (not executed)
curl -X POST /api/email/send -d '{
  "template": "welcome",
  "variables": {
    "username": "<script>alert(\"XSS\")</script>"
  }
}'
# Expected: Email contains &lt;script&gt; (escaped)
```

### 3. Attachment Path Traversal Prevention

**Vulnerability**: Access files outside allowed directory

**Attack Example**:
```python
# Malicious input
attachment = "../../etc/passwd"

# Without validation: Reads /etc/passwd
# With validation: Rejected with error
```

**Implementation**:

```python
async def validate_attachment_path(file_path: str) -> str:
    """Prevent path traversal in attachments"""
    # 1. Prevent directory traversal
    if '..' in file_path or file_path.startswith('/'):
        raise ValueError("Invalid file path (path traversal attempt)")

    # 2. Whitelist file extensions
    allowed_extensions = ['.pdf', '.txt', '.csv', '.jpg', '.png', '.gif', '.zip']
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in allowed_extensions:
        raise ValueError(f"File extension {ext} not allowed")

    # 3. Check file size
    max_size_mb = int(os.environ.get('EMAIL_ATTACHMENTS_MAX_SIZE_MB', '10'))
    stats = await aiofiles.os.stat(file_path)
    if stats.st_size > max_size_mb * 1024 * 1024:
        raise ValueError(f"File size exceeds {max_size_mb}MB limit")

    return os.path.abspath(file_path)
```

**Testing**:
```bash
# Should be rejected
curl -X POST /api/email/send -d '{
  "attachments": ["../../etc/passwd"]
}'
# Expected: 400 error
```

### 4. No PII in Logs

**Vulnerability**: Sensitive data exposed in logs

**Bad Example** (Don't do this):
```python
# ❌ BAD: Full email address in logs
logging.info(f"Sent email to {email}")

# ❌ BAD: API key in logs
logging.error(f"SendGrid error with key {api_key}")
```

**Good Example**:
```python
# ✅ GOOD: Masked email
logging.info(f"Sent email to {email.split('@')[0]}@***")

# ✅ GOOD: No API key
logging.error("SendGrid API error")

# ✅ GOOD: Message ID only
logging.info(f"Email sent: {message_id}")
```

**Implementation**:

```python
# Mask email addresses
def mask_email(email: str) -> str:
    """Mask email for logging (PII protection)"""
    return f"{email.split('@')[0]}@***"

# Log without PII
console.log(f"[EMAIL] Sent: {message_id} to {mask_email(to)}")
```

## Provider Security

### SendGrid Security

**API Key Management**:

```bash
# ✅ GOOD: Environment variable
export SENDGRID_API_KEY=SG.abc123...

# ❌ BAD: Hardcoded in code
api_key = "SG.abc123..."  # Don't do this!
```

**Permissions**:
1. Use restricted API keys (not full access)
2. Only grant "Mail Send" permission
3. Rotate API keys every 90 days
4. Use separate keys for dev/staging/production

**Sender Verification**:
1. Verify sender domain (not just email)
2. Set up SPF record: `v=spf1 include:sendgrid.net ~all`
3. Set up DKIM (SendGrid provides keys)
4. Set up DMARC: `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com`

### AWS SES Security

**IAM Policy** (Least Privilege):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ses:SendEmail",
        "ses:SendRawEmail"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ses:FromAddress": "noreply@yourdomain.com"
        }
      }
    }
  ]
}
```

**Best Practices**:
1. Use IAM user (not root account)
2. Rotate access keys every 90 days
3. Enable CloudTrail logging
4. Request production access (remove sandbox)
5. Set up bounce/complaint SNS notifications

### SMTP Security

**TLS Configuration**:

```python
# ✅ GOOD: Use TLS
transporter = nodemailer.createTransport({
  host: 'smtp.example.com',
  port: 587,  # STARTTLS
  secure: False,  # Upgrade to TLS
  auth: { user: '...', pass: '...' }
})

# ❌ BAD: Unencrypted
transporter = nodemailer.createTransport({
  host: 'smtp.example.com',
  port: 25,  # Unencrypted
  secure: False,
  auth: { user: '...', pass: '...' }
})
```

**Password Security**:
1. Use app-specific passwords (not account password)
2. Store in environment variables
3. Never commit to git
4. Use secrets manager in production (AWS Secrets Manager, HashiCorp Vault)

## Redis Security

### Authentication

```bash
# Set Redis password
redis-cli CONFIG SET requirepass "your_strong_password_here"

# Update connection URL
REDIS_URL=redis://:your_strong_password_here@localhost:6379
```

### Network Security

```bash
# Bind to localhost only (not public)
bind 127.0.0.1

# Disable dangerous commands
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command KEYS ""
rename-command CONFIG ""
```

### TLS (Production)

```bash
# Enable TLS in redis.conf
tls-port 6380
tls-cert-file /path/to/redis.crt
tls-key-file /path/to/redis.key
tls-ca-cert-file /path/to/ca.crt

# Update connection URL
REDIS_URL=rediss://localhost:6380  # Note: rediss (with TLS)
```

## Email Queue Security

### Queue Integrity

**Prevent Queue Tampering**:

```python
# ✅ GOOD: Validate email data before queuing
async def send_email(...):
    # Validate all inputs
    to = validate_email_header(to)
    subject = validate_email_header(subject)

    # Then queue
    await redis.lpush('queue:email:high', email_id)
```

**Prevent Queue Overflow** (DoS):

```python
# Limit queue size
MAX_QUEUE_SIZE = 10000

queue_size = await redis.llen('queue:email:high')
if queue_size > MAX_QUEUE_SIZE:
    raise ValueError("Email queue is full. Try again later.")
```

### Retry Security

**Prevent Infinite Retries**:

```python
MAX_RETRIES = 3  # Hard limit

if retry_count >= MAX_RETRIES:
    # Mark as failed (don't retry)
    await redis.hset(email_id, 'status', 'failed')
    logging.error(f"Email failed after {MAX_RETRIES} retries: {email_id}")
```

## Webhook Security

### Verify Webhook Authenticity

**SendGrid**:

```python
from sendgrid.helpers.eventwebhook import EventWebhook

@app.post("/webhooks/sendgrid")
async def handle_sendgrid_webhook(request: Request):
    # Verify signature
    public_key = os.environ.get('SENDGRID_WEBHOOK_PUBLIC_KEY')
    signature = request.headers.get('X-Twilio-Email-Event-Webhook-Signature')
    timestamp = request.headers.get('X-Twilio-Email-Event-Webhook-Timestamp')

    event_webhook = EventWebhook()
    ec_public_key = event_webhook.convert_public_key_to_ecdsa(public_key)

    body = await request.body()
    if not event_webhook.verify_signature(ec_public_key, body, signature, timestamp):
        return Response(status_code=403)  # Reject

    # Process webhook
    ...
```

**AWS SES (SNS)**:

```python
import boto3

@app.post("/webhooks/ses")
async def handle_ses_webhook(request: Request):
    # Verify SNS signature
    message = await request.json()

    # Check if message is from SNS
    if message.get('Type') == 'SubscriptionConfirmation':
        # Confirm subscription
        subscribe_url = message.get('SubscribeURL')
        # Visit URL to confirm

    # Verify signature
    sns = boto3.client('sns')
    # SNS signature verification logic
    ...
```

### Webhook Rate Limiting

```python
# Prevent webhook abuse
@app.post("/webhooks/sendgrid")
@rate_limit(max_requests=100, window_seconds=60)  # Max 100/min
async def handle_sendgrid_webhook(request: Request):
    ...
```

## Bounce and Complaint Handling

### Bounce Handling

```python
# Store bounced emails (don't send again)
@app.post("/webhooks/sendgrid")
async def handle_sendgrid_webhook(request: Request):
    events = await request.json()

    for event in events:
        if event['event'] in ['bounce', 'dropped']:
            email = event['email']
            await redis.sadd('bounced_emails', email)

            # Log for investigation
            logging.warning(f"Email bounced: {mask_email(email)}, reason: {event.get('reason')}")
```

### Complaint Handling (Spam Reports)

```python
# Unsubscribe on spam reports
for event in events:
    if event['event'] == 'spam_report':
        email = event['email']
        await redis.sadd('unsubscribed_emails', email)

        # Log for compliance
        logging.info(f"Email unsubscribed (spam): {mask_email(email)}")
```

### Check Before Sending

```python
async def send_email(to: str, ...):
    # Check if bounced
    is_bounced = await redis.sismember('bounced_emails', to)
    if is_bounced:
        raise ValueError("Email address has bounced")

    # Check if unsubscribed
    is_unsubscribed = await redis.sismember('unsubscribed_emails', to)
    if is_unsubscribed:
        raise ValueError("Email address has unsubscribed")

    # Send email
    ...
```

## Security Testing

### Run Security Tests

```bash
# Install dependencies
pip install pytest pytest-asyncio fakeredis

# Run all tests
pytest tests/test_security.py -v

# Run specific test category
pytest tests/test_security.py -v -k "TestEmailHeaderInjection"
pytest tests/test_security.py -v -k "TestXSSPrevention"
pytest tests/test_security.py -v -k "TestPathTraversalPrevention"
```

### Expected Results

All tests should **PASS**:

```
tests/test_security.py::TestEmailHeaderInjection::test_reject_crlf_in_to_address PASSED
tests/test_security.py::TestEmailHeaderInjection::test_reject_crlf_in_subject PASSED
tests/test_security.py::TestXSSPrevention::test_escape_script_tags PASSED
tests/test_security.py::TestXSSPrevention::test_escape_javascript_protocol PASSED
tests/test_security.py::TestPathTraversalPrevention::test_reject_parent_directory_traversal PASSED
...

================================== 39 passed in 2.5s ==================================
```

If any test **FAILS**, do NOT deploy to production.

## Production Security Checklist

Before deploying email system to production:

### Configuration
- [ ] All secrets in environment variables (not hardcoded)
- [ ] `.env` file in `.gitignore`
- [ ] Separate keys for dev/staging/production
- [ ] API keys rotated (< 90 days old)

### Email Provider
- [ ] Sender domain verified (not just email)
- [ ] SPF record configured
- [ ] DKIM keys configured
- [ ] DMARC policy configured
- [ ] Production access granted (not sandbox)
- [ ] Webhooks configured for bounces/complaints
- [ ] Webhook signatures verified

### Redis
- [ ] Redis authentication enabled
- [ ] Redis not exposed to public internet
- [ ] TLS enabled (production)
- [ ] Dangerous commands disabled
- [ ] Backup/persistence configured

### Security Tests
- [ ] All 39 security tests passing
- [ ] CRLF injection tests passing
- [ ] XSS prevention tests passing
- [ ] Path traversal tests passing
- [ ] No PII in logs verified

### Monitoring
- [ ] Email queue size alerts (> 1000)
- [ ] Failed email alerts (retry count = max)
- [ ] Bounce rate alerts (> 5%)
- [ ] Complaint rate alerts (> 0.1%)
- [ ] Provider API error alerts

### Rate Limiting
- [ ] Email sending rate limits enabled
- [ ] Per-user email limits (prevent abuse)
- [ ] Webhook rate limits configured
- [ ] Queue size limits enforced

### Logging
- [ ] No PII in logs (emails masked)
- [ ] No API keys in logs
- [ ] Message IDs logged (for debugging)
- [ ] Log retention policy configured

## Incident Response

### Bounce Rate Spike

**Symptoms**: Bounce rate > 5%

**Causes**:
1. Invalid email list
2. Domain reputation issue
3. Email content flagged as spam

**Response**:
1. Pause email sending immediately
2. Review recent bounce emails: `redis-cli SMEMBERS bounced_emails`
3. Check provider dashboard for details
4. Clean email list (remove invalid emails)
5. Review email content (spam keywords)
6. Contact provider support if needed

### Complaint Rate Spike

**Symptoms**: Complaint rate > 0.1%

**Causes**:
1. Sending to unsubscribed users
2. No unsubscribe link
3. Misleading subject lines

**Response**:
1. Pause email sending immediately
2. Review complaint emails: `redis-cli SMEMBERS unsubscribed_emails`
3. Audit unsubscribe process
4. Review email content and subject lines
5. Implement double opt-in for new subscribers

### API Key Leaked

**Symptoms**: API key found in public repository

**Response**:
1. **IMMEDIATELY** revoke API key in provider dashboard
2. Generate new API key
3. Update environment variables in all environments
4. Rotate database credentials (if exposed)
5. Review git history: `git log -p | grep -i "sendgrid_api_key"`
6. Use tools like GitGuardian or TruffleHog
7. Report to security team

### Redis Breach

**Symptoms**: Unauthorized access to Redis

**Response**:
1. Immediately flush Redis: `redis-cli FLUSHALL` (if compromised)
2. Change Redis password
3. Review Redis logs for unauthorized access
4. Enable Redis ACL (fine-grained permissions)
5. Move Redis to private network
6. Enable TLS
7. Audit all email data for exposure

## Compliance

### GDPR (EU)

- **Right to Access**: Provide email history on request
- **Right to Delete**: Remove email addresses from all lists
- **Right to Opt-Out**: Honor unsubscribe requests immediately

**Implementation**:

```python
# Delete user data (GDPR)
async def delete_user_email_data(email: str):
    # Remove from all lists
    await redis.srem('bounced_emails', email)
    await redis.srem('unsubscribed_emails', email)

    # Delete email history (if stored)
    # ... implementation depends on your storage
```

### CAN-SPAM (US)

- **Unsubscribe Link**: Include in all marketing emails
- **Physical Address**: Include in email footer
- **Accurate Headers**: Don't spoof from/subject fields
- **Honor Opt-Outs**: Process within 10 business days

**Implementation**:

```html
<!-- Include in all marketing emails -->
<footer>
  <p>{{ company_name }}, {{ physical_address }}</p>
  <p><a href="{{ unsubscribe_link }}">Unsubscribe</a></p>
</footer>
```

## Help

- **Security Tests**: `tests/test_security.py`
- **Documentation**: `.claude/skills/email-universal/SKILL.md`
- **Quick Start**: `playbooks/QUICK-START.md`
- **OWASP Top 10**: https://owasp.org/Top10/

**Emergency Contact**: security@yourdomain.com

Deploy safely!
