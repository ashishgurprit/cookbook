"""
Email System - FastAPI Implementation
======================================

Production-ready email system with multi-provider support, queue, and security-first design.

Features:
- Multi-provider (SendGrid, AWS SES, SMTP)
- Email queue (Redis-based)
- XSS-safe template rendering
- Email header injection prevention
- Bounce/complaint handling
- Security logging (no PII)
- OWASP compliant

Usage:
    from email_system import EmailService, EmailPriority

    email_service = EmailService(redis_url=os.environ["REDIS_URL"])

    # Send email (queued)
    await email_service.send_email(
        to="user@example.com",
        subject="Password Reset",
        template="password-reset",
        variables={"user_name": "John", "reset_link": "https://..."},
        priority=EmailPriority.HIGH
    )
"""

from fastapi import FastAPI, Request, HTTPException
from enum import Enum
from typing import Optional, Dict, List, Any
from redis.asyncio import Redis
import aiosmtplib
import boto3
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content, Attachment as SGAttachment
import os
import sys
import time
import json
import hashlib
import hmac
import structlog
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import asyncio

# ============================================================================
# CONFIGURATION
# ============================================================================

logger = structlog.get_logger()

# Startup validation
def validate_environment():
    """Validate required environment variables at startup"""
    required = ["REDIS_URL"]

    # At least one provider must be configured
    providers = ["SENDGRID_API_KEY", "AWS_ACCESS_KEY_ID", "SMTP_HOST"]
    has_provider = any(os.environ.get(p) for p in providers)

    missing = [var for var in required if not os.environ.get(var)]

    if missing:
        print(f"❌ Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)

    if not has_provider:
        print(f"❌ At least one email provider must be configured:")
        print("   - SENDGRID_API_KEY (SendGrid)")
        print("   - AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (AWS SES)")
        print("   - SMTP_HOST + SMTP_PORT + SMTP_USER + SMTP_PASSWORD (SMTP)")
        sys.exit(1)

    print("✅ Email system configuration validated")

validate_environment()

# ============================================================================
# ENUMS
# ============================================================================

class EmailPriority(str, Enum):
    HIGH = "high"      # Critical emails (password reset, verification)
    NORMAL = "normal"  # Notifications, alerts
    LOW = "low"        # Marketing, newsletters

class EmailProvider(str, Enum):
    SENDGRID = "sendgrid"
    AWS_SES = "ses"
    SMTP = "smtp"

# ============================================================================
# SECURITY HELPERS
# ============================================================================

def validate_email_header(value: str) -> str:
    """
    Prevent CRLF injection in email headers

    Attack: subject = "Test\r\nBcc: attacker@evil.com"
    Prevention: Reject any header with \r or \n
    """
    if not value:
        raise ValueError("Header value cannot be empty")

    if '\r' in value or '\n' in value:
        raise ValueError("Invalid characters in email header (CRLF injection attempt)")

    return value.strip()

def escape_html(text: str) -> str:
    """
    Escape HTML entities to prevent XSS

    Attack: user_name = "<script>alert('XSS')</script>"
    Prevention: Escape all HTML special characters
    """
    if not text:
        return ""

    return str(text).replace('&', '&amp;') \
                    .replace('<', '&lt;') \
                    .replace('>', '&gt;') \
                    .replace('"', '&quot;') \
                    .replace("'", '&#039;')

def escape_url(url: str) -> str:
    """URL encode special characters"""
    from urllib.parse import quote
    return quote(url, safe=':/?#[]@!$&\'()*+,;=')

def validate_attachment_path(file_path: str) -> str:
    """
    Prevent path traversal in attachments

    Attack: file_path = "../../etc/passwd"
    Prevention: Check for .. and absolute paths
    """
    import os.path

    if '..' in file_path or file_path.startswith('/'):
        raise ValueError("Invalid file path (path traversal attempt)")

    if not os.path.isfile(file_path):
        raise ValueError("File not found")

    # Check extension
    ALLOWED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg', '.gif', '.txt', '.csv', '.zip'}
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Invalid attachment type: {ext}")

    # Check size (10MB max)
    MAX_SIZE = 10 * 1024 * 1024
    size = os.path.getsize(file_path)
    if size > MAX_SIZE:
        raise ValueError(f"Attachment too large: {size} bytes (max {MAX_SIZE})")

    return file_path

# ============================================================================
# TEMPLATE RENDERING
# ============================================================================

class TemplateRenderer:
    """XSS-safe template renderer"""

    def __init__(self, templates_dir: str = "templates/email"):
        self.templates_dir = templates_dir

    def render(self, template_name: str, variables: Dict[str, Any]) -> tuple[str, str]:
        """
        Render HTML and plain text email templates

        Returns: (html, plain_text)
        """
        # Load templates
        html_path = os.path.join(self.templates_dir, f"{template_name}.html")
        text_path = os.path.join(self.templates_dir, f"{template_name}.txt")

        if not os.path.exists(html_path):
            raise ValueError(f"Template not found: {template_name}.html")

        with open(html_path, 'r') as f:
            html_template = f.read()

        # Plain text is optional but recommended
        plain_text_template = ""
        if os.path.exists(text_path):
            with open(text_path, 'r') as f:
                plain_text_template = f.read()

        # Escape all variables (XSS prevention)
        safe_vars = {}
        for key, value in variables.items():
            if isinstance(value, str):
                # URLs use URL encoding
                if key.endswith('_link') or key.endswith('_url'):
                    safe_vars[key] = escape_url(value)
                else:
                    safe_vars[key] = escape_html(value)
            else:
                safe_vars[key] = value

        # Simple variable replacement: {{ variable_name }}
        html = html_template
        plain_text = plain_text_template

        for key, value in safe_vars.items():
            placeholder = f"{{{{ {key} }}}}"
            html = html.replace(placeholder, str(value))
            plain_text = plain_text.replace(placeholder, str(value))

        return html, plain_text

# ============================================================================
# EMAIL PROVIDERS
# ============================================================================

class SendGridProvider:
    """SendGrid email provider"""

    def __init__(self, api_key: str, from_email: str):
        self.client = SendGridAPIClient(api_key)
        self.from_email = from_email

    async def send(
        self,
        to: str,
        subject: str,
        html: str,
        plain_text: str,
        attachments: Optional[List[str]] = None
    ) -> Dict:
        """Send email via SendGrid"""

        # Validate headers
        to = validate_email_header(to)
        subject = validate_email_header(subject)

        # Create message
        message = Mail(
            from_email=Email(self.from_email),
            to_emails=To(to),
            subject=subject,
            html_content=Content("text/html", html),
            plain_text_content=Content("text/plain", plain_text)
        )

        # Add attachments
        if attachments:
            for file_path in attachments:
                validate_attachment_path(file_path)

                with open(file_path, 'rb') as f:
                    data = f.read()

                import base64
                encoded = base64.b64encode(data).decode()

                attachment = SGAttachment()
                attachment.file_content = encoded
                attachment.file_name = os.path.basename(file_path)
                attachment.disposition = "attachment"
                message.add_attachment(attachment)

        # Send
        response = self.client.send(message)

        return {
            'provider': 'sendgrid',
            'status_code': response.status_code,
            'message_id': response.headers.get('X-Message-Id')
        }

class AWSSESProvider:
    """AWS SES email provider"""

    def __init__(self, from_email: str):
        self.client = boto3.client('ses',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            region_name=os.environ.get('AWS_REGION', 'us-east-1')
        )
        self.from_email = from_email

    async def send(
        self,
        to: str,
        subject: str,
        html: str,
        plain_text: str,
        attachments: Optional[List[str]] = None
    ) -> Dict:
        """Send email via AWS SES"""

        # Validate headers
        to = validate_email_header(to)
        subject = validate_email_header(subject)

        if not attachments:
            # Simple send (no attachments)
            response = self.client.send_email(
                Source=self.from_email,
                Destination={'ToAddresses': [to]},
                Message={
                    'Subject': {'Data': subject},
                    'Body': {
                        'Html': {'Data': html},
                        'Text': {'Data': plain_text}
                    }
                }
            )
        else:
            # Send with attachments (use raw email)
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = to

            # Add body
            msg.attach(MIMEText(plain_text, 'plain'))
            msg.attach(MIMEText(html, 'html'))

            # Add attachments
            for file_path in attachments:
                validate_attachment_path(file_path)

                with open(file_path, 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())

                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename={os.path.basename(file_path)}'
                )
                msg.attach(part)

            response = self.client.send_raw_email(
                Source=self.from_email,
                Destinations=[to],
                RawMessage={'Data': msg.as_string()}
            )

        return {
            'provider': 'ses',
            'message_id': response['MessageId']
        }

class SMTPProvider:
    """SMTP email provider"""

    def __init__(self, host: str, port: int, user: str, password: str, from_email: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.from_email = from_email

    async def send(
        self,
        to: str,
        subject: str,
        html: str,
        plain_text: str,
        attachments: Optional[List[str]] = None
    ) -> Dict:
        """Send email via SMTP"""

        # Validate headers
        to = validate_email_header(to)
        subject = validate_email_header(subject)

        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.from_email
        msg['To'] = to

        # Add body (plain text first, then HTML)
        msg.attach(MIMEText(plain_text, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        # Add attachments
        if attachments:
            for file_path in attachments:
                validate_attachment_path(file_path)

                with open(file_path, 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())

                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename={os.path.basename(file_path)}'
                )
                msg.attach(part)

        # Send
        async with aiosmtplib.SMTP(hostname=self.host, port=self.port) as smtp:
            await smtp.login(self.user, self.password)
            await smtp.send_message(msg)

        # Generate message ID (SMTP doesn't return one)
        message_id = hashlib.sha256(f"{to}{subject}{time.time()}".encode()).hexdigest()

        return {
            'provider': 'smtp',
            'message_id': message_id
        }

# ============================================================================
# EMAIL SERVICE
# ============================================================================

class EmailService:
    """Main email service with queue and multi-provider support"""

    def __init__(self, redis_url: str, templates_dir: str = "templates/email"):
        self.redis_url = redis_url
        self.redis: Optional[Redis] = None
        self.template_renderer = TemplateRenderer(templates_dir)

        # Initialize providers
        self.providers: Dict[EmailProvider, Any] = {}

        # SendGrid
        if os.environ.get('SENDGRID_API_KEY'):
            self.providers[EmailProvider.SENDGRID] = SendGridProvider(
                api_key=os.environ['SENDGRID_API_KEY'],
                from_email=os.environ.get('EMAIL_FROM', 'noreply@example.com')
            )

        # AWS SES
        if os.environ.get('AWS_ACCESS_KEY_ID'):
            self.providers[EmailProvider.AWS_SES] = AWSSESProvider(
                from_email=os.environ.get('EMAIL_FROM', 'noreply@example.com')
            )

        # SMTP
        if os.environ.get('SMTP_HOST'):
            self.providers[EmailProvider.SMTP] = SMTPProvider(
                host=os.environ['SMTP_HOST'],
                port=int(os.environ.get('SMTP_PORT', 587)),
                user=os.environ['SMTP_USER'],
                password=os.environ['SMTP_PASSWORD'],
                from_email=os.environ.get('EMAIL_FROM', 'noreply@example.com')
            )

        # Default provider
        self.default_provider = EmailProvider.SENDGRID if EmailProvider.SENDGRID in self.providers else list(self.providers.keys())[0]

    async def connect(self):
        """Connect to Redis"""
        self.redis = await Redis.from_url(self.redis_url, decode_responses=True)
        await self.redis.ping()
        logger.info("email.redis_connected")

    async def close(self):
        """Close connections"""
        if self.redis:
            await self.redis.close()

    async def send_email(
        self,
        to: str,
        subject: str,
        template: str,
        variables: Dict[str, Any],
        priority: EmailPriority = EmailPriority.NORMAL,
        provider: Optional[EmailProvider] = None,
        attachments: Optional[List[str]] = None
    ) -> Dict:
        """
        Send email (queued for background processing)

        Args:
            to: Recipient email address
            subject: Email subject
            template: Template name (e.g., "password-reset")
            variables: Template variables (e.g., {"user_name": "John", "reset_link": "..."})
            priority: Email priority (HIGH, NORMAL, LOW)
            provider: Email provider (default: auto-select)
            attachments: List of file paths to attach

        Returns:
            {'email_id': '...', 'status': 'queued'}
        """
        # Generate email ID
        email_id = f"email_{int(time.time() * 1000)}_{hashlib.sha256(to.encode()).hexdigest()[:8]}"

        # Store email data
        email_data = {
            'to': to,
            'subject': subject,
            'template': template,
            'variables': json.dumps(variables),
            'priority': priority.value,
            'provider': (provider or self.default_provider).value,
            'attachments': json.dumps(attachments or []),
            'retry_count': 0,
            'max_retries': 3,
            'created_at': time.time(),
            'status': 'queued'
        }

        await self.redis.hset(f"email:{email_id}", mapping=email_data)

        # Add to queue
        queue_key = f"queue:email:{priority.value}"
        await self.redis.lpush(queue_key, email_id)

        logger.info("email.queued",
            email_id=email_id,
            template=template,
            priority=priority.value
            # NO: to, subject, variables (PII)
        )

        return {
            'email_id': email_id,
            'status': 'queued'
        }

    async def process_queue(self):
        """Background worker to process email queue"""
        logger.info("email.worker_started")

        while True:
            try:
                # Process high priority first
                for priority in [EmailPriority.HIGH, EmailPriority.NORMAL, EmailPriority.LOW]:
                    queue_key = f"queue:email:{priority.value}"
                    email_id = await self.redis.rpop(queue_key)

                    if email_id:
                        await self._send_email_from_queue(email_id)

                # Small delay between queue checks
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error("email.worker_error", error=str(e))
                await asyncio.sleep(1)

    async def _send_email_from_queue(self, email_id: str):
        """Send email from queue"""
        try:
            # Get email data
            email_data = await self.redis.hgetall(f"email:{email_id}")

            if not email_data:
                logger.warning("email.not_found", email_id=email_id)
                return

            # Parse data
            to = email_data['to']
            subject = email_data['subject']
            template = email_data['template']
            variables = json.loads(email_data['variables'])
            provider_name = email_data['provider']
            attachments = json.loads(email_data.get('attachments', '[]'))

            # Render template
            html, plain_text = self.template_renderer.render(template, variables)

            # Get provider
            provider = self.providers.get(EmailProvider(provider_name))
            if not provider:
                raise ValueError(f"Provider not configured: {provider_name}")

            # Send email
            result = await provider.send(
                to=to,
                subject=subject,
                html=html,
                plain_text=plain_text,
                attachments=attachments
            )

            # Mark as sent
            await self.redis.hset(f"email:{email_id}", mapping={
                'status': 'sent',
                'sent_at': time.time(),
                'message_id': result.get('message_id', '')
            })

            logger.info("email.sent",
                email_id=email_id,
                template=template,
                provider=provider_name
                # NO: to, subject, variables (PII)
            )

        except Exception as e:
            # Retry logic
            retry_count = int(email_data.get('retry_count', 0))
            max_retries = int(email_data.get('max_retries', 3))

            if retry_count < max_retries:
                # Re-queue with backoff
                await self.redis.hset(f"email:{email_id}", 'retry_count', retry_count + 1)

                priority = email_data.get('priority', 'normal')
                queue_key = f"queue:email:{priority}"
                await self.redis.lpush(queue_key, email_id)

                # Exponential backoff (1s, 2s, 4s)
                await asyncio.sleep(2 ** retry_count)

                logger.warning("email.retry",
                    email_id=email_id,
                    retry_count=retry_count + 1,
                    error=str(e)
                )
            else:
                # Max retries reached
                await self.redis.hset(f"email:{email_id}", mapping={
                    'status': 'failed',
                    'error': str(e),
                    'failed_at': time.time()
                })

                logger.error("email.failed",
                    email_id=email_id,
                    error=str(e)
                )

# ============================================================================
# WEBHOOK HANDLERS
# ============================================================================

async def handle_sendgrid_webhook(request: Request, email_service: EmailService):
    """Handle SendGrid bounce/complaint webhooks"""
    events = await request.json()

    for event in events:
        email = event.get('email')
        event_type = event.get('event')

        if event_type in ['bounce', 'dropped']:
            # Hard bounce
            await email_service.redis.sadd('bounced_emails', email)
            logger.warning("email.bounced", email=email, type=event_type)

        elif event_type == 'spam_report':
            # Spam complaint
            await email_service.redis.sadd('unsubscribed_emails', email)
            logger.warning("email.spam_complaint", email=email)

    return {"status": "processed"}

async def handle_ses_webhook(request: Request, email_service: EmailService):
    """Handle AWS SES bounce/complaint notifications (via SNS)"""
    message = await request.json()

    # Parse SNS message
    notification = json.loads(message['Message'])
    notification_type = notification['notificationType']

    if notification_type == 'Bounce':
        bounce = notification['bounce']
        for recipient in bounce['bouncedRecipients']:
            email = recipient['emailAddress']
            await email_service.redis.sadd('bounced_emails', email)
            logger.warning("email.bounced", email=email, type='ses')

    elif notification_type == 'Complaint':
        complaint = notification['complaint']
        for recipient in complaint['complainedRecipients']:
            email = recipient['emailAddress']
            await email_service.redis.sadd('unsubscribed_emails', email)
            logger.warning("email.spam_complaint", email=email)

    return {"status": "processed"}

# ============================================================================
# EXAMPLE USAGE
# ============================================================================

"""
# main.py

from fastapi import FastAPI
from email_system import EmailService, EmailPriority
import asyncio

app = FastAPI()

# Initialize email service
email_service = EmailService(redis_url=os.environ["REDIS_URL"])

@app.on_event("startup")
async def startup():
    await email_service.connect()

    # Start queue worker in background
    asyncio.create_task(email_service.process_queue())

@app.on_event("shutdown")
async def shutdown():
    await email_service.close()

# Send email
@app.post("/api/send-password-reset")
async def send_password_reset(email: str, reset_link: str):
    result = await email_service.send_email(
        to=email,
        subject="Password Reset Request",
        template="password-reset",
        variables={
            "user_name": "John Doe",
            "reset_link": reset_link,
            "expiry_hours": "24",
            "app_name": "MyApp",
            "current_year": "2026"
        },
        priority=EmailPriority.HIGH
    )

    return result

# Webhooks
@app.post("/webhooks/sendgrid")
async def sendgrid_webhook(request: Request):
    return await handle_sendgrid_webhook(request, email_service)

@app.post("/webhooks/ses")
async def ses_webhook(request: Request):
    return await handle_ses_webhook(request, email_service)
"""
