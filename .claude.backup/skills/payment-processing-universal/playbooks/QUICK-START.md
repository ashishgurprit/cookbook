# Payment Processing - Quick Start Guide

Get payment processing working in 20 minutes.

## Prerequisites

- Python 3.9+ or Node.js 16+
- Redis running
- Payment provider account (Stripe or PayPal)

## Step 1: Choose Your Provider (3 minutes)

### Option A: Stripe (Recommended)

**Best For**: Modern payments, subscriptions, best developer experience

1. **Sign up**: https://dashboard.stripe.com/register
2. **Get API keys**: Dashboard → Developers → API Keys
3. **Get test keys**:
   - Publishable key: `pk_test_...`
   - Secret key: `sk_test_...`

**Cost**: 2.9% + $0.30 per transaction

### Option B: PayPal

**Best For**: Customer trust, global reach

1. **Sign up**: https://www.paypal.com/businessmanage/
2. **Create app**: Developer → My Apps & Credentials
3. **Get sandbox credentials**:
   - Client ID: `<sandbox_client_id>`
   - Client Secret: `<sandbox_secret>`

**Cost**: 3.49% + $0.49 per transaction

## Step 2: Install Dependencies (2 minutes)

### Python (FastAPI)

```bash
pip install fastapi uvicorn stripe paypalrestsdk redis pydantic
```

### Redis

```bash
# macOS
brew install redis
brew services start redis

# Ubuntu
sudo apt install redis-server
sudo systemctl start redis

# Docker
docker run -d -p 6379:6379 redis:7-alpine
```

## Step 3: Configure Environment (3 minutes)

Create `.env` file:

```bash
# Stripe (primary)
STRIPE_PUBLISHABLE_KEY=pk_test_your_publishable_key_here
STRIPE_SECRET_KEY=sk_test_your_secret_key_here
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret  # Get from webhook setup

# PayPal (fallback - optional)
PAYPAL_CLIENT_ID=your_paypal_client_id
PAYPAL_CLIENT_SECRET=your_paypal_client_secret
PAYPAL_MODE=sandbox  # or 'live' for production

# Redis
REDIS_URL=redis://localhost:6379

# App
APP_URL=https://localhost:3000  # Or your domain
PAYMENT_CURRENCY=usd
```

**Security**: Add `.env` to `.gitignore`!

## Step 4: Copy Payment Service (2 minutes)

```bash
# Copy FastAPI payment service
cp .claude/skills/payment-processing-universal/templates/backend/fastapi-payment.py ./app/payment_service.py
```

## Step 5: Integrate into Your App (5 minutes)

### FastAPI Example

```python
from fastapi import FastAPI
from app.payment_service import PaymentService, PaymentProvider
import os

app = FastAPI()

# Initialize payment service
payment_service = PaymentService(
    redis_url=os.environ.get('REDIS_URL')
)

@app.on_event("startup")
async def startup():
    await payment_service.initialize()
    print("[PAYMENT] Payment service initialized")

@app.on_event("shutdown")
async def shutdown():
    await payment_service.close()

# Create payment endpoint
@app.post("/api/payment/create")
async def create_payment(amount: int, currency: str = "usd"):
    """Create payment intent"""
    result = await payment_service.create_payment(
        amount=amount,
        currency=currency,
        provider=PaymentProvider.STRIPE,
        metadata={'order_id': '12345'}
    )
    return result

# Stripe webhook endpoint
@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhooks"""
    from app.payment_service import handle_stripe_webhook
    return await handle_stripe_webhook(request, payment_service)
```

### Frontend Integration (Stripe Elements)

```html
<!DOCTYPE html>
<html>
<head>
  <script src="https://js.stripe.com/v3/"></script>
</head>
<body>
  <form id="payment-form">
    <div id="card-element"></div>
    <button type="submit">Pay $10.00</button>
    <div id="error-message"></div>
  </form>

  <script>
    const stripe = Stripe('pk_test_your_publishable_key');
    const elements = stripe.elements();
    const cardElement = elements.create('card');
    cardElement.mount('#card-element');

    document.getElementById('payment-form').addEventListener('submit', async (e) => {
      e.preventDefault();

      // 1. Create payment intent (backend)
      const response = await fetch('/api/payment/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({amount: 1000, currency: 'usd'})  // $10.00
      });
      const {client_secret} = await response.json();

      // 2. Confirm payment (Stripe handles card)
      const {error, paymentIntent} = await stripe.confirmCardPayment(client_secret, {
        payment_method: {card: cardElement}
      });

      if (error) {
        document.getElementById('error-message').textContent = error.message;
      } else {
        alert('Payment successful!');
      }
    });
  </script>
</body>
</html>
```

## Step 6: Set Up Webhooks (3 minutes)

### Stripe Webhooks

1. **Stripe Dashboard** → Developers → Webhooks → Add Endpoint
2. **Endpoint URL**: `https://yourdomain.com/webhooks/stripe`
3. **Events to send**: Select these:
   - `payment_intent.succeeded`
   - `payment_intent.payment_failed`
   - `invoice.payment_succeeded` (for subscriptions)
4. **Copy webhook secret** to `STRIPE_WEBHOOK_SECRET`

### Test Webhooks Locally

```bash
# Install Stripe CLI
brew install stripe/stripe-cli/stripe

# Forward webhooks to localhost
stripe listen --forward-to localhost:8000/webhooks/stripe

# Trigger test events
stripe trigger payment_intent.succeeded
```

## Step 7: Test Payment Flow (5 minutes)

### Test Cards (Stripe)

```
Success:
4242 4242 4242 4242  (Visa)

Decline:
4000 0000 0000 0002  (Card declined)

3D Secure Required:
4000 0027 6000 3184  (Requires authentication)

# Use any future expiry date, any 3-digit CVC
```

### Test Payment

```bash
# Create payment
curl -X POST http://localhost:8000/api/payment/create \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 1000,
    "currency": "usd"
  }'

# Response:
{
  "payment_intent_id": "pi_abc123",
  "client_secret": "pi_abc123_secret_xyz",
  "status": "requires_payment_method"
}
```

### Test Refund

```bash
curl -X POST http://localhost:8000/api/payment/refund \
  -H "Content-Type: application/json" \
  -d '{
    "payment_id": "pi_abc123",
    "reason": "requested_by_customer"
  }'
```

## Common Issues

### Issue 1: "No such payment_intent"

**Cause**: Using wrong API key (test vs live)

**Solution**:
- Check you're using test key (`sk_test_...`)
- Verify payment intent was created successfully

### Issue 2: "Webhook signature verification failed"

**Cause**: Wrong webhook secret or payload modified

**Solution**:
- Verify `STRIPE_WEBHOOK_SECRET` is correct
- Check you're using raw request body (not parsed JSON)
- Test with Stripe CLI: `stripe listen --forward-to localhost:8000/webhooks/stripe`

### Issue 3: "Payment requires authentication"

**Cause**: 3D Secure required (EU regulation)

**Solution**:
- Use Stripe Payment Intents API (handles 3DS automatically)
- Customer will see authentication popup
- This is normal for EU customers

## Production Checklist

Before deploying to production:

**Provider Setup**:
- [ ] Activate live mode on Stripe/PayPal
- [ ] Use live API keys (`pk_live_...`, `sk_live_...`)
- [ ] Set up production webhooks
- [ ] Configure SPF/DKIM for email receipts

**Security**:
- [ ] All payment pages use HTTPS
- [ ] Environment variables configured (no hardcoded keys)
- [ ] Webhook signature verification enabled
- [ ] Security tests passing (`pytest tests/test_security.py`)
- [ ] API keys rotated if exposed
- [ ] `.env` in `.gitignore`

**PCI Compliance**:
- [ ] Complete SAQ-A questionnaire
- [ ] NEVER accept card numbers in API
- [ ] NEVER log card numbers
- [ ] Use provider SDKs only (Stripe Elements, PayPal SDK)

**Testing**:
- [ ] Test successful payment flow
- [ ] Test declined payment
- [ ] Test 3D Secure flow
- [ ] Test refund flow
- [ ] Test webhook handling
- [ ] Test idempotency (duplicate requests)

**Monitoring**:
- [ ] Set up alerts for failed payments
- [ ] Monitor webhook delivery
- [ ] Track payment success rate
- [ ] Monitor fraud rate

## Next Steps

1. **Review PCI Compliance**: See `playbooks/PCI-COMPLIANCE.md`
2. **Run security tests**: `pytest tests/test_security.py -v`
3. **Set up subscriptions**: See SKILL.md for subscription guide
4. **Configure fraud prevention**: Enable Stripe Radar
5. **Set up monitoring**: Track payment metrics

## Resources

- **Stripe Docs**: https://stripe.com/docs
- **PayPal Docs**: https://developer.paypal.com/docs
- **PCI Compliance**: `playbooks/PCI-COMPLIANCE.md`
- **Security Tests**: `tests/test_security.py`
- **Full Guide**: `SKILL.md`

## Help

**Stripe Support**: https://support.stripe.com/
**PayPal Support**: https://www.paypal.com/us/smarthelp/contact-us

**Common Questions**:
- Test cards: https://stripe.com/docs/testing
- Webhook testing: Use Stripe CLI
- PCI compliance: We achieve SAQ-A (simplest level)

You're ready to accept payments securely!
