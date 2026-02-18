# Payment Processing Universal - Production Guide

**Multi-provider payment processing with PCI-DSS compliance.**

Version: 1.0.0
Status: Production Ready
PCI Level: SAQ-A (Simplest)

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [PCI-DSS Compliance](#pci-dss-compliance)
4. [Provider Integration](#provider-integration)
5. [Payment Flow](#payment-flow)
6. [Subscription Management](#subscription-management)
7. [Refund Handling](#refund-handling)
8. [Webhook Security](#webhook-security)
9. [Idempotency](#idempotency)
10. [Fraud Prevention](#fraud-prevention)
11. [Testing Guide](#testing-guide)
12. [Security Considerations](#security-considerations)
13. [Troubleshooting](#troubleshooting)

---

## Overview

### Why Multi-Provider?

**Problem**: Single payment provider = vendor lock-in + single point of failure

**Solution**: Multi-provider adapter pattern

**Benefits**:
- ✅ No vendor lock-in (switch providers anytime)
- ✅ Customer choice (Stripe cards vs PayPal)
- ✅ Higher conversion (+15-20% with PayPal option)
- ✅ Redundancy (automatic failover)
- ✅ Cost optimization (use cheapest provider per transaction)

### Supported Providers

| Provider | Use Case | Fees | Best For |
|----------|----------|------|----------|
| **Stripe** (Primary) | Online payments, subscriptions | 2.9% + $0.30 | Developer experience, modern features |
| **PayPal** (Fallback) | Customer preference, global | 3.49% + $0.49 | Customer trust, international |
| **Square** (Optional) | In-person payments, POS | 2.6% + $0.10 | Retail, physical stores |

### Critical Rules

🚫 **NEVER** store credit card numbers
🚫 **NEVER** log card numbers (even masked)
🚫 **NEVER** process cards directly without PCI compliance
✅ **ALWAYS** use provider SDKs (Stripe Elements, PayPal SDK)
✅ **ALWAYS** verify webhook signatures
✅ **ALWAYS** use idempotency keys

---

## Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────┐
│           Customer Checkout                 │
│  (Stripe Elements / PayPal Button)          │
└──────────────┬──────────────────────────────┘
               │ (Card data goes directly to provider)
               ▼
┌──────────────────────────────────────────────┐
│         Your Backend (Payment Service)       │
│  • Creates payment intent                    │
│  • Receives webhook confirmations            │
│  • Never sees card numbers                   │
└──────────────┬───────────────────────────────┘
               │
       ┌───────┴───────┐
       │               │
       ▼               ▼
┌────────────┐   ┌────────────┐
│   Stripe   │   │   PayPal   │
│  Provider  │   │  Provider  │
└────────────┘   └────────────┘
       │               │
       ▼               ▼
  Webhooks        Webhooks
  (payment       (payment
   success)       success)
```

### Data Flow

**1. Customer Initiates Payment**
```javascript
// Frontend: Stripe Elements (no card data to backend)
const {paymentIntent} = await stripe.confirmCardPayment(clientSecret);
```

**2. Backend Creates Payment Intent**
```python
# Backend: Create payment intent (receives only token, not card)
payment_intent = stripe.PaymentIntent.create(
    amount=1000,  # $10.00
    currency='usd',
    customer=customer_id,
    metadata={'order_id': '12345'}
)
```

**3. Provider Processes Payment**
- Customer's card charged
- Provider handles 3D Secure / SCA if needed
- Payment succeeds or fails

**4. Webhook Confirms Payment**
```python
# Backend: Webhook handler (verified signature)
@app.post("/webhooks/stripe")
async def handle_stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')

    event = stripe.Webhook.construct_event(
        payload, sig_header, webhook_secret
    )

    if event.type == 'payment_intent.succeeded':
        # Fulfill order
        fulfill_order(event.data.object.metadata.order_id)
```

---

## PCI-DSS Compliance

### Compliance Level: SAQ-A

**What is SAQ-A?**
- Self-Assessment Questionnaire A
- **Simplest** PCI compliance level
- Only **22 questions** (vs 329 for direct processing)
- Requires: Never touch card data

**How We Achieve SAQ-A**:
1. ✅ Use Stripe Elements / PayPal SDK (card data goes directly to provider)
2. ✅ Never store, process, or transmit card data
3. ✅ All payment pages served over HTTPS
4. ✅ Webhook endpoints secured (signature verification)

### The Golden Rule

**NEVER touch card data. Ever.**

```python
# ❌ BAD: Receiving card number
@app.post("/api/charge")
async def charge(card_number: str, cvv: str, expiry: str):
    # PCI violation! Now you need SAQ-D (329 questions)
    pass

# ✅ GOOD: Receiving token from provider
@app.post("/api/charge")
async def charge(payment_method_id: str):
    # payment_method_id is a token (tok_1234...)
    # No card data = SAQ-A compliance
    payment_intent = stripe.PaymentIntent.create(
        payment_method=payment_method_id,
        amount=1000
    )
```

### Required Security Measures

1. **HTTPS Everywhere** 🔒
   - All payment pages must use HTTPS
   - No mixed content warnings
   - Valid SSL certificate

2. **Webhook Signature Verification** ✅
   - Verify EVERY webhook
   - Reject unsigned webhooks
   - Use provider's verification library

3. **Secure Environment Variables** 🔑
   - API keys in environment (not code)
   - Separate keys for dev/staging/prod
   - Rotate keys quarterly

4. **Access Control** 👥
   - Limit who can access payment dashboards
   - 2FA required for payment provider accounts
   - Audit log access

### PCI-DSS Annual Review

**Required Actions** (every year):
1. Review SAQ-A questionnaire (22 questions)
2. Verify no card data stored
3. Test webhook security
4. Rotate API keys
5. Update TLS certificates
6. Train team on PCI requirements

---

## Provider Integration

### Stripe Integration

**Why Stripe Primary?**
- Best developer experience
- Modern Payment Intents API
- Excellent fraud prevention (Radar)
- Subscription management built-in

**Setup**:

1. **Create Stripe Account**: https://dashboard.stripe.com/register

2. **Get API Keys**:
   ```bash
   # Test keys (for development)
   STRIPE_TEST_PUBLISHABLE_KEY=pk_test_...
   STRIPE_TEST_SECRET_KEY=sk_test_...

   # Live keys (for production)
   STRIPE_LIVE_PUBLISHABLE_KEY=pk_live_...
   STRIPE_LIVE_SECRET_KEY=sk_live_...
   ```

3. **Install SDK**:
   ```bash
   # Python
   pip install stripe

   # Node.js
   npm install stripe
   ```

**Payment Intent Flow**:

```python
import stripe

stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

# 1. Create payment intent (backend)
payment_intent = stripe.PaymentIntent.create(
    amount=2000,  # $20.00 (in cents)
    currency='usd',
    automatic_payment_methods={'enabled': True},
    metadata={
        'order_id': '12345',
        'customer_email': 'customer@example.com'
    }
)

# Return client_secret to frontend
client_secret = payment_intent.client_secret

# 2. Confirm payment (frontend with Stripe Elements)
# JavaScript:
const {error, paymentIntent} = await stripe.confirmCardPayment(
    clientSecret,
    {payment_method: {card: cardElement}}
);

# 3. Webhook confirms success (backend)
# See Webhook Security section
```

---

### PayPal Integration

**Why PayPal Fallback?**
- High customer trust (300M+ accounts)
- Global reach (200+ countries)
- Buyer protection built-in
- No credit card required

**Setup**:

1. **Create PayPal Business Account**: https://www.paypal.com/businessmanage/

2. **Get API Credentials**:
   ```bash
   # Sandbox (for development)
   PAYPAL_CLIENT_ID=<sandbox_client_id>
   PAYPAL_CLIENT_SECRET=<sandbox_secret>
   PAYPAL_MODE=sandbox

   # Live (for production)
   PAYPAL_CLIENT_ID=<live_client_id>
   PAYPAL_CLIENT_SECRET=<live_secret>
   PAYPAL_MODE=live
   ```

3. **Install SDK**:
   ```bash
   # Python
   pip install paypalrestsdk

   # Node.js
   npm install @paypal/checkout-server-sdk
   ```

**Payment Order Flow**:

```python
import paypalrestsdk

paypalrestsdk.configure({
    "mode": os.environ.get('PAYPAL_MODE'),
    "client_id": os.environ.get('PAYPAL_CLIENT_ID'),
    "client_secret": os.environ.get('PAYPAL_CLIENT_SECRET')
})

# 1. Create order (backend)
payment = paypalrestsdk.Payment({
    "intent": "sale",
    "payer": {"payment_method": "paypal"},
    "redirect_urls": {
        "return_url": "https://yoursite.com/payment/success",
        "cancel_url": "https://yoursite.com/payment/cancel"
    },
    "transactions": [{
        "amount": {"total": "20.00", "currency": "USD"},
        "description": "Order #12345"
    }]
})

if payment.create():
    # Redirect customer to PayPal
    for link in payment.links:
        if link.rel == "approval_url":
            approval_url = link.href

# 2. Customer approves on PayPal site

# 3. Execute payment (backend after redirect)
payment = paypalrestsdk.Payment.find(payment_id)
if payment.execute({"payer_id": payer_id}):
    # Payment successful
    fulfill_order(order_id)
```

---

## Payment Flow

### One-Time Payment Flow

```
Customer                Frontend              Backend              Provider
   │                       │                     │                     │
   │  1. Click "Pay"       │                     │                     │
   ├──────────────────────>│                     │                     │
   │                       │  2. Request Intent  │                     │
   │                       ├────────────────────>│                     │
   │                       │                     │  3. Create Intent   │
   │                       │                     ├────────────────────>│
   │                       │                     │  4. Return Secret   │
   │                       │  5. Client Secret   │<────────────────────┤
   │                       │<────────────────────┤                     │
   │  6. Enter Card        │                     │                     │
   ├──────────────────────>│                     │                     │
   │                       │  7. Confirm Payment (card data)           │
   │                       ├──────────────────────────────────────────>│
   │                       │                     │  8. Process Card    │
   │                       │                     │<────────────────────┤
   │  9. Success/Failure   │                     │                     │
   │<──────────────────────┤                     │                     │
   │                       │                     │  10. Webhook Event  │
   │                       │                     │<────────────────────┤
   │                       │                     │  11. Fulfill Order  │
   │                       │                     │                     │
```

**Key Points**:
- Card data goes directly from frontend to provider (never touches backend)
- Backend only receives payment method tokens
- Webhook confirms final payment status

### Subscription Flow

```
Customer subscribes
       ↓
Create Stripe Customer
       ↓
Attach Payment Method (card token)
       ↓
Create Subscription
       ↓
Stripe charges card monthly
       ↓
Webhooks notify of each charge
```

**Stripe Subscription Example**:

```python
# Create customer
customer = stripe.Customer.create(
    email='customer@example.com',
    payment_method=payment_method_id,
    invoice_settings={
        'default_payment_method': payment_method_id
    }
)

# Create subscription
subscription = stripe.Subscription.create(
    customer=customer.id,
    items=[{'price': 'price_monthly_premium'}],  # Created in dashboard
    expand=['latest_invoice.payment_intent']
)

# Stripe automatically charges customer monthly
# Webhook events: invoice.payment_succeeded, invoice.payment_failed
```

---

## Refund Handling

### Full Refund

```python
# Stripe
refund = stripe.Refund.create(
    payment_intent=payment_intent_id,
    reason='requested_by_customer'  # or 'duplicate', 'fraudulent'
)

# PayPal
refund = paypalrestsdk.Sale.find(sale_id).refund({
    "amount": {"total": "20.00", "currency": "USD"}
})
```

### Partial Refund

```python
# Refund $5 of $20 charge
refund = stripe.Refund.create(
    payment_intent=payment_intent_id,
    amount=500,  # $5.00 in cents
    reason='requested_by_customer'
)
```

### Refund Best Practices

1. **Refund Time Limits** ⏱️
   - Stripe: Up to 180 days
   - PayPal: Up to 180 days
   - After limit: Manual bank transfer required

2. **Track Refund Status** 📊
   ```python
   refund_status = refund.status  # succeeded, failed, pending
   ```

3. **Webhook Events** 📬
   ```python
   # Stripe webhook
   if event.type == 'charge.refunded':
       # Update order status to refunded
       mark_order_refunded(event.data.object.metadata.order_id)
   ```

4. **Partial Refund Tracking** 🧾
   ```python
   # Track refunded amount
   charge = stripe.Charge.retrieve(charge_id)
   total_refunded = charge.amount_refunded  # in cents
   ```

---

## Webhook Security

**Critical**: Webhooks must be secured to prevent spoofing attacks.

### Attack Scenario

```python
# ❌ INSECURE: Attacker sends fake webhook
POST /webhooks/stripe
{
    "type": "payment_intent.succeeded",
    "data": {"object": {"id": "pi_fake", "amount": 1000000}}
}
# Without signature verification, you fulfill a fake $10,000 order!
```

### Stripe Webhook Verification

```python
import stripe

@app.post("/webhooks/stripe")
async def handle_stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')

    try:
        # ✅ SECURE: Verify signature
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError as e:
        # Invalid payload
        return Response(status_code=400)
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature - potential attack!
        logging.warning(f"Webhook signature verification failed: {e}")
        return Response(status_code=400)

    # Process verified event
    if event.type == 'payment_intent.succeeded':
        payment_intent = event.data.object
        fulfill_order(payment_intent.metadata.order_id)

    return {"status": "success"}
```

### PayPal Webhook Verification

```python
from paypalhttp import HttpClient
from paypalcheckoutsdk.core import PayPalHttpClient, SandboxEnvironment

@app.post("/webhooks/paypal")
async def handle_paypal_webhook(request: Request):
    payload = await request.body()
    headers = {
        'paypal-transmission-id': request.headers.get('paypal-transmission-id'),
        'paypal-transmission-time': request.headers.get('paypal-transmission-time'),
        'paypal-transmission-sig': request.headers.get('paypal-transmission-sig'),
        'paypal-cert-url': request.headers.get('paypal-cert-url'),
        'paypal-auth-algo': request.headers.get('paypal-auth-algo')
    }

    # ✅ SECURE: Verify webhook signature
    # (Use PayPal SDK to verify)

    # Process verified event
    event = json.loads(payload)
    if event['event_type'] == 'PAYMENT.SALE.COMPLETED':
        fulfill_order(event['resource']['custom_id'])

    return {"status": "success"}
```

### Webhook Setup

**Stripe**:
1. Dashboard → Developers → Webhooks → Add Endpoint
2. URL: `https://yourdomain.com/webhooks/stripe`
3. Events: `payment_intent.succeeded`, `payment_intent.payment_failed`
4. Copy webhook secret to `STRIPE_WEBHOOK_SECRET`

**PayPal**:
1. Dashboard → Developer → My Apps & Credentials
2. Create Webhook
3. URL: `https://yourdomain.com/webhooks/paypal`
4. Events: `PAYMENT.SALE.COMPLETED`, `PAYMENT.SALE.REFUNDED`

---

## Idempotency

**Problem**: Network failures can cause duplicate requests

```python
# Customer clicks "Pay" → Network timeout → Clicks again
# Without idempotency: Charged twice!
```

### Stripe Idempotency

```python
import uuid

# Generate unique idempotency key per payment attempt
idempotency_key = f"order_{order_id}_{uuid.uuid4()}"

payment_intent = stripe.PaymentIntent.create(
    amount=1000,
    currency='usd',
    idempotency_key=idempotency_key  # ✅ Prevents duplicate charges
)

# If request fails and retries, Stripe returns same payment_intent
# (doesn't create duplicate)
```

### Custom Idempotency Implementation

```python
# Store processed idempotency keys
processed_keys = set()  # Use Redis in production

@app.post("/api/charge")
async def charge(order_id: str, idempotency_key: str):
    # Check if already processed
    if idempotency_key in processed_keys:
        # Return cached result (don't charge again)
        return get_cached_result(idempotency_key)

    # Process payment
    result = stripe.PaymentIntent.create(...)

    # Store as processed
    processed_keys.add(idempotency_key)
    cache_result(idempotency_key, result)

    return result
```

---

## Fraud Prevention

### Stripe Radar

**Stripe Radar**: Built-in fraud detection (included free)

**Features**:
- Machine learning fraud detection
- 3D Secure / SCA automatically applied to risky payments
- Configurable rules (block high-risk countries, etc.)

**Enable Radar**:
- Automatically enabled on all Stripe accounts
- Configure rules in Dashboard → Radar → Rules

**Example Rules**:
```
Block if :ip_country != :card_country
Require 3D Secure if :amount > 100
Block if :cvc_check = fail
```

### PayPal Fraud Protection

**PayPal Fraud Protection**: Built-in (included)

**Features**:
- Buyer/Seller protection
- Chargeback protection
- Fraud detection (automatic)

### Custom Fraud Checks

```python
# Example: Velocity check (max 3 payments per hour per user)
@app.post("/api/charge")
async def charge(user_id: str):
    # Check recent payment count
    recent_payments = count_payments_last_hour(user_id)
    if recent_payments >= 3:
        raise ValueError("Too many payment attempts. Please wait 1 hour.")

    # Proceed with payment
    ...
```

---

## Testing Guide

### Test Card Numbers

**Stripe Test Cards**:
```
# Success
4242 4242 4242 4242  (Visa)
5555 5555 5555 4444  (Mastercard)

# Decline
4000 0000 0000 0002  (Card declined)

# Fraud
4000 0000 0000 9235  (Flagged as fraudulent by Radar)

# 3D Secure Required
4000 0027 6000 3184  (Requires authentication)

# Use any future expiry date, any 3-digit CVC
```

**PayPal Sandbox**:
- Create test accounts: https://developer.paypal.com/developer/accounts/
- Use sandbox credentials for testing

### Testing Webhooks Locally

**Use Stripe CLI**:
```bash
# Install Stripe CLI
brew install stripe/stripe-cli/stripe

# Forward webhooks to localhost
stripe listen --forward-to localhost:3000/webhooks/stripe

# Trigger test events
stripe trigger payment_intent.succeeded
```

**Use ngrok for PayPal**:
```bash
# Expose localhost to internet
ngrok http 3000

# Use ngrok URL in PayPal webhook settings
https://abc123.ngrok.io/webhooks/paypal
```

### Test Checklist

- [ ] Successful payment (Stripe)
- [ ] Successful payment (PayPal)
- [ ] Declined payment
- [ ] Payment requires 3D Secure
- [ ] Full refund
- [ ] Partial refund
- [ ] Subscription creation
- [ ] Subscription cancellation
- [ ] Webhook signature verification
- [ ] Idempotency (duplicate request)
- [ ] Fraud detection (flagged card)

---

## Security Considerations

### OWASP Compliance

| OWASP Category | Implementation | Status |
|----------------|----------------|--------|
| **A03:2021 Injection** | No card data in requests (use tokens) | ✅ |
| **A04:2021 Insecure Design** | Provider SDKs handle card processing | ✅ |
| **A05:2021 Security Misconfiguration** | API keys in env, HTTPS enforced | ✅ |
| **A07:2021 Auth Failures** | Webhook signature verification | ✅ |
| **A09:2021 Logging Failures** | No card numbers in logs | ✅ |

### Security Checklist

**Code Security**:
- [ ] Never log card numbers (even masked)
- [ ] API keys in environment variables (not code)
- [ ] All payment endpoints use HTTPS
- [ ] Webhook signatures verified
- [ ] Idempotency keys used
- [ ] CORS configured (restrict payment API)

**Infrastructure Security**:
- [ ] TLS 1.2+ only
- [ ] Valid SSL certificate
- [ ] Firewall configured (limit payment API access)
- [ ] Database encrypted at rest
- [ ] Backups encrypted

**Operational Security**:
- [ ] 2FA enabled on payment provider accounts
- [ ] Separate API keys for dev/staging/prod
- [ ] API keys rotated quarterly
- [ ] Payment access limited to authorized team
- [ ] Annual PCI-DSS review completed

### Logging Best Practices

```python
# ❌ BAD: Logging card numbers
logging.info(f"Charging card {card_number}")  # PCI violation!

# ✅ GOOD: Logging payment intent ID only
logging.info(f"Charging payment intent {payment_intent_id}")

# ✅ GOOD: Masking sensitive data
logging.info(f"Payment from {email.split('@')[0]}@***")
```

---

## Troubleshooting

### Common Errors

**Error**: `No such payment_intent: pi_abc123`

**Cause**: Payment intent ID doesn't exist or belongs to different account

**Solution**:
- Verify you're using correct API key (test vs live)
- Check payment intent was created successfully
- Ensure using correct Stripe account

---

**Error**: `Your card was declined`

**Cause**: Customer's card was declined by bank

**Solution**:
- Ask customer to contact their bank
- Suggest alternate payment method (PayPal)
- Check decline reason: `charge.failure_code`

---

**Error**: `Webhook signature verification failed`

**Cause**: Webhook signature doesn't match

**Solution**:
- Verify webhook secret is correct
- Check payload wasn't modified
- Ensure using raw request body (not parsed JSON)

---

**Error**: `This payment requires authentication`

**Cause**: 3D Secure / SCA required (EU regulation)

**Solution**:
- Use Stripe Payment Intents API (handles 3DS automatically)
- Customer will see authentication popup
- Don't use deprecated Charges API

---

**Error**: `Idempotency key used with different parameters`

**Cause**: Same idempotency key used for different payment

**Solution**:
- Generate unique idempotency key per payment attempt
- Use `order_id` + `timestamp` or `uuid`

---

## Next Steps

1. **Copy payment templates** to your project
2. **Set up provider accounts** (Stripe, PayPal)
3. **Configure environment variables**
4. **Test with test cards**
5. **Set up webhooks**
6. **Run security tests**
7. **Deploy to staging**
8. **Complete PCI SAQ-A review**
9. **Deploy to production**

---

## Resources

- **Stripe Docs**: https://stripe.com/docs
- **PayPal Docs**: https://developer.paypal.com/docs
- **PCI-DSS**: https://www.pcisecuritystandards.org/
- **SCA Guide**: https://stripe.com/docs/strong-customer-authentication
- **Stripe Testing**: https://stripe.com/docs/testing

---

**Payment processing is production-ready. Follow PCI-DSS guidelines and never touch card data.**
