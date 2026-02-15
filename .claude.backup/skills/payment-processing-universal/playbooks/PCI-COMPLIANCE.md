# PCI-DSS Compliance Guide

**Payment Card Industry Data Security Standard (PCI-DSS) compliance guide for SAQ-A level.**

## Compliance Level: SAQ-A ✅

**What is SAQ-A?**
- **Simplest** PCI compliance level
- Only **22 questions** (vs 329 for direct card processing)
- Achieved by NEVER touching card data
- Annual self-assessment required

## The Golden Rule

### 🚫 NEVER TOUCH CARD DATA

**Never**:
- ❌ Accept card numbers in API requests
- ❌ Store card numbers in database
- ❌ Log card numbers (even masked)
- ❌ Transmit card data through your servers
- ❌ Process cards directly

**Always**:
- ✅ Use Stripe Elements / PayPal SDK (card data goes directly to provider)
- ✅ Only receive payment tokens (pm_xxx, tok_xxx)
- ✅ Serve all payment pages over HTTPS
- ✅ Verify webhook signatures

## SAQ-A Requirements (22 Questions)

### Requirement 1-2: Secure Network

**1.1** Are firewalls configured to protect cardholder data?
- ✅ **YES** - Payment providers handle this (we never see card data)

**2.1** Is default password changed on all systems?
- ✅ **YES** - Strong passwords on payment provider accounts

**2.2** Is sensitive data encrypted during transmission?
- ✅ **YES** - HTTPS only (TLS 1.2+)

### Requirement 3-4: Protect Cardholder Data

**3.1** Is cardholder data stored?
- ✅ **NO** - We NEVER store card data (providers handle it)

**4.1** Is strong cryptography used for transmission?
- ✅ **YES** - HTTPS with TLS 1.2+ enforced

### Requirement 5-6: Maintain Security Programs

**5.1** Is antivirus software deployed?
- ✅ **YES** - Standard server security

**6.1** Are security patches applied?
- ✅ **YES** - Regular system updates

### Requirement 8-9: Access Control

**8.1** Is access to cardholder data restricted?
- ✅ **YES** - Only authorized team members access payment dashboards
- ✅ **YES** - 2FA required on Stripe/PayPal accounts

**9.1** Is physical access to cardholder data restricted?
- ✅ **N/A** - We don't store card data

### Requirement 10-11: Monitor and Test

**10.1** Are access logs maintained?
- ✅ **YES** - Application logs (no card data in logs)

**11.1** Are security testing procedures in place?
- ✅ **YES** - Security test suite (`tests/test_security.py`)

### Requirement 12: Information Security Policy

**12.1** Is security policy established?
- ✅ **YES** - This document + SKILL.md

## How We Achieve SAQ-A Compliance

### 1. Use Provider SDKs (Never Touch Cards)

**Stripe Integration**:
```javascript
// Frontend: Card data goes directly to Stripe
const {error, paymentIntent} = await stripe.confirmCardPayment(
    clientSecret,
    {payment_method: {card: cardElement}}
);
// Backend NEVER sees card number
```

**What We Receive**:
- ✅ Payment method ID: `pm_1234567890`
- ✅ Payment intent ID: `pi_abc123def456`
- ❌ NEVER: Card number, CVV, expiry

### 2. HTTPS Everywhere

```python
# ✅ GOOD: HTTPS only
PAYMENT_URL = "https://yourdomain.com/api/payment"

# ❌ BAD: HTTP not allowed
PAYMENT_URL = "http://yourdomain.com/api/payment"  # PCI violation!
```

**Enforce HTTPS**:
- Use TLS 1.2 or higher
- Valid SSL certificate
- Redirect HTTP → HTTPS
- HSTS header enabled

### 3. Webhook Signature Verification

```python
# ✅ SECURE: Verify webhook signature
event = stripe.Webhook.construct_event(
    payload, signature, webhook_secret
)

# ❌ INSECURE: Accept unverified webhooks
# Attacker can send fake "payment succeeded" webhooks!
```

### 4. No Card Data in Logs

```python
# ❌ BAD: Logging card number
logging.info(f"Processing card {card_number}")  # PCI violation!

# ✅ GOOD: Log payment intent ID only
logging.info(f"Processing payment {payment_intent_id}")

# ✅ GOOD: Mask card for display
masked = f"****{card_number[-4:]}"  # Only last 4 digits
```

### 5. API Keys in Environment Variables

```bash
# ✅ GOOD: Environment variables
export STRIPE_SECRET_KEY=sk_live_...

# ❌ BAD: Hardcoded in code
stripe.api_key = "sk_live_abc123"  # Never commit to git!
```

## Annual PCI Review Checklist

**Complete this checklist every year**:

### Technical Controls
- [ ] All payment pages use HTTPS (TLS 1.2+)
- [ ] Valid SSL certificate (not expired)
- [ ] Webhook signatures verified for all providers
- [ ] No card data in application database
- [ ] No card data in application logs
- [ ] API keys stored in environment variables (not code)
- [ ] Separate API keys for dev/staging/production
- [ ] Test cards used in development (not real cards)

### Access Controls
- [ ] 2FA enabled on Stripe account
- [ ] 2FA enabled on PayPal account
- [ ] Limited team access to payment dashboards
- [ ] Strong passwords enforced
- [ ] API keys rotated in last 90 days

### Security Testing
- [ ] All security tests passing (`pytest tests/test_security.py`)
- [ ] Webhook signature tests passing
- [ ] Idempotency tests passing
- [ ] No vulnerabilities in dependencies (`pip-audit`, `npm audit`)

### Documentation
- [ ] PCI policy reviewed and updated
- [ ] Team trained on PCI requirements
- [ ] Incident response plan updated
- [ ] Contact information current

### Provider Compliance
- [ ] Stripe PCI certificate current
- [ ] PayPal PCI certificate current
- [ ] Provider compliance documents on file

## What NEVER To Do

### ❌ NEVER Accept Card Numbers

```python
# ❌ PCI VIOLATION: Accepting card data
@app.post("/api/charge")
async def charge(card_number: str, cvv: str, expiry: str):
    # This requires SAQ-D (329 questions) + annual audit ($50k-$200k)
    pass
```

### ❌ NEVER Store Card Numbers

```sql
-- ❌ PCI VIOLATION: Storing card data
CREATE TABLE payments (
    id INT PRIMARY KEY,
    card_number VARCHAR(16),  -- NEVER DO THIS!
    cvv VARCHAR(3),            -- NEVER DO THIS!
    expiry VARCHAR(5)          -- NEVER DO THIS!
);
```

### ❌ NEVER Log Card Numbers

```python
# ❌ PCI VIOLATION: Logging card numbers
logger.info(f"Card: {card_number}")  # Audit failure!

# ❌ PCI VIOLATION: Even masked is risky
logger.info(f"Card: ****{card_number[-4:]}")  # Still not allowed

# ✅ GOOD: Log payment ID only
logger.info(f"Payment: {payment_intent_id}")
```

### ❌ NEVER Use HTTP for Payments

```python
# ❌ PCI VIOLATION: HTTP for payment pages
PAYMENT_PAGE = "http://yourdomain.com/checkout"  # Not allowed!

# ✅ GOOD: HTTPS only
PAYMENT_PAGE = "https://yourdomain.com/checkout"
```

## Incident Response

### Data Breach Response Plan

**If card data is compromised**:

1. **Immediate Actions** (within 1 hour):
   - [ ] Isolate affected systems
   - [ ] Disable compromised API keys
   - [ ] Notify payment providers (Stripe, PayPal)
   - [ ] Preserve evidence (logs, database backups)

2. **Investigation** (within 24 hours):
   - [ ] Determine scope of breach
   - [ ] Identify how many cards affected
   - [ ] Document timeline of events
   - [ ] Contact forensics firm (PCI DSS requirement)

3. **Notification** (within 72 hours):
   - [ ] Notify affected customers
   - [ ] Notify card brands (Visa, Mastercard)
   - [ ] File breach report with authorities
   - [ ] Notify cyber insurance

4. **Remediation**:
   - [ ] Fix vulnerability
   - [ ] Run security tests
   - [ ] Change all API keys
   - [ ] Update security procedures
   - [ ] Retrain team

**Fines for Non-Compliance**:
- $5,000 - $100,000 per month of non-compliance
- Plus legal costs, customer notification, credit monitoring
- Potential loss of ability to accept cards

### Common Violations

**Violation**: Logged card number accidentally
**Fine**: $10,000 - $100,000
**Remediation**: Delete logs, rotate keys, update code

**Violation**: Accepted card number in API
**Fine**: $50,000+ and mandatory SAQ-D audit
**Remediation**: Remove endpoint, migrate to tokens

**Violation**: Stored card number in database
**Fine**: $100,000+ and forensic audit
**Remediation**: Delete data, encrypt backups, migrate to tokens

## Compliance Verification

### Self-Assessment Steps

1. **Review Code** (monthly):
```bash
# Search for card-related keywords
grep -r "card_number" .
grep -r "cvv" .
grep -r "expiry" .

# Should return ZERO results
```

2. **Check Logs** (monthly):
```bash
# Search logs for card patterns
grep -E "^\d{13,19}$" application.log

# Should return ZERO results
```

3. **Run Security Tests** (weekly):
```bash
pytest tests/test_security.py -v

# All tests should PASS
```

4. **Verify HTTPS** (daily):
```bash
# Check SSL certificate
curl -vI https://yourdomain.com/api/payment 2>&1 | grep "SSL certificate"

# Should show valid certificate
```

### Documentation Required

Keep these documents on file:
- [ ] Completed SAQ-A questionnaire (annually)
- [ ] Attestation of Compliance (AOC) - signed annually
- [ ] Network diagram (updated quarterly)
- [ ] Security policy (reviewed annually)
- [ ] Incident response plan (tested annually)
- [ ] Stripe PCI compliance certificate
- [ ] PayPal PCI compliance certificate

## Resources

- **PCI SSC**: https://www.pcisecuritystandards.org/
- **SAQ-A Questionnaire**: https://www.pcisecuritystandards.org/documents/SAQ_A_v4.pdf
- **Stripe PCI Guide**: https://stripe.com/docs/security/guide
- **PayPal PCI Guide**: https://www.paypal.com/us/webapps/mpp/pci-compliance

## Summary

**PCI-DSS SAQ-A Compliance** = Simple if you follow one rule:

### 🚫 NEVER TOUCH CARD DATA

Use Stripe/PayPal SDKs. Let them handle PCI compliance. You focus on building great products.

**Annual Requirements**:
1. Complete SAQ-A questionnaire (22 questions)
2. Sign Attestation of Compliance
3. Run security tests (all passing)
4. Rotate API keys
5. Review team access
6. Update documentation

That's it. Simple compliance for smart developers.
