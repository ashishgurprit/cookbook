# Stripe Subscription Billing - Production Guide

**Stripe-specific SaaS subscription billing with checkout, webhooks, tiers, portals, and usage metering.**

Version: 1.0.0
Status: Production Ready
Extends: `payment-processing-universal` (PCI-DSS base patterns)

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Stripe Checkout Integration](#stripe-checkout-integration)
4. [Webhook Handling](#webhook-handling)
5. [Subscription Lifecycle Management](#subscription-lifecycle-management)
6. [Customer Portal](#customer-portal)
7. [Usage-Based Billing](#usage-based-billing)
8. [Subscription Tier Management](#subscription-tier-management)
9. [Proration and Plan Changes](#proration-and-plan-changes)
10. [Credit System Integration](#credit-system-integration)
11. [Mobile Integration](#mobile-integration)
12. [Environment Variables](#environment-variables)
13. [Testing Guide](#testing-guide)
14. [Troubleshooting](#troubleshooting)
15. [Integrates With](#integrates-with)

---

## Overview

### What This Skill Covers

This skill provides **Stripe-specific** patterns for SaaS subscription billing. It extends `payment-processing-universal` (which covers multi-provider, PCI-DSS, and generic payment patterns) with deep Stripe implementation for:

- Checkout Sessions (one-time and recurring)
- Webhook event processing with idempotency
- Subscription lifecycle (create, upgrade, downgrade, cancel, renew)
- Customer Portal for self-service billing management
- Usage-based (metered) billing for overage models
- Credit deposit models (monthly credits with expiry)
- Mobile companion app billing (web-based to avoid App Store fees)

### Module Dependency Diagram

```
                    ┌─────────────────────────────────┐
                    │   stripe-subscription-billing    │ <-- THIS SKILL
                    │   (Stripe-specific SaaS focus)   │
                    └──────────┬──────────────────────┘
                               │ extends
                    ┌──────────▼──────────────────────┐
                    │  payment-processing-universal    │
                    │  (PCI-DSS, multi-provider base)  │
                    └──────────┬──────────────────────┘
                               │
              ┌────────────────┼────────────────────┐
              │                │                    │
   ┌──────────▼─────┐  ┌──────▼───────┐  ┌────────▼──────────┐
   │ unified-api-   │  │ database-orm-│  │ notification-     │
   │ client         │  │ patterns     │  │ universal         │
   │ (Stripe SDK)   │  │ (sub state)  │  │ (payment emails)  │
   └────────────────┘  └──────────────┘  └───────────────────┘
                               │
                    ┌──────────▼──────────────────────┐
                    │     mobile-subscription          │
                    │  (RevenueCat for iOS/Android)    │
                    └─────────────────────────────────┘
```

### Key Principle: Webhooks Are the Source of Truth

**NEVER trust frontend redirect success pages for payment confirmation.**

The checkout success URL is a UX convenience. The webhook `checkout.session.completed` is the **only** reliable signal that payment succeeded. Build your fulfillment logic in webhook handlers.

```
Frontend redirect success_url  -->  UX only (show "thank you" page)
Webhook checkout.session.completed  -->  TRUTH (grant access, add credits)
```

---

## Quick Start

### Node.js (Express)

```bash
npm install stripe express
```

```javascript
// stripe-billing.js
const Stripe = require('stripe');
const express = require('express');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

// --- Price Configuration ---
const PRICE_IDS = {
  starter_monthly: process.env.STRIPE_PRICE_STARTER_MONTHLY,
  starter_yearly:  process.env.STRIPE_PRICE_STARTER_YEARLY,
  pro_monthly:     process.env.STRIPE_PRICE_PRO_MONTHLY,
  pro_yearly:      process.env.STRIPE_PRICE_PRO_YEARLY,
  agency_monthly:  process.env.STRIPE_PRICE_AGENCY_MONTHLY,
  agency_yearly:   process.env.STRIPE_PRICE_AGENCY_YEARLY,
  // One-time credit packs
  pack_10:  process.env.STRIPE_PRICE_PACK_10,
  pack_25:  process.env.STRIPE_PRICE_PACK_25,
  pack_50:  process.env.STRIPE_PRICE_PACK_50,
  pack_100: process.env.STRIPE_PRICE_PACK_100,
};

const PLAN_DETAILS = {
  starter_monthly: { credits: 10, plan: 'starter', billing: 'monthly' },
  starter_yearly:  { credits: 10, plan: 'starter', billing: 'yearly' },
  pro_monthly:     { credits: 40, plan: 'pro', billing: 'monthly' },
  pro_yearly:      { credits: 40, plan: 'pro', billing: 'yearly' },
  agency_monthly:  { credits: 150, plan: 'agency', billing: 'monthly' },
  agency_yearly:   { credits: 150, plan: 'agency', billing: 'yearly' },
  pack_10:  { credits: 10, plan: null, billing: 'one_time' },
  pack_25:  { credits: 27, plan: null, billing: 'one_time' },
  pack_50:  { credits: 55, plan: null, billing: 'one_time' },
  pack_100: { credits: 115, plan: null, billing: 'one_time' },
};

// --- Create Checkout Session ---
app.post('/api/payments/create-checkout', async (req, res) => {
  const { planType, userId, email } = req.body;

  const priceId = PRICE_IDS[planType];
  if (!priceId) {
    return res.status(400).json({ error: `Invalid plan: ${planType}` });
  }

  const planDetails = PLAN_DETAILS[planType];
  const isSubscription = ['monthly', 'yearly'].includes(planDetails.billing);

  // Get or create Stripe customer
  const customerId = await getOrCreateCustomer(userId, email);

  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    payment_method_types: ['card'],
    line_items: [{ price: priceId, quantity: 1 }],
    mode: isSubscription ? 'subscription' : 'payment',
    success_url: `${process.env.APP_URL}/dashboard?payment=success&session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.APP_URL}/pricing`,
    metadata: {
      user_id: userId,
      plan_type: planType,
      credits: String(planDetails.credits),
    },
    ...(isSubscription && {
      subscription_data: {
        metadata: { user_id: userId, plan_type: planType },
      },
    }),
    allow_promotion_codes: true,
    billing_address_collection: 'auto',
  });

  res.json({
    checkout_url: session.url,
    session_id: session.id,
    expires_at: new Date(session.expires_at * 1000),
  });
});

// --- Webhook Handler ---
// IMPORTANT: Use raw body for signature verification
app.post('/api/payments/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('Webhook signature verification failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Idempotency: check if already processed
    if (await isEventProcessed(event.id)) {
      return res.json({ status: 'already_processed' });
    }

    try {
      switch (event.type) {
        case 'checkout.session.completed':
          await handleCheckoutCompleted(event.data.object);
          break;
        case 'invoice.paid':
          await handleInvoicePaid(event.data.object);
          break;
        case 'invoice.payment_failed':
          await handleInvoicePaymentFailed(event.data.object);
          break;
        case 'customer.subscription.updated':
          await handleSubscriptionUpdated(event.data.object);
          break;
        case 'customer.subscription.deleted':
          await handleSubscriptionDeleted(event.data.object);
          break;
        default:
          console.log(`Unhandled event type: ${event.type}`);
      }

      await markEventProcessed(event.id);
      res.json({ status: 'success' });
    } catch (err) {
      console.error(`Webhook processing error: ${err.message}`);
      res.status(500).json({ error: 'Processing failed' });
    }
  }
);

// --- Customer Portal ---
app.post('/api/payments/customer-portal', async (req, res) => {
  const { userId } = req.body;
  const customerId = await getCustomerId(userId);

  if (!customerId) {
    return res.status(400).json({ error: 'No payment history found' });
  }

  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: `${process.env.APP_URL}/dashboard`,
  });

  res.json({ portal_url: session.url });
});

app.listen(3000);
```

### Python (FastAPI)

```bash
pip install stripe fastapi uvicorn
```

```python
# stripe_billing.py
import os
import stripe
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Header
from pydantic import BaseModel, Field

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

router = APIRouter(prefix="/api/v1/payments", tags=["Payments"])

# --- Price Configuration ---
PRICE_IDS = {
    "starter_monthly": os.getenv("STRIPE_PRICE_STARTER_MONTHLY", ""),
    "starter_yearly":  os.getenv("STRIPE_PRICE_STARTER_YEARLY", ""),
    "pro_monthly":     os.getenv("STRIPE_PRICE_PRO_MONTHLY", ""),
    "pro_yearly":      os.getenv("STRIPE_PRICE_PRO_YEARLY", ""),
    "agency_monthly":  os.getenv("STRIPE_PRICE_AGENCY_MONTHLY", ""),
    "agency_yearly":   os.getenv("STRIPE_PRICE_AGENCY_YEARLY", ""),
    "pack_10":  os.getenv("STRIPE_PRICE_PACK_10", ""),
    "pack_25":  os.getenv("STRIPE_PRICE_PACK_25", ""),
    "pack_50":  os.getenv("STRIPE_PRICE_PACK_50", ""),
    "pack_100": os.getenv("STRIPE_PRICE_PACK_100", ""),
    # Usage-based overage
    "agency_overage": os.getenv("STRIPE_PRICE_AGENCY_OVERAGE", ""),
}

PLAN_DETAILS = {
    "starter_monthly": {"credits": 10, "plan": "starter", "billing": "monthly", "price_usd": 29},
    "starter_yearly":  {"credits": 10, "plan": "starter", "billing": "yearly", "price_usd": 278.40},
    "pro_monthly":     {"credits": 40, "plan": "pro", "billing": "monthly", "price_usd": 79},
    "pro_yearly":      {"credits": 40, "plan": "pro", "billing": "yearly", "price_usd": 758.40},
    "agency_monthly":  {"credits": 150, "plan": "agency", "billing": "monthly", "price_usd": 199},
    "agency_yearly":   {"credits": 150, "plan": "agency", "billing": "yearly", "price_usd": 1910.40},
    "pack_10":  {"credits": 10,  "plan": None, "billing": "one_time", "price_usd": 35},
    "pack_25":  {"credits": 27,  "plan": None, "billing": "one_time", "price_usd": 69},
    "pack_50":  {"credits": 55,  "plan": None, "billing": "one_time", "price_usd": 129},
    "pack_100": {"credits": 115, "plan": None, "billing": "one_time", "price_usd": 239},
}


# --- Models ---
class CreateCheckoutRequest(BaseModel):
    plan_type: str = Field(description="Plan key from PRICE_IDS")
    success_url: Optional[str] = None
    cancel_url: Optional[str] = None


class CheckoutResponse(BaseModel):
    checkout_url: str
    session_id: str
    expires_at: datetime


class CustomerPortalResponse(BaseModel):
    portal_url: str


class SubscriptionStatus(BaseModel):
    has_subscription: bool
    plan: Optional[str] = None
    status: Optional[str] = None
    current_period_end: Optional[datetime] = None
    cancel_at_period_end: bool = False
    credits_remaining: int = 0
    credits_used_this_period: int = 0


# --- Endpoints ---
@router.post("/create-checkout", response_model=CheckoutResponse)
async def create_checkout(request: CreateCheckoutRequest, user=Depends(get_current_user)):
    price_id = PRICE_IDS.get(request.plan_type)
    if not price_id:
        raise HTTPException(status_code=400, detail=f"Invalid plan: {request.plan_type}")

    plan_details = PLAN_DETAILS.get(request.plan_type, {})
    is_subscription = plan_details.get("billing") in ["monthly", "yearly"]

    customer_id = await get_or_create_customer(user.uid, user.email)

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription" if is_subscription else "payment",
        success_url=request.success_url or f"{os.getenv('APP_URL')}/dashboard?payment=success",
        cancel_url=request.cancel_url or f"{os.getenv('APP_URL')}/pricing",
        metadata={
            "user_id": user.uid,
            "plan_type": request.plan_type,
            "credits": str(plan_details.get("credits", 0)),
        },
        subscription_data={"metadata": {"user_id": user.uid, "plan_type": request.plan_type}}
            if is_subscription else None,
        allow_promotion_codes=True,
        billing_address_collection="auto",
    )

    return CheckoutResponse(
        checkout_url=session.url,
        session_id=session.id,
        expires_at=datetime.fromtimestamp(session.expires_at),
    )


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
):
    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, os.getenv("STRIPE_WEBHOOK_SECRET")
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Idempotency
    if await is_event_processed(event["id"]):
        return {"status": "already_processed"}

    event_type = event["type"]
    data = event["data"]["object"]

    handlers = {
        "checkout.session.completed": handle_checkout_completed,
        "invoice.paid": handle_invoice_paid,
        "invoice.payment_failed": handle_invoice_payment_failed,
        "customer.subscription.updated": handle_subscription_updated,
        "customer.subscription.deleted": handle_subscription_deleted,
    }

    handler = handlers.get(event_type)
    if handler:
        await handler(data)
        await mark_event_processed(event["id"])

    return {"status": "success"}
```

---

## Stripe Checkout Integration

### One-Time Payments vs Subscriptions

Stripe Checkout supports two modes, determined by the price type:

```python
# Mode is determined by plan billing type
plan_details = PLAN_DETAILS.get(plan_type, {})
is_subscription = plan_details.get("billing") in ["monthly", "yearly"]
mode = "subscription" if is_subscription else "payment"
```

### Checkout Session Creation (Complete)

```python
class StripePaymentService:
    """Service class for all Stripe payment operations."""

    @staticmethod
    def create_checkout_session(
        user_id: str,
        email: str,
        plan_type: str,
        success_url: Optional[str] = None,
        cancel_url: Optional[str] = None,
        name: Optional[str] = None,
    ) -> stripe.checkout.Session:
        """
        Create a Stripe Checkout Session for subscription or one-time payment.

        Args:
            user_id: Internal user ID (stored in metadata for webhook mapping)
            email: Pre-fills the email field in checkout
            plan_type: Key from PRICE_IDS (e.g., "pro_monthly", "pack_50")
            success_url: Where to redirect after successful payment
            cancel_url: Where to redirect if user cancels
            name: User's name for Stripe Customer creation

        Returns:
            Stripe Checkout Session with .url for redirect
        """
        price_id = PRICE_IDS.get(plan_type)
        if not price_id:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid plan type: {plan_type}. Price ID not configured."
            )

        # Get or create Stripe customer (links internal user to Stripe)
        customer_id = StripePaymentService.get_or_create_customer(user_id, email, name)

        plan_details = PLAN_DETAILS.get(plan_type, {})
        is_subscription = plan_details.get("billing") in ["monthly", "yearly"]
        mode = "subscription" if is_subscription else "payment"

        # Build line items
        line_items = [{"price": price_id, "quantity": 1}]

        # For agency plans: add metered overage line item
        if plan_type.startswith("agency_") and PRICE_IDS.get("agency_overage"):
            line_items.append({"price": PRICE_IDS["agency_overage"]})

        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=["card"],
            line_items=line_items,
            mode=mode,
            success_url=success_url or f"{APP_URL}/dashboard?payment=success&session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=cancel_url or f"{APP_URL}/pricing",
            metadata={
                "user_id": user_id,
                "plan_type": plan_type,
                "credits": str(plan_details.get("credits", 0)),
            },
            # Subscription-specific: store metadata on the subscription itself
            subscription_data={
                "metadata": {
                    "user_id": user_id,
                    "plan_type": plan_type,
                }
            } if is_subscription else None,
            allow_promotion_codes=True,
            billing_address_collection="auto",
            automatic_tax={"enabled": False},  # Enable after configuring Stripe Tax
        )

        return session
```

### Customer Creation Pattern

```python
@staticmethod
def get_or_create_customer(user_id: str, email: str, name: Optional[str] = None) -> str:
    """
    Get existing Stripe customer or create new one.
    Links internal user_id to Stripe customer via metadata.

    Strategy:
    1. Check local DB for stored stripe_customer_id
    2. Search Stripe by email (catches manual dashboard creations)
    3. Create new customer if neither found

    Returns: Stripe Customer ID (cus_xxx)
    """
    # 1. Check local storage first (fastest)
    user_data = get_user_data(user_id)
    if user_data.get("stripe_customer_id"):
        return user_data["stripe_customer_id"]

    # 2. Check if customer exists in Stripe by email
    try:
        existing = stripe.Customer.list(email=email, limit=1)
        if existing.data:
            customer_id = existing.data[0].id
            update_user_data(user_id, {"stripe_customer_id": customer_id})
            return customer_id
    except stripe.error.StripeError as e:
        logger.warning(f"Error checking existing customer: {e}")

    # 3. Create new customer
    customer = stripe.Customer.create(
        email=email,
        name=name,
        metadata={
            "user_id": user_id,
            "source": "your_app_name",
        }
    )
    update_user_data(user_id, {"stripe_customer_id": customer.id})
    logger.info(f"Created Stripe customer {customer.id} for user {user_id}")
    return customer.id
```

### Frontend Integration (React)

```tsx
// PurchaseCredits.tsx
interface PlanOption {
  id: string;
  name: string;
  price: string;
  credits: number;
  popular?: boolean;
}

const PLAN_OPTIONS: PlanOption[] = [
  { id: 'starter_monthly', name: 'Starter', price: '$29/mo', credits: 10 },
  { id: 'pro_monthly', name: 'Pro', price: '$79/mo', credits: 40, popular: true },
  { id: 'agency_monthly', name: 'Agency', price: '$199/mo', credits: 150 },
];

const CREDIT_PACKS: PlanOption[] = [
  { id: 'pack_10', name: '10 Credits', price: '$35', credits: 10 },
  { id: 'pack_25', name: '27 Credits', price: '$69', credits: 27 },
  { id: 'pack_50', name: '55 Credits', price: '$129', credits: 55, popular: true },
  { id: 'pack_100', name: '115 Credits', price: '$239', credits: 115 },
];

const handlePurchase = async (planId: string) => {
  try {
    const response = await fetch('/api/v1/payments/create-checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan_type: planId }),
    });

    if (response.ok) {
      const data = await response.json();
      // Redirect to Stripe Checkout (hosted page)
      window.location.href = data.checkout_url;
    }
  } catch (error) {
    console.error('Purchase error:', error);
  }
};
```

---

## Webhook Handling

### Critical Webhook Events

| Event | When It Fires | Action |
|-------|---------------|--------|
| `checkout.session.completed` | Customer completes checkout | Grant access / add credits |
| `invoice.paid` | Subscription renews successfully | Reset monthly credits |
| `invoice.payment_failed` | Renewal payment fails | Mark as past_due, notify user |
| `customer.subscription.updated` | Plan change, cancellation scheduled | Update subscription state |
| `customer.subscription.deleted` | Subscription fully canceled | Downgrade to free tier |

### Webhook Endpoint with Signature Verification

```python
@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
):
    """
    Stripe webhook endpoint.

    CRITICAL SECURITY:
    1. Use RAW request body (not parsed JSON) for signature verification
    2. Verify signature BEFORE any processing
    3. Check idempotency BEFORE processing (prevent duplicate fulfillment)
    4. Return 200 quickly (process asynchronously if needed)
    """
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook not configured")

    # Get raw body - MUST be raw bytes, not parsed JSON
    payload = await request.body()

    # Verify webhook signature (prevents spoofing attacks)
    try:
        event = stripe.Webhook.construct_event(
            payload,
            stripe_signature,
            STRIPE_WEBHOOK_SECRET,
        )
    except ValueError as e:
        logger.error(f"Invalid webhook payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid webhook signature: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Idempotency check (prevents double-processing)
    event_id = event.get("id")
    if await is_event_processed(event_id):
        logger.info(f"Event {event_id} already processed, skipping")
        return {"status": "already_processed"}

    event_type = event.get("type")
    data = event.get("data", {}).get("object", {})

    logger.info(f"Processing webhook: {event_type}")

    try:
        if event_type == "checkout.session.completed":
            await handle_checkout_completed(data)
        elif event_type == "customer.subscription.updated":
            await handle_subscription_updated(data)
        elif event_type == "customer.subscription.deleted":
            await handle_subscription_deleted(data)
        elif event_type == "invoice.paid":
            await handle_invoice_paid(data)
        elif event_type == "invoice.payment_failed":
            await handle_invoice_payment_failed(data)
        else:
            logger.info(f"Unhandled event: {event_type}")

        await mark_event_processed(event_id)
        return {"status": "success"}

    except Exception as e:
        logger.error(f"Webhook processing error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Processing error")
```

### Node.js Webhook (Express)

```javascript
// CRITICAL: Webhook route MUST use express.raw() middleware, NOT express.json()
// express.json() parses the body, which breaks signature verification

app.post('/api/payments/webhook',
  express.raw({ type: 'application/json' }),  // Raw body for signature check
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,  // Raw Buffer, not parsed JSON
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('Webhook sig verification failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Process event...
    res.json({ received: true });
  }
);
```

### Checkout Completed Handler

```python
async def handle_checkout_completed(session: dict) -> None:
    """
    Handle successful checkout.

    Distinguishes between:
    - Subscription purchases (monthly/yearly recurring)
    - One-time credit pack purchases
    """
    user_id = session.get("metadata", {}).get("user_id")
    plan_type = session.get("metadata", {}).get("plan_type")
    credits = int(session.get("metadata", {}).get("credits", 0))

    if not user_id:
        logger.error("Checkout completed but no user_id in metadata")
        return

    plan_details = PLAN_DETAILS.get(plan_type, {})

    if plan_details.get("billing") in ["monthly", "yearly"]:
        # --- SUBSCRIPTION PURCHASE ---
        await update_user_subscription(
            user_id=user_id,
            stripe_customer_id=session.get("customer"),
            stripe_subscription_id=session.get("subscription"),
            plan_type=plan_details.get("plan", "starter"),
            credits=credits,
        )

        # Extract metered billing subscription item ID (for agency overage)
        if session.get("subscription"):
            try:
                subscription = stripe.Subscription.retrieve(session["subscription"])
                for item in subscription.get("items", {}).get("data", []):
                    if item.get("price", {}).get("recurring", {}).get("usage_type") == "metered":
                        await update_user_data(user_id, {"subscription_item_id": item["id"]})
                        break
            except stripe.error.StripeError as e:
                logger.error(f"Failed to get subscription details: {e}")

        logger.info(f"Subscription activated: user={user_id}, plan={plan_details.get('plan')}")

        # Trigger notification (via notification-universal skill)
        await send_subscription_activated_email(user_id, plan_details)

    else:
        # --- ONE-TIME CREDIT PURCHASE ---
        await update_user_data(user_id, {"stripe_customer_id": session.get("customer")})
        new_balance = await add_credits_atomic(user_id, credits, reason=f"purchase:{plan_type}")

        logger.info(f"Credits purchased: user={user_id}, added={credits}, balance={new_balance}")

        # Trigger notification
        await send_credits_purchased_email(user_id, credits, new_balance)
```

### Invoice Paid Handler (Subscription Renewal)

```python
async def handle_invoice_paid(invoice: dict) -> None:
    """
    Handle subscription renewal payment.

    This fires monthly/yearly when Stripe automatically charges the customer.
    Reset credits for the new billing period.
    """
    customer_id = invoice.get("customer")
    subscription_id = invoice.get("subscription")

    # Find user from Stripe customer metadata
    user_id = await find_user_by_customer_id(customer_id)
    if not user_id:
        logger.warning("Invoice paid but cannot find user")
        return

    # Get subscription to determine credit allocation
    try:
        subscription = stripe.Subscription.retrieve(subscription_id)
        plan_type = subscription.get("metadata", {}).get("plan_type")
        plan_details = PLAN_DETAILS.get(plan_type, {})

        if plan_details:
            credits_to_add = plan_details.get("credits", 0)
            # Reset credits for new period (not additive -- use-it-or-lose-it)
            await update_user_subscription(
                user_id=user_id,
                credits=credits_to_add,
                plan_type=plan_details.get("plan", "starter"),
            )
            logger.info(f"Renewed: user={user_id}, credits reset to {credits_to_add}")

    except stripe.error.StripeError as e:
        logger.error(f"Failed to process invoice: {e}")
```

### Subscription Updated Handler

```python
async def handle_subscription_updated(subscription: dict) -> None:
    """Handle plan changes, cancellation scheduling, etc."""
    user_id = subscription.get("metadata", {}).get("user_id")

    if not user_id:
        # Fallback: look up by customer ID
        customer_id = subscription.get("customer")
        user_id = await find_user_by_customer_id(customer_id)

    if not user_id:
        logger.warning("Subscription updated but cannot find user")
        return

    await update_user_data(user_id, {
        "status": subscription.get("status"),
        "cancel_at_period_end": subscription.get("cancel_at_period_end", False),
        "current_period_end": datetime.fromtimestamp(
            subscription.get("current_period_end", 0)
        ).isoformat() if subscription.get("current_period_end") else None,
    })

    logger.info(f"Subscription updated: user={user_id}, status={subscription.get('status')}")
```

### Subscription Deleted Handler

```python
async def handle_subscription_deleted(subscription: dict) -> None:
    """Handle subscription cancellation/expiration."""
    customer_id = subscription.get("customer")
    user_id = subscription.get("metadata", {}).get("user_id")

    if not user_id and customer_id:
        user_id = await find_user_by_customer_id(customer_id)

    if not user_id:
        logger.warning("Subscription deleted but cannot find user")
        return

    await update_user_data(user_id, {
        "subscription_id": None,
        "plan": "free",
        "status": "canceled",
        # Keep remaining credits -- they are already paid for
    })

    logger.info(f"Subscription canceled: user={user_id}")

    # Trigger win-back campaign (via notification-universal skill)
    await send_cancellation_email(user_id)
```

### Invoice Payment Failed Handler

```python
async def handle_invoice_payment_failed(invoice: dict) -> None:
    """Handle failed renewal payment."""
    customer_id = invoice.get("customer")
    user_id = await find_user_by_customer_id(customer_id)

    if user_id:
        await update_user_data(user_id, {"status": "past_due"})
        logger.warning(f"Payment failed: user={user_id}")

        # Notify user to update payment method
        # Links to Customer Portal for self-service
        await send_payment_failed_email(user_id)
```

### Idempotency Implementation

```python
# Database table for processed webhook events
# Uses database-orm-patterns module

# SQLAlchemy model
class ProcessedWebhookEvent(Base):
    __tablename__ = "processed_webhook_events"

    event_id = Column(String(255), primary_key=True)
    event_type = Column(String(100), nullable=False)
    processed_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("idx_processed_events_at", "processed_at"),
    )


async def is_event_processed(event_id: str) -> bool:
    """Check if webhook event was already processed."""
    async with get_session() as session:
        result = await session.execute(
            select(ProcessedWebhookEvent).where(
                ProcessedWebhookEvent.event_id == event_id
            )
        )
        return result.scalar_one_or_none() is not None


async def mark_event_processed(event_id: str, event_type: str = "") -> None:
    """Mark webhook event as processed."""
    async with get_session() as session:
        event = ProcessedWebhookEvent(event_id=event_id, event_type=event_type)
        session.add(event)
        await session.commit()
```

### Webhook Setup Checklist

```bash
# 1. In Stripe Dashboard: Developers > Webhooks > Add endpoint
# URL: https://yourdomain.com/api/v1/payments/webhook

# 2. Select these events:
#    - checkout.session.completed
#    - customer.subscription.updated
#    - customer.subscription.deleted
#    - invoice.paid
#    - invoice.payment_failed

# 3. Copy signing secret to STRIPE_WEBHOOK_SECRET env var

# 4. For local development, use Stripe CLI:
stripe listen --forward-to localhost:3000/api/v1/payments/webhook

# 5. Test with:
stripe trigger checkout.session.completed
stripe trigger invoice.paid
stripe trigger customer.subscription.deleted
```

---

## Subscription Lifecycle Management

### State Machine

```
                    ┌──────────┐
                    │   FREE   │  (Default state)
                    └────┬─────┘
                         │ checkout.session.completed
                         ▼
                    ┌──────────┐
             ┌─────│  ACTIVE  │◄─────────────────────┐
             │     └────┬─────┘                       │
             │          │                             │
             │          │ invoice.payment_failed      │ invoice.paid
             │          ▼                             │ (payment retried)
             │     ┌──────────┐                       │
             │     │ PAST_DUE ├───────────────────────┘
             │     └────┬─────┘
             │          │ all retries exhausted
             │          ▼
             │     ┌──────────┐
             │     │ CANCELED │
             │     └──────────┘
             │
             │ cancel_at_period_end=true
             ▼
        ┌─────────────────┐
        │ ACTIVE (cancel   │  subscription.updated
        │ scheduled)       │─────────────────────┐
        └────────┬────────┘                      │
                 │ period ends                    │ user reactivates
                 ▼                                │
            ┌──────────┐                          │
            │ CANCELED  │  subscription.deleted   │
            └─────┬────┘                         ▼
                  │                        ┌──────────┐
                  ▼                        │  ACTIVE  │
             ┌──────────┐                  └──────────┘
             │   FREE   │
             └──────────┘
```

### Cancellation Handling

```python
@staticmethod
def cancel_subscription(user_id: str, at_period_end: bool = True) -> bool:
    """
    Cancel a subscription.

    Args:
        at_period_end: If True, keeps access until period ends (recommended).
                       If False, cancels immediately (usually for refund scenarios).
    """
    user_data = get_user_data(user_id)
    subscription_id = user_data.get("subscription_id")

    if not subscription_id:
        raise HTTPException(status_code=400, detail="No active subscription")

    if at_period_end:
        # Graceful: user keeps access until period ends
        stripe.Subscription.modify(
            subscription_id,
            cancel_at_period_end=True,
        )
        update_user_data(user_id, {"cancel_at_period_end": True})
    else:
        # Immediate: user loses access now
        stripe.Subscription.cancel(subscription_id)
        update_user_data(user_id, {
            "subscription_id": None,
            "plan": "free",
            "status": "canceled",
        })

    return True
```

### Subscription Status Retrieval

```python
@staticmethod
def get_subscription_status(user_id: str) -> SubscriptionStatus:
    """Get current subscription status from Stripe + local DB."""
    user_data = get_user_data(user_id)

    subscription_id = user_data.get("subscription_id")
    if not subscription_id:
        return SubscriptionStatus(
            has_subscription=False,
            credits_remaining=user_data.get("credits", 0),
        )

    try:
        subscription = stripe.Subscription.retrieve(subscription_id)

        return SubscriptionStatus(
            has_subscription=True,
            plan=user_data.get("plan"),
            status=subscription.status,  # active, past_due, canceled, etc.
            current_period_end=datetime.fromtimestamp(subscription.current_period_end),
            cancel_at_period_end=subscription.cancel_at_period_end,
            credits_remaining=user_data.get("credits", 0),
            credits_used_this_period=user_data.get("credits_used", 0),
        )
    except stripe.error.StripeError as e:
        logger.error(f"Failed to get subscription: {e}")
        return SubscriptionStatus(
            has_subscription=True,
            plan=user_data.get("plan"),
            status="unknown",
            credits_remaining=user_data.get("credits", 0),
        )
```

---

## Customer Portal

### Overview

Stripe Customer Portal is a hosted UI that lets customers self-serve:
- Update payment method
- View and download invoices
- Cancel or reactivate subscription
- Update billing information

### Portal Session Creation

```python
@staticmethod
def create_customer_portal_session(
    user_id: str,
    return_url: Optional[str] = None
) -> stripe.billing_portal.Session:
    """
    Create a Stripe Customer Portal session.

    Requires:
    1. Customer must exist in Stripe
    2. Portal must be configured in Stripe Dashboard:
       Settings > Billing > Customer portal
    """
    user_data = get_user_data(user_id)
    customer_id = user_data.get("stripe_customer_id")

    if not customer_id:
        raise HTTPException(
            status_code=400,
            detail="No payment history found. Please make a purchase first."
        )

    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=return_url or f"{APP_URL}/dashboard",
    )

    return session  # Redirect user to session.url
```

### Portal Configuration

Configure the portal in Stripe Dashboard under Settings > Billing > Customer portal:

```
Portal Features to Enable:
  [x] Invoice history         -- Users can view/download invoices
  [x] Update payment method   -- Users can change their card
  [x] Cancel subscription     -- Users can self-cancel
  [x] Update billing info     -- Users can change address
  [ ] Switch plans             -- Enable if you want in-portal upgrades
```

### Frontend Integration

```tsx
const openPortal = async () => {
  const response = await fetch('/api/v1/payments/customer-portal', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ return_url: window.location.href }),
  });

  if (response.ok) {
    const { portal_url } = await response.json();
    window.location.href = portal_url;
  }
};

// In JSX:
<button onClick={openPortal}>Manage Billing</button>
```

---

## Usage-Based Billing

### When to Use Usage-Based Billing

Usage-based billing works for:
- API call metering
- Overage beyond included allocation
- Pay-per-use models on top of base subscription

### Metered Billing Setup

```bash
# 1. Create metered price in Stripe
stripe prices create \
  --product="prod_xxx" \
  --unit-amount=150 \
  --currency=usd \
  --recurring[interval]=month \
  --recurring[usage_type]=metered \
  --recurring[aggregate_usage]=sum \
  --metadata[type]="agency_overage"
```

### Recording Usage

```python
@staticmethod
def record_usage(
    user_id: str,
    quantity: int = 1,
    action: str = "increment"
) -> Optional[stripe.SubscriptionItem]:
    """
    Record usage for metered billing (e.g., agency plan overage).

    Args:
        user_id: Internal user ID
        quantity: Number of units consumed
        action: "increment" adds to total, "set" replaces total

    Returns:
        Usage record if successful
    """
    user_data = get_user_data(user_id)
    subscription_item_id = user_data.get("subscription_item_id")

    if not subscription_item_id:
        logger.warning(f"No subscription item for user {user_id}")
        return None

    try:
        usage_record = stripe.SubscriptionItem.create_usage_record(
            subscription_item_id,
            quantity=quantity,
            timestamp=int(time.time()),
            action=action,  # "increment" or "set"
        )
        logger.info(f"Recorded {quantity} usage for user {user_id}")
        return usage_record
    except stripe.error.StripeError as e:
        logger.error(f"Failed to record usage: {e}")
        return None
```

### Overage Model Pattern

```python
async def use_credit(user_id: str) -> dict:
    """
    Use one credit. For agency plan, allows overage with metered billing.

    Returns:
        {success: bool, credits_remaining: int, overage: bool}
    """
    result = await use_credit_atomic(user_id)

    if not result.get("success"):
        return {"success": False, "error": "No credits remaining"}

    # Record overage for agency plan
    if result.get("plan") == "agency" and result.get("overage"):
        payment_service.record_usage(user_id, 1)

    return {
        "success": True,
        "credits_remaining": result.get("credits_remaining", 0),
        "overage": result.get("overage", False),
    }
```

---

## Subscription Tier Management

### Tier Configuration Pattern

```python
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional

class SubscriptionTier(str, Enum):
    FREE = "free"
    TRIAL = "trial"
    STARTER = "starter"
    PRO = "pro"
    AGENCY = "agency"


@dataclass
class TierConfig:
    """Feature flags and limits per subscription tier."""
    tier: SubscriptionTier

    # Credits
    monthly_credits: int
    monthly_price_usd: float
    yearly_price_usd: float

    # Feature flags
    basic_seo: bool = True
    advanced_seo: bool = False
    white_label: bool = False
    api_access: bool = False
    priority_support: bool = False

    # Content limits
    max_word_count: int = 1500
    max_images: int = 2

    # Research depth
    research_queries: int = 3

    @property
    def yearly_savings_percent(self) -> int:
        monthly_total = self.monthly_price_usd * 12
        if monthly_total == 0:
            return 0
        return int((1 - self.yearly_price_usd / monthly_total) * 100)


TIER_CONFIGS: Dict[SubscriptionTier, TierConfig] = {
    SubscriptionTier.FREE: TierConfig(
        tier=SubscriptionTier.FREE,
        monthly_credits=1,
        monthly_price_usd=0,
        yearly_price_usd=0,
        max_word_count=1500,
        max_images=1,
        research_queries=2,
    ),
    SubscriptionTier.STARTER: TierConfig(
        tier=SubscriptionTier.STARTER,
        monthly_credits=10,
        monthly_price_usd=29,
        yearly_price_usd=278.40,  # 20% off
        max_word_count=2000,
        max_images=3,
        research_queries=4,
    ),
    SubscriptionTier.PRO: TierConfig(
        tier=SubscriptionTier.PRO,
        monthly_credits=40,
        monthly_price_usd=79,
        yearly_price_usd=758.40,  # 20% off
        advanced_seo=True,
        max_word_count=2500,
        max_images=3,
        research_queries=6,
        priority_support=True,
    ),
    SubscriptionTier.AGENCY: TierConfig(
        tier=SubscriptionTier.AGENCY,
        monthly_credits=150,
        monthly_price_usd=199,
        yearly_price_usd=1910.40,  # 20% off
        advanced_seo=True,
        white_label=True,
        api_access=True,
        max_word_count=3000,
        max_images=4,
        research_queries=8,
        priority_support=True,
    ),
}


def get_tier_config(plan_id: str) -> TierConfig:
    """Map plan identifier to tier configuration."""
    plan_mapping = {
        "free": SubscriptionTier.FREE,
        "trial": SubscriptionTier.FREE,
        "starter": SubscriptionTier.STARTER,
        "starter_monthly": SubscriptionTier.STARTER,
        "starter_yearly": SubscriptionTier.STARTER,
        "pro": SubscriptionTier.PRO,
        "pro_monthly": SubscriptionTier.PRO,
        "pro_yearly": SubscriptionTier.PRO,
        "agency": SubscriptionTier.AGENCY,
        "agency_monthly": SubscriptionTier.AGENCY,
        "agency_yearly": SubscriptionTier.AGENCY,
    }
    tier = plan_mapping.get(plan_id.lower(), SubscriptionTier.FREE)
    return TIER_CONFIGS[tier]
```

### Tier-Based Feature Gating

```python
def check_feature_access(user_plan: str, feature: str) -> bool:
    """Check if a user's plan includes a specific feature."""
    tier_config = get_tier_config(user_plan)

    feature_map = {
        "advanced_seo": tier_config.advanced_seo,
        "white_label": tier_config.white_label,
        "api_access": tier_config.api_access,
        "priority_support": tier_config.priority_support,
    }

    return feature_map.get(feature, False)


# Usage in route handler
@router.post("/generate")
async def generate_content(request: GenerateRequest, user=Depends(get_current_user)):
    tier_config = get_tier_config(user.plan)

    if request.word_count > tier_config.max_word_count:
        raise HTTPException(
            status_code=403,
            detail=f"Word count {request.word_count} exceeds {user.plan} plan limit ({tier_config.max_word_count})"
        )

    if request.advanced_seo and not tier_config.advanced_seo:
        raise HTTPException(
            status_code=403,
            detail="Advanced SEO requires Pro or Agency plan"
        )

    # Proceed with generation...
```

---

## Proration and Plan Changes

### Upgrade Handling

```python
async def upgrade_subscription(user_id: str, new_plan_type: str) -> dict:
    """
    Upgrade a user's subscription with proration.

    Stripe handles proration automatically:
    - Credits remaining time on old plan
    - Charges proportional amount for new plan
    - Issues invoice for the difference
    """
    user_data = await get_user_data(user_id)
    subscription_id = user_data.get("subscription_id")

    if not subscription_id:
        raise HTTPException(status_code=400, detail="No active subscription to upgrade")

    new_price_id = PRICE_IDS.get(new_plan_type)
    if not new_price_id:
        raise HTTPException(status_code=400, detail=f"Invalid plan: {new_plan_type}")

    # Get current subscription
    subscription = stripe.Subscription.retrieve(subscription_id)
    current_item = subscription["items"]["data"][0]

    # Modify subscription with proration
    updated_subscription = stripe.Subscription.modify(
        subscription_id,
        items=[{
            "id": current_item["id"],
            "price": new_price_id,
        }],
        proration_behavior="create_prorations",  # or "always_invoice"
        metadata={
            "user_id": user_id,
            "plan_type": new_plan_type,
        },
    )

    # Update local state
    new_plan_details = PLAN_DETAILS.get(new_plan_type, {})
    await update_user_data(user_id, {
        "plan": new_plan_details.get("plan"),
        "credits": new_plan_details.get("credits", 0),
    })

    return {
        "success": True,
        "new_plan": new_plan_details.get("plan"),
        "new_credits": new_plan_details.get("credits", 0),
        "proration_amount": updated_subscription.get("latest_invoice"),
    }
```

### Downgrade Handling

```python
async def downgrade_subscription(user_id: str, new_plan_type: str) -> dict:
    """
    Downgrade subscription at end of current period.

    Best practice: Schedule the downgrade for period end so the user
    gets the full value of what they already paid for.
    """
    user_data = await get_user_data(user_id)
    subscription_id = user_data.get("subscription_id")

    if not subscription_id:
        raise HTTPException(status_code=400, detail="No active subscription")

    new_price_id = PRICE_IDS.get(new_plan_type)

    # Get current subscription
    subscription = stripe.Subscription.retrieve(subscription_id)
    current_item = subscription["items"]["data"][0]

    # Schedule downgrade for end of period (no proration)
    updated = stripe.Subscription.modify(
        subscription_id,
        items=[{
            "id": current_item["id"],
            "price": new_price_id,
        }],
        proration_behavior="none",  # No refund, change takes effect at renewal
        metadata={
            "user_id": user_id,
            "plan_type": new_plan_type,
            "pending_downgrade": "true",
        },
    )

    return {
        "success": True,
        "effective_at": datetime.fromtimestamp(subscription.current_period_end),
        "new_plan": PLAN_DETAILS.get(new_plan_type, {}).get("plan"),
        "message": "Downgrade will take effect at end of current billing period",
    }
```

### Proration Behavior Options

| Behavior | Use Case | Effect |
|----------|----------|--------|
| `create_prorations` | Upgrade mid-cycle | Credits remaining time, charges difference |
| `always_invoice` | Immediate upgrade invoice | Creates and pays invoice immediately |
| `none` | Downgrade at period end | No proration, change at next renewal |

---

## Credit System Integration

### Credit Deposit Model (Monthly Credits)

```python
# Credits are deposited monthly and expire at period end (use-it-or-lose-it)
# This is the "Netflix" model -- subscription buys monthly allocation

# Database model (uses database-orm-patterns module)
class UserCredits(Base):
    __tablename__ = "user_credits"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(255), unique=True, nullable=False, index=True)

    # Credit balance
    credits_balance = Column(Integer, default=0, nullable=False)
    credits_used_this_period = Column(Integer, default=0, nullable=False)

    # Plan info
    plan_type = Column(String(50), default="free")
    billing_source = Column(String(20), default="stripe")

    # Stripe integration
    stripe_customer_id = Column(String(255), nullable=True, index=True)
    stripe_subscription_id = Column(String(255), nullable=True)

    # Billing cycle
    current_period_start = Column(DateTime(timezone=True), nullable=True)
    current_period_end = Column(DateTime(timezone=True), nullable=True)
    cancel_at_period_end = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
```

### Atomic Credit Operations

```python
async def use_credit_atomic(user_id: str) -> dict:
    """
    Atomically use one credit with row-level locking.
    Prevents race conditions in concurrent requests.
    """
    async with get_session() as session:
        # SELECT ... FOR UPDATE (row-level lock)
        result = await session.execute(
            select(UserCredits)
            .where(UserCredits.user_id == user_id)
            .with_for_update()
        )
        user_credits = result.scalar_one_or_none()

        if not user_credits:
            return {"success": False, "error": "User not found"}

        if user_credits.credits_balance <= 0:
            # Agency plan: allow overage
            if user_credits.plan_type == "agency":
                user_credits.credits_used_this_period += 1
                await session.commit()
                return {
                    "success": True,
                    "credits_remaining": 0,
                    "overage": True,
                    "plan": "agency",
                }
            return {"success": False, "error": "No credits remaining"}

        user_credits.credits_balance -= 1
        user_credits.credits_used_this_period += 1
        await session.commit()

        return {
            "success": True,
            "credits_remaining": user_credits.credits_balance,
            "overage": False,
            "plan": user_credits.plan_type,
        }


async def add_credits_atomic(user_id: str, amount: int, reason: str = "purchase") -> dict:
    """Atomically add credits with row-level locking."""
    async with get_session() as session:
        result = await session.execute(
            select(UserCredits)
            .where(UserCredits.user_id == user_id)
            .with_for_update()
        )
        user_credits = result.scalar_one_or_none()

        if not user_credits:
            # Create new record
            user_credits = UserCredits(user_id=user_id, credits_balance=amount)
            session.add(user_credits)
        else:
            user_credits.credits_balance += amount

        await session.commit()

        return {
            "success": True,
            "new_balance": user_credits.credits_balance,
            "added": amount,
            "reason": reason,
        }
```

### Credit Pack Pricing Strategy

```python
# Pricing hierarchy: Subscriptions always cheaper per-credit than packs
# This encourages subscriptions over one-time purchases

CREDIT_PRICING = {
    # Subscriptions (per-credit cost)
    "agency_yearly":   1.06,   # BEST VALUE
    "agency_monthly":  1.33,
    "pro_yearly":      1.58,
    "pro_monthly":     1.98,
    "starter_yearly":  2.32,
    "starter_monthly": 2.90,

    # Credit Packs (one-time, higher per-credit cost)
    "pack_100": 2.08,  # 115 credits for $239
    "pack_50":  2.35,  # 55 credits for $129
    "pack_25":  2.56,  # 27 credits for $69
    "pack_10":  3.50,  # 10 credits for $35  (MOST EXPENSIVE)
}
```

---

## Mobile Integration

### Companion App Model

Mobile apps use a "companion app" model to avoid App Store 30% fee:
- In-app: Show features, use credits, display content
- Purchase: Redirect to web browser for Stripe checkout
- This follows Netflix, Kindle, Audible patterns

```tsx
// Platform detection
const isNative = Platform.isNative();  // Capacitor / React Native

const handlePurchase = async (planId: string) => {
  if (isNative) {
    // Native app: Open web browser for purchase (avoids 30% fee)
    const returnUrl = `yourapp://purchase-complete?plan=${planId}`;
    await openPurchasePage(returnUrl);
  } else {
    // Web: Direct Stripe checkout
    const response = await fetch('/api/v1/payments/create-checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan_type: planId }),
    });
    const { checkout_url } = await response.json();
    window.location.href = checkout_url;
  }
};
```

### RevenueCat Integration (via mobile-subscription module)

For apps that DO sell through App Store/Play Store (with 30% fee), use the `mobile-subscription` module for RevenueCat integration:

```
See: mobile-subscription module
  - RevenueCat SDK setup
  - Server-side receipt validation
  - Cross-platform entitlement sync
  - Stripe <-> RevenueCat subscription mapping
```

Key bridging pattern:

```python
# Sync RevenueCat subscription to your Stripe customer record
async def sync_mobile_subscription(user_id: str, revenuecat_data: dict):
    """
    When a user subscribes via mobile (RevenueCat),
    update the same user record used by Stripe web subscriptions.
    """
    await update_user_data(user_id, {
        "plan": revenuecat_data["entitlements"]["pro"]["product_identifier"],
        "billing_source": "revenuecat",
        "credits": PLAN_DETAILS.get(revenuecat_data["plan"], {}).get("credits", 0),
    })
```

---

## Environment Variables

```bash
# =============================================================================
# STRIPE API KEYS
# =============================================================================
STRIPE_SECRET_KEY=sk_test_xxx          # Backend: API calls
STRIPE_PUBLISHABLE_KEY=pk_test_xxx     # Frontend: Stripe.js initialization
STRIPE_WEBHOOK_SECRET=whsec_xxx        # Webhook: Signature verification

# =============================================================================
# SUBSCRIPTION PRICE IDS (from Stripe Dashboard > Products)
# =============================================================================
STRIPE_PRICE_STARTER_MONTHLY=price_xxx
STRIPE_PRICE_STARTER_YEARLY=price_xxx
STRIPE_PRICE_PRO_MONTHLY=price_xxx
STRIPE_PRICE_PRO_YEARLY=price_xxx
STRIPE_PRICE_AGENCY_MONTHLY=price_xxx
STRIPE_PRICE_AGENCY_YEARLY=price_xxx

# =============================================================================
# CREDIT PACK PRICE IDS (one-time payments)
# =============================================================================
STRIPE_PRICE_PACK_10=price_xxx
STRIPE_PRICE_PACK_25=price_xxx
STRIPE_PRICE_PACK_50=price_xxx
STRIPE_PRICE_PACK_100=price_xxx

# =============================================================================
# USAGE-BASED BILLING (optional)
# =============================================================================
STRIPE_PRICE_AGENCY_OVERAGE=price_xxx  # Metered price for overage

# =============================================================================
# APPLICATION URLS
# =============================================================================
APP_URL=https://yourdomain.com
STRIPE_SUCCESS_URL=https://yourdomain.com/dashboard?payment=success
STRIPE_CANCEL_URL=https://yourdomain.com/pricing
```

### Environment Separation

```bash
# CRITICAL: Use separate keys for each environment

# Development
STRIPE_SECRET_KEY=sk_test_xxx

# Staging
STRIPE_SECRET_KEY=sk_test_yyy  # Different test account

# Production
STRIPE_SECRET_KEY=sk_live_xxx  # LIVE key
```

### Public Config Endpoint

```python
@router.get("/config")
async def get_stripe_config():
    """
    Expose publishable key to frontend. This is SAFE to expose.
    Never expose the secret key.
    """
    return {
        "publishable_key": STRIPE_PUBLISHABLE_KEY,
        "plans": {
            k: {
                "credits": v.get("credits"),
                "plan": v.get("plan"),
                "billing": v.get("billing"),
            }
            for k, v in PLAN_DETAILS.items()
        }
    }
```

---

## Testing Guide

### Stripe Test Cards

```
# Successful payment
4242 4242 4242 4242   Visa (always succeeds)
5555 5555 5555 4444   Mastercard

# Declined
4000 0000 0000 0002   Generic decline
4000 0000 0000 9995   Insufficient funds

# 3D Secure / SCA Required
4000 0027 6000 3184   Authentication required
4000 0025 0000 3155   Always requires 3DS

# Fraud detection
4000 0000 0000 9235   Flagged by Radar as fraudulent

# For all test cards: any future expiry, any 3-digit CVC, any ZIP
```

### Local Webhook Testing

```bash
# 1. Install Stripe CLI
brew install stripe/stripe-cli/stripe

# 2. Login to your Stripe account
stripe login

# 3. Forward webhooks to local server
stripe listen --forward-to localhost:3000/api/v1/payments/webhook

# 4. In another terminal, trigger test events
stripe trigger checkout.session.completed
stripe trigger invoice.paid
stripe trigger customer.subscription.updated
stripe trigger customer.subscription.deleted
stripe trigger invoice.payment_failed
```

### Stripe Product Setup Script

```bash
#!/bin/bash
# stripe-setup.sh - Create products and prices

# Starter Plan
stripe products create \
  --name="YourApp Starter" \
  --description="10 credits per month" \
  --metadata[tier]="starter" \
  --metadata[credits_monthly]="10"

stripe prices create \
  --product="YourApp Starter" \
  --unit-amount=2900 \
  --currency=usd \
  --recurring[interval]=month \
  --metadata[plan]="starter_monthly"

stripe prices create \
  --product="YourApp Starter" \
  --unit-amount=27840 \
  --currency=usd \
  --recurring[interval]=year \
  --metadata[plan]="starter_yearly"

# Pro Plan
stripe products create \
  --name="YourApp Pro" \
  --description="40 credits per month" \
  --metadata[tier]="pro" \
  --metadata[credits_monthly]="40"

stripe prices create \
  --product="YourApp Pro" \
  --unit-amount=7900 \
  --currency=usd \
  --recurring[interval]=month \
  --metadata[plan]="pro_monthly"

stripe prices create \
  --product="YourApp Pro" \
  --unit-amount=75840 \
  --currency=usd \
  --recurring[interval]=year \
  --metadata[plan]="pro_yearly"

# Agency Plan
stripe products create \
  --name="YourApp Agency" \
  --description="150 credits per month" \
  --metadata[tier]="agency" \
  --metadata[credits_monthly]="150"

stripe prices create \
  --product="YourApp Agency" \
  --unit-amount=19900 \
  --currency=usd \
  --recurring[interval]=month \
  --metadata[plan]="agency_monthly"

stripe prices create \
  --product="YourApp Agency" \
  --unit-amount=191040 \
  --currency=usd \
  --recurring[interval]=year \
  --metadata[plan]="agency_yearly"

echo "Done! Run: stripe prices list --limit=20 to get price IDs"
```

### Integration Test Checklist

```
Checkout Flow:
  [ ] Subscription checkout (monthly)
  [ ] Subscription checkout (yearly)
  [ ] One-time credit pack purchase
  [ ] Checkout with promotion code
  [ ] Checkout cancellation (user clicks back)

Webhook Processing:
  [ ] checkout.session.completed (subscription)
  [ ] checkout.session.completed (one-time)
  [ ] invoice.paid (renewal)
  [ ] invoice.payment_failed
  [ ] customer.subscription.updated
  [ ] customer.subscription.deleted
  [ ] Duplicate event (idempotency check)
  [ ] Invalid signature (rejection)

Subscription Lifecycle:
  [ ] Create subscription
  [ ] Cancel at period end
  [ ] Reactivate canceled subscription
  [ ] Upgrade (starter -> pro)
  [ ] Downgrade (pro -> starter)
  [ ] Subscription expiry

Credits:
  [ ] Credits deposited on subscription start
  [ ] Credits reset on renewal
  [ ] Credits preserved on cancellation
  [ ] Atomic credit deduction (concurrent requests)
  [ ] Credit pack purchase adds to balance

Customer Portal:
  [ ] Portal session creation
  [ ] Update payment method
  [ ] View invoices
  [ ] Cancel from portal

Usage-Based:
  [ ] Record metered usage
  [ ] Agency overage billing
```

---

## Troubleshooting

### Common Errors

**Error**: `Webhook signature verification failed`
```
Cause: Raw body was parsed before reaching verification
Fix: Ensure webhook route uses raw body middleware:
  - Express: express.raw({ type: 'application/json' })
  - FastAPI: await request.body() (not request.json())
Check: STRIPE_WEBHOOK_SECRET matches the endpoint's signing secret
```

**Error**: `No such price: price_xxx`
```
Cause: Price ID does not exist or belongs to wrong mode (test vs live)
Fix: Verify STRIPE_PRICE_* env vars match your Stripe Dashboard
Check: Are you using test keys with test prices? Live keys with live prices?
```

**Error**: `No such customer: cus_xxx`
```
Cause: Customer was created in different mode or deleted
Fix: Re-create customer mapping with get_or_create_customer()
Check: stripe.api_key mode matches the customer's mode
```

**Error**: `This customer has no attached payment source or default payment method`
```
Cause: Trying to create subscription without checkout
Fix: Use Checkout Sessions (not direct Subscription.create) for new customers
```

**Error**: `Idempotency key used with different parameters`
```
Cause: Same idempotency key reused for different request
Fix: Generate unique keys per request using order_id + uuid
```

**Error**: Credits not deposited after checkout
```
Cause: Webhook not reaching your server or handler failing
Fix:
  1. Check Stripe Dashboard > Developers > Webhooks for delivery status
  2. Check server logs for webhook processing errors
  3. Verify STRIPE_WEBHOOK_SECRET is correct
  4. Ensure user_id is in session metadata
```

---

## Integrates With

### Direct Dependencies

| Module/Skill | How It's Used |
|-------------|---------------|
| **payment-processing-universal** | Base PCI-DSS compliance, multi-provider patterns. This skill EXTENDS it with Stripe-specific subscription billing. |
| **unified-api-client** | HTTP client patterns for Stripe SDK calls, retry logic, error handling. |
| **database-orm-patterns** | Subscription state storage, atomic credit operations with row-level locking, webhook idempotency table. |
| **notification-universal** | Payment confirmation emails, failed payment alerts, cancellation win-back campaigns. |

### Optional Dependencies

| Module/Skill | How It's Used |
|-------------|---------------|
| **mobile-subscription** | RevenueCat integration for iOS/Android in-app purchases. Bridges mobile subscriptions to same user record used by Stripe web subscriptions. |
| **auth-universal** | User authentication for payment endpoints (Firebase Auth, JWT, etc.). |
| **analytics-universal** | Conversion tracking, revenue analytics, churn metrics. |
| **rate-limiting-universal** | Protect checkout and webhook endpoints from abuse. |

### Relationship to payment-processing-universal

```
payment-processing-universal:
  - PCI-DSS SAQ-A compliance rules
  - Multi-provider adapter pattern (Stripe + PayPal + Square)
  - Generic webhook security patterns
  - Idempotency concepts
  - Fraud prevention (Radar overview)
  - Test card numbers
  - Refund handling

stripe-subscription-billing (THIS SKILL):
  - Stripe Checkout Sessions (one-time + subscription modes)
  - Stripe-specific webhook handlers (5 events, full code)
  - Subscription lifecycle state machine
  - Customer Portal integration
  - Usage-based metered billing
  - SaaS tier management (Free/Starter/Pro/Agency)
  - Credit deposit model with atomic operations
  - Proration and plan change handling
  - Mobile companion app billing
  - Production-ready code (Python + Node.js)
```

---

## Resources

- **Stripe Checkout**: https://stripe.com/docs/checkout
- **Stripe Billing**: https://stripe.com/docs/billing
- **Stripe Webhooks**: https://stripe.com/docs/webhooks
- **Customer Portal**: https://stripe.com/docs/billing/subscriptions/integrating-customer-portal
- **Usage-Based Billing**: https://stripe.com/docs/billing/subscriptions/usage-based
- **Stripe CLI**: https://stripe.com/docs/stripe-cli
- **Test Cards**: https://stripe.com/docs/testing

---

**This skill is production-ready. All patterns extracted from live SaaS applications processing real Stripe payments.**

---

# Research Update: February 2026

| Topic | Update |
|-------|--------|
| API Version | Current: `2026-01-28.clover`. Update `apiVersion` in Stripe client initialization. |
| SDK Version | `stripe` npm package: 20.3.1. Major version jump from 14.x. |
| Deprecations | `payments` capability type deprecated (use per-location types). Issuing Authorization `id` property deprecated. Non-namespaced `StripeClient` services deprecated. |
| Best Practice | Use namespaced services under `StripeClient` (e.g., `stripe.subscriptions.create()` not top-level). |

**Action items:**
- Update API version to `2026-01-28.clover` in all Stripe client configs
- Migrate from non-namespaced to namespaced StripeClient services
- Review `payments` capability usage and switch to per-location types
