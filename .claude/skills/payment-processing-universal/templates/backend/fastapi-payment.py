"""
Payment Processing Universal - FastAPI Implementation

Multi-provider payment processing with PCI-DSS compliance.

Providers:
- Stripe (primary - best developer experience, modern features)
- PayPal (fallback - high customer trust, global reach)
- Square (optional - in-person payments, POS integration)

PCI Compliance: SAQ-A (Simplest Level)
- NEVER touch card data (use provider SDKs)
- Card data goes directly from frontend to provider
- We only receive payment tokens

Security Features:
- Webhook signature verification (prevent spoofing)
- Idempotency (prevent duplicate charges)
- HTTPS only
- No card numbers in logs
- API keys in environment variables

OWASP Compliance:
- A03:2021 Injection (no card data in requests)
- A04:2021 Insecure Design (provider SDKs handle card processing)
- A05:2021 Security Misconfiguration (HTTPS, env vars)
- A07:2021 Auth Failures (webhook signature verification)
- A09:2021 Logging Failures (no sensitive data in logs)

Installation:
  pip install fastapi uvicorn stripe paypalrestsdk redis pydantic

Environment Variables:
  # Stripe (primary)
  STRIPE_PUBLISHABLE_KEY=pk_test_your_publishable_key
  STRIPE_SECRET_KEY=sk_test_your_secret_key
  STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

  # PayPal (fallback)
  PAYPAL_CLIENT_ID=your_paypal_client_id
  PAYPAL_CLIENT_SECRET=your_paypal_client_secret
  PAYPAL_MODE=sandbox  # or 'live'
  PAYPAL_WEBHOOK_ID=your_webhook_id

  # Redis (idempotency)
  REDIS_URL=redis://localhost:6379

  # App configuration
  APP_URL=https://yourdomain.com
  PAYMENT_CURRENCY=usd

Usage:
  from fastapi import FastAPI
  from payment_service import PaymentService, PaymentProvider

  app = FastAPI()
  payment_service = PaymentService(redis_url=os.environ.get('REDIS_URL'))

  @app.on_event("startup")
  async def startup():
      await payment_service.initialize()

  @app.post("/api/payment/create")
  async def create_payment(amount: int, provider: str = PaymentProvider.STRIPE):
      result = await payment_service.create_payment(
          amount=amount,
          currency='usd',
          provider=provider,
          metadata={'order_id': '12345'}
      )
      return result
"""

from fastapi import FastAPI, Request, Response, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from enum import Enum
import stripe
import paypalrestsdk
import os
import logging
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta
import redis.asyncio as aioredis

# ============================================================================
# CONFIGURATION
# ============================================================================

# Configure Stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

# Configure PayPal
paypalrestsdk.configure({
    "mode": os.environ.get('PAYPAL_MODE', 'sandbox'),
    "client_id": os.environ.get('PAYPAL_CLIENT_ID'),
    "client_secret": os.environ.get('PAYPAL_CLIENT_SECRET')
})

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# ENUMS AND MODELS
# ============================================================================

class PaymentProvider(str, Enum):
    """Supported payment providers"""
    STRIPE = "stripe"
    PAYPAL = "paypal"
    SQUARE = "square"


class PaymentStatus(str, Enum):
    """Payment status"""
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"
    REFUNDED = "refunded"


class RefundReason(str, Enum):
    """Refund reasons"""
    REQUESTED_BY_CUSTOMER = "requested_by_customer"
    DUPLICATE = "duplicate"
    FRAUDULENT = "fraudulent"


class CreatePaymentRequest(BaseModel):
    """Request to create payment"""
    amount: int = Field(..., description="Amount in cents (e.g., 1000 = $10.00)", gt=0)
    currency: str = Field(default="usd", description="Currency code (e.g., 'usd', 'eur')")
    provider: PaymentProvider = Field(default=PaymentProvider.STRIPE)
    payment_method_id: Optional[str] = Field(None, description="Payment method token from provider")
    customer_email: Optional[str] = Field(None, description="Customer email")
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict, description="Custom metadata")
    idempotency_key: Optional[str] = Field(None, description="Idempotency key to prevent duplicates")


class CreateSubscriptionRequest(BaseModel):
    """Request to create subscription"""
    customer_email: str = Field(..., description="Customer email")
    payment_method_id: str = Field(..., description="Payment method token")
    price_id: str = Field(..., description="Price ID from provider")
    provider: PaymentProvider = Field(default=PaymentProvider.STRIPE)
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict)


class RefundRequest(BaseModel):
    """Request to refund payment"""
    payment_id: str = Field(..., description="Payment ID to refund")
    amount: Optional[int] = Field(None, description="Amount to refund (cents). None = full refund")
    reason: RefundReason = Field(default=RefundReason.REQUESTED_BY_CUSTOMER)


# ============================================================================
# SECURITY HELPERS
# ============================================================================

def generate_idempotency_key(prefix: str, unique_id: str) -> str:
    """
    Generate idempotency key for payment request

    Idempotency prevents duplicate charges if request is retried

    Example:
        key = generate_idempotency_key('order', '12345')
        # Returns: 'order_12345_1705523456'
    """
    timestamp = int(time.time())
    return f"{prefix}_{unique_id}_{timestamp}"


def mask_card_number(card_number: str) -> str:
    """
    Mask card number for logging (PCI compliance)

    Security: NEVER log full card numbers

    Example:
        mask_card_number('4242424242424242')
        # Returns: '****4242'
    """
    if not card_number or len(card_number) < 4:
        return "****"
    return f"****{card_number[-4:]}"


def mask_email(email: str) -> str:
    """
    Mask email for logging (PII protection)

    Example:
        mask_email('user@example.com')
        # Returns: 'u***@example.com'
    """
    if not email or '@' not in email:
        return "***"

    local, domain = email.split('@')
    masked_local = local[0] + '***' if len(local) > 1 else '***'
    return f"{masked_local}@{domain}"


# ============================================================================
# STRIPE PROVIDER
# ============================================================================

class StripeProvider:
    """
    Stripe payment provider

    Best For: Online payments, subscriptions, modern features
    Fees: 2.9% + $0.30 per transaction (US cards)
    PCI: SAQ-A (simplest level, Stripe handles card data)
    """

    def __init__(self):
        self.api_key = os.environ.get('STRIPE_SECRET_KEY')
        if not self.api_key:
            raise ValueError("STRIPE_SECRET_KEY environment variable not set")

        stripe.api_key = self.api_key
        logger.info("[PAYMENT] Stripe provider initialized")

    async def create_payment_intent(
        self,
        amount: int,
        currency: str,
        payment_method_id: Optional[str] = None,
        customer_email: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        idempotency_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create Stripe Payment Intent

        Payment Intent: Tracks payment from creation to settlement

        Flow:
        1. Backend creates Payment Intent (returns client_secret)
        2. Frontend uses Stripe.js to confirm payment (with card)
        3. Webhook confirms payment success/failure

        Args:
            amount: Amount in cents (e.g., 1000 = $10.00)
            currency: Currency code (e.g., 'usd')
            payment_method_id: Payment method token (from Stripe Elements)
            customer_email: Customer email (for receipt)
            metadata: Custom metadata (e.g., {'order_id': '12345'})
            idempotency_key: Prevent duplicate charges

        Returns:
            {
                'payment_intent_id': 'pi_abc123',
                'client_secret': 'pi_abc123_secret_xyz',
                'status': 'requires_payment_method',
                'amount': 1000,
                'currency': 'usd'
            }
        """
        try:
            # Prepare payment intent parameters
            params = {
                'amount': amount,
                'currency': currency,
                'automatic_payment_methods': {'enabled': True},
                'metadata': metadata or {}
            }

            if payment_method_id:
                params['payment_method'] = payment_method_id
                params['confirm'] = True  # Automatically confirm

            if customer_email:
                params['receipt_email'] = customer_email

            # Create payment intent with idempotency
            if idempotency_key:
                payment_intent = stripe.PaymentIntent.create(
                    **params,
                    idempotency_key=idempotency_key
                )
            else:
                payment_intent = stripe.PaymentIntent.create(**params)

            logger.info(f"[PAYMENT] Stripe Payment Intent created: {payment_intent.id} "
                       f"for {mask_email(customer_email or 'guest')}")

            return {
                'payment_intent_id': payment_intent.id,
                'client_secret': payment_intent.client_secret,
                'status': payment_intent.status,
                'amount': payment_intent.amount,
                'currency': payment_intent.currency,
                'provider': PaymentProvider.STRIPE
            }

        except stripe.error.CardError as e:
            # Card was declined
            logger.warning(f"[PAYMENT] Stripe card declined: {e.user_message}")
            raise HTTPException(status_code=400, detail=e.user_message)

        except stripe.error.StripeError as e:
            # Other Stripe errors
            logger.error(f"[PAYMENT] Stripe error: {str(e)}")
            raise HTTPException(status_code=500, detail="Payment processing error")

    async def create_customer(self, email: str, payment_method_id: str) -> str:
        """
        Create Stripe Customer (for subscriptions)

        Returns:
            customer_id: 'cus_abc123'
        """
        try:
            customer = stripe.Customer.create(
                email=email,
                payment_method=payment_method_id,
                invoice_settings={
                    'default_payment_method': payment_method_id
                }
            )

            logger.info(f"[PAYMENT] Stripe customer created: {customer.id} for {mask_email(email)}")
            return customer.id

        except stripe.error.StripeError as e:
            logger.error(f"[PAYMENT] Stripe customer creation failed: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create customer")

    async def create_subscription(
        self,
        customer_id: str,
        price_id: str,
        metadata: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Create Stripe Subscription

        Subscription: Recurring billing (monthly, yearly, etc.)

        Setup:
        1. Create price in Stripe Dashboard (e.g., $10/month)
        2. Get price_id (e.g., 'price_1234')
        3. Create subscription with price_id

        Args:
            customer_id: Customer ID from create_customer()
            price_id: Price ID from Stripe Dashboard
            metadata: Custom metadata

        Returns:
            {
                'subscription_id': 'sub_abc123',
                'status': 'active',
                'current_period_end': 1705523456
            }
        """
        try:
            subscription = stripe.Subscription.create(
                customer=customer_id,
                items=[{'price': price_id}],
                metadata=metadata or {},
                expand=['latest_invoice.payment_intent']
            )

            logger.info(f"[PAYMENT] Stripe subscription created: {subscription.id}")

            return {
                'subscription_id': subscription.id,
                'status': subscription.status,
                'current_period_end': subscription.current_period_end,
                'provider': PaymentProvider.STRIPE
            }

        except stripe.error.StripeError as e:
            logger.error(f"[PAYMENT] Stripe subscription creation failed: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create subscription")

    async def cancel_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Cancel Stripe subscription"""
        try:
            subscription = stripe.Subscription.delete(subscription_id)
            logger.info(f"[PAYMENT] Stripe subscription canceled: {subscription_id}")

            return {
                'subscription_id': subscription.id,
                'status': subscription.status,
                'canceled_at': subscription.canceled_at
            }

        except stripe.error.StripeError as e:
            logger.error(f"[PAYMENT] Stripe subscription cancellation failed: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to cancel subscription")

    async def create_refund(
        self,
        payment_intent_id: str,
        amount: Optional[int] = None,
        reason: str = RefundReason.REQUESTED_BY_CUSTOMER
    ) -> Dict[str, Any]:
        """
        Refund Stripe payment

        Args:
            payment_intent_id: Payment Intent ID to refund
            amount: Amount to refund (cents). None = full refund
            reason: Refund reason

        Returns:
            {
                'refund_id': 'ref_abc123',
                'status': 'succeeded',
                'amount': 1000
            }
        """
        try:
            params = {
                'payment_intent': payment_intent_id,
                'reason': reason
            }

            if amount is not None:
                params['amount'] = amount

            refund = stripe.Refund.create(**params)

            logger.info(f"[PAYMENT] Stripe refund created: {refund.id} for {payment_intent_id}")

            return {
                'refund_id': refund.id,
                'status': refund.status,
                'amount': refund.amount,
                'provider': PaymentProvider.STRIPE
            }

        except stripe.error.StripeError as e:
            logger.error(f"[PAYMENT] Stripe refund failed: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create refund")

    async def verify_webhook_signature(self, payload: bytes, signature: str) -> Any:
        """
        Verify Stripe webhook signature

        Security: CRITICAL - prevents webhook spoofing attacks

        Attack without verification:
            Attacker sends fake webhook → "payment_intent.succeeded"
            → We fulfill fake order → Lost money!

        Args:
            payload: Raw request body (bytes)
            signature: 'stripe-signature' header

        Returns:
            event: Verified Stripe event

        Raises:
            ValueError: Invalid payload
            stripe.error.SignatureVerificationError: Invalid signature (attack!)
        """
        webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
        if not webhook_secret:
            raise ValueError("STRIPE_WEBHOOK_SECRET not configured")

        try:
            event = stripe.Webhook.construct_event(
                payload, signature, webhook_secret
            )
            return event

        except ValueError as e:
            logger.error(f"[PAYMENT] Invalid webhook payload: {e}")
            raise

        except stripe.error.SignatureVerificationError as e:
            logger.warning(f"[PAYMENT] Webhook signature verification failed: {e}")
            raise


# ============================================================================
# PAYPAL PROVIDER
# ============================================================================

class PayPalProvider:
    """
    PayPal payment provider

    Best For: Customer trust, global reach, buyer protection
    Fees: 3.49% + $0.49 per transaction (US)
    PCI: SAQ-A (PayPal handles card data)
    """

    def __init__(self):
        self.client_id = os.environ.get('PAYPAL_CLIENT_ID')
        self.client_secret = os.environ.get('PAYPAL_CLIENT_SECRET')
        self.mode = os.environ.get('PAYPAL_MODE', 'sandbox')

        if not self.client_id or not self.client_secret:
            raise ValueError("PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET required")

        paypalrestsdk.configure({
            "mode": self.mode,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        })

        logger.info(f"[PAYMENT] PayPal provider initialized (mode: {self.mode})")

    async def create_order(
        self,
        amount: int,
        currency: str,
        metadata: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Create PayPal Order

        Flow:
        1. Backend creates order (returns approval URL)
        2. Customer redirects to PayPal to approve
        3. PayPal redirects back to return_url
        4. Backend executes order (captures payment)

        Args:
            amount: Amount in cents (e.g., 1000 = $10.00)
            currency: Currency code (e.g., 'USD')
            metadata: Custom metadata

        Returns:
            {
                'order_id': 'PAYID-abc123',
                'approval_url': 'https://paypal.com/checkoutnow?token=...',
                'status': 'CREATED'
            }
        """
        try:
            # Convert cents to dollars
            amount_decimal = f"{amount / 100:.2f}"

            payment = paypalrestsdk.Payment({
                "intent": "sale",
                "payer": {"payment_method": "paypal"},
                "redirect_urls": {
                    "return_url": f"{os.environ.get('APP_URL')}/payment/paypal/success",
                    "cancel_url": f"{os.environ.get('APP_URL')}/payment/paypal/cancel"
                },
                "transactions": [{
                    "amount": {
                        "total": amount_decimal,
                        "currency": currency.upper()
                    },
                    "description": metadata.get('description', 'Payment') if metadata else 'Payment',
                    "custom": json.dumps(metadata) if metadata else '{}'
                }]
            })

            if payment.create():
                # Get approval URL
                approval_url = None
                for link in payment.links:
                    if link.rel == "approval_url":
                        approval_url = link.href
                        break

                logger.info(f"[PAYMENT] PayPal order created: {payment.id}")

                return {
                    'order_id': payment.id,
                    'approval_url': approval_url,
                    'status': payment.state.upper(),
                    'provider': PaymentProvider.PAYPAL
                }
            else:
                logger.error(f"[PAYMENT] PayPal order creation failed: {payment.error}")
                raise HTTPException(status_code=500, detail="PayPal order creation failed")

        except Exception as e:
            logger.error(f"[PAYMENT] PayPal error: {str(e)}")
            raise HTTPException(status_code=500, detail="Payment processing error")

    async def execute_order(self, payment_id: str, payer_id: str) -> Dict[str, Any]:
        """
        Execute PayPal order (capture payment)

        Called after customer approves payment on PayPal site

        Args:
            payment_id: Payment ID from create_order()
            payer_id: Payer ID from PayPal redirect

        Returns:
            {
                'payment_id': 'PAYID-abc123',
                'status': 'APPROVED',
                'amount': 1000
            }
        """
        try:
            payment = paypalrestsdk.Payment.find(payment_id)

            if payment.execute({"payer_id": payer_id}):
                logger.info(f"[PAYMENT] PayPal order executed: {payment_id}")

                # Extract amount
                amount_str = payment.transactions[0].amount.total
                amount_cents = int(float(amount_str) * 100)

                return {
                    'payment_id': payment.id,
                    'status': payment.state.upper(),
                    'amount': amount_cents,
                    'provider': PaymentProvider.PAYPAL
                }
            else:
                logger.error(f"[PAYMENT] PayPal execution failed: {payment.error}")
                raise HTTPException(status_code=500, detail="PayPal execution failed")

        except Exception as e:
            logger.error(f"[PAYMENT] PayPal execution error: {str(e)}")
            raise HTTPException(status_code=500, detail="Payment execution error")

    async def create_refund(
        self,
        sale_id: str,
        amount: Optional[int] = None,
        currency: str = "USD"
    ) -> Dict[str, Any]:
        """
        Refund PayPal payment

        Args:
            sale_id: Sale ID from execute_order()
            amount: Amount to refund (cents). None = full refund
            currency: Currency code

        Returns:
            {
                'refund_id': 'ref_abc123',
                'status': 'completed',
                'amount': 1000
            }
        """
        try:
            sale = paypalrestsdk.Sale.find(sale_id)

            params = {}
            if amount is not None:
                amount_decimal = f"{amount / 100:.2f}"
                params['amount'] = {
                    'total': amount_decimal,
                    'currency': currency.upper()
                }

            refund = sale.refund(params)

            if refund.success():
                logger.info(f"[PAYMENT] PayPal refund created: {refund.id}")

                refund_amount = int(float(refund.amount.total) * 100)

                return {
                    'refund_id': refund.id,
                    'status': refund.state,
                    'amount': refund_amount,
                    'provider': PaymentProvider.PAYPAL
                }
            else:
                logger.error(f"[PAYMENT] PayPal refund failed: {refund.error}")
                raise HTTPException(status_code=500, detail="PayPal refund failed")

        except Exception as e:
            logger.error(f"[PAYMENT] PayPal refund error: {str(e)}")
            raise HTTPException(status_code=500, detail="Refund processing error")


# ============================================================================
# PAYMENT SERVICE
# ============================================================================

class PaymentService:
    """
    Main payment service with multi-provider support

    Features:
    - Multi-provider (Stripe, PayPal)
    - Idempotency (prevent duplicate charges)
    - Webhook handling
    - Refunds
    - Subscriptions
    """

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis = None
        self.providers = {}

    async def initialize(self):
        """Initialize payment service"""
        # Connect to Redis (for idempotency)
        self.redis = await aioredis.from_url(self.redis_url)

        # Initialize providers
        try:
            self.providers[PaymentProvider.STRIPE] = StripeProvider()
        except ValueError as e:
            logger.warning(f"Stripe not configured: {e}")

        try:
            self.providers[PaymentProvider.PAYPAL] = PayPalProvider()
        except ValueError as e:
            logger.warning(f"PayPal not configured: {e}")

        if not self.providers:
            raise ValueError("No payment providers configured")

        logger.info("[PAYMENT] Payment service initialized")

    async def create_payment(
        self,
        amount: int,
        currency: str = "usd",
        provider: PaymentProvider = PaymentProvider.STRIPE,
        payment_method_id: Optional[str] = None,
        customer_email: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        idempotency_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create payment with idempotency

        Idempotency: Prevents duplicate charges if request is retried

        Example:
            # First request
            payment1 = await create_payment(..., idempotency_key='order_12345_1')

            # Network fails, customer retries
            payment2 = await create_payment(..., idempotency_key='order_12345_1')

            # payment1.id == payment2.id (no duplicate charge!)
        """
        # Check idempotency
        if idempotency_key:
            cached = await self.redis.get(f"idempotency:{idempotency_key}")
            if cached:
                logger.info(f"[PAYMENT] Idempotent request, returning cached result")
                return json.loads(cached)

        # Get provider
        provider_instance = self.providers.get(provider)
        if not provider_instance:
            raise HTTPException(status_code=400, detail=f"Provider {provider} not available")

        # Create payment
        if provider == PaymentProvider.STRIPE:
            result = await provider_instance.create_payment_intent(
                amount=amount,
                currency=currency,
                payment_method_id=payment_method_id,
                customer_email=customer_email,
                metadata=metadata,
                idempotency_key=idempotency_key
            )
        elif provider == PaymentProvider.PAYPAL:
            result = await provider_instance.create_order(
                amount=amount,
                currency=currency,
                metadata=metadata
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")

        # Cache result for idempotency (1 hour TTL)
        if idempotency_key:
            await self.redis.setex(
                f"idempotency:{idempotency_key}",
                3600,
                json.dumps(result)
            )

        return result

    async def create_subscription(
        self,
        customer_email: str,
        payment_method_id: str,
        price_id: str,
        provider: PaymentProvider = PaymentProvider.STRIPE,
        metadata: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create subscription (Stripe only for now)"""
        if provider != PaymentProvider.STRIPE:
            raise HTTPException(status_code=400, detail="Subscriptions only supported on Stripe")

        stripe_provider = self.providers[PaymentProvider.STRIPE]

        # Create customer
        customer_id = await stripe_provider.create_customer(
            email=customer_email,
            payment_method_id=payment_method_id
        )

        # Create subscription
        subscription = await stripe_provider.create_subscription(
            customer_id=customer_id,
            price_id=price_id,
            metadata=metadata
        )

        return subscription

    async def cancel_subscription(
        self,
        subscription_id: str,
        provider: PaymentProvider = PaymentProvider.STRIPE
    ) -> Dict[str, Any]:
        """Cancel subscription"""
        if provider != PaymentProvider.STRIPE:
            raise HTTPException(status_code=400, detail="Subscriptions only supported on Stripe")

        stripe_provider = self.providers[PaymentProvider.STRIPE]
        return await stripe_provider.cancel_subscription(subscription_id)

    async def create_refund(
        self,
        payment_id: str,
        provider: PaymentProvider,
        amount: Optional[int] = None,
        reason: str = RefundReason.REQUESTED_BY_CUSTOMER
    ) -> Dict[str, Any]:
        """Create refund"""
        provider_instance = self.providers.get(provider)
        if not provider_instance:
            raise HTTPException(status_code=400, detail=f"Provider {provider} not available")

        return await provider_instance.create_refund(
            payment_intent_id=payment_id,
            amount=amount,
            reason=reason
        )

    async def close(self):
        """Close connections"""
        if self.redis:
            await self.redis.close()


# ============================================================================
# WEBHOOK HANDLERS
# ============================================================================

async def handle_stripe_webhook(
    request: Request,
    payment_service: PaymentService
) -> Dict[str, str]:
    """
    Handle Stripe webhook

    Security: CRITICAL - Verify signature to prevent spoofing

    Setup:
    1. Stripe Dashboard → Developers → Webhooks → Add Endpoint
    2. URL: https://yourdomain.com/webhooks/stripe
    3. Events: payment_intent.succeeded, payment_intent.payment_failed
    4. Copy webhook secret to STRIPE_WEBHOOK_SECRET
    """
    payload = await request.body()
    signature = request.headers.get('stripe-signature')

    if not signature:
        raise HTTPException(status_code=400, detail="Missing signature")

    try:
        # Verify signature (prevents spoofing)
        stripe_provider = payment_service.providers[PaymentProvider.STRIPE]
        event = await stripe_provider.verify_webhook_signature(payload, signature)

    except (ValueError, stripe.error.SignatureVerificationError) as e:
        logger.warning(f"[PAYMENT] Invalid webhook: {e}")
        raise HTTPException(status_code=400, detail="Invalid webhook")

    # Handle events
    event_type = event['type']

    if event_type == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        logger.info(f"[PAYMENT] Payment succeeded: {payment_intent['id']}")

        # TODO: Fulfill order using payment_intent.metadata.order_id
        # await fulfill_order(payment_intent['metadata']['order_id'])

    elif event_type == 'payment_intent.payment_failed':
        payment_intent = event['data']['object']
        logger.warning(f"[PAYMENT] Payment failed: {payment_intent['id']}")

        # TODO: Notify customer of failure

    elif event_type == 'invoice.payment_succeeded':
        invoice = event['data']['object']
        logger.info(f"[PAYMENT] Subscription payment succeeded: {invoice['id']}")

        # TODO: Extend subscription

    elif event_type == 'invoice.payment_failed':
        invoice = event['data']['object']
        logger.warning(f"[PAYMENT] Subscription payment failed: {invoice['id']}")

        # TODO: Notify customer, retry payment

    return {"status": "success"}


async def handle_paypal_webhook(
    request: Request,
    payment_service: PaymentService
) -> Dict[str, str]:
    """
    Handle PayPal webhook

    Setup:
    1. PayPal Dashboard → Developer → My Apps & Credentials
    2. Create Webhook
    3. URL: https://yourdomain.com/webhooks/paypal
    4. Events: PAYMENT.SALE.COMPLETED, PAYMENT.SALE.REFUNDED
    """
    payload = await request.body()
    event = json.loads(payload)

    # TODO: Verify PayPal webhook signature
    # (PayPal signature verification is more complex, see PayPal docs)

    event_type = event.get('event_type')

    if event_type == 'PAYMENT.SALE.COMPLETED':
        sale = event['resource']
        logger.info(f"[PAYMENT] PayPal sale completed: {sale['id']}")

        # TODO: Fulfill order using sale.custom (contains metadata)

    elif event_type == 'PAYMENT.SALE.REFUNDED':
        refund = event['resource']
        logger.info(f"[PAYMENT] PayPal refund processed: {refund['id']}")

        # TODO: Mark order as refunded

    return {"status": "success"}


# ============================================================================
# FASTAPI INTEGRATION EXAMPLE
# ============================================================================

async def example_fastapi_integration():
    """Example FastAPI integration"""
    app = FastAPI(title="Payment Processing API")

    # Initialize payment service
    payment_service = PaymentService(
        redis_url=os.environ.get('REDIS_URL', 'redis://localhost:6379')
    )

    @app.on_event("startup")
    async def startup():
        await payment_service.initialize()

    @app.on_event("shutdown")
    async def shutdown():
        await payment_service.close()

    # Create payment endpoint
    @app.post("/api/payment/create")
    async def create_payment(request: CreatePaymentRequest):
        """Create payment"""
        result = await payment_service.create_payment(
            amount=request.amount,
            currency=request.currency,
            provider=request.provider,
            payment_method_id=request.payment_method_id,
            customer_email=request.customer_email,
            metadata=request.metadata,
            idempotency_key=request.idempotency_key
        )
        return result

    # Create subscription endpoint
    @app.post("/api/subscription/create")
    async def create_subscription(request: CreateSubscriptionRequest):
        """Create subscription"""
        result = await payment_service.create_subscription(
            customer_email=request.customer_email,
            payment_method_id=request.payment_method_id,
            price_id=request.price_id,
            provider=request.provider,
            metadata=request.metadata
        )
        return result

    # Refund endpoint
    @app.post("/api/payment/refund")
    async def refund_payment(request: RefundRequest):
        """Refund payment"""
        # Note: You need to store payment provider with payment
        result = await payment_service.create_refund(
            payment_id=request.payment_id,
            provider=PaymentProvider.STRIPE,  # Or get from database
            amount=request.amount,
            reason=request.reason
        )
        return result

    # Stripe webhook endpoint
    @app.post("/webhooks/stripe")
    async def stripe_webhook(request: Request):
        """Handle Stripe webhooks"""
        return await handle_stripe_webhook(request, payment_service)

    # PayPal webhook endpoint
    @app.post("/webhooks/paypal")
    async def paypal_webhook(request: Request):
        """Handle PayPal webhooks"""
        return await handle_paypal_webhook(request, payment_service)

    return app


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'PaymentService',
    'PaymentProvider',
    'PaymentStatus',
    'StripeProvider',
    'PayPalProvider',
    'CreatePaymentRequest',
    'CreateSubscriptionRequest',
    'RefundRequest',
    'handle_stripe_webhook',
    'handle_paypal_webhook',
]
