---
name: api-integration-middleware
description: "Production-ready patterns for CONSUMING third-party APIs: circuit breakers, webhook ingestion, OAuth token refresh, adapter/anti-corruption layers, audit logging, rate limit handling, timeout cascades, health probes, and mock/stub strategies. Use when: (1) Integrating with external REST/webhook APIs, (2) Building resilient third-party consumption layers, (3) Implementing circuit breaker or bulkhead patterns, (4) Handling OAuth token lifecycle, (5) Normalizing inconsistent vendor APIs. Triggers on 'API integration', 'circuit breaker', 'webhook handler', 'token refresh', 'anti-corruption layer', 'API middleware', 'third-party resilience', or 'API consumption' requests."
license: Proprietary
extends: unified-api-client
---

# API Integration Middleware

Production-ready patterns for **consuming** third-party APIs with resilience, observability, and maintainability. This skill sits on top of the `unified-api-client` base class and the `multi-provider-pattern` skill, adding the consumption-specific middleware that turns raw HTTP calls into production-grade integrations.

## Module Dependency Diagram

```
                    ┌──────────────────────────────┐
                    │     Your Application Code    │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │  api-integration-middleware   │  ◄── THIS SKILL
                    │  (circuit breaker, webhooks,  │
                    │   OAuth, adapters, logging,   │
                    │   rate limits, timeouts,      │
                    │   health checks, mocks)       │
                    └──┬───────┬───────┬───────┬───┘
                       │       │       │       │
          ┌────────────▼──┐ ┌─▼───────▼──┐ ┌──▼──────────────┐
          │ unified-api-  │ │  multi-    │ │  caching-       │
          │ client        │ │  provider- │ │  universal      │
          │ (base HTTP)   │ │  pattern   │ │  (response      │
          │               │ │  (fallback │ │   caching)      │
          │               │ │   chains)  │ │                 │
          └───────────────┘ └────────────┘ └─────────────────┘
                       │                        │
          ┌────────────▼──────────┐  ┌──────────▼──────────┐
          │ database-orm-patterns │  │ scheduling-framework │
          │ (webhook event store, │  │ (polling-based       │
          │  audit log tables)    │  │  integrations)       │
          └───────────────────────┘  └─────────────────────┘
```

**Relationship to existing modules:**
- **`unified-api-client`** provides `BaseAPIClient`, `Result`, `AuthStrategy`, `RetryConfig`, and the exception hierarchy (`RateLimitError`, `TimeoutError`, etc.). This skill **extends** that base with middleware patterns.
- **`multi-provider-pattern`** handles provider selection, fallback chains, and cost optimization. This skill adds **consumption-layer concerns** (circuit breaking, webhook verification, token lifecycle) that apply regardless of which provider is selected.
- **`caching-universal`** provides multi-layer cache (L1 in-memory, L2 Redis, L3 CDN). This skill references it for response caching strategies.
- **`database-orm-patterns`** provides `BaseModel` and `BaseRepository`. This skill uses them for webhook event storage and audit trail persistence.
- **`scheduling-framework`** provides job scheduling. This skill references it for polling-based API integrations and periodic health checks.

---

## Quick Start

### Python: Resilient API Client with Circuit Breaker

```python
from unified_api_client import BaseAPIClient, BearerTokenAuth, RetryConfig

from api_integration_middleware import (
    CircuitBreaker,
    CircuitBreakerConfig,
    OAuthTokenManager,
    RequestAuditLogger,
    AdapterLayer,
)


class StripeClient(BaseAPIClient):
    """Stripe API client with circuit breaker and audit logging."""

    def __init__(self, api_key: str, db_session=None):
        super().__init__(
            base_url="https://api.stripe.com/v1",
            auth=BearerTokenAuth(api_key),
            retry=RetryConfig(max_retries=3, retryable_status_codes=(429, 500, 502, 503)),
            timeout=15.0,
        )
        self.circuit = CircuitBreaker(
            CircuitBreakerConfig(failure_threshold=5, recovery_timeout=30.0)
        )
        self.audit = RequestAuditLogger(db_session=db_session)

    def create_charge(self, amount: int, currency: str, source: str) -> dict:
        with self.circuit:
            result = self.post(
                "charges",
                data={"amount": amount, "currency": currency, "source": source},
            )
            self.audit.log(result)
            return result.unwrap()
```

### TypeScript: Resilient API Client with Circuit Breaker

```typescript
import { BaseAPIClient, BearerTokenAuth } from "unified-api-client";
import {
  CircuitBreaker,
  RequestAuditLogger,
  AdapterLayer,
} from "./api-integration-middleware";

class StripeClient extends BaseAPIClient {
  private circuit: CircuitBreaker;
  private audit: RequestAuditLogger;

  constructor(apiKey: string) {
    super({
      baseUrl: "https://api.stripe.com/v1",
      auth: new BearerTokenAuth(apiKey),
      retry: { maxRetries: 3, retryableStatusCodes: [429, 500, 502, 503] },
      timeout: 15_000,
    });
    this.circuit = new CircuitBreaker({ failureThreshold: 5, recoveryTimeout: 30_000 });
    this.audit = new RequestAuditLogger();
  }

  async createCharge(amount: number, currency: string, source: string) {
    return this.circuit.execute(async () => {
      const result = await this.post<{ id: string; status: string }>("charges", {
        json: { amount, currency, source },
      });
      this.audit.log(result);
      return result;
    });
  }
}
```

---

# 1. CIRCUIT BREAKER PATTERN

## Why Circuit Breakers

When a third-party API goes down, naive retry logic hammers the failing service, exhausts your connection pool, and cascades failures into your own system. The circuit breaker stops this by tracking failures and short-circuiting requests when a threshold is breached.

## State Machine

```
         success / under threshold
         ┌──────────────────┐
         │                  │
         ▼                  │
    ┌─────────┐    failure  │     ┌──────────┐
    │ CLOSED  │────────────►│     │   OPEN   │
    │(normal) │  threshold  │     │ (reject) │
    └─────────┘  reached    │     └────┬─────┘
         ▲                  │          │
         │                  │          │ recovery_timeout
         │   success        │          │ expires
         │                  │          ▼
         │            ┌─────┴──────────────┐
         └────────────┤    HALF-OPEN       │
                      │ (probe: 1 request) │
                      └────────────────────┘
                           │
                           │ failure
                           ▼
                      ┌──────────┐
                      │   OPEN   │
                      │ (reject) │
                      └──────────┘
```

**States:**
- **CLOSED**: Normal operation. Failures are counted. When `failure_threshold` is reached, transition to OPEN.
- **OPEN**: All requests are immediately rejected with `CircuitOpenError`. After `recovery_timeout` elapses, transition to HALF-OPEN.
- **HALF-OPEN**: One probe request is allowed through. If it succeeds, transition to CLOSED and reset counters. If it fails, transition back to OPEN.

## Python Implementation

```python
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, TypeVar, Generic

T = TypeVar("T")


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when the circuit breaker is open and rejecting requests."""

    def __init__(self, service_name: str, retry_after: float):
        self.service_name = service_name
        self.retry_after = retry_after
        super().__init__(
            f"Circuit breaker OPEN for '{service_name}'. "
            f"Retry after {retry_after:.1f}s."
        )


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    failure_threshold: int = 5          # Failures before opening
    recovery_timeout: float = 30.0      # Seconds before half-open probe
    half_open_max_calls: int = 1        # Probe requests in half-open
    success_threshold: int = 2          # Successes to close from half-open
    counted_exceptions: tuple = ()      # Empty = count all exceptions
    excluded_exceptions: tuple = ()     # Never count these as failures


@dataclass
class CircuitBreakerMetrics:
    """Observable metrics for monitoring dashboards."""
    total_requests: int = 0
    total_failures: int = 0
    total_rejections: int = 0           # Rejected while OPEN
    total_successes: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    state_changes: int = 0


class CircuitBreaker:
    """Thread-safe circuit breaker for third-party API calls.

    Extends the retry logic in unified-api-client by adding
    state-machine-based failure isolation.

    Usage:
        breaker = CircuitBreaker(CircuitBreakerConfig(failure_threshold=5))

        # As context manager
        with breaker:
            result = api_client.get("/resource")

        # As decorator
        @breaker
        def call_external_api():
            return api_client.get("/resource")

        # Explicit execute
        result = breaker.execute(lambda: api_client.get("/resource"))
    """

    def __init__(
        self,
        config: Optional[CircuitBreakerConfig] = None,
        name: str = "default",
        on_state_change: Optional[Callable[[CircuitState, CircuitState], None]] = None,
    ):
        self.config = config or CircuitBreakerConfig()
        self.name = name
        self._state = CircuitState.CLOSED
        self._lock = threading.RLock()
        self._metrics = CircuitBreakerMetrics()
        self._opened_at: Optional[float] = None
        self._half_open_calls = 0
        self._on_state_change = on_state_change

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to(CircuitState.HALF_OPEN)
            return self._state

    @property
    def metrics(self) -> CircuitBreakerMetrics:
        return self._metrics

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to try a probe request."""
        if self._opened_at is None:
            return False
        return (time.monotonic() - self._opened_at) >= self.config.recovery_timeout

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state with callback notification."""
        old_state = self._state
        self._state = new_state
        self._metrics.state_changes += 1

        if new_state == CircuitState.OPEN:
            self._opened_at = time.monotonic()
            self._half_open_calls = 0
        elif new_state == CircuitState.CLOSED:
            self._metrics.consecutive_failures = 0
            self._half_open_calls = 0
        elif new_state == CircuitState.HALF_OPEN:
            self._half_open_calls = 0

        if self._on_state_change and old_state != new_state:
            self._on_state_change(old_state, new_state)

    def _is_counted_exception(self, exc: Exception) -> bool:
        """Determine if this exception counts as a circuit-breaker failure."""
        if self.config.excluded_exceptions and isinstance(exc, self.config.excluded_exceptions):
            return False
        if self.config.counted_exceptions:
            return isinstance(exc, self.config.counted_exceptions)
        return True  # Count all exceptions by default

    def _record_success(self) -> None:
        with self._lock:
            self._metrics.total_successes += 1
            self._metrics.consecutive_failures = 0
            self._metrics.consecutive_successes += 1
            self._metrics.last_success_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                if self._metrics.consecutive_successes >= self.config.success_threshold:
                    self._transition_to(CircuitState.CLOSED)

    def _record_failure(self) -> None:
        with self._lock:
            self._metrics.total_failures += 1
            self._metrics.consecutive_failures += 1
            self._metrics.consecutive_successes = 0
            self._metrics.last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                if self._metrics.consecutive_failures >= self.config.failure_threshold:
                    self._transition_to(CircuitState.OPEN)

    def execute(self, func: Callable[[], T]) -> T:
        """Execute a function through the circuit breaker."""
        with self._lock:
            self._metrics.total_requests += 1
            current_state = self.state  # May trigger OPEN -> HALF_OPEN

            if current_state == CircuitState.OPEN:
                self._metrics.total_rejections += 1
                retry_after = self.config.recovery_timeout - (
                    time.monotonic() - (self._opened_at or 0)
                )
                raise CircuitOpenError(self.name, max(0.0, retry_after))

            if current_state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.config.half_open_max_calls:
                    self._metrics.total_rejections += 1
                    raise CircuitOpenError(self.name, self.config.recovery_timeout)
                self._half_open_calls += 1

        try:
            result = func()
            self._record_success()
            return result
        except Exception as exc:
            if self._is_counted_exception(exc):
                self._record_failure()
            raise

    # Context manager support
    def __enter__(self):
        with self._lock:
            self._metrics.total_requests += 1
            current_state = self.state
            if current_state == CircuitState.OPEN:
                self._metrics.total_rejections += 1
                retry_after = self.config.recovery_timeout - (
                    time.monotonic() - (self._opened_at or 0)
                )
                raise CircuitOpenError(self.name, max(0.0, retry_after))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val is None:
            self._record_success()
        elif isinstance(exc_val, Exception) and self._is_counted_exception(exc_val):
            self._record_failure()
        return False  # Do not suppress exceptions

    # Decorator support
    def __call__(self, func):
        import functools

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return self.execute(lambda: func(*args, **kwargs))

        return wrapper
```

## TypeScript Implementation

```typescript
enum CircuitState {
  CLOSED = "closed",
  OPEN = "open",
  HALF_OPEN = "half_open",
}

interface CircuitBreakerConfig {
  failureThreshold: number;        // Default: 5
  recoveryTimeout: number;         // Milliseconds. Default: 30_000
  halfOpenMaxCalls: number;        // Default: 1
  successThreshold: number;        // Default: 2
  isCountedError?: (err: Error) => boolean;  // Default: count all
}

interface CircuitBreakerMetrics {
  totalRequests: number;
  totalFailures: number;
  totalRejections: number;
  totalSuccesses: number;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  lastFailureTime?: number;
  lastSuccessTime?: number;
  stateChanges: number;
}

class CircuitOpenError extends Error {
  constructor(
    public readonly serviceName: string,
    public readonly retryAfter: number,
  ) {
    super(
      `Circuit breaker OPEN for '${serviceName}'. Retry after ${retryAfter}ms.`,
    );
    this.name = "CircuitOpenError";
  }
}

class CircuitBreaker {
  private state = CircuitState.CLOSED;
  private openedAt?: number;
  private halfOpenCalls = 0;
  private readonly config: Required<CircuitBreakerConfig>;
  private readonly _metrics: CircuitBreakerMetrics = {
    totalRequests: 0,
    totalFailures: 0,
    totalRejections: 0,
    totalSuccesses: 0,
    consecutiveFailures: 0,
    consecutiveSuccesses: 0,
    stateChanges: 0,
  };

  constructor(
    config: Partial<CircuitBreakerConfig> & { failureThreshold: number },
    private readonly name = "default",
    private readonly onStateChange?: (from: CircuitState, to: CircuitState) => void,
  ) {
    this.config = {
      failureThreshold: config.failureThreshold,
      recoveryTimeout: config.recoveryTimeout ?? 30_000,
      halfOpenMaxCalls: config.halfOpenMaxCalls ?? 1,
      successThreshold: config.successThreshold ?? 2,
      isCountedError: config.isCountedError ?? (() => true),
    };
  }

  get metrics(): Readonly<CircuitBreakerMetrics> {
    return { ...this._metrics };
  }

  get currentState(): CircuitState {
    if (
      this.state === CircuitState.OPEN &&
      this.openedAt &&
      Date.now() - this.openedAt >= this.config.recoveryTimeout
    ) {
      this.transitionTo(CircuitState.HALF_OPEN);
    }
    return this.state;
  }

  private transitionTo(newState: CircuitState): void {
    const old = this.state;
    this.state = newState;
    this._metrics.stateChanges++;

    if (newState === CircuitState.OPEN) {
      this.openedAt = Date.now();
      this.halfOpenCalls = 0;
    } else if (newState === CircuitState.CLOSED) {
      this._metrics.consecutiveFailures = 0;
      this.halfOpenCalls = 0;
    } else if (newState === CircuitState.HALF_OPEN) {
      this.halfOpenCalls = 0;
    }

    if (old !== newState) {
      this.onStateChange?.(old, newState);
    }
  }

  private recordSuccess(): void {
    this._metrics.totalSuccesses++;
    this._metrics.consecutiveFailures = 0;
    this._metrics.consecutiveSuccesses++;
    this._metrics.lastSuccessTime = Date.now();

    if (this.state === CircuitState.HALF_OPEN) {
      if (this._metrics.consecutiveSuccesses >= this.config.successThreshold) {
        this.transitionTo(CircuitState.CLOSED);
      }
    }
  }

  private recordFailure(): void {
    this._metrics.totalFailures++;
    this._metrics.consecutiveFailures++;
    this._metrics.consecutiveSuccesses = 0;
    this._metrics.lastFailureTime = Date.now();

    if (this.state === CircuitState.HALF_OPEN) {
      this.transitionTo(CircuitState.OPEN);
    } else if (this.state === CircuitState.CLOSED) {
      if (this._metrics.consecutiveFailures >= this.config.failureThreshold) {
        this.transitionTo(CircuitState.OPEN);
      }
    }
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    this._metrics.totalRequests++;
    const current = this.currentState;

    if (current === CircuitState.OPEN) {
      this._metrics.totalRejections++;
      const retryAfter =
        this.config.recoveryTimeout - (Date.now() - (this.openedAt ?? 0));
      throw new CircuitOpenError(this.name, Math.max(0, retryAfter));
    }

    if (current === CircuitState.HALF_OPEN) {
      if (this.halfOpenCalls >= this.config.halfOpenMaxCalls) {
        this._metrics.totalRejections++;
        throw new CircuitOpenError(this.name, this.config.recoveryTimeout);
      }
      this.halfOpenCalls++;
    }

    try {
      const result = await fn();
      this.recordSuccess();
      return result;
    } catch (err) {
      if (err instanceof Error && this.config.isCountedError(err)) {
        this.recordFailure();
      }
      throw err;
    }
  }
}
```

## Circuit Breaker Registry (Multi-Service)

When your application consumes multiple third-party APIs, maintain a registry so each service has its own independent circuit breaker.

```python
class CircuitBreakerRegistry:
    """Global registry of circuit breakers, one per external service."""

    _breakers: dict[str, CircuitBreaker] = {}
    _lock = threading.Lock()

    @classmethod
    def get(cls, service_name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        with cls._lock:
            if service_name not in cls._breakers:
                cls._breakers[service_name] = CircuitBreaker(
                    config=config or CircuitBreakerConfig(),
                    name=service_name,
                )
            return cls._breakers[service_name]

    @classmethod
    def health_report(cls) -> dict[str, dict]:
        """Generate a health report for all registered breakers."""
        return {
            name: {
                "state": breaker.state.value,
                "consecutive_failures": breaker.metrics.consecutive_failures,
                "total_rejections": breaker.metrics.total_rejections,
            }
            for name, breaker in cls._breakers.items()
        }
```

```typescript
class CircuitBreakerRegistry {
  private static breakers = new Map<string, CircuitBreaker>();

  static get(name: string, config?: Partial<CircuitBreakerConfig>): CircuitBreaker {
    if (!this.breakers.has(name)) {
      this.breakers.set(
        name,
        new CircuitBreaker({ failureThreshold: 5, ...config }, name),
      );
    }
    return this.breakers.get(name)!;
  }

  static healthReport(): Record<string, { state: string; failures: number }> {
    const report: Record<string, { state: string; failures: number }> = {};
    for (const [name, breaker] of this.breakers) {
      report[name] = {
        state: breaker.currentState,
        failures: breaker.metrics.consecutiveFailures,
      };
    }
    return report;
  }
}
```

---

# 2. WEBHOOK INGESTION

## Why Proper Webhook Handling Matters

Webhooks are how third-party services push events to you. Unlike API calls you initiate, webhooks arrive at *their* pace and must be processed reliably. Three critical concerns: **signature verification** (is this really from Stripe?), **idempotency** (what if they send it twice?), and **retry handling** (what if your server was down?).

## Signature Verification

Every major provider signs webhook payloads. Never skip verification.

### Python

```python
import hashlib
import hmac
import time
from typing import Optional


class WebhookVerificationError(Exception):
    """Raised when webhook signature verification fails."""
    pass


class WebhookVerifier:
    """Verify webhook signatures from third-party providers.

    Supports HMAC-SHA256 (Stripe, GitHub, Shopify) and
    HMAC-SHA1 (older GitHub hooks) schemes.
    """

    def __init__(self, secret: str, tolerance_seconds: int = 300):
        self.secret = secret.encode("utf-8")
        self.tolerance = tolerance_seconds

    def verify_stripe(self, payload: bytes, signature_header: str) -> dict:
        """Verify Stripe webhook signature (v1 scheme).

        Stripe header format: t=<timestamp>,v1=<signature>[,v0=<old_sig>]
        """
        elements = dict(
            pair.split("=", 1) for pair in signature_header.split(",")
        )
        timestamp = elements.get("t")
        signature = elements.get("v1")

        if not timestamp or not signature:
            raise WebhookVerificationError("Missing timestamp or signature")

        # Protect against replay attacks
        ts = int(timestamp)
        if abs(time.time() - ts) > self.tolerance:
            raise WebhookVerificationError(
                f"Timestamp outside tolerance ({self.tolerance}s)"
            )

        # Compute expected signature
        signed_payload = f"{timestamp}.".encode("utf-8") + payload
        expected = hmac.new(
            self.secret, signed_payload, hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, signature):
            raise WebhookVerificationError("Signature mismatch")

        import json
        return json.loads(payload)

    def verify_github(self, payload: bytes, signature_header: str) -> dict:
        """Verify GitHub webhook signature (sha256= scheme)."""
        if not signature_header.startswith("sha256="):
            raise WebhookVerificationError("Invalid signature format")

        signature = signature_header[7:]
        expected = hmac.new(
            self.secret, payload, hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, signature):
            raise WebhookVerificationError("Signature mismatch")

        import json
        return json.loads(payload)

    def verify_hmac_sha256(self, payload: bytes, signature: str) -> dict:
        """Generic HMAC-SHA256 verification for any provider."""
        expected = hmac.new(
            self.secret, payload, hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, signature):
            raise WebhookVerificationError("Signature mismatch")

        import json
        return json.loads(payload)
```

### TypeScript

```typescript
import { createHmac, timingSafeEqual } from "crypto";

class WebhookVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebhookVerificationError";
  }
}

class WebhookVerifier {
  private readonly secret: Buffer;
  private readonly toleranceSeconds: number;

  constructor(secret: string, toleranceSeconds = 300) {
    this.secret = Buffer.from(secret, "utf-8");
    this.toleranceSeconds = toleranceSeconds;
  }

  verifyStripe(payload: Buffer, signatureHeader: string): unknown {
    const elements = Object.fromEntries(
      signatureHeader.split(",").map((p) => p.split("=", 2) as [string, string]),
    );
    const timestamp = elements["t"];
    const signature = elements["v1"];

    if (!timestamp || !signature) {
      throw new WebhookVerificationError("Missing timestamp or signature");
    }

    const ts = parseInt(timestamp, 10);
    if (Math.abs(Date.now() / 1000 - ts) > this.toleranceSeconds) {
      throw new WebhookVerificationError("Timestamp outside tolerance");
    }

    const signedPayload = Buffer.concat([
      Buffer.from(`${timestamp}.`),
      payload,
    ]);
    const expected = createHmac("sha256", this.secret)
      .update(signedPayload)
      .digest("hex");

    if (
      !timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(signature, "hex"))
    ) {
      throw new WebhookVerificationError("Signature mismatch");
    }

    return JSON.parse(payload.toString("utf-8"));
  }

  verifyGitHub(payload: Buffer, signatureHeader: string): unknown {
    if (!signatureHeader.startsWith("sha256=")) {
      throw new WebhookVerificationError("Invalid signature format");
    }
    const signature = signatureHeader.slice(7);
    const expected = createHmac("sha256", this.secret)
      .update(payload)
      .digest("hex");

    if (
      !timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(signature, "hex"))
    ) {
      throw new WebhookVerificationError("Signature mismatch");
    }

    return JSON.parse(payload.toString("utf-8"));
  }
}
```

## Idempotency Layer

Webhooks are delivered at-least-once. You must deduplicate.

### Python (uses `database-orm-patterns` for storage)

```python
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Any
from enum import Enum

# Uses BaseModel and BaseRepository from database-orm-patterns module
from database_orm_patterns import BaseModel, BaseRepository


class WebhookEventStatus(str, Enum):
    RECEIVED = "received"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED_DUPLICATE = "skipped_duplicate"


class WebhookEvent(BaseModel):
    """Persistent record of every webhook received.

    Table schema:
        id              BIGSERIAL PRIMARY KEY
        idempotency_key VARCHAR(255) UNIQUE NOT NULL
        provider        VARCHAR(64)  NOT NULL
        event_type      VARCHAR(128) NOT NULL
        payload         JSONB        NOT NULL
        status          VARCHAR(32)  NOT NULL DEFAULT 'received'
        attempts        INT          NOT NULL DEFAULT 0
        error_message   TEXT
        received_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        processed_at    TIMESTAMPTZ
    """
    __tablename__ = "webhook_events"

    idempotency_key: str
    provider: str
    event_type: str
    payload: dict
    status: str = WebhookEventStatus.RECEIVED
    attempts: int = 0
    error_message: Optional[str] = None
    processed_at: Optional[datetime] = None


class WebhookProcessor:
    """Idempotent webhook processor with at-least-once delivery guarantees.

    Usage:
        processor = WebhookProcessor(db_session)

        @processor.handler("stripe", "invoice.paid")
        def handle_invoice_paid(event: WebhookEvent):
            # Process the invoice...
            pass

        # In your webhook endpoint:
        processor.process(
            provider="stripe",
            event_type="invoice.paid",
            idempotency_key=request.headers["Stripe-Webhook-Id"],
            payload=verified_payload,
        )
    """

    def __init__(self, db_session, max_retries: int = 3):
        self.db = db_session
        self.max_retries = max_retries
        self._handlers: dict[tuple[str, str], Any] = {}

    def handler(self, provider: str, event_type: str):
        """Register a handler for a specific provider + event type."""
        def decorator(func):
            self._handlers[(provider, event_type)] = func
            return func
        return decorator

    def process(
        self,
        provider: str,
        event_type: str,
        idempotency_key: str,
        payload: dict,
    ) -> WebhookEvent:
        """Process a webhook event idempotently.

        Returns the WebhookEvent record (created or existing).
        """
        # Step 1: Check for duplicate
        existing = self.db.query(WebhookEvent).filter_by(
            idempotency_key=idempotency_key
        ).first()

        if existing:
            if existing.status == WebhookEventStatus.COMPLETED:
                existing.status = WebhookEventStatus.SKIPPED_DUPLICATE
                return existing  # Already processed successfully
            if existing.attempts >= self.max_retries:
                return existing  # Exhausted retries
            # Retry a previously failed event
            event = existing
        else:
            event = WebhookEvent(
                idempotency_key=idempotency_key,
                provider=provider,
                event_type=event_type,
                payload=payload,
            )
            self.db.add(event)
            self.db.flush()

        # Step 2: Find and execute handler
        handler_fn = self._handlers.get((provider, event_type))
        if not handler_fn:
            event.status = WebhookEventStatus.SKIPPED_DUPLICATE
            event.error_message = f"No handler for {provider}/{event_type}"
            self.db.commit()
            return event

        # Step 3: Execute with error capture
        event.status = WebhookEventStatus.PROCESSING
        event.attempts += 1
        self.db.commit()

        try:
            handler_fn(event)
            event.status = WebhookEventStatus.COMPLETED
            event.processed_at = datetime.utcnow()
        except Exception as exc:
            event.status = WebhookEventStatus.FAILED
            event.error_message = str(exc)[:2000]

        self.db.commit()
        return event

    def generate_idempotency_key(self, provider: str, payload: dict) -> str:
        """Generate a deterministic idempotency key from payload content.

        Use this when the provider does not send its own unique event ID.
        """
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(f"{provider}:{canonical}".encode()).hexdigest()
```

### TypeScript

```typescript
import { createHash } from "crypto";

enum WebhookEventStatus {
  RECEIVED = "received",
  PROCESSING = "processing",
  COMPLETED = "completed",
  FAILED = "failed",
  SKIPPED_DUPLICATE = "skipped_duplicate",
}

interface WebhookEvent {
  id: number;
  idempotencyKey: string;
  provider: string;
  eventType: string;
  payload: Record<string, unknown>;
  status: WebhookEventStatus;
  attempts: number;
  errorMessage?: string;
  receivedAt: Date;
  processedAt?: Date;
}

type WebhookHandler = (event: WebhookEvent) => Promise<void>;

class WebhookProcessor {
  private handlers = new Map<string, WebhookHandler>();

  constructor(
    private readonly db: any, // Your ORM repository
    private readonly maxRetries = 3,
  ) {}

  /** Register a handler for a provider + event type pair. */
  on(provider: string, eventType: string, handler: WebhookHandler): void {
    this.handlers.set(`${provider}:${eventType}`, handler);
  }

  /** Process a webhook event idempotently. */
  async process(
    provider: string,
    eventType: string,
    idempotencyKey: string,
    payload: Record<string, unknown>,
  ): Promise<WebhookEvent> {
    // Check for existing event
    let event = await this.db.findOne("webhook_events", {
      idempotencyKey,
    });

    if (event) {
      if (event.status === WebhookEventStatus.COMPLETED) {
        return { ...event, status: WebhookEventStatus.SKIPPED_DUPLICATE };
      }
      if (event.attempts >= this.maxRetries) {
        return event;
      }
    } else {
      event = await this.db.insert("webhook_events", {
        idempotencyKey,
        provider,
        eventType,
        payload,
        status: WebhookEventStatus.RECEIVED,
        attempts: 0,
        receivedAt: new Date(),
      });
    }

    const handler = this.handlers.get(`${provider}:${eventType}`);
    if (!handler) {
      await this.db.update("webhook_events", event.id, {
        status: WebhookEventStatus.SKIPPED_DUPLICATE,
        errorMessage: `No handler for ${provider}/${eventType}`,
      });
      return event;
    }

    await this.db.update("webhook_events", event.id, {
      status: WebhookEventStatus.PROCESSING,
      attempts: event.attempts + 1,
    });

    try {
      await handler(event);
      await this.db.update("webhook_events", event.id, {
        status: WebhookEventStatus.COMPLETED,
        processedAt: new Date(),
      });
    } catch (err) {
      await this.db.update("webhook_events", event.id, {
        status: WebhookEventStatus.FAILED,
        errorMessage: (err as Error).message.slice(0, 2000),
      });
    }

    return event;
  }

  /** Generate a deterministic idempotency key when the provider lacks one. */
  static generateIdempotencyKey(
    provider: string,
    payload: Record<string, unknown>,
  ): string {
    const canonical = JSON.stringify(payload, Object.keys(payload).sort());
    return createHash("sha256")
      .update(`${provider}:${canonical}`)
      .digest("hex");
  }
}
```

## Webhook Endpoint Pattern (Framework-Agnostic)

```python
# Flask / FastAPI-style pseudo-code

def webhook_endpoint(request):
    """Generic webhook handler pattern."""
    # 1. Read raw body BEFORE any parsing (needed for signature verification)
    raw_body = request.get_body()  # bytes

    # 2. Verify signature
    verifier = WebhookVerifier(secret=config.STRIPE_WEBHOOK_SECRET)
    try:
        payload = verifier.verify_stripe(raw_body, request.headers["Stripe-Signature"])
    except WebhookVerificationError:
        return Response(status=401)  # Do NOT leak error details

    # 3. Acknowledge immediately (return 200 before processing)
    #    Many providers will retry if they don't get 2xx within 5-15 seconds.
    #    Queue the actual processing for background execution.
    #    See: scheduling-framework module for background job patterns.

    # 4. Process idempotently
    processor.process(
        provider="stripe",
        event_type=payload["type"],
        idempotency_key=request.headers.get("Stripe-Webhook-Id", ""),
        payload=payload,
    )

    return Response(status=200)
```

**Critical rule:** Always return `200` quickly. Offload heavy processing to a background job queue (see `scheduling-framework` module). Providers interpret slow responses as failures and will retry.

---

# 3. OAUTH TOKEN REFRESH FLOWS

## Beyond Client Credentials

The `unified-api-client` module already includes `OAuth2ClientCredentials` for machine-to-machine flows. This section covers the more complex **authorization code grant** with refresh tokens, which is required when acting on behalf of a user (Google, Microsoft, Salesforce, etc.).

## Token Lifecycle

```
┌───────────────┐     authorize     ┌──────────────────┐
│   User Login  │──────────────────►│  Authorization   │
│               │                   │  Server          │
└───────────────┘                   └────────┬─────────┘
                                             │
                                    authorization_code
                                             │
                                             ▼
┌───────────────┐    code exchange  ┌──────────────────┐
│  Your App     │──────────────────►│  Token Endpoint  │
│               │◄──────────────────│                  │
│               │  access_token +   └──────────────────┘
│               │  refresh_token
│               │
│   ┌───────────┴──────────────┐
│   │  Token Store (encrypted) │
│   │  - access_token          │
│   │  - refresh_token         │
│   │  - expires_at            │
│   │  - scopes                │
│   └───────────┬──────────────┘
│               │
│   on expiry:  │  POST /token { grant_type: refresh_token }
│               ├──────────────────►  Token Endpoint
│               │◄──────────────────  new access_token
│               │                     (+ possibly new refresh_token)
└───────────────┘
```

## Python Implementation

```python
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Callable
from unified_api_client import AuthStrategy, AuthenticationError

import requests


@dataclass
class OAuthTokens:
    """Container for OAuth token data."""
    access_token: str
    refresh_token: Optional[str] = None
    expires_at: float = 0.0         # Unix timestamp (monotonic)
    token_type: str = "Bearer"
    scopes: list[str] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        """Check if the access token is expired (with 60s buffer)."""
        return time.monotonic() >= (self.expires_at - 60)


class OAuthTokenManager(AuthStrategy):
    """Full OAuth2 authorization-code-grant token manager.

    Handles automatic refresh, token persistence, and thread-safe
    concurrent access. Implements the unified-api-client AuthStrategy
    interface so it can be used as a drop-in auth provider.

    Args:
        client_id: OAuth2 client ID.
        client_secret: OAuth2 client secret.
        token_url: Token endpoint URL.
        tokens: Initial tokens (from authorization code exchange).
        on_tokens_refreshed: Callback invoked with new tokens after refresh.
            Use this to persist tokens to your database.
        scopes: Requested scopes for refresh.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_url: str,
        tokens: OAuthTokens,
        on_tokens_refreshed: Optional[Callable[[OAuthTokens], None]] = None,
        scopes: Optional[list[str]] = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self._tokens = tokens
        self._on_refreshed = on_tokens_refreshed
        self._scopes = scopes or []
        self._lock = threading.RLock()
        self._refresh_in_progress = False

    @classmethod
    def from_authorization_code(
        cls,
        client_id: str,
        client_secret: str,
        token_url: str,
        authorization_code: str,
        redirect_uri: str,
        on_tokens_refreshed: Optional[Callable[[OAuthTokens], None]] = None,
    ) -> "OAuthTokenManager":
        """Exchange an authorization code for tokens and create a manager."""
        resp = requests.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=30,
        )
        if not resp.ok:
            raise AuthenticationError(
                f"Token exchange failed: {resp.status_code} {resp.text}"
            )

        body = resp.json()
        tokens = OAuthTokens(
            access_token=body["access_token"],
            refresh_token=body.get("refresh_token"),
            expires_at=time.monotonic() + body.get("expires_in", 3600),
            token_type=body.get("token_type", "Bearer"),
            scopes=body.get("scope", "").split(),
        )

        manager = cls(
            client_id=client_id,
            client_secret=client_secret,
            token_url=token_url,
            tokens=tokens,
            on_tokens_refreshed=on_tokens_refreshed,
        )

        if on_tokens_refreshed:
            on_tokens_refreshed(tokens)

        return manager

    def _refresh(self) -> OAuthTokens:
        """Refresh the access token using the refresh token."""
        if not self._tokens.refresh_token:
            raise AuthenticationError(
                "Cannot refresh: no refresh_token available. "
                "User must re-authorize."
            )

        data = {
            "grant_type": "refresh_token",
            "refresh_token": self._tokens.refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self._scopes:
            data["scope"] = " ".join(self._scopes)

        resp = requests.post(self.token_url, data=data, timeout=30)

        if resp.status_code == 400:
            body = resp.json()
            error = body.get("error", "")
            if error in ("invalid_grant", "invalid_token"):
                raise AuthenticationError(
                    "Refresh token is invalid or revoked. User must re-authorize."
                )

        if not resp.ok:
            raise AuthenticationError(
                f"Token refresh failed: {resp.status_code} {resp.text}"
            )

        body = resp.json()
        self._tokens = OAuthTokens(
            access_token=body["access_token"],
            # Some providers rotate refresh tokens; use new one if provided
            refresh_token=body.get("refresh_token", self._tokens.refresh_token),
            expires_at=time.monotonic() + body.get("expires_in", 3600),
            token_type=body.get("token_type", "Bearer"),
            scopes=body.get("scope", "").split() or self._tokens.scopes,
        )

        if self._on_refreshed:
            self._on_refreshed(self._tokens)

        return self._tokens

    def get_valid_token(self) -> str:
        """Return a valid access token, refreshing if necessary.

        Thread-safe: only one thread performs the refresh; others wait.
        """
        with self._lock:
            if self._tokens.is_expired:
                self._refresh()
            return self._tokens.access_token

    def apply(self, request_kwargs: dict, headers: dict) -> None:
        """AuthStrategy interface: inject the Authorization header."""
        token = self.get_valid_token()
        headers["Authorization"] = f"{self._tokens.token_type} {token}"

    def revoke(self, revoke_url: str) -> None:
        """Revoke the refresh token at the provider's revocation endpoint."""
        if not self._tokens.refresh_token:
            return
        requests.post(
            revoke_url,
            data={
                "token": self._tokens.refresh_token,
                "token_type_hint": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=15,
        )
```

### TypeScript

```typescript
import { AuthStrategy, AuthenticationError } from "unified-api-client";

interface OAuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;       // Date.now() + expiresIn * 1000
  tokenType: string;
  scopes: string[];
}

type TokenRefreshedCallback = (tokens: OAuthTokens) => void | Promise<void>;

class OAuthTokenManager implements AuthStrategy {
  private tokens: OAuthTokens;
  private refreshPromise?: Promise<OAuthTokens>;

  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
    private readonly tokenUrl: string,
    tokens: OAuthTokens,
    private readonly onTokensRefreshed?: TokenRefreshedCallback,
  ) {
    this.tokens = tokens;
  }

  /** Exchange authorization code for tokens. */
  static async fromAuthorizationCode(opts: {
    clientId: string;
    clientSecret: string;
    tokenUrl: string;
    code: string;
    redirectUri: string;
    onTokensRefreshed?: TokenRefreshedCallback;
  }): Promise<OAuthTokenManager> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: opts.code,
      redirect_uri: opts.redirectUri,
      client_id: opts.clientId,
      client_secret: opts.clientSecret,
    });

    const resp = await fetch(opts.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    if (!resp.ok) {
      throw new AuthenticationError(
        `Token exchange failed: ${resp.status} ${await resp.text()}`,
      );
    }

    const json = (await resp.json()) as Record<string, unknown>;
    const tokens: OAuthTokens = {
      accessToken: json.access_token as string,
      refreshToken: json.refresh_token as string | undefined,
      expiresAt: Date.now() + ((json.expires_in as number) ?? 3600) * 1000,
      tokenType: (json.token_type as string) ?? "Bearer",
      scopes: ((json.scope as string) ?? "").split(" ").filter(Boolean),
    };

    const manager = new OAuthTokenManager(
      opts.clientId,
      opts.clientSecret,
      opts.tokenUrl,
      tokens,
      opts.onTokensRefreshed,
    );

    await opts.onTokensRefreshed?.(tokens);
    return manager;
  }

  private isExpired(): boolean {
    return Date.now() >= this.tokens.expiresAt - 60_000;
  }

  /** Refresh with deduplication: concurrent callers share one refresh. */
  private async refresh(): Promise<OAuthTokens> {
    if (this.refreshPromise) return this.refreshPromise;

    this.refreshPromise = (async () => {
      if (!this.tokens.refreshToken) {
        throw new AuthenticationError("No refresh token. User must re-authorize.");
      }

      const body = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: this.tokens.refreshToken,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      });

      const resp = await fetch(this.tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });

      if (!resp.ok) {
        const text = await resp.text();
        throw new AuthenticationError(`Token refresh failed: ${resp.status} ${text}`);
      }

      const json = (await resp.json()) as Record<string, unknown>;
      this.tokens = {
        accessToken: json.access_token as string,
        refreshToken: (json.refresh_token as string) ?? this.tokens.refreshToken,
        expiresAt: Date.now() + ((json.expires_in as number) ?? 3600) * 1000,
        tokenType: (json.token_type as string) ?? "Bearer",
        scopes: ((json.scope as string) ?? "").split(" ").filter(Boolean),
      };

      await this.onTokensRefreshed?.(this.tokens);
      return this.tokens;
    })().finally(() => {
      this.refreshPromise = undefined;
    });

    return this.refreshPromise;
  }

  async getValidToken(): Promise<string> {
    if (this.isExpired()) {
      await this.refresh();
    }
    return this.tokens.accessToken;
  }

  async apply(_init: RequestInit, headers: Headers): Promise<void> {
    const token = await this.getValidToken();
    headers.set("Authorization", `${this.tokens.tokenType} ${token}`);
  }
}
```

**Key design decisions:**
- **Refresh deduplication**: In TypeScript, concurrent requests share a single refresh promise. In Python, `threading.RLock` serializes access.
- **Callback on refresh**: The `on_tokens_refreshed` callback lets you persist tokens to your database immediately after a refresh, preventing token loss on restart.
- **Rotating refresh tokens**: Some providers (Google) issue new refresh tokens on every refresh. Always store the latest one.

---

# 4. ADAPTER / ANTI-CORRUPTION LAYER PATTERN

## Why Adapters

Third-party APIs are messy. They use inconsistent naming (`camelCase` vs `snake_case`), return nested structures you do not need, change field names between versions, and embed pagination in different places. The adapter pattern normalizes all of this behind a clean internal interface.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Application                        │
│                                                             │
│   Uses clean internal models:                               │
│     Invoice { id, amount_cents, currency, status, due_at }  │
└─────────────────────┬───────────────────────────────────────┘
                      │
         ┌────────────▼────────────┐
         │     Adapter Layer       │
         │  (Anti-Corruption)      │
         │                         │
         │  - Maps vendor fields   │
         │  - Normalizes types     │
         │  - Handles pagination   │
         │  - Converts errors      │
         └────┬──────────┬────────┘
              │          │
     ┌────────▼──┐  ┌────▼────────┐
     │ Stripe    │  │ QuickBooks  │
     │ Raw API   │  │ Raw API     │
     └───────────┘  └─────────────┘
```

## Python Implementation

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Generic, TypeVar, Optional
from enum import Enum

# ---------- Internal Domain Models ----------

class InvoiceStatus(str, Enum):
    DRAFT = "draft"
    SENT = "sent"
    PAID = "paid"
    OVERDUE = "overdue"
    VOID = "void"


@dataclass
class Invoice:
    """Internal domain model - clean and consistent."""
    id: str
    external_id: str           # Original ID from the provider
    provider: str              # Which provider this came from
    amount_cents: int          # Always in cents to avoid float issues
    currency: str              # ISO 4217 (e.g., "USD")
    status: InvoiceStatus
    customer_email: str
    due_at: Optional[datetime] = None
    paid_at: Optional[datetime] = None
    line_items: list[dict] = None
    raw: Optional[dict] = None  # Store raw response for debugging


# ---------- Abstract Adapter ----------

T_Internal = TypeVar("T_Internal")
T_External = TypeVar("T_External")


class APIAdapter(ABC, Generic[T_External, T_Internal]):
    """Abstract adapter for transforming between vendor and internal models.

    Subclass per provider. The adapter is the ONLY place where
    vendor-specific field names, date formats, and quirks exist.
    """

    @abstractmethod
    def to_internal(self, external: T_External) -> T_Internal:
        """Convert vendor response to internal domain model."""

    @abstractmethod
    def to_external(self, internal: T_Internal) -> dict:
        """Convert internal model to vendor request format."""

    @abstractmethod
    def map_error(self, error: Exception) -> Exception:
        """Convert vendor-specific errors to domain errors."""

    def to_internal_list(self, externals: list[T_External]) -> list[T_Internal]:
        """Batch conversion with error isolation."""
        results = []
        for item in externals:
            try:
                results.append(self.to_internal(item))
            except Exception as exc:
                # Log but don't fail the whole batch for one bad record
                import logging
                logging.warning("Failed to adapt item: %s", exc)
        return results


# ---------- Concrete Adapters ----------

class StripeInvoiceAdapter(APIAdapter[dict, Invoice]):
    """Adapter for Stripe's invoice API responses."""

    # Stripe status -> internal status mapping
    STATUS_MAP = {
        "draft": InvoiceStatus.DRAFT,
        "open": InvoiceStatus.SENT,
        "paid": InvoiceStatus.PAID,
        "uncollectible": InvoiceStatus.OVERDUE,
        "void": InvoiceStatus.VOID,
    }

    def to_internal(self, external: dict) -> Invoice:
        return Invoice(
            id=f"stripe_{external['id']}",
            external_id=external["id"],
            provider="stripe",
            amount_cents=external["amount_due"],     # Stripe uses cents natively
            currency=external["currency"].upper(),
            status=self.STATUS_MAP.get(
                external["status"], InvoiceStatus.DRAFT
            ),
            customer_email=external.get("customer_email", ""),
            due_at=(
                datetime.fromtimestamp(external["due_date"])
                if external.get("due_date") else None
            ),
            paid_at=(
                datetime.fromtimestamp(external["status_transitions"]["paid_at"])
                if external.get("status_transitions", {}).get("paid_at") else None
            ),
            line_items=[
                {
                    "description": line["description"],
                    "amount_cents": line["amount"],
                    "quantity": line["quantity"],
                }
                for line in external.get("lines", {}).get("data", [])
            ],
            raw=external,
        )

    def to_external(self, internal: Invoice) -> dict:
        return {
            "amount": internal.amount_cents,
            "currency": internal.currency.lower(),
            "customer_email": internal.customer_email,
        }

    def map_error(self, error: Exception) -> Exception:
        # Convert Stripe-specific error structures to domain errors
        if hasattr(error, "status_code") and error.status_code == 402:
            return PaymentRequiredError(str(error))
        return error


class QuickBooksInvoiceAdapter(APIAdapter[dict, Invoice]):
    """Adapter for QuickBooks invoice API responses.

    QuickBooks returns amounts as strings with decimals, uses
    different field names, and nests data differently.
    """

    STATUS_MAP = {
        "Emailed": InvoiceStatus.SENT,
        "Paid": InvoiceStatus.PAID,
        "Overdue": InvoiceStatus.OVERDUE,
        "Voided": InvoiceStatus.VOID,
    }

    def to_internal(self, external: dict) -> Invoice:
        # QuickBooks uses string amounts like "150.00"
        amount_str = external.get("TotalAmt", "0")
        amount_cents = int(float(amount_str) * 100)

        return Invoice(
            id=f"qb_{external['Id']}",
            external_id=external["Id"],
            provider="quickbooks",
            amount_cents=amount_cents,
            currency=external.get("CurrencyRef", {}).get("value", "USD"),
            status=self.STATUS_MAP.get(
                external.get("EmailStatus", ""), InvoiceStatus.DRAFT
            ),
            customer_email=external.get("BillEmail", {}).get("Address", ""),
            due_at=(
                datetime.strptime(external["DueDate"], "%Y-%m-%d")
                if external.get("DueDate") else None
            ),
            line_items=[
                {
                    "description": line.get("Description", ""),
                    "amount_cents": int(
                        float(line.get("Amount", "0")) * 100
                    ),
                    "quantity": int(
                        line.get("SalesItemLineDetail", {}).get("Qty", 1)
                    ),
                }
                for line in external.get("Line", [])
                if line.get("DetailType") == "SalesItemLineDetail"
            ],
            raw=external,
        )

    def to_external(self, internal: Invoice) -> dict:
        return {
            "TotalAmt": str(internal.amount_cents / 100),
            "CurrencyRef": {"value": internal.currency},
            "BillEmail": {"Address": internal.customer_email},
        }

    def map_error(self, error: Exception) -> Exception:
        return error


# ---------- Adapter Registry ----------

class AdapterRegistry:
    """Registry of adapters by provider name.

    Integrates with multi-provider-pattern: when the provider manager
    selects a provider, look up the matching adapter here.
    """

    _adapters: dict[str, APIAdapter] = {}

    @classmethod
    def register(cls, provider: str, adapter: APIAdapter) -> None:
        cls._adapters[provider] = adapter

    @classmethod
    def get(cls, provider: str) -> APIAdapter:
        if provider not in cls._adapters:
            raise ValueError(f"No adapter registered for provider '{provider}'")
        return cls._adapters[provider]


# Register adapters at module load time
AdapterRegistry.register("stripe", StripeInvoiceAdapter())
AdapterRegistry.register("quickbooks", QuickBooksInvoiceAdapter())
```

### TypeScript

```typescript
// ---------- Internal Domain Model ----------

enum InvoiceStatus {
  DRAFT = "draft",
  SENT = "sent",
  PAID = "paid",
  OVERDUE = "overdue",
  VOID = "void",
}

interface Invoice {
  id: string;
  externalId: string;
  provider: string;
  amountCents: number;
  currency: string;
  status: InvoiceStatus;
  customerEmail: string;
  dueAt?: Date;
  paidAt?: Date;
  lineItems: Array<{ description: string; amountCents: number; quantity: number }>;
  raw?: unknown;
}

// ---------- Abstract Adapter ----------

interface APIAdapter<TExternal, TInternal> {
  toInternal(external: TExternal): TInternal;
  toExternal(internal: TInternal): Record<string, unknown>;
  mapError(error: Error): Error;
}

// ---------- Concrete Adapter ----------

const STRIPE_STATUS_MAP: Record<string, InvoiceStatus> = {
  draft: InvoiceStatus.DRAFT,
  open: InvoiceStatus.SENT,
  paid: InvoiceStatus.PAID,
  uncollectible: InvoiceStatus.OVERDUE,
  void: InvoiceStatus.VOID,
};

class StripeInvoiceAdapter implements APIAdapter<Record<string, any>, Invoice> {
  toInternal(external: Record<string, any>): Invoice {
    return {
      id: `stripe_${external.id}`,
      externalId: external.id,
      provider: "stripe",
      amountCents: external.amount_due,
      currency: external.currency.toUpperCase(),
      status: STRIPE_STATUS_MAP[external.status] ?? InvoiceStatus.DRAFT,
      customerEmail: external.customer_email ?? "",
      dueAt: external.due_date ? new Date(external.due_date * 1000) : undefined,
      paidAt: external.status_transitions?.paid_at
        ? new Date(external.status_transitions.paid_at * 1000)
        : undefined,
      lineItems: (external.lines?.data ?? []).map((line: any) => ({
        description: line.description,
        amountCents: line.amount,
        quantity: line.quantity,
      })),
      raw: external,
    };
  }

  toExternal(internal: Invoice): Record<string, unknown> {
    return {
      amount: internal.amountCents,
      currency: internal.currency.toLowerCase(),
      customer_email: internal.customerEmail,
    };
  }

  mapError(error: Error): Error {
    return error;
  }
}

// ---------- Adapter Registry ----------

class AdapterRegistry {
  private static adapters = new Map<string, APIAdapter<any, any>>();

  static register(provider: string, adapter: APIAdapter<any, any>): void {
    this.adapters.set(provider, adapter);
  }

  static get<E, I>(provider: string): APIAdapter<E, I> {
    const adapter = this.adapters.get(provider);
    if (!adapter) throw new Error(`No adapter for provider '${provider}'`);
    return adapter;
  }
}

AdapterRegistry.register("stripe", new StripeInvoiceAdapter());
```

**Key principles:**
- **Raw data preservation**: Always store `raw` response for debugging. Adapter bugs are common; you need the original data.
- **Cents not dollars**: Convert all monetary amounts to integer cents to avoid floating-point errors.
- **Error mapping**: Each adapter converts vendor-specific errors into domain-level errors your app understands.
- **Integrates with `multi-provider-pattern`**: The adapter registry maps 1:1 with providers in the provider manager.

---

# 5. REQUEST/RESPONSE LOGGING AND AUDIT TRAILS

## Why Structured Logging

When a third-party API returns an unexpected result six hours later, you need a complete trace: what you sent, what they returned, how long it took, and which retry attempt succeeded. This is not optional in production.

## Python Implementation

```python
import json
import logging
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger("api.audit")


@dataclass
class APIAuditEntry:
    """Structured audit log entry for a single API call."""
    request_id: str
    timestamp: str
    provider: str
    method: str
    url: str
    status_code: Optional[int]
    latency_ms: float
    request_headers: dict          # Sanitized (no secrets)
    request_body_preview: Optional[str]  # First 1000 chars
    response_headers: Optional[dict]
    response_body_preview: Optional[str]  # First 2000 chars
    error: Optional[str] = None
    retry_attempt: int = 0
    circuit_breaker_state: Optional[str] = None


class RequestAuditLogger:
    """Log all API interactions for debugging and compliance.

    Integrates as a request/response interceptor on BaseAPIClient.
    Uses database-orm-patterns for persistent storage when db_session
    is provided; falls back to structured logging otherwise.
    """

    # Headers that must NEVER appear in logs
    REDACTED_HEADERS = frozenset({
        "authorization",
        "x-api-key",
        "cookie",
        "set-cookie",
        "proxy-authorization",
    })

    def __init__(
        self,
        provider_name: str = "unknown",
        db_session=None,
        log_body: bool = True,
        max_body_length: int = 2000,
    ):
        self.provider = provider_name
        self.db = db_session
        self.log_body = log_body
        self.max_body_length = max_body_length

    def _sanitize_headers(self, headers: dict) -> dict:
        """Remove sensitive headers before logging."""
        return {
            k: ("***REDACTED***" if k.lower() in self.REDACTED_HEADERS else v)
            for k, v in headers.items()
        }

    def _truncate(self, text: Optional[str]) -> Optional[str]:
        if text is None:
            return None
        if len(text) > self.max_body_length:
            return text[: self.max_body_length] + f"... ({len(text)} total chars)"
        return text

    def log_request(
        self,
        method: str,
        url: str,
        headers: dict,
        body: Any = None,
        retry_attempt: int = 0,
    ) -> str:
        """Log an outgoing request. Returns the request_id for correlation."""
        request_id = str(uuid.uuid4())

        body_preview = None
        if self.log_body and body is not None:
            if isinstance(body, (dict, list)):
                body_preview = self._truncate(json.dumps(body, default=str))
            elif isinstance(body, str):
                body_preview = self._truncate(body)

        entry = {
            "event": "api_request",
            "request_id": request_id,
            "provider": self.provider,
            "method": method.upper(),
            "url": url,
            "retry_attempt": retry_attempt,
            "headers": self._sanitize_headers(headers),
        }
        if body_preview:
            entry["body_preview"] = body_preview

        logger.info(json.dumps(entry, default=str))
        return request_id

    def log_response(
        self,
        request_id: str,
        method: str,
        url: str,
        status_code: int,
        response_headers: dict,
        response_body: Any,
        latency_ms: float,
        retry_attempt: int = 0,
        error: Optional[str] = None,
    ) -> APIAuditEntry:
        """Log an API response and optionally persist to database."""
        body_preview = None
        if self.log_body and response_body is not None:
            if isinstance(response_body, (dict, list)):
                body_preview = self._truncate(json.dumps(response_body, default=str))
            elif isinstance(response_body, str):
                body_preview = self._truncate(response_body)

        entry = APIAuditEntry(
            request_id=request_id,
            timestamp=datetime.utcnow().isoformat(),
            provider=self.provider,
            method=method.upper(),
            url=url,
            status_code=status_code,
            latency_ms=round(latency_ms, 2),
            request_headers={},    # Already logged in request phase
            request_body_preview=None,
            response_headers=self._sanitize_headers(response_headers),
            response_body_preview=body_preview,
            error=error,
            retry_attempt=retry_attempt,
        )

        # Structured log
        logger.info(json.dumps(asdict(entry), default=str))

        # Persist to database if available
        if self.db:
            self._persist(entry)

        return entry

    def _persist(self, entry: APIAuditEntry) -> None:
        """Persist audit entry to database using database-orm-patterns."""
        try:
            self.db.execute(
                """
                INSERT INTO api_audit_log
                    (request_id, timestamp, provider, method, url,
                     status_code, latency_ms, response_preview, error)
                VALUES
                    (:request_id, :timestamp, :provider, :method, :url,
                     :status_code, :latency_ms, :response_preview, :error)
                """,
                {
                    "request_id": entry.request_id,
                    "timestamp": entry.timestamp,
                    "provider": entry.provider,
                    "method": entry.method,
                    "url": entry.url,
                    "status_code": entry.status_code,
                    "latency_ms": entry.latency_ms,
                    "response_preview": entry.response_body_preview,
                    "error": entry.error,
                },
            )
            self.db.commit()
        except Exception as exc:
            logger.error("Failed to persist audit entry: %s", exc)


# ---------- Integration with BaseAPIClient ----------

def create_audit_interceptors(audit_logger: RequestAuditLogger):
    """Create request/response interceptors for BaseAPIClient (TypeScript).

    For the Python BaseAPIClient, wrap the .request() method instead:

        original_request = client.request
        def audited_request(method, path, **kwargs):
            request_id = audit_logger.log_request(method, path, ...)
            start = time.monotonic()
            try:
                result = original_request(method, path, **kwargs)
                audit_logger.log_response(request_id, ...)
                return result
            except Exception as exc:
                audit_logger.log_response(request_id, ..., error=str(exc))
                raise
        client.request = audited_request
    """
    pass
```

### TypeScript

```typescript
import { RequestInterceptor, ResponseInterceptor } from "unified-api-client";
import { randomUUID } from "crypto";

interface AuditEntry {
  requestId: string;
  timestamp: string;
  provider: string;
  method: string;
  url: string;
  statusCode?: number;
  latencyMs: number;
  error?: string;
}

const REDACTED_HEADERS = new Set([
  "authorization",
  "x-api-key",
  "cookie",
  "set-cookie",
]);

function sanitizeHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = REDACTED_HEADERS.has(key.toLowerCase())
      ? "***REDACTED***"
      : value;
  });
  return result;
}

/**
 * Create request/response interceptors for BaseAPIClient.
 *
 * Usage:
 *   const { requestInterceptor, responseInterceptor } = createAuditInterceptors("stripe");
 *   const client = new BaseAPIClient({
 *     baseUrl: "https://api.stripe.com",
 *     requestInterceptors: [requestInterceptor],
 *     responseInterceptors: [responseInterceptor],
 *   });
 */
function createAuditInterceptors(providerName: string, logger = console) {
  const requestTimestamps = new Map<string, number>();

  const requestInterceptor: RequestInterceptor = (url, init) => {
    const requestId = randomUUID();
    // Store requestId and start time on the init for correlation
    (init as any).__requestId = requestId;
    requestTimestamps.set(requestId, Date.now());

    logger.info(
      JSON.stringify({
        event: "api_request",
        requestId,
        provider: providerName,
        method: init.method,
        url,
      }),
    );
  };

  const responseInterceptor: ResponseInterceptor = (response, url) => {
    const requestId = (response as any).__requestId ?? "unknown";
    const startTime = requestTimestamps.get(requestId);
    const latencyMs = startTime ? Date.now() - startTime : -1;
    requestTimestamps.delete(requestId);

    logger.info(
      JSON.stringify({
        event: "api_response",
        requestId,
        provider: providerName,
        url,
        statusCode: response.status,
        latencyMs,
        headers: sanitizeHeaders(response.headers),
      }),
    );
  };

  return { requestInterceptor, responseInterceptor };
}
```

**Audit table migration** (uses `database-orm-patterns` migration helpers):

```sql
CREATE TABLE api_audit_log (
    id              BIGSERIAL PRIMARY KEY,
    request_id      UUID NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    provider        VARCHAR(64) NOT NULL,
    method          VARCHAR(10) NOT NULL,
    url             TEXT NOT NULL,
    status_code     SMALLINT,
    latency_ms      REAL NOT NULL,
    response_preview TEXT,
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_provider_ts ON api_audit_log (provider, timestamp);
CREATE INDEX idx_audit_request_id ON api_audit_log (request_id);

-- Partition by month for large-volume APIs
-- ALTER TABLE api_audit_log PARTITION BY RANGE (timestamp);
```

---

# 6. RATE LIMIT DETECTION AND BACKOFF

## Beyond Basic Retries

The `unified-api-client` already handles `429` status codes with exponential backoff and respects `Retry-After` headers. This section covers **advanced rate limit scenarios**: provider-specific header parsing, proactive rate limiting, sliding window tracking, and quota management.

## Provider Rate Limit Header Formats

Different providers communicate rate limits differently:

| Provider | Headers | Example |
|----------|---------|---------|
| **GitHub** | `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (Unix timestamp) | `Remaining: 42`, `Reset: 1699900000` |
| **Stripe** | `Retry-After` (seconds) | `Retry-After: 2` |
| **Twitter/X** | `x-rate-limit-limit`, `x-rate-limit-remaining`, `x-rate-limit-reset` (Unix timestamp) | Same as GitHub |
| **Shopify** | `X-Shopify-Shop-Api-Call-Limit` | `32/40` (used/max) |
| **Salesforce** | `Sforce-Limit-Info` | `api-usage=45/15000` |
| **Google** | `429` + `Retry-After` + error body with `retryDelay` | Varies by API |

## Python Implementation

```python
import time
import re
import threading
from dataclasses import dataclass
from typing import Optional
from unified_api_client import Result


@dataclass
class RateLimitInfo:
    """Parsed rate limit state from response headers."""
    limit: Optional[int] = None          # Max requests allowed
    remaining: Optional[int] = None      # Requests remaining
    reset_at: Optional[float] = None     # Unix timestamp when limit resets
    retry_after: Optional[float] = None  # Seconds to wait (from 429)

    @property
    def utilization(self) -> Optional[float]:
        """Return usage percentage (0.0 to 1.0)."""
        if self.limit and self.remaining is not None:
            return 1.0 - (self.remaining / self.limit)
        return None

    @property
    def seconds_until_reset(self) -> Optional[float]:
        """Seconds until the rate limit window resets."""
        if self.reset_at:
            return max(0.0, self.reset_at - time.time())
        return self.retry_after


class RateLimitParser:
    """Parse rate limit information from response headers.

    Handles the major vendor-specific header formats.
    """

    @staticmethod
    def parse_github(headers: dict) -> RateLimitInfo:
        return RateLimitInfo(
            limit=int(headers.get("X-RateLimit-Limit", 0)) or None,
            remaining=int(headers.get("X-RateLimit-Remaining", 0))
            if "X-RateLimit-Remaining" in headers else None,
            reset_at=float(headers.get("X-RateLimit-Reset", 0)) or None,
        )

    @staticmethod
    def parse_shopify(headers: dict) -> RateLimitInfo:
        call_limit = headers.get("X-Shopify-Shop-Api-Call-Limit", "")
        if "/" in call_limit:
            used, total = call_limit.split("/")
            limit = int(total)
            remaining = limit - int(used)
            return RateLimitInfo(limit=limit, remaining=remaining)
        return RateLimitInfo()

    @staticmethod
    def parse_salesforce(headers: dict) -> RateLimitInfo:
        info = headers.get("Sforce-Limit-Info", "")
        match = re.search(r"api-usage=(\d+)/(\d+)", info)
        if match:
            used, total = int(match.group(1)), int(match.group(2))
            return RateLimitInfo(limit=total, remaining=total - used)
        return RateLimitInfo()

    @staticmethod
    def parse_standard(headers: dict) -> RateLimitInfo:
        """Parse standard Retry-After header (used by most APIs on 429)."""
        retry_after = headers.get("Retry-After")
        if retry_after:
            try:
                return RateLimitInfo(retry_after=float(retry_after))
            except ValueError:
                # Some APIs use HTTP-date format
                pass
        return RateLimitInfo()


class ProactiveRateLimiter:
    """Proactively slow down requests as you approach rate limits.

    Instead of waiting for a 429, monitor remaining quota from response
    headers and throttle before hitting the limit.

    Works alongside the TokenBucketRateLimiter from unified-api-client.
    """

    def __init__(
        self,
        warn_threshold: float = 0.8,   # Start throttling at 80% usage
        block_threshold: float = 0.95,  # Block new requests at 95%
    ):
        self.warn_threshold = warn_threshold
        self.block_threshold = block_threshold
        self._last_info: Optional[RateLimitInfo] = None
        self._lock = threading.Lock()

    def update(self, info: RateLimitInfo) -> None:
        """Update rate limit state from the latest response."""
        with self._lock:
            self._last_info = info

    def should_throttle(self) -> Optional[float]:
        """Return seconds to sleep, or None if request can proceed.

        Call this BEFORE making a request. Returns a suggested delay
        if you are approaching the rate limit.
        """
        with self._lock:
            if not self._last_info:
                return None

            utilization = self._last_info.utilization
            if utilization is None:
                return None

            if utilization >= self.block_threshold:
                # Near limit: wait until reset
                wait = self._last_info.seconds_until_reset
                return wait if wait else 5.0

            if utilization >= self.warn_threshold:
                # Approaching limit: add progressive delay
                overage = (utilization - self.warn_threshold) / (
                    self.block_threshold - self.warn_threshold
                )
                return overage * 2.0  # 0-2 seconds delay

            return None


class SlidingWindowTracker:
    """Track your own request rate with a sliding window.

    Use this when the API does NOT return rate limit headers
    and you must self-enforce a known rate limit.
    """

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window = window_seconds
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> Optional[float]:
        """Try to acquire a request slot.

        Returns None if allowed, or seconds to wait if rate-limited.
        """
        with self._lock:
            now = time.monotonic()
            cutoff = now - self.window

            # Remove expired timestamps
            self._timestamps = [t for t in self._timestamps if t > cutoff]

            if len(self._timestamps) >= self.max_requests:
                # Must wait until the oldest request exits the window
                wait = self._timestamps[0] - cutoff
                return max(0.0, wait)

            self._timestamps.append(now)
            return None
```

### TypeScript

```typescript
interface RateLimitInfo {
  limit?: number;
  remaining?: number;
  resetAt?: number;       // Unix timestamp (ms)
  retryAfter?: number;    // Seconds
}

class RateLimitParser {
  static parseGitHub(headers: Headers): RateLimitInfo {
    return {
      limit: parseInt(headers.get("X-RateLimit-Limit") ?? "") || undefined,
      remaining: parseInt(headers.get("X-RateLimit-Remaining") ?? "") ?? undefined,
      resetAt: parseInt(headers.get("X-RateLimit-Reset") ?? "") * 1000 || undefined,
    };
  }

  static parseShopify(headers: Headers): RateLimitInfo {
    const callLimit = headers.get("X-Shopify-Shop-Api-Call-Limit") ?? "";
    const parts = callLimit.split("/");
    if (parts.length === 2) {
      const limit = parseInt(parts[1]);
      const remaining = limit - parseInt(parts[0]);
      return { limit, remaining };
    }
    return {};
  }

  static parseStandard(headers: Headers): RateLimitInfo {
    const retryAfter = headers.get("Retry-After");
    if (retryAfter) {
      return { retryAfter: parseFloat(retryAfter) };
    }
    return {};
  }
}

class ProactiveRateLimiter {
  private lastInfo?: RateLimitInfo;

  constructor(
    private warnThreshold = 0.8,
    private blockThreshold = 0.95,
  ) {}

  update(info: RateLimitInfo): void {
    this.lastInfo = info;
  }

  shouldThrottle(): number | null {
    if (!this.lastInfo?.limit || this.lastInfo.remaining === undefined) {
      return null;
    }

    const utilization = 1 - this.lastInfo.remaining / this.lastInfo.limit;

    if (utilization >= this.blockThreshold) {
      if (this.lastInfo.resetAt) {
        return Math.max(0, (this.lastInfo.resetAt - Date.now()) / 1000);
      }
      return 5;
    }

    if (utilization >= this.warnThreshold) {
      const overage =
        (utilization - this.warnThreshold) /
        (this.blockThreshold - this.warnThreshold);
      return overage * 2;
    }

    return null;
  }
}
```

---

# 7. TIMEOUT CASCADES AND DEADLINE PROPAGATION

## The Timeout Problem

When Service A calls Service B, which calls Service C, timeouts compound. If A has a 30s timeout and B has a 30s timeout, A could wait 30s for B which is itself waiting 30s for C -- exceeding A's own caller's timeout. Deadline propagation solves this by passing a shrinking time budget through the call chain.

## Deadline Context

```
Incoming request (budget: 10s)
  └─► Service A starts (remaining: 10s)
        ├─► Call API B (budget: 8s, keeping 2s for post-processing)
        │     └─► Call API C (budget: 5s, keeping 3s for B's post-processing)
        │           └─► Response in 2s (remaining: 3s returned to B)
        │     └─► B post-processes (remaining: 6s returned to A)
        └─► A post-processes (remaining: 4s)
```

### Python

```python
import time
import threading
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Optional

# Thread-local / async-safe deadline context
_deadline_var: ContextVar[Optional[float]] = ContextVar("deadline", default=None)


@dataclass
class DeadlineContext:
    """Propagate a time budget through a chain of API calls.

    Usage:
        # In your top-level handler:
        with DeadlineContext(budget_seconds=10.0):
            result_a = api_a.get("/data", timeout=DeadlineContext.remaining(reserve=2.0))
            result_b = api_b.get("/enrich", timeout=DeadlineContext.remaining(reserve=1.0))
            return combine(result_a, result_b)
    """

    budget_seconds: float
    _entered_at: Optional[float] = None
    _previous_deadline: Optional[float] = None

    def __enter__(self) -> "DeadlineContext":
        self._entered_at = time.monotonic()
        self._previous_deadline = _deadline_var.get(None)

        # If there's already a deadline, use the tighter one
        new_deadline = self._entered_at + self.budget_seconds
        if self._previous_deadline is not None:
            new_deadline = min(new_deadline, self._previous_deadline)

        _deadline_var.set(new_deadline)
        return self

    def __exit__(self, *exc):
        _deadline_var.set(self._previous_deadline)

    @staticmethod
    def remaining(reserve: float = 0.0, minimum: float = 1.0) -> float:
        """Get remaining time budget for the next API call.

        Args:
            reserve: Seconds to hold back for post-processing.
            minimum: Minimum timeout to return (never go below this).

        Returns:
            Timeout in seconds for the next call.

        Raises:
            DeadlineExceededError: If the deadline has already passed.
        """
        deadline = _deadline_var.get(None)
        if deadline is None:
            return 30.0  # Default timeout when no deadline is set

        remaining = deadline - time.monotonic() - reserve
        if remaining <= 0:
            raise DeadlineExceededError(
                f"Deadline exceeded (reserve={reserve}s)"
            )
        return max(remaining, minimum)

    @staticmethod
    def is_expired() -> bool:
        """Check if the current deadline has passed."""
        deadline = _deadline_var.get(None)
        if deadline is None:
            return False
        return time.monotonic() >= deadline


class DeadlineExceededError(Exception):
    """Raised when a deadline has been exceeded before making a call."""
    pass


# ---------- Usage with BaseAPIClient ----------

class DeadlineAwareClient:
    """Mixin that automatically applies deadline-based timeouts.

    Inherit alongside BaseAPIClient to get automatic deadline propagation.
    """

    def request(self, method, path, **kwargs):
        # If no explicit timeout, derive from deadline context
        if "timeout" not in kwargs or kwargs["timeout"] is None:
            try:
                kwargs["timeout"] = DeadlineContext.remaining(reserve=0.5)
            except DeadlineExceededError:
                from unified_api_client import TimeoutError
                raise TimeoutError(
                    f"Deadline exceeded before calling {method} {path}"
                )

        return super().request(method, path, **kwargs)
```

### TypeScript

```typescript
import { AsyncLocalStorage } from "async_hooks";

const deadlineStorage = new AsyncLocalStorage<number>();

class DeadlineExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeadlineExceededError";
  }
}

class DeadlineContext {
  /**
   * Run a function within a deadline budget.
   *
   * @example
   * await DeadlineContext.withBudget(10_000, async () => {
   *   const timeout = DeadlineContext.remaining(2000); // reserve 2s
   *   const result = await client.get("/data", { timeout });
   * });
   */
  static async withBudget<T>(
    budgetMs: number,
    fn: () => Promise<T>,
  ): Promise<T> {
    const existingDeadline = deadlineStorage.getStore();
    const newDeadline = Date.now() + budgetMs;
    const effectiveDeadline =
      existingDeadline !== undefined
        ? Math.min(existingDeadline, newDeadline)
        : newDeadline;

    return deadlineStorage.run(effectiveDeadline, fn);
  }

  /** Get remaining budget in milliseconds. */
  static remaining(reserveMs = 0, minimumMs = 1000): number {
    const deadline = deadlineStorage.getStore();
    if (deadline === undefined) return 30_000;

    const remaining = deadline - Date.now() - reserveMs;
    if (remaining <= 0) {
      throw new DeadlineExceededError(
        `Deadline exceeded (reserve=${reserveMs}ms)`,
      );
    }
    return Math.max(remaining, minimumMs);
  }

  static isExpired(): boolean {
    const deadline = deadlineStorage.getStore();
    if (deadline === undefined) return false;
    return Date.now() >= deadline;
  }
}
```

**When to use deadlines:**
- Multi-step workflows that call 2+ external APIs sequentially.
- Nested service calls (your API calls another internal service that calls a third-party).
- Any request with a user-facing SLA (the user expects a response within N seconds).

---

# 8. HEALTH CHECK PROBES FOR THIRD-PARTY DEPENDENCIES

## Why Health Probes

Your `/health` endpoint should report not just "my server is up" but "I can reach Stripe, I can reach the email provider, and my database is responding." This gives your load balancer, Kubernetes liveness probes, and monitoring dashboards actionable data.

## Python Implementation

```python
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class DependencyStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class DependencyHealth:
    """Health status of a single external dependency."""
    name: str
    status: DependencyStatus
    latency_ms: Optional[float] = None
    message: Optional[str] = None
    last_checked: Optional[float] = None
    consecutive_failures: int = 0


@dataclass
class HealthReport:
    """Aggregate health report for all dependencies."""
    status: DependencyStatus          # Worst status across all deps
    dependencies: list[DependencyHealth] = field(default_factory=list)
    checked_at: str = ""

    @property
    def is_healthy(self) -> bool:
        return self.status == DependencyStatus.HEALTHY


class HealthCheckRegistry:
    """Registry of health check probes for third-party dependencies.

    Usage:
        registry = HealthCheckRegistry()

        # Register probes
        registry.register("stripe", lambda: stripe_client.get("/v1/balance"))
        registry.register("sendgrid", lambda: sendgrid_client.get("/v3/scopes"))
        registry.register(
            "postgres",
            lambda: db.execute("SELECT 1"),
            timeout=5.0,
            critical=True,  # Failing this makes overall status UNHEALTHY
        )

        # Check all (parallel execution)
        report = registry.check_all()
        # report.status == DependencyStatus.HEALTHY

        # Use with scheduling-framework for periodic checks
        scheduler.add_job(registry.check_all, interval_seconds=60)
    """

    def __init__(self, default_timeout: float = 10.0):
        self._probes: dict[str, dict] = {}
        self._results: dict[str, DependencyHealth] = {}
        self._lock = threading.Lock()
        self.default_timeout = default_timeout

    def register(
        self,
        name: str,
        probe: Callable,
        timeout: Optional[float] = None,
        critical: bool = False,
    ) -> None:
        """Register a health check probe.

        Args:
            name: Dependency name (e.g., "stripe", "postgres").
            probe: Callable that raises on failure, returns anything on success.
            timeout: Max seconds for this probe. Default: 10s.
            critical: If True, failure makes overall status UNHEALTHY.
        """
        self._probes[name] = {
            "probe": probe,
            "timeout": timeout or self.default_timeout,
            "critical": critical,
        }

    def _check_one(self, name: str) -> DependencyHealth:
        """Execute a single health check probe."""
        probe_config = self._probes[name]
        start = time.monotonic()

        try:
            probe_config["probe"]()
            latency = (time.monotonic() - start) * 1000

            health = DependencyHealth(
                name=name,
                status=DependencyStatus.HEALTHY,
                latency_ms=round(latency, 2),
                last_checked=time.time(),
                consecutive_failures=0,
            )

            # Mark as degraded if latency is high
            if latency > probe_config["timeout"] * 500:  # >50% of timeout
                health.status = DependencyStatus.DEGRADED
                health.message = f"High latency: {latency:.0f}ms"

        except Exception as exc:
            latency = (time.monotonic() - start) * 1000
            prev = self._results.get(name)
            failures = (prev.consecutive_failures + 1) if prev else 1

            health = DependencyHealth(
                name=name,
                status=DependencyStatus.UNHEALTHY,
                latency_ms=round(latency, 2),
                message=str(exc)[:500],
                last_checked=time.time(),
                consecutive_failures=failures,
            )

        with self._lock:
            self._results[name] = health
        return health

    def check_all(self, parallel: bool = True) -> HealthReport:
        """Run all registered probes and produce an aggregate report.

        Args:
            parallel: If True, run probes concurrently (recommended).
        """
        from datetime import datetime

        results: list[DependencyHealth] = []

        if parallel and len(self._probes) > 1:
            with ThreadPoolExecutor(max_workers=len(self._probes)) as executor:
                futures = {
                    executor.submit(self._check_one, name): name
                    for name in self._probes
                }
                for future in as_completed(futures):
                    results.append(future.result())
        else:
            for name in self._probes:
                results.append(self._check_one(name))

        # Determine overall status
        overall = DependencyStatus.HEALTHY
        for dep in results:
            if dep.status == DependencyStatus.UNHEALTHY:
                if self._probes[dep.name].get("critical"):
                    overall = DependencyStatus.UNHEALTHY
                    break
                elif overall != DependencyStatus.UNHEALTHY:
                    overall = DependencyStatus.DEGRADED
            elif dep.status == DependencyStatus.DEGRADED:
                if overall == DependencyStatus.HEALTHY:
                    overall = DependencyStatus.DEGRADED

        return HealthReport(
            status=overall,
            dependencies=results,
            checked_at=datetime.utcnow().isoformat(),
        )

    def get_cached_report(self) -> HealthReport:
        """Return the last known health report without running new checks."""
        from datetime import datetime
        results = list(self._results.values())
        overall = DependencyStatus.HEALTHY
        for dep in results:
            if dep.status == DependencyStatus.UNHEALTHY:
                overall = DependencyStatus.UNHEALTHY
                break
            elif dep.status == DependencyStatus.DEGRADED:
                overall = DependencyStatus.DEGRADED
        return HealthReport(
            status=overall,
            dependencies=results,
            checked_at=datetime.utcnow().isoformat(),
        )
```

### TypeScript

```typescript
enum DependencyStatus {
  HEALTHY = "healthy",
  DEGRADED = "degraded",
  UNHEALTHY = "unhealthy",
}

interface DependencyHealth {
  name: string;
  status: DependencyStatus;
  latencyMs?: number;
  message?: string;
  lastChecked?: string;
  consecutiveFailures: number;
}

interface HealthReport {
  status: DependencyStatus;
  dependencies: DependencyHealth[];
  checkedAt: string;
}

class HealthCheckRegistry {
  private probes = new Map<
    string,
    { probe: () => Promise<void>; timeout: number; critical: boolean }
  >();
  private lastResults = new Map<string, DependencyHealth>();

  register(
    name: string,
    probe: () => Promise<void>,
    opts?: { timeout?: number; critical?: boolean },
  ): void {
    this.probes.set(name, {
      probe,
      timeout: opts?.timeout ?? 10_000,
      critical: opts?.critical ?? false,
    });
  }

  private async checkOne(name: string): Promise<DependencyHealth> {
    const config = this.probes.get(name)!;
    const start = Date.now();

    try {
      await Promise.race([
        config.probe(),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("Health check timeout")), config.timeout),
        ),
      ]);

      const latencyMs = Date.now() - start;
      const health: DependencyHealth = {
        name,
        status:
          latencyMs > config.timeout * 0.5
            ? DependencyStatus.DEGRADED
            : DependencyStatus.HEALTHY,
        latencyMs,
        lastChecked: new Date().toISOString(),
        consecutiveFailures: 0,
      };
      this.lastResults.set(name, health);
      return health;
    } catch (err) {
      const prev = this.lastResults.get(name);
      const health: DependencyHealth = {
        name,
        status: DependencyStatus.UNHEALTHY,
        latencyMs: Date.now() - start,
        message: (err as Error).message.slice(0, 500),
        lastChecked: new Date().toISOString(),
        consecutiveFailures: (prev?.consecutiveFailures ?? 0) + 1,
      };
      this.lastResults.set(name, health);
      return health;
    }
  }

  async checkAll(): Promise<HealthReport> {
    const results = await Promise.all(
      [...this.probes.keys()].map((name) => this.checkOne(name)),
    );

    let overall = DependencyStatus.HEALTHY;
    for (const dep of results) {
      if (dep.status === DependencyStatus.UNHEALTHY) {
        const config = this.probes.get(dep.name)!;
        if (config.critical) {
          overall = DependencyStatus.UNHEALTHY;
          break;
        }
        overall = DependencyStatus.DEGRADED;
      } else if (dep.status === DependencyStatus.DEGRADED) {
        if (overall === DependencyStatus.HEALTHY) {
          overall = DependencyStatus.DEGRADED;
        }
      }
    }

    return {
      status: overall,
      dependencies: results,
      checkedAt: new Date().toISOString(),
    };
  }
}
```

**Integration with `scheduling-framework`:** Register `registry.check_all()` as a periodic job (every 30-60 seconds) so your health endpoint returns cached results instantly instead of blocking on probe execution.

---

# 9. MOCK/STUB PATTERNS FOR DEVELOPMENT WITHOUT LIVE APIs

## Why Mock at the Client Level

Testing against live third-party APIs is slow, flaky, costs money, and risks hitting rate limits. Mock at the HTTP client boundary so your application code is exercised identically to production while the network layer is replaced.

## Python Implementation

```python
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from unified_api_client import Result, BaseAPIClient


@dataclass
class MockResponse:
    """A canned response for a mocked API route."""
    status_code: int = 200
    body: Any = None
    headers: dict = field(default_factory=dict)
    delay_seconds: float = 0.0    # Simulate latency
    side_effect: Optional[Callable] = None  # Raise or compute dynamically


@dataclass
class RecordedRequest:
    """A captured request for assertion in tests."""
    method: str
    path: str
    headers: dict
    body: Any
    params: Optional[dict] = None


class MockAPIClient(BaseAPIClient):
    """Drop-in replacement for BaseAPIClient in tests and local development.

    Routes requests to canned responses instead of making HTTP calls.
    Records all requests for assertion.

    Usage:
        mock = MockAPIClient(base_url="https://api.stripe.com/v1")

        # Register responses
        mock.when("GET", "/charges/ch_123").respond(
            status_code=200,
            body={"id": "ch_123", "amount": 5000},
        )

        mock.when("POST", "/charges").respond(
            status_code=201,
            body={"id": "ch_new", "amount": 1000},
        )

        # Use exactly like the real client
        result = mock.get("charges/ch_123")
        assert result.success
        assert result.data["amount"] == 5000

        # Assert requests were made
        assert mock.request_count == 2
        assert mock.last_request.method == "POST"
    """

    def __init__(self, base_url: str = "https://mock.api", **kwargs):
        super().__init__(base_url=base_url, **kwargs)
        self._routes: list[tuple[str, str, MockResponse]] = []
        self._recorded: list[RecordedRequest] = []
        self._default_response = MockResponse(
            status_code=404,
            body={"error": "No mock registered for this route"},
        )

    def when(self, method: str, path_pattern: str) -> "_MockRouteBuilder":
        """Register a mock route. path_pattern supports regex."""
        return _MockRouteBuilder(self, method.upper(), path_pattern)

    def _add_route(self, method: str, pattern: str, response: MockResponse):
        self._routes.append((method, pattern, response))

    @property
    def recorded_requests(self) -> list[RecordedRequest]:
        return list(self._recorded)

    @property
    def request_count(self) -> int:
        return len(self._recorded)

    @property
    def last_request(self) -> Optional[RecordedRequest]:
        return self._recorded[-1] if self._recorded else None

    def reset(self) -> None:
        """Clear all routes and recorded requests."""
        self._routes.clear()
        self._recorded.clear()

    def request(
        self,
        method: str,
        path: str,
        *,
        params=None,
        json=None,
        data=None,
        headers=None,
        timeout=None,
        **kwargs,
    ) -> Result:
        """Override: route to mock responses instead of HTTP."""
        import time as _time

        # Record the request
        self._recorded.append(
            RecordedRequest(
                method=method.upper(),
                path=path,
                headers=headers or {},
                body=json or data,
                params=params,
            )
        )

        # Find matching route
        response = self._find_route(method.upper(), path)

        # Simulate latency
        if response.delay_seconds > 0:
            _time.sleep(response.delay_seconds)

        # Side effect (raise exception, dynamic response)
        if response.side_effect:
            result = response.side_effect()
            if isinstance(result, Exception):
                raise result
            if isinstance(result, MockResponse):
                response = result

        # Build Result
        success = 200 <= response.status_code < 300
        return Result(
            success=success,
            data=response.body,
            status_code=response.status_code,
            headers=response.headers,
            error=None if success else str(response.body),
        )

    def _find_route(self, method: str, path: str) -> MockResponse:
        """Find the first matching route."""
        clean_path = path.lstrip("/")
        for route_method, pattern, response in self._routes:
            if route_method != method:
                continue
            clean_pattern = pattern.lstrip("/")
            if re.fullmatch(clean_pattern, clean_path):
                return response
        return self._default_response


class _MockRouteBuilder:
    """Fluent builder for mock route responses."""

    def __init__(self, client: MockAPIClient, method: str, pattern: str):
        self._client = client
        self._method = method
        self._pattern = pattern

    def respond(
        self,
        status_code: int = 200,
        body: Any = None,
        headers: Optional[dict] = None,
        delay_seconds: float = 0.0,
    ) -> MockAPIClient:
        self._client._add_route(
            self._method,
            self._pattern,
            MockResponse(
                status_code=status_code,
                body=body,
                headers=headers or {},
                delay_seconds=delay_seconds,
            ),
        )
        return self._client

    def raise_error(self, exception: Exception) -> MockAPIClient:
        self._client._add_route(
            self._method,
            self._pattern,
            MockResponse(side_effect=lambda: (_ for _ in ()).throw(exception)),
        )
        return self._client

    def respond_with(self, fn: Callable[[], MockResponse]) -> MockAPIClient:
        """Dynamic response based on a factory function."""
        self._client._add_route(
            self._method,
            self._pattern,
            MockResponse(side_effect=fn),
        )
        return self._client
```

### TypeScript

```typescript
import { Result, BaseAPIClient } from "unified-api-client";

interface MockResponseConfig {
  statusCode?: number;
  body?: unknown;
  headers?: Record<string, string>;
  delayMs?: number;
  sideEffect?: () => unknown | Promise<unknown>;
}

interface RecordedRequest {
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
  params?: Record<string, string>;
}

class MockAPIClient {
  private routes: Array<{
    method: string;
    pattern: RegExp;
    response: Required<MockResponseConfig>;
  }> = [];
  private _recorded: RecordedRequest[] = [];

  when(method: string, pathPattern: string) {
    return {
      respond: (config: MockResponseConfig = {}): MockAPIClient => {
        this.routes.push({
          method: method.toUpperCase(),
          pattern: new RegExp(`^/?${pathPattern.replace(/^\//, "")}$`),
          response: {
            statusCode: config.statusCode ?? 200,
            body: config.body ?? null,
            headers: config.headers ?? {},
            delayMs: config.delayMs ?? 0,
            sideEffect: config.sideEffect ?? (() => null),
          },
        });
        return this;
      },
    };
  }

  get recordedRequests(): ReadonlyArray<RecordedRequest> {
    return this._recorded;
  }

  get requestCount(): number {
    return this._recorded.length;
  }

  get lastRequest(): RecordedRequest | undefined {
    return this._recorded[this._recorded.length - 1];
  }

  reset(): void {
    this.routes = [];
    this._recorded = [];
  }

  async request<T = unknown>(
    method: string,
    path: string,
    options: {
      params?: Record<string, string>;
      json?: unknown;
      body?: BodyInit;
      headers?: Record<string, string>;
      timeout?: number;
    } = {},
  ): Promise<Result<T>> {
    this._recorded.push({
      method: method.toUpperCase(),
      path,
      headers: options.headers,
      body: options.json ?? options.body,
      params: options.params,
    });

    const route = this.routes.find(
      (r) =>
        r.method === method.toUpperCase() &&
        r.pattern.test(path.replace(/^\//, "")),
    );

    const response = route?.response ?? {
      statusCode: 404,
      body: { error: "No mock registered" },
      headers: {},
      delayMs: 0,
      sideEffect: () => null,
    };

    if (response.delayMs > 0) {
      await new Promise((r) => setTimeout(r, response.delayMs));
    }

    const sideResult = await response.sideEffect();
    if (sideResult instanceof Error) throw sideResult;

    const success = response.statusCode >= 200 && response.statusCode < 300;
    return {
      success,
      data: response.body as T,
      statusCode: response.statusCode,
      headers: response.headers,
      error: success ? undefined : JSON.stringify(response.body),
    };
  }

  // Convenience methods matching BaseAPIClient interface
  async get<T = unknown>(path: string, options?: any): Promise<Result<T>> {
    return this.request<T>("GET", path, options);
  }

  async post<T = unknown>(path: string, options?: any): Promise<Result<T>> {
    return this.request<T>("POST", path, options);
  }

  async put<T = unknown>(path: string, options?: any): Promise<Result<T>> {
    return this.request<T>("PUT", path, options);
  }

  async delete<T = unknown>(path: string, options?: any): Promise<Result<T>> {
    return this.request<T>("DELETE", path, options);
  }
}
```

## Test Fixture Patterns

```python
# conftest.py (pytest)
import pytest


@pytest.fixture
def mock_stripe():
    """Pre-configured mock Stripe client for tests."""
    mock = MockAPIClient(base_url="https://api.stripe.com/v1")

    # Common successful responses
    mock.when("GET", r"charges/ch_\w+").respond(
        body={"id": "ch_test", "amount": 5000, "currency": "usd", "status": "succeeded"},
    )
    mock.when("POST", "charges").respond(
        status_code=201,
        body={"id": "ch_new", "amount": 1000, "currency": "usd"},
    )
    mock.when("GET", "balance").respond(
        body={"available": [{"amount": 100000, "currency": "usd"}]},
    )

    return mock


@pytest.fixture
def mock_stripe_failing():
    """Stripe mock that simulates failures for resilience tests."""
    mock = MockAPIClient(base_url="https://api.stripe.com/v1")

    call_count = 0

    def flaky_response():
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            return MockResponse(status_code=503, body={"error": "Service unavailable"})
        return MockResponse(status_code=200, body={"id": "ch_recovered"})

    mock.when("POST", "charges").respond_with(flaky_response)
    return mock


def test_circuit_breaker_opens_on_failures(mock_stripe_failing):
    """Test that circuit breaker opens after threshold failures."""
    breaker = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))

    failures = 0
    for _ in range(5):
        try:
            breaker.execute(lambda: mock_stripe_failing.post("charges", json={}))
        except (CircuitOpenError, Exception):
            failures += 1

    assert breaker.state == CircuitState.OPEN
    assert breaker.metrics.total_rejections > 0
```

## Environment-Based Client Selection

```python
import os


def create_api_client(provider: str) -> BaseAPIClient:
    """Factory that returns mock or real client based on environment.

    Set API_MOCK_MODE=1 for local development without live APIs.
    """
    if os.getenv("API_MOCK_MODE") == "1":
        from api_mocks import get_mock_client
        return get_mock_client(provider)

    # Production: return real client
    from api_clients import get_real_client
    return get_real_client(provider)
```

---

# INTEGRATES WITH

| Module / Skill | Relationship | How They Connect |
|---|---|---|
| **`unified-api-client`** (module) | **Base class** | This skill's patterns extend `BaseAPIClient`, `Result`, `AuthStrategy`, and the exception hierarchy. Circuit breakers wrap the `.request()` method. Audit loggers use the request/response interceptor hooks. |
| **`multi-provider-pattern`** (skill) | **Provider abstraction** | Multi-provider handles *which* API to call (primary vs fallback). This skill handles *how* to call it (circuit breaker, timeout, logging). Use both together: provider manager selects the provider, then this skill's middleware wraps the actual call. |
| **`caching-universal`** (skill) | **Response caching** | Cache successful API responses using `caching-universal`'s multi-layer strategy (L1 in-memory, L2 Redis). This skill's adapter layer is the ideal cache boundary: cache the *internal* model, not the raw vendor response. |
| **`database-orm-patterns`** (module) | **Persistence** | Webhook events (`WebhookEvent` model) and audit logs (`api_audit_log` table) use `BaseModel` and `BaseRepository` for persistence. Migration helpers from this module create the required tables. |
| **`scheduling-framework`** (module) | **Periodic tasks** | Use the scheduler for: (1) periodic health check probes, (2) polling-based API integrations (when webhooks are unavailable), (3) token refresh jobs, (4) audit log cleanup/rotation. |
| **`rate-limiting-universal`** (skill) | **Inbound vs outbound** | `rate-limiting-universal` protects *your* API from being overwhelmed. This skill handles rate limits *imposed on you* by third-party APIs. They are complementary. |
| **`security-owasp`** (skill) | **Secret management** | API keys, OAuth secrets, and webhook signing secrets must be stored securely. Follow `security-owasp` patterns for secret rotation, environment variable management, and encrypted storage. |
| **`testing-strategies`** (skill) | **Test patterns** | The mock/stub patterns in Section 9 align with `testing-strategies` for integration and contract testing. Use `MockAPIClient` in unit tests, real clients in integration tests with recorded fixtures. |

## Decision Matrix: When to Use Which Pattern

| Scenario | Patterns to Apply |
|---|---|
| Single API, low volume | Adapter + Audit logging |
| Single API, high volume | + Rate limit detection + Proactive throttling |
| Single API, critical path | + Circuit breaker + Health probe |
| Multiple providers for same function | + `multi-provider-pattern` for fallback |
| User-delegated OAuth access | + OAuth token manager |
| Receiving webhooks | + Webhook verifier + Idempotency layer |
| Multi-step API orchestration | + Deadline propagation |
| Local development | + Mock client + Environment-based selection |
| All production integrations | All of the above |

---

# Research Update: February 2026

## OWASP Top 10 2025 (Updated from 2021)

The OWASP Top 10 was updated in 2025 with significant changes:

| Rank | 2025 Category | Change from 2021 |
|------|--------------|------------------|
| A01 | Broken Access Control | Stays #1, now includes SSRF |
| A02 | Security Misconfiguration | Surged from #5 to #2 |
| A03 | **Software Supply Chain Failures** | **NEW** (expanded from Vulnerable Components) |
| A04 | Cryptographic Failures | Dropped from #2 |
| A05 | Injection | Dropped from #3 |
| A06 | Insecure Design | Dropped from #4 |
| A10 | **Mishandling of Exceptional Conditions** | **NEW** — improper error handling, failing open |

**Key takeaways for middleware:**
- Supply chain security (A03) has highest exploit+impact scores — validate ALL dependencies
- Error handling (A10) is now a Top 10 category — never fail open, never expose stack traces
- Security misconfiguration at #2 — enforce secure defaults in all middleware configs
