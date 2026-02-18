---
name: multi-provider-pattern
description: "Production-ready multi-provider service architecture with automatic fallback, cost optimization, and provider abstraction. Use when: (1) Building services with multiple API backends, (2) Implementing provider fallback chains, (3) Optimizing costs across providers, (4) Creating resilient third-party integrations, (5) Abstract vendor-specific implementations. Triggers on 'multi-provider', 'provider fallback', 'service abstraction', 'API failover', or multi-backend architecture requests."
license: Proprietary
---

# Multi-Provider Service Pattern

Production-ready architecture for building services with multiple provider backends, automatic fallback, and cost optimization.

## Quick Reference: Common Use Cases

| Service Type | Primary Provider | Fallback Provider | Reason |
|-------------|------------------|-------------------|--------|
| OCR | Google Vision API | Tesseract (local) | Cost + offline capability |
| Translation | Google Translate | MyMemory/LibreTranslate | Cost + rate limits |
| Payment | Stripe | PayPal | Geographic coverage |
| Email | SendGrid | AWS SES | Reliability + cost |
| SMS | Twilio | Vonage | Delivery rates by region |
| Cloud Storage | S3 | Azure Blob | Vendor lock-in mitigation |
| Maps/Geocoding | Google Maps | OpenStreetMap | Cost + usage limits |
| AI/LLM | OpenAI | Anthropic/Local | Availability + features |

---

# WHY MULTI-PROVIDER ARCHITECTURE?

## The Problem with Single-Provider Systems

```
Single Provider Issues:
├── Vendor Lock-in
│   └── Impossible to switch without rewrite
├── Cost Escalation
│   └── No leverage when pricing changes
├── Service Disruptions
│   └── Single point of failure
├── Rate Limits
│   └── Hard caps on scaling
├── Geographic Limitations
│   └── Service unavailable in regions
└── Feature Gaps
    └── Missing capabilities for edge cases
```

## The Multi-Provider Solution

```
Benefits:
├── Resilience: Automatic failover
├── Cost Optimization: Use cheapest for each task
├── Flexibility: Switch providers without code changes
├── Scalability: Distribute load across providers
├── Quality: Choose best provider per use case
└── Compliance: Geographic data residency
```

---

# ARCHITECTURE PATTERN

## Core Components

```
┌─────────────────────────────────────────┐
│          Client Application             │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│       Service Interface (Abstract)      │
│  - process(input) → output              │
│  - validate(input) → bool               │
│  - estimate_cost(input) → float         │
└───────────────┬─────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────┐
│         Provider Manager                │
│  - Select provider by strategy          │
│  - Implement fallback chain             │
│  - Track metrics & costs                │
│  - Cache results                        │
└───────────┬───────────┬─────────────────┘
            │           │
            ▼           ▼
┌─────────────┐   ┌─────────────┐
│ Provider A  │   │ Provider B  │
│ (Primary)   │   │ (Fallback)  │
└─────────────┘   └─────────────┘
```

## Pattern Flow

```
1. REQUEST
   └─► Provider Manager receives request

2. PROVIDER SELECTION
   ├─► Strategy: Cost, Quality, Speed, Availability
   └─► Select primary provider

3. EXECUTION
   ├─► Try primary provider
   ├─► If success → Return result
   └─► If failure → Proceed to fallback

4. FALLBACK CHAIN
   ├─► Try secondary provider
   ├─► Try tertiary provider
   └─► If all fail → Raise exception or use default

5. POST-PROCESSING
   ├─► Log metrics (cost, latency, provider used)
   ├─► Cache result (if applicable)
   └─► Return to client
```

---

# IMPLEMENTATION GUIDE

## Step 1: Define Abstract Base Class

### Base Provider Interface

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from dataclasses import dataclass
from enum import Enum

class ProviderStatus(Enum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"

@dataclass
class ProviderResult:
    """Standardized result from any provider"""
    success: bool
    data: Any
    provider_name: str
    cost: float
    latency_ms: float
    metadata: Dict[str, Any]
    error: Optional[str] = None

class BaseProvider(ABC):
    """Abstract base class for all providers"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
        self._status = ProviderStatus.AVAILABLE

    @abstractmethod
    def process(self, input_data: Any, **kwargs) -> ProviderResult:
        """Process the input and return standardized result"""
        pass

    @abstractmethod
    def validate_input(self, input_data: Any) -> bool:
        """Validate input before processing"""
        pass

    @abstractmethod
    def estimate_cost(self, input_data: Any) -> float:
        """Estimate cost for this operation"""
        pass

    @abstractmethod
    def health_check(self) -> ProviderStatus:
        """Check provider availability"""
        pass

    @property
    def is_available(self) -> bool:
        """Quick availability check"""
        return self._status == ProviderStatus.AVAILABLE

    @property
    def priority(self) -> int:
        """Provider priority (lower = higher priority)"""
        return self.config.get('priority', 100)
```

## Step 2: Implement Concrete Providers

### Example: OCR Provider Implementation

```python
import time
from google.cloud import vision
import pytesseract
from PIL import Image

class GoogleVisionProvider(BaseProvider):
    """Google Vision API OCR Provider"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.client = vision.ImageAnnotatorClient()
        self.cost_per_image = 0.0015  # $1.50 per 1000 images

    def process(self, image_path: str, **kwargs) -> ProviderResult:
        start_time = time.time()

        try:
            with open(image_path, 'rb') as image_file:
                content = image_file.read()

            image = vision.Image(content=content)
            response = self.client.text_detection(image=image)

            if response.error.message:
                raise Exception(response.error.message)

            text = response.text_annotations[0].description if response.text_annotations else ""
            confidence = self._calculate_confidence(response)

            latency_ms = (time.time() - start_time) * 1000

            return ProviderResult(
                success=True,
                data={
                    'text': text,
                    'confidence': confidence,
                    'language': self._detect_language(response)
                },
                provider_name=self.name,
                cost=self.cost_per_image,
                latency_ms=latency_ms,
                metadata={'annotations_count': len(response.text_annotations)}
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return ProviderResult(
                success=False,
                data=None,
                provider_name=self.name,
                cost=0.0,
                latency_ms=latency_ms,
                metadata={},
                error=str(e)
            )

    def validate_input(self, image_path: str) -> bool:
        import os
        return os.path.exists(image_path) and os.path.getsize(image_path) < 20 * 1024 * 1024

    def estimate_cost(self, image_path: str) -> float:
        return self.cost_per_image

    def health_check(self) -> ProviderStatus:
        try:
            # Quick test with minimal API call
            return ProviderStatus.AVAILABLE
        except:
            return ProviderStatus.UNAVAILABLE

    def _calculate_confidence(self, response) -> float:
        if not response.text_annotations:
            return 0.0
        return response.text_annotations[0].confidence if hasattr(response.text_annotations[0], 'confidence') else 0.9

    def _detect_language(self, response) -> str:
        if response.text_annotations and hasattr(response.text_annotations[0], 'locale'):
            return response.text_annotations[0].locale
        return 'unknown'


class TesseractProvider(BaseProvider):
    """Tesseract OCR Provider (Local, Free)"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.cost_per_image = 0.0  # Free!

    def process(self, image_path: str, **kwargs) -> ProviderResult:
        start_time = time.time()

        try:
            image = Image.open(image_path)
            text = pytesseract.image_to_string(image)

            # Tesseract confidence data
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
            confidences = [int(conf) for conf in data['conf'] if conf != '-1']
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0

            latency_ms = (time.time() - start_time) * 1000

            return ProviderResult(
                success=True,
                data={
                    'text': text,
                    'confidence': avg_confidence / 100,  # Normalize to 0-1
                    'language': pytesseract.image_to_osd(image)['lang'] if image else 'unknown'
                },
                provider_name=self.name,
                cost=0.0,
                latency_ms=latency_ms,
                metadata={'word_count': len(data['text'])}
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return ProviderResult(
                success=False,
                data=None,
                provider_name=self.name,
                cost=0.0,
                latency_ms=latency_ms,
                metadata={},
                error=str(e)
            )

    def validate_input(self, image_path: str) -> bool:
        import os
        return os.path.exists(image_path)

    def estimate_cost(self, image_path: str) -> float:
        return 0.0

    def health_check(self) -> ProviderStatus:
        try:
            pytesseract.get_tesseract_version()
            return ProviderStatus.AVAILABLE
        except:
            return ProviderStatus.UNAVAILABLE
```

## Step 3: Build Provider Manager

### Provider Selection Strategies

```python
from enum import Enum
from typing import List, Optional
import logging

class SelectionStrategy(Enum):
    COST = "cost"              # Choose cheapest
    QUALITY = "quality"        # Choose highest quality
    SPEED = "speed"            # Choose fastest
    PRIORITY = "priority"      # Use configured priority order
    ROUND_ROBIN = "round_robin"  # Distribute load

class ProviderManager:
    """Manages multiple providers with fallback and strategy selection"""

    def __init__(self, providers: List[BaseProvider], strategy: SelectionStrategy = SelectionStrategy.PRIORITY):
        self.providers = sorted(providers, key=lambda p: p.priority)
        self.strategy = strategy
        self.logger = logging.getLogger(__name__)
        self._round_robin_index = 0

    def process(self, input_data: Any, **kwargs) -> ProviderResult:
        """Process input using provider selection strategy with fallback"""

        # Select provider order based on strategy
        provider_order = self._select_provider_order(input_data)

        last_error = None

        for provider in provider_order:
            # Skip unavailable providers
            if not provider.is_available:
                self.logger.warning(f"Skipping unavailable provider: {provider.name}")
                continue

            # Validate input
            if not provider.validate_input(input_data):
                self.logger.warning(f"Input validation failed for {provider.name}")
                continue

            # Try processing
            self.logger.info(f"Attempting processing with {provider.name}")
            result = provider.process(input_data, **kwargs)

            if result.success:
                self.logger.info(f"Successfully processed with {provider.name} (cost: ${result.cost:.4f}, latency: {result.latency_ms:.0f}ms)")
                self._log_metrics(result)
                return result
            else:
                last_error = result.error
                self.logger.warning(f"{provider.name} failed: {result.error}")

        # All providers failed
        raise Exception(f"All providers failed. Last error: {last_error}")

    def _select_provider_order(self, input_data: Any) -> List[BaseProvider]:
        """Select provider order based on strategy"""

        if self.strategy == SelectionStrategy.PRIORITY:
            return self.providers  # Already sorted by priority

        elif self.strategy == SelectionStrategy.COST:
            return sorted(self.providers, key=lambda p: p.estimate_cost(input_data))

        elif self.strategy == SelectionStrategy.QUALITY:
            # Assume Google Vision > Tesseract for quality
            # In production, use historical quality metrics
            return sorted(self.providers, key=lambda p: p.config.get('quality_score', 0), reverse=True)

        elif self.strategy == SelectionStrategy.SPEED:
            # Use historical latency data
            return sorted(self.providers, key=lambda p: p.config.get('avg_latency_ms', 1000))

        elif self.strategy == SelectionStrategy.ROUND_ROBIN:
            ordered = self.providers[self._round_robin_index:] + self.providers[:self._round_robin_index]
            self._round_robin_index = (self._round_robin_index + 1) % len(self.providers)
            return ordered

        return self.providers

    def estimate_cost(self, input_data: Any) -> Dict[str, float]:
        """Estimate cost across all providers"""
        return {
            provider.name: provider.estimate_cost(input_data)
            for provider in self.providers
        }

    def health_check_all(self) -> Dict[str, ProviderStatus]:
        """Check health of all providers"""
        return {
            provider.name: provider.health_check()
            for provider in self.providers
        }

    def _log_metrics(self, result: ProviderResult):
        """Log metrics for monitoring/analytics"""
        # In production: send to DataDog, CloudWatch, etc.
        self.logger.info(f"METRICS: provider={result.provider_name} cost={result.cost} latency={result.latency_ms}ms success={result.success}")
```

## Step 4: Configuration Management

### YAML Configuration

```yaml
# config/providers.yaml

ocr_service:
  strategy: "priority"  # cost, quality, speed, priority, round_robin

  providers:
    - name: "GoogleVisionProvider"
      enabled: true
      priority: 1
      quality_score: 0.95
      config:
        credentials_path: "/path/to/google-credentials.json"
        max_file_size_mb: 20

    - name: "TesseractProvider"
      enabled: true
      priority: 2
      quality_score: 0.75
      config:
        language: "eng"
        oem: 3  # OCR Engine Mode
        psm: 6  # Page Segmentation Mode

translation_service:
  strategy: "cost"

  providers:
    - name: "GoogleTranslateProvider"
      enabled: true
      priority: 1
      quality_score: 0.95
      config:
        api_key: "${GOOGLE_TRANSLATE_API_KEY}"
        cost_per_char: 0.00002

    - name: "MyMemoryProvider"
      enabled: true
      priority: 2
      quality_score: 0.70
      config:
        email: "user@example.com"
        cost_per_char: 0.0  # Free tier

    - name: "LibreTranslateProvider"
      enabled: true
      priority: 3
      quality_score: 0.65
      config:
        api_url: "http://localhost:5000"
        cost_per_char: 0.0  # Self-hosted

payment_service:
  strategy: "priority"

  providers:
    - name: "StripeProvider"
      enabled: true
      priority: 1
      config:
        api_key: "${STRIPE_API_KEY}"
        webhook_secret: "${STRIPE_WEBHOOK_SECRET}"
        supported_countries: ["US", "CA", "GB", "AU", "EU"]

    - name: "PayPalProvider"
      enabled: true
      priority: 2
      config:
        client_id: "${PAYPAL_CLIENT_ID}"
        client_secret: "${PAYPAL_CLIENT_SECRET}"
        supported_countries: ["ALL"]
```

### Configuration Loader

```python
import yaml
import os
from typing import Dict, Any

class ConfigLoader:
    """Load and parse provider configuration"""

    @staticmethod
    def load(config_path: str) -> Dict[str, Any]:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Substitute environment variables
        return ConfigLoader._substitute_env_vars(config)

    @staticmethod
    def _substitute_env_vars(config: Any) -> Any:
        """Recursively substitute ${VAR} with env values"""
        if isinstance(config, dict):
            return {k: ConfigLoader._substitute_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [ConfigLoader._substitute_env_vars(item) for item in config]
        elif isinstance(config, str) and config.startswith('${') and config.endswith('}'):
            var_name = config[2:-1]
            return os.getenv(var_name, config)
        return config
```

---

# ADVANCED PATTERNS

## Pattern 1: Caching Layer

```python
import hashlib
import json
from typing import Optional

class CachedProviderManager(ProviderManager):
    """Provider manager with result caching"""

    def __init__(self, providers: List[BaseProvider], strategy: SelectionStrategy, cache_backend):
        super().__init__(providers, strategy)
        self.cache = cache_backend

    def process(self, input_data: Any, use_cache: bool = True, **kwargs) -> ProviderResult:
        if use_cache:
            cache_key = self._generate_cache_key(input_data, kwargs)
            cached_result = self.cache.get(cache_key)

            if cached_result:
                self.logger.info(f"Cache hit: {cache_key}")
                return cached_result

        result = super().process(input_data, **kwargs)

        if result.success and use_cache:
            cache_key = self._generate_cache_key(input_data, kwargs)
            self.cache.set(cache_key, result, ttl=3600)  # 1 hour

        return result

    def _generate_cache_key(self, input_data: Any, kwargs: Dict) -> str:
        """Generate deterministic cache key"""
        # For file inputs, use file hash
        if isinstance(input_data, str) and os.path.isfile(input_data):
            with open(input_data, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            return f"ocr:{file_hash}"

        # For text inputs, use content hash
        content = json.dumps({'input': input_data, 'kwargs': kwargs}, sort_keys=True)
        return hashlib.md5(content.encode()).hexdigest()
```

## Pattern 2: Cost Tracking

```python
from datetime import datetime
from typing import List

class CostTracker:
    """Track costs across providers"""

    def __init__(self):
        self.costs: List[Dict] = []

    def record(self, result: ProviderResult):
        self.costs.append({
            'provider': result.provider_name,
            'cost': result.cost,
            'timestamp': datetime.utcnow(),
            'success': result.success
        })

    def get_total_cost(self, provider_name: Optional[str] = None) -> float:
        if provider_name:
            return sum(c['cost'] for c in self.costs if c['provider'] == provider_name)
        return sum(c['cost'] for c in self.costs)

    def get_cost_by_provider(self) -> Dict[str, float]:
        from collections import defaultdict
        costs = defaultdict(float)
        for c in self.costs:
            costs[c['provider']] += c['cost']
        return dict(costs)

    def get_average_cost(self) -> float:
        if not self.costs:
            return 0.0
        return self.get_total_cost() / len(self.costs)
```

## Pattern 3: Circuit Breaker

```python
from datetime import datetime, timedelta

class CircuitBreaker:
    """Prevent cascading failures"""

    def __init__(self, failure_threshold: int = 5, timeout_seconds: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout = timedelta(seconds=timeout_seconds)
        self.failures = {}
        self.last_failure_time = {}

    def is_open(self, provider_name: str) -> bool:
        """Check if circuit is open (provider disabled)"""
        if provider_name not in self.failures:
            return False

        # Check if timeout has passed
        if datetime.utcnow() - self.last_failure_time[provider_name] > self.timeout:
            # Reset circuit
            self.failures[provider_name] = 0
            return False

        return self.failures[provider_name] >= self.failure_threshold

    def record_failure(self, provider_name: str):
        self.failures[provider_name] = self.failures.get(provider_name, 0) + 1
        self.last_failure_time[provider_name] = datetime.utcnow()

    def record_success(self, provider_name: str):
        self.failures[provider_name] = 0
```

---

# BEST PRACTICES

## 1. Provider Selection Strategy

```
Choose strategy based on use case:

PRIORITY:
  ✓ When quality matters most
  ✓ Clear provider hierarchy
  ✓ Fallback for reliability

COST:
  ✓ High-volume operations
  ✓ Budget-constrained applications
  ✓ Similar quality across providers

QUALITY:
  ✓ Critical accuracy requirements
  ✓ Customer-facing results
  ✓ Willing to pay for best results

SPEED:
  ✓ Real-time applications
  ✓ User-facing interactive features
  ✓ Latency-sensitive workflows

ROUND_ROBIN:
  ✓ Load distribution
  ✓ Avoid rate limits
  ✓ Equal provider costs
```

## 2. Error Handling

```python
# DO: Graceful degradation
try:
    result = provider_manager.process(input_data)
except Exception as e:
    logger.error(f"All providers failed: {e}")
    # Return cached result or default
    return get_cached_or_default(input_data)

# DON'T: Silent failures
try:
    result = provider_manager.process(input_data)
except:
    pass  # ❌ Never do this
```

## 3. Monitoring & Alerting

```python
# Track key metrics
- Success rate per provider
- Average latency per provider
- Cost per operation
- Fallback frequency
- Provider availability

# Alert on:
- Provider failure rate > 10%
- Cost spike > 2x average
- All providers unavailable
- Excessive fallback usage
```

## 4. Testing Strategy

```python
# Unit tests: Test each provider in isolation
# Integration tests: Test provider manager with mocked providers
# E2E tests: Test with real providers (dev accounts)
# Load tests: Verify fallback under load
# Chaos tests: Random provider failures
```

---

# IMPLEMENTATION CHECKLIST

See `checklists/implementation.md` for complete checklist.

## Quick Checklist

- [ ] Define abstract base class with standard interface
- [ ] Implement concrete providers (minimum 2)
- [ ] Add input validation for each provider
- [ ] Implement cost estimation
- [ ] Add health checks
- [ ] Build provider manager with selection strategy
- [ ] Configure fallback chain
- [ ] Add caching layer (optional)
- [ ] Implement circuit breaker (recommended)
- [ ] Add logging and metrics
- [ ] Write configuration file
- [ ] Create provider factory/registry
- [ ] Add unit tests for each provider
- [ ] Add integration tests for manager
- [ ] Document provider-specific requirements
- [ ] Set up monitoring/alerting

---

# REAL-WORLD EXAMPLES

## Example 1: OCR Service with Cost Optimization

```
Scenario: Process 10,000 documents/month
Primary: Google Vision ($1.50/1000) = $15/month
Fallback: Tesseract (free) = $0/month

Strategy: Use Tesseract for simple documents, Google Vision for complex

Result: $5/month (67% cost reduction)
```

## Example 2: Translation Pipeline with Quality Thresholds

```
Scenario: Translate user-generated content
Primary: Google Translate (high quality, $20/1M chars)
Fallback: MyMemory (good quality, free)
Last resort: LibreTranslate (basic quality, self-hosted)

Strategy: Try free providers first, upgrade if confidence < 0.8

Result: 80% free tier coverage, premium for quality-critical content
```

## Example 3: Payment Processing with Geographic Routing

```
Scenario: Global e-commerce
Primary: Stripe (US, EU, AU)
Fallback: PayPal (worldwide)

Strategy: Route by customer country

Result: Optimal fees per region, 99.9% payment acceptance
```

---

# FILE REFERENCES

- `templates/abstract_provider.py` - Base provider class template
- `templates/concrete_provider.py` - Example concrete implementations
- `templates/provider_manager.py` - Provider manager with strategies
- `templates/provider_config.yaml` - Configuration examples
- `checklists/implementation.md` - Complete implementation checklist
- `checklists/testing.md` - Testing strategy checklist
- `references/examples.md` - Real-world implementation examples
- `references/providers.md` - Common provider APIs and docs
- `examples/ocr_service.py` - Complete OCR service example
- `examples/translation_service.py` - Complete translation service example
- `examples/payment_service.py` - Complete payment service example
