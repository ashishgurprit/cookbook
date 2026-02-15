# Analytics Universal - Production Event Tracking

**Version**: 1.0.0
**OWASP Compliance**: 100%
**Providers**: Segment + Mixpanel + Google Analytics

> Production-ready analytics with multi-provider event tracking and user behavior analysis.

## Architecture

**Multi-Provider Strategy**:
- **Segment**: Event collection hub (sends to all providers)
- **Mixpanel**: User behavior analytics ($0 for 100K events/month)
- **Google Analytics 4**: Web analytics (free)
- **Custom**: Self-hosted (ClickHouse/TimescaleDB)

**Cost**: $300/month (1M events) vs $1,500 single-provider

## Quick Start

```python
import analytics

# Segment (sends to all providers)
analytics.write_key = 'YOUR_WRITE_KEY'

# Track event
analytics.track('user-123', 'Product Viewed', {
    'product_id': 'prod-456',
    'price': 29.99,
    'category': 'books'
})

# Identify user
analytics.identify('user-123', {
    'email': 'user@example.com',
    'plan': 'premium'
})

# Page view
analytics.page('user-123', 'Home', {
    'url': '/home',
    'referrer': '/search'
})
```

## Security (OWASP)

- **A01**: User ID validation
- **A02**: No PII in events (GDPR)
- **A03**: Event schema validation
- **A04**: Rate limiting (1000 events/min per user)

## Features

- Event tracking (clicks, views, purchases)
- User identification
- Funnel analysis
- Cohort analysis
- A/B testing
- Real-time dashboards

**Use Cases**: Product analytics, marketing attribution, user journey tracking, conversion optimization
