# Analytics Universal - Quick Start (10 min)

## Setup

```bash
# Install Segment client
pip install analytics-python

# Environment
SEGMENT_WRITE_KEY=your-write-key
```

## Basic Usage

```python
import analytics

analytics.write_key = 'YOUR_WRITE_KEY'

# Track purchase
analytics.track('user-123', 'Order Completed', {
    'order_id': 'order-456',
    'revenue': 99.99,
    'products': ['product-1', 'product-2']
})

# User properties
analytics.identify('user-123', {
    'email': 'user@example.com',
    'name': 'John Doe',
    'plan': 'premium'
})
```

## Cost

- Segment: $120/month (1M events)
- Mixpanel: Free (100K events)
- Google Analytics: Free
- **Total**: $300/month
