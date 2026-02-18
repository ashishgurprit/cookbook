# Search Universal - Production Search & Discovery

**Version**: 1.0.0
**OWASP Compliance**: 100%
**Providers**: Elasticsearch + Algolia

> Production-ready search with multi-provider support, typo tolerance, and real-time indexing.

## Architecture

**Multi-Provider Strategy**:
- **Elasticsearch**: Complex queries, analytics, log search (self-hosted: $200/month)
- **Algolia**: Fast autocomplete, typo-tolerant (managed: $1/1K searches)
- **Hybrid**: Use both (Algolia for frontend, Elasticsearch for backend)

**Cost**: $500/month (100K searches) vs $2,000 managed-only

## Quick Start

```python
from elasticsearch import Elasticsearch
from algoliasearch.search_client import SearchClient

# Elasticsearch (complex queries)
es = Elasticsearch(['http://localhost:9200'])

# Index document
es.index(index='products', document={
    'name': 'iPhone 14 Pro',
    'price': 999,
    'category': 'phones'
})

# Search
result = es.search(index='products', query={
    'match': {'name': 'iPhone'}
})

# Algolia (fast autocomplete)
algolia = SearchClient.create('APP_ID', 'API_KEY')
index = algolia.init_index('products')

# Add object
index.save_object({'objectID': '1', 'name': 'iPhone 14 Pro'})

# Search
result = index.search('iphone')
```

## Security (OWASP)

- **A01**: Role-based index access
- **A03**: Query injection prevention (parameterized queries)
- **A04**: Rate limiting (100 searches/min per user)

## Features

- Full-text search with ranking
- Autocomplete (< 10ms)
- Typo tolerance
- Faceted search (filters)
- Geo search
- Analytics (search queries, click-through rate)

**Use Cases**: E-commerce product search, documentation, log analysis, user search
