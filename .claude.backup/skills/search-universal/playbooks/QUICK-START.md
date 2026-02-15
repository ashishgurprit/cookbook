# Search Universal - Quick Start (15 min)

## Setup

```bash
# Install Elasticsearch (Docker)
docker run -d -p 9200:9200 -e "discovery.type=single-node" elasticsearch:8.11.0

# Install Python client
pip install elasticsearch algoliasearch

# Environment
ELASTICSEARCH_URL=http://localhost:9200
ALGOLIA_APP_ID=your-app-id
ALGOLIA_API_KEY=your-api-key
```

## Basic Usage

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(['http://localhost:9200'])

# Index
es.index(index='products', document={'name': 'iPhone', 'price': 999})

# Search
result = es.search(index='products', query={'match': {'name': 'iPhone'}})
print(result['hits']['hits'])

# Autocomplete
result = es.search(index='products', query={
    'match_phrase_prefix': {'name': 'iPh'}
})
```

## Cost

- Elasticsearch (self-hosted): $200/month
- Algolia (managed): $1/1K searches
- **Total**: $500/month (100K searches)
