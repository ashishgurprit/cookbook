---
name: affiliate-monetization
description: "Production-ready affiliate monetization system with hybrid link routing, Amazon Associates management, product scraping, and content injection. Use when: (1) Adding affiliate links to content, (2) Managing Amazon Associates tags across regions or brands, (3) Scraping Amazon for product data (ASINs, prices, ratings), (4) Building hybrid monetization with Amazon + Skimlinks, (5) Injecting affiliate product boxes into HTML content, (6) Tracking affiliate link performance. Triggers on 'affiliate links', 'monetization', 'Amazon Associates', 'product scraping', 'Skimlinks', 'ASIN', or 'affiliate revenue'."
license: Proprietary
---

# Affiliate Monetization System

Production-ready hybrid affiliate link management, product discovery, and content monetization framework. Handles Amazon Associates direct tagging, Skimlinks fallback routing, Playwright-based product scraping, AI-powered product discovery, and affiliate HTML injection into content pipelines.

## Table of Contents

1. [Overview](#overview)
2. [Module Dependency Diagram](#module-dependency-diagram)
3. [Quick Start](#quick-start)
4. [Amazon Affiliate Management](#amazon-affiliate-management)
5. [Product Scraping](#product-scraping)
6. [AI-Powered Product Discovery](#ai-powered-product-discovery)
7. [Skimlinks Integration](#skimlinks-integration)
8. [Hybrid Monetization Router](#hybrid-monetization-router)
9. [Content Monetization Injection](#content-monetization-injection)
10. [Statistics and Reporting](#statistics-and-reporting)
11. [Environment Variables](#environment-variables)
12. [Integrates With](#integrates-with)

---

## Overview

### The Problem

Content pipelines produce HTML with raw outbound links. Converting these to revenue-generating affiliate links manually is slow, error-prone, and breaks in RSS feeds, newsletters, and ad-blocker environments.

### The Solution

A three-tier monetization router that "hardcodes" affiliate attribution into HTML before database storage, ensuring it works everywhere:

```
Priority 1: Amazon   -- Direct Associates tag (highest commission, 100% attribution)
Priority 2: Skimlinks -- Auto-monetize 60,000+ other merchants
Priority 3: Passthrough -- Raw link fallback for non-monetizable URLs
```

### Key Capabilities

| Capability | Description | Revenue Impact |
|------------|-------------|----------------|
| **Multi-region Amazon tags** | Region-specific and brand-specific affiliate tags | +15-30% with localized links |
| **Hybrid routing** | Amazon direct + Skimlinks fallback | Monetize 90%+ of outbound links |
| **Browser scraping** | Playwright-based ASIN extraction | Automated product discovery |
| **AI product finder** | Perplexity/OpenAI product search | No CAPTCHA, no bot detection |
| **Best sellers scraping** | Category-based bestseller lists | Pre-validated high-converting products |
| **Content injection** | HTML box, inline, and list styles | Native-looking affiliate sections |
| **Hardcoded links** | Links baked into HTML before storage | Works in RSS, email, ad-blocked |

### Critical Rules

- **ALWAYS** include FTC disclosure text with affiliate links
- **ALWAYS** use `rel="nofollow sponsored"` on affiliate anchor tags
- **NEVER** cloak affiliate links from users without disclosure
- **NEVER** store raw affiliate credentials in code or version control
- **ALWAYS** respect Amazon Associates Program Operating Agreement rate limits
- **ALWAYS** deduplicate ASINs when scraping across categories

---

## Module Dependency Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                    Content Pipeline                               │
│          (content-pipeline-orchestrator module)                   │
└──────────┬───────────────────────────────────────────────────────┘
           │ Raw HTML with untagged links
           ▼
┌──────────────────────────────────────────────────────────────────┐
│               Hybrid Monetization Router                         │
│                                                                  │
│  ┌─────────────┐   ┌──────────────┐   ┌────────────────┐       │
│  │   Amazon     │   │  Skimlinks   │   │  Passthrough   │       │
│  │  Direct Tag  │──▶│   Redirect   │──▶│   Raw Link     │       │
│  │  (Priority 1)│   │  (Priority 2)│   │  (Priority 3)  │       │
│  └──────┬──────┘   └──────┬───────┘   └───────┬────────┘       │
│         │                  │                    │                │
│         ▼                  ▼                    ▼                │
│  ┌──────────────────────────────────────────────────────┐       │
│  │             Monetized HTML Output                     │       │
│  │  - rel="nofollow sponsored" on all affiliate links    │       │
│  │  - FTC disclosure text appended                       │       │
│  │  - Stats tracked per method                           │       │
│  └──────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────────┐
│               Product Data Sources                               │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐      │
│  │  Playwright   │  │  Best Seller │  │  AI Product      │      │
│  │  Scraper      │  │  Scraper     │  │  Finder          │      │
│  │  (Browser)    │  │  (HTTP/BS4)  │  │  (Perplexity/    │      │
│  │              │  │              │  │   OpenAI)         │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────────┘      │
│         │                  │                  │                  │
│         ▼                  ▼                  ▼                  │
│  ┌──────────────────────────────────────────────────────┐       │
│  │           Products Database (JSON/CSV/DB)             │       │
│  │         (database-orm-patterns module)                 │       │
│  └──────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────┘
```

### External Module Dependencies

```
affiliate-monetization
├── unified-api-client module        -- HTTP calls to Perplexity/OpenAI APIs
├── batch-processing skill           -- Bulk keyword scraping, CSV processing
├── content-pipeline-orchestrator    -- Pipeline stage integration
└── database-orm-patterns module     -- Tracking data persistence
```

---

## Quick Start

### 1. Basic Amazon Link Generation

```python
from affiliate import AffiliateManager

manager = AffiliateManager(default_region="us")

# Create link from ASIN
url = manager.create_amazon_link("B08ABC1234", brand="GREEK")
# => "https://www.amazon.com/dp/B08ABC1234?tag=greekmyths-20"

# Tag an existing Amazon URL
tagged = manager.add_affiliate_tag_to_url(
    "https://www.amazon.com/dp/B08ABC1234",
    brand="HINDU"
)
# => "https://www.amazon.com/dp/B08ABC1234?tag=hindustories-20"
```

### 2. Monetize All Links in HTML

```python
from monetization import MonetizationManager

monetizer = MonetizationManager(
    amazon_tag="yoursite-20",
    skimlinks_id="102394X1592384"
)

raw_html = '''
<p>Check out <a href="https://www.amazon.com/dp/B08ABC1234">this book</a>
and <a href="https://www.barnesandnoble.com/w/example">this one too</a>.</p>
'''

monetized_html = monetizer.monetize_content(raw_html)
# Amazon link gets ?tag=yoursite-20
# B&N link gets Skimlinks redirect wrapper
# Both get rel="nofollow sponsored"

print(monetizer.get_stats())
# => {"amazon": 1, "skimlinks": 1, "passthrough": 0, "skipped": 0}
```

### 3. Scrape Products for Keywords

```python
import asyncio
from amazon_scraper import AmazonScraper

scraper = AmazonScraper(affiliate_tag="yoursite-20", headless=True)

products = asyncio.run(
    scraper.scrape_keyword("greek mythology kids", max_results=3)
)

for p in products:
    print(f"{p.title} — {p.affiliate_url}")
```

### 4. AI-Powered Product Discovery (No Scraping)

```python
import asyncio
from perplexity_amazon import PerplexityAmazonFinder

finder = PerplexityAmazonFinder()

products = asyncio.run(
    finder.find_products("norse mythology children's books", max_results=5)
)
# No CAPTCHA, no bot detection, AI understands context
```

---

## Amazon Affiliate Management

### Multi-Region Domain Support

The system supports Amazon storefronts across multiple regions. Each region uses its own domain for link construction.

```python
# Supported Amazon domains
AMAZON_DOMAINS = {
    "us": "amazon.com",
    "uk": "amazon.co.uk",
    "ca": "amazon.ca",
    "au": "amazon.com.au",
    "in": "amazon.in",
    "de": "amazon.de",
    "fr": "amazon.fr",
    "es": "amazon.es",
    "it": "amazon.it",
    "jp": "amazon.co.jp"
}

# Short-link domains (also recognized as Amazon)
SHORT_DOMAINS = {"amzn.to", "amzn.com", "a.co"}
```

**Usage pattern:**

```python
manager = AffiliateManager(default_region="uk")

# Uses amazon.co.uk automatically
url = manager.create_amazon_link("B08XYZ5678")
# => "https://www.amazon.co.uk/dp/B08XYZ5678?tag=yoursite-21"
```

### Brand-Specific Affiliate Tags

Different product categories or brands can use different tracking IDs. This enables per-brand revenue attribution and separate Amazon Associates accounts.

```python
# Brand configuration structure
brand_config = {
    "BRAND_KEY": {
        "tag": "tracking-tag-20",
        "keywords": ["keyword1", "keyword2"],
        "default_products": [
            {"title": "Product Name", "asin": "B08XXXXX01"},
            {"title": "Another Product", "asin": "B08XXXXX02"}
        ]
    }
}
```

**How tag selection works:**

```python
manager = AffiliateManager()

# Brand-specific tag
tag = manager.get_affiliate_tag("GREEK")   # => "greekmyths-20"
tag = manager.get_affiliate_tag("HINDU")   # => "hindustories-20"
tag = manager.get_affiliate_tag("UNKNOWN") # => fallback default tag
```

**Configuration storage:**

```
config_path/
├── affiliates.json     # Brand-to-tag mapping and default products
└── products.json       # Product database (ASIN -> product details)
```

### ASIN Extraction and Validation

ASINs (Amazon Standard Identification Numbers) are 10-character alphanumeric identifiers. The system extracts them from multiple sources.

```python
import re

# Pattern for ASIN extraction from text
ASIN_PATTERN = r'\b([B][0-9A-Z]{9})\b'

# Extract from Amazon URL path
URL_ASIN_PATTERN = r'/dp/([A-Z0-9]{10})'

# Extract from search result card (Playwright)
asin = await card.get_attribute("data-asin")

# Extract from HTML link href
href = link['href']
match = re.search(r'/dp/([A-Z0-9]{10})', href)
if match:
    asin = match.group(1)

# Validate ASIN format
def is_valid_asin(asin: str) -> bool:
    return bool(asin) and len(asin) == 10 and asin[0] in ('B', '0')
```

### SiteStripe URL Generation

SiteStripe is Amazon's browser toolbar for generating affiliate links. This system automates the same URL format programmatically:

```python
def create_affiliate_url(asin: str, tag: str, domain: str = "amazon.com") -> str:
    """
    Generate the same URL format as Amazon SiteStripe.

    Format: https://www.{domain}/dp/{ASIN}?tag={tracking-id}
    """
    return f"https://www.{domain}/dp/{asin}?tag={tag}"
```

**Adding tags to existing URLs:**

```python
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def add_affiliate_tag(url: str, tag: str) -> str:
    """Add or replace affiliate tag on any Amazon URL."""
    parsed = urlparse(url)

    # Verify it is an Amazon URL
    if "amazon" not in parsed.netloc:
        return url

    # Parse existing query params
    query_params = parse_qs(parsed.query)

    # Add/replace tag
    query_params["tag"] = [tag]

    # Rebuild URL
    new_query = urlencode(query_params, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))
```

### Product Database Management

Products are stored locally for quick access and to avoid repeated scraping.

```python
from dataclasses import dataclass

@dataclass
class AffiliateProduct:
    """Affiliate product record."""
    title: str
    asin: str = ""
    affiliate_url: str = ""
    description: str = ""
    brand: str = ""
    category: str = ""

# Add product to database
manager = AffiliateManager()
product = manager.add_product(
    asin="0440406943",
    title="D'Aulaires' Book of Greek Myths",
    brand="GREEK",
    description="Classic children's mythology collection"
)

# Retrieve recommended products for a brand
products = manager.get_recommended_products("GREEK", limit=3)
```

---

## Product Scraping

### Strategy 1: Playwright Browser Automation

Full browser automation for scraping Amazon search results. Extracts ASINs, titles, prices, ratings, images, and review counts.

**When to use:** You need rich product data (images, ratings, review counts) and are running on infrastructure that supports headless browsers.

```python
import asyncio
from amazon_scraper import AmazonScraper

scraper = AmazonScraper(
    affiliate_tag="yoursite-20",
    region="us",
    headless=True  # Set False for debugging
)

# Single keyword search
products = asyncio.run(
    scraper.scrape_keyword(
        keyword="sikh stories for kids",
        max_results=3,
        department="stripbooks"  # Amazon department filter
    )
)
```

**Extracted data per product:**

```python
@dataclass
class AmazonProduct:
    keyword: str          # Search keyword used
    title: str            # Product title
    asin: str             # 10-char Amazon ID
    url: str              # Raw product URL
    affiliate_url: str    # URL with tracking tag
    price: str            # Display price (e.g., "$14.99")
    rating: str           # Star rating text
    reviews_count: str    # Number of reviews
    image_url: str        # Product image URL
    rank: int             # Position in search results
```

**Selectors used for extraction:**

```python
# Search result container
RESULT_SELECTOR = '[data-component-type="s-search-result"]'

# Individual fields
TITLE_SELECTOR = "h2 a span"
LINK_SELECTOR = "h2 a"
PRICE_SELECTOR = ".a-price .a-offscreen"
RATING_SELECTOR = ".a-icon-star-small span"
IMAGE_SELECTOR = "img.s-image"
ASIN_ATTRIBUTE = "data-asin"

# Product detail page (single ASIN lookup)
DETAIL_TITLE = "#productTitle"
DETAIL_PRICE = ".a-price .a-offscreen"
DETAIL_RATING = "#acrPopover"
```

### Bulk Keyword Processing from CSV

Process many keywords at once with built-in rate limiting. Integrates with the `batch-processing` skill for progress tracking and error recovery.

```python
# CSV format:
# keyword
# greek mythology kids
# norse gods children
# buddhist stories

products = asyncio.run(
    scraper.scrape_keywords_from_csv(
        csv_path="data/keywords.csv",
        output_path="data/products_results.csv",
        keyword_column="keyword",
        max_results_per_keyword=3
    )
)
# Built-in 3-second delay between keywords for rate limiting
```

**Output CSV columns:**

```
keyword, title, asin, url, affiliate_url, price, rating, reviews_count, image_url, rank
```

### Single ASIN Lookup

Fetch details for a known ASIN without searching:

```python
product = asyncio.run(scraper.scrape_single_asin("0440406943"))
if product:
    print(f"{product.title} — {product.price}")
```

### Rate Limiting and Anti-Bot Measures

```python
# User-agent rotation
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Browser context setup with realistic headers
context = await browser.new_context(user_agent=USER_AGENT)

# Inter-request delays
DELAY_BETWEEN_KEYWORDS = 3      # seconds (Playwright scraper)
DELAY_BETWEEN_CATEGORIES = 2.0  # seconds (Best sellers scraper)
DELAY_BETWEEN_AI_REQUESTS = 0.5 # seconds (Perplexity finder)

# Timeout configuration
PAGE_LOAD_TIMEOUT = 30000        # 30 seconds
SELECTOR_WAIT_TIMEOUT = 10000    # 10 seconds
API_REQUEST_TIMEOUT = 60         # 60 seconds
```

**Best practices for avoiding blocks:**

```
1. Always use headless=True in production
2. Set realistic user-agent strings
3. Maintain 2-5 second delays between requests
4. Handle missing selectors gracefully (Amazon changes layout)
5. Rotate user-agents for high-volume scraping
6. Use AI-powered finders (Perplexity) for reliability
7. Prefer Best Sellers scraping (public pages, less bot detection)
```

### Strategy 2: Best Sellers Scraping (HTTP + BeautifulSoup)

Lighter-weight scraping that uses HTTP requests instead of a full browser. Targets Amazon's public Best Sellers pages for pre-validated popular products.

**When to use:** You want high-converting products without keyword guessing. Best Sellers pages are public and less aggressively bot-protected.

```python
from amazon_bestsellers import AmazonBestSellersScraper

scraper = AmazonBestSellersScraper(
    affiliate_tag="yoursite-20",
    region="us"
)

# Scrape a single category
products = scraper.scrape_category(
    category="childrens-mythology",
    max_products=50
)

# Scrape all categories (40+ categories available)
all_products = scraper.scrape_all_categories(
    max_products_per_category=50,
    delay_between_requests=2.0
)
# Automatically deduplicates by ASIN
```

**Available category groups:**

```
Children's Books (8 categories)
├── childrens-books, childrens-mythology, childrens-religious
├── childrens-history, childrens-classics, childrens-literature
├── childrens-geography, childrens-biographies

Mythology (7 categories)
├── greek-roman-mythology, norse-mythology, eastern-mythology
├── celtic-mythology, fairy-tales, folklore, legends-sagas

Religion & Spirituality (7 categories)
├── buddhism, hinduism, islam, christianity
├── judaism, comparative-religion, eastern-philosophy

History by Region (11 categories)
├── ancient-history, european-history, asian-history
├── african-history, middle-east-history, americas-history
├── greek-history, roman-history, egypt-history
├── india-history, china-history, japan-history ...

Cultural Studies (4 categories)
├── cultural-anthropology, ethnic-studies
├── indigenous-peoples, native-american

+ Legends, Language, Philosophy, Classical Literature,
  Adventure, Art, Education categories (10+ more)
```

**ASIN extraction from Best Sellers pages (multi-method):**

```python
# Method 1: data-asin attribute on container
asin = item.get('data-asin')

# Method 2: Extract from link href with regex
link = item.find('a', href=True)
match = re.search(r'/dp/([A-Z0-9]{10})', link['href'])
asin = match.group(1) if match else None

# Title extraction (multiple fallback selectors)
title = (
    item.find('div', class_=re.compile(r'.*p13n-sc-truncate.*')) or
    item.find('span', class_=re.compile(r'.*line-clamp.*')) or
    item.find('a', attrs={'aria-label': True})
)
```

**Deduplication across categories:**

```python
seen_asins = set()
unique_products = []

for product in all_products:
    if product.asin not in seen_asins:
        seen_asins.add(product.asin)
        unique_products.append(product)
```

**Category statistics:**

```python
stats = scraper.get_category_stats(products)
# {
#   "total_products": 2500,
#   "unique_asins": 1847,
#   "by_category": {"childrens-mythology": 50, ...},
#   "categories_scraped": 40
# }
```

---

## AI-Powered Product Discovery

### Perplexity AI Finder

Uses Perplexity's web-search-enabled LLM to find Amazon products. No browser automation, no CAPTCHA, no bot detection.

**When to use:** Reliability is paramount, or you need context-aware product matching (e.g., "books about kindness for 8-year-olds").

```python
import asyncio
from perplexity_amazon import PerplexityAmazonFinder

finder = PerplexityAmazonFinder(
    perplexity_api_key="pplx-...",
    amazon_tag="yoursite-20",
    region="us"
)

# Single keyword
products = asyncio.run(
    finder.find_products("japanese mythology for kids", max_results=3)
)
```

**Prompt engineering for product search:**

```python
def create_search_prompt(keyword: str, max_results: int, domain: str) -> str:
    return f"""Find the top {max_results} children's books or educational
products on Amazon.{domain} for the keyword "{keyword}".

For each product, provide:
1. Product title
2. ASIN (10-character Amazon product ID)
3. Current price (if available)
4. Star rating (if available)

Format your response as a JSON array like this:
[
  {{"title": "Product Name", "asin": "B08ABC1234", "price": "$14.99", "rating": "4.5"}}
]

Focus on products suitable for children ages 6-12. Only return results from Amazon."""
```

**API configuration:**

```python
# Perplexity API settings
API_URL = "https://api.perplexity.ai/chat/completions"
MODEL = "llama-3.1-sonar-small-128k-online"  # Web-search enabled, cost-effective
TEMPERATURE = 0.1  # Low for consistent results
MAX_TOKENS = 1000
```

### Batch Product Discovery

Process multiple keywords in parallel with concurrency control:

```python
keywords = [
    "greek mythology kids",
    "norse gods children",
    "buddhist stories kids",
    "hindu epics children",
    "japanese folklore kids"
]

results = asyncio.run(
    finder.batch_find_products(
        keywords=keywords,
        max_results_per_keyword=3,
        max_concurrent=5  # Concurrency limit via semaphore
    )
)

for keyword, products in results.items():
    print(f"'{keyword}': {len(products)} products found")
```

**Concurrency pattern using asyncio.Semaphore:**

```python
async def batch_find_products(keywords, max_concurrent=5):
    semaphore = asyncio.Semaphore(max_concurrent)

    async def search_with_limit(kw):
        async with semaphore:
            products = await find_products(kw)
            await asyncio.sleep(0.5)  # Delay between requests
            return kw, products

    tasks = [search_with_limit(kw) for kw in keywords]
    completed = await asyncio.gather(*tasks, return_exceptions=True)

    results = {}
    for result in completed:
        if isinstance(result, Exception):
            logger.error(f"Batch search error: {result}")
            continue
        keyword, products = result
        results[keyword] = products

    return results
```

### Response Parsing with Fallback

The AI response parser uses a two-phase approach:

```python
def parse_products(response_text: str, keyword: str) -> list:
    # Phase 1: Try structured JSON extraction
    json_match = re.search(r'\[.*\]', response_text, re.DOTALL)
    if json_match:
        products_data = json.loads(json_match.group())
        # Validate each ASIN is exactly 10 characters
        for item in products_data:
            if len(item.get("asin", "")) == 10:
                # Build product object
                ...

    # Phase 2: Fallback - extract raw ASINs from text
    if not products:
        asin_pattern = r'\b([B][0-9A-Z]{9})\b'
        asins = re.findall(asin_pattern, response_text)
        # Build minimal product objects (title may be empty)
        ...
```

### OpenAI GPT-4 Alternative

If Perplexity is unavailable, the same pattern works with OpenAI:

```python
from perplexity_amazon import OpenAIAmazonFinder

finder = OpenAIAmazonFinder(amazon_tag="yoursite-20")
products = asyncio.run(finder.find_products("celtic myths for kids"))
# Uses gpt-4o model, same response parsing logic
```

---

## Skimlinks Integration

### What is Skimlinks?

Skimlinks auto-monetizes outbound links for 60,000+ merchants. For any non-Amazon link, wrap it with Skimlinks redirect to earn commission.

### Redirect URL Format

```python
def wrap_skimlinks(url: str, pub_id: str) -> str:
    """
    Wrap URL with Skimlinks redirect.

    This hardcodes monetization into the HTML, ensuring it works in:
    - RSS feeds (no JavaScript needed)
    - Email newsletters
    - Ad-blocker environments (no client-side script to block)
    """
    from urllib.parse import quote_plus
    encoded_url = quote_plus(url)
    return f"https://go.redirectingat.com/?id={pub_id}&url={encoded_url}"
```

**Example:**

```
Input:  https://www.barnesandnoble.com/w/tales-of-guru-nanak
Output: https://go.redirectingat.com/?id=102394X1592384&url=https%3A%2F%2Fwww.barnesandnoble.com%2Fw%2Ftales-of-guru-nanak
```

### Priority Merchants

Merchants known to have good Skimlinks commission rates:

```python
PRIORITY_MERCHANTS = {
    # US Retailers
    "nordstrom.com", "saksfifthavenue.com", "bloomingdales.com",
    "macys.com", "target.com", "walmart.com", "bestbuy.com",
    "barnesandnoble.com", "booksamillion.com",

    # UK Retailers
    "asos.com", "selfridges.com", "harrods.com", "johnlewis.com",
    "waterstones.com", "whsmith.co.uk",

    # Global
    "ebay.com", "etsy.com", "bookdepository.com",
    "abebooks.com", "alibris.com", "thriftbooks.com"
}
```

### Hardcoded vs JavaScript Monetization

```
┌──────────────────────────────────┬─────────────────────────────────┐
│     Hardcoded (This System)      │     JavaScript (Traditional)    │
├──────────────────────────────────┼─────────────────────────────────┤
│ Links modified before storage    │ Links modified at page load     │
│ Works in RSS feeds               │ Breaks in RSS feeds             │
│ Works in email newsletters       │ Breaks in email                 │
│ Works with ad-blockers           │ Blocked by ad-blockers          │
│ No client-side dependency        │ Requires JS execution           │
│ One-time processing cost         │ Per-pageview processing cost    │
│ Harder to A/B test               │ Easy to A/B test                │
└──────────────────────────────────┴─────────────────────────────────┘
```

---

## Hybrid Monetization Router

### Routing Priority Logic

The router processes each URL through a priority chain:

```
URL Input
    │
    ├──► Is it a non-HTTP URL? ──► SKIP (anchors, mailto, etc.)
    │
    ├──► Is it a skip-listed domain? ──► SKIP
    │    (social media, search engines, own domain)
    │
    ├──► Is it an Amazon domain? ──► AMAZON DIRECT TAG
    │    (amazon.com, amzn.to, a.co, etc.)
    │
    ├──► Is Skimlinks configured? ──► SKIMLINKS REDIRECT
    │    (wraps URL for any other merchant)
    │
    └──► PASSTHROUGH (raw link, no monetization)
```

### Skip-Listed Domains

These domains are never monetized:

```python
SKIP_DOMAINS = {
    # Internal
    "localhost", "127.0.0.1",

    # Social media (no affiliate programs)
    "facebook.com", "twitter.com", "instagram.com",
    "youtube.com", "tiktok.com", "pinterest.com", "linkedin.com",

    # Reference (inappropriate to monetize)
    "wikipedia.org",

    # Search engines
    "google.com", "bing.com",

    # Own domain
    "yourdomain.com"
}
```

### Full Router Implementation Pattern

```python
class MonetizationRouter:
    """
    Hybrid monetization router.

    Processes HTML content and monetizes all outbound links
    using the highest-priority method available.
    """

    def __init__(self, amazon_tag: str, skimlinks_id: str = ""):
        self.amazon_tag = amazon_tag
        self.skimlinks_id = skimlinks_id
        self._stats = {"amazon": 0, "skimlinks": 0, "passthrough": 0, "skipped": 0}

    def monetize_content(self, html_content: str, brand: str = "") -> str:
        """Scan HTML and monetize all outbound links."""
        self._stats = {"amazon": 0, "skimlinks": 0, "passthrough": 0, "skipped": 0}

        # Regex pattern for href attributes in anchor tags
        link_pattern = r'(<a\s+[^>]*href\s*=\s*["\'])([^"\']+)(["\'][^>]*>)'

        def replace_link(match):
            prefix = match.group(1)
            url = match.group(2)
            suffix = match.group(3)

            monetized = self._process_url(url, brand)

            # Add rel="nofollow sponsored" for affiliate links
            if monetized.method in ["amazon", "skimlinks"]:
                if 'rel=' not in suffix.lower():
                    suffix = suffix.replace('>', ' rel="nofollow sponsored">')

            return f'{prefix}{monetized.monetized_url}{suffix}'

        return re.sub(link_pattern, replace_link, html_content, flags=re.IGNORECASE)

    def _process_url(self, url: str, brand: str = "") -> MonetizedLink:
        """Route a single URL through the priority chain."""
        # Guard: non-HTTP
        if not url or not url.startswith(("http://", "https://")):
            self._stats["skipped"] += 1
            return MonetizedLink(url, url, "skipped", "")

        domain = urlparse(url).netloc.lower().replace("www.", "")

        # Guard: skip-listed
        if self._should_skip(domain):
            self._stats["skipped"] += 1
            return MonetizedLink(url, url, "skipped", domain)

        # Priority 1: Amazon
        if self._is_amazon(domain):
            monetized = self._add_amazon_tag(url, brand)
            self._stats["amazon"] += 1
            return MonetizedLink(url, monetized, "amazon", domain)

        # Priority 2: Skimlinks
        if self.skimlinks_id:
            monetized = self._wrap_skimlinks(url)
            self._stats["skimlinks"] += 1
            return MonetizedLink(url, monetized, "skimlinks", domain)

        # Priority 3: Passthrough
        self._stats["passthrough"] += 1
        return MonetizedLink(url, url, "passthrough", domain)
```

### Amazon Tag Injection with Fallback

```python
def _add_amazon_tag(self, url: str, brand: str = "") -> str:
    """Add Associates tag with graceful error handling."""
    tag = self.amazon_tag

    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        query_params["tag"] = [tag]  # Replace any existing tag

        new_query = urlencode(query_params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    except Exception:
        # Simple string fallback if URL parsing fails
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}tag={tag}"
```

### MonetizedLink Data Class

```python
@dataclass
class MonetizedLink:
    """Result of link monetization."""
    original_url: str      # Original URL before processing
    monetized_url: str     # URL after monetization
    method: str            # "amazon", "skimlinks", "passthrough", "skipped"
    merchant: str          # Domain of the merchant
```

### Single URL Convenience Method

```python
# Monetize one URL without processing full HTML
monetizer = MonetizationManager(amazon_tag="yoursite-20")
result = monetizer.monetize_single_url("https://www.amazon.com/dp/B08ABC1234")
# => "https://www.amazon.com/dp/B08ABC1234?tag=yoursite-20"
```

---

## Content Monetization Injection

### HTML Affiliate Box (Rich Display)

```python
manager = AffiliateManager()

# Generate styled affiliate recommendation box
html = manager.generate_affiliate_html(
    brand="GREEK",
    num_products=3,
    style="box"  # "box", "inline", or "list"
)
```

**Output (box style):**

```html
<div class="affiliate-box">
  <h4>Recommended Books</h4>
  <ul>
    <li><a href="https://www.amazon.com/dp/0440406943?tag=greekmyths-20"
           target="_blank" rel="nofollow sponsored">
        D'Aulaires' Book of Greek Myths</a></li>
    <li><a href="https://www.amazon.com/dp/0786838655?tag=greekmyths-20"
           target="_blank" rel="nofollow sponsored">
        Percy Jackson Lightning Thief</a></li>
  </ul>
  <p class="affiliate-disclosure">
    <small>As an Amazon Associate, we earn from qualifying purchases.</small>
  </p>
</div>
```

### Inline Style (Paragraph Insert)

```python
html = manager.generate_affiliate_html(brand="HINDU", style="inline")
```

**Output:**

```html
<p class="affiliate-inline">Want to learn more? Check out:
<a href="..." target="_blank" rel="nofollow sponsored">Amar Chitra Katha Collection</a>,
<a href="..." target="_blank" rel="nofollow sponsored">Ramayana for Children</a>.
(affiliate links)</p>
```

### List Style (Simple Bullets)

```python
html = manager.generate_affiliate_html(brand="BUDDHIST", style="list")
```

**Output:**

```html
<div class="affiliate-list">
  <p>* <a href="..." target="_blank" rel="nofollow sponsored">Jataka Tales for Children</a></p>
  <p>* <a href="..." target="_blank" rel="nofollow sponsored">Buddha at Bedtime</a></p>
</div>
```

### Monetized Product Section (Hybrid Router)

The monetization manager can generate a complete product recommendation section with automatic link routing:

```python
monetizer = MonetizationManager(
    amazon_tag="yoursite-20",
    skimlinks_id="102394X1592384"
)

products = [
    {"title": "Greek Myths for Kids", "url": "https://amazon.com/dp/B08ABC1234",
     "description": "Beautifully illustrated"},
    {"title": "Mythology Collection", "url": "https://bookdepository.com/example",
     "description": "Free worldwide shipping"}
]

html = monetizer.generate_affiliate_section(brand="GREEK", products=products)
```

**Output:**

```html
<div class="affiliate-recommendations">
  <h4>Recommended Reading</h4>
  <ul class="book-list">
    <li><a href="https://amazon.com/dp/B08ABC1234?tag=yoursite-20"
           rel="nofollow sponsored" target="_blank">
        Greek Myths for Kids</a> - Beautifully illustrated</li>
    <li><a href="https://go.redirectingat.com/?id=102394X1592384&url=..."
           rel="nofollow sponsored" target="_blank">
        Mythology Collection</a> - Free worldwide shipping</li>
  </ul>
  <p class="affiliate-disclosure">
    <small>As an Amazon Associate and Skimlinks affiliate,
    we earn from qualifying purchases.</small>
  </p>
</div>
```

### Processing Existing Content Links

Scan HTML content and add affiliate tags to all Amazon links found:

```python
manager = AffiliateManager()

html_content = '''
<p>Read <a href="https://www.amazon.com/dp/B08ABC1234">this book</a>
and <a href="https://www.amazon.co.uk/dp/B08XYZ5678">this UK book</a>.</p>
'''

processed = manager.process_content_links(html_content, brand="GREEK")
# All Amazon URLs now have ?tag=greekmyths-20
# All Amazon links now have rel="nofollow sponsored"
```

**Regex pattern used for link detection:**

```python
AMAZON_LINK_PATTERN = r'href=["\']?(https?://(?:www\.)?amazon\.[a-z.]+/[^"\'\s>]+)["\']?'
```

### FTC Disclosure Text

```python
manager = AffiliateManager()

# Short (for inline use)
short = manager.get_disclosure_text("short")
# => "As an Amazon Associate, we earn from qualifying purchases."

# Long (for page footer or dedicated disclosure page)
long = manager.get_disclosure_text("long")
# => "Disclosure: This post contains affiliate links. If you click through
#     and make a purchase, we may receive a commission at no additional cost
#     to you. This helps support our site and allows us to continue creating
#     free content for children. As an Amazon Associate, we earn from
#     qualifying purchases."
```

---

## Statistics and Reporting

### Per-Content-Block Stats

After processing HTML content, the monetization router tracks how many links were handled by each method:

```python
monetizer = MonetizationManager(amazon_tag="yoursite-20", skimlinks_id="...")
monetized_html = monetizer.monetize_content(raw_html)

stats = monetizer.get_stats()
# {
#   "amazon": 5,       # Links tagged with Amazon Associates
#   "skimlinks": 3,    # Links wrapped with Skimlinks redirect
#   "passthrough": 1,  # Links left unchanged (no affiliate program)
#   "skipped": 2       # Internal/social links not processed
# }
```

### Product Database Stats

```python
manager = AffiliateManager()
stats = manager.get_stats()

# AffiliateLinkStats object:
# {
#   "total_links": 47,        # Total products in database
#   "clicks": 0,              # Requires external tracking integration
#   "conversions": 0,         # Requires Amazon Associates report import
#   "revenue": 0.0,           # Requires Amazon Associates report import
#   "by_brand": {
#     "GREEK": 12,
#     "HINDU": 8,
#     "BUDDHIST": 6,
#     ...
#   },
#   "top_products": []        # Populated from external analytics
# }
```

### Best Sellers Scraping Stats

```python
scraper = AmazonBestSellersScraper()
products = scraper.scrape_all_categories()
stats = scraper.get_category_stats(products)

# {
#   "total_products": 2500,
#   "unique_asins": 1847,
#   "categories_scraped": 40,
#   "by_category": {
#     "childrens-mythology": 50,
#     "greek-roman-mythology": 48,
#     "buddhism": 50,
#     ...
#   }
# }
```

### Logging Integration

All components use Python's standard `logging` module with named loggers:

```python
# Logger names
"affiliate"           # AffiliateManager operations
"monetization"        # MonetizationManager routing
"amazon_scraper"      # Playwright-based scraping
"amazon_bestsellers"  # Best sellers scraping
"perplexity_amazon"   # AI-powered product discovery

# Log format for production
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)

# Sample log output:
# 2024-01-15 10:23:45 [monetization] INFO: Monetized 11 links: Amazon=5, Skimlinks=3, Passthrough=1, Skipped=2
# 2024-01-15 10:23:46 [amazon_scraper] INFO: Extracted 3 products for 'greek mythology kids'
# 2024-01-15 10:23:47 [amazon_bestsellers] INFO: Scraped 50 products from childrens-mythology
```

---

## Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `AMAZON_AFFILIATE_TAG` | Yes | Default Amazon Associates tracking ID | `yoursite-20` |
| `SKIMLINKS_PUB_ID` | No | Skimlinks Publisher ID for non-Amazon monetization | `102394X1592384` |
| `PERPLEXITY_API_KEY` | No | Perplexity AI API key for product discovery | `pplx-abc123...` |
| `OPENAI_API_KEY` | No | OpenAI API key (alternative to Perplexity) | `sk-abc123...` |

### .env File Template

```bash
# === Affiliate Monetization ===

# Amazon Associates (REQUIRED)
AMAZON_AFFILIATE_TAG=yoursite-20

# Skimlinks (optional, for non-Amazon merchants)
SKIMLINKS_PUB_ID=102394X1592384

# AI Product Discovery (pick one)
PERPLEXITY_API_KEY=pplx-your-key-here
OPENAI_API_KEY=sk-your-key-here
```

### Dependencies

```
# Core
python-dotenv          # Environment variable loading

# Scraping (Playwright-based)
playwright             # Browser automation
# Run: playwright install chromium

# Scraping (HTTP-based)
requests               # HTTP client for Best Sellers pages
beautifulsoup4         # HTML parsing

# AI Product Discovery
aiohttp                # Async HTTP for Perplexity API
openai                 # OpenAI client (optional alternative)
```

---

## Integrates With

### `unified-api-client` module

Used for making HTTP calls to Perplexity and OpenAI APIs for product discovery. The AI product finders use `aiohttp` for async API requests; when integrating into a larger system, route these through the unified API client for centralized rate limiting, retry logic, and credential management.

```python
# Instead of raw aiohttp:
async with aiohttp.ClientSession() as session:
    async with session.post(url, headers=headers, json=payload) as response:
        ...

# Use unified client for production:
from unified_api_client import APIClient

client = APIClient(provider="perplexity")
response = await client.post("/chat/completions", json=payload)
```

### `batch-processing` skill

The CSV keyword scraping and multi-category best sellers scraping are batch operations. Integrate with the batch-processing skill for:

- Progress tracking with ETA
- Checkpoint/resume capability
- Error categorization and retry
- Parallel execution with concurrency limits

```python
from batch_processor import BatchProcessor

processor = BatchProcessor(
    items=keywords,
    handler=scraper.scrape_keyword,
    batch_size=10,
    delay_between_batches=3.0,
    checkpoint_file="scrape_checkpoint.json"
)

results = await processor.run()
```

### `content-pipeline-orchestrator` module

The monetization router is designed as a pipeline stage. Insert it after content generation but before database storage:

```
Pipeline Stages:
1. Content Generation (AI/manual)
2. SEO Optimization
3. Image Processing
4. >>> Affiliate Monetization <<<  (this skill)
5. Database Storage
6. Publishing
```

```python
# Pipeline stage integration
class AffiliateMonetizationStage:
    def __init__(self):
        self.monetizer = MonetizationManager()

    async def process(self, content: dict) -> dict:
        content["html"] = self.monetizer.monetize_content(
            content["html"],
            brand=content.get("brand", "")
        )
        content["affiliate_stats"] = self.monetizer.get_stats()
        return content
```

### `database-orm-patterns` module

Product data, scraping results, and affiliate statistics persist to storage. Use the database-orm-patterns module for:

- Product table (ASINs, titles, prices, last-scraped timestamps)
- Affiliate stats table (clicks, conversions, revenue by brand/product)
- Scrape job history (keywords processed, products found, errors)

```python
# Product model example
class Product(Base):
    __tablename__ = "affiliate_products"

    asin = Column(String(10), primary_key=True)
    title = Column(String(500))
    brand = Column(String(100))
    affiliate_url = Column(String(1000))
    price = Column(String(20))
    rating = Column(String(20))
    last_scraped = Column(DateTime)
    category = Column(String(100))

class AffiliateClick(Base):
    __tablename__ = "affiliate_clicks"

    id = Column(Integer, primary_key=True)
    asin = Column(String(10), ForeignKey("affiliate_products.asin"))
    clicked_at = Column(DateTime)
    source_page = Column(String(500))
    method = Column(String(20))  # "amazon", "skimlinks"
```

---

## Decision Matrix: Which Scraping Strategy?

```
┌───────────────────────┬──────────────┬──────────────┬──────────────┐
│ Factor                │ Playwright   │ Best Sellers │ AI Finder    │
│                       │ Scraper      │ (HTTP/BS4)   │ (Perplexity) │
├───────────────────────┼──────────────┼──────────────┼──────────────┤
│ Reliability           │ Medium       │ High         │ Very High    │
│ Speed                 │ Slow         │ Medium       │ Fast         │
│ Bot detection risk    │ High         │ Medium       │ None         │
│ Data richness         │ Full         │ Moderate     │ Moderate     │
│ Infrastructure needs  │ Chromium     │ None         │ API key      │
│ Cost per query        │ Free         │ Free         │ ~$0.01       │
│ Context understanding │ None         │ None         │ High         │
│ Best for              │ Rich data    │ Popular      │ Niche        │
│                       │ extraction   │ products     │ keywords     │
└───────────────────────┴──────────────┴──────────────┴──────────────┘

Recommended strategy: Use AI Finder for initial discovery,
Best Sellers for popular categories, Playwright for detailed enrichment.
```
