# Website SEO Optimizer

Universal SEO analysis tool that works with multiple platforms: URLs, Shopify, Ghost, static sites, and Python frameworks.

## Features

- **Multi-Platform Support**: Analyze content from any source via pluggable connectors
- **Comprehensive Analysis**: Keyword density, on-page SEO, content quality, technical audit
- **Actionable Recommendations**: Prioritized suggestions with impact estimates
- **Professional Reports**: Text, Markdown, and JSON output formats

## Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```python
from connectors import create_url_connector
from core import SEOAnalyzer

# Analyze any URL
connector = create_url_connector()
content = connector.fetch('https://example.com')

analyzer = SEOAnalyzer()
analysis = analyzer.analyze(content)

print(analyzer.generate_report(analysis))
```

### Command Line

```bash
# Analyze a URL
python examples/url_analysis.py https://example.com

# With target keyword
python examples/url_analysis.py https://example.com --keyword "your keyword"
```

## Supported Platforms

### ✅ Phase 1 (MVP) - Available Now

- **URL Connector**: Analyze any public website
  - No authentication required
  - Instant analysis
  - Works with any HTTP/HTTPS URL

### 🚧 Phase 2 - Coming Soon

- **Shopify Connector**: E-commerce product and page optimization
- **Ghost Connector**: Blog post and content analysis

### 🚧 Phase 3 - Coming Soon

- **Static Site Connector**: Next.js, Gatsby, Hugo, Jekyll
- **Python Framework Connector**: Django, Flask, FastAPI

## Architecture

### Connector Pattern

All connectors implement the same interface:

```python
class BaseConnector:
    def fetch(identifier: str) -> NormalizedContent
    def list_items(**filters) -> List[Dict]
    def test_connection() -> Tuple[bool, str]
    def update(identifier: str, **updates) -> bool  # Optional
```

### Normalized Content

All connectors return content in a standardized format:

```python
@dataclass
class NormalizedContent:
    # Required fields
    title: str
    content: str  # HTML
    url_slug: str
    url: str

    # Optional SEO fields
    meta_description: str
    meta_keywords: str
    canonical_url: str

    # Structured content
    headings: List[Dict]
    images: List[Dict]
    links: List[Dict]

    # Platform-specific data
    platform: PlatformType
    raw_data: Optional[Dict]
```

## Analysis Modules

### Keyword Analyzer

- Keyword density calculation
- Keyword placement detection
- LSI keyword extraction
- Recommendations for improvement

### On-Page Optimizer

- Title tag analysis (50-60 chars optimal)
- Meta description analysis (150-160 chars optimal)
- Header structure (H1-H6)
- Content quality (word count, readability)
- Image optimization (alt text)
- URL slug analysis

### SEO Analyzer (Orchestrator)

- Combines all analysis modules
- Calculates overall score (0-100)
- Prioritizes recommendations (CRITICAL, HIGH, MEDIUM, LOW)
- Generates formatted reports

## Examples

### Example 1: Basic URL Analysis

```python
from connectors import create_url_connector
from core import SEOAnalyzer

# Fetch content
connector = create_url_connector()
content = connector.fetch('https://example.com/blog/post')

# Analyze
analyzer = SEOAnalyzer()
analysis = analyzer.analyze(content, target_keyword='dog training')

# Results
print(f"Score: {analysis['overall_score']}/100")
print(f"Critical Issues: {analysis['critical_issues']}")
print(f"Recommendations: {len(analysis['recommendations'])}")

# Full report
report = analyzer.generate_report(analysis)
print(report)
```

### Example 2: Batch Analysis

```python
from connectors import create_url_connector
from core import SEOAnalyzer

urls = [
    'https://example.com/page1',
    'https://example.com/page2',
    'https://example.com/page3',
]

connector = create_url_connector()
analyzer = SEOAnalyzer()

results = []
for url in urls:
    content = connector.fetch(url)
    analysis = analyzer.analyze(content)
    results.append({
        'url': url,
        'score': analysis['overall_score'],
        'issues': analysis['critical_issues']
    })

# Summary
avg_score = sum(r['score'] for r in results) / len(results)
print(f"Average Score: {avg_score:.1f}/100")
print(f"Pages Needing Attention: {sum(1 for r in results if r['score'] < 70)}")
```

### Example 3: Generate Optimizations

```python
from connectors import create_url_connector
from core import SEOAnalyzer

connector = create_url_connector()
analyzer = SEOAnalyzer()

content = connector.fetch('https://example.com/page')
analysis = analyzer.analyze(content)

# Generate optimized title
optimized_title = analyzer.onpage_optimizer.generate_optimized_title(
    content.title,
    analysis['target_keyword']
)

# Generate optimized meta description
optimized_meta = analyzer.onpage_optimizer.generate_optimized_meta_description(
    content.content,
    analysis['target_keyword']
)

print(f"Optimized Title: {optimized_title}")
print(f"Optimized Meta: {optimized_meta}")
```

## Development

### Project Structure

```
website-seo-optimizer/
├── connectors/          # Platform connectors
│   ├── base_connector.py
│   ├── url_connector.py
│   └── __init__.py
├── core/                # Analysis modules
│   ├── keyword_analyzer.py
│   ├── onpage_optimizer.py
│   ├── seo_analyzer.py
│   └── __init__.py
├── examples/            # Example scripts
│   └── url_analysis.py
├── tests/               # Unit tests (future)
├── requirements.txt
└── README.md
```

### Adding a New Connector

1. Create new file in `connectors/` (e.g., `shopify_connector.py`)
2. Implement `BaseConnector` interface
3. Return `NormalizedContent` from `fetch()`
4. Add to `connectors/__init__.py`
5. Create example script in `examples/`

Example template:

```python
from .base_connector import BaseConnector, NormalizedContent, PlatformType

class MyConnector(BaseConnector):
    @property
    def platform_type(self) -> PlatformType:
        return PlatformType.MY_PLATFORM

    def fetch(self, identifier: str) -> NormalizedContent:
        # Fetch from API/file
        data = self._fetch_from_source(identifier)

        # Normalize to standard format
        return NormalizedContent(
            title=data['title'],
            content=data['html_content'],
            url_slug=data['slug'],
            url=data['url'],
            meta_description=data.get('meta_description', ''),
            platform=PlatformType.MY_PLATFORM,
            raw_data=data
        )

    def list_items(self, **filters) -> List[Dict]:
        # Return list of available items
        pass

    def test_connection(self) -> Tuple[bool, str]:
        # Test API/file access
        pass
```

## Scoring System

### Overall Score (0-100)

- **90-100**: Excellent - Optimized for search engines
- **70-89**: Good - Minor improvements needed
- **50-69**: Needs Work - Several issues to address
- **0-49**: Poor - Major optimization required

### Component Scores

- **Keyword Analysis**: 15 points
  - Density: 30 points
  - Placement: 50 points
  - LSI Keywords: 20 points

- **On-Page SEO**: 70 points
  - Title: 15 points
  - Meta Description: 10 points
  - Headers: 10 points
  - Content: 20 points
  - Images: 10 points
  - URL: 5 points

- **Technical SEO**: 15 points (future)
  - Site speed
  - Mobile-friendliness
  - Schema markup
  - Internal linking

## Roadmap

### v0.1.0 (Current - Phase 1)
- ✅ URL Connector
- ✅ Core analysis modules
- ✅ Command-line interface
- ✅ Text/Markdown reports

### v0.2.0 (Phase 2)
- 🚧 Shopify Connector
- 🚧 Ghost Connector
- 🚧 JSON export
- 🚧 Batch processing utilities

### v0.3.0 (Phase 3)
- 🚧 Static Site Connector
- 🚧 Python Framework Connector
- 🚧 Technical SEO auditing
- 🚧 Schema.org generation

### v1.0.0 (Production)
- 🚧 Full test coverage
- 🚧 CI/CD pipeline
- 🚧 Performance optimization
- 🚧 Plugin system

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

MIT License - See LICENSE file for details

## Credits

Built on patterns from the `wordpress-seo-optimizer` skill, generalized for multi-platform support.

Core analysis algorithms inspired by industry best practices from:
- Google Search Central
- Moz SEO Guide
- Yoast SEO
