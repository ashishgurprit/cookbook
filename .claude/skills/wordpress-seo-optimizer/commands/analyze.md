# Analyze Command

Perform comprehensive SEO analysis of a WordPress post or page.

## Usage

```bash
/wordpress-seo-optimizer analyze [URL or post-id] [options]
```

## Parameters

- `target` - WordPress post URL or post ID (e.g., `https://site.com/post` or `post-id:123`)
- `--verbose` - Show detailed analysis
- `--score-only` - Show only SEO score (0-100)
- `--json` - Output as JSON format
- `--geo-aeo-focus` - Focus on GEO/AEO analysis
- `--save-report` - Save report to file

## What It Analyzes

### Keyword Analysis
- Target keyword identification
- Keyword density calculation
- LSI (Latent Semantic Indexing) keyword suggestions
- Keyword placement (title, H1, first 100 words)

### On-Page SEO
- **Title Tag**: Length (50-60 chars), keyword presence, compelling copy
- **Meta Description**: Length (150-160 chars), keyword, CTA
- **Headers**: H1 present, H2/H3 hierarchy, keyword distribution
- **Content Quality**: Word count, readability score, keyword density
- **Images**: Alt text present, file size, format optimization
- **URL Slug**: Length, keyword inclusion, clean structure
- **Internal Links**: Count, descriptive anchors

### Technical SEO (Basic)
- Mobile-friendly check
- HTTPS verification
- Schema markup detection
- Canonical tags

### GEO/AEO (MVP)
- Quotability scoring
- E-E-A-T indicators
- Featured snippet opportunities

## Example Output

```
┌─────────────────────────────────────┐
│  SEO ANALYSIS REPORT                │
├─────────────────────────────────────┤
│  📊 SEO Score: 68/100               │
│  ⚠️  Issues Found: 8                │
│  ✅  Optimizations Available: 12    │
└─────────────────────────────────────┘

KEYWORDS
  Target: "dog training tips"
  Current Density: 0.8% (Target: 1.5%)
  LSI Keywords: Missing
  Placement: ✅ Title, ⚠️ H1 (not found)

ON-PAGE SEO
  Title Tag
    ✅ Length: 52 chars (optimal)
    ✅ Keyword present
    ✅ Compelling

  Meta Description
    ⚠️  Missing (critical)
    Recommendation: Add 150-160 char description

  Headers
    ⚠️  H1: Not found (critical)
    ✅ H2: 5 headings (good structure)
    ✅ H3: 8 headings

  Content
    ✅ Word count: 1,245 (good)
    ⚠️  Readability: 52/100 (target: >60)
    ⚠️  Keyword density: 0.8% (target: 1.5%)

  Images
    ✅ Total: 5 images
    ✅ Alt text: 5/5 (100%)
    ⚠️  Large files: 3 images >200KB

  Internal Links
    ⚠️  Count: 1 (target: 3-5)
    ⚠️  Anchors: Generic ("click here")

TECHNICAL SEO
  ✅ Mobile-friendly
  ✅ HTTPS enabled
  ⚠️  Schema: No Article schema
  ✅ Canonical tag present

GEO/AEO OPTIMIZATION
  Quotability Score: 65/100
  E-E-A-T Score: 70/100
  ⚠️  Author credentials: Not visible
  ⚠️  Last updated date: Missing
  Featured Snippet Opportunities: 2

RECOMMENDATIONS (Priority Order)
  CRITICAL:
  1. Add meta description (150-160 chars)
  2. Add H1 heading with target keyword

  HIGH:
  3. Optimize images (convert to WebP, compress)
  4. Add Article schema markup
  5. Increase keyword density to 1.5%

  MEDIUM:
  6. Add 2-3 more internal links
  7. Improve readability to >60
  8. Add author bio with credentials

  LOW:
  9. Add "Last updated" timestamp
  10. Optimize URL slug

SEO SCORE BREAKDOWN:
  Title Tag:        15/15 ✅
  Meta Description:  0/10 ❌
  Headers:           5/10 ⚠️
  Content:          14/20 ⚠️
  Images:            7/10 ⚠️
  Technical:        12/15 ✅
  Schema:            0/10 ❌
  Links:             2/5 ⚠️
  GEO/AEO:           3/5 ⚠️

  TOTAL: 68/100

Apply optimizations automatically?
[Yes] [No] [Review individually]
```

## Implementation Steps

1. Authenticate with WordPress REST API
2. Fetch post content and metadata
3. Run analysis modules:
   - Keyword analyzer
   - On-page optimizer
   - Technical auditor (basic)
   - GEO/AEO analyzer (basic)
4. Calculate SEO score (0-100)
5. Generate prioritized recommendations
6. Format and display report
7. Offer optimization options

## Error Handling

- **Authentication failed**: Check credentials and permissions
- **Post not found**: Verify URL or post ID
- **API access denied**: Ensure user has read permissions
- **Network timeout**: Retry with exponential backoff

## Related Commands

- `/wordpress-seo-optimizer optimize` - Apply recommended optimizations
- `/wordpress-seo-optimizer keywords` - Deep keyword research
- `/wordpress-seo-optimizer technical` - Comprehensive technical audit
