# WordPress SEO Optimizer

> Comprehensive SEO/AEO/GEO optimization for WordPress sites via REST API

Automate WordPress SEO optimization including traditional search (SEO), AI search engines (GEO), and answer engines (AEO). Keyword research, on-page optimization, technical audits, schema markup, and analytics tracking - all via WordPress REST API.

## Quick Start

```bash
# Analyze a post for SEO issues
/wordpress-seo-optimizer analyze https://yoursite.com/post-slug

# Apply optimizations
/wordpress-seo-optimizer optimize post-id:123 --apply-all

# Research keywords
/wordpress-seo-optimizer keywords "dog training tips" --research

# Technical SEO audit
/wordpress-seo-optimizer technical https://yoursite.com

# Add schema markup
/wordpress-seo-optimizer schema post-id:123 --type=Article

# Setup analytics tracking
/wordpress-seo-optimizer monitor https://yoursite.com

# Generate SEO report
/wordpress-seo-optimizer report https://yoursite.com --last-30-days
```

## Features

### 🔍 Comprehensive SEO Analysis
- **Keyword Analysis** - Target keyword identification, density calculation, LSI keywords
- **On-Page SEO** - Title tags, meta descriptions, header structure, content optimization
- **Technical SEO** - Core Web Vitals, mobile optimization, HTTPS, sitemaps
- **Internal Linking** - Link opportunities, anchor text optimization, orphan page detection

### 🤖 AI Search Optimization (GEO/AEO)
- **GEO (Generative Engine Optimization)** - Optimize for ChatGPT, Perplexity, Copilot citations
- **AEO (Answer Engine Optimization)** - Featured snippets, voice search, PAA targeting
- **E-E-A-T Scoring** - Experience, Expertise, Authority, Trust signals
- **Quotability Analysis** - Make content easily citable by AI

### 🏗️ Schema Markup
- **Automatic Schema Generation** - Article, BlogPosting, FAQPage, HowTo, LocalBusiness
- **Schema Validation** - Google Rich Results Test integration
- **Dynamic Field Population** - Content-based schema generation

### 📊 Analytics & Tracking
- **Google Search Console** - Search queries, clicks, impressions, rankings
- **Google Analytics 4** - Traffic, conversions, user behavior
- **Core Web Vitals** - LCP, INP, CLS monitoring
- **Keyword Ranking Tracking** - Monitor position changes over time

### ⚙️ WordPress Integration
- **REST API Native** - No FTP or file access required
- **App Password Auth** - Secure WordPress 5.6+ authentication
- **Multi-Plugin Support** - Yoast SEO, RankMath, All in One SEO, SEOPress
- **Batch Operations** - Optimize multiple posts efficiently

## Requirements

- **WordPress 5.6+** (for Application Passwords)
- **HTTPS enabled** (required for security)
- **WordPress user account** with Editor or Administrator role
- **Optional:** Yoast SEO, RankMath, or All in One SEO plugin for enhanced features

## Setup

### 1. Create WordPress Application Password

1. Log in to your WordPress admin panel
2. Navigate to **Users** → **Your Profile**
3. Scroll to **Application Passwords** section
4. Enter name: "SEO Optimizer"
5. Click **Add New Application Password**
6. Copy the generated password (format: `xxxx xxxx xxxx xxxx xxxx xxxx`)

### 2. Test Connection

```bash
/wordpress-seo-optimizer analyze https://yoursite.com/any-post
```

The skill will prompt you for:
- WordPress URL (e.g., `https://yoursite.com`)
- Username
- Application Password

Credentials are stored securely for future use.

## Commands

### `analyze` - SEO Audit

Comprehensive SEO analysis of a post or page.

```bash
/wordpress-seo-optimizer analyze [URL or post-id]
```

**Options:**
- `--verbose` - Show detailed analysis
- `--score-only` - Show only SEO score (0-100)
- `--json` - Output as JSON

**Example:**
```bash
/wordpress-seo-optimizer analyze https://site.com/dog-training-tips
```

**Output:**
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

ON-PAGE SEO
  ✅ Title: 52 chars (optimal)
  ⚠️  Meta description: Missing
  ⚠️  H1: Not found
  ✅ Images: 5/5 have alt text

TECHNICAL SEO
  ⚠️  LCP: 3.2s (Target: <2.5s)
  ✅ Mobile-friendly
  ✅ HTTPS enabled
  ⚠️  Schema: No Article schema

GEO/AEO OPTIMIZATION
  Quotability Score: 65/100
  E-E-A-T Score: 70/100
  Featured Snippet Opportunities: 2

RECOMMENDATIONS (Priority Order)
  1. Add meta description (150-160 chars)
  2. Add H1 heading with target keyword
  3. Optimize images for faster LCP
  4. Add Article schema markup
  5. Increase keyword density to 1.5%
  6. Add FAQ schema for Q&A section
  7. Include author credentials (E-E-A-T)
  8. Add "Last updated" timestamp

Apply optimizations? [Yes/No]
```

---

### `optimize` - Apply Optimizations

Apply SEO optimizations to a post.

```bash
/wordpress-seo-optimizer optimize [URL or post-id] [options]
```

**Options:**
- `--apply-all` - Apply all recommended optimizations
- `--title="New Title"` - Update title
- `--meta="Description"` - Update meta description
- `--keywords="keyword1,keyword2"` - Set target keywords
- `--schema=Article` - Add schema markup
- `--optimize-images` - Optimize image alt text
- `--fix-headers` - Fix header hierarchy
- `--add-internal-links` - Add internal links
- `--dry-run` - Preview changes without applying

**Example:**
```bash
/wordpress-seo-optimizer optimize post-id:123 --apply-all
```

**Output:**
```
Applying Optimizations...

✅ Title updated: "Dog Training Tips: 10 Proven Methods for New Owners"
✅ Meta description added: "Discover 10 effective dog training tips..."
✅ Article schema markup added
✅ H1 heading added: "Dog Training Tips"
✅ 3 internal links added
✅ 5 images optimized (alt text)

SEO Score: 68 → 89 (+21 points)

Changes applied successfully!
View post: https://site.com/dog-training-tips
```

---

### `keywords` - Keyword Research

Research and analyze keywords for content optimization.

```bash
/wordpress-seo-optimizer keywords [keyword or URL] [options]
```

**Options:**
- `--research` - Full keyword research (volume, competition)
- `--lsi` - Generate LSI keywords only
- `--competitors` - Analyze competitor keywords
- `--save-to=post-id` - Save keywords to post meta

**Example:**
```bash
/wordpress-seo-optimizer keywords "dog training tips" --research
```

**Output:**
```
KEYWORD RESEARCH: "dog training tips"

PRIMARY KEYWORD
  Search Volume: 12,100/month
  Competition: Medium (58/100)
  CPC: $2.40
  Difficulty: 45/100

LSI KEYWORDS (Semantic Variations)
  • puppy training tips (8,200/mo)
  • dog obedience training (6,500/mo)
  • dog behavior training (4,800/mo)
  • positive reinforcement dog training (3,100/mo)

RELATED QUESTIONS (For AEO/Featured Snippets)
  • What is the best age to start dog training?
  • How long does it take to train a dog?
  • What are the basic dog commands?
  • How do you house train a puppy?

COMPETITOR ANALYSIS
  Top 3 competitors targeting this keyword:
  1. site1.com/training - SEO Score: 92
  2. site2.com/dogs - SEO Score: 88
  3. site3.com/tips - SEO Score: 85

RECOMMENDATIONS
  • Target keyword density: 1.5% (use 15 times in 1000 words)
  • Include 3-5 LSI keywords naturally
  • Answer related questions in H2 sections
  • Target featured snippet with FAQ schema
```

---

### `technical` - Technical SEO Audit

Comprehensive technical SEO audit.

```bash
/wordpress-seo-optimizer technical [URL] [options]
```

**Options:**
- `--audit-only` - Analysis only, no fixes
- `--fix-issues` - Automatically fix issues
- `--cwv` - Core Web Vitals focus
- `--mobile` - Mobile optimization focus

**Example:**
```bash
/wordpress-seo-optimizer technical https://site.com
```

**Output:**
```
TECHNICAL SEO AUDIT

CORE WEB VITALS
  ⚠️  LCP: 3.2s (Target: <2.5s)
       Issue: Large hero image not optimized
       Fix: Convert to WebP, use lazy loading

  ✅ INP: 120ms (Target: <200ms)

  ✅ CLS: 0.05 (Target: <0.1)

MOBILE OPTIMIZATION
  ✅ Mobile-friendly design
  ✅ Responsive viewport
  ⚠️  Touch targets too small (3 instances)
       Fix: Increase button size to 48x48px

SECURITY & PROTOCOL
  ✅ HTTPS enabled
  ✅ SSL certificate valid
  ✅ No mixed content

CRAWLABILITY
  ✅ Robots.txt valid
  ✅ XML sitemap present (/sitemap.xml)
  ⚠️  5 pages not in sitemap
       Fix: Regenerate sitemap

STRUCTURED DATA
  ⚠️  No Article schema found
  ⚠️  No BreadcrumbList schema
  ✅ Organization schema valid

ISSUES FOUND: 5
CRITICAL: 1 | WARNING: 3 | INFO: 1

Apply fixes? [Yes/No]
```

---

### `schema` - Schema Markup Management

Add, update, or validate schema markup.

```bash
/wordpress-seo-optimizer schema [URL or post-id] [options]
```

**Options:**
- `--type=Article|FAQ|HowTo|LocalBusiness|Product` - Schema type
- `--validate` - Validate existing schema
- `--remove` - Remove schema
- `--preview` - Preview JSON-LD without applying

**Supported Schema Types:**
- **Article** / **BlogPosting** - Blog posts and articles
- **FAQPage** - FAQ sections
- **HowTo** - Step-by-step guides
- **LocalBusiness** - Local business information
- **Product** - Product pages
- **Review** - Review articles
- **BreadcrumbList** - Breadcrumb navigation

**Example:**
```bash
/wordpress-seo-optimizer schema post-id:123 --type=Article
```

**Output:**
```
Generating Article Schema...

{
  "@context": "https://schema.org",
  "@type": "Article",
  "headline": "Dog Training Tips: 10 Proven Methods",
  "author": {
    "@type": "Person",
    "name": "John Smith"
  },
  "datePublished": "2026-02-11T10:00:00Z",
  "dateModified": "2026-02-11T10:00:00Z",
  "image": "https://site.com/wp-content/uploads/dog-training.jpg",
  "publisher": {
    "@type": "Organization",
    "name": "Dog Training Pro",
    "logo": {
      "@type": "ImageObject",
      "url": "https://site.com/logo.png"
    }
  },
  "description": "Discover 10 effective dog training tips..."
}

✅ Schema added to post
✅ Validated with Google Rich Results Test
✅ No errors found

Test your schema: https://search.google.com/test/rich-results
```

---

### `monitor` - Analytics Setup & Tracking

Setup and configure analytics tracking.

```bash
/wordpress-seo-optimizer monitor [URL] [options]
```

**Options:**
- `--setup-gsc` - Setup Google Search Console
- `--setup-ga4` - Setup Google Analytics 4
- `--track-keywords` - Enable keyword ranking tracking
- `--track-cwv` - Enable Core Web Vitals monitoring

**Example:**
```bash
/wordpress-seo-optimizer monitor https://site.com --setup-gsc
```

**Output:**
```
ANALYTICS SETUP

Google Search Console Setup
  1. Verify site ownership
  2. Submit sitemap
  3. Enable data collection

Follow this URL to authorize:
https://accounts.google.com/o/oauth2/auth?client_id=...

[After authorization]

✅ Google Search Console connected
✅ Sitemap submitted: https://site.com/sitemap.xml
✅ Data collection enabled

You can now track:
  • Search queries and impressions
  • Click-through rates
  • Average position
  • Core Web Vitals

Run `/wordpress-seo-optimizer report` to view data
```

---

### `report` - SEO Reporting

Generate comprehensive SEO reports.

```bash
/wordpress-seo-optimizer report [URL] [options]
```

**Options:**
- `--last-7-days` - 7-day report
- `--last-30-days` - 30-day report (default)
- `--last-90-days` - 90-day report
- `--keyword="keyword"` - Specific keyword tracking
- `--export=pdf|csv|json` - Export format

**Example:**
```bash
/wordpress-seo-optimizer report https://site.com --last-30-days
```

**Output:**
```
SEO PERFORMANCE REPORT (Last 30 Days)

OVERVIEW
  SEO Score: 85/100 (+12 from last month)
  Total Posts Optimized: 24
  Average Optimization: 89/100

SEARCH CONSOLE DATA
  Total Clicks: 5,420 (+15%)
  Total Impressions: 68,200 (+22%)
  Average CTR: 7.9% (+0.4%)
  Average Position: 8.2 (-1.8)

TOP PERFORMING KEYWORDS
  1. "dog training tips" - Position 3.2 (▲2)
     Clicks: 842 | Impressions: 12,400
  2. "puppy training" - Position 5.8 (▲1)
     Clicks: 524 | Impressions: 8,900
  3. "dog obedience" - Position 7.1 (▼2)
     Clicks: 412 | Impressions: 7,200

CORE WEB VITALS
  LCP: 2.4s (Passing) ✅
  INP: 180ms (Passing) ✅
  CLS: 0.08 (Passing) ✅

FEATURED SNIPPETS
  Acquired: 3 new snippets
  Lost: 1 snippet
  Total: 12 snippets

GEO/AEO PERFORMANCE
  AI Search Citations: 8 detected
    • Perplexity: 4 citations
    • ChatGPT: 3 citations
    • Copilot: 1 citation

RECOMMENDATIONS
  1. Focus on "dog behavior training" (opportunity keyword)
  2. Optimize 5 posts with score <70
  3. Update 8 posts with old content (>1 year)
  4. Add FAQ schema to 12 posts

Export report? [Yes/No]
```

---

## WordPress Plugin Support

### Supported SEO Plugins

The skill works with popular WordPress SEO plugins via REST API:

| Plugin | Features Available |
|--------|-------------------|
| **Yoast SEO** | ✅ Title/meta, ✅ Keywords, ✅ Readability, ✅ Schema (partial) |
| **RankMath** | ✅ Title/meta, ✅ Keywords, ✅ Schema, ✅ Redirects |
| **All in One SEO** | ✅ Title/meta, ✅ Keywords, ✅ Schema |
| **SEOPress** | ✅ Title/meta, ✅ Schema, ✅ Redirects |

**Note:** Not all plugin features are accessible via REST API. For advanced features, install the custom **SEO Optimizer Pro** plugin.

### Custom WordPress Plugins

For advanced functionality, install these optional plugins:

#### SEO Optimizer Pro (Optional)

Extends REST API with advanced SEO features:
- Keyword tracking and ranking history
- Internal link analysis and suggestions
- Schema validation
- Core Web Vitals tracking
- Broken link detection

**Installation:**
```bash
# Download from GitHub releases
https://github.com/[your-repo]/seo-optimizer-pro/releases

# Upload via WordPress Admin
Plugins → Add New → Upload Plugin → Activate
```

#### Analytics Bridge (Optional)

Unified analytics interface:
- Google Search Console connector
- Google Analytics 4 connector
- Combined dashboard data
- Historical data tracking

**Installation:**
Same process as SEO Optimizer Pro.

---

## Use Cases

### 1. Blog Post Optimization

Optimize a new blog post before publishing:

```bash
# Write your post in WordPress (save as draft)

# Analyze
/wordpress-seo-optimizer analyze https://site.com/new-post

# Research keywords
/wordpress-seo-optimizer keywords "main topic" --research

# Optimize
/wordpress-seo-optimizer optimize post-id:123 \
  --title="Optimized Title" \
  --keywords="main,keyword,list" \
  --schema=Article \
  --optimize-images \
  --add-internal-links

# Final check
/wordpress-seo-optimizer analyze post-id:123 --score-only

# Publish when score >80
```

---

### 2. Bulk Content Optimization

Optimize multiple existing posts:

```bash
# Get list of posts needing optimization
/wordpress-seo-optimizer report https://site.com --show-low-scores

# Bulk optimize (will process one by one with confirmation)
/wordpress-seo-optimizer optimize --bulk \
  --post-ids=123,456,789 \
  --apply-all \
  --batch-size=5
```

---

### 3. Technical SEO Audit

Perform comprehensive technical audit:

```bash
# Full technical audit
/wordpress-seo-optimizer technical https://site.com

# Focus on Core Web Vitals
/wordpress-seo-optimizer technical https://site.com --cwv

# Mobile optimization check
/wordpress-seo-optimizer technical https://site.com --mobile

# Apply recommended fixes
/wordpress-seo-optimizer technical https://site.com --fix-issues
```

---

### 4. AI Search Optimization (GEO/AEO)

Optimize for AI search engines:

```bash
# Analyze GEO/AEO readiness
/wordpress-seo-optimizer analyze https://site.com/post --geo-aeo-focus

# Optimize for featured snippets
/wordpress-seo-optimizer optimize post-id:123 \
  --add-faq-schema \
  --optimize-for-snippets

# Add schema for AI understanding
/wordpress-seo-optimizer schema post-id:123 --type=FAQPage
```

---

### 5. Keyword Research Workflow

Research and implement keywords:

```bash
# 1. Research main topic
/wordpress-seo-optimizer keywords "dog training" --research

# 2. Find related questions (for content structure)
/wordpress-seo-optimizer keywords "dog training" --related-questions

# 3. Analyze competitors
/wordpress-seo-optimizer keywords "dog training" --competitors

# 4. Create content targeting keywords

# 5. Optimize with keywords
/wordpress-seo-optimizer optimize post-id:123 \
  --keywords="dog training,puppy training,obedience" \
  --target-density=1.5
```

---

### 6. Ongoing Monitoring

Setup continuous SEO monitoring:

```bash
# Initial setup
/wordpress-seo-optimizer monitor https://site.com \
  --setup-gsc \
  --setup-ga4 \
  --track-keywords \
  --track-cwv

# Weekly reports
/wordpress-seo-optimizer report https://site.com --last-7-days

# Monthly performance review
/wordpress-seo-optimizer report https://site.com \
  --last-30-days \
  --export=pdf
```

---

## Best Practices

### On-Page SEO

1. **Title Tags**
   - Keep between 50-60 characters
   - Include primary keyword early
   - Make it compelling (improve CTR)
   - Unique for every page

2. **Meta Descriptions**
   - 150-160 characters
   - Include primary keyword
   - Add clear call-to-action
   - Accurate preview of content

3. **Header Structure**
   - One H1 per page (contains primary keyword)
   - Logical H2/H3 hierarchy
   - Descriptive and scannable
   - Answer user questions

4. **Content Optimization**
   - Keyword density: 1-2% (natural, not forced)
   - Comprehensive coverage (>1000 words)
   - Include LSI keywords
   - High readability (Flesch-Kincaid >60)
   - Regular updates (freshness)

### Technical SEO

1. **Core Web Vitals**
   - LCP <2.5s (optimize images, lazy loading)
   - INP <200ms (optimize JavaScript)
   - CLS <0.1 (reserve space for images/ads)

2. **Mobile Optimization**
   - Responsive design
   - Touch-friendly elements (48x48px min)
   - Fast mobile load times
   - No intrusive interstitials

3. **Schema Markup**
   - Add Article schema to all posts
   - Use FAQPage for Q&A sections
   - HowTo for step-by-step guides
   - LocalBusiness for local pages

### GEO/AEO Optimization

1. **Quotability**
   - Clear, standalone statements
   - Definitive facts with sources
   - Concise definitions
   - Numbered lists and steps

2. **E-E-A-T Signals**
   - Author bio with credentials
   - Expert quotes and citations
   - Regular content updates
   - Source attribution

3. **Featured Snippets**
   - Answer questions in 40-60 words
   - Use lists and tables
   - Question-format headings
   - FAQ schema

### Keyword Strategy

1. **Research**
   - Focus on long-tail keywords (lower competition)
   - Consider search intent (informational, commercial, navigational)
   - Analyze competitor keywords
   - Target keyword clusters (related topics)

2. **Implementation**
   - Primary keyword in title, H1, first paragraph
   - LSI keywords throughout content
   - Natural language (not keyword stuffing)
   - Internal linking with keyword anchors

3. **Monitoring**
   - Track rankings weekly
   - Monitor traffic changes
   - Adjust based on performance
   - Capitalize on quick wins

---

## Troubleshooting

### Authentication Issues

**Problem:** "Authentication failed" error

**Solutions:**
1. Verify WordPress URL is correct (with https://)
2. Check Application Password is copied correctly (with spaces)
3. Ensure user has Editor or Administrator role
4. Verify Application Passwords are enabled (WordPress 5.6+)

```bash
# Test authentication
/wordpress-seo-optimizer analyze https://site.com/test-post
```

---

### Plugin Detection Failed

**Problem:** "SEO plugin not detected" warning

**Solutions:**
1. Install Yoast SEO or RankMath
2. Ensure plugin is activated
3. Check plugin version (use latest)
4. Verify REST API access

```bash
# Check which plugins are detected
/wordpress-seo-optimizer technical https://site.com --plugin-check
```

---

### Optimization Not Applied

**Problem:** Changes not appearing on website

**Solutions:**
1. Check WordPress caching plugins (clear cache)
2. Verify user permissions (need edit_posts capability)
3. Check if custom fields are registered with REST API
4. Review WordPress error logs

```bash
# Verify changes with verbose mode
/wordpress-seo-optimizer optimize post-id:123 --verbose
```

---

### Core Web Vitals Issues

**Problem:** CWV scores failing

**Solutions:**
1. **LCP (>2.5s)**
   - Optimize images (WebP format, compression)
   - Use lazy loading
   - Implement CDN
   - Optimize server response time

2. **INP (>200ms)**
   - Minimize JavaScript
   - Defer non-critical scripts
   - Remove unused plugins

3. **CLS (>0.1)**
   - Set image dimensions
   - Reserve space for ads
   - Avoid injecting content above existing content

```bash
# Detailed CWV analysis
/wordpress-seo-optimizer technical https://site.com --cwv --fix-issues
```

---

## Security Considerations

### Application Passwords

- **Scope:** App passwords grant full user access (no granular permissions)
- **Best Practice:** Create dedicated user with Editor role (not Administrator)
- **Rotation:** Revoke and regenerate passwords periodically
- **Storage:** Credentials stored securely in Claude Code config

### HTTPS Requirement

- **Always use HTTPS** - Basic auth credentials are visible over HTTP
- **SSL Certificate:** Free via Let's Encrypt
- **Mixed Content:** Ensure all resources load via HTTPS

### WordPress Hardening

- Keep WordPress core updated
- Keep plugins updated
- Use strong passwords
- Limit login attempts
- Regular backups

---

## FAQ

### Q: Do I need to install any WordPress plugins?

**A:** No for basic functionality. The skill works with standard WordPress REST API. Optional plugins (Yoast SEO, RankMath) provide enhanced features. For advanced features, install our custom **SEO Optimizer Pro** plugin.

---

### Q: Will this work with my WordPress theme?

**A:** Yes. The skill uses WordPress REST API which is theme-independent. All changes are made via API, not theme files.

---

### Q: Can I use this with WooCommerce products?

**A:** Yes. WooCommerce products are WordPress posts and can be optimized. Use Product schema for product pages.

---

### Q: How often should I run SEO audits?

**A:**
- **New content:** Analyze before publishing
- **Existing content:** Monthly audits
- **Technical SEO:** Quarterly audits
- **Ongoing monitoring:** Weekly reports

---

### Q: Does this replace my SEO plugin?

**A:** No, it complements your SEO plugin. The skill automates optimization tasks and provides analysis. Your plugin (Yoast, RankMath) still handles on-page SEO displays, XML sitemaps, etc.

---

### Q: What's the difference between SEO, GEO, and AEO?

**A:**
- **SEO (Search Engine Optimization):** Traditional Google/Bing search rankings
- **GEO (Generative Engine Optimization):** AI search engines (ChatGPT, Perplexity, Copilot)
- **AEO (Answer Engine Optimization):** Featured snippets, voice search, direct answers

This skill optimizes for all three.

---

### Q: Can I undo optimizations?

**A:** Yes. WordPress maintains post revisions. You can revert via WordPress admin (Posts → Revisions) or use the skill:

```bash
/wordpress-seo-optimizer optimize post-id:123 --revert-to-revision=5
```

---

## Support & Resources

### Documentation

- [Strategic Plan](./STRATEGIC_PLAN.md) - Full technical architecture and decision framework
- [API Reference](./docs/API_REFERENCE.md) - Module and function documentation
- [WordPress REST API Docs](https://developer.wordpress.org/rest-api/) - WordPress official docs

### Related Skills

- `/seo-geo-aeo` - General SEO knowledge (not WordPress-specific)
- `/blog-content-writer` - Content creation with SEO built-in
- `/wordpress-patterns` - WordPress development patterns

### External Resources

- [Google Search Central](https://developers.google.com/search) - Google SEO documentation
- [Yoast SEO Academy](https://yoast.com/academy/) - SEO learning
- [Schema.org](https://schema.org/) - Structured data specifications

---

## Contributing

This skill is part of the **Streamlined Development** centralized learning system.

### Report Issues

- Found a bug? [Create an issue](https://github.com/[repo]/issues)
- Have a feature request? [Create an issue](https://github.com/[repo]/issues)

### Contribute Lessons

If you've learned something valuable while using this skill:

```bash
cd /path/to/streamlined-development
./scripts/contribute-lesson.sh wordpress-seo-optimizer
```

---

## License

Part of the Streamlined Development system.

---

**Version:** 0.1.0-alpha (MVP in development)
**Last Updated:** 2026-02-11
**Status:** Planning phase - see [STRATEGIC_PLAN.md](./STRATEGIC_PLAN.md) for implementation roadmap
