# Technical SEO Audit Checklist

Comprehensive technical SEO audit for websites.

## Crawlability & Indexation

### Robots.txt
- [ ] Robots.txt exists at /robots.txt
- [ ] No important pages blocked
- [ ] Sitemap URL included
- [ ] Proper User-agent directives
- [ ] No conflicting rules

### XML Sitemap
- [ ] Sitemap exists and accessible
- [ ] Submitted to Google Search Console
- [ ] Submitted to Bing Webmaster Tools
- [ ] Contains only indexable URLs
- [ ] No 404 or redirected URLs
- [ ] Last modified dates accurate
- [ ] Under 50MB / 50,000 URLs per sitemap
- [ ] Sitemap index if multiple sitemaps

### Indexation
- [ ] Site indexed (site:domain.com search)
- [ ] Important pages indexed
- [ ] No duplicate content indexed
- [ ] Noindex tags used correctly
- [ ] Canonical tags implemented
- [ ] No orphan pages (pages without internal links)

### Crawl Budget
- [ ] No infinite URL parameters
- [ ] Pagination handled (rel=next/prev or load more)
- [ ] Faceted navigation managed
- [ ] Session IDs not in URLs
- [ ] Calendar/date archives limited

## Site Architecture

### URL Structure
- [ ] URLs are clean and readable
- [ ] Lowercase URLs only
- [ ] Hyphens used (not underscores)
- [ ] No special characters
- [ ] Logical hierarchy
- [ ] Trailing slash consistency
- [ ] Under 75 characters

### Navigation
- [ ] Clear main navigation
- [ ] Breadcrumb navigation implemented
- [ ] Footer navigation useful
- [ ] Maximum 3 clicks to any page
- [ ] HTML sitemap available

### Internal Linking
- [ ] Important pages have most internal links
- [ ] No broken internal links
- [ ] Anchor text descriptive
- [ ] Related content linked
- [ ] Content silos/clusters logical

## Page Speed & Performance

### Core Web Vitals
- [ ] LCP < 2.5 seconds
- [ ] INP < 200ms
- [ ] CLS < 0.1

### Speed Optimization
- [ ] Images compressed and optimized
- [ ] WebP format used where supported
- [ ] Lazy loading for below-fold images
- [ ] CSS minified
- [ ] JavaScript minified
- [ ] Defer/async for non-critical JS
- [ ] Render-blocking resources eliminated
- [ ] Browser caching enabled
- [ ] Gzip/Brotli compression enabled
- [ ] CDN implemented for static assets
- [ ] TTFB < 200ms

### Resource Optimization
- [ ] No oversized images
- [ ] No unused CSS
- [ ] No unused JavaScript
- [ ] Fonts optimized (WOFF2, font-display: swap)
- [ ] Third-party scripts minimized
- [ ] Preload critical resources
- [ ] Preconnect to required origins

## Mobile Optimization

### Mobile-Friendliness
- [ ] Passes Google Mobile-Friendly Test
- [ ] Responsive design implemented
- [ ] Viewport meta tag correct
- [ ] Text readable without zooming
- [ ] Touch targets adequately sized (48px+)
- [ ] No horizontal scrolling required
- [ ] Content same as desktop

### Mobile UX
- [ ] No intrusive interstitials
- [ ] Forms easy to complete on mobile
- [ ] Buttons/links not too close together
- [ ] Phone numbers clickable (tel: links)
- [ ] Maps/addresses accessible

## Security

### HTTPS
- [ ] SSL certificate valid
- [ ] SSL certificate not expiring soon
- [ ] All pages served over HTTPS
- [ ] HTTP redirects to HTTPS
- [ ] No mixed content warnings
- [ ] HSTS header implemented

### Security Headers
- [ ] Content-Security-Policy
- [ ] X-Content-Type-Options
- [ ] X-Frame-Options
- [ ] Referrer-Policy
- [ ] Permissions-Policy

## On-Page Elements

### Title Tags
- [ ] Every page has unique title
- [ ] Titles under 60 characters
- [ ] Primary keyword included
- [ ] Brand included where appropriate
- [ ] No duplicate titles

### Meta Descriptions
- [ ] Every page has meta description
- [ ] Descriptions 150-160 characters
- [ ] Compelling with CTA
- [ ] Keyword included naturally
- [ ] No duplicate descriptions

### Headings
- [ ] One H1 per page
- [ ] Logical heading hierarchy
- [ ] Keywords in headings
- [ ] No empty heading tags
- [ ] No skipped heading levels

### Images
- [ ] All images have alt text
- [ ] Alt text descriptive
- [ ] File names descriptive
- [ ] Images properly sized
- [ ] No missing images (404)

## Structured Data

### Implementation
- [ ] Appropriate schema types used
- [ ] Schema validates in testing tool
- [ ] No errors in Search Console
- [ ] Required properties included
- [ ] Recommended properties added

### Common Schemas
- [ ] Organization/LocalBusiness
- [ ] Breadcrumbs
- [ ] Article/BlogPosting (if applicable)
- [ ] FAQ (if applicable)
- [ ] Product (if e-commerce)
- [ ] Review/Rating (if applicable)

## International SEO (if applicable)

### Hreflang
- [ ] Hreflang tags implemented
- [ ] Self-referencing hreflang
- [ ] Return tags present
- [ ] Valid language/region codes
- [ ] x-default specified

### Multi-Regional
- [ ] Country-specific content
- [ ] Local currency/measurements
- [ ] Proper geo-targeting in Search Console
- [ ] ccTLDs or subdirectories used correctly

## Duplicate Content

### Detection
- [ ] No duplicate title tags
- [ ] No duplicate meta descriptions
- [ ] No duplicate content across pages
- [ ] Parameter handling configured
- [ ] WWW vs non-WWW resolved
- [ ] Trailing slash consistency

### Resolution
- [ ] Canonical tags implemented
- [ ] 301 redirects for duplicates
- [ ] Noindex for unavoidable duplicates
- [ ] Pagination handled correctly

## Error Handling

### HTTP Status Codes
- [ ] No 404 errors for important pages
- [ ] Custom 404 page exists
- [ ] 404 page helpful (search, navigation)
- [ ] No soft 404s
- [ ] Proper use of 301 vs 302 redirects
- [ ] No redirect chains (max 2 hops)
- [ ] No redirect loops

### Server Errors
- [ ] No 5xx errors
- [ ] Server stable under load
- [ ] Error logging enabled
- [ ] Uptime monitoring in place

## Search Console

### Setup
- [ ] Property verified
- [ ] All versions verified (www, non-www, http, https)
- [ ] Sitemap submitted
- [ ] Users/permissions configured

### Monitoring
- [ ] Coverage report clean
- [ ] No manual actions
- [ ] Core Web Vitals monitored
- [ ] Security issues checked
- [ ] Enhancement reports reviewed

## Tools for Audit

### Free Tools
- Google Search Console
- Google PageSpeed Insights
- Google Mobile-Friendly Test
- Google Rich Results Test
- Bing Webmaster Tools
- Lighthouse (Chrome DevTools)

### Paid Tools
- Screaming Frog SEO Spider
- Ahrefs Site Audit
- SEMrush Site Audit
- Sitebulb
- DeepCrawl

## Audit Schedule

| Check | Frequency |
|-------|-----------|
| Crawl errors | Weekly |
| Core Web Vitals | Weekly |
| Broken links | Monthly |
| Full technical audit | Quarterly |
| Security review | Quarterly |
| Structured data validation | Monthly |
| Sitemap accuracy | Monthly |
