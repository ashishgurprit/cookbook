# Optimize Command

Apply SEO optimizations to a WordPress post or page.

## Usage

```bash
/wordpress-seo-optimizer optimize [URL or post-id] [options]
```

## Parameters

- `target` - WordPress post URL or post ID
- `--apply-all` - Apply all recommended optimizations automatically
- `--title="New Title"` - Update title tag
- `--meta="Description"` - Update meta description
- `--keywords="keyword1,keyword2"` - Set target keywords
- `--schema=Article` - Add schema markup type
- `--optimize-images` - Optimize image alt text
- `--fix-headers` - Fix header hierarchy
- `--add-internal-links` - Add internal links
- `--target-density=1.5` - Target keyword density percentage
- `--dry-run` - Preview changes without applying
- `--confirm` - Require confirmation before each change

## Optimization Types (MVP)

### 1. Title Tag Optimization
- Ensure 50-60 characters
- Include primary keyword
- Front-load important keywords
- Make compelling for CTR

### 2. Meta Description
- Generate 150-160 character description
- Include primary keyword
- Add clear call-to-action
- Accurately preview content

### 3. Header Structure
- Add H1 with primary keyword (if missing)
- Fix header hierarchy (no skipped levels)
- Distribute keywords across H2/H3

### 4. Image Alt Text
- Add descriptive alt text to all images
- Include keywords where natural
- Keep under 125 characters

### 5. Schema Markup (Basic)
- Add Article schema with:
  - Headline
  - Author
  - Published/modified dates
  - Image
  - Description

## Example Usage

### Apply All Optimizations
```bash
/wordpress-seo-optimizer optimize post-id:123 --apply-all
```

### Selective Optimization
```bash
/wordpress-seo-optimizer optimize https://site.com/post \
  --title="New SEO Title" \
  --meta="Compelling meta description here" \
  --schema=Article \
  --optimize-images
```

### Preview Before Applying
```bash
/wordpress-seo-optimizer optimize post-id:123 --apply-all --dry-run
```

## Example Output

```
Analyzing post for optimization opportunities...

┌─────────────────────────────────────────────────────┐
│  OPTIMIZATION PREVIEW                                │
├─────────────────────────────────────────────────────┤
│  Post: "Dog Training Tips" (ID: 123)                │
│  Current SEO Score: 68/100                          │
│  Projected Score: 89/100 (+21 points)               │
└─────────────────────────────────────────────────────┘

PLANNED CHANGES:

1. TITLE TAG ✏️
   Current: "Dog Training"
   New:     "Dog Training Tips: 10 Proven Methods for New Owners"
   Impact:  +5 points

2. META DESCRIPTION ✏️
   Current: (missing)
   New:     "Discover 10 effective dog training tips that work.
             From puppy basics to advanced commands, learn proven
             methods used by professional trainers. Start today!"
   Impact:  +10 points

3. HEADER STRUCTURE ✏️
   Add H1: "Dog Training Tips for New Dog Owners"
   Fix H3 under H2 (currently H4 under H2)
   Impact:  +5 points

4. ARTICLE SCHEMA ✏️
   Add JSON-LD schema with:
   - @type: Article
   - headline: "Dog Training Tips: 10 Proven Methods"
   - author: "John Smith"
   - datePublished: "2026-02-11"
   - image: "https://site.com/wp-content/uploads/dog-training.jpg"
   Impact:  +10 points

5. IMAGE OPTIMIZATION ✏️
   - image-1.jpg: Add alt "Golden retriever puppy learning sit command"
   - image-2.jpg: Add alt "Dog training treats and clicker"
   - image-3.jpg: Optimize alt "puppy" → "Puppy responding to training cues"
   Impact:  +3 points

6. KEYWORD DENSITY ✏️
   Current: 0.8% (8 mentions in 1000 words)
   Target:  1.5% (15 mentions)
   Action:  Naturally add 7 more keyword mentions
   Impact:  +5 points

SUMMARY:
  Total Changes: 6
  SEO Score: 68 → 89 (+21 points)
  Estimated Time: 30 seconds

Apply these optimizations?
[Yes] [No] [Review individually]

> Yes

Applying optimizations...

✅ Title tag updated
✅ Meta description added
✅ H1 heading added
✅ Header hierarchy fixed
✅ Article schema added to post meta
✅ 3 image alt texts updated
✅ Keyword density optimized

┌─────────────────────────────────────────────────────┐
│  OPTIMIZATION COMPLETE                               │
├─────────────────────────────────────────────────────┤
│  ✅ All optimizations applied successfully          │
│  📊 SEO Score: 68 → 89 (+21 points)                 │
│  ⏱️  Completed in: 1.2 seconds                      │
└─────────────────────────────────────────────────────┘

BEFORE/AFTER COMPARISON:
  Title Tag:        10/15 → 15/15 ✅
  Meta Description:  0/10 → 10/10 ✅
  Headers:           5/10 → 10/10 ✅
  Content:          14/20 → 19/20 ✅
  Images:            7/10 → 10/10 ✅
  Technical:        12/15 → 12/15 ─
  Schema:            0/10 → 10/10 ✅
  Links:             2/5 →  2/5 ─
  GEO/AEO:           3/5 →  3/5 ─

NEXT STEPS:
  1. Add 2-3 internal links (run with --add-internal-links)
  2. Consider adding FAQ schema for Q&A section
  3. Monitor rankings in Google Search Console

View optimized post: https://site.com/dog-training-tips
Run analysis again: /wordpress-seo-optimizer analyze post-id:123
```

## Implementation Steps

1. Fetch current post data via WordPress REST API
2. Run analysis to identify optimization opportunities
3. Generate optimized values:
   - Title tag (use AI for compelling copy)
   - Meta description (keyword + CTA)
   - H1 heading
   - Image alt text
   - Schema markup
4. Preview changes to user
5. If confirmed, apply via REST API:
   - Update post title
   - Update post meta (Yoast/RankMath fields)
   - Update content (headers, images)
   - Inject schema
6. Verify changes
7. Display before/after comparison

## Optimization Safety

### Safeguards
- **Dry-run mode**: Preview before applying
- **Confirmation required**: User approves changes
- **Reversible**: WordPress maintains post revisions
- **Validation**: Check changes don't break content
- **Backup**: Store original values before modification

### What's NOT Modified (MVP)
- Post content text (only structure)
- Published status
- Categories/tags
- Featured image (file)
- Custom fields (except SEO meta)

## Error Handling

- **Insufficient permissions**: User needs `edit_posts` capability
- **Post locked**: Another user editing (check lock status)
- **SEO plugin conflict**: Detect and adapt to plugin being used
- **Network error**: Retry with exponential backoff
- **Validation failure**: Rollback and report error

## Integration with SEO Plugins

### Yoast SEO
- Update `_yoast_wpseo_title`
- Update `_yoast_wpseo_metadesc`
- Update `_yoast_wpseo_focuskw`

### RankMath
- Update `rank_math_title`
- Update `rank_math_description`
- Update `rank_math_focus_keyword`

### All in One SEO
- Update `_aioseo_title`
- Update `_aioseo_description`
- Update `_aioseo_keywords`

## Related Commands

- `/wordpress-seo-optimizer analyze` - Analyze before optimizing
- `/wordpress-seo-optimizer keywords` - Research target keywords first
- `/wordpress-seo-optimizer schema` - Advanced schema management
