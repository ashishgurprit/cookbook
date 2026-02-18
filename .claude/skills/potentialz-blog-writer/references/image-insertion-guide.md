# Image URL Insertion Guide for Structured Data Markup

## Overview

When generating structured data markup for Potentialz blog posts, image URLs need to be inserted at specific locations. This guide explains the process for inserting Wix-hosted image URLs into the JSON-LD schema.

## Wix Image URL Format

Wix-hosted images follow this pattern:
```
https://static.wixstatic.com/media/[hash]~mv2.[format]
```

Examples:
- `https://static.wixstatic.com/media/cf1eaf_2490410401b649d3a17d2c07561cbd21~mv2.jpg`
- `https://static.wixstatic.com/media/194442_f34296b0d6854428b53111b991f0b4be~mv2.png`

## Placeholder Locations in Schema

### 1. Article Schema - Hero Image

**Location**: `@graph[0].image`
**Line**: Approximately line 8
**Placeholder**: `[IMAGE_URL_HERO]`

```json
{
  "@type": "Article",
  "image": "[IMAGE_URL_HERO]",  // <-- INSERT HERE
  ...
}
```

**What to insert**: The main hero/featured image for the blog post

### 2. Organization Schema - Logo

**Location**: `@graph[1].logo`
**Line**: Approximately line 22
**Placeholder**: Already set to organization logo

```json
{
  "@type": "Organization",
  "logo": "https://static.wixstatic.com/media/194442_f34296b0d6854428b53111b991f0b4be~mv2.png",
  ...
}
```

**Note**: This should remain the standard Potentialz logo unless specifically changed.

### 3. LocalBusiness Schema - Business Image

**Location**: `@graph[2].image`
**Line**: Approximately line 35
**Placeholder**: `[IMAGE_URL_PRACTICE]`

```json
{
  "@type": "LocalBusiness",
  "image": "[IMAGE_URL_PRACTICE]",  // <-- INSERT HERE
  ...
}
```

**What to insert**: Practice photo or location image

## Step-by-Step Process

### Step 1: Generate the Markup

When creating content, generate the structured data with placeholders:

```json
"image": "[IMAGE_URL_HERO]",
```

### Step 2: List Required Images

At the end of the structured data section, provide a list:

```markdown
**Image URLs Required:**

1. **Line 8** - Hero Image `[IMAGE_URL_HERO]`
   - Description: Main blog post featured image
   - Recommended: Professional, topic-relevant image

2. **Line 35** - Practice Image `[IMAGE_URL_PRACTICE]`
   - Description: Potentialz practice photo
   - Default: https://static.wixstatic.com/media/cf1eaf_2490410401b649d3a17d2c07561cbd21~mv2.jpg
```

### Step 3: Request User Input

Ask the user:

```markdown
Please provide the Wix image URLs to replace the placeholders:

1. Hero image URL for Line 8:
2. (Optional) Custom practice image for Line 35, or use default:
```

### Step 4: Insert and Validate

After receiving URLs:
1. Replace each placeholder with the actual URL
2. Validate the JSON is still properly formatted
3. Check total character count stays under 7,000

## Default Images

Use these defaults when specific images aren't provided:

### Organization Logo
```
https://static.wixstatic.com/media/194442_f34296b0d6854428b53111b991f0b4be~mv2.png
```

### Practice Photo
```
https://static.wixstatic.com/media/cf1eaf_2490410401b649d3a17d2c07561cbd21~mv2.jpg
```

### Location/Map Image
```
https://lh3.googleusercontent.com/p/AF1QipMaMNR54N_B3B3YeeCGEwNAtnSgwfv7wT_-msBb
```

## Validation Checklist

After inserting images:

- [ ] All `[IMAGE_URL_*]` placeholders replaced
- [ ] URLs are properly formatted (start with https://)
- [ ] No trailing commas or syntax errors
- [ ] JSON validates (use jsonlint.com)
- [ ] Total markup under 7,000 characters
- [ ] Image URLs are accessible (not 404)

## Common Issues

### Issue 1: Invalid JSON after insertion

**Problem**: Missing quotes or commas
**Solution**: Ensure URL is wrapped in double quotes: `"https://..."`

### Issue 2: Image URL too long

**Problem**: Very long hash in Wix URL
**Solution**: Use shortened or optimized URL if available

### Issue 3: Character limit exceeded

**Problem**: Markup exceeds 7,000 characters
**Solution**:
- Remove optional fields
- Shorten descriptions
- Use minimal sameAs array

## Template with Line Numbers

```json
1  {
2    "@context": "https://schema.org",
3    "@graph": [
4      {
5        "@type": "Article",
6        "@id": "https://www.potentialz.com.au/post/[slug]#article",
7        "headline": "[Title]",
8        "image": "[IMAGE_URL_HERO]",  // <-- LINE 8: Hero image
9        "author": {
10         "@type": "Organization",
11         "name": "Potentialz Unlimited"
12       },
...
35       "image": "[IMAGE_URL_PRACTICE]",  // <-- LINE 35: Practice image
...
```

## Quick Reference Card

| Placeholder | Location | Default Available |
|-------------|----------|-------------------|
| `[IMAGE_URL_HERO]` | Article.image (Line ~8) | No - must provide |
| `[IMAGE_URL_PRACTICE]` | LocalBusiness.image (Line ~35) | Yes - use practice photo |
| `[IMAGE_URL_AUTHOR]` | Author.image (if used) | Yes - use team photo |

## Example Completed Markup Snippet

```json
{
  "@type": "Article",
  "headline": "Understanding Anxiety: A Guide for Bella Vista Families",
  "image": "https://static.wixstatic.com/media/cf1eaf_abc123def456~mv2.jpg",
  "author": {
    "@type": "Organization",
    "name": "Potentialz Unlimited"
  }
}
```
