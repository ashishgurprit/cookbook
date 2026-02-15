# Article Template

Use this template when generating new blog content for any of the four sites.

## MDX Frontmatter

```yaml
---
title: "[Compelling Title with Primary Keyword - Under 60 Characters]"
description: "[150-160 character description with primary keyword and value proposition]"
date: "[YYYY-MM-DD]"
author: "Ash Ganda"
tags: ["[platform/category]", "[keyword1]", "[keyword2]", "[keyword3]"]
image: "/images/hero-[slug].png"
ogImage: "/images/hero-[slug]-og.jpg"
readingTime: "[X] min read"
slug: "[url-friendly-slug-from-title]"
keywords: ["[primary-keyword]", "[secondary-keyword]", "[tertiary-keyword]", "[long-tail-keyword]"]
lastModified: "[YYYY-MM-DD]"
schema:
  type: "Article"
  category: "Technology"
cluster: "[cloud-platforms|enterprise-platforms|digital-marketing|web-development]"
relatedPosts: []
---
```

## Article Structure

### Hook Paragraph

Write a compelling opening that:
- States the problem or opportunity clearly
- Establishes relevance to the target audience
- Creates urgency or curiosity
- Previews the value of reading further

**Length**: 75-150 words depending on site

### Context Section

Provide background that:
- Explains why this topic matters now
- Sets industry or market context
- Establishes credibility
- Connects to reader's situation

**Length**: 150-300 words depending on site

### Main Sections (2-4 sections)

Each section should:
- Have a clear ## heading with keyword
- Open with a transition from previous section
- Include specific examples or case studies
- Provide data points or statistics
- Offer practical implementation guidance
- End with a bridge to the next section

**Length**: 250-400 words per section

### Practical Takeaways Section

Provide actionable guidance:
- Numbered steps or bullet points
- Clear, specific actions
- Resource recommendations
- Time/cost estimates where appropriate

**Length**: 150-250 words

### Conclusion

Wrap up with:
- Summary of key points
- Forward-looking insight
- Call-to-action aligned with site brand
- Optional: Invitation to engage further

**Length**: 100-150 words

## Site-Specific Adaptations

### For ashganda.com
- More strategic, less tactical
- Longer analysis sections
- Executive-level language
- Reference analyst reports

### For insights.cloudgeeks.com.au
- Include Australian context
- Add cost considerations
- Reference local compliance
- Provide SMB-friendly alternatives

### For eawesome.com.au
- Include code examples
- Reference specific frameworks
- Developer-focused language
- Performance considerations

### For cosmowebtech.com.au
- Simplest language
- Step-by-step format
- Local Western Sydney context
- Screenshots described

## Quality Checklist

Before finalizing:

- [ ] Title includes primary keyword and is under 60 characters
- [ ] Description is 150-160 characters with keyword
- [ ] Word count matches site target
- [ ] At least 3 specific examples included
- [ ] Statistics or data points included
- [ ] All sections have clear transitions
- [ ] Tone matches site brand guide
- [ ] Actionable takeaways are clear and specific
- [ ] Conclusion has forward-looking insight
- [ ] No promotional or sales language
- [ ] No jargon without explanation
- [ ] All claims are supportable

## Example Article Outline

**Site**: insights.cloudgeeks.com.au
**Topic**: Azure vs AWS for Australian SMBs

```markdown
---
title: "Azure vs AWS for Australian SMBs: 2025 Comparison"
description: "Compare Azure and AWS for Australian small businesses. Cost analysis, local support, compliance considerations, and practical migration guidance."
date: "2025-01-15"
author: "Ash Ganda"
tags: ["Cloud Infrastructure", "Azure", "AWS", "SMB"]
...
---

[Hook: Australian SMBs face critical cloud choice]

## The Australian SMB Cloud Landscape
[Context: Market share, local data centers, support options]

## Cost Comparison: What Australian Businesses Actually Pay
[Analysis: Pricing models, typical workloads, hidden costs]

## Local Support and Compliance
[Analysis: Australian data sovereignty, Essential Eight, local partners]

## Migration Considerations
[Practical: Steps, timeline, common pitfalls]

## Making Your Decision
[Takeaways: Decision framework, recommendations by business type]

## What's Next for Cloud in Australia
[Conclusion: Trends, forward look, CTA]
```

## Infographic Placement

Insert infographic after the second-to-last section:

```markdown
![Infographic](/images/[slug]-infographic.png)
```

## Contextual Image Placement

Insert contextual image before the conclusion:

```markdown
![Descriptive Alt Text](/images/[slug]-contextual.jpg)
```

## Closing Format

```markdown
---
*[Site-appropriate call-to-action]*
```

### Site-Specific CTAs

**ashganda.com**:
> *Looking to develop your cloud strategy? Explore our enterprise consulting services.*

**insights.cloudgeeks.com.au**:
> *Need help with your cloud migration? Contact our team for a free consultation.*

**eawesome.com.au**:
> *Building your next app? Let's discuss your architecture.*

**cosmowebtech.com.au**:
> *Ready to improve your online presence? Get in touch for a free website review.*
