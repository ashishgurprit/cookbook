# Historical Content Template

Use this template when generating content backdated to a specific historical date. This is critical for Phase 2 content generation where posts are created to fill historical gaps.

## Temporal Grounding Rules

### Critical Principle
**Write FROM the publication date, not ABOUT it.** The reader should experience the content as if they are reading it on the actual publication date.

### Language Rules

| Situation | Correct | Incorrect |
|-----------|---------|-----------|
| Referencing the topic | "Cloud adoption is accelerating" | "Cloud adoption was accelerating" |
| Future developments | "We expect to see..." | "As we now know..." |
| Recent events | "Last month's announcement..." | "The announcement that happened..." |
| Technology state | "The latest version includes..." | "The version available then had..." |

### DO
- Use present and future tense appropriate to the date
- Reference "recent" events from that time period
- Describe technology as it existed at that date
- Project future trends as they would have been predicted then

### DO NOT
- Mention anything that happened after the publication date
- Use retrospective language ("as we now know", "in hindsight")
- Reference technologies not yet released
- Mention acquisitions, product shutdowns, or pivots that came later

## Pre-Writing Research Checklist

Before writing historical content, verify:

1. **What was available**:
   - Framework/platform versions at that date
   - Features that had been released
   - Major announcements up to that point

2. **What was NOT yet available**:
   - Future versions and features
   - Products not yet launched
   - Companies not yet acquired

3. **Context of the time**:
   - Major tech news from that month
   - Industry trends being discussed
   - Market conditions and events

## Historical Context Block

Include this context block in your prompt when generating content:

```
CRITICAL TEMPORAL GROUNDING:
Publication Date: [DATE]
Write as if today is [DATE].

AVAILABLE AT THIS TIME:
- [Technology/version]
- [Recent announcement]
- [Current market condition]

NOT YET AVAILABLE (DO NOT MENTION):
- [Future product/feature]
- [Later acquisition]
- [Subsequent event]

RECENT CONTEXT (reference as "recent"):
- [News from past 1-3 months]
- [Industry development]
- [Market trend]
```

## Example: Historical Post for November 2018

### Context Block

```
CRITICAL TEMPORAL GROUNDING:
Publication Date: 2018-11-15
Write as if today is November 15, 2018.

AVAILABLE AT THIS TIME:
- AWS Lambda (launched 2014, mature)
- Azure Functions GA (launched 2016)
- GCP Cloud Functions (GA since July 2018)
- React 16.6 (just released October 2018)
- Node.js 10 LTS (current)
- Python 3.7 (released June 2018)

NOT YET AVAILABLE (DO NOT MENTION):
- AWS Lambda Layers (announced Nov 29, 2018 - AFTER this date)
- Azure Functions v2 runtime (still in preview)
- React Hooks (announced Feb 2019)
- Node.js 12 (released April 2019)
- Python 3.8 (released October 2019)

RECENT CONTEXT:
- AWS re:Invent 2018 coming up (Nov 26-30)
- Microsoft acquired GitHub (June 2018)
- Kubernetes 1.12 released (Sept 2018)
- Serverless Framework 1.32 current version
```

### Sample Opening (Correct)

> "Serverless computing is reaching a tipping point in enterprise adoption. With AWS Lambda now over four years old and Azure Functions maturing rapidly, the question for CTOs is no longer whether to adopt serverless, but how to do so strategically."

### Sample Opening (Incorrect)

> "Looking back at the state of serverless in late 2018, we can see how the ecosystem was about to experience major changes with Lambda Layers and improved cold start times."

## MDX Frontmatter for Historical Content

```yaml
---
title: "[Title appropriate to the date's context]"
description: "[Description using present tense]"
date: "[HISTORICAL-DATE]"
author: "Ash Ganda"
tags: ["[platform]", "[keyword1]", "[keyword2]"]
image: "/images/hero-[slug].png"
ogImage: "/images/hero-[slug]-og.jpg"
readingTime: "[X] min read"
slug: "[slug]"
keywords: ["[keywords relevant to that time]"]
lastModified: "[TODAY'S-DATE]"
schema:
  type: "Article"
  category: "Technology"
cluster: "[appropriate-cluster]"
relatedPosts: []
---
```

Note: `date` is the historical publication date, `lastModified` is when the file was actually created.

## Topic Selection by Era

### 2016-2017: Cloud Foundations Era
- Basic cloud migration guides
- IaaS vs PaaS decisions
- Early containerization (Docker)
- DevOps fundamentals

### 2018-2019: Serverless & Kubernetes Era
- Serverless architecture patterns
- Kubernetes adoption strategies
- Multi-cloud early discussions
- CI/CD pipeline evolution

### 2020-2021: Pandemic Digital Acceleration
- Remote work infrastructure
- Digital transformation urgency
- E-commerce and cloud scaling
- Security for distributed teams

### 2022-2023: AI Integration Era
- Early ChatGPT enterprise applications
- AI/ML infrastructure decisions
- Cloud cost optimization
- Platform engineering emergence

### 2024-2025: GenAI Enterprise Era
- Enterprise AI strategy
- AI governance and compliance
- Advanced cloud patterns
- Platform maturity

## Quality Checklist for Historical Content

- [ ] All technologies mentioned existed at the publication date
- [ ] No references to future events or developments
- [ ] Language uses appropriate tense (present/future from that date's perspective)
- [ ] "Recent" events are actually recent to that date
- [ ] Predictions/trends are what would have been said then
- [ ] Version numbers are correct for that date
- [ ] Company names reflect that date (no future acquisitions)
- [ ] Market context matches that era

## Common Mistakes to Avoid

### Technology Anachronisms
- Mentioning Kubernetes features before they existed
- Referencing cloud services before their GA date
- Using framework versions not yet released
- Citing acquisitions before they happened

### Linguistic Tells
- "As we now know..." (retrospective)
- "This would later become..." (retrospective)
- "Looking back..." (retrospective)
- "In hindsight..." (retrospective)

### Context Errors
- Mentioning COVID impacts in pre-2020 content
- Referencing ChatGPT in pre-November 2022 content
- Discussing post-acquisition product changes
- Using current pricing for historical cost analyses

## Verification Process

Before finalizing historical content:

1. **Date Check**: Search for any dates mentioned - ensure none are after publication
2. **Product Check**: Verify all products/features existed at that time
3. **Version Check**: Confirm version numbers are historically accurate
4. **Event Check**: Ensure no references to future acquisitions, shutdowns, or pivots
5. **Language Check**: Scan for retrospective phrasing
6. **Context Check**: Verify market conditions match the era
