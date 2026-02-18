# Monthly Research & Update Cycle

> Systematic monthly research to keep all skills and modules current with industry best practices.
> Run at the start of each month: `/project:monthly-research-update`

---

## Overview

This skill drives a monthly research cycle that:
1. **Scans** for version updates, deprecations, and new best practices across all tracked technologies
2. **Prioritizes** which skills/modules need updates based on staleness + impact
3. **Researches** top professional sources for each domain
4. **Updates** skills/modules with latest patterns
5. **Logs** everything to SQLite for tracking and accountability

---

## Monthly Cycle Process

### Phase 1: Staleness Assessment (10 min)

Run the staleness check to identify what needs attention:

```sql
-- Find most stale components (not researched in 60+ days)
SELECT component_type, component_name, domain, last_researched,
       julianday('now') - julianday(COALESCE(last_researched, '2024-01-01')) as days_stale,
       technologies
FROM freshness_tracker
ORDER BY days_stale DESC
LIMIT 20;

-- Components never researched
SELECT component_type, component_name, domain, technologies
FROM freshness_tracker
WHERE last_researched IS NULL
ORDER BY domain;

-- Research log from last cycle
SELECT domain, COUNT(*) as findings,
       SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END) as applied,
       SUM(CASE WHEN status = 'researched' THEN 1 ELSE 0 END) as pending
FROM research_log
WHERE cycle_date = strftime('%Y-%m', 'now', '-1 month')
GROUP BY domain;
```

### Phase 2: Domain Research (60-90 min)

Research each domain in priority order. For each domain:

1. **Check official release notes/changelogs** for version bumps
2. **Scan professional blogs** for new patterns and best practices
3. **Check deprecation notices** that affect our code
4. **Look for security advisories** that need immediate action
5. **Note emerging tools/frameworks** gaining traction

#### Research Sources by Domain

##### Frontend (React, Next.js, CSS)
| Source | What to Check | Frequency |
|--------|--------------|-----------|
| [nextjs.org/blog](https://nextjs.org/blog) | New versions, App Router changes, caching updates | Monthly |
| [react.dev/blog](https://react.dev/blog) | React releases, new hooks, compiler updates | Monthly |
| [vitejs.dev/blog](https://vitejs.dev/blog) | Vite releases, plugin ecosystem | Monthly |
| [tailwindcss.com/blog](https://tailwindcss.com/blog) | Tailwind releases, new utilities | Monthly |
| [web.dev/blog](https://web.dev/blog) | Core Web Vitals changes, Chrome features | Monthly |
| [developer.chrome.com/blog](https://developer.chrome.com/blog) | DevTools updates, Web Platform features | Monthly |
| Kent C. Dodds blog | React patterns, testing practices | Monthly |
| Dan Abramov blog | React internals, mental models | Quarterly |
| Addy Osmani blog | Performance, loading strategies | Quarterly |

**Key questions to answer:**
- Has React released a new major version? New hooks?
- Has Next.js changed its caching behavior (again)?
- Are there new CSS features with broad support (container queries, @layer, :has)?
- Have Core Web Vitals thresholds changed?
- Is Turbopack stable enough to recommend over webpack?

##### Mobile (React Native, Expo)
| Source | What to Check | Frequency |
|--------|--------------|-----------|
| [expo.dev/changelog](https://expo.dev/changelog) | SDK releases, API changes, EAS updates | Monthly |
| [reactnative.dev/blog](https://reactnative.dev/blog) | RN releases, architecture changes | Monthly |
| [supabase.com/blog](https://supabase.com/blog) | Auth changes, new features, RLS updates | Monthly |
| [revenuecat.com/blog](https://www.revenuecat.com/blog) | IAP changes, StoreKit updates | Monthly |
| [developer.apple.com/news](https://developer.apple.com/news/) | iOS policy changes, new APIs | Monthly |
| [android-developers.googleblog.com](https://android-developers.googleblog.com/) | Android policy, Play Store changes | Monthly |

**Key questions to answer:**
- Has Expo released a new SDK version? Breaking changes?
- Has React Native's New Architecture become default?
- Have Apple/Google changed review guidelines or policies?
- Has Supabase changed auth flows or RLS behavior?
- Are there new StoreKit/Play Billing APIs affecting subscriptions?

##### AI/ML (LLMs, Image Gen, RAG)
| Source | What to Check | Frequency |
|--------|--------------|-----------|
| [docs.anthropic.com](https://docs.anthropic.com/en/docs) | Claude API changes, new models, tool use updates | Monthly |
| [platform.openai.com](https://platform.openai.com/docs) | GPT updates, API changes, new capabilities | Monthly |
| [blog.langchain.dev](https://blog.langchain.dev/) | LangChain releases, new abstractions | Monthly |
| [cloud.google.com/blog](https://cloud.google.com/blog/products/ai-machine-learning) | Vertex AI, Imagen, Gemini updates | Monthly |
| [huggingface.co/blog](https://huggingface.co/blog) | Open source model releases, benchmarks | Monthly |
| [pinecone.io/blog](https://www.pinecone.io/blog/) | Vector DB patterns, embedding strategies | Quarterly |

**Key questions to answer:**
- Have Claude/GPT released new models or deprecated old ones?
- Has the recommended approach to tool use / function calling changed?
- Are there new embedding models with better performance?
- Has RAG best practice shifted (chunking strategies, reranking)?
- Are there new image generation models worth supporting?

##### DevOps/Infrastructure
| Source | What to Check | Frequency |
|--------|--------------|-----------|
| [nodejs.org/blog](https://nodejs.org/en/blog) | Node.js LTS releases, deprecations | Monthly |
| [pnpm.io/blog](https://pnpm.io/blog) | pnpm releases, workspace changes | Monthly |
| [eslint.org/blog](https://eslint.org/blog/) | ESLint flat config, rule updates | Monthly |
| [prisma.io/blog](https://www.prisma.io/blog) | Prisma releases, new features | Monthly |
| [orm.drizzle.team](https://orm.drizzle.team/blog) | Drizzle releases, migration tools | Monthly |
| [github.blog/changelog](https://github.blog/changelog/) | Actions updates, new features | Monthly |
| [vercel.com/blog](https://vercel.com/blog) | Deployment features, edge runtime | Monthly |
| [blog.railway.com](https://blog.railway.com/) | Railway features, pricing changes | Quarterly |

**Key questions to answer:**
- Is there a new Node.js LTS version? EOL dates changed?
- Has ESLint fully migrated to flat config? Old config deprecated?
- Has Prisma or Drizzle added major features (e.g., edge support)?
- Have GitHub Actions changed pricing, runners, or permissions model?

##### E-Commerce/Payments
| Source | What to Check | Frequency |
|--------|--------------|-----------|
| [stripe.com/blog](https://stripe.com/blog) | API version changes, new products | Monthly |
| [docs.stripe.com/changelog](https://docs.stripe.com/changelog) | API changelog, deprecations | Monthly |
| [shopify.dev/changelog](https://shopify.dev/changelog) | Storefront API changes, new APIs | Monthly |
| [developer.woocommerce.com](https://developer.woocommerce.com/) | REST API updates, HPOS migration | Quarterly |

**Key questions to answer:**
- Has Stripe released a new API version? Deprecated endpoints?
- Has Shopify changed Storefront API versioning or rate limits?
- Is WooCommerce HPOS (High-Performance Order Storage) now default?

##### Security
| Source | What to Check | Frequency |
|--------|--------------|-----------|
| [owasp.org](https://owasp.org/www-project-top-ten/) | Top 10 updates, new attack vectors | Quarterly |
| [portswigger.net/research](https://portswigger.net/research) | New web vulnerabilities | Monthly |
| [passkeys.dev](https://passkeys.dev/) | Passkey adoption, browser support | Quarterly |
| OAuth/OIDC specs | OAuth 2.1 finalization, DPoP adoption | Quarterly |

**Key questions to answer:**
- Has OWASP Top 10 been updated?
- Is OAuth 2.1 finalized? Should we update auth patterns?
- What percentage of users can use Passkeys now?
- Are there new JWT attacks or mitigations?

##### Marketing/SEO
| Source | What to Check | Frequency |
|--------|--------------|-----------|
| [developers.google.com/search/blog](https://developers.google.com/search/blog) | Algorithm updates, ranking signals | Monthly |
| [schema.org](https://schema.org/docs/releases.html) | New schema types, property changes | Quarterly |
| [developers.hubspot.com/changelog](https://developers.hubspot.com/changelog) | API changes, new endpoints | Monthly |
| [mautic.org](https://github.com/mautic/mautic/releases) | Mautic releases | Quarterly |

**Key questions to answer:**
- Has Google changed ranking signals or core algorithm?
- Are there new structured data types gaining rich result support?
- Has GA4 API added new dimensions/metrics?
- Has Google Search Console API changed?

---

### Phase 3: Log Findings (15 min)

For each finding, insert into `research_log`:

```sql
INSERT INTO research_log
(cycle_date, domain, topic, current_version, latest_version,
 breaking_changes, new_best_practices, deprecations,
 action_needed, affected_skills, affected_modules, priority, sources)
VALUES
('2026-02', 'frontend', 'Next.js', '15.1', '15.3',
 'params is now Promise in all page components',
 'PPR (Partial Prerendering) is now stable',
 'generateStaticParams no longer uses legacy fallback',
 'update', 'nextjs-app-patterns', NULL, 'high',
 'https://nextjs.org/blog/next-15-3');
```

### Phase 4: Prioritize Updates (10 min)

Score each finding using the RICE framework:

```
Priority Score = (Reach x Impact x Confidence) / Effort

Reach:      How many skills/modules are affected? (1-10)
Impact:     How significant is the change? (1-5)
            5 = Breaking change / security vulnerability
            4 = Major new feature / deprecation
            3 = Best practice shift
            2 = Minor improvement
            1 = Cosmetic / documentation only
Confidence: How certain are we this needs updating? (0.5-1.0)
Effort:     How many hours to update? (1-20)
```

**Auto-escalation rules:**
- Security vulnerabilities → CRITICAL (update within 48 hours)
- Breaking changes in current LTS/stable → HIGH (update within 1 week)
- Deprecation notices → MEDIUM (update within 1 month)
- New best practices → LOW (update in next cycle)

### Phase 5: Apply Updates (2-4 hours)

For each prioritized update:

1. Read the current SKILL.md or module source
2. Identify sections that need changes
3. Update code examples with latest APIs
4. Update version numbers and compatibility notes
5. Add migration notes if patterns changed
6. Mark as applied in research_log

```sql
UPDATE research_log
SET status = 'applied', applied_at = CURRENT_TIMESTAMP
WHERE id = <finding_id>;

UPDATE freshness_tracker
SET last_researched = date('now'), last_updated = date('now'), staleness_score = 0
WHERE component_name = '<skill-or-module-name>';
```

### Phase 6: Staleness Recalculation (5 min)

After applying updates, recalculate staleness scores:

```sql
-- Increase staleness by 1 point per week since last research
UPDATE freshness_tracker
SET staleness_score = MIN(100,
    CAST((julianday('now') - julianday(COALESCE(last_researched, '2024-01-01'))) / 7 AS INTEGER)
);

-- Report: most stale after this cycle
SELECT component_type, component_name, domain, staleness_score, last_researched
FROM freshness_tracker
WHERE staleness_score > 30
ORDER BY staleness_score DESC;
```

---

## Research Checklist Template

Copy this for each monthly cycle:

```markdown
## Research Cycle: YYYY-MM

### Pre-Research
- [ ] Run staleness assessment query
- [ ] Review last month's unapplied findings
- [ ] Note any user-reported issues with outdated patterns

### Domain Research
- [ ] **Frontend**: React, Next.js, Vite, Tailwind, CSS
- [ ] **Mobile**: Expo SDK, React Native, Supabase, RevenueCat
- [ ] **AI/ML**: Claude API, OpenAI, LangChain, Vertex AI
- [ ] **DevOps**: Node.js, pnpm, ESLint, Prisma, GitHub Actions
- [ ] **E-Commerce**: Stripe, Shopify, WooCommerce
- [ ] **Security**: OWASP, OAuth, Passkeys, JWT
- [ ] **Marketing**: Google Search, GA4, Schema.org, CRM
- [ ] **Content**: WordPress, Decap, Sanity, Contentful

### Findings Logged
- [ ] All findings inserted into research_log
- [ ] Priority scores calculated
- [ ] Critical/High items flagged for immediate action

### Updates Applied
- [ ] Security vulnerabilities patched (if any)
- [ ] Breaking changes addressed
- [ ] High-priority updates applied
- [ ] SKILL.md files updated
- [ ] Module source code updated (if needed)

### Post-Update
- [ ] Staleness scores recalculated
- [ ] Freshness tracker updated
- [ ] Summary written for team review
- [ ] Lessons captured for any gotchas encountered
```

---

## Quarterly Deep Dives

Every 3 months, do a deeper analysis on one domain:

| Quarter | Deep Dive Domain | Focus Areas |
|---------|-----------------|-------------|
| Q1 (Jan) | Frontend | React ecosystem, build tools, CSS evolution |
| Q2 (Apr) | Mobile | Expo SDK major version, Apple/Google policy |
| Q3 (Jul) | AI/ML | Model landscape, RAG patterns, agent frameworks |
| Q4 (Oct) | DevOps + Security | Node.js LTS cycle, OWASP review, auth standards |

Deep dives should:
- Benchmark our patterns against top open-source projects
- Review conference talks from recent events (React Conf, Next.js Conf, Google I/O, WWDC)
- Compare our implementations to official documentation recommendations
- Identify patterns we're using that the industry has moved away from

---

## Annual Review

Once per year (December):

1. **Full ecosystem audit** — Are we tracking the right technologies?
2. **Skill relevance check** — Should any skills be deprecated or merged?
3. **Module health review** — Are modules still architecturally sound?
4. **Technology radar** — What's entering Adopt/Trial/Assess/Hold?
5. **Competitive analysis** — What are agencies like us using that we're not?

---

## Automation Opportunities

### What Can Be Automated Now
- Staleness score calculation (run as cron/scheduled script)
- RSS feed monitoring for official blogs (GitHub Actions + RSS parser)
- npm/pip outdated checks against skill-documented versions
- GitHub release monitoring for tracked dependencies

### Future Automation
- Auto-detect breaking changes by diffing changelogs
- Auto-generate research reports from RSS feeds
- Slack/email alerts when tracked dependencies release major versions
- Auto-PR with version bump suggestions

### Example: GitHub Actions Dependency Monitor

```yaml
name: Monthly Dependency Check
on:
  schedule:
    - cron: '0 9 1 * *'  # 1st of each month at 9am

jobs:
  check-versions:
    runs-on: ubuntu-latest
    steps:
      - name: Check Next.js
        run: |
          LATEST=$(npm view next version)
          echo "Next.js latest: $LATEST"

      - name: Check Expo
        run: |
          LATEST=$(npm view expo version)
          echo "Expo latest: $LATEST"

      - name: Check Stripe
        run: |
          LATEST=$(npm view stripe version)
          echo "Stripe latest: $LATEST"

      - name: Generate Report
        run: echo "TODO: Compare against documented versions in skills"
```

---

## Database Schema Reference

```sql
-- Research findings per monthly cycle
research_log(
    id, cycle_date, domain, topic,
    current_version, latest_version,
    breaking_changes, new_best_practices, deprecations,
    action_needed,        -- update | rewrite | none
    affected_skills,      -- comma-separated
    affected_modules,     -- comma-separated
    priority,             -- critical | high | medium | low
    status,               -- researched | in-progress | applied | skipped
    sources,              -- URLs
    created_at, applied_at
)

-- Component freshness tracking
freshness_tracker(
    id, component_type, component_name, domain,
    last_researched,      -- date of last research
    last_updated,         -- date of last code update
    staleness_score,      -- 0-100 (auto-calculated)
    technologies,         -- JSON array of tech names
    update_sources,       -- JSON array of URLs to check
    notes
)
```

---

## Quick Start: Running Your First Cycle

```bash
# 1. Check what's most stale
sqlite3 .claude/content.db "SELECT component_name, domain, staleness_score FROM freshness_tracker ORDER BY staleness_score DESC LIMIT 10;"

# 2. Research the top domain (e.g., frontend)
# Use web search to check each source listed above

# 3. Log findings
sqlite3 .claude/content.db "INSERT INTO research_log (cycle_date, domain, topic, latest_version, action_needed, affected_skills, priority) VALUES ('$(date +%Y-%m)', 'frontend', 'Next.js 16', '16.0', 'update', 'nextjs-app-patterns', 'high');"

# 4. After updating, mark as applied
sqlite3 .claude/content.db "UPDATE freshness_tracker SET last_researched = date('now'), staleness_score = 0 WHERE component_name = 'nextjs-app-patterns';"
```
