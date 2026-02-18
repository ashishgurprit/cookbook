# Module-First Development System

> **MANDATORY FRAMEWORK**: Before writing ANY implementation code, check existing reusable modules first.
> This skill is automatically invoked by all development skills to prevent duplicate code.

---

## Overview

Every development skill in this system MUST follow the Module-First protocol:

1. **Check** — Query existing modules for reusable code
2. **Import** — Use module code as foundation (not from scratch)
3. **Extend** — Only write new code for gaps not covered by modules
4. **Contribute** — Feed learnings back to modules for future reuse

**Planning/assessment skills** use the Framework-First variant instead:
1. **Check** — Load relevant assessment frameworks and checklists
2. **Apply** — Use structured evaluation templates
3. **Score** — Apply consistent scoring/grading systems
4. **Document** — Output in standardized format

---

## Module Registry

### Integration & API (used by 7+ skills)
| Module | Path | What It Provides |
|--------|------|-----------------|
| `unified-api-client` | `modules/unified-api-client/` | Base HTTP client, retry logic, auth strategies (API key, OAuth, Bearer), response normalization |
| `omni-channel-core` | `modules/omni-channel-core/` | Multi-channel routing, provider abstraction, message normalization |
| `social-media-client` | `modules/social-media-client/` | Unified posting to 13+ networks, scheduling, analytics |

### Data & Infrastructure (used by 6+ skills)
| Module | Path | What It Provides |
|--------|------|-----------------|
| `database-orm-patterns` | `modules/database-orm-patterns/` | SQLAlchemy setup, repository pattern, model mixins, migrations |
| `scheduling-framework` | `modules/scheduling-framework/` | Cron management, health checks, job history, failure alerts |
| `content-pipeline-orchestrator` | `modules/content-pipeline-orchestrator/` | State machine (CREATED→PUBLISHED), pipeline stages, error recovery |

### Content & Publishing (used by 5+ skills)
| Module | Path | What It Provides |
|--------|------|-----------------|
| `wordpress-publisher` | `modules/wordpress-publisher/` | WP REST API client, media upload, SEO metadata, batch publishing |
| `astro-blog-seo` | `modules/astro-blog-seo/` | JSON-LD structured data, meta tags, Open Graph optimization |
| `decap-image-paste` | `modules/decap-image-paste/` | Clipboard paste handler, GitHub upload, image optimization |

### Media & AI (used by 3+ skills)
| Module | Path | What It Provides |
|--------|------|-----------------|
| `image-optimizer` | `modules/image-optimizer/` | WebP conversion, batch processing, resize/crop, quality optimization |
| `image-generation-validator` | `modules/image-generation-validator/` | Hash/timestamp validation, multi-provider support, quality scoring |
| `agent-core` | `modules/agent-core/` | LLM agent framework, tool management, conversation handling |
| `prompt-template-engine` | `modules/prompt-template-engine/` | Template rendering, variable injection, prompt versioning |
| `rag-pipeline` | `modules/rag-pipeline/` | Vector search, embedding generation, context retrieval |
| `text-chunker` | `modules/text-chunker/` | Semantic chunking, token-aware splitting, overlap management |

### Mobile (19 modules)
| Module | Path | What It Provides |
|--------|------|-----------------|
| `supabase-mobile-auth` | `modules/supabase-mobile-auth/` | Supabase auth hooks, social login, magic links, session management |
| `supabase-database-setup` | `modules/supabase-database-setup/` | RLS policies, table setup, migration patterns, type generation |
| `supabase-realtime` | `modules/supabase-realtime/` | Realtime subscriptions, broadcast, presence tracking |
| `expo-push-notifications` | `modules/expo-push-notifications/` | Push notification setup, FCM/APNs, notification handlers |
| `mobile-analytics` | `modules/mobile-analytics/` | Event tracking, screen views, user properties, funnels |
| `mobile-subscription` | `modules/mobile-subscription/` | In-app purchases, RevenueCat, subscription lifecycle |
| `mobile-deep-linking` | `modules/mobile-deep-linking/` | Universal links, deep link routing, deferred deep links |
| `mobile-crash-reporting` | `modules/mobile-crash-reporting/` | Sentry integration, error boundaries, crash analytics |
| `mobile-form-validation` | `modules/mobile-form-validation/` | Zod/Yup schemas, form state management, error display |
| `mobile-biometric-auth` | `modules/mobile-biometric-auth/` | Face ID, Touch ID, fingerprint, secure credential storage |
| `mobile-network-status` | `modules/mobile-network-status/` | Connectivity detection, offline mode, sync queue |
| `mobile-permissions` | `modules/mobile-permissions/` | Camera, location, notifications permission flows |
| `mobile-localization` | `modules/mobile-localization/` | i18n setup, RTL support, dynamic language switching |
| `mobile-skeleton-loaders` | `modules/mobile-skeleton-loaders/` | Content placeholder animations, shimmer effects |
| `mobile-onboarding` | `modules/mobile-onboarding/` | Onboarding flows, feature tours, progressive disclosure |
| `mobile-remote-config` | `modules/mobile-remote-config/` | Feature flags, A/B testing, remote configuration |
| `mobile-social-sharing` | `modules/mobile-social-sharing/` | Share sheets, social platform deep links, OG previews |
| `mobile-maps-location` | `modules/mobile-maps-location/` | MapView, geolocation, geocoding, location permissions |
| `mobile-chat` | `modules/mobile-chat/` | Chat UI components, message bubbles, typing indicators |

---

## Protocol: Development Skills

When ANY development skill is invoked, follow this protocol BEFORE writing code:

### Step 1: Identify Relevant Modules

```
For the current task, check:
1. What domain does this task belong to? (API, mobile, content, etc.)
2. Which modules from the registry above are relevant?
3. Does the SQLite database have additional code blocks?

Query: SELECT name, description, language FROM code_blocks
       WHERE tags LIKE '%<domain>%' OR name LIKE '%<keyword>%';
```

### Step 2: Load Module Code

```
For each relevant module:
1. Read modules/<name>/README.md for API documentation
2. Read modules/<name>/src/ for implementation code
3. Note which functions/classes/hooks to import
```

### Step 3: Compose Solution

```
Architecture:
┌─────────────────────────────────────┐
│         Your Implementation         │
│  (only NEW logic unique to task)    │
├─────────────────────────────────────┤
│         Module Adapters             │
│  (thin wrappers customizing        │
│   module behavior for this task)    │
├─────────────────────────────────────┤
│         Reusable Modules            │
│  (imported as-is from modules/)     │
│  unified-api-client                 │
│  database-orm-patterns              │
│  scheduling-framework               │
│  etc.                               │
└─────────────────────────────────────┘
```

### Step 4: Report Module Usage

After implementation, report:
- Which modules were used
- What percentage of code came from modules vs new
- Any gaps that should become new modules

---

## Protocol: Planning & Assessment Skills

Planning skills don't write code but MUST use structured frameworks:

### Assessment Frameworks Available

| Framework | Used By | What It Provides |
|-----------|---------|-----------------|
| SPADE Decision Framework | `strategic-plan` | Setting, People, Alternatives, Decide, Explain |
| 3D Decision Matrix | `strategic-plan` | C-Suite perspectives x Six Thinking Hats x Decision type |
| WCAG 2.2 Checklist | `accessibility-wcag` | 78 success criteria across 4 principles |
| SEO/GEO/AEO Audit | `seo-geo-aeo` | Search optimization scoring matrix |
| CRO Hypothesis Template | `conversion-rate-optimization` | ICE scoring, experiment design, statistical significance |
| Security OWASP Top 10 | `security-owasp` | Vulnerability assessment checklist |
| Performance Budget | `performance` | Core Web Vitals, bundle analysis, lighthouse scoring |
| ASO Checklist | `app-store-optimization` | App store listing optimization matrix |

### Planning Skill Protocol

```
1. LOAD the relevant assessment framework
2. GATHER facts using the framework's checklist
3. SCORE using the framework's scoring system
4. RECOMMEND with prioritized action items
5. OUTPUT in the framework's standard format
```

---

## Lesson Feedback Loop

Lessons learned from real projects feed back into the system:

### How Lessons Improve Modules

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Project    │     │   Lessons    │     │   Module     │
│   Work       │────>│   Captured   │────>│   Upgrades   │
│              │     │   (146+)     │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
                           │
                           │ keyword + category
                           │ matching engine
                           ▼
                     ┌──────────────┐
                     │ lesson_module │
                     │ _map table   │
                     │ (610 links)  │
                     └──────────────┘
                           │
                     ┌─────┴─────┐
                     ▼           ▼
              ┌──────────┐ ┌──────────┐
              │ Critical │ │ Upgrade  │
              │ Bugfixes │ │ Features │
              │ (33)     │ │ (74)     │
              └──────────┘ └──────────┘
```

### Module Health Monitoring

Each module has a health score (0-100) based on:
- **Lesson density**: More actionable lessons = lower health (needs attention)
- **Skill references**: More skills depending on it = higher importance
- **Upgrade priority**: critical / high / medium / low

Query current health:
```sql
SELECT name, health_score, upgrade_priority, lesson_count, skill_ref_count
FROM module_registry
ORDER BY health_score ASC;
```

### Current Critical Modules (need immediate attention)

| Module | Health | Lessons | Issue |
|--------|--------|---------|-------|
| `database-orm-patterns` | 10 | 98 | Massive lesson accumulation — patterns need consolidation |
| `unified-api-client` | 25 | 62 | Many API integration lessons not yet incorporated |
| `agent-core` | 10 | 49 | AI/LLM lessons need integration into agent framework |
| `content-pipeline-orchestrator` | 35 | 57 | Pipeline lessons need state machine improvements |
| `mobile-localization` | 45 | 43 | i18n patterns from projects need extraction |
| `rag-pipeline` | 45 | 25 | RAG lessons need vector search improvements |

### Triggering Module Upgrades

When lesson_count for a module exceeds thresholds:
- **> 50 lessons**: CRITICAL — schedule immediate upgrade sprint
- **> 25 lessons**: HIGH — include in next development cycle
- **> 10 lessons**: MEDIUM — batch upgrades quarterly
- **< 10 lessons**: LOW — address opportunistically

Upgrade process:
1. Query lessons mapped to the module
2. Extract actionable patterns and fixes
3. Update module source code
4. Update module README
5. Mark lessons as applied in `lesson_usage` table
6. Recalculate health score

```sql
-- Find lessons that should improve a specific module
SELECT l.title, l.content, lm.relevance, lm.action_needed
FROM lesson_module_map lm
JOIN lessons l ON lm.lesson_id = l.id
WHERE lm.module_name = '<module-name>'
AND lm.relevance IN ('critical', 'actionable')
ORDER BY lm.relevance;
```

---

## Skill-Module Dependency Map

### How to Check Dependencies

```sql
-- What modules does a skill need?
SELECT m.module_name, m.dependency_type
FROM skill_module_deps m
JOIN skills s ON m.skill_id = s.id
WHERE s.name = '<skill-name>';

-- What skills use a specific module?
SELECT s.name, m.dependency_type
FROM skill_module_deps m
JOIN skills s ON m.skill_id = s.id
WHERE m.module_name = '<module-name>';

-- Find skills with no module dependencies (potential improvement targets)
SELECT s.name FROM skills s
WHERE s.id NOT IN (SELECT skill_id FROM skill_module_deps);
```

### Current Top Module Dependencies

| Module | Skills Using It |
|--------|----------------|
| `unified-api-client` | google-analytics-search-console, crm-marketing-automation, affiliate-monetization, stripe-subscription-billing, wix-app-framework, google-vertex-ai-imagen, ecommerce-universal |
| `database-orm-patterns` | google-analytics-search-console, crm-marketing-automation, affiliate-monetization, smart-content-scheduler, stripe-subscription-billing, migration-upgrade-patterns |
| `wordpress-publisher` | smart-content-scheduler, cms-headless-universal, ecommerce-universal, affiliate-monetization, nextjs-app-patterns |
| `content-pipeline-orchestrator` | smart-content-scheduler, affiliate-monetization, cms-headless-universal |
| `scheduling-framework` | smart-content-scheduler, migration-upgrade-patterns |
| `image-optimizer` | cms-headless-universal, google-vertex-ai-imagen |

---

## Database Schema

The integration system uses these SQLite tables in `.claude/content.db`:

```sql
-- Skills (67 entries)
skills(id, name, description, skill_type, content, content_hash, metadata)

-- Code blocks / modules (230+ entries)
code_blocks(id, name, description, language, code, code_hash, tags, usage_count)

-- Module registry (51 entries)
module_registry(id, name, description, category, status, health_score,
                lesson_count, skill_ref_count, upgrade_priority, upgrade_notes)

-- Skill → Module dependencies (41+ entries)
skill_module_deps(id, skill_id, module_name, dependency_type, usage_description)

-- Lesson → Module mappings (610+ entries)
lesson_module_map(id, lesson_id, module_name, relevance, action_needed)

-- Lesson → Skill mappings (1597+ entries)
lesson_skill_map(id, lesson_id, skill_id, relevance, action_needed)

-- Lessons (146 entries, 18 categories)
lessons(id, title, content, category, source_project, created_at)

-- Lesson usage tracking
lesson_usage(id, lesson_id, project_id, used_at)

-- Projects (83 entries)
projects(id, name, path, status, last_synced)
```

---

## Quick Reference: Which Modules to Use

### "I'm building an API integration"
→ Start with: `unified-api-client` + `database-orm-patterns`
→ Add if needed: `scheduling-framework` (for retries), `omni-channel-core` (multi-channel)

### "I'm building a content publishing feature"
→ Start with: `content-pipeline-orchestrator` + `wordpress-publisher`
→ Add if needed: `social-media-client` (social), `image-optimizer` (images), `astro-blog-seo` (SEO)

### "I'm building a mobile app feature"
→ Start with: `supabase-mobile-auth` + `supabase-database-setup`
→ Add if needed: Domain-specific mobile modules from the 19 available

### "I'm building an AI/LLM feature"
→ Start with: `agent-core` + `prompt-template-engine`
→ Add if needed: `rag-pipeline` + `text-chunker` (for RAG), `document-extractor` (for ingestion)

### "I'm building a marketing/analytics feature"
→ Start with: `unified-api-client` + `database-orm-patterns`
→ Add if needed: `social-media-client` (social), `scheduling-framework` (automation)

### "I'm doing a migration or upgrade"
→ Start with: `database-orm-patterns` (for DB migrations)
→ Reference: `migration-upgrade-patterns` skill for framework-specific guidance

### "I'm building payment/billing"
→ Start with: `mobile-subscription` (mobile) or `unified-api-client` (web)
→ Reference: `stripe-subscription-billing` skill for Stripe patterns

---

## Enforcement

This system is enforced through:

1. **Skill headers**: Every development skill's SKILL.md starts with `## Module Dependencies`
2. **Pre-implementation check**: Skills list required modules before any code sections
3. **Health monitoring**: `module_registry` table tracks which modules need upgrades
4. **Lesson feedback**: `lesson_module_map` routes new learnings to relevant modules
5. **Gap detection**: Orphan modules and missing dependencies are tracked

### For Skill Authors

When creating a new skill:
1. Check `module_registry` for relevant modules
2. Add `## Module Dependencies` section listing required modules
3. Import and use module code in your implementation sections
4. Insert dependency records: `INSERT INTO skill_module_deps (skill_id, module_name, dependency_type) VALUES (...)`
5. Test that module references resolve to actual files in `modules/`
