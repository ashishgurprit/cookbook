# Strategic Plan: WordPress SEO/AEO/GEO Optimization Skill

**Date:** 2026-02-11
**Type:** HIGH-STAKES
**Reversibility:** TWO-WAY (can be modified/extended)
**Importance:** HIGH (impacts user visibility, traffic, and business outcomes)
**Process:** Quick SPADE

---

## Decision Classification

```
Decision Matrix Position: HIGH-STAKES (High Importance + Two-Way Door)

                    REVERSIBILITY
          ┌─────────────────┬─────────────────┐
          │   TWO-WAY DOOR  │   ONE-WAY DOOR  │
┌─────────┼─────────────────┼─────────────────┤
│  HIGH   │   ✓ HERE        │    TRAPDOOR     │
│         │   Quick SPADE   │   Full SPADE    │
├─────────┼─────────────────┼─────────────────┤
│  LOW    │     YOLO        │    VERIFY       │
└─────────┴─────────────────┴─────────────────┘
```

**Rationale:**
- **HIGH Importance**: Affects search visibility, traffic, and SEO outcomes for all WordPress sites
- **TWO-WAY Door**: Can iterate, add features, refine approach without breaking existing implementations
- **Process**: Quick SPADE with CTO + CPO perspectives

---

## C-Suite Perspectives

### Primary Perspectives

**CTO (Chief Technology Officer)**
- Technical architecture and plugin integration
- WordPress REST API utilization
- Performance and scalability
- Security considerations (app password access)
- Analytics implementation

**CPO (Chief Product Officer)**
- User experience and workflow
- Value delivered to end users
- Ease of use and learning curve
- Feature completeness vs. simplicity

### Secondary Consultants

**CRO (Chief Revenue Officer)**
- Impact on search rankings and organic traffic
- ROI through improved visibility
- Competitive differentiation

**COO (Chief Operating Officer)**
- Implementation complexity
- Maintenance burden
- Documentation and support needs

---

## 🎩 Thinking Hat Analysis

### ⚪ White Hat (Facts & Information)

#### Current State

**Existing Assets:**
- `modules/wordpress-publisher/` - WordPress REST API client
  - Authentication via app passwords
  - Post/media management
  - Basic SEO meta injection (Yoast, RankMath)
  - Python + TypeScript implementations

**WordPress SEO Plugin Landscape:**

| Plugin | Market Share | API Access | Capabilities |
|--------|--------------|------------|--------------|
| **Yoast SEO** | ~30% (12M+ sites) | REST API ✓ | Meta fields, readability, XML sitemaps |
| **RankMath** | ~10% (2M+ sites) | REST API ✓ | Schema, redirects, analytics |
| **All in One SEO** | ~20% (3M+ sites) | REST API ✓ | Similar to Yoast |
| **SEOPress** | ~2% (300k+ sites) | REST API ✓ | Schema, breadcrumbs |
| **The SEO Framework** | ~0.5% (100k+) | Limited API | Lightweight alternative |

**WordPress REST API Capabilities:**
- Posts/pages CRUD
- Media uploads
- Taxonomies (categories/tags)
- Custom post meta (if registered with `show_in_rest`)
- Custom fields
- Comments
- User management

**WordPress Ecosystem Facts:**
- 43% of all websites use WordPress (2025)
- WordPress 5.6+ has built-in Application Passwords
- REST API v2 is stable and well-documented
- Gutenberg block editor uses REST API extensively

#### SEO Components Required

**1. Keyword Research & Analysis**
- Identify target keywords per page
- Search volume and competition data
- LSI (Latent Semantic Indexing) keywords
- Competitor keyword analysis

**2. On-Page SEO**
- Title tags (50-60 chars)
- Meta descriptions (150-160 chars)
- Header structure (H1-H6)
- URL slugs
- Image alt text
- Internal linking
- Content optimization
- Keyword density

**3. Technical SEO**
- Core Web Vitals (LCP, INP, CLS)
- Mobile optimization
- XML sitemaps
- Robots.txt
- Canonical tags
- Schema markup (JSON-LD)
- Site speed
- HTTPS/security

**4. Internal SEO**
- Internal link structure
- Content clustering/silos
- Breadcrumb navigation
- Anchor text optimization
- Orphan page detection

**5. External SEO (Indirect)**
- Backlink opportunities identification
- Content promotion strategies
- Social sharing optimization
- Local SEO (Google Business Profile)

**6. GEO (Generative Engine Optimization)**
- Quotable content structure
- Authority signals (E-E-A-T)
- Structured, parseable content
- Source attribution
- Freshness timestamps
- Comprehensive topic coverage

**7. AEO (Answer Engine Optimization)**
- Featured snippet optimization
- FAQ schema
- People Also Ask (PAA) targeting
- Voice search optimization
- Question-answer format

**8. Analytics & Tracking**
- Google Analytics 4 integration
- Google Search Console data
- Keyword ranking tracking
- Traffic monitoring
- Conversion tracking
- Core Web Vitals monitoring

#### WordPress Plugins We Can Work With (REST API Access)

**SEO Plugins:**
- ✅ Yoast SEO (meta fields via REST)
- ✅ RankMath (meta fields + schema via REST)
- ✅ All in One SEO (REST API support)
- ✅ SEOPress (REST API support)

**Analytics Plugins:**
- ✅ MonsterInsights (Google Analytics connector)
- ✅ Site Kit by Google (GA4, GSC, PageSpeed)
- ✅ Matomo Analytics (self-hosted)

**Performance Plugins:**
- ✅ WP Rocket (some settings via API)
- ✅ W3 Total Cache (limited API)
- ⚠️ Most caching plugins have limited API access

**Schema Plugins:**
- ✅ Schema Pro (REST API for schema types)
- ✅ WP SEO Structured Data Schema (REST support)

**Image Optimization:**
- ✅ Smush (REST API for bulk optimization)
- ✅ ShortPixel (API available)
- ✅ Imagify (REST API support)

#### Plugins We May Need to Create

**1. SEO Optimizer Pro Custom Plugin**
- Comprehensive SEO analysis endpoint
- Keyword density calculation
- Readability scoring (Flesch-Kincaid)
- Internal link analysis
- Broken link detection
- Image alt text audit
- Schema validation
- Core Web Vitals tracking endpoint

**2. Keyword Research Connector**
- Integrate with keyword APIs:
  - Google Keyword Planner API
  - SEMrush API
  - Ahrefs API
  - Moz API
  - DataForSEO API
- Store keyword data as post meta
- Keyword tracking over time

**3. Analytics Bridge Plugin**
- Unified analytics interface
- GSC (Google Search Console) API connector
- GA4 data retrieval
- Core Web Vitals monitoring
- Custom dashboard endpoint

**4. Schema Generator Plugin**
- Dynamic schema generation based on content type
- Article, BlogPosting, FAQPage, HowTo
- Local Business schema
- Product schema
- Review schema
- Custom schema types

**5. Internal Link Suggester**
- Analyze content for internal linking opportunities
- Suggest related posts
- Anchor text optimization
- Link equity distribution analysis

---

### 🟢 Green Hat (Alternatives & Creativity)

#### Alternative 1: Comprehensive Integrated Skill

**Approach:** Single unified skill that handles all SEO aspects end-to-end

**Components:**
1. Keyword research workflow
2. On-page optimization (title, meta, headers, content)
3. Technical SEO audit and fixes
4. Internal linking recommendations
5. Schema markup generation
6. Analytics setup and monitoring
7. GEO/AEO optimization
8. Performance optimization

**How it Works:**
```
User: /wordpress-seo-optimizer optimize https://mysite.com/blog/post-slug

Skill:
1. Fetches post via WordPress REST API
2. Analyzes current SEO state
3. Identifies keyword opportunities
4. Generates optimization recommendations
5. Applies changes via REST API
6. Tracks analytics
7. Provides ongoing monitoring
```

**Pros:**
- Complete solution in one skill
- Seamless workflow
- Consistent experience
- Easier for users to understand

**Cons:**
- Large, complex skill
- Harder to maintain
- May be overwhelming for simple use cases
- Testing complexity

---

#### Alternative 2: Modular Multi-Skill Approach

**Approach:** Separate skills for different SEO aspects

**Skills:**
1. `/wordpress-keyword-research` - Keyword identification and analysis
2. `/wordpress-onpage-seo` - Title, meta, headers, content optimization
3. `/wordpress-technical-seo` - Technical audit and fixes
4. `/wordpress-schema-generator` - Schema markup creation
5. `/wordpress-analytics-setup` - Analytics and tracking setup
6. `/wordpress-internal-linking` - Internal link optimization
7. `/wordpress-geo-aeo` - GEO/AEO optimization

**How it Works:**
```
User: /wordpress-keyword-research identify keywords for "dog training tips"
User: /wordpress-onpage-seo optimize post-id 123 with keyword "dog training"
User: /wordpress-schema-generator add FAQ schema to post 123
```

**Pros:**
- Modular and focused
- Easier to maintain individual components
- Users choose what they need
- Can be developed incrementally

**Cons:**
- Fragmented experience
- User needs to know which skill to use
- Potential duplication across skills
- More skills to document

---

#### Alternative 3: Pipeline-Based Approach (RECOMMENDED)

**Approach:** Main orchestrator skill with modular sub-workflows

**Structure:**
```
/wordpress-seo-optimizer [command] [target]

Commands:
- analyze      - Full SEO audit of post/page
- optimize     - Apply all optimizations
- keywords     - Keyword research and selection
- technical    - Technical SEO audit
- schema       - Add/update schema markup
- monitor      - Setup analytics tracking
- report       - Generate SEO report
```

**How it Works:**
```
User: /wordpress-seo-optimizer analyze https://mysite.com/post-slug

Skill Output:
┌─────────────────────────────────────┐
│  SEO ANALYSIS REPORT                │
├─────────────────────────────────────┤
│  ⚠️  Issues Found: 8                │
│  ✅  Optimizations Available: 12    │
└─────────────────────────────────────┘

KEYWORDS:
  Target: "dog training tips"
  Density: 0.8% (Target: 1-2%)
  LSI Keywords: Missing

ON-PAGE:
  ✅ Title: 52 chars (optimal)
  ⚠️  Meta description: Missing
  ⚠️  H1: Not found
  ✅ Images: 5/5 have alt text

TECHNICAL:
  ⚠️  LCP: 3.2s (Target: <2.5s)
  ✅ Mobile-friendly
  ⚠️  Schema: No Article schema

RECOMMENDATIONS:
  1. Add meta description (150-160 chars)
  2. Add H1 heading with target keyword
  3. Optimize images for faster LCP
  4. Add Article schema markup
  5. Increase keyword density to 1.5%

Apply optimizations? [Yes/No]
```

**Pros:**
- Unified entry point
- Modular internals (easy to maintain)
- Clear user experience
- Progressive disclosure (analyze → optimize)
- Can be extended with new commands

**Cons:**
- More complex architecture initially
- Requires command parsing

---

### 🟡 Yellow Hat (Benefits & Opportunities)

#### Benefits of Alternative 3 (Pipeline-Based)

**For Users:**
1. **One-stop SEO solution** - Single skill handles everything
2. **Clear workflow** - Analyze → Optimize → Monitor
3. **Educational** - Learn SEO best practices through recommendations
4. **Time-saving** - Automates tedious SEO tasks
5. **Confidence** - Data-driven recommendations with explanations
6. **Scalability** - Batch optimization for multiple posts

**For Technical Implementation:**
1. **Leverages existing modules** - Uses `wordpress-publisher` foundation
2. **REST API native** - No WordPress file access needed
3. **App password security** - Secure authentication
4. **Plugin extensibility** - Can create custom plugins as needed
5. **Language flexibility** - Python for analysis, TypeScript for frontend

**For SEO Outcomes:**
1. **Comprehensive optimization** - Covers SEO/GEO/AEO
2. **Modern search targeting** - AI search engines + traditional
3. **Technical excellence** - Core Web Vitals, schema, mobile
4. **Content quality** - Keyword optimization without keyword stuffing
5. **Competitive advantage** - Advanced GEO/AEO few competitors use

**For Business Value:**
1. **Increased organic traffic** - Better rankings
2. **Higher CTR** - Optimized titles and descriptions
3. **Better conversions** - Faster site, better UX
4. **AI visibility** - Citations in ChatGPT, Perplexity, etc.
5. **Voice search ready** - Featured snippets and PAA

#### Strategic Opportunities

**1. Integration with Existing Skills**
- `/blog-content-writer` → Auto-optimize content as it's written
- `/universal-content-pipeline` → SEO optimization in publishing workflow
- `/seo-geo-aeo` → WordPress-specific implementation

**2. Data-Driven Insights**
- Track keyword rankings over time
- A/B test title tags and meta descriptions
- Monitor Core Web Vitals trends
- Identify content gaps

**3. Automation Possibilities**
- Scheduled SEO audits
- Automatic schema generation based on content type
- Auto-internal linking as new posts are published
- Bulk optimization for existing content

**4. Competitive Intelligence**
- Analyze competitor WordPress sites
- Identify keyword opportunities
- Reverse-engineer successful content structures

**5. Multi-Site Management**
- Manage SEO across multiple WordPress sites
- Centralized reporting
- Consistent SEO standards

---

### ⚫ Black Hat (Risks & Concerns)

#### Technical Risks

**1. WordPress Plugin Compatibility**
- **Risk:** SEO plugins may not expose all settings via REST API
- **Mitigation:** Create custom plugin to expose additional endpoints
- **Fallback:** Focus on plugins with good API support (Yoast, RankMath)

**2. Authentication & Security**
- **Risk:** App passwords grant full user access (no scope limiting)
- **Mitigation:** Recommend dedicated user account with Editor role
- **Best Practice:** Clear documentation on security implications

**3. WordPress Version Compatibility**
- **Risk:** REST API differences across WordPress versions
- **Mitigation:** Require WordPress 5.6+ (app passwords introduced)
- **Testing:** Test against multiple WordPress versions

**4. Rate Limiting**
- **Risk:** WordPress sites may have rate limits on REST API
- **Mitigation:** Implement respectful rate limiting (configurable delays)
- **Strategy:** Batch operations with progress tracking

**5. Plugin Conflicts**
- **Risk:** SEO plugins may conflict with each other
- **Mitigation:** Detect active plugins and adapt behavior
- **Documentation:** Clear compatibility matrix

#### User Experience Risks

**1. Overwhelming Complexity**
- **Risk:** Too many options confuse users
- **Mitigation:** Progressive disclosure - simple by default, advanced options available
- **Design:** Clear "analyze → optimize" workflow

**2. Over-Optimization**
- **Risk:** Users may over-optimize and trigger spam filters
- **Mitigation:** Built-in guardrails (keyword density limits, readability scores)
- **Education:** Explain why recommendations matter

**3. Unrealistic Expectations**
- **Risk:** Users expect instant ranking improvements
- **Mitigation:** Set clear expectations about SEO timeframes
- **Documentation:** "SEO is a long-term strategy"

#### Business Risks

**1. SEO Plugin Dependency**
- **Risk:** Major plugins change their API or go out of business
- **Mitigation:** Support multiple plugins (Yoast, RankMath, AIOSEO)
- **Strategy:** Abstract plugin specifics behind common interface

**2. Google Algorithm Changes**
- **Risk:** SEO best practices change over time
- **Mitigation:** Build skill to be maintainable and updatable
- **Strategy:** Focus on fundamentals (content quality, E-E-A-T, technical excellence)

**3. AI Search Disruption**
- **Risk:** Traditional SEO may become less important
- **Mitigation:** Already includes GEO (Generative Engine Optimization)
- **Future-proof:** Easy to add new optimization types

#### Operational Risks

**1. Maintenance Burden**
- **Risk:** Complex skill requires ongoing maintenance
- **Mitigation:** Modular architecture - update components independently
- **Documentation:** Clear code documentation and testing

**2. Support Complexity**
- **Risk:** Users need help with WordPress-specific issues
- **Mitigation:** Comprehensive documentation and error messages
- **Strategy:** Leverage existing WordPress community resources

**3. API Key Management**
- **Risk:** Users need API keys for keyword research tools
- **Mitigation:** Make external APIs optional, provide alternatives
- **Free tier:** Support free APIs where possible

---

### 🔴 Red Hat (Intuition & Gut Feelings)

**CTO Intuition:**
> "This feels like a natural evolution of our existing WordPress modules. The REST API foundation is solid, and we already have the wordpress-publisher module handling authentication and basic operations. Building on that makes sense. The modular pipeline approach feels right - it's how developers think."

**CPO Intuition:**
> "Users struggle with SEO because it's complex and time-consuming. A skill that says 'here are 8 issues, let me fix them for you' is incredibly compelling. The analyze → optimize workflow is intuitive. I'm slightly concerned about overwhelming users with too much information, but progressive disclosure can solve that."

**CRO Intuition:**
> "SEO is THE use case for WordPress users. Every site owner wants better rankings. If we can deliver real improvements in search visibility, this becomes a must-have skill. GEO/AEO is the differentiator - few tools are optimizing for AI search yet."

**COO Intuition:**
> "The maintenance concern is real - WordPress and SEO plugins change frequently. But if we build this modularly and with good abstractions, we can adapt. The custom plugin approach for advanced features is pragmatic - it gives us control when we need it."

**Overall Gut Check:**
✅ **This feels like the right project at the right time**
- WordPress is ubiquitous
- SEO is a universal need
- We have solid foundations to build on
- GEO/AEO is emerging and we can lead here
- The modular approach balances complexity and usability

---

### 🔵 Blue Hat (Synthesis & Process Control)

#### Decision Framework Summary

**Question:** How should we structure the WordPress SEO optimization skill?

**Decision Type:** HIGH-STAKES (important but reversible)

**Recommended Process:** Quick SPADE

**Perspectives Consulted:** CTO, CPO, CRO, COO

**Thinking Hats Applied:**
- ⚪ White: Analyzed current state, WordPress ecosystem, SEO components
- 🟢 Green: Generated 3 alternatives (Integrated, Modular, Pipeline)
- 🟡 Yellow: Identified benefits and opportunities
- ⚫ Black: Assessed risks and mitigation strategies
- 🔴 Red: Validated with intuition and gut checks
- 🔵 Blue: Now synthesizing decision

---

## SPADE Decision Framework

### S - Setting (Context)

**Decision:** How to structure and implement a WordPress SEO/AEO/GEO optimization skill

**Why This Matters:**
- WordPress powers 43% of websites
- SEO is critical for visibility and traffic
- AI search (GEO/AEO) is emerging rapidly
- Users need automation for complex SEO tasks
- We have existing WordPress infrastructure to build on

**Context:**
- Existing `wordpress-publisher` module provides REST API foundation
- Existing `/seo-geo-aeo` skill provides knowledge but no WordPress integration
- Gap: No automated WordPress-specific SEO optimization tool
- Opportunity: First-to-market with comprehensive GEO/AEO for WordPress

**Constraints:**
- Must use WordPress REST API (no FTP/file access)
- Must support app password authentication
- Must work with popular SEO plugins (Yoast, RankMath)
- Must be maintainable as WordPress/plugins evolve
- Should not require users to install custom code initially

---

### P - People (Stakeholders)

**Responsible:** CTO
*Owns the technical architecture and implementation decision*

**Approvers:**
- CPO: User experience and feature set
- CRO: Value proposition and competitive positioning

**Consultants:**
- COO: Operational feasibility and maintenance
- Users: WordPress site owners, content creators, SEO practitioners

**Informed:**
- Development team
- Documentation writers
- Support team

---

### A - Alternatives (Options Evaluated)

#### Option 1: Comprehensive Integrated Skill ❌

**Description:** Single monolithic skill with all SEO features

**Pros:**
- Unified experience
- Single entry point
- Consistent behavior

**Cons:**
- Complex and hard to maintain
- Overwhelming for simple use cases
- Testing difficulty
- Tight coupling

**Assessment:** Too rigid, violates separation of concerns

---

#### Option 2: Modular Multi-Skill Approach ❌

**Description:** Separate skills for each SEO aspect

**Pros:**
- Clean separation
- Independent maintenance
- Focused functionality

**Cons:**
- Fragmented user experience
- User confusion about which skill to use
- Duplication across skills
- Coordination overhead

**Assessment:** Too fragmented, poor UX

---

#### Option 3: Pipeline-Based Approach ✅ **SELECTED**

**Description:** Single orchestrator skill with command-based sub-workflows

**Architecture:**
```
wordpress-seo-optimizer/
├── README.md                          # Main skill documentation
├── skill.json                         # Skill metadata
├── commands/
│   ├── analyze.md                     # SEO audit command
│   ├── optimize.md                    # Apply optimizations
│   ├── keywords.md                    # Keyword research
│   ├── technical.md                   # Technical SEO
│   ├── schema.md                      # Schema markup
│   ├── monitor.md                     # Analytics setup
│   └── report.md                      # SEO reporting
├── modules/
│   ├── keyword_analyzer.py            # Keyword research logic
│   ├── onpage_optimizer.py            # On-page SEO
│   ├── technical_auditor.py           # Technical SEO audits
│   ├── schema_generator.py            # Schema markup
│   ├── internal_linker.py             # Internal linking
│   ├── geo_aeo_optimizer.py           # GEO/AEO optimization
│   └── analytics_connector.py         # Analytics integration
├── wordpress_plugins/
│   ├── seo-optimizer-pro/             # Custom WordPress plugin
│   │   ├── seo-optimizer-pro.php
│   │   ├── includes/
│   │   │   ├── class-keyword-tracker.php
│   │   │   ├── class-link-analyzer.php
│   │   │   ├── class-schema-validator.php
│   │   │   └── class-cwv-monitor.php
│   │   └── README.md
│   └── analytics-bridge/              # Analytics connector plugin
│       ├── analytics-bridge.php
│       └── includes/
│           ├── class-gsc-connector.php
│           └── class-ga4-connector.php
├── templates/
│   ├── schema/                        # Schema JSON-LD templates
│   │   ├── article.json
│   │   ├── faq.json
│   │   ├── howto.json
│   │   └── local-business.json
│   └── reports/                       # Report templates
│       ├── audit_report.md
│       └── optimization_summary.md
├── tests/
│   ├── test_keyword_analyzer.py
│   ├── test_onpage_optimizer.py
│   └── test_wordpress_api.py
└── examples/
    ├── basic_optimization.md
    ├── bulk_optimization.md
    └── custom_workflow.md
```

**Command Structure:**
```bash
# Main command format
/wordpress-seo-optimizer [command] [target] [options]

# Examples
/wordpress-seo-optimizer analyze https://site.com/post-slug
/wordpress-seo-optimizer optimize post-id:123 --apply-all
/wordpress-seo-optimizer keywords "dog training tips" --research
/wordpress-seo-optimizer technical https://site.com --audit-only
/wordpress-seo-optimizer schema post-id:123 --type=Article
/wordpress-seo-optimizer monitor https://site.com --setup-analytics
/wordpress-seo-optimizer report https://site.com --last-30-days
```

**Workflow:**
```
1. User: /wordpress-seo-optimizer analyze https://site.com/post-slug

2. Skill:
   - Authenticates with WordPress REST API
   - Fetches post content and metadata
   - Analyzes:
     * Keywords (target, density, LSI)
     * On-page SEO (title, meta, headers)
     * Technical SEO (schema, mobile, speed)
     * Internal links
     * GEO/AEO readiness
   - Generates comprehensive report

3. Output:
   - Issues found (prioritized)
   - Optimization opportunities
   - Recommendations with explanations
   - "Apply all" or selective optimization options

4. User: /wordpress-seo-optimizer optimize post-id:123 --apply-all

5. Skill:
   - Applies optimizations via REST API
   - Updates post meta (title, description)
   - Adds/updates schema markup
   - Optimizes images (if plugin available)
   - Updates internal links
   - Confirms changes

6. Output:
   - Success summary
   - Before/after comparison
   - Next steps (monitoring, content updates)
```

**Why This Option:**
- ✅ **Unified entry point** - Single skill to learn
- ✅ **Modular internals** - Easy to maintain and extend
- ✅ **Clear workflow** - Analyze → Optimize → Monitor
- ✅ **Progressive disclosure** - Simple by default, powerful when needed
- ✅ **Extensible** - Add new commands without restructuring
- ✅ **Leverages existing modules** - Builds on wordpress-publisher
- ✅ **Balances UX and architecture** - Best of both worlds

---

### D - Decide (The Decision)

**DECISION: Implement Option 3 - Pipeline-Based Approach**

**Rationale:**

1. **Technical Excellence (CTO)**
   - Modular architecture enables independent component updates
   - Builds on proven `wordpress-publisher` foundation
   - REST API-native approach is secure and maintainable
   - Custom plugins provide flexibility when needed

2. **User Experience (CPO)**
   - Single skill reduces cognitive load
   - Command-based interface is intuitive
   - Analyze → Optimize workflow matches mental model
   - Progressive disclosure prevents overwhelm

3. **Business Value (CRO)**
   - Comprehensive SEO/GEO/AEO coverage
   - Competitive differentiator (few tools do GEO/AEO)
   - Addresses universal need (every WordPress site needs SEO)
   - Scalable to enterprise use cases

4. **Operational Feasibility (COO)**
   - Can be built incrementally (MVP → full feature set)
   - Maintenance burden is manageable with modular design
   - Testing strategy is clear
   - Documentation can grow with features

**Key Insights from Thinking Hats:**
- ⚪ **White**: WordPress ecosystem is stable, REST API is mature, plugins are compatible
- 🟢 **Green**: Pipeline approach balances modularity and usability
- 🟡 **Yellow**: Delivers comprehensive value, future-proof with GEO/AEO
- ⚫ **Black**: Risks are manageable with proper abstractions and documentation
- 🔴 **Red**: Feels right - builds on strengths, addresses real need, good timing

---

### E - Explain (Communication & Rollout)

#### To Development Team

**Message:**
> We're building a WordPress SEO optimization skill using a pipeline-based architecture. This will be a command-driven skill (`/wordpress-seo-optimizer [command]`) that handles comprehensive SEO analysis and optimization via the WordPress REST API.
>
> **Architecture:** We'll build on our existing `wordpress-publisher` module and create modular components for keyword analysis, on-page optimization, technical audits, schema generation, and GEO/AEO optimization. Each component will be independently testable and maintainable.
>
> **Development Approach:** Start with MVP (analyze + optimize commands) and iterate based on user feedback. Custom WordPress plugins will be developed only when REST API limitations are encountered.
>
> **Timeline:** Phase 1 (MVP) - 2 weeks, Phase 2 (Full features) - 4 weeks

#### To Users

**Message:**
> Introducing `/wordpress-seo-optimizer` - your all-in-one WordPress SEO assistant.
>
> **What it does:**
> - Analyzes your posts and pages for SEO issues
> - Provides clear, actionable recommendations
> - Automatically applies optimizations with your approval
> - Optimizes for traditional search AND AI search engines (ChatGPT, Perplexity, etc.)
> - Monitors your SEO performance over time
>
> **How to use it:**
> ```
> /wordpress-seo-optimizer analyze https://yoursite.com/post-slug
> ```
>
> The skill will audit your content and show you exactly what needs to be improved - from keyword optimization to technical SEO to schema markup.
>
> **Requirements:**
> - WordPress 5.6+ (for Application Passwords)
> - A WordPress user account with Editor role or higher
> - Optional: Yoast SEO or RankMath plugin for advanced features
>
> **Getting started:**
> 1. Create an Application Password in your WordPress profile
> 2. Run `/wordpress-seo-optimizer analyze [your-post-url]`
> 3. Review recommendations
> 4. Apply optimizations with one command

#### To Stakeholders

**Executive Summary:**
> **Project:** WordPress SEO/AEO/GEO Optimization Skill
>
> **Objective:** Automate comprehensive SEO optimization for WordPress sites, including emerging AI search engine optimization (GEO/AEO)
>
> **Value Proposition:**
> - Increase organic traffic through better search rankings
> - Improve visibility in AI search engines (ChatGPT, Perplexity)
> - Save hours of manual SEO work per post
> - Ensure technical SEO best practices
>
> **Differentiation:**
> - First tool to comprehensively address GEO/AEO for WordPress
> - Combines keyword research, on-page, technical, and content optimization
> - Automated workflow from analysis to implementation
>
> **Target Users:**
> - Content creators and bloggers
> - Digital marketers managing WordPress sites
> - SEO professionals optimizing client sites
> - Agencies managing multiple WordPress properties
>
> **Implementation:**
> - Builds on existing WordPress modules
> - Phased rollout: MVP → Full feature set
> - Timeline: 2 weeks (MVP), 6 weeks (complete)
>
> **Success Metrics:**
> - Adoption rate among WordPress users
> - Average SEO score improvement
> - User satisfaction scores
> - Organic traffic increases (tracked case studies)

---

## Implementation Roadmap

### Phase 1: MVP (Weeks 1-2)

**Goal:** Basic analyze and optimize workflow

**Deliverables:**
1. `/wordpress-seo-optimizer analyze` command
   - Keyword analysis
   - On-page SEO audit (title, meta, headers)
   - Basic technical checks (mobile, HTTPS)
   - Schema detection

2. `/wordpress-seo-optimizer optimize` command
   - Update title and meta description
   - Optimize URL slug
   - Add basic Article schema
   - Update image alt text

3. WordPress authentication setup
   - App password documentation
   - Secure credential storage
   - Connection testing

4. Basic reporting
   - SEO score (0-100)
   - Prioritized issues list
   - Optimization recommendations

**Success Criteria:**
- Can analyze and optimize a WordPress post end-to-end
- Clear, actionable recommendations
- Safe optimization (nothing breaks)

---

### Phase 2: Advanced Features (Weeks 3-4)

**Goal:** Comprehensive SEO coverage

**Deliverables:**
1. `/wordpress-seo-optimizer keywords` command
   - Keyword research integration (DataForSEO API)
   - LSI keyword identification
   - Competitor keyword analysis
   - Keyword difficulty scoring

2. `/wordpress-seo-optimizer technical` command
   - Core Web Vitals analysis
   - Mobile optimization check
   - Sitemap validation
   - Robots.txt audit
   - Canonical tag verification

3. `/wordpress-seo-optimizer schema` command
   - Advanced schema types (FAQ, HowTo, LocalBusiness)
   - Schema validation
   - Dynamic schema generation based on content

4. Internal linking module
   - Related post detection
   - Anchor text optimization
   - Orphan page identification

**Success Criteria:**
- Full technical SEO audit capabilities
- Advanced schema generation
- Keyword research integration working

---

### Phase 3: GEO/AEO & Analytics (Weeks 5-6)

**Goal:** AI search optimization and performance tracking

**Deliverables:**
1. GEO (Generative Engine Optimization)
   - Quotability analysis
   - E-E-A-T scoring
   - Content structure optimization for AI parsing
   - Source attribution recommendations
   - Freshness indicators

2. AEO (Answer Engine Optimization)
   - Featured snippet optimization
   - FAQ schema generation
   - PAA (People Also Ask) targeting
   - Voice search optimization
   - Question-answer format suggestions

3. `/wordpress-seo-optimizer monitor` command
   - Google Search Console integration
   - Google Analytics 4 setup
   - Keyword ranking tracking
   - Core Web Vitals monitoring

4. `/wordpress-seo-optimizer report` command
   - Comprehensive SEO report generation
   - Keyword ranking trends
   - Traffic analysis
   - Conversion tracking

**Success Criteria:**
- GEO/AEO optimization functional
- Analytics integration working
- Comprehensive reporting available

---

### Phase 4: Scale & Polish (Weeks 7-8)

**Goal:** Enterprise features and refinement

**Deliverables:**
1. Bulk optimization
   - Batch analyze multiple posts
   - Bulk apply optimizations
   - Progress tracking
   - Rollback capability

2. Custom WordPress plugins
   - SEO Optimizer Pro plugin (advanced features)
   - Analytics Bridge plugin (unified analytics)
   - Installation and setup documentation

3. Advanced workflows
   - Content templates with SEO built-in
   - Automated SEO audits (scheduled)
   - Multi-site management

4. Documentation and examples
   - Comprehensive user guide
   - API documentation
   - Video tutorials
   - Use case examples

**Success Criteria:**
- Can manage SEO for dozens of posts efficiently
- Custom plugins stable and documented
- User documentation complete

---

## Technical Architecture

### Core Components

#### 1. WordPress API Client (Existing - `wordpress-publisher`)

```python
from wordpress_publisher import WordPressClient

wp = WordPressClient(
    base_url="https://site.com",
    username="user",
    app_password="xxxx xxxx xxxx"
)
```

**Extend with:**
- SEO plugin detection (Yoast, RankMath, AIOSEO)
- Schema retrieval and validation
- Core Web Vitals endpoint (requires custom plugin)

---

#### 2. Keyword Analyzer Module

**Purpose:** Keyword research, density analysis, LSI keyword identification

**Features:**
- Keyword extraction from content
- Density calculation (target: 1-2%)
- LSI keyword suggestions
- Competitor keyword analysis (via API)
- Keyword difficulty scoring

**APIs to Integrate:**
- **DataForSEO** (free tier available) - keyword volume and competition
- **OpenAI** - LSI keyword generation
- **Google Keyword Planner API** (optional - requires Google Ads)

**Example:**
```python
from modules.keyword_analyzer import KeywordAnalyzer

analyzer = KeywordAnalyzer()
result = analyzer.analyze_content(
    content="<p>Dog training tips...</p>",
    target_keyword="dog training tips"
)

print(result)
# {
#   "target_keyword": "dog training tips",
#   "density": 1.2,
#   "target_density": 1.5,
#   "lsi_keywords": ["puppy training", "obedience training", "dog behavior"],
#   "recommendations": [
#     "Increase keyword density to 1.5% (add 3 more mentions)",
#     "Include LSI keywords: 'puppy training', 'obedience training'"
#   ]
# }
```

---

#### 3. On-Page Optimizer Module

**Purpose:** Optimize title, meta, headers, content, images

**Features:**
- Title tag optimization (50-60 chars, keyword placement)
- Meta description generation (150-160 chars, compelling CTA)
- Header structure analysis (H1-H6 hierarchy)
- Image alt text optimization
- URL slug optimization
- Content readability scoring (Flesch-Kincaid)

**Example:**
```python
from modules.onpage_optimizer import OnPageOptimizer

optimizer = OnPageOptimizer(wp_client)
recommendations = optimizer.analyze(post_id=123)

# Apply optimizations
optimizer.optimize(
    post_id=123,
    updates={
        "title": "Dog Training Tips: 10 Proven Methods for New Owners",
        "meta_description": "Discover 10 effective dog training tips...",
        "seo_title": "Dog Training Tips | Complete Guide for Beginners",
        "optimize_images": True,
        "fix_headers": True
    }
)
```

---

#### 4. Technical SEO Auditor Module

**Purpose:** Technical SEO checks (mobile, speed, schema, etc.)

**Features:**
- Mobile-friendliness test
- Core Web Vitals analysis (via PageSpeed Insights API)
- HTTPS verification
- Canonical tag check
- Sitemap validation
- Robots.txt audit
- Structured data validation

**APIs:**
- **PageSpeed Insights API** - Core Web Vitals
- **Google Rich Results Test** - Schema validation
- **Google Mobile-Friendly Test** - Mobile check

**Example:**
```python
from modules.technical_auditor import TechnicalAuditor

auditor = TechnicalAuditor()
report = auditor.audit(url="https://site.com/post")

print(report)
# {
#   "mobile_friendly": True,
#   "https": True,
#   "core_web_vitals": {
#     "lcp": 2.8,  # Largest Contentful Paint (target: <2.5s)
#     "inp": 150,  # Interaction to Next Paint (target: <200ms)
#     "cls": 0.05  # Cumulative Layout Shift (target: <0.1)
#   },
#   "schema": {
#     "found": ["Article"],
#     "valid": True,
#     "missing": ["FAQPage", "BreadcrumbList"]
#   },
#   "issues": [
#     "LCP is 2.8s (target: <2.5s) - optimize images",
#     "Missing FAQPage schema for FAQ section"
#   ]
# }
```

---

#### 5. Schema Generator Module

**Purpose:** Generate and inject JSON-LD schema markup

**Features:**
- Schema type detection based on content
- Template-based schema generation
- Dynamic field population
- Multi-schema support
- Schema validation

**Supported Schemas:**
- Article, BlogPosting
- FAQPage
- HowTo
- LocalBusiness
- Product
- Review
- BreadcrumbList

**Example:**
```python
from modules.schema_generator import SchemaGenerator

generator = SchemaGenerator()
schema = generator.generate(
    schema_type="Article",
    data={
        "headline": "Dog Training Tips",
        "author": "John Smith",
        "date_published": "2026-02-11",
        "image": "https://site.com/image.jpg",
        "description": "Comprehensive guide to dog training"
    }
)

# Inject into WordPress post
generator.inject_schema(wp_client, post_id=123, schema=schema)
```

---

#### 6. GEO/AEO Optimizer Module

**Purpose:** Optimize for AI search engines and answer engines

**Features:**

**GEO (Generative Engine Optimization):**
- Quotability scoring (are statements clear and standalone?)
- E-E-A-T analysis (Experience, Expertise, Authority, Trust)
- Content structure recommendations
- Source attribution check
- Freshness indicators (last updated dates)

**AEO (Answer Engine Optimization):**
- Featured snippet targeting
- FAQ extraction and schema generation
- PAA (People Also Ask) analysis
- Voice search optimization
- Question-answer format conversion

**Example:**
```python
from modules.geo_aeo_optimizer import GEOAEOOptimizer

optimizer = GEOAEOOptimizer()
analysis = optimizer.analyze_geo_aeo(content="<p>Dog training...</p>")

print(analysis)
# {
#   "geo_score": 75,  # 0-100
#   "aeo_score": 68,
#   "quotability": {
#     "score": 70,
#     "issues": [
#       "Paragraph 3 lacks clear topic sentence",
#       "Add standalone definitions for technical terms"
#     ]
#   },
#   "eeat_score": 80,
#   "featured_snippet_opportunities": [
#     {
#       "question": "What is the best age to start dog training?",
#       "format": "paragraph",
#       "current_content": "You can start training as early as 8 weeks...",
#       "optimization": "Add clear answer in first 50 words"
#     }
#   ],
#   "recommendations": [
#     "Add author bio with credentials (E-E-A-T)",
#     "Include 'Last updated: [date]' at top",
#     "Convert section 4 to FAQ schema",
#     "Add question-format H2 headings for voice search"
#   ]
# }
```

---

#### 7. Analytics Connector Module

**Purpose:** Integrate with Google Search Console, Google Analytics 4, keyword tracking

**Features:**
- GSC API integration (search queries, clicks, impressions)
- GA4 data retrieval (traffic, conversions)
- Keyword ranking tracking (via DataForSEO or custom)
- Core Web Vitals monitoring
- Automated reporting

**APIs:**
- **Google Search Console API**
- **Google Analytics 4 API**
- **DataForSEO** - Keyword rankings

**Example:**
```python
from modules.analytics_connector import AnalyticsConnector

analytics = AnalyticsConnector(
    gsc_credentials="gsc_credentials.json",
    ga4_property_id="123456789"
)

# Get Search Console data
gsc_data = analytics.get_gsc_performance(
    url="https://site.com/post",
    date_range="last_30_days"
)

print(gsc_data)
# {
#   "clicks": 1250,
#   "impressions": 15000,
#   "ctr": 8.3,
#   "average_position": 5.2,
#   "top_queries": [
#     {"query": "dog training tips", "clicks": 450, "position": 3.1},
#     {"query": "puppy training", "clicks": 220, "position": 7.5}
#   ]
# }
```

---

### Custom WordPress Plugins

#### Plugin 1: SEO Optimizer Pro

**Purpose:** Expose additional SEO data and functionality via REST API

**Features:**
1. **Keyword Tracking Endpoint**
   - Store target keywords per post
   - Track keyword rankings over time
   - REST API: `/wp-json/seo-optimizer/v1/keywords/{post_id}`

2. **Internal Link Analysis Endpoint**
   - Analyze internal links sitewide
   - Find link opportunities
   - REST API: `/wp-json/seo-optimizer/v1/internal-links`

3. **Schema Validation Endpoint**
   - Validate schema markup
   - Test with Google Rich Results Test
   - REST API: `/wp-json/seo-optimizer/v1/schema/validate/{post_id}`

4. **Core Web Vitals Tracking**
   - Store CWV data per page
   - Historical tracking
   - REST API: `/wp-json/seo-optimizer/v1/cwv/{post_id}`

**Installation:**
```bash
# Download plugin
curl -O https://github.com/yourusername/seo-optimizer-pro/releases/latest/seo-optimizer-pro.zip

# Upload via WordPress admin
# Plugins → Add New → Upload Plugin → Activate
```

**REST API Usage:**
```python
# Store target keyword
wp.post("/wp-json/seo-optimizer/v1/keywords/123", json={
    "target_keyword": "dog training tips",
    "lsi_keywords": ["puppy training", "obedience training"]
})

# Get internal link analysis
links = wp.get("/wp-json/seo-optimizer/v1/internal-links")
print(links)
# {
#   "total_posts": 150,
#   "avg_internal_links": 3.2,
#   "orphan_pages": [123, 456],  # Post IDs with no internal links
#   "opportunities": [
#     {
#       "from_post": 100,
#       "to_post": 123,
#       "relevance_score": 0.85,
#       "suggested_anchor": "dog training tips"
#     }
#   ]
# }
```

---

#### Plugin 2: Analytics Bridge

**Purpose:** Unified analytics interface for GSC and GA4 data

**Features:**
1. **Google Search Console Connector**
   - Authenticate with GSC
   - Retrieve search analytics per post
   - REST API: `/wp-json/analytics-bridge/v1/gsc/{post_id}`

2. **Google Analytics 4 Connector**
   - Authenticate with GA4
   - Retrieve traffic data per post
   - REST API: `/wp-json/analytics-bridge/v1/ga4/{post_id}`

3. **Combined Dashboard Data**
   - Unified metrics (traffic, rankings, conversions)
   - REST API: `/wp-json/analytics-bridge/v1/dashboard/{post_id}`

**Configuration:**
```php
// In WordPress admin: Settings → Analytics Bridge
// Enter GSC and GA4 credentials (OAuth or service account)
// Configure property IDs and tracking preferences
```

---

### Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  User: /wordpress-seo-optimizer analyze URL                 │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Skill Entry Point                                           │
│  - Parse command (analyze, optimize, keywords, etc.)         │
│  - Authenticate with WordPress REST API                      │
│  - Route to appropriate module                               │
└────────────────────┬────────────────────────────────────────┘
                     │
        ┌────────────┼────────────┬────────────┐
        ▼            ▼            ▼            ▼
   ┌────────┐  ┌─────────┐  ┌─────────┐  ┌──────────┐
   │Keyword │  │ On-Page │  │Technical│  │  Schema  │
   │Analyzer│  │Optimizer│  │ Auditor │  │Generator │
   └───┬────┘  └────┬────┘  └────┬────┘  └─────┬────┘
       │            │             │             │
       └────────────┼─────────────┼─────────────┘
                    ▼
        ┌───────────────────────────┐
        │  WordPress REST API        │
        │  - Fetch post content      │
        │  - Update meta fields      │
        │  - Inject schema           │
        └───────────┬───────────────┘
                    │
                    ▼
        ┌───────────────────────────┐
        │  WordPress Site            │
        │  - Posts/Pages             │
        │  - Media Library           │
        │  - SEO Plugins (Yoast/RM)  │
        │  - Custom Plugins          │
        └───────────┬───────────────┘
                    │
                    ▼
        ┌───────────────────────────┐
        │  External APIs             │
        │  - PageSpeed Insights      │
        │  - DataForSEO (keywords)   │
        │  - Google Search Console   │
        │  - Google Analytics 4      │
        └───────────────────────────┘
```

---

## Testing Strategy

### Unit Tests

**Components to Test:**
1. Keyword Analyzer
   - Keyword extraction accuracy
   - Density calculation
   - LSI keyword generation

2. On-Page Optimizer
   - Title tag generation
   - Meta description generation
   - Readability scoring

3. Technical Auditor
   - Core Web Vitals parsing
   - Schema validation
   - Mobile-friendliness detection

4. Schema Generator
   - Schema template rendering
   - JSON-LD validation
   - Dynamic field population

**Example Test:**
```python
# tests/test_keyword_analyzer.py
import pytest
from modules.keyword_analyzer import KeywordAnalyzer

def test_keyword_density_calculation():
    analyzer = KeywordAnalyzer()
    content = "Dog training tips are essential. These dog training methods work."
    result = analyzer.calculate_density(content, "dog training")
    assert result["density"] == pytest.approx(2.0, rel=0.1)  # ~2%
```

---

### Integration Tests

**Scenarios:**
1. WordPress REST API connectivity
2. SEO plugin detection (Yoast, RankMath)
3. Schema injection and retrieval
4. Analytics API integration

**Example Test:**
```python
# tests/test_wordpress_integration.py
import pytest
from wordpress_publisher import WordPressClient
from modules.onpage_optimizer import OnPageOptimizer

@pytest.fixture
def wp_client():
    return WordPressClient(
        base_url="https://test-site.com",
        username="test_user",
        app_password="test_password"
    )

def test_optimize_title_tag(wp_client):
    optimizer = OnPageOptimizer(wp_client)

    # Create test post
    post = wp_client.create_post({
        "title": "Bad Title",
        "content": "<p>Dog training content...</p>",
        "status": "draft"
    })

    # Optimize
    optimizer.optimize(post["id"], {
        "title": "Dog Training Tips: 10 Proven Methods"
    })

    # Verify
    updated_post = wp_client.get_post(post["id"])
    assert updated_post["title"]["rendered"] == "Dog Training Tips: 10 Proven Methods"

    # Cleanup
    wp_client.delete_post(post["id"], force=True)
```

---

### End-to-End Tests

**Workflow Tests:**
1. Complete analyze → optimize workflow
2. Keyword research → content optimization
3. Technical audit → fixes applied
4. Analytics setup → data retrieval

**Example Test:**
```python
# tests/test_e2e_workflow.py
def test_complete_optimization_workflow(wp_client):
    # 1. Create a post with SEO issues
    post = wp_client.create_post({
        "title": "test",  # Too short
        "content": "<p>Short content</p>",  # No keywords
        "status": "draft"
    })

    # 2. Run analysis
    from modules.onpage_optimizer import OnPageOptimizer
    optimizer = OnPageOptimizer(wp_client)
    analysis = optimizer.analyze(post["id"])

    assert len(analysis["issues"]) > 0
    assert "Title too short" in str(analysis["issues"])

    # 3. Apply optimizations
    optimizer.optimize(post["id"], {
        "title": "Dog Training Tips: Complete Guide for New Owners",
        "meta_description": "Learn effective dog training methods...",
        "optimize_content": True
    })

    # 4. Verify improvements
    final_analysis = optimizer.analyze(post["id"])
    assert len(final_analysis["issues"]) < len(analysis["issues"])

    # Cleanup
    wp_client.delete_post(post["id"], force=True)
```

---

## Documentation Plan

### User Documentation

#### 1. Getting Started Guide
- WordPress requirements
- Creating Application Password
- First analysis command
- Understanding the report
- Applying optimizations

#### 2. Command Reference
- `/wordpress-seo-optimizer analyze` - Full command options
- `/wordpress-seo-optimizer optimize` - Optimization types
- `/wordpress-seo-optimizer keywords` - Keyword research
- `/wordpress-seo-optimizer technical` - Technical audits
- `/wordpress-seo-optimizer schema` - Schema management
- `/wordpress-seo-optimizer monitor` - Analytics setup
- `/wordpress-seo-optimizer report` - Reporting options

#### 3. SEO Best Practices Guide
- On-page SEO fundamentals
- Technical SEO checklist
- GEO/AEO strategies
- Schema markup guide
- Internal linking strategy

#### 4. Use Cases & Examples
- Optimizing a blog post
- Technical SEO audit
- Bulk optimization workflow
- Multi-site management
- Analytics tracking setup

#### 5. Troubleshooting
- Common errors and solutions
- Plugin compatibility issues
- API authentication problems
- Performance optimization

---

### Developer Documentation

#### 1. Architecture Overview
- Component diagram
- Data flow
- Module responsibilities
- Extension points

#### 2. Module API Reference
- KeywordAnalyzer
- OnPageOptimizer
- TechnicalAuditor
- SchemaGenerator
- GEOAEOOptimizer
- AnalyticsConnector

#### 3. WordPress Plugin Development
- SEO Optimizer Pro plugin guide
- Analytics Bridge plugin guide
- Custom REST endpoints
- Security considerations

#### 4. Testing Guide
- Unit test examples
- Integration test setup
- E2E test scenarios
- CI/CD pipeline

#### 5. Contributing Guide
- Code style
- Pull request process
- Issue reporting
- Feature requests

---

## Success Metrics

### User Adoption
- Number of active users
- Posts optimized per user
- Retention rate (30-day, 90-day)

### SEO Performance
- Average SEO score improvement (before/after)
- % of posts with schema markup (before/after)
- Average keyword density improvement
- Core Web Vitals improvements

### Business Impact
- Organic traffic increase (user-reported case studies)
- Search ranking improvements
- Featured snippet acquisitions
- AI search engine citations (Perplexity, ChatGPT)

### User Satisfaction
- Net Promoter Score (NPS)
- User feedback scores
- Support ticket volume
- Feature request themes

### Technical Health
- API success rate (REST API calls)
- Error rate
- Average execution time
- Plugin compatibility rate

---

## Risk Mitigation Plan

### Risk 1: SEO Plugin API Limitations
**Mitigation:**
- Support multiple plugins (Yoast, RankMath, AIOSEO)
- Create custom plugin for advanced features
- Document fallback strategies

### Risk 2: WordPress Version Incompatibility
**Mitigation:**
- Require WordPress 5.6+ (app passwords)
- Test against LTS versions
- Monitor WordPress release cycle
- Graceful degradation for older versions

### Risk 3: Rate Limiting
**Mitigation:**
- Implement respectful rate limiting
- Configurable delays between requests
- Batch operations with progress tracking
- Retry logic with exponential backoff

### Risk 4: User Over-Optimization
**Mitigation:**
- Built-in guardrails (keyword density limits)
- Readability warnings
- "Natural language first" messaging
- Educational content on SEO best practices

### Risk 5: Maintenance Burden
**Mitigation:**
- Modular architecture (update components independently)
- Comprehensive test coverage
- Clear documentation
- Community contributions encouraged

---

## Commitment

### Disagree & Commit Statement

All stakeholders commit to the pipeline-based approach for the WordPress SEO optimizer skill. While alternative architectures were considered, we agree that the command-driven, modular design offers the best balance of user experience, maintainability, and extensibility.

**Commitments:**

**CTO:**
- Commits to modular architecture with clear interfaces
- Will prioritize maintainability and testing
- Ensures WordPress REST API best practices

**CPO:**
- Commits to intuitive command structure
- Will gather user feedback after MVP
- Ensures clear, actionable recommendations in reports

**CRO:**
- Commits to comprehensive SEO/GEO/AEO coverage
- Will measure and report on business impact
- Ensures competitive differentiation messaging

**COO:**
- Commits to phased rollout with clear milestones
- Will monitor operational metrics (errors, performance)
- Ensures documentation quality and completeness

---

## Next Steps

### Immediate Actions (This Week)

1. **Create Skill Directory Structure**
   - Initialize `/wordpress-seo-optimizer/` skill directory
   - Set up module structure
   - Create README.md and skill.json

2. **Extend WordPress Publisher Module**
   - Add SEO plugin detection
   - Add schema retrieval methods
   - Test with Yoast and RankMath

3. **Build Keyword Analyzer MVP**
   - Keyword extraction
   - Density calculation
   - Basic LSI suggestions (using OpenAI)

4. **Create Analyze Command**
   - Command parsing
   - WordPress API integration
   - Basic SEO audit (title, meta, keywords)
   - Report generation

### Week 2 Actions

5. **Build On-Page Optimizer**
   - Title tag optimization
   - Meta description generation
   - Image alt text optimization
   - Update via REST API

6. **Create Optimize Command**
   - Apply optimizations
   - Confirmation workflow
   - Success reporting

7. **Testing & Documentation**
   - Unit tests for keyword analyzer
   - Integration tests with WordPress
   - Getting started guide
   - Command reference

### Week 3+ (See Phase 2-4 Roadmap Above)

---

## Appendix: WordPress REST API Endpoints

### Key Endpoints for SEO Optimization

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/wp/v2/posts` | GET | List posts |
| `/wp/v2/posts/{id}` | GET | Get post details |
| `/wp/v2/posts/{id}` | POST | Update post |
| `/wp/v2/media` | POST | Upload media |
| `/wp/v2/media/{id}` | GET | Get media details |
| `/wp/v2/categories` | GET/POST | Manage categories |
| `/wp/v2/tags` | GET/POST | Manage tags |
| `/wp/v2/users/me` | GET | Get authenticated user |

### Custom Meta Fields (SEO Plugins)

**Yoast SEO:**
```json
{
  "meta": {
    "_yoast_wpseo_title": "SEO Title Here",
    "_yoast_wpseo_metadesc": "Meta description here",
    "_yoast_wpseo_focuskw": "focus keyword"
  }
}
```

**RankMath:**
```json
{
  "meta": {
    "rank_math_title": "SEO Title Here",
    "rank_math_description": "Meta description here",
    "rank_math_focus_keyword": "focus,keywords,here"
  }
}
```

---

## Appendix: SEO Scoring Algorithm

### SEO Score Calculation (0-100)

**Components:**

| Component | Weight | Criteria |
|-----------|--------|----------|
| **Title Tag** | 15% | Length (50-60), keyword presence, compelling |
| **Meta Description** | 10% | Length (150-160), keyword, CTA |
| **Headers** | 10% | H1 present, H2/H3 hierarchy, keywords |
| **Content Quality** | 20% | Length (>1000 words), readability, keyword density |
| **Images** | 10% | Alt text present, optimized size, WebP format |
| **Technical** | 15% | Mobile-friendly, HTTPS, Core Web Vitals |
| **Schema** | 10% | Present, valid, appropriate type |
| **Internal Links** | 5% | 3+ internal links, descriptive anchors |
| **GEO/AEO** | 5% | Quotability, E-E-A-T, FAQ schema |

**Example Calculation:**
```python
def calculate_seo_score(post_data):
    score = 0

    # Title Tag (15 points)
    if 50 <= len(post_data["title"]) <= 60:
        score += 10
    if post_data["target_keyword"] in post_data["title"].lower():
        score += 5

    # Meta Description (10 points)
    if 150 <= len(post_data["meta_description"]) <= 160:
        score += 7
    if post_data["target_keyword"] in post_data["meta_description"].lower():
        score += 3

    # Headers (10 points)
    if post_data["has_h1"]:
        score += 5
    if post_data["header_hierarchy_valid"]:
        score += 5

    # Content Quality (20 points)
    if post_data["word_count"] >= 1000:
        score += 10
    if 1.0 <= post_data["keyword_density"] <= 2.0:
        score += 5
    if post_data["readability_score"] >= 60:  # Flesch-Kincaid
        score += 5

    # Images (10 points)
    if post_data["images_with_alt"] / post_data["total_images"] >= 0.9:
        score += 10

    # Technical (15 points)
    if post_data["mobile_friendly"]:
        score += 5
    if post_data["https"]:
        score += 5
    if post_data["cwv_passed"]:  # Core Web Vitals
        score += 5

    # Schema (10 points)
    if post_data["has_schema"]:
        score += 5
    if post_data["schema_valid"]:
        score += 5

    # Internal Links (5 points)
    if post_data["internal_links"] >= 3:
        score += 5

    # GEO/AEO (5 points)
    if post_data["geo_aeo_score"] >= 70:
        score += 5

    return score
```

---

## Conclusion

This strategic plan outlines a comprehensive approach to building a WordPress SEO/AEO/GEO optimization skill using a pipeline-based architecture. The decision has been made through systematic analysis using the 3D Decision Matrix (C-Suite perspectives + Six Thinking Hats + SPADE framework).

**Key Takeaways:**
- ✅ **Decision:** Pipeline-based approach (Option 3)
- ✅ **Architecture:** Modular components with unified entry point
- ✅ **Timeline:** 8 weeks (MVP in 2 weeks)
- ✅ **Differentiation:** First comprehensive GEO/AEO tool for WordPress
- ✅ **Foundation:** Builds on existing `wordpress-publisher` module
- ✅ **Risk Management:** Mitigation strategies in place
- ✅ **Success Metrics:** Clear measurement framework

**All stakeholders commit to this plan and will execute with full support.**

---

*Strategic Plan created: 2026-02-11*
*Decision Type: HIGH-STAKES*
*Framework: 3D Decision Matrix (SPADE + Six Thinking Hats + C-Suite Perspectives)*
