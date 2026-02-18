# CBT Journaling Module (Universal)

**Purpose:** Traditional Cognitive Behavioral Therapy journaling and thought record system for psychology practice apps

**Type:** Reusable module for mental health/therapy applications

**Compliance:** Includes HIPAA/privacy considerations for clinical use

---

## What This Module Provides

### Core CBT Features

1. **Thought Records** - Classic 7-column CBT thought records
2. **Mood Tracking** - Emotion logging with intensity ratings
3. **Cognitive Distortion Detection** - Identify thinking patterns
4. **Behavioral Activation** - Activity scheduling and monitoring
5. **CBT Homework** - Therapist-assigned exercises
6. **Progress Tracking** - Mood trends and insights over time

### Components Included

- Database schemas (Supabase/PostgreSQL)
- API route templates (Next.js/Express adaptable)
- UI component specifications
- CBT prompt templates
- Privacy/security guidelines
- Implementation guide

---

## Use Cases

- Therapy practice management apps
- Mental health journaling apps
- CBT self-help applications
- Patient homework portals
- Telehealth platforms

---

## Key Files

```
journaling-cbt-universal/
├── README.md                           # This file
├── docs/
│   ├── cbt-framework.md               # CBT concepts and methodology
│   ├── privacy-compliance.md          # HIPAA/privacy guidelines
│   └── implementation-guide.md        # How to integrate
├── schemas/
│   ├── thought-records.sql            # Thought record tables
│   ├── mood-tracking.sql              # Mood/emotion tracking
│   └── homework-assignments.sql       # CBT homework system
└── templates/
    ├── api-thought-records.ts         # Thought record CRUD API
    ├── api-mood-tracking.ts           # Mood logging API
    ├── component-thought-record.md    # UI specs for thought record form
    └── prompts-cbt.md                 # Guided prompts for users
```

---

## Quick Start

1. **Read** `docs/cbt-framework.md` to understand the methodology
2. **Review** database schemas in `schemas/`
3. **Adapt** API templates from `templates/` to your framework
4. **Implement** UI components using `component-*.md` specs
5. **Review** `privacy-compliance.md` for healthcare regulations

---

## License

Free to use for clinical and commercial applications.
No attribution required for clinical use.

---

*Version: 1.0*
*Created: 2026-01-19*
