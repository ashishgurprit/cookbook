# Client Project Scaffolding

> Production-grade project scaffolding for client engagements. Covers framework selection, directory structure, tooling, CI/CD, and multi-environment configuration. Auto-discovered when project initialization, scaffolding, or new client setup is detected.

**Version**: 1.0.0
**Last Updated**: 2026-02-16
**Applies To**: All new client projects

---

## Table of Contents

1. [Overview](#1-overview)
2. [Project Type Decision Matrix](#2-project-type-decision-matrix)
3. [Next.js Scaffolding (Web Apps & Marketing Sites)](#3-nextjs-scaffolding)
4. [Expo / React Native Scaffolding (Mobile Apps)](#4-expo--react-native-scaffolding)
5. [Python / FastAPI Scaffolding (Backend APIs)](#5-python--fastapi-scaffolding)
6. [Astro Scaffolding (Static & Blog Sites)](#6-astro-scaffolding)
7. [Monorepo with Turborepo (Full-Stack)](#7-monorepo-with-turborepo)
8. [Shared Tooling Configuration](#8-shared-tooling-configuration)
9. [Client-Specific Customization](#9-client-specific-customization)
10. [Integrates With](#10-integrates-with)

---

## 1. Overview

Every client project begins with the same question: **What is the right stack?** This skill provides a repeatable, production-grade scaffolding process so that every new project starts with:

- Correct framework for the use case
- Consistent directory structure across the team
- Pre-configured linting, formatting, and type checking
- Git hooks enforcing quality gates before commits
- CI/CD pipeline ready from day one
- Environment variable management that prevents secrets from leaking
- Multi-environment support (development, staging, production)
- Client branding and analytics wired in from the start

**Default package manager**: pnpm (see `pnpm-migration` skill for rationale and setup).

**Principle**: Spend 30 minutes scaffolding correctly to save 30 hours of rework later.

---

## 2. Project Type Decision Matrix

Use this matrix to select the right project type for the client's requirements.

### Quick Decision Table

| Requirement | Next.js | Expo/RN | FastAPI | Astro | Monorepo |
|---|---|---|---|---|---|
| Web application with auth | **Best** | -- | Backend only | -- | Full-stack |
| Marketing / landing site | Good | -- | -- | **Best** | -- |
| E-commerce storefront | **Best** | -- | Backend only | -- | Full-stack |
| iOS + Android mobile app | -- | **Best** | Backend only | -- | Full-stack |
| REST/GraphQL API only | -- | -- | **Best** | -- | -- |
| Blog / documentation | Good | -- | -- | **Best** | -- |
| SaaS with web + mobile | -- | -- | -- | -- | **Best** |
| Dashboard / admin panel | **Best** | -- | -- | -- | Full-stack |
| Static portfolio | -- | -- | -- | **Best** | -- |
| Microservices backend | -- | -- | **Best** | -- | Monorepo |

### Decision Flowchart

```
Start
  |
  +-- Does the client need a mobile app (iOS/Android)?
  |     |
  |     +-- YES --> Does the client ALSO need a web app?
  |     |             |
  |     |             +-- YES --> Monorepo (Turborepo)
  |     |             |             apps/web (Next.js)
  |     |             |             apps/mobile (Expo)
  |     |             |             packages/shared (shared code)
  |     |             |
  |     |             +-- NO --> Expo / React Native (standalone)
  |     |
  |     +-- NO --> Is there heavy dynamic content / auth / SSR?
  |                   |
  |                   +-- YES --> Next.js
  |                   |
  |                   +-- NO --> Is it primarily a blog or static content?
  |                                 |
  |                                 +-- YES --> Astro
  |                                 |
  |                                 +-- NO --> Is it a backend API only?
  |                                               |
  |                                               +-- YES --> Python / FastAPI
  |                                               |
  |                                               +-- NO --> Next.js (default)
```

### Detailed Selection Criteria

**Choose Next.js when**:
- Building a web application with server-side rendering or static generation
- Need React ecosystem (largest component library pool)
- Client wants Vercel deployment (zero-config)
- Dashboard, SaaS, or e-commerce front-end
- SEO matters but content is also dynamic
- Need API routes alongside the frontend

**Choose Expo / React Native when**:
- Primary deliverable is a mobile app on iOS and/or Android
- Client wants presence in the App Store / Google Play
- Need native device features (camera, push notifications, biometrics)
- Cross-platform code sharing is a priority
- Over-the-air updates are valuable (EAS Update)

**Choose Python / FastAPI when**:
- Building a standalone API (REST or GraphQL)
- Heavy data processing, ML, or AI integrations
- Background job processing with Celery or similar
- The frontend is built separately or by another team
- Need WebSocket support alongside HTTP

**Choose Astro when**:
- Content-first site (blog, documentation, portfolio)
- Performance is paramount (zero JS by default)
- Multi-framework support needed (React + Vue components on one page)
- Client has a small team and needs simplicity
- SEO-critical marketing pages

**Choose Monorepo (Turborepo) when**:
- Project has 2+ applications (web + mobile, web + API, etc.)
- Shared code between apps (types, utilities, UI components)
- Single CI/CD pipeline for the entire product
- Team larger than 3 developers
- Need shared design system across apps

---

## 3. Next.js Scaffolding

### 3.1 Initialize Project

```bash
# Create with pnpm (default package manager)
pnpm create next-app@latest client-project-name \
  --typescript \
  --tailwind \
  --eslint \
  --app \
  --src-dir \
  --import-alias "@/*"

cd client-project-name
```

### 3.2 Directory Structure

```
client-project-name/
├── .github/
│   └── workflows/
│       ├── ci.yml                  # Lint + test + typecheck
│       └── deploy.yml              # Build + deploy
├── .husky/
│   ├── pre-commit                  # lint-staged
│   └── commit-msg                  # commitlint
├── public/
│   ├── fonts/                      # Self-hosted fonts
│   ├── images/                     # Static images
│   └── favicon.ico
├── src/
│   ├── app/                        # Next.js App Router
│   │   ├── (auth)/                 # Route group: auth pages
│   │   │   ├── login/page.tsx
│   │   │   └── register/page.tsx
│   │   ├── (dashboard)/            # Route group: authenticated
│   │   │   ├── layout.tsx
│   │   │   └── page.tsx
│   │   ├── api/                    # API routes
│   │   │   └── health/route.ts
│   │   ├── layout.tsx              # Root layout
│   │   ├── page.tsx                # Home page
│   │   ├── loading.tsx             # Global loading
│   │   ├── error.tsx               # Global error boundary
│   │   ├── not-found.tsx           # 404 page
│   │   └── globals.css
│   ├── components/
│   │   ├── ui/                     # Reusable UI primitives
│   │   │   ├── Button.tsx
│   │   │   ├── Input.tsx
│   │   │   └── index.ts
│   │   ├── layout/                 # Layout components
│   │   │   ├── Header.tsx
│   │   │   ├── Footer.tsx
│   │   │   └── Sidebar.tsx
│   │   └── features/               # Feature-specific components
│   │       └── auth/
│   │           └── LoginForm.tsx
│   ├── hooks/                      # Custom React hooks
│   │   ├── useAuth.ts
│   │   └── useMediaQuery.ts
│   ├── lib/                        # Utilities and clients
│   │   ├── api.ts                  # API client (fetch wrapper)
│   │   ├── utils.ts                # General utilities
│   │   ├── constants.ts            # App-wide constants
│   │   └── validations.ts          # Zod schemas
│   ├── services/                   # Business logic / data layer
│   │   ├── auth.service.ts
│   │   └── user.service.ts
│   ├── stores/                     # State management (Zustand)
│   │   └── auth.store.ts
│   ├── types/                      # TypeScript types
│   │   ├── api.ts
│   │   └── index.ts
│   └── config/                     # App configuration
│       ├── brand.ts                # Client brand config
│       ├── env.ts                  # Typed env vars
│       └── site.ts                 # Site metadata
├── tests/
│   ├── __mocks__/                  # Jest mocks
│   ├── setup.ts                    # Test setup
│   └── utils.tsx                   # Test utilities (render helpers)
├── .env.example                    # Environment template
├── .env.local                      # Local overrides (git-ignored)
├── .eslintrc.json
├── .prettierrc
├── .gitignore
├── commitlint.config.js
├── jest.config.ts
├── lint-staged.config.js
├── next.config.ts
├── package.json
├── pnpm-lock.yaml
├── postcss.config.js
├── tailwind.config.ts
└── tsconfig.json
```

### 3.3 Typed Environment Variables

```typescript
// src/config/env.ts
import { z } from 'zod';

const envSchema = z.object({
  // Server-side only
  DATABASE_URL: z.string().url(),
  AUTH_SECRET: z.string().min(32),
  STRIPE_SECRET_KEY: z.string().startsWith('sk_'),

  // Client-side (NEXT_PUBLIC_ prefix)
  NEXT_PUBLIC_APP_URL: z.string().url(),
  NEXT_PUBLIC_SUPABASE_URL: z.string().url().optional(),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().optional(),
  NEXT_PUBLIC_ANALYTICS_ID: z.string().optional(),
});

// Validate at build time
const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.flatten().fieldErrors);
  throw new Error('Invalid environment variables');
}

export const env = parsed.data;
```

### 3.4 .env.example

```bash
# .env.example — Copy to .env.local and fill in values
# NEVER commit actual secrets. This file is safe to commit.

# Application
NEXT_PUBLIC_APP_URL=http://localhost:3000
NODE_ENV=development

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Authentication
AUTH_SECRET=generate-a-32-char-secret-here

# Payments (Stripe)
STRIPE_SECRET_KEY=sk_test_...
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_...

# Supabase (if applicable)
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key

# Analytics
NEXT_PUBLIC_ANALYTICS_ID=G-XXXXXXXXXX

# Error Monitoring
SENTRY_DSN=https://key@sentry.io/project-id
SENTRY_AUTH_TOKEN=sntrys_...
```

### 3.5 Next.js CI/CD (GitHub Actions)

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'

      - run: pnpm install --frozen-lockfile

      - name: Lint
        run: pnpm lint

      - name: Type Check
        run: pnpm tsc --noEmit

      - name: Unit Tests
        run: pnpm test -- --coverage

      - name: Build
        run: pnpm build
        env:
          NEXT_PUBLIC_APP_URL: https://staging.example.com
```

---

## 4. Expo / React Native Scaffolding

### 4.1 Initialize Project

```bash
# Create Expo project with TypeScript
pnpm create expo-app client-mobile-app --template tabs

cd client-mobile-app

# Install EAS CLI globally (for builds and submissions)
pnpm add -g eas-cli

# Initialize EAS
eas init
eas build:configure
```

### 4.2 Directory Structure

```
client-mobile-app/
├── .github/
│   └── workflows/
│       ├── ci.yml                  # Lint + test + typecheck
│       └── eas-build.yml           # EAS Build trigger
├── .husky/
│   ├── pre-commit
│   └── commit-msg
├── app/                            # Expo Router (file-based routing)
│   ├── (tabs)/                     # Tab navigation group
│   │   ├── _layout.tsx
│   │   ├── index.tsx               # Home tab
│   │   ├── explore.tsx             # Explore tab
│   │   └── profile.tsx             # Profile tab
│   ├── (auth)/                     # Auth flow group
│   │   ├── _layout.tsx
│   │   ├── login.tsx
│   │   └── register.tsx
│   ├── _layout.tsx                 # Root layout (providers)
│   ├── +not-found.tsx              # 404 screen
│   └── modal.tsx                   # Modal route
├── assets/
│   ├── fonts/
│   ├── images/
│   └── animations/                 # Lottie files
├── components/
│   ├── ui/                         # Reusable UI primitives
│   │   ├── Button.tsx
│   │   ├── Text.tsx
│   │   └── index.ts
│   ├── layout/                     # Layout wrappers
│   │   └── SafeAreaWrapper.tsx
│   └── features/                   # Feature-specific
│       └── auth/
│           └── LoginForm.tsx
├── hooks/                          # Custom hooks
│   ├── useAuth.ts
│   ├── useColorScheme.ts
│   └── useThemeColor.ts
├── lib/                            # Utilities
│   ├── api.ts                      # API client
│   ├── storage.ts                  # AsyncStorage wrapper
│   ├── constants.ts
│   └── validations.ts
├── services/                       # Business logic
│   ├── auth.service.ts
│   └── notification.service.ts
├── stores/                         # State (Zustand)
│   ├── auth.store.ts
│   └── app.store.ts
├── types/                          # TypeScript types
│   └── index.ts
├── config/
│   ├── brand.ts                    # Client branding
│   ├── env.ts                      # Typed env vars
│   └── theme.ts                    # Design tokens
├── __tests__/
│   └── setup.ts
├── .env.example
├── .eslintrc.js
├── .prettierrc
├── app.json                        # Expo config
├── eas.json                        # EAS Build config
├── babel.config.js
├── metro.config.js
├── package.json
├── pnpm-lock.yaml
└── tsconfig.json
```

### 4.3 EAS Build Configuration

```json
// eas.json
{
  "cli": {
    "version": ">= 12.0.0",
    "appVersionSource": "remote"
  },
  "build": {
    "development": {
      "developmentClient": true,
      "distribution": "internal",
      "ios": {
        "simulator": true
      },
      "env": {
        "APP_ENV": "development",
        "API_URL": "http://localhost:3000/api"
      }
    },
    "preview": {
      "distribution": "internal",
      "autoIncrement": true,
      "env": {
        "APP_ENV": "staging",
        "API_URL": "https://staging-api.example.com"
      }
    },
    "production": {
      "autoIncrement": true,
      "env": {
        "APP_ENV": "production",
        "API_URL": "https://api.example.com"
      }
    }
  },
  "submit": {
    "production": {
      "ios": {
        "appleId": "client@example.com",
        "ascAppId": "1234567890",
        "appleTeamId": "XXXXXXXXXX"
      },
      "android": {
        "serviceAccountKeyPath": "./google-service-account.json",
        "track": "internal"
      }
    }
  }
}
```

### 4.4 Expo CI/CD (GitHub Actions with EAS)

```yaml
# .github/workflows/eas-build.yml
name: EAS Build

on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      platform:
        description: 'Platform to build'
        required: true
        default: 'all'
        type: choice
        options: [ios, android, all]
      profile:
        description: 'Build profile'
        required: true
        default: 'preview'
        type: choice
        options: [development, preview, production]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'

      - run: pnpm install --frozen-lockfile

      - uses: expo/expo-github-action@v8
        with:
          eas-version: latest
          token: ${{ secrets.EXPO_TOKEN }}

      - name: Build
        run: |
          PLATFORM=${{ inputs.platform || 'all' }}
          PROFILE=${{ inputs.profile || 'preview' }}
          eas build --platform $PLATFORM --profile $PROFILE --non-interactive
```

### 4.5 Expo Environment Variables

```typescript
// config/env.ts
import Constants from 'expo-constants';
import { z } from 'zod';

const envSchema = z.object({
  APP_ENV: z.enum(['development', 'staging', 'production']).default('development'),
  API_URL: z.string().url(),
  SENTRY_DSN: z.string().optional(),
  ANALYTICS_KEY: z.string().optional(),
});

const rawEnv = {
  APP_ENV: Constants.expoConfig?.extra?.APP_ENV ?? process.env.APP_ENV,
  API_URL: Constants.expoConfig?.extra?.API_URL ?? process.env.API_URL,
  SENTRY_DSN: Constants.expoConfig?.extra?.SENTRY_DSN ?? process.env.SENTRY_DSN,
  ANALYTICS_KEY: Constants.expoConfig?.extra?.ANALYTICS_KEY ?? process.env.ANALYTICS_KEY,
};

const parsed = envSchema.safeParse(rawEnv);

if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.flatten().fieldErrors);
  throw new Error('Invalid environment variables. Check config/env.ts');
}

export const env = parsed.data;
```

---

## 5. Python / FastAPI Scaffolding

### 5.1 Initialize Project

```bash
# Create project directory
mkdir client-api && cd client-api

# Initialize Python project with uv (modern package manager)
uv init --python 3.12
uv add fastapi uvicorn[standard] pydantic pydantic-settings sqlalchemy alembic
uv add --dev pytest pytest-asyncio httpx ruff mypy

# Or with pip + venv
python3.12 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn[standard] pydantic pydantic-settings sqlalchemy alembic
pip install -D pytest pytest-asyncio httpx ruff mypy
```

### 5.2 Directory Structure

```
client-api/
├── .github/
│   └── workflows/
│       ├── ci.yml                  # Lint + test + typecheck
│       └── deploy.yml              # Build + deploy
├── alembic/                        # Database migrations
│   ├── versions/
│   ├── env.py
│   └── alembic.ini
├── app/
│   ├── __init__.py
│   ├── main.py                     # FastAPI app entry point
│   ├── config.py                   # Settings (pydantic-settings)
│   ├── dependencies.py             # Dependency injection
│   ├── api/
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── router.py           # v1 router aggregator
│   │   │   ├── auth.py             # Auth endpoints
│   │   │   ├── users.py            # User endpoints
│   │   │   └── health.py           # Health check
│   │   └── deps.py                 # Route dependencies
│   ├── models/                     # SQLAlchemy models
│   │   ├── __init__.py
│   │   ├── base.py                 # Base model
│   │   ├── user.py
│   │   └── mixins.py               # Timestamp mixin, etc.
│   ├── schemas/                    # Pydantic schemas
│   │   ├── __init__.py
│   │   ├── user.py
│   │   └── auth.py
│   ├── services/                   # Business logic
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   └── user.py
│   ├── repositories/               # Data access layer
│   │   ├── __init__.py
│   │   └── user.py
│   ├── core/                       # Cross-cutting concerns
│   │   ├── __init__.py
│   │   ├── database.py             # DB session management
│   │   ├── security.py             # JWT, hashing
│   │   ├── exceptions.py           # Custom exceptions
│   │   └── middleware.py           # Custom middleware
│   └── utils/                      # Utilities
│       ├── __init__.py
│       └── logging.py
├── tests/
│   ├── conftest.py                 # Fixtures
│   ├── test_auth.py
│   ├── test_users.py
│   └── factories/                  # Test data factories
│       └── user.py
├── scripts/
│   ├── seed.py                     # Database seeding
│   └── migrate.sh                  # Migration helper
├── .env.example
├── .gitignore
├── .pre-commit-config.yaml
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml                  # Project config (replaces setup.py)
├── ruff.toml                       # Linter config
└── README.md
```

### 5.3 FastAPI Main Entry Point

```python
# app/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.config import settings
from app.core.database import engine, Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    async with engine.begin() as conn:
        # In production, use Alembic migrations instead
        if settings.ENVIRONMENT == "development":
            await conn.run_sync(Base.metadata.create_all)
    yield
    # Shutdown
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json" if settings.ENVIRONMENT != "production" else None,
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": settings.VERSION}
```

### 5.4 Settings with pydantic-settings

```python
# app/config.py
from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List


class Settings(BaseSettings):
    # Application
    PROJECT_NAME: str = "Client API"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    API_V1_PREFIX: str = "/api/v1"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://user:pass@localhost:5432/dbname"

    # Auth
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ALGORITHM: str = "HS256"

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    # Monitoring
    SENTRY_DSN: str | None = None

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
```

### 5.5 Python CI/CD (GitHub Actions)

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  quality:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_DB: test_db
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v4

      - name: Setup Python
        run: uv python install 3.12

      - name: Install dependencies
        run: uv sync

      - name: Lint (ruff)
        run: uv run ruff check .

      - name: Format check (ruff)
        run: uv run ruff format --check .

      - name: Type check (mypy)
        run: uv run mypy app/

      - name: Test
        run: uv run pytest --cov=app --cov-report=xml
        env:
          DATABASE_URL: postgresql+asyncpg://test:test@localhost:5432/test_db
          SECRET_KEY: test-secret-key-for-ci
```

### 5.6 Python .env.example

```bash
# .env.example — Copy to .env and fill in values

# Application
ENVIRONMENT=development
PROJECT_NAME="Client API"

# Database
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/dbname

# Authentication
SECRET_KEY=generate-a-secure-random-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30

# CORS (comma-separated origins)
CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Monitoring
SENTRY_DSN=

# Redis (for caching / background jobs)
REDIS_URL=redis://localhost:6379/0
```

---

## 6. Astro Scaffolding

### 6.1 Initialize Project

```bash
# Create Astro project
pnpm create astro@latest client-site -- \
  --template blog \
  --typescript strict \
  --install \
  --git

cd client-site

# Add integrations
pnpm astro add tailwind
pnpm astro add sitemap
pnpm astro add mdx
```

### 6.2 Directory Structure

```
client-site/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── deploy.yml
├── .husky/
│   ├── pre-commit
│   └── commit-msg
├── public/
│   ├── fonts/
│   ├── images/
│   ├── favicon.svg
│   └── robots.txt
├── src/
│   ├── assets/                     # Processed assets (optimized by Astro)
│   │   └── images/
│   ├── components/                 # UI components (.astro or .tsx)
│   │   ├── BaseHead.astro          # <head> content
│   │   ├── Header.astro
│   │   ├── Footer.astro
│   │   ├── BlogCard.astro
│   │   └── react/                  # Interactive React islands
│   │       ├── ContactForm.tsx
│   │       └── SearchModal.tsx
│   ├── content/                    # Content collections
│   │   ├── config.ts               # Collection schemas
│   │   ├── blog/
│   │   │   ├── first-post.md
│   │   │   └── second-post.mdx
│   │   └── pages/
│   │       ├── about.md
│   │       └── privacy.md
│   ├── layouts/
│   │   ├── BaseLayout.astro        # HTML shell
│   │   ├── BlogLayout.astro        # Blog post layout
│   │   └── PageLayout.astro        # Static page layout
│   ├── pages/
│   │   ├── index.astro             # Home page
│   │   ├── about.astro
│   │   ├── blog/
│   │   │   ├── index.astro         # Blog listing
│   │   │   └── [...slug].astro     # Dynamic blog post
│   │   ├── 404.astro
│   │   └── rss.xml.ts              # RSS feed
│   ├── styles/
│   │   └── global.css
│   └── config/
│       ├── brand.ts                # Client branding
│       ├── site.ts                 # Site metadata
│       └── navigation.ts           # Nav items
├── .env.example
├── .eslintrc.json
├── .prettierrc
├── astro.config.mjs
├── package.json
├── pnpm-lock.yaml
├── tailwind.config.mjs
└── tsconfig.json
```

### 6.3 Astro Configuration

```javascript
// astro.config.mjs
import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import sitemap from '@astrojs/sitemap';
import mdx from '@astrojs/mdx';
import react from '@astrojs/react';

export default defineConfig({
  site: 'https://www.clientsite.com',
  integrations: [
    tailwind(),
    sitemap(),
    mdx(),
    react(),  // For interactive islands
  ],
  markdown: {
    shikiConfig: {
      theme: 'github-dark',
    },
  },
  vite: {
    optimizeDeps: {
      exclude: ['@resvg/resvg-js'],
    },
  },
});
```

### 6.4 Astro CI/CD

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'

      - run: pnpm install --frozen-lockfile
      - run: pnpm run lint
      - run: pnpm astro check
      - run: pnpm build
```

---

## 7. Monorepo with Turborepo

### 7.1 Initialize Monorepo

```bash
# Create Turborepo monorepo
pnpm dlx create-turbo@latest client-platform

cd client-platform
```

### 7.2 Directory Structure

```
client-platform/
├── .github/
│   └── workflows/
│       ├── ci.yml                  # Monorepo CI (affected packages only)
│       ├── deploy-web.yml          # Web deployment
│       ├── deploy-api.yml          # API deployment
│       └── eas-build.yml           # Mobile EAS builds
├── .husky/
│   ├── pre-commit
│   └── commit-msg
├── apps/
│   ├── web/                        # Next.js frontend
│   │   ├── src/
│   │   │   ├── app/
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   ├── lib/
│   │   │   └── config/
│   │   ├── next.config.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   ├── mobile/                     # Expo/React Native app
│   │   ├── app/
│   │   ├── components/
│   │   ├── hooks/
│   │   ├── lib/
│   │   ├── app.json
│   │   ├── eas.json
│   │   ├── package.json
│   │   └── tsconfig.json
│   ├── api/                        # FastAPI or Node.js API
│   │   ├── app/
│   │   ├── tests/
│   │   ├── Dockerfile
│   │   └── package.json            # or pyproject.toml
│   └── docs/                       # Documentation site (Astro)
│       ├── src/
│       ├── astro.config.mjs
│       └── package.json
├── packages/
│   ├── ui/                         # Shared UI component library
│   │   ├── src/
│   │   │   ├── components/
│   │   │   │   ├── Button.tsx
│   │   │   │   ├── Input.tsx
│   │   │   │   ├── Modal.tsx
│   │   │   │   ├── Card.tsx
│   │   │   │   └── index.ts
│   │   │   ├── hooks/
│   │   │   │   └── index.ts
│   │   │   └── index.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   ├── shared/                     # Shared utilities and types
│   │   ├── src/
│   │   │   ├── types/
│   │   │   │   ├── api.ts
│   │   │   │   ├── user.ts
│   │   │   │   └── index.ts
│   │   │   ├── utils/
│   │   │   │   ├── date.ts
│   │   │   │   ├── format.ts
│   │   │   │   ├── validation.ts
│   │   │   │   └── index.ts
│   │   │   ├── constants/
│   │   │   │   └── index.ts
│   │   │   └── index.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   ├── config-eslint/              # Shared ESLint configuration
│   │   ├── base.js
│   │   ├── next.js
│   │   ├── react-native.js
│   │   └── package.json
│   ├── config-typescript/          # Shared TypeScript configuration
│   │   ├── base.json
│   │   ├── nextjs.json
│   │   ├── react-native.json
│   │   ├── library.json
│   │   └── package.json
│   └── config-tailwind/            # Shared Tailwind configuration
│       ├── tailwind.config.ts      # Base config with brand tokens
│       └── package.json
├── tooling/                        # Build tooling
│   └── scripts/
│       ├── setup-env.sh
│       └── validate-packages.ts
├── .env.example
├── .gitignore
├── .npmrc                          # pnpm config
├── commitlint.config.js
├── lint-staged.config.js
├── package.json                    # Root workspace config
├── pnpm-lock.yaml
├── pnpm-workspace.yaml
└── turbo.json                      # Turborepo pipeline config
```

### 7.3 Root package.json

```json
{
  "name": "client-platform",
  "private": true,
  "scripts": {
    "build": "turbo build",
    "dev": "turbo dev",
    "lint": "turbo lint",
    "typecheck": "turbo typecheck",
    "test": "turbo test",
    "clean": "turbo clean && rm -rf node_modules",
    "format": "prettier --write \"**/*.{ts,tsx,js,jsx,md,json}\"",
    "format:check": "prettier --check \"**/*.{ts,tsx,js,jsx,md,json}\"",
    "prepare": "husky"
  },
  "devDependencies": {
    "@commitlint/cli": "^19.0.0",
    "@commitlint/config-conventional": "^19.0.0",
    "husky": "^9.0.0",
    "lint-staged": "^15.0.0",
    "prettier": "^3.2.0",
    "turbo": "^2.0.0"
  },
  "packageManager": "pnpm@9.15.0",
  "engines": {
    "node": ">=20"
  }
}
```

### 7.4 pnpm-workspace.yaml

```yaml
# pnpm-workspace.yaml
packages:
  - 'apps/*'
  - 'packages/*'
  - 'tooling/*'
```

### 7.5 turbo.json Pipeline

```json
{
  "$schema": "https://turbo.build/schema.json",
  "globalDependencies": [
    "**/.env.*local",
    "**/.env"
  ],
  "globalEnv": [
    "NODE_ENV",
    "NEXT_PUBLIC_*"
  ],
  "tasks": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": [
        ".next/**",
        "!.next/cache/**",
        "dist/**",
        "build/**"
      ]
    },
    "dev": {
      "cache": false,
      "persistent": true
    },
    "lint": {
      "dependsOn": ["^build"]
    },
    "typecheck": {
      "dependsOn": ["^build"]
    },
    "test": {
      "dependsOn": ["^build"],
      "outputs": ["coverage/**"]
    },
    "clean": {
      "cache": false
    }
  }
}
```

### 7.6 Shared UI Package

```json
// packages/ui/package.json
{
  "name": "@client/ui",
  "version": "0.0.0",
  "private": true,
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "exports": {
    ".": "./src/index.ts",
    "./components": "./src/components/index.ts",
    "./hooks": "./src/hooks/index.ts"
  },
  "scripts": {
    "lint": "eslint src/",
    "typecheck": "tsc --noEmit"
  },
  "devDependencies": {
    "@client/config-eslint": "workspace:*",
    "@client/config-typescript": "workspace:*",
    "react": "^18.3.0",
    "react-dom": "^18.3.0",
    "typescript": "^5.5.0"
  },
  "peerDependencies": {
    "react": "^18.3.0",
    "react-dom": "^18.3.0"
  }
}
```

```typescript
// packages/ui/src/components/Button.tsx
import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cn } from '../utils';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'destructive';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, disabled, children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center rounded-md font-medium transition-colors',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2',
          'disabled:pointer-events-none disabled:opacity-50',
          {
            'bg-brand-primary text-white hover:bg-brand-primary/90': variant === 'primary',
            'bg-brand-secondary text-white hover:bg-brand-secondary/90': variant === 'secondary',
            'border border-gray-300 bg-white hover:bg-gray-50': variant === 'outline',
            'hover:bg-gray-100': variant === 'ghost',
            'bg-red-600 text-white hover:bg-red-700': variant === 'destructive',
          },
          {
            'h-8 px-3 text-sm': size === 'sm',
            'h-10 px-4 text-sm': size === 'md',
            'h-12 px-6 text-base': size === 'lg',
          },
          className,
        )}
        disabled={disabled || loading}
        {...props}
      >
        {loading ? <span className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" /> : null}
        {children}
      </button>
    );
  },
);

Button.displayName = 'Button';
```

### 7.7 Shared TypeScript Config

```json
// packages/config-typescript/base.json
{
  "$schema": "https://json.schemastore.org/tsconfig",
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022"],
    "module": "ESNext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "allowImportingTsExtensions": true,
    "noEmit": true,
    "declaration": true,
    "declarationMap": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "isolatedModules": true,
    "skipLibCheck": true,
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "incremental": true
  },
  "exclude": ["node_modules", "dist", "build", ".next", ".expo"]
}
```

```json
// packages/config-typescript/nextjs.json
{
  "$schema": "https://json.schemastore.org/tsconfig",
  "extends": "./base.json",
  "compilerOptions": {
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "jsx": "preserve",
    "module": "ESNext",
    "plugins": [{ "name": "next" }],
    "paths": {
      "@/*": ["./src/*"]
    }
  }
}
```

```json
// packages/config-typescript/react-native.json
{
  "$schema": "https://json.schemastore.org/tsconfig",
  "extends": "./base.json",
  "compilerOptions": {
    "lib": ["ES2022"],
    "jsx": "react-jsx",
    "module": "ESNext",
    "moduleResolution": "bundler"
  }
}
```

### 7.8 Shared ESLint Config

```javascript
// packages/config-eslint/base.js
module.exports = {
  parser: '@typescript-eslint/parser',
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'prettier',
  ],
  plugins: ['@typescript-eslint'],
  rules: {
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
    'no-console': ['warn', { allow: ['warn', 'error'] }],
  },
  ignorePatterns: ['node_modules/', 'dist/', '.next/', '.expo/', 'coverage/'],
};
```

```javascript
// packages/config-eslint/next.js
module.exports = {
  extends: [
    './base.js',
    'next/core-web-vitals',
    'next/typescript',
  ],
  rules: {
    '@next/next/no-html-link-for-pages': 'off', // handled per-app
  },
};
```

### 7.9 Monorepo CI/CD

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  quality:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Needed for Turborepo affected detection

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'

      - run: pnpm install --frozen-lockfile

      - name: Lint (affected only)
        run: pnpm turbo lint --filter=...[origin/main]

      - name: Type Check (affected only)
        run: pnpm turbo typecheck --filter=...[origin/main]

      - name: Test (affected only)
        run: pnpm turbo test --filter=...[origin/main]

      - name: Build (affected only)
        run: pnpm turbo build --filter=...[origin/main]
```

### 7.10 Consuming Shared Packages

```json
// apps/web/package.json (partial)
{
  "dependencies": {
    "@client/ui": "workspace:*",
    "@client/shared": "workspace:*"
  },
  "devDependencies": {
    "@client/config-eslint": "workspace:*",
    "@client/config-typescript": "workspace:*",
    "@client/config-tailwind": "workspace:*"
  }
}
```

```typescript
// apps/web/src/app/page.tsx — using shared packages
import { Button, Card } from '@client/ui/components';
import { formatDate, validateEmail } from '@client/shared/utils';
import type { User } from '@client/shared/types';

export default function HomePage() {
  return (
    <main>
      <Card>
        <h1>Welcome</h1>
        <Button variant="primary" size="lg">
          Get Started
        </Button>
      </Card>
    </main>
  );
}
```

---

## 8. Shared Tooling Configuration

These configurations apply across **all** project types (except Python, which uses its own tooling).

### 8.1 ESLint Configuration

```json
// .eslintrc.json (standalone projects)
{
  "extends": [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "next/core-web-vitals",
    "prettier"
  ],
  "parser": "@typescript-eslint/parser",
  "plugins": ["@typescript-eslint"],
  "rules": {
    "@typescript-eslint/no-unused-vars": ["error", { "argsIgnorePattern": "^_" }],
    "@typescript-eslint/no-explicit-any": "warn",
    "@typescript-eslint/consistent-type-imports": ["error", { "prefer": "type-imports" }],
    "no-console": ["warn", { "allow": ["warn", "error"] }],
    "prefer-const": "error",
    "no-var": "error"
  },
  "ignorePatterns": ["node_modules/", ".next/", "dist/", "coverage/"]
}
```

### 8.2 Prettier Configuration

```json
// .prettierrc
{
  "semi": true,
  "singleQuote": true,
  "tabWidth": 2,
  "trailingComma": "all",
  "printWidth": 100,
  "bracketSpacing": true,
  "arrowParens": "always",
  "endOfLine": "lf",
  "plugins": ["prettier-plugin-tailwindcss"]
}
```

### 8.3 TypeScript Configuration (Standalone)

```json
// tsconfig.json (Next.js standalone)
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "plugins": [{ "name": "next" }],
    "paths": {
      "@/*": ["./src/*"]
    },
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts"],
  "exclude": ["node_modules"]
}
```

### 8.4 Git Hooks (Husky + lint-staged)

```bash
# Install and configure
pnpm add -D husky lint-staged @commitlint/cli @commitlint/config-conventional

# Initialize husky
pnpm exec husky init
```

```bash
# .husky/pre-commit
pnpm exec lint-staged
```

```bash
# .husky/commit-msg
pnpm exec commitlint --edit $1
```

```javascript
// lint-staged.config.js
module.exports = {
  // TypeScript / JavaScript
  '*.{ts,tsx,js,jsx}': [
    'eslint --fix --max-warnings=0',
    'prettier --write',
  ],
  // Styles
  '*.{css,scss}': [
    'prettier --write',
  ],
  // JSON / Markdown / YAML
  '*.{json,md,yml,yaml}': [
    'prettier --write',
  ],
};
```

```javascript
// commitlint.config.js
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      [
        'feat',     // New feature
        'fix',      // Bug fix
        'docs',     // Documentation
        'style',    // Formatting (no code change)
        'refactor', // Refactoring (no feature/fix)
        'perf',     // Performance improvement
        'test',     // Adding tests
        'build',    // Build system changes
        'ci',       // CI/CD changes
        'chore',    // Maintenance
        'revert',   // Revert commit
      ],
    ],
    'subject-case': [2, 'never', ['upper-case', 'pascal-case', 'start-case']],
    'subject-max-length': [2, 'always', 72],
  },
};
```

### 8.5 .gitignore (Universal)

```gitignore
# Dependencies
node_modules/
.pnp
.pnp.js

# Build outputs
.next/
dist/
build/
out/
.expo/

# Environment
.env
.env.local
.env.*.local

# IDE
.vscode/settings.json
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Testing
coverage/
*.lcov

# Debug
npm-debug.log*
pnpm-debug.log*
yarn-error.log*

# Turbo
.turbo/

# Sentry
.sentryclirc

# Python (if applicable)
__pycache__/
*.py[cod]
.venv/
*.egg-info/
```

### 8.6 README Template

```markdown
# Project Name

> One-line project description.

## Prerequisites

- Node.js >= 20
- pnpm >= 9
- (Other requirements)

## Getting Started

1. Clone the repository
2. Copy environment variables: `cp .env.example .env.local`
3. Install dependencies: `pnpm install`
4. Start development server: `pnpm dev`

## Scripts

| Command | Description |
|---------|-------------|
| `pnpm dev` | Start development server |
| `pnpm build` | Production build |
| `pnpm lint` | Run ESLint |
| `pnpm typecheck` | Run TypeScript compiler check |
| `pnpm test` | Run tests |
| `pnpm format` | Format code with Prettier |

## Project Structure

(Describe the project-specific directory structure here)

## Environment Variables

See `.env.example` for required variables.

## Deployment

(Describe deployment process)

## Contributing

1. Create a feature branch: `git checkout -b feat/your-feature`
2. Commit using conventional commits: `git commit -m "feat: add new feature"`
3. Push and create a pull request
```

---

## 9. Client-Specific Customization

### 9.1 Brand Configuration

Every project should centralize brand values in a single file so that updating branding is a one-file change.

```typescript
// src/config/brand.ts (or config/brand.ts)

export const brand = {
  name: 'Client Name',
  tagline: 'Their tagline goes here',

  // Colors — these feed into Tailwind config
  colors: {
    primary: {
      50:  '#eff6ff',
      100: '#dbeafe',
      200: '#bfdbfe',
      300: '#93c5fd',
      400: '#60a5fa',
      500: '#3b82f6',  // Main brand color
      600: '#2563eb',
      700: '#1d4ed8',
      800: '#1e40af',
      900: '#1e3a8a',
      950: '#172554',
    },
    secondary: {
      50:  '#faf5ff',
      500: '#a855f7',
      900: '#581c87',
    },
    accent: '#f59e0b',
    success: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
  },

  // Typography
  fonts: {
    heading: 'Inter',
    body: 'Inter',
    mono: 'JetBrains Mono',
  },

  // External links
  social: {
    twitter: 'https://twitter.com/clientname',
    linkedin: 'https://linkedin.com/company/clientname',
    github: 'https://github.com/clientname',
  },

  // Assets
  logo: {
    light: '/images/logo-light.svg',
    dark: '/images/logo-dark.svg',
    icon: '/images/icon.svg',
  },

  // Legal
  legal: {
    companyName: 'Client Name Inc.',
    year: new Date().getFullYear(),
  },
} as const;

export type Brand = typeof brand;
```

### 9.2 Tailwind Integration with Brand Config

```typescript
// tailwind.config.ts
import type { Config } from 'tailwindcss';
import { brand } from './src/config/brand';

const config: Config = {
  content: [
    './src/**/*.{ts,tsx,astro,mdx}',
    // If monorepo, include shared packages:
    // '../../packages/ui/src/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        'brand-primary': brand.colors.primary,
        'brand-secondary': brand.colors.secondary,
        'brand-accent': brand.colors.accent,
      },
      fontFamily: {
        heading: [brand.fonts.heading, 'system-ui', 'sans-serif'],
        body: [brand.fonts.body, 'system-ui', 'sans-serif'],
        mono: [brand.fonts.mono, 'monospace'],
      },
    },
  },
  plugins: [],
};

export default config;
```

### 9.3 Multi-Environment Setup

```typescript
// src/config/env.ts
import { z } from 'zod';

// Define the environment enum
const Environment = z.enum(['development', 'staging', 'production']);
type Environment = z.infer<typeof Environment>;

// Per-environment configuration
const environmentConfig: Record<Environment, {
  apiUrl: string;
  analyticsEnabled: boolean;
  sentryEnabled: boolean;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  features: Record<string, boolean>;
}> = {
  development: {
    apiUrl: 'http://localhost:3001/api',
    analyticsEnabled: false,
    sentryEnabled: false,
    logLevel: 'debug',
    features: {
      newOnboarding: true,
      betaFeatures: true,
    },
  },
  staging: {
    apiUrl: 'https://staging-api.clientsite.com',
    analyticsEnabled: true,
    sentryEnabled: true,
    logLevel: 'info',
    features: {
      newOnboarding: true,
      betaFeatures: true,
    },
  },
  production: {
    apiUrl: 'https://api.clientsite.com',
    analyticsEnabled: true,
    sentryEnabled: true,
    logLevel: 'warn',
    features: {
      newOnboarding: false,
      betaFeatures: false,
    },
  },
};

const currentEnv = Environment.parse(
  process.env.NEXT_PUBLIC_APP_ENV ?? process.env.NODE_ENV ?? 'development'
);

export const config = {
  env: currentEnv,
  isDev: currentEnv === 'development',
  isStaging: currentEnv === 'staging',
  isProd: currentEnv === 'production',
  ...environmentConfig[currentEnv],
};

// Feature flag helper
export function isFeatureEnabled(feature: string): boolean {
  return config.features[feature] ?? false;
}
```

### 9.4 Analytics Integration Points

Set up a provider-agnostic analytics layer so the specific provider can be swapped without touching application code.

```typescript
// src/lib/analytics.ts
import { config } from '@/config/env';

// Provider-agnostic analytics interface
interface AnalyticsEvent {
  name: string;
  properties?: Record<string, string | number | boolean>;
}

interface AnalyticsUser {
  id: string;
  email?: string;
  name?: string;
  properties?: Record<string, string | number | boolean>;
}

class Analytics {
  private initialized = false;

  init(): void {
    if (!config.analyticsEnabled || this.initialized) return;

    // Initialize your analytics provider here
    // Examples: PostHog, Mixpanel, Amplitude, Google Analytics

    // PostHog example:
    // posthog.init(env.NEXT_PUBLIC_POSTHOG_KEY, {
    //   api_host: env.NEXT_PUBLIC_POSTHOG_HOST,
    //   capture_pageview: false, // we handle manually
    // });

    // Google Analytics example:
    // gtag('config', env.NEXT_PUBLIC_GA_ID);

    this.initialized = true;
  }

  identify(user: AnalyticsUser): void {
    if (!config.analyticsEnabled) return;
    // posthog.identify(user.id, { email: user.email, name: user.name, ...user.properties });
    console.debug('[Analytics] identify:', user.id);
  }

  track(event: AnalyticsEvent): void {
    if (!config.analyticsEnabled) return;
    // posthog.capture(event.name, event.properties);
    console.debug('[Analytics] track:', event.name, event.properties);
  }

  page(name: string, properties?: Record<string, string>): void {
    if (!config.analyticsEnabled) return;
    // posthog.capture('$pageview', { page: name, ...properties });
    console.debug('[Analytics] page:', name);
  }

  reset(): void {
    if (!config.analyticsEnabled) return;
    // posthog.reset();
    console.debug('[Analytics] reset');
  }
}

export const analytics = new Analytics();
```

```typescript
// Usage in React (Next.js example)
// src/components/layout/AnalyticsProvider.tsx
'use client';

import { useEffect } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';
import { analytics } from '@/lib/analytics';

export function AnalyticsProvider({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  useEffect(() => {
    analytics.init();
  }, []);

  useEffect(() => {
    analytics.page(pathname);
  }, [pathname, searchParams]);

  return <>{children}</>;
}
```

### 9.5 Error Monitoring Bootstrap

```typescript
// src/lib/error-monitoring.ts
import { config, env } from '@/config/env';

interface ErrorContext {
  user?: { id: string; email?: string };
  tags?: Record<string, string>;
  extra?: Record<string, unknown>;
}

class ErrorMonitoring {
  private initialized = false;

  init(): void {
    if (!config.sentryEnabled || this.initialized) return;

    // Sentry example:
    // Sentry.init({
    //   dsn: env.SENTRY_DSN,
    //   environment: config.env,
    //   tracesSampleRate: config.isProd ? 0.1 : 1.0,
    //   replaysSessionSampleRate: 0.1,
    //   replaysOnErrorSampleRate: 1.0,
    //   integrations: [
    //     Sentry.replayIntegration(),
    //     Sentry.browserTracingIntegration(),
    //   ],
    // });

    this.initialized = true;
  }

  captureException(error: Error, context?: ErrorContext): void {
    if (!config.sentryEnabled) {
      console.error('[Error]', error, context);
      return;
    }
    // Sentry.captureException(error, {
    //   user: context?.user,
    //   tags: context?.tags,
    //   extra: context?.extra,
    // });
  }

  captureMessage(message: string, level: 'info' | 'warning' | 'error' = 'info'): void {
    if (!config.sentryEnabled) {
      console.log(`[${level}]`, message);
      return;
    }
    // Sentry.captureMessage(message, level);
  }

  setUser(user: { id: string; email?: string }): void {
    if (!config.sentryEnabled) return;
    // Sentry.setUser(user);
  }

  clearUser(): void {
    if (!config.sentryEnabled) return;
    // Sentry.setUser(null);
  }
}

export const errorMonitoring = new ErrorMonitoring();
```

### 9.6 Next.js Sentry Integration

```typescript
// next.config.ts (with Sentry)
import { withSentryConfig } from '@sentry/nextjs';

const nextConfig = {
  // ... your Next.js config
};

export default withSentryConfig(nextConfig, {
  org: 'client-org',
  project: 'client-web',
  silent: !process.env.CI,
  widenClientFileUpload: true,
  tunnelRoute: '/monitoring',
  hideSourceMaps: true,
  disableLogger: true,
});
```

### 9.7 Multi-Environment Deployment Strategy

```
Environment     Branch      URL                           Purpose
-----------     ------      ---                           -------
Development     feature/*   localhost:3000                Local development
Staging         develop     staging.clientsite.com        QA and client review
Production      main        www.clientsite.com            Live users

Deploy triggers:
- PR to develop  --> auto-deploy to staging (after CI passes)
- PR to main     --> requires 1 approval, auto-deploy to production
- Hotfix         --> branch from main, PR directly to main
```

```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    branches: [main, develop]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'

      - run: pnpm install --frozen-lockfile

      - name: Set environment
        run: |
          if [ "${{ github.ref }}" = "refs/heads/main" ]; then
            echo "DEPLOY_ENV=production" >> $GITHUB_ENV
            echo "DEPLOY_URL=https://www.clientsite.com" >> $GITHUB_ENV
          else
            echo "DEPLOY_ENV=staging" >> $GITHUB_ENV
            echo "DEPLOY_URL=https://staging.clientsite.com" >> $GITHUB_ENV
          fi

      - name: Build
        run: pnpm build
        env:
          NEXT_PUBLIC_APP_ENV: ${{ env.DEPLOY_ENV }}
          NEXT_PUBLIC_APP_URL: ${{ env.DEPLOY_URL }}

      # Vercel deployment
      - name: Deploy to Vercel
        uses: amondnet/vercel-action@v25
        with:
          vercel-token: ${{ secrets.VERCEL_TOKEN }}
          vercel-org-id: ${{ secrets.VERCEL_ORG_ID }}
          vercel-project-id: ${{ secrets.VERCEL_PROJECT_ID }}
          vercel-args: ${{ env.DEPLOY_ENV == 'production' && '--prod' || '' }}
```

---

## 10. Integrates With

This skill references and is designed to work with the following skills and modules in the streamlined development system.

### Skills

| Skill | Relationship |
|-------|-------------|
| **`pnpm-migration`** | Default package manager for all JS/TS scaffolding. Use pnpm for installs, lockfiles, and workspace protocol in monorepos. |
| **`cicd-templates`** | Extended CI/CD pipeline configurations beyond the starters in this skill. Reference for advanced caching, matrix builds, deployment gates. |
| **`elite-frontend-developer`** | Frontend coding conventions, React patterns, performance optimization. Apply these standards when building components after scaffolding. |
| **`testing-strategies`** | Test setup bootstrapping (unit, integration, e2e). Use to configure Jest/Vitest, testing-library, and coverage thresholds after initial scaffolding. |
| **`deployment-lifecycle`** | Production deployment regimen. Follow its checklists for staging/production rollout after the project is scaffolded and developed. |
| **`deployment-patterns`** | Advanced deployment strategies (blue/green, canary, rolling). Reference when configuring production deployment pipelines. |
| **`security-owasp`** | Security hardening. Apply OWASP best practices to all scaffolded projects, especially auth flows and API endpoints. |
| **`design-system`** | Design system patterns. Use when building the shared UI package in monorepo setups. |
| **`api-patterns`** | API design conventions. Apply when scaffolding FastAPI or Next.js API routes. |
| **`performance`** | Performance optimization techniques. Reference after scaffolding for Core Web Vitals tuning and bundle analysis. |
| **`database-patterns`** | Database design patterns. Use when setting up database models and migrations in FastAPI or full-stack projects. |

### Modules

| Module | Relationship |
|--------|-------------|
| **`eas-deployment`** | EAS Build and Submit configuration templates. Use its `eas.json`, `app.json`, and GitHub Actions templates when scaffolding Expo projects. |
| **`supabase-database-setup`** | Supabase client setup and base schemas. Use when the client project uses Supabase for database, auth, or storage. Contains ready-made clients for Next.js and React Native. |

### Usage Pattern

When scaffolding a new client project, follow this sequence:

1. **This skill** -- Select project type and generate initial structure
2. **`pnpm-migration`** -- Ensure pnpm is configured correctly
3. **`testing-strategies`** -- Configure test framework and initial test files
4. **`cicd-templates`** -- Enhance CI/CD beyond the starter provided here
5. **`elite-frontend-developer`** -- Apply frontend conventions to components
6. **`eas-deployment`** (mobile) -- Configure EAS Build profiles
7. **`supabase-database-setup`** (if using Supabase) -- Initialize database client and schemas
8. **`security-owasp`** -- Review and harden auth, inputs, and API surface
9. **`deployment-lifecycle`** -- Prepare staging and production environments

---

## Appendix A: Scaffolding Checklist

Use this checklist when scaffolding any new client project.

### Pre-Scaffolding

- [ ] Client requirements gathered and documented
- [ ] Project type selected from decision matrix
- [ ] Repository created (GitHub)
- [ ] Team access configured
- [ ] Domain / hosting decided

### Scaffolding

- [ ] Project initialized with correct template
- [ ] Directory structure matches skill guide
- [ ] pnpm configured as package manager
- [ ] TypeScript configured with strict mode
- [ ] ESLint + Prettier configured
- [ ] Tailwind CSS configured (if applicable)
- [ ] Git hooks installed (husky + lint-staged + commitlint)
- [ ] `.env.example` created with all required variables
- [ ] `.gitignore` covers all necessary patterns
- [ ] Brand config file created with client colors/fonts/logos
- [ ] Multi-environment config set up (dev/staging/prod)
- [ ] Analytics provider wired in (disabled in dev)
- [ ] Error monitoring bootstrapped (Sentry or equivalent)
- [ ] CI/CD pipeline configured (GitHub Actions)
- [ ] README written with setup instructions

### Post-Scaffolding

- [ ] `pnpm install` succeeds
- [ ] `pnpm dev` starts without errors
- [ ] `pnpm build` completes successfully
- [ ] `pnpm lint` passes
- [ ] `pnpm typecheck` passes
- [ ] CI pipeline runs and passes
- [ ] First commit follows conventional commits format
- [ ] Team members can clone and run locally

---

## Appendix B: Quick Start Commands

### Next.js

```bash
pnpm create next-app@latest my-app --typescript --tailwind --eslint --app --src-dir --import-alias "@/*"
cd my-app
pnpm add -D husky lint-staged @commitlint/cli @commitlint/config-conventional prettier prettier-plugin-tailwindcss
pnpm add zod zustand
pnpm exec husky init
```

### Expo

```bash
pnpm create expo-app my-app --template tabs
cd my-app
pnpm add -g eas-cli
eas init && eas build:configure
pnpm add -D husky lint-staged @commitlint/cli @commitlint/config-conventional prettier
pnpm add zod zustand expo-constants
pnpm exec husky init
```

### FastAPI

```bash
mkdir my-api && cd my-api
uv init --python 3.12
uv add fastapi uvicorn[standard] pydantic pydantic-settings sqlalchemy[asyncio] alembic asyncpg
uv add --dev pytest pytest-asyncio httpx ruff mypy
alembic init alembic
```

### Astro

```bash
pnpm create astro@latest my-site -- --template blog --typescript strict --install --git
cd my-site
pnpm astro add tailwind sitemap mdx react
pnpm add -D husky lint-staged @commitlint/cli @commitlint/config-conventional prettier prettier-plugin-tailwindcss
pnpm exec husky init
```

### Monorepo (Turborepo)

```bash
pnpm dlx create-turbo@latest my-platform
cd my-platform
pnpm add -D -w husky lint-staged @commitlint/cli @commitlint/config-conventional prettier
pnpm exec husky init
```
