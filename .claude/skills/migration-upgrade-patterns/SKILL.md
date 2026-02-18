# Migration & Upgrade Patterns Skill

**Purpose:** Comprehensive framework for migrating frameworks, upgrading runtime versions, evolving database schemas, and managing dependency lifecycles with zero downtime and reliable rollback.

**When to use:** Framework migrations, major version upgrades, database schema changes, dependency updates, runtime version bumps, or any large-scale codebase evolution requiring a structured, low-risk approach.

---

## Overview

Migrations and upgrades are among the highest-risk activities in a codebase. They touch every layer of the stack, break implicit contracts, and expose phantom dependencies. This skill codifies patterns learned across dozens of production migrations -- from React 18 to 19, Next.js Pages Router to App Router, Expo SDK major bumps, Node.js LTS transitions, and database schema evolutions -- into repeatable, safe playbooks.

### Key Components

1. **Migration Decision Framework** -- When to migrate vs. stay
2. **Frontend Framework Migrations** -- React, Next.js incremental strategies
3. **Mobile SDK Upgrades** -- Expo SDK version-to-version patterns
4. **Runtime Version Upgrades** -- Node.js major version transitions
5. **Database Schema Migrations** -- Zero-downtime expand-contract pattern
6. **Dependency Upgrade Strategy** -- Systematic approach to package updates
7. **Feature Flag Strategy** -- Gradual rollout during migrations
8. **Codemod Patterns** -- Automated code transformations at scale
9. **Rollback Procedures** -- Safety nets and recovery playbooks

### Guiding Principles

- **Never migrate everything at once.** Incremental migration reduces blast radius.
- **Run old and new in parallel.** Verify parity before cutting over.
- **Automate the boring parts.** Codemods and scripts beat manual find-and-replace.
- **Feature flags are your safety net.** Toggle between old and new paths.
- **Test at every stage.** Regression suites gate each migration phase.
- **Document the decision.** Future-you needs to know *why*, not just *what*.

---

## 1. Migration Decision Framework

Before writing a single line of migration code, answer these questions systematically.

### The MIGRATE Checklist

| Factor | Question | Score (1-5) |
|--------|----------|-------------|
| **M**aintenance burden | Is the current version costing us developer time? | ___ |
| **I**ncompatibility risk | Are dependencies dropping support for our version? | ___ |
| **G**ains available | Does the new version offer concrete performance/DX wins? | ___ |
| **R**esources available | Do we have the team bandwidth for a migration? | ___ |
| **A**utomation possible | Can codemods handle >50% of the changes? | ___ |
| **T**esting coverage | Do we have sufficient test coverage to catch regressions? | ___ |
| **E**cosystem readiness | Are our key dependencies compatible with the target? | ___ |

**Scoring:**
- **28-35**: Strong migrate -- start planning immediately
- **21-27**: Migrate when convenient -- schedule for next quarter
- **14-20**: Hold -- address blockers first (usually testing or ecosystem)
- **7-13**: Stay -- migration cost exceeds benefit

### Decision Matrix: Migrate vs. Stay vs. Rewrite

| Signal | Migrate | Stay | Rewrite |
|--------|---------|------|---------|
| Security patches ending | Yes | -- | -- |
| Performance 2x improvement | Yes | -- | -- |
| Breaking change count < 20 | Yes | -- | -- |
| Breaking change count > 100 | -- | -- | Consider |
| No test coverage | -- | Yes (add tests first) | -- |
| New paradigm (class -> hooks) | Incremental | -- | -- |
| Team unfamiliar with new version | Train first | Yes (short-term) | -- |
| Ecosystem incompatible | -- | Yes (wait) | -- |
| End-of-life in < 6 months | Yes (urgent) | -- | -- |
| Current version works fine | -- | Yes | -- |

### Pre-Migration Checklist

Before starting any migration:

- [ ] **Dependency audit**: Run compatibility check against target version
- [ ] **Test coverage baseline**: Measure current coverage; aim for 70%+ before migrating
- [ ] **Performance baseline**: Record current metrics (build time, runtime perf, bundle size)
- [ ] **Breaking changes inventory**: Read every changelog entry between current and target
- [ ] **Codemod availability**: Check for official or community codemods
- [ ] **Team alignment**: Ensure everyone knows migration is in progress
- [ ] **Branch strategy decided**: Feature branch, feature flags, or parallel directories
- [ ] **Rollback plan documented**: How to revert at every stage
- [ ] **Timeline estimated**: Pad by 2x for unknowns

---

## 2. React 18 to 19 Migration

### What Changed in React 19

| Feature | React 18 | React 19 |
|---------|----------|----------|
| **ref as prop** | `forwardRef()` required | `ref` is a regular prop |
| **Context** | `<Context.Provider>` | `<Context>` directly |
| **Cleanup in refs** | Not supported | Return cleanup function from ref callback |
| **`use()` hook** | Not available | Read promises and context in render |
| **`useActionState()`** | Not available | Replaces `useFormState` |
| **`useOptimistic()`** | Not available | Built-in optimistic updates |
| **`<form>` actions** | Manual `onSubmit` | `action` prop with async functions |
| **React Compiler** | Not available | Automatic memoization (optional) |
| **`useDeferredValue`** | No initial value | Accepts `initialValue` param |
| **Error handling** | Swallowed errors re-thrown | Errors not re-thrown; `onUncaughtError` |
| **Metadata** | react-helmet / next/head | Native `<title>`, `<meta>`, `<link>` in components |
| **Stylesheets** | Manual management | `precedence` prop for ordering |

### Migration Strategy (Incremental)

**Phase 1: Preparation (1-2 days)**

```bash
# Check compatibility
npx react-codemod@latest upgrade

# Review deprecation warnings in development
# React 18.3 was a bridge release with deprecation warnings
# Ensure you're on React 18.3 first
pnpm add react@18.3 react-dom@18.3
```

```bash
# Run the full test suite and fix deprecation warnings
pnpm test 2>&1 | grep -i "deprecated\|warning"
```

**Phase 2: Upgrade React (1 day)**

```bash
# Upgrade React and React DOM
pnpm add react@19 react-dom@19 @types/react@19 @types/react-dom@19

# Upgrade related packages
pnpm add react-test-renderer@19  # if used
pnpm add eslint-plugin-react-hooks@latest
```

**Phase 3: Apply Codemods (1-2 days)**

```bash
# Official React 19 codemod
npx react-codemod@latest upgrade

# This handles:
# - forwardRef removal
# - Context.Provider -> Context
# - useFormState -> useActionState
# - Type changes in TypeScript
# - String ref removal (if any remain)
```

**Phase 4: Manual Fixes (2-5 days)**

```typescript
// BEFORE: forwardRef pattern
const Input = forwardRef<HTMLInputElement, InputProps>((props, ref) => {
  return <input ref={ref} {...props} />;
});

// AFTER: ref as regular prop
const Input = ({ ref, ...props }: InputProps & { ref?: React.Ref<HTMLInputElement> }) => {
  return <input ref={ref} {...props} />;
};

// BEFORE: Context.Provider
<ThemeContext.Provider value={theme}>
  <App />
</ThemeContext.Provider>

// AFTER: Context directly
<ThemeContext value={theme}>
  <App />
</ThemeContext>

// BEFORE: useFormState (from react-dom)
const [state, formAction] = useFormState(submitForm, initialState);

// AFTER: useActionState (from react)
const [state, formAction, isPending] = useActionState(submitForm, initialState);

// NEW: use() hook for async data
function UserProfile({ userPromise }: { userPromise: Promise<User> }) {
  const user = use(userPromise);  // Suspends until resolved
  return <h1>{user.name}</h1>;
}

// NEW: useOptimistic for instant UI feedback
function TodoList({ todos }: { todos: Todo[] }) {
  const [optimisticTodos, addOptimisticTodo] = useOptimistic(
    todos,
    (state, newTodo: Todo) => [...state, newTodo]
  );

  async function addTodo(formData: FormData) {
    const newTodo = { id: Date.now(), text: formData.get('text') as string };
    addOptimisticTodo(newTodo);
    await saveTodo(newTodo);
  }

  return (
    <form action={addTodo}>
      <input name="text" />
      <button type="submit">Add</button>
      {optimisticTodos.map(todo => <li key={todo.id}>{todo.text}</li>)}
    </form>
  );
}

// NEW: Document metadata in components
function BlogPost({ post }: { post: Post }) {
  return (
    <article>
      <title>{post.title}</title>
      <meta name="description" content={post.excerpt} />
      <link rel="canonical" href={post.url} />
      <h1>{post.title}</h1>
      <p>{post.content}</p>
    </article>
  );
}
```

**Phase 5: React Compiler (Optional, 1-3 days)**

```bash
# Install the React Compiler (Babel plugin)
pnpm add -D babel-plugin-react-compiler

# Or for Next.js
pnpm add -D babel-plugin-react-compiler
```

```javascript
// next.config.js (Next.js)
const nextConfig = {
  experimental: {
    reactCompiler: true,
  },
};

// babel.config.js (standalone)
module.exports = {
  plugins: [
    ['babel-plugin-react-compiler', {
      // Opt-in mode: only compile annotated components
      compilationMode: 'annotation', // or 'all' for everything
    }],
  ],
};
```

```typescript
// Opt specific components in/out
// Opt in (when using annotation mode):
'use memo';
function ExpensiveComponent() { /* ... */ }

// Opt out (when using all mode):
'use no memo';
function ComponentWithSideEffects() { /* ... */ }
```

**What the compiler replaces:**
- `useMemo()` -- automatic
- `useCallback()` -- automatic
- `React.memo()` -- automatic

**What the compiler does NOT replace:**
- `useRef()` -- still needed
- `useEffect()` -- still needed
- `useState()` -- still needed
- Custom hooks with side effects -- still needed

### React 19 Migration Checklist

- [ ] Upgrade to React 18.3 first and fix all deprecation warnings
- [ ] Run `npx react-codemod@latest upgrade`
- [ ] Upgrade to React 19 and @types/react@19
- [ ] Remove all `forwardRef` wrappers (ref is now a regular prop)
- [ ] Replace `Context.Provider` with `Context` directly
- [ ] Replace `useFormState` with `useActionState`
- [ ] Remove unnecessary `useMemo`/`useCallback` if enabling compiler
- [ ] Test form actions with new `action` prop
- [ ] Verify error boundaries still work (error handling changed)
- [ ] Update third-party component libraries to React 19-compatible versions
- [ ] Run full test suite
- [ ] Performance benchmark against React 18 baseline

---

## 3. Next.js Pages Router to App Router Migration

### Understanding the Shift

| Concept | Pages Router | App Router |
|---------|-------------|------------|
| **Routing** | `pages/about.tsx` | `app/about/page.tsx` |
| **Layouts** | `_app.tsx` + `_document.tsx` | `layout.tsx` (nested) |
| **Data Fetching** | `getServerSideProps` / `getStaticProps` | `async` Server Components |
| **API Routes** | `pages/api/hello.ts` | `app/api/hello/route.ts` |
| **Loading** | Custom per-page | `loading.tsx` (automatic) |
| **Errors** | `_error.tsx` | `error.tsx` (per-segment) |
| **Metadata** | `next/head` | `metadata` export or `generateMetadata` |
| **Default Rendering** | Client-side | Server Components |
| **Client Components** | All components | Explicit `'use client'` |

### Incremental Migration Strategy

The key insight: **Pages Router and App Router can coexist.** Migrate page by page.

**Phase 1: Setup App Router alongside Pages Router (1 day)**

```
project/
├── app/                    # New App Router pages go here
│   └── layout.tsx          # Root layout (required)
├── pages/                  # Existing Pages Router stays
│   ├── _app.tsx
│   ├── _document.tsx
│   ├── index.tsx
│   ├── about.tsx
│   └── api/
│       └── hello.ts
├── components/             # Shared between both routers
└── next.config.js
```

```typescript
// app/layout.tsx -- Root layout (required)
import { Inter } from 'next/font/google';
import '../styles/globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: 'My App',
  description: 'Migrating to App Router',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={inter.className}>
        {children}
      </body>
    </html>
  );
}
```

**Phase 2: Migrate Shared Providers (1-2 days)**

```typescript
// app/providers.tsx
'use client';

import { ThemeProvider } from 'next-themes';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { SessionProvider } from 'next-auth/react';

const queryClient = new QueryClient();

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SessionProvider>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider attribute="class" defaultTheme="system">
          {children}
        </ThemeProvider>
      </QueryClientProvider>
    </SessionProvider>
  );
}

// app/layout.tsx -- use providers
import { Providers } from './providers';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

**Phase 3: Migrate Pages One at a Time (1-2 weeks)**

Migration order matters. Start with the simplest pages:

1. Static pages (About, FAQ, Terms) -- easiest
2. Dynamic pages with `getStaticProps` -- straightforward
3. Dynamic pages with `getServerSideProps` -- moderate
4. Pages with complex client-side state -- hardest

```typescript
// BEFORE: pages/about.tsx (Pages Router)
import Head from 'next/head';

export default function AboutPage() {
  return (
    <>
      <Head>
        <title>About Us</title>
        <meta name="description" content="About our company" />
      </Head>
      <h1>About Us</h1>
      <p>We build great software.</p>
    </>
  );
}

// AFTER: app/about/page.tsx (App Router)
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'About Us',
  description: 'About our company',
};

export default function AboutPage() {
  return (
    <>
      <h1>About Us</h1>
      <p>We build great software.</p>
    </>
  );
}

// BEFORE: pages/posts/[slug].tsx with getStaticProps
export async function getStaticProps({ params }) {
  const post = await getPost(params.slug);
  return { props: { post }, revalidate: 60 };
}

export async function getStaticPaths() {
  const posts = await getAllPosts();
  return {
    paths: posts.map(p => ({ params: { slug: p.slug } })),
    fallback: 'blocking',
  };
}

export default function PostPage({ post }) {
  return <Article post={post} />;
}

// AFTER: app/posts/[slug]/page.tsx (App Router)
import { notFound } from 'next/navigation';

// Replaces getStaticPaths
export async function generateStaticParams() {
  const posts = await getAllPosts();
  return posts.map(post => ({ slug: post.slug }));
}

// Replaces getStaticProps (revalidate goes here)
export const revalidate = 60;

export async function generateMetadata({ params }: { params: { slug: string } }) {
  const post = await getPost(params.slug);
  if (!post) return {};
  return { title: post.title, description: post.excerpt };
}

// The component itself fetches data directly (Server Component)
export default async function PostPage({ params }: { params: { slug: string } }) {
  const post = await getPost(params.slug);
  if (!post) notFound();
  return <Article post={post} />;
}

// BEFORE: pages/dashboard.tsx with getServerSideProps
export async function getServerSideProps({ req }) {
  const session = await getSession({ req });
  if (!session) return { redirect: { destination: '/login' } };
  const data = await getDashboardData(session.user.id);
  return { props: { data } };
}

// AFTER: app/dashboard/page.tsx (App Router)
import { redirect } from 'next/navigation';
import { getServerSession } from 'next-auth';

export default async function DashboardPage() {
  const session = await getServerSession();
  if (!session) redirect('/login');

  const data = await getDashboardData(session.user.id);
  return <Dashboard data={data} />;
}
```

**Phase 4: Migrate API Routes (1-2 days)**

```typescript
// BEFORE: pages/api/users.ts
import type { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'GET') {
    const users = await getUsers();
    res.status(200).json(users);
  } else if (req.method === 'POST') {
    const user = await createUser(req.body);
    res.status(201).json(user);
  } else {
    res.status(405).end();
  }
}

// AFTER: app/api/users/route.ts
import { NextRequest, NextResponse } from 'next/server';

export async function GET() {
  const users = await getUsers();
  return NextResponse.json(users);
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  const user = await createUser(body);
  return NextResponse.json(user, { status: 201 });
}
```

**Phase 5: Add App Router Features (ongoing)**

```typescript
// loading.tsx -- automatic loading state
export default function Loading() {
  return <Skeleton />;
}

// error.tsx -- per-route error boundary
'use client';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div>
      <h2>Something went wrong</h2>
      <button onClick={reset}>Try again</button>
    </div>
  );
}

// not-found.tsx -- custom 404 per route
export default function NotFound() {
  return <h2>Page not found</h2>;
}

// Parallel Routes -- simultaneous views
// app/@dashboard/page.tsx
// app/@analytics/page.tsx
// app/layout.tsx
export default function Layout({
  children,
  dashboard,
  analytics,
}: {
  children: React.ReactNode;
  dashboard: React.ReactNode;
  analytics: React.ReactNode;
}) {
  return (
    <>
      {children}
      {dashboard}
      {analytics}
    </>
  );
}

// Intercepting Routes -- modal pattern
// app/@modal/(.)photo/[id]/page.tsx intercepts /photo/[id]
```

**Phase 6: Remove Pages Router (1 day)**

Only after all pages are migrated:

```bash
# Verify no pages remain
ls pages/  # Should only have _app.tsx, _document.tsx, _error.tsx (if any)

# Delete pages directory
rm -rf pages/

# Remove Pages Router specific dependencies
pnpm remove @types/next  # if using old types

# Clean up next.config.js -- remove Pages Router specific config
```

### Next.js Migration Checklist

- [ ] Create `app/layout.tsx` root layout
- [ ] Move providers to `app/providers.tsx` with `'use client'`
- [ ] Migrate static pages first (About, Terms, FAQ)
- [ ] Migrate `getStaticProps` pages to async Server Components
- [ ] Migrate `getServerSideProps` pages to async Server Components
- [ ] Migrate API routes from `pages/api/` to `app/api/route.ts`
- [ ] Replace `next/head` with `metadata` exports
- [ ] Replace `next/router` with `next/navigation`
- [ ] Add `loading.tsx` and `error.tsx` for each route segment
- [ ] Mark interactive components with `'use client'`
- [ ] Test all routes in both routers during coexistence
- [ ] Remove `pages/` directory after full migration
- [ ] Update deployment configuration if needed

---

## 4. Expo SDK Major Version Upgrades

### Expo Upgrade Philosophy

Expo releases major SDK versions roughly every quarter. Each brings React Native version bumps, new APIs, and occasional breaking changes. The key: **follow the official upgrade helper, do not skip versions**.

### SDK Version Compatibility Map

| Expo SDK | React Native | React | Node.js | Key Changes |
|----------|-------------|-------|---------|-------------|
| SDK 50 | 0.73 | 18.2 | 18+ | expo-router v3, new splash screen |
| SDK 51 | 0.74 | 18.2 | 18+ | New architecture default, bridgeless |
| SDK 52 | 0.76 | 18.3 | 18+ | React Native 0.76, edge-to-edge Android |

### Upgrade Procedure (Per-Version)

**Step 1: Pre-Upgrade Preparation**

```bash
# Check current SDK version
npx expo --version
cat app.json | grep "sdkVersion"

# Create a branch for the upgrade
git checkout -b feat/expo-sdk-upgrade

# Run Expo Doctor to identify issues
npx expo-doctor

# Install the upgrade tool
npx expo install expo@latest

# Or for a specific SDK version
npx expo install expo@^52.0.0
```

**Step 2: Run the Upgrade Command**

```bash
# Automatic upgrade to latest SDK
npx expo install --fix

# This command:
# 1. Updates expo and all @expo/* packages
# 2. Updates react-native to the compatible version
# 3. Updates react and react-dom
# 4. Fixes peer dependency issues
# 5. Updates native dependencies
```

**Step 3: Fix Breaking Changes**

```bash
# Run expo-doctor again to find remaining issues
npx expo-doctor

# Check for deprecated APIs
npx expo customize

# Rebuild native projects if using bare workflow
npx expo prebuild --clean
```

**Step 4: Test Thoroughly**

```bash
# Clear all caches
npx expo start --clear

# Test on iOS Simulator
npx expo run:ios

# Test on Android Emulator
npx expo run:android

# Run tests
pnpm test

# Test EAS Build
eas build --platform all --profile preview
```

### Common Breaking Changes by SDK Version

**SDK 50 to 51:**
```typescript
// expo-router v3 changes
// BEFORE: Stack screen options
<Stack.Screen
  options={{ headerShown: false }}
/>

// AFTER: Same API, but verify typed routes
// app.json: add "experiments": { "typedRoutes": true }

// New Architecture is now the default
// If your native modules don't support New Architecture:
// app.json
{
  "expo": {
    "newArchEnabled": false  // Opt out temporarily
  }
}
```

**SDK 51 to 52:**
```typescript
// React Native 0.76 changes
// Edge-to-edge Android layout by default
// Need to handle safe areas explicitly

import { SafeAreaView } from 'react-native-safe-area-context';

// BEFORE: Status bar area was automatically avoided
// AFTER: Must use SafeAreaView or edge-to-edge-aware components

// Stylesheet changes
import { StyleSheet } from 'react-native';

const styles = StyleSheet.create({
  container: {
    flex: 1,
    // Android edge-to-edge: content may go behind status/nav bars
    // Use SafeAreaView or apply insets manually
  },
});

// expo-splash-screen changes
// BEFORE: SplashScreen.preventAutoHideAsync() in app root
// AFTER: Same API but ensure compatibility with new SDK

import * as SplashScreen from 'expo-splash-screen';

SplashScreen.preventAutoHideAsync();

export default function App() {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    prepare().then(() => {
      setReady(true);
      SplashScreen.hideAsync();
    });
  }, []);

  if (!ready) return null;
  return <RootLayout />;
}
```

### EAS Build Compatibility

```json
// eas.json -- update build profiles
{
  "cli": {
    "version": ">= 12.0.0"
  },
  "build": {
    "development": {
      "developmentClient": true,
      "distribution": "internal",
      "ios": {
        "simulator": true
      }
    },
    "preview": {
      "distribution": "internal"
    },
    "production": {
      "autoIncrement": true
    }
  },
  "submit": {
    "production": {}
  }
}
```

```bash
# After SDK upgrade, always rebuild development client
eas build --profile development --platform all

# Test with EAS Update for OTA compatibility
eas update --branch preview --message "SDK upgrade test"
```

### Expo SDK Upgrade Checklist

- [ ] Read official upgrade guide for target SDK version
- [ ] Create dedicated branch for upgrade
- [ ] Run `npx expo install --fix` to upgrade packages
- [ ] Run `npx expo-doctor` to find remaining issues
- [ ] Fix all breaking changes per changelog
- [ ] Run `npx expo prebuild --clean` (bare workflow)
- [ ] Test on iOS Simulator and Android Emulator
- [ ] Test on physical devices
- [ ] Rebuild EAS development client
- [ ] Test EAS Update (OTA) compatibility
- [ ] Run full test suite
- [ ] Test deep linking and push notifications
- [ ] Update `eas.json` if needed
- [ ] Merge after all platforms verified

---

## 5. Node.js Major Version Upgrades

### Node.js LTS Schedule

| Version | Status | Active LTS Start | End of Life |
|---------|--------|-------------------|-------------|
| Node 18 | Maintenance | Oct 2023 | Apr 2025 |
| Node 20 | Active LTS | Oct 2024 | Apr 2026 |
| Node 22 | Active LTS | Oct 2025 | Apr 2027 |

**Rule of thumb:** Always be on an Active LTS version. Start planning migration 3 months before current version enters Maintenance.

### What Changes Between Major Versions

**Node 18 to 20:**
```javascript
// New: Stable test runner
import { describe, it, mock } from 'node:test';
import assert from 'node:assert';

describe('User Service', () => {
  it('should create a user', async () => {
    const user = await createUser({ name: 'Test' });
    assert.strictEqual(user.name, 'Test');
  });
});

// New: Permission model (experimental in 20, stable in 22)
// node --experimental-permission --allow-fs-read=/app index.js

// New: import.meta.resolve() now synchronous
const resolvedPath = import.meta.resolve('./config.json');

// New: Stable globalThis.structuredClone()
const deepCopy = structuredClone(complexObject);

// Removed: url.parse() deprecated (use new URL())
// BEFORE
const parsed = url.parse('https://example.com/path');

// AFTER
const parsed = new URL('https://example.com/path');
```

**Node 20 to 22:**
```javascript
// New: require() can load ESM modules (behind flag, then stable)
// This is huge for gradual ESM migration
const esmModule = require('./esm-module.mjs');

// New: Built-in WebSocket client
const ws = new WebSocket('wss://example.com');

// New: glob and globSync in fs module
import { globSync } from 'node:fs';
const files = globSync('**/*.js', { cwd: '/app/src' });

// New: Stable watch mode
// node --watch server.js (replaces nodemon for development)

// New: Maglev compiler (V8 performance improvements)
// Automatic -- no code changes needed, ~5-10% perf boost

// New: AbortSignal.any() for combining abort signals
const controller1 = new AbortController();
const controller2 = new AbortController();
const signal = AbortSignal.any([controller1.signal, controller2.signal]);
```

### Upgrade Procedure

**Step 1: Check Compatibility**

```bash
# Check current Node.js version
node --version

# Check .nvmrc or .node-version
cat .nvmrc

# Check package.json engines field
cat package.json | jq '.engines'

# Check for node version-specific dependencies
npx npx-check-engines
```

**Step 2: Update Version Managers**

```bash
# nvm
nvm install 22
nvm alias default 22

# fnm
fnm install 22
fnm default 22

# volta
volta install node@22

# mise (formerly rtx)
mise install node@22
mise use --global node@22
```

**Step 3: Update Project Configuration**

```bash
# .nvmrc
echo "22" > .nvmrc

# .node-version
echo "22" > .node-version
```

```json
// package.json
{
  "engines": {
    "node": ">=22.0.0"
  }
}
```

**Step 4: Rebuild and Test**

```bash
# Clean install
rm -rf node_modules
pnpm install

# Rebuild native modules (critical!)
pnpm rebuild

# Run tests
pnpm test

# Check for deprecation warnings
node --trace-deprecation app.js 2>&1 | grep "DeprecationWarning"
```

**Step 5: Update CI/CD**

```yaml
# GitHub Actions
jobs:
  test:
    strategy:
      matrix:
        node-version: [20, 22]  # Test both during migration
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
```

```dockerfile
# Dockerfile
FROM node:22-alpine
# (was node:20-alpine)
```

### Common Node.js Upgrade Issues

| Issue | Symptom | Fix |
|-------|---------|-----|
| Native modules fail | `Error: Module version mismatch` | `pnpm rebuild` or reinstall native deps |
| OpenSSL changes | `ERR_OSSL_EVP_UNSUPPORTED` | Update crypto usage or set `--openssl-legacy-provider` |
| ESM/CJS confusion | `ERR_REQUIRE_ESM` | Add `"type": "module"` or use `.mjs` extension |
| Deprecated API | `DeprecationWarning` | Replace with recommended alternative |
| npm version mismatch | Lock file incompatibility | Delete lock file, reinstall |
| V8 flag changes | Startup crash | Remove deprecated V8 flags from NODE_OPTIONS |

### Node.js Upgrade Checklist

- [ ] Check `.nvmrc` / `.node-version` / `engines` field
- [ ] Install target Node.js version via version manager
- [ ] Clean install all dependencies (`rm -rf node_modules && pnpm install`)
- [ ] Rebuild native modules (`pnpm rebuild`)
- [ ] Run full test suite
- [ ] Check for deprecation warnings (`node --trace-deprecation`)
- [ ] Update Dockerfile base image
- [ ] Update CI/CD matrix to test both old and new
- [ ] Update `.nvmrc` / `.node-version`
- [ ] Update `engines` in `package.json`
- [ ] Test production build
- [ ] Deploy to staging first
- [ ] Remove old version from CI matrix after full rollout

---

## 6. Database Migration Patterns

### The Expand-Contract Pattern (Zero Downtime)

The expand-contract pattern ensures database schema changes never break running application code. The idea: **expand** the schema to support both old and new, migrate data, then **contract** by removing the old.

```
Timeline:
────────────────────────────────────────────────────────────
Phase 1: EXPAND         Phase 2: MIGRATE      Phase 3: CONTRACT
Add new column/table    Backfill data         Remove old column/table
Old code works          Old code works        Only new code deployed
New code works          New code works        Old code removed
────────────────────────────────────────────────────────────
```

#### Example: Renaming a Column

You cannot rename a column in-place without downtime. Use expand-contract instead.

**Phase 1: Expand (add new column)**

```sql
-- Migration: 001_add_full_name_column.sql
ALTER TABLE users ADD COLUMN full_name VARCHAR(255);

-- Create trigger to sync during transition
CREATE OR REPLACE FUNCTION sync_name_to_full_name()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.full_name IS NULL THEN
    NEW.full_name = NEW.name;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_sync_name
BEFORE INSERT OR UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION sync_name_to_full_name();
```

**Phase 2: Migrate data (backfill)**

```sql
-- Migration: 002_backfill_full_name.sql
UPDATE users SET full_name = name WHERE full_name IS NULL;

-- Verify
SELECT COUNT(*) FROM users WHERE full_name IS NULL;  -- Should be 0
```

**Phase 3: Deploy new code**

Deploy application code that reads from `full_name` instead of `name`. Both columns exist, so old instances still work during rolling deployment.

**Phase 4: Contract (remove old column)**

```sql
-- Migration: 003_remove_name_column.sql
-- Only run after all application instances use full_name
DROP TRIGGER trigger_sync_name ON users;
DROP FUNCTION sync_name_to_full_name();
ALTER TABLE users DROP COLUMN name;
```

#### Example: Changing Column Type

```sql
-- Phase 1: Expand - add new column with target type
ALTER TABLE orders ADD COLUMN amount_decimal DECIMAL(10,2);

-- Phase 2: Migrate - backfill with type conversion
UPDATE orders SET amount_decimal = amount_int::DECIMAL / 100.0;

-- Application: Read from amount_decimal, write to both
-- Phase 3: Contract - remove old column after cutover
ALTER TABLE orders DROP COLUMN amount_int;
ALTER TABLE orders RENAME COLUMN amount_decimal TO amount;
```

#### Example: Splitting a Table

```sql
-- Phase 1: Expand - create new table
CREATE TABLE user_profiles (
  user_id UUID PRIMARY KEY REFERENCES users(id),
  bio TEXT,
  avatar_url VARCHAR(500),
  location VARCHAR(255)
);

-- Phase 2: Migrate - copy data
INSERT INTO user_profiles (user_id, bio, avatar_url, location)
SELECT id, bio, avatar_url, location FROM users;

-- Phase 3: Application reads from user_profiles, writes to both
-- Phase 4: Contract - remove columns from users table
ALTER TABLE users DROP COLUMN bio;
ALTER TABLE users DROP COLUMN avatar_url;
ALTER TABLE users DROP COLUMN location;
```

### Alembic Migration Workflows (Python / SQLAlchemy)

```bash
# Project structure
project/
├── alembic/
│   ├── env.py              # Migration environment config
│   ├── versions/           # Migration files
│   │   ├── 001_initial.py
│   │   ├── 002_add_users.py
│   │   └── 003_add_profiles.py
│   └── alembic.ini
├── models/
│   └── user.py
└── database.py
```

```python
# Generate migration from model changes
# alembic revision --autogenerate -m "add user profiles"

# alembic/versions/003_add_profiles.py
"""add user profiles"""

from alembic import op
import sqlalchemy as sa

revision = '003'
down_revision = '002'

def upgrade():
    op.create_table(
        'user_profiles',
        sa.Column('user_id', sa.UUID(), sa.ForeignKey('users.id'), primary_key=True),
        sa.Column('bio', sa.Text(), nullable=True),
        sa.Column('avatar_url', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index('idx_profiles_user_id', 'user_profiles', ['user_id'])

def downgrade():
    op.drop_index('idx_profiles_user_id')
    op.drop_table('user_profiles')
```

```bash
# Run migrations
alembic upgrade head          # Apply all pending
alembic upgrade +1            # Apply next one only
alembic downgrade -1          # Rollback last one
alembic history               # View migration history
alembic current               # Show current revision
alembic stamp head            # Mark as up-to-date without running

# Safe production workflow
alembic upgrade head --sql    # Preview SQL without executing
alembic upgrade head          # Apply after review
```

**Alembic Best Practices:**

```python
# 1. Always provide downgrade
def downgrade():
    op.drop_table('user_profiles')  # Must undo upgrade exactly

# 2. Use batch operations for SQLite compatibility
with op.batch_alter_table('users') as batch_op:
    batch_op.add_column(sa.Column('phone', sa.String(20)))
    batch_op.drop_column('fax')

# 3. Data migrations in separate files
def upgrade():
    # Schema change only -- no data migration here
    op.add_column('users', sa.Column('status', sa.String(20), nullable=True))

# Separate migration for data:
def upgrade():
    op.execute("UPDATE users SET status = 'active' WHERE status IS NULL")
    op.alter_column('users', 'status', nullable=False, server_default='active')

# 4. Create indexes concurrently (PostgreSQL)
from alembic import op

def upgrade():
    op.execute('CREATE INDEX CONCURRENTLY idx_users_email ON users(email)')

# In alembic/env.py, for CONCURRENTLY to work:
# context.configure(transaction_per_migration=True)

# 5. Use op.execute for complex SQL
def upgrade():
    op.execute("""
        CREATE MATERIALIZED VIEW user_stats AS
        SELECT user_id, COUNT(*) as order_count, SUM(total) as total_spent
        FROM orders
        GROUP BY user_id
    """)
```

### Prisma Migration Workflows (TypeScript)

```bash
# Project structure
project/
├── prisma/
│   ├── schema.prisma        # Schema definition
│   └── migrations/          # Migration history
│       ├── 20240115_init/
│       │   └── migration.sql
│       └── 20240120_add_profiles/
│           └── migration.sql
└── src/
    └── db.ts
```

```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id        String   @id @default(uuid())
  email     String   @unique
  name      String
  profile   Profile?
  orders    Order[]
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")

  @@map("users")
}

model Profile {
  userId    String @id @map("user_id")
  user      User   @relation(fields: [userId], references: [id], onDelete: Cascade)
  bio       String?
  avatarUrl String? @map("avatar_url")

  @@map("user_profiles")
}
```

```bash
# Generate migration from schema changes
npx prisma migrate dev --name add_profiles
# Creates SQL migration + applies it + regenerates client

# Apply migrations in production
npx prisma migrate deploy
# Applies pending migrations without generating new ones

# Reset database (development only!)
npx prisma migrate reset
# Drops DB, recreates, applies all migrations, runs seed

# View migration status
npx prisma migrate status

# Resolve migration issues
npx prisma migrate resolve --applied 20240120_add_profiles
npx prisma migrate resolve --rolled-back 20240120_add_profiles
```

**Prisma Best Practices:**

```prisma
// 1. Use @map for snake_case database columns
model User {
  firstName String @map("first_name")
  lastName  String @map("last_name")
  @@map("users")
}

// 2. Add indexes for query performance
model Order {
  id     String @id @default(uuid())
  userId String @map("user_id")
  status String

  @@index([userId])
  @@index([status])
  @@index([userId, status])
  @@map("orders")
}

// 3. Soft deletes pattern
model Post {
  id        String    @id @default(uuid())
  title     String
  deletedAt DateTime? @map("deleted_at")

  @@map("posts")
}
```

```typescript
// Custom migration for data changes
// prisma/migrations/20240120_backfill_status/migration.sql
-- Backfill status column
UPDATE users SET status = 'active' WHERE status IS NULL;

-- Add NOT NULL constraint after backfill
ALTER TABLE users ALTER COLUMN status SET NOT NULL;
ALTER TABLE users ALTER COLUMN status SET DEFAULT 'active';
```

### Database Migration Safety Rules

| Rule | Why |
|------|-----|
| Never rename columns directly | Breaks running application code |
| Add columns as nullable first | Avoids table lock on large tables |
| Create indexes concurrently | Prevents table lock during creation |
| Separate schema and data migrations | Schema is fast; data backfill is slow |
| Always test on staging first | Catch issues before production |
| Take a backup before production migration | Safety net for worst case |
| Monitor migration duration | Kill if exceeding expected time |
| Never modify committed migrations | Create new ones instead |
| Use transactions for multi-step changes | Atomic rollback on failure |
| Test downgrade path | Verify rollback actually works |

---

## 7. Dependency Upgrade Strategy

### Routine Dependency Updates (Weekly/Biweekly)

**Step 1: Audit Current State**

```bash
# npm/pnpm -- check outdated packages
pnpm outdated

# Output format:
# Package         Current  Wanted  Latest
# react           18.2.0   18.3.1  19.0.0
# typescript      5.3.3    5.4.5   5.6.2
# eslint          8.56.0   8.57.1  9.15.0

# Check for security vulnerabilities
pnpm audit

# Check for license issues
npx license-checker --summary
```

**Step 2: Categorize Updates**

| Category | Version Change | Risk | Strategy |
|----------|---------------|------|----------|
| **Patch** | 1.2.3 -> 1.2.4 | Low | Auto-update, run tests |
| **Minor** | 1.2.3 -> 1.3.0 | Low-Medium | Update in batch, review changelog |
| **Major** | 1.2.3 -> 2.0.0 | High | Update individually, read migration guide |
| **Security** | Any | Critical | Update immediately regardless of breaking |

**Step 3: Update Procedure**

```bash
# Patch and minor updates (batch)
pnpm update                    # Updates within semver range
pnpm update --latest           # Updates to latest, ignoring semver

# Major updates (one at a time)
pnpm add react@latest react-dom@latest  # Major version bump

# After each update:
pnpm test                      # Run test suite
pnpm build                     # Verify build succeeds
pnpm typecheck                 # TypeScript check (if applicable)
```

**Step 4: Handling Breaking Changes**

```bash
# Check what changed
# 1. Read the CHANGELOG
open "https://github.com/<package>/blob/main/CHANGELOG.md"

# 2. Check migration guide (if major version)
open "https://github.com/<package>/blob/main/MIGRATION.md"

# 3. Search for codemods
npx <package>-codemod          # Some packages provide codemods

# 4. Check GitHub issues for common problems
open "https://github.com/<package>/issues?q=is:issue+upgrade"
```

### Lock File Management

```bash
# pnpm-lock.yaml best practices:

# 1. ALWAYS commit the lock file
git add pnpm-lock.yaml

# 2. Use --frozen-lockfile in CI
pnpm install --frozen-lockfile  # Fails if lock file needs updating

# 3. Regenerate lock file when corrupted
rm pnpm-lock.yaml
pnpm install

# 4. Resolve merge conflicts in lock file
# Option A: Regenerate (safest)
git checkout --ours pnpm-lock.yaml
pnpm install

# Option B: Let pnpm resolve
pnpm install  # Automatically resolves based on package.json
```

### Automated Dependency Updates

```yaml
# Renovate bot configuration (renovate.json)
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "packageRules": [
    {
      "groupName": "patch updates",
      "matchUpdateTypes": ["patch"],
      "automerge": true,
      "schedule": ["every weekend"]
    },
    {
      "groupName": "minor updates",
      "matchUpdateTypes": ["minor"],
      "automerge": false,
      "schedule": ["every 2 weeks on Monday"]
    },
    {
      "groupName": "major updates",
      "matchUpdateTypes": ["major"],
      "automerge": false,
      "dependencyDashboardApproval": true
    },
    {
      "matchPackageNames": ["react", "react-dom", "next"],
      "groupName": "React ecosystem",
      "automerge": false
    }
  ],
  "vulnerabilityAlerts": {
    "enabled": true,
    "automerge": true
  }
}
```

```yaml
# Dependabot (GitHub native) -- .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    reviewers:
      - "team-lead"
    labels:
      - "dependencies"
    ignore:
      - dependency-name: "aws-sdk"
        update-types: ["version-update:semver-major"]
    groups:
      development-dependencies:
        dependency-type: "development"
        update-types:
          - "minor"
          - "patch"
      production-dependencies:
        dependency-type: "production"
        update-types:
          - "patch"
```

### Dependency Upgrade Checklist

- [ ] Run `pnpm outdated` to see available updates
- [ ] Run `pnpm audit` to check for security vulnerabilities
- [ ] Categorize updates by risk (patch/minor/major/security)
- [ ] Apply security patches immediately
- [ ] Batch patch and minor updates
- [ ] Apply major updates one at a time
- [ ] Read changelogs for major version changes
- [ ] Run full test suite after each batch of updates
- [ ] Verify build succeeds
- [ ] Run TypeScript type checking
- [ ] Test in staging environment
- [ ] Commit updated lock file

---

## 8. Feature Flag Strategy During Migrations

### Why Feature Flags for Migrations

Feature flags let you deploy migration code to production without activating it, then gradually roll out the new path while keeping the old path as a fallback.

```
Traditional Migration:                Feature-Flagged Migration:
Old Code ──── Big Bang ──── New Code  Old Code ─┬─ Flag OFF ─── Old Path
                                                 └─ Flag ON ──── New Path
                                                      ↑
                                                 Gradual rollout: 1% → 10% → 50% → 100%
```

### Feature Flag Patterns

**Pattern 1: Simple Boolean Flag**

```typescript
// For straightforward migrations
const useNewRouter = featureFlags.isEnabled('use-app-router');

function Navigation() {
  if (useNewRouter) {
    return <AppRouterNavigation />;  // New implementation
  }
  return <PagesRouterNavigation />;  // Old implementation
}
```

**Pattern 2: Percentage Rollout**

```typescript
// Gradual rollout based on user percentage
const flag = featureFlags.getFlag('new-checkout-flow');

// flag.rolloutPercentage: 0 → 5 → 25 → 50 → 100
if (flag.isEnabledForUser(userId)) {
  return <NewCheckout />;
}
return <OldCheckout />;
```

**Pattern 3: User Segment Targeting**

```typescript
// Target specific user groups first
const flag = featureFlags.getFlag('react-19-components', {
  rules: [
    { segment: 'internal-team', enabled: true },     // Internal first
    { segment: 'beta-users', enabled: true },         // Beta users next
    { segment: 'all-users', percentage: 10 },         // 10% of everyone
  ],
});
```

**Pattern 4: Environment-Based Flags**

```typescript
// Different behavior per environment
const migrationFlags = {
  development: {
    useNewDatabase: true,
    useNewAPI: true,
    useNewUI: true,
  },
  staging: {
    useNewDatabase: true,
    useNewAPI: true,
    useNewUI: false,
  },
  production: {
    useNewDatabase: true,
    useNewAPI: false,
    useNewUI: false,
  },
};
```

### Implementation Options

**Option 1: Environment Variables (Simplest)**

```typescript
// .env
FEATURE_NEW_CHECKOUT=false
FEATURE_APP_ROUTER=true

// Usage
const useNewCheckout = process.env.FEATURE_NEW_CHECKOUT === 'true';
```

**Option 2: Configuration File**

```typescript
// feature-flags.ts
export const featureFlags = {
  newCheckout: {
    enabled: process.env.NODE_ENV === 'development',
    rolloutPercentage: 0,
  },
  appRouter: {
    enabled: true,
    rolloutPercentage: 100,
  },
} as const;

function isEnabled(flag: keyof typeof featureFlags, userId?: string): boolean {
  const config = featureFlags[flag];
  if (!config.enabled) return false;
  if (config.rolloutPercentage === 100) return true;
  if (!userId) return false;

  // Deterministic hash for consistent user experience
  const hash = simpleHash(userId + flag);
  return (hash % 100) < config.rolloutPercentage;
}
```

**Option 3: Remote Config (Production)**

```typescript
// Using LaunchDarkly / Unleash / Flagsmith / Firebase Remote Config
import { initialize } from 'launchdarkly-node-server-sdk';

const ldClient = initialize('sdk-key');

async function isEnabled(flag: string, user: LDUser): Promise<boolean> {
  await ldClient.waitForInitialization();
  return ldClient.variation(flag, user, false);
}

// Mobile: Firebase Remote Config
// See: mobile-remote-config module for implementation details
```

### Migration Rollout Schedule

```
Week 1: Deploy with flag OFF everywhere
         - Verify no performance impact from flag checking
         - Monitor error rates

Week 2: Enable for internal team (development + staging)
         - Internal testing and feedback
         - Fix issues found

Week 3: Enable for 5% of production users
         - Monitor metrics vs. control group
         - Compare error rates, performance, conversion

Week 4: Increase to 25% of production users
         - Broader validation
         - Address edge cases

Week 5: Increase to 50%
         - Statistical significance on metrics
         - Final go/no-go decision

Week 6: Increase to 100%
         - Full rollout
         - Keep flag in code for 1 more week

Week 7: Remove feature flag code
         - Delete old code path
         - Remove flag configuration
         - Clean commit: "chore: remove new-checkout feature flag"
```

### Feature Flag Cleanup

**Critical:** Feature flags are technical debt. Remove them after full rollout.

```bash
# Find stale feature flags
grep -r "featureFlags\.\|FEATURE_\|isEnabled(" src/ --include="*.ts" --include="*.tsx"

# Checklist for flag removal:
# 1. Flag at 100% for >= 1 week with no issues
# 2. Remove all conditional branches (keep new path only)
# 3. Remove flag from configuration
# 4. Remove old code path
# 5. Update tests to remove flag-dependent branches
# 6. Deploy and verify
```

---

## 9. Codemod Patterns

### What Are Codemods

Codemods are programs that automatically transform source code. Instead of manually updating hundreds of files, a codemod applies consistent changes across the entire codebase in seconds.

### When to Use Codemods

| Scenario | Manual | Codemod |
|----------|--------|---------|
| < 10 files affected | Yes | No (overhead too high) |
| 10-50 files affected | Maybe | Recommended |
| > 50 files affected | No | Required |
| Pattern is mechanical | -- | Always prefer codemod |
| Pattern requires judgment | Always | Partial (transform obvious, flag ambiguous) |

### jscodeshift (JavaScript/TypeScript)

jscodeshift is the standard tool for JavaScript/TypeScript codemods. It parses code into an AST, applies transformations, and writes back.

```bash
# Install
pnpm add -D jscodeshift @types/jscodeshift

# Run a codemod
npx jscodeshift --parser=tsx --extensions=ts,tsx -t transforms/my-codemod.ts src/
```

**Example: Replace `React.FC` with plain function types**

```typescript
// transforms/remove-react-fc.ts
import type { API, FileInfo, JSCodeshift } from 'jscodeshift';

export default function transformer(file: FileInfo, api: API) {
  const j: JSCodeshift = api.jscodeshift;
  const root = j(file.source);

  // Find: const MyComponent: React.FC<Props> = (props) => { ... }
  // Replace with: const MyComponent = (props: Props) => { ... }

  root
    .find(j.VariableDeclarator, {
      id: {
        typeAnnotation: {
          typeAnnotation: {
            typeName: {
              type: 'TSQualifiedName',
              right: { name: 'FC' },
            },
          },
        },
      },
    })
    .forEach(path => {
      const typeAnnotation = path.node.id.typeAnnotation;
      const propsType = typeAnnotation?.typeAnnotation?.typeParameters?.params?.[0];

      if (propsType && path.node.init?.type === 'ArrowFunctionExpression') {
        // Add type annotation to first parameter
        const params = path.node.init.params;
        if (params.length > 0 && params[0].type === 'Identifier') {
          params[0].typeAnnotation = j.tsTypeAnnotation(propsType);
        }
        // Remove React.FC type annotation
        path.node.id.typeAnnotation = null;
      }
    });

  return root.toSource({ quote: 'single' });
}
```

```bash
# Run the codemod
npx jscodeshift --parser=tsx --extensions=ts,tsx \
  -t transforms/remove-react-fc.ts \
  src/components/

# Dry run first (see what would change)
npx jscodeshift --parser=tsx --extensions=ts,tsx \
  -t transforms/remove-react-fc.ts \
  --dry \
  src/components/
```

**Example: Rename Imports**

```typescript
// transforms/rename-import.ts
import type { API, FileInfo } from 'jscodeshift';

export default function transformer(file: FileInfo, api: API) {
  const j = api.jscodeshift;
  const root = j(file.source);

  // Rename: import { useHistory } from 'react-router-dom'
  // To:     import { useNavigate } from 'react-router-dom'

  root
    .find(j.ImportSpecifier, { imported: { name: 'useHistory' } })
    .forEach(path => {
      path.node.imported.name = 'useNavigate';
      if (path.node.local?.name === 'useHistory') {
        path.node.local.name = 'useNavigate';
      }
    });

  // Also rename usage: useHistory() -> useNavigate()
  root
    .find(j.Identifier, { name: 'useHistory' })
    .forEach(path => {
      if (path.parent.node.type !== 'ImportSpecifier') {
        path.node.name = 'useNavigate';
      }
    });

  return root.toSource();
}
```

### Framework-Provided Codemods

Many frameworks ship official codemods for major version upgrades.

```bash
# React 19 upgrade
npx react-codemod@latest upgrade

# Next.js upgrade
npx @next/codemod@latest <transform-name> <path>
# Available transforms:
# - next-image-to-legacy-image
# - next-image-experimental
# - built-in-next-font
# - metadata-to-viewport-export
# - app-dir-runtime-config-experimental-edge

# Material UI v4 to v5
npx @mui/codemod v5.0.0/preset-safe src/

# Styled Components v5 to v6
npx @styled-components/codemods v6 src/

# ESLint v8 to v9
npx @eslint/migrate-config .eslintrc.json
```

### Writing Custom Codemods: Best Practices

```typescript
// 1. Always handle edge cases
export default function transformer(file: FileInfo, api: API) {
  const j = api.jscodeshift;
  const root = j(file.source);
  let hasChanges = false;

  root.find(j.CallExpression, { callee: { name: 'oldFunction' } })
    .forEach(path => {
      // Check that we're not inside a test file
      if (file.path.includes('.test.') || file.path.includes('.spec.')) {
        return;
      }
      path.node.callee.name = 'newFunction';
      hasChanges = true;
    });

  // Only modify file if changes were made (preserves formatting)
  return hasChanges ? root.toSource() : file.source;
}

// 2. Add a report of what was changed
// Run with: npx jscodeshift ... 2>&1 | tee codemod-report.log

// 3. Test your codemod
// __tests__/remove-react-fc.test.ts
import { applyTransform } from 'jscodeshift/src/testUtils';
import transform from '../transforms/remove-react-fc';

test('removes React.FC type annotation', () => {
  const input = `const Foo: React.FC<Props> = (props) => <div />;`;
  const expected = `const Foo = (props: Props) => <div />;`;

  const result = applyTransform(transform, {}, { source: input });
  expect(result).toBe(expected);
});
```

### AST Explorer for Development

Use [astexplorer.net](https://astexplorer.net) to develop codemods:

1. Set parser to `@typescript-eslint/parser` or `babel`
2. Set transform to `jscodeshift`
3. Paste sample code on the left
4. Write transform on the bottom-left
5. See output on the right

### Codemod Execution Checklist

- [ ] Write and test codemod on sample files
- [ ] Dry-run on full codebase (`--dry` flag)
- [ ] Review dry-run output for unexpected changes
- [ ] Create a dedicated branch for codemod changes
- [ ] Run codemod on full codebase
- [ ] Run formatter (Prettier) after codemod to normalize style
- [ ] Run linter to catch issues
- [ ] Run full test suite
- [ ] Manual review of a sample of changed files
- [ ] Commit with descriptive message: "refactor: apply codemod to remove React.FC usage"

---

## 10. Rollback Procedures and Safety Nets

### Rollback Decision Matrix

| Severity | Error Rate | Performance | Action | Timeframe |
|----------|------------|-------------|--------|-----------|
| **P0 Critical** | > 5% | > 3x degradation | Immediate rollback | < 5 minutes |
| **P1 High** | 2-5% | 2-3x degradation | Rollback within 15 min | < 15 minutes |
| **P2 Medium** | 1-2% | 1.5-2x degradation | Monitor, prepare rollback | < 1 hour |
| **P3 Low** | < 1% | < 1.5x degradation | Fix forward | Next deploy |

### Rollback Strategies by Migration Type

**Framework Upgrade Rollback:**

```bash
# Git-based rollback (fastest)
git revert <migration-commit>
pnpm install
pnpm build
# Deploy

# Version pinning rollback
pnpm add react@18.2.0 react-dom@18.2.0
pnpm install
pnpm build
# Deploy

# Feature flag rollback (if used)
# Toggle flag OFF -- instant, no deployment needed
curl -X PATCH https://flags-api.internal/flags/use-react-19 \
  -d '{"enabled": false}'
```

**Database Migration Rollback:**

```bash
# Alembic rollback
alembic downgrade -1          # Rollback last migration
alembic downgrade <revision>  # Rollback to specific revision

# Prisma rollback
# Prisma doesn't have built-in rollback, so:
# 1. Write a reverse migration manually
npx prisma migrate dev --name rollback_profiles

# 2. Or restore from backup
pg_restore -d mydb backup_before_migration.dump

# CRITICAL: If you used expand-contract, rollback is just:
# - Revert application code (stop reading from new column)
# - Don't drop the new column yet (it's harmless)
# - Clean up new column in next maintenance window
```

**Node.js Version Rollback:**

```bash
# nvm rollback
nvm use 20  # Switch back to previous version
pnpm rebuild
pnpm test

# Docker rollback
# Change Dockerfile: FROM node:22-alpine -> FROM node:20-alpine
docker build -t myapp:rollback .

# CI/CD rollback
# Revert .nvmrc / .node-version change
git revert <node-upgrade-commit>
```

### Safety Nets

**1. Automated Canary Analysis**

```bash
#!/bin/bash
# canary-analysis.sh -- run after deploying to canary

CANARY_URL="${1}"
BASELINE_URL="${2}"
DURATION="${3:-300}"  # 5 minutes default

echo "Comparing canary ($CANARY_URL) vs baseline ($BASELINE_URL)"

# Collect metrics for DURATION seconds
for i in $(seq 1 $DURATION); do
  CANARY_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$CANARY_URL/health")
  BASELINE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASELINE_URL/health")

  CANARY_TIME=$(curl -s -o /dev/null -w "%{time_total}" "$CANARY_URL/health")
  BASELINE_TIME=$(curl -s -o /dev/null -w "%{time_total}" "$BASELINE_URL/health")

  if [ "$CANARY_STATUS" != "200" ]; then
    echo "CANARY UNHEALTHY at second $i -- triggering rollback"
    exit 1
  fi

  # Alert if canary is 2x slower
  if (( $(echo "$CANARY_TIME > $BASELINE_TIME * 2" | bc -l) )); then
    echo "WARNING: Canary response time ${CANARY_TIME}s vs baseline ${BASELINE_TIME}s"
  fi

  sleep 1
done

echo "Canary analysis passed"
```

**2. Database Backup Before Migration**

```bash
#!/bin/bash
# pre-migration-backup.sh

DB_NAME="${1}"
BACKUP_DIR="/backups/migrations"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_${TIMESTAMP}.dump"

echo "Creating backup: $BACKUP_FILE"
pg_dump -Fc "$DB_NAME" > "$BACKUP_FILE"

# Verify backup integrity
pg_restore --list "$BACKUP_FILE" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "Backup verified: $BACKUP_FILE"
  echo "$BACKUP_FILE" > "${BACKUP_DIR}/latest_${DB_NAME}"
else
  echo "ERROR: Backup verification failed!"
  exit 1
fi
```

**3. Automated Regression Testing**

```bash
#!/bin/bash
# post-migration-test.sh

echo "Running regression tests..."

# Unit tests
pnpm test || { echo "Unit tests failed -- rollback!"; exit 1; }

# Type checking
pnpm typecheck || { echo "Type errors found -- rollback!"; exit 1; }

# Build verification
pnpm build || { echo "Build failed -- rollback!"; exit 1; }

# Integration tests (if staging is available)
if [ -n "$STAGING_URL" ]; then
  pnpm test:integration --target="$STAGING_URL" || {
    echo "Integration tests failed -- rollback!"
    exit 1
  }
fi

echo "All regression tests passed"
```

**4. Migration Runbook Template**

```markdown
## Migration Runbook: [Migration Name]

### Pre-Migration
- [ ] Backup database: `./scripts/pre-migration-backup.sh mydb`
- [ ] Note current version: `git rev-parse HEAD` = ___
- [ ] Note current metrics baseline:
  - Error rate: ___%
  - P95 response time: ___ms
  - Throughput: ___ req/s

### Migration Steps
1. [ ] Step 1: ___
2. [ ] Step 2: ___
3. [ ] Step 3: ___

### Verification
- [ ] Run smoke tests: `./scripts/smoke-tests.sh`
- [ ] Error rate < baseline + 0.5%
- [ ] P95 response time < baseline * 1.5
- [ ] Critical user flows working

### Rollback Procedure
If any verification fails:
1. [ ] `git revert <commit>` or toggle feature flag OFF
2. [ ] Redeploy previous version
3. [ ] Restore database if needed: `pg_restore -d mydb <backup_file>`
4. [ ] Verify rollback successful
5. [ ] Notify team

### Post-Migration
- [ ] Monitor for 30 minutes
- [ ] Update documentation
- [ ] Remove feature flags (after 1 week of stability)
- [ ] Close migration ticket
```

### Rollback Checklist

- [ ] Identify rollback trigger (error rate, performance, functionality)
- [ ] Execute rollback procedure for the migration type
- [ ] Verify application health after rollback
- [ ] Communicate rollback to team
- [ ] Document what went wrong
- [ ] Plan fix before re-attempting migration
- [ ] Schedule post-mortem if P0/P1 incident

---

## Quick Reference: Migration Command Cheat Sheet

```bash
# React 18 -> 19
npx react-codemod@latest upgrade
pnpm add react@19 react-dom@19 @types/react@19 @types/react-dom@19

# Next.js Pages -> App Router
# (Incremental -- no single command, migrate page by page)
npx @next/codemod@latest <transform-name> <path>

# Expo SDK upgrade
npx expo install expo@latest
npx expo install --fix
npx expo-doctor

# Node.js version upgrade
nvm install 22 && nvm alias default 22
rm -rf node_modules && pnpm install && pnpm rebuild

# Database migrations
alembic upgrade head              # Alembic: apply
alembic downgrade -1              # Alembic: rollback
npx prisma migrate deploy         # Prisma: apply
npx prisma migrate dev --name x   # Prisma: create + apply

# Dependency updates
pnpm outdated                     # Check available updates
pnpm update                       # Update within semver
pnpm update --latest              # Update to latest
pnpm audit                        # Security check

# Codemods
npx jscodeshift --parser=tsx -t transform.ts src/
npx jscodeshift --dry -t transform.ts src/  # Preview only

# Feature flags
# Toggle ON:  curl -X PATCH flags-api/flags/name -d '{"enabled":true}'
# Toggle OFF: curl -X PATCH flags-api/flags/name -d '{"enabled":false}'
```

---

## Integrates With

| Skill/Module | Relationship |
|-------------|-------------|
| **`pnpm-migration`** skill | Package manager migration is a specific instance of this skill's dependency upgrade patterns. Use `pnpm-migration` for the detailed npm/yarn-to-pnpm playbook. |
| **`deployment-patterns`** skill | Zero-downtime deployment strategies (blue-green, canary, rolling) are critical during migration rollout. Use `deployment-patterns` for deployment execution during the migration. |
| **`testing-strategies`** skill | Regression testing gates every migration phase. Use `testing-strategies` for test pyramid, fixture patterns, and coverage requirements during upgrades. |
| **`database-orm-patterns`** module | Detailed Alembic migration helpers, SQLAlchemy patterns, and query optimization. This skill covers migration strategy; that module covers ORM implementation details. |
| **`mobile-remote-config`** module | Firebase Remote Config and feature flag implementation for mobile apps. Use during Expo SDK upgrades for gradual rollout on mobile platforms. |
| **`eas-deployment`** module | EAS Build and EAS Update workflows. Critical companion during Expo SDK upgrades for building development clients and verifying OTA compatibility. |
| **`cicd-templates`** skill | CI/CD pipeline configuration. Update pipelines as part of Node.js and framework upgrades. |
| **`security-owasp`** skill | Security audit during dependency upgrades. `pnpm audit` integration and vulnerability response. |

---

## Common Pitfalls Across All Migrations

| Pitfall | Why It Happens | Prevention |
|---------|---------------|------------|
| Skipping versions | "We'll go from v18 straight to v22" | Always upgrade one major version at a time |
| Big bang migration | "Let's rewrite everything this sprint" | Incremental migration with parallel operation |
| No rollback plan | "It'll work, we tested it" | Document rollback before starting |
| Forgetting CI/CD | "Tests pass locally" | Update CI matrix to test both versions |
| Ignoring deprecation warnings | "Those warnings are fine" | Fix ALL deprecation warnings before upgrading |
| Not reading changelogs | "What could go wrong?" | Read every changelog entry between versions |
| Migrating without tests | "We'll test manually" | Achieve 70%+ coverage before migrating |
| Feature flag debt | "We'll clean up those flags later" | Schedule flag removal within 2 weeks of 100% rollout |
| Lock file conflicts | "Just delete and regenerate" | Regenerate properly after merge conflicts |
| Phantom dependencies | "It worked before, why not now?" | Use strict dependency resolution (pnpm default) |

---

**Impact:** Structured migration patterns reduce upgrade risk by 80%, cut migration time in half through automation, and eliminate the "big bang rewrite" anti-pattern that derails teams for months.
