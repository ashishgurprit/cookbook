# Wix App Framework - Production Guide

**Build, deploy, and monetize Wix marketplace apps with React, TypeScript, and external backends.**

Version: 1.0.0
Status: Production Ready
Extracted From: `social-media-autopost-plugin/wix/`

---

## Table of Contents

1. [Overview](#overview)
2. [Module Dependency Diagram](#module-dependency-diagram)
3. [Quick Start (React + TypeScript)](#quick-start-react--typescript)
4. [Wix CLI Setup](#wix-cli-setup)
5. [OAuth & Authentication](#oauth--authentication)
6. [Dashboard Pages](#dashboard-pages)
7. [Wix Data API Patterns](#wix-data-api-patterns)
8. [Billing & Subscriptions](#billing--subscriptions)
9. [Wix Blocks (Custom UI Components)](#wix-blocks-custom-ui-components)
10. [Deployment & Publishing](#deployment--publishing)
11. [Environment Variables](#environment-variables)
12. [Integrates With](#integrates-with)

---

## Overview

This skill covers the complete lifecycle of building a Wix App Market application using two architectural approaches:

1. **Wix Native** -- Uses the Wix CLI (`@wix/cli`), Wix Design System, and Wix backend (Velo). Best for simple apps that live entirely within the Wix ecosystem.

2. **External Dashboard** -- Uses a custom React + Vite frontend and a Node.js + Fastify backend, embedded into the Wix dashboard via iframe. Best for complex apps needing full control over UI, database, and business logic.

### When to Use Each Architecture

| Factor | Wix Native | External Dashboard |
|--------|-----------|-------------------|
| **UI Complexity** | Simple forms, settings | Complex dashboards, real-time updates |
| **Backend Logic** | Wix Velo (sandboxed JS) | Full Node.js, any framework |
| **Database** | Wix Data Collections | PostgreSQL, MongoDB, any DB |
| **Authentication** | Wix-managed | Wix Instance Token + custom auth |
| **Billing** | Wix Paid Plans API | Wix Paid Plans + custom billing |
| **Deployment** | `wix publish` | Self-hosted (Hetzner, Railway, Vercel) |
| **Cost** | Free (Wix-hosted) | Server hosting costs |
| **Time to Build** | Days | Weeks |

### Key Concepts

- **Wix Instance Token**: A signed JWT-like token passed via `?instance=<token>` query parameter when your app loads inside the Wix dashboard. Contains `instanceId`, `siteOwnerId`, `permissions`, and more. This is the primary authentication mechanism for external dashboard apps.

- **Wix Dev Center**: Portal at `dev.wix.com` where you register your app, configure OAuth, define dashboard pages, set up webhooks, and manage Paid Plans.

- **Wix Design System (WDS)**: React component library (`@wix/design-system`) that provides Wix-native look and feel. Components include `Page`, `Card`, `Button`, `Badge`, `Modal`, `FormField`, `Input`, `Tabs`, `ToggleSwitch`, and more.

- **Wix Velo**: Server-side JavaScript runtime for Wix Native apps. Provides `wixData`, `secrets`, and other APIs. Limited to Wix's sandbox environment.

---

## Module Dependency Diagram

```
                    ┌──────────────────────────────┐
                    │     wix-app-framework         │
                    │     (this skill)              │
                    └──────────┬───────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                     │
          ▼                    ▼                     ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────────┐
│ unified-api-     │ │ auth-universal   │ │ payment-processing-      │
│ client (module)  │ │ (skill)          │ │ universal (skill)        │
│                  │ │                  │ │                          │
│ - Base HTTP      │ │ - OAuth 2.0     │ │ - Wix Paid Plans         │
│   client         │ │   patterns      │ │   integration            │
│ - Retry logic    │ │ - JWT token     │ │ - Webhook verification   │
│ - Auth strategy  │ │   management    │ │ - Subscription lifecycle │
│   injection      │ │ - Session mgmt  │ │ - Credit systems         │
│ - Response       │ │ - MFA support   │ │ - Plan ID mapping        │
│   normalization  │ │                  │ │                          │
└──────────────────┘ └──────────────────┘ └──────────────────────────┘
          │                    │                     │
          └────────────────────┼─────────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │     background-jobs-          │
                    │     universal (skill)         │
                    │                               │
                    │ - BullMQ job queues           │
                    │ - Redis connection mgmt      │
                    │ - Worker process patterns     │
                    │ - Progress tracking           │
                    └──────────────────────────────┘
```

**Dependency Details:**

| Dependency | Type | Path | Used For |
|-----------|------|------|----------|
| `unified-api-client` | module | `modules/unified-api-client/` | HTTP client for Wix API calls, auth header injection, retry logic |
| `auth-universal` | skill | `.claude/skills/auth-universal/` | OAuth 2.0 flow patterns (Wix uses OAuth 2.0), JWT verification, session management |
| `payment-processing-universal` | skill | `.claude/skills/payment-processing-universal/` | Wix Paid Plans integration, webhook signature verification, subscription lifecycle |
| `background-jobs-universal` | skill | `.claude/skills/background-jobs-universal/` | BullMQ job queues for async operations, worker processes, progress polling |

---

## Quick Start (React + TypeScript)

### Wix Native App (Simple)

```bash
# 1. Install Wix CLI
npm install -g @wix/cli

# 2. Create project
mkdir my-wix-app && cd my-wix-app
npm init -y

# 3. Install dependencies
npm install @wix/design-system react react-dom
npm install -D @wix/cli typescript @types/react @types/react-dom

# 4. Create package.json scripts
cat > package.json << 'EOF'
{
  "name": "@my-org/my-wix-app",
  "version": "1.0.0",
  "scripts": {
    "dev": "wix dev",
    "build": "wix build",
    "preview": "wix preview",
    "publish": "wix publish"
  },
  "dependencies": {
    "@wix/design-system": "latest",
    "react": "^18.0.0",
    "react-dom": "^18.0.0"
  },
  "devDependencies": {
    "@wix/cli": "^1.0.0",
    "typescript": "^5.0.0"
  }
}
EOF

# 5. Start development
wix dev
```

### External Dashboard App (Full Control)

```bash
# 1. Create project structure
mkdir -p my-wix-app/{frontend,backend}

# 2. Frontend: React + Vite + Tailwind
cd my-wix-app/frontend
npm create vite@latest . -- --template react-ts
npm install @wix/design-system
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p

# 3. Backend: Node.js + Fastify + Prisma
cd ../backend
npm init -y
npm install fastify @prisma/client ioredis bullmq dotenv jsonwebtoken
npm install -D prisma typescript @types/node tsx

# 4. Initialize Prisma
npx prisma init

# 5. Create Docker Compose for services
cat > ../docker-compose.yml << 'EOF'
version: '3.8'
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: my_wix_app
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
volumes:
  postgres_data:
  redis_data:
EOF

# 6. Start services
docker compose up -d
cd frontend && npm run dev   # Frontend on :5173
cd ../backend && npm run dev # Backend on :3000
```

### Minimal Dashboard Page (Wix Native)

```tsx
// src/pages/dashboard.tsx
import { useState, useEffect } from 'react';
import {
  Page,
  WixDesignSystemProvider,
  Card,
  Text,
  Button,
  Loader,
  Badge,
  Box,
} from '@wix/design-system';

export default function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    try {
      // Call your backend functions here
      setData({ status: 'connected' });
    } catch (error) {
      console.error('Failed to load:', error);
    }
    setLoading(false);
  }

  if (loading) {
    return (
      <WixDesignSystemProvider>
        <Page>
          <Page.Content>
            <Box align="center" padding="60px">
              <Loader size="large" />
              <Text>Loading...</Text>
            </Box>
          </Page.Content>
        </Page>
      </WixDesignSystemProvider>
    );
  }

  return (
    <WixDesignSystemProvider>
      <Page>
        <Page.Header
          title="My App"
          subtitle="App description here"
        />
        <Page.Content>
          <Card>
            <Card.Header
              title="Status"
              suffix={
                <Badge skin="success">Active</Badge>
              }
            />
            <Card.Content>
              <Text>Your app is running.</Text>
            </Card.Content>
          </Card>
        </Page.Content>
      </Page>
    </WixDesignSystemProvider>
  );
}
```

---

## Wix CLI Setup

### Installation and Commands

```bash
# Install globally
npm install -g @wix/cli

# Core commands
wix dev          # Start local development server
wix build        # Build for production
wix preview      # Preview before publishing
wix publish      # Publish to Wix

# Link to existing site
wix dev          # Will prompt to select a site on first run
```

### Project Structure (Wix Native)

```
my-wix-app/
├── src/
│   ├── backend/              # Server-side code (Wix Velo)
│   │   ├── api-client.ts     # HTTP client for external APIs
│   │   └── service.ts        # Business logic
│   └── pages/                # Dashboard UI (React)
│       └── dashboard.tsx     # Main dashboard page
├── public/                   # Static assets
├── package.json
└── tsconfig.json
```

### Project Structure (External Dashboard)

```
my-wix-app/
├── frontend/                     # React + Vite + Tailwind
│   ├── src/
│   │   ├── components/           # React components
│   │   │   ├── ErrorBoundary.tsx
│   │   │   ├── Toast.tsx
│   │   │   ├── PostForm.tsx
│   │   │   ├── ProgressBar.tsx
│   │   │   └── PricingModal.tsx
│   │   ├── contexts/
│   │   │   └── WixContext.tsx    # Wix instance token context
│   │   ├── hooks/
│   │   │   ├── useJobPoller.ts   # Job progress polling
│   │   │   └── usePostForm.ts
│   │   ├── pages/
│   │   │   └── WixDashboardPage.tsx
│   │   ├── services/
│   │   │   ├── api.ts            # Backend API client
│   │   │   └── wixBiEvents.ts    # Wix BI event tracking
│   │   ├── types/
│   │   │   └── index.ts          # TypeScript interfaces
│   │   └── utils/
│   │       └── wixInstance.ts    # Token extraction
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   └── package.json
│
├── backend/                      # Node.js + Fastify + Prisma
│   ├── src/
│   │   ├── routes/
│   │   │   ├── wix.ts           # Wix API routes
│   │   │   └── webhooks.ts      # Webhook handlers
│   │   ├── services/
│   │   │   ├── userService.ts
│   │   │   ├── postService.ts
│   │   │   ├── jobService.ts
│   │   │   ├── billingService.ts
│   │   │   └── database.ts      # Prisma singleton
│   │   ├── middleware/
│   │   │   └── wixAuth.ts       # Token verification
│   │   └── workers/
│   │       └── publishWorker.ts  # Background job processing
│   ├── prisma/
│   │   └── schema.prisma
│   ├── Dockerfile
│   └── package.json
│
├── docker-compose.yml            # Production stack
├── Caddyfile                     # Reverse proxy
└── .env.example
```

### Wix CLI Configuration

The `@wix/cli` package handles the build pipeline, TypeScript compilation, and deployment for Wix Native apps. It transforms your `src/` directory into Wix-compatible code.

```json
// tsconfig.json (Wix Native)
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "node",
    "jsx": "react-jsx",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "./dist"
  },
  "include": ["src/**/*"]
}
```

---

## OAuth & Authentication

Wix uses two distinct authentication mechanisms depending on your architecture.

### Architecture 1: Wix Instance Token (External Dashboard)

When your app loads inside the Wix dashboard, Wix passes an instance token as a URL parameter. This is the primary auth mechanism for external dashboard apps.

#### Token Flow

```
USER OPENS APP IN WIX DASHBOARD
        │
        ▼
┌────────────────────────────────────────────────────────┐
│ 1. Wix loads your app URL with ?instance=<token>       │
│    URL: https://your-app.com/dashboard                 │
│         ?instance=eyJhbGciOiJIUzI1NiJ9...              │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│ 2. Frontend extracts & decodes token                   │
│    - getWixInstanceFromUrl() -> token string            │
│    - decodeWixInstance(token) -> WixInstanceData        │
│    - All API calls include:                            │
│      Authorization: WixInstance <token>                 │
└────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────┐
│ 3. Backend verifies token on each request              │
│    - Decode base64-encoded token                       │
│    - Verify HMAC-SHA256 signature with WIX_APP_SECRET  │
│    - Extract instanceId, siteOwnerId, permissions      │
│    - Look up user by instanceId                        │
└────────────────────────────────────────────────────────┘
```

#### Frontend: Token Extraction

```typescript
// utils/wixInstance.ts

export interface WixInstanceData {
  instanceId: string;
  signDate: string;
  uid?: string;
  permissions?: string;
  demoMode?: boolean;
  siteOwnerId?: string;
  siteMemberId?: string;
  expirationDate?: string;
  loginAccountId?: string;
}

/**
 * Extract instance token from URL query parameters
 */
export function getWixInstanceFromUrl(): string | null {
  const params = new URLSearchParams(window.location.search);
  return params.get('instance');
}

/**
 * Decode the instance token (base64-encoded JSON after the signature)
 * Note: This does NOT verify the signature -- verification must happen on the backend
 */
export function decodeWixInstance(token: string): WixInstanceData | null {
  try {
    // Token format: <signature>.<base64-encoded-data>
    const parts = token.split('.');
    if (parts.length < 2) return null;

    const data = JSON.parse(atob(parts[1]));
    return data as WixInstanceData;
  } catch {
    return null;
  }
}
```

#### Frontend: WixContext Provider

```tsx
// contexts/WixContext.tsx
import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { getWixInstanceFromUrl, decodeWixInstance } from '../utils/wixInstance';
import type { WixInstanceData, WixUserData, WixContextType } from '../types';

const WixContext = createContext<WixContextType | null>(null);

export function WixProvider({ children }: { children: React.ReactNode }) {
  const [instanceToken, setInstanceToken] = useState<string | null>(null);
  const [instanceData, setInstanceData] = useState<WixInstanceData | null>(null);
  const [userData, setUserData] = useState<WixUserData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Extract token on mount
  useEffect(() => {
    const token = getWixInstanceFromUrl();
    if (token) {
      setInstanceToken(token);
      setInstanceData(decodeWixInstance(token));
    } else {
      setError('No Wix instance token found');
      setIsLoading(false);
    }
  }, []);

  // Fetch user data when token is available
  useEffect(() => {
    if (instanceToken) {
      refreshUserData();
    }
  }, [instanceToken]);

  const refreshUserData = useCallback(async () => {
    if (!instanceToken) return;
    setIsLoading(true);
    try {
      const response = await fetch('/api/v1/wix/user/status', {
        headers: {
          'Authorization': `WixInstance ${instanceToken}`,
        },
      });
      const data = await response.json();
      if (data.success) {
        setUserData(data.data);
      } else {
        setError(data.error || 'Failed to load user data');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error');
    }
    setIsLoading(false);
  }, [instanceToken]);

  const hasCredits = Boolean(userData && userData.credits > 0);

  const trackEvent = useCallback((eventName: string, params?: Record<string, unknown>) => {
    // Send BI event to Wix analytics
    console.log('[WixBI]', eventName, params);
  }, []);

  return (
    <WixContext.Provider value={{
      instanceToken,
      instanceData,
      userData,
      isLoading,
      error,
      refreshUserData,
      hasCredits,
      trackEvent,
    }}>
      {children}
    </WixContext.Provider>
  );
}

export function useWixContext() {
  const ctx = useContext(WixContext);
  if (!ctx) throw new Error('useWixContext must be used within WixProvider');
  return ctx;
}
```

#### Backend: Token Verification Middleware

```typescript
// middleware/wixAuth.ts
import crypto from 'crypto';
import { FastifyRequest, FastifyReply } from 'fastify';

const WIX_APP_SECRET = process.env.WIX_APP_SECRET!;

interface WixInstancePayload {
  instanceId: string;
  signDate: string;
  uid?: string;
  permissions?: string;
  siteOwnerId?: string;
  siteMemberId?: string;
  demoMode?: boolean;
}

/**
 * Verify and decode Wix instance token
 * Uses HMAC-SHA256 with the app secret from Wix Dev Center
 */
export function verifyWixInstance(token: string): WixInstancePayload | null {
  try {
    const [signature, encodedData] = token.split('.');
    if (!signature || !encodedData) return null;

    // Verify HMAC-SHA256 signature
    const expectedSignature = crypto
      .createHmac('sha256', WIX_APP_SECRET)
      .update(encodedData)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    if (signature !== expectedSignature) {
      return null; // Invalid signature
    }

    // Decode payload
    const data = JSON.parse(
      Buffer.from(encodedData, 'base64').toString('utf-8')
    );

    return data as WixInstancePayload;
  } catch {
    return null;
  }
}

/**
 * Fastify middleware: extract and verify Wix instance token
 */
export async function wixAuthMiddleware(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const authHeader = request.headers.authorization;

  if (!authHeader || !authHeader.startsWith('WixInstance ')) {
    return reply.code(401).send({
      success: false,
      error: 'Missing WixInstance authorization header',
    });
  }

  const token = authHeader.replace('WixInstance ', '');
  const instanceData = verifyWixInstance(token);

  if (!instanceData) {
    return reply.code(401).send({
      success: false,
      error: 'Invalid Wix instance token',
    });
  }

  // Attach to request for downstream handlers
  (request as any).wixInstance = instanceData;
}
```

### Architecture 2: Wix Velo Backend Auth (Wix Native)

For Wix Native apps, authentication is handled by the Wix platform itself. Your backend code runs in a sandboxed environment with access to Wix APIs.

```typescript
// src/backend/service.ts (Wix Velo)

// Wix Secrets API -- stores API keys securely
declare const secrets: {
  get(key: string): Promise<string>;
};

// Access secrets in backend code
async function getApiKey(): Promise<string> {
  return await secrets.get('MY_API_KEY');
}
```

### OAuth 2.0 Registration (Wix Dev Center)

When registering your app in the Wix Dev Center, you configure OAuth settings:

1. **App URL**: The URL where your dashboard loads (e.g., `https://your-app.com/wix-dashboard`)
2. **Redirect URL**: For OAuth callbacks (e.g., `https://your-app.com/oauth/callback`)
3. **App Secret**: Used to verify instance tokens (HMAC-SHA256)
4. **Webhook URL**: Where Wix sends lifecycle events

**Important**: The `auth-universal` skill provides reusable patterns for OAuth 2.0 that apply to Wix authentication. Specifically:
- JWT/HMAC token verification patterns
- Session management approaches
- Token refresh strategies

---

## Dashboard Pages

### Wix Design System Components

The `@wix/design-system` package provides components that match the Wix dashboard look and feel. Always wrap your pages with `WixDesignSystemProvider`.

#### Core Layout Pattern

```tsx
import {
  Page,
  WixDesignSystemProvider,
  Card,
  Text,
  Button,
  Badge,
  Box,
  Divider,
  Tabs,
  Loader,
  FormField,
  Input,
  Checkbox,
  ToggleSwitch,
  Modal,
  TextButton,
} from '@wix/design-system';

export default function DashboardPage() {
  return (
    <WixDesignSystemProvider>
      <Page>
        {/* Page Header with title and optional action button */}
        <Page.Header
          title="My App Dashboard"
          subtitle="Manage your app settings"
          actionsBar={
            <Button onClick={() => {}}>Primary Action</Button>
          }
        />

        <Page.Content>
          {/* Cards are the primary content container */}
          <Card>
            <Card.Header
              title="Section Title"
              suffix={
                <Badge skin="success">Active</Badge>
              }
            />
            <Card.Content>
              <Box direction="vertical" gap="12px">
                <Text>Card content goes here</Text>
              </Box>
            </Card.Content>
          </Card>

          <Divider />

          {/* Tab navigation */}
          <Tabs
            activeId="tab1"
            items={[
              { id: 'tab1', title: 'Overview' },
              { id: 'tab2', title: 'Settings' },
              { id: 'tab3', title: 'History' },
            ]}
            onClick={(tab) => console.log(tab.id)}
          />
        </Page.Content>
      </Page>
    </WixDesignSystemProvider>
  );
}
```

#### Common Component Patterns

**Connection Status Card:**

```tsx
<Card>
  <Card.Header
    title="Connection Status"
    suffix={
      <Badge skin={connected ? 'success' : 'danger'}>
        {connected ? 'Connected' : 'Not Connected'}
      </Badge>
    }
  />
  <Card.Content>
    <Box direction="vertical" gap="12px">
      <Text>{statusMessage}</Text>
      {!connected && (
        <Button size="small" onClick={handleConnect}>
          Connect
        </Button>
      )}
    </Box>
  </Card.Content>
</Card>
```

**Toggle Switch for Mode Selection:**

```tsx
<Card>
  <Card.Header title="Configuration" />
  <Card.Content>
    <Box direction="vertical" gap="12px">
      <Box gap="12px" align="center">
        <ToggleSwitch
          checked={advancedMode}
          onChange={() => setAdvancedMode(!advancedMode)}
        />
        <Text>
          {advancedMode ? 'Advanced Mode' : 'Simple Mode'}
        </Text>
      </Box>
      <Text size="small" secondary>
        {advancedMode
          ? 'Full control over all settings'
          : 'Simplified settings for quick setup'}
      </Text>
    </Box>
  </Card.Content>
</Card>
```

**Modal Dialog:**

```tsx
<Modal
  isOpen={showModal}
  onRequestClose={() => setShowModal(false)}
  screen="desktop"
>
  <Box direction="vertical" gap="20px" padding="24px">
    <Text size="large" weight="bold">
      Modal Title
    </Text>

    <FormField label="Field Label *">
      <Input
        value={fieldValue}
        onChange={(e) => setFieldValue(e.target.value)}
      />
    </FormField>

    <Box gap="12px">
      <Button onClick={handleSubmit}>
        Submit
      </Button>
      <Button skin="light" onClick={() => setShowModal(false)}>
        Cancel
      </Button>
    </Box>
  </Box>
</Modal>
```

**List with Action Buttons:**

```tsx
<Box direction="vertical" gap="12px">
  {items.map((item) => (
    <Box
      key={item.id}
      padding="12px"
      backgroundColor="D10"
      direction="vertical"
      gap="8px"
    >
      <Box gap="8px" align="center">
        <Text weight="bold">{item.name}</Text>
        {item.isDefault && (
          <Badge size="tiny" skin="success">Default</Badge>
        )}
      </Box>
      {item.description && (
        <Text size="small" secondary>{item.description}</Text>
      )}
      <Box gap="8px">
        <TextButton size="small" onClick={() => handleSetDefault(item.id)}>
          Set as Default
        </TextButton>
        <TextButton
          size="small"
          skin="destructive"
          onClick={() => handleDelete(item.id)}
        >
          Delete
        </TextButton>
      </Box>
    </Box>
  ))}
</Box>
```

### External Dashboard: Vite Configuration

For external dashboard apps, configure Vite to proxy API requests to your backend:

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
```

### Embedding in Wix Dashboard

When your app loads inside the Wix dashboard, it renders in an iframe. Handle the `?instance=` parameter and ensure cross-origin communication works:

```tsx
// pages/WixDashboardPage.tsx
import { useEffect } from 'react';
import { useWixContext } from '../contexts/WixContext';
import { WixProvider } from '../contexts/WixContext';
import Dashboard from '../components/Dashboard';

function WixDashboardInner() {
  const { isLoading, error, userData } = useWixContext();

  useEffect(() => {
    // Check for upgrade=success parameter (post-checkout redirect)
    const params = new URLSearchParams(window.location.search);
    if (params.get('upgrade') === 'success') {
      // Remove from URL to prevent re-triggering
      params.delete('upgrade');
      window.history.replaceState({}, '', `?${params.toString()}`);
      // Trigger data refresh
    }
  }, []);

  if (isLoading) return <LoadingScreen />;
  if (error) return <ErrorScreen message={error} />;
  return <Dashboard userData={userData} />;
}

export default function WixDashboardPage() {
  return (
    <WixProvider>
      <WixDashboardInner />
    </WixProvider>
  );
}
```

---

## Wix Data API Patterns

### Wix Velo Data Collections (Wix Native)

In Wix Native apps, you use `wixData` to interact with Wix Data Collections. These are NoSQL-like collections managed by the Wix platform.

```typescript
// Wix Data API declarations
declare const wixData: {
  get(collection: string, itemId: string): Promise<any>;
  insert(collection: string, item: object): Promise<object>;
  save(collection: string, item: any): Promise<any>;
  remove(collection: string, itemId: string): Promise<void>;
  query(collection: string): WixDataQuery;
};

interface WixDataQuery {
  eq(field: string, value: unknown): WixDataQuery;
  ne(field: string, value: unknown): WixDataQuery;
  gt(field: string, value: unknown): WixDataQuery;
  lt(field: string, value: unknown): WixDataQuery;
  contains(field: string, value: string): WixDataQuery;
  ascending(field: string): WixDataQuery;
  descending(field: string): WixDataQuery;
  limit(count: number): WixDataQuery;
  skip(count: number): WixDataQuery;
  find(): Promise<{ items: any[]; totalCount: number }>;
}
```

#### CRUD Operations

```typescript
// --- CREATE ---
async function createItem(data: object): Promise<object> {
  return await wixData.insert('MyCollection', {
    ...data,
    _createdDate: new Date(),
  });
}

// --- READ (by ID) ---
async function getItem(id: string): Promise<any> {
  return await wixData.get('MyCollection', id);
}

// --- READ (query) ---
async function queryItems(status: string, limit: number = 20): Promise<any[]> {
  const results = await wixData.query('MyCollection')
    .eq('status', status)
    .descending('_createdDate')
    .limit(limit)
    .find();
  return results.items;
}

// --- UPDATE ---
async function updateItem(id: string, data: object): Promise<any> {
  return await wixData.save('MyCollection', {
    _id: id,
    ...data,
  });
}

// --- DELETE ---
async function deleteItem(id: string): Promise<void> {
  await wixData.remove('MyCollection', id);
}
```

#### Key-Value Configuration Pattern

A common pattern is using a collection as a key-value store for app configuration:

```typescript
/**
 * Get configuration value from AppConfig collection
 */
async function getConfig(key: string): Promise<string | null> {
  try {
    const config = await wixData.query('AppConfig')
      .eq('key', key)
      .find();
    return config.items.length > 0 ? config.items[0].value : null;
  } catch {
    return null;
  }
}

/**
 * Set configuration value (upsert pattern)
 */
async function setConfig(key: string, value: string): Promise<void> {
  try {
    const existing = await wixData.query('AppConfig')
      .eq('key', key)
      .find();

    if (existing.items.length > 0) {
      // Update existing
      await wixData.save('AppConfig', {
        _id: existing.items[0]._id,
        key,
        value,
      });
    } else {
      // Create new
      await wixData.save('AppConfig', { key, value });
    }
  } catch (error) {
    console.error(`Failed to set config ${key}:`, error);
  }
}
```

### External Database (Prisma + PostgreSQL)

For external dashboard apps, use Prisma ORM with PostgreSQL for full relational database support.

#### Schema Definition

```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

enum PlanType {
  free
  starter
  pro
  agency
}

enum BillingSource {
  wix
  stripe
  none
}

enum PostStatus {
  draft
  scheduled
  publishing
  published
  failed
}

enum JobStatus {
  queued
  processing
  optimizing
  publishing
  completed
  failed
}

model User {
  id                    String        @id @default(uuid())
  wixInstanceId         String        @unique @map("wix_instance_id")
  email                 String?
  planType              PlanType      @default(free) @map("plan_type")
  credits               Int           @default(3)
  creditsUsedThisPeriod Int           @default(0) @map("credits_used_this_period")
  billingSource         BillingSource @default(wix) @map("billing_source")
  wixPlanId             String?       @map("wix_plan_id")
  wixOrderId            String?       @map("wix_order_id")
  currentPeriodEnd      DateTime?     @map("current_period_end")
  cancelAtPeriodEnd     Boolean       @default(false) @map("cancel_at_period_end")
  createdAt             DateTime      @default(now()) @map("created_at")
  updatedAt             DateTime      @updatedAt @map("updated_at")

  posts         Post[]
  jobs          Job[]
  brandProfiles BrandProfile[]

  @@map("users")
}

model Post {
  id              String     @id @default(uuid())
  userId          String     @map("user_id")
  title           String
  content         String
  url             String?
  imageUrl        String?    @map("image_url")
  networks        String[]
  status          PostStatus @default(draft)
  scheduledAt     DateTime?  @map("scheduled_at")
  publishedAt     DateTime?  @map("published_at")
  platformResults Json?      @map("platform_results")
  error           String?
  createdAt       DateTime   @default(now()) @map("created_at")
  updatedAt       DateTime   @updatedAt @map("updated_at")

  user User  @relation(fields: [userId], references: [id])
  jobs Job[]

  @@map("posts")
}

model Job {
  id              String    @id @default(uuid())
  userId          String    @map("user_id")
  postId          String?   @map("post_id")
  type            String    @default("publish")
  status          JobStatus @default(queued)
  progressPercent Int       @default(0) @map("progress_percent")
  currentStep     String    @default("Queued") @map("current_step")
  result          Json?
  error           String?
  createdAt       DateTime  @default(now()) @map("created_at")
  updatedAt       DateTime  @updatedAt @map("updated_at")

  user User  @relation(fields: [userId], references: [id])
  post Post? @relation(fields: [postId], references: [id])

  @@map("jobs")
}

model BrandProfile {
  id              String   @id @default(uuid())
  userId          String   @map("user_id")
  name            String
  description     String?
  targetAudience  String?  @map("target_audience")
  tonePreference  String?  @map("tone_preference")
  industryTags    String[] @map("industry_tags")
  brandHashtags   String?  @map("brand_hashtags")
  isDefault       Boolean  @default(false) @map("is_default")
  createdAt       DateTime @default(now()) @map("created_at")
  updatedAt       DateTime @updatedAt @map("updated_at")

  user User @relation(fields: [userId], references: [id])

  @@map("brand_profiles")
}
```

#### Database Service (Singleton Pattern)

```typescript
// services/database.ts
import { PrismaClient } from '@prisma/client';

let prisma: PrismaClient | null = null;

export function getPrismaClient(): PrismaClient {
  if (!prisma) {
    prisma = new PrismaClient({
      log: process.env.NODE_ENV === 'development'
        ? ['query', 'error', 'warn']
        : ['error'],
    });

    // Graceful shutdown
    process.on('beforeExit', async () => {
      await prisma?.$disconnect();
    });
  }
  return prisma;
}

export const db = getPrismaClient();
```

#### User Service with Credit Management

```typescript
// services/userService.ts
import { db } from './database';

// Plan credit allocations
const PLAN_CREDITS: Record<string, number> = {
  free: 3,
  starter: 50,
  pro: 100,
  agency: 300,
};

/**
 * Get user by Wix instance ID
 */
export async function getUserByInstanceId(instanceId: string) {
  return db.user.findUnique({
    where: { wixInstanceId: instanceId },
  });
}

/**
 * Create new user with trial credits
 */
export async function createUser(instanceId: string, email?: string) {
  return db.user.create({
    data: {
      wixInstanceId: instanceId,
      email,
      planType: 'free',
      credits: PLAN_CREDITS['free'],
      creditsUsedThisPeriod: 0,
      billingSource: 'wix',
    },
  });
}

/**
 * Deduct credits -- returns null if insufficient
 */
export async function deductCredits(userId: string, amount: number = 1) {
  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user || user.credits < amount) return null;

  return db.user.update({
    where: { id: userId },
    data: {
      credits: { decrement: amount },
      creditsUsedThisPeriod: { increment: amount },
    },
  });
}
```

---

## Billing & Subscriptions

### Wix Paid Plans Architecture

Wix Paid Plans is the billing system for apps distributed through the Wix App Market. It integrates directly with the Wix checkout flow and handles payment processing.

```
┌──────────────────────────────────────────────────────────────────┐
│                    WIX BILLING LIFECYCLE                          │
└──────────────────────────────────────────────────────────────────┘

User clicks "Upgrade" in your app
        │
        ▼
┌────────────────────────────────────────────────────────────────┐
│ 1. Your app calls Wix Billing API to get checkout URL          │
│    POST /api/v1/wix/billing/checkout-url                       │
│    Body: { planId: 'pro-monthly' }                             │
│                                                                 │
│    Backend generates Wix checkout URL using Wix SDK             │
│    Returns: { checkoutUrl: 'https://wix.com/checkout/...' }    │
└────────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────────┐
│ 2. User is redirected to Wix checkout page                     │
│    Wix handles payment processing (credit card, PayPal)        │
│    User completes payment                                      │
└────────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────────┐
│ 3. Wix sends webhook to your backend                           │
│    POST /api/v1/wix/webhook/plan-purchased                     │
│    Payload: {                                                   │
│      instanceId, planId, orderId, validUntil, autoRenew        │
│    }                                                            │
└────────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────────┐
│ 4. Your backend updates user record                            │
│    - Map planId to normalized plan type                        │
│    - Set credits based on plan                                 │
│    - Store orderId for reference                               │
│    - Set period end date                                       │
└────────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────────┐
│ 5. User is redirected back to your app                         │
│    URL: https://your-app.com/dashboard?upgrade=success         │
│    Frontend detects parameter, refreshes user data             │
└────────────────────────────────────────────────────────────────┘
```

### Webhook Handlers

Wix sends lifecycle webhooks for app installation, removal, and billing events. These MUST be idempotent because Wix retries failed webhooks at ~1min, ~10min, and ~1hr intervals.

```typescript
// routes/webhooks.ts
import { FastifyInstance } from 'fastify';
import {
  createUser,
  getUserByInstanceId,
  updateUserPlan,
  setCancellationFlag,
} from '../services/userService';

export default async function webhookRoutes(fastify: FastifyInstance) {
  // App installed -- create user with trial credits
  fastify.post('/app-installed', async (request, reply) => {
    const { instanceId, email } = request.body as any;
    fastify.log.info({ instanceId }, 'App installed webhook');

    try {
      // Idempotent: check if user exists
      let user = await getUserByInstanceId(instanceId);
      if (!user) {
        user = await createUser(instanceId, email);
        fastify.log.info({ userId: user.id }, 'New user created');
      }
      return { success: true, userId: user.id };
    } catch (error: any) {
      fastify.log.error(error, 'app-installed webhook failed');
      return reply.code(500).send({ success: false, error: error.message });
    }
  });

  // App removed -- mark inactive (keep data for reinstalls)
  fastify.post('/app-removed', async (request, reply) => {
    const { instanceId } = request.body as any;
    fastify.log.info({ instanceId }, 'App removed webhook');
    // Optional: mark user as inactive, schedule data deletion
    return { success: true };
  });

  // Plan purchased -- grant subscription
  fastify.post('/plan-purchased', async (request, reply) => {
    const { instanceId, planId, orderId, validUntil } = request.body as any;
    fastify.log.info({ instanceId, planId }, 'Plan purchased webhook');

    try {
      // Idempotent: create user if missing (edge case)
      let user = await getUserByInstanceId(instanceId);
      if (!user) {
        user = await createUser(instanceId);
      }

      const updatedUser = await updateUserPlan(
        instanceId, planId, orderId, new Date(validUntil)
      );
      return { success: true, userId: updatedUser.id };
    } catch (error: any) {
      fastify.log.error(error, 'plan-purchased webhook failed');
      return reply.code(500).send({ success: false, error: error.message });
    }
  });

  // Plan updated -- handle upgrade/downgrade
  fastify.post('/plan-updated', async (request, reply) => {
    const { instanceId, planId, orderId, validUntil } = request.body as any;
    fastify.log.info({ instanceId, planId }, 'Plan updated webhook');

    try {
      const updatedUser = await updateUserPlan(
        instanceId, planId, orderId, new Date(validUntil)
      );
      return { success: true, userId: updatedUser.id };
    } catch (error: any) {
      fastify.log.error(error, 'plan-updated webhook failed');
      return reply.code(500).send({ success: false, error: error.message });
    }
  });

  // Plan cancelled -- set flag, keep access until period ends
  fastify.post('/plan-cancelled', async (request, reply) => {
    const { instanceId } = request.body as any;
    fastify.log.info({ instanceId }, 'Plan cancelled webhook');

    try {
      const updatedUser = await setCancellationFlag(instanceId, true);
      return { success: true, userId: updatedUser.id };
    } catch (error: any) {
      fastify.log.error(error, 'plan-cancelled webhook failed');
      return reply.code(500).send({ success: false, error: error.message });
    }
  });
}
```

### Plan ID Mapping (Critical)

Wix plan IDs can arrive in multiple formats. You MUST handle all variants to avoid billing bugs.

```typescript
// CRITICAL: Wix sends plan IDs in various formats
// Your backend must normalize them before processing

const PLAN_MAPPING: Record<string, string> = {
  // Short IDs
  'free': 'free',
  'starter': 'starter',
  'pro': 'pro',
  'agency': 'agency',

  // Hyphenated variants
  'starter-plan': 'starter',
  'pro-plan': 'pro',
  'agency-plan': 'agency',

  // Monthly/yearly variants
  'starter-monthly': 'starter',
  'pro-monthly': 'pro',
  'agency-monthly': 'agency',
  'starter-yearly': 'starter',
  'pro-yearly': 'pro',
  'agency-yearly': 'agency',
};

function normalizePlanId(planId: string): string {
  return PLAN_MAPPING[planId.toLowerCase()] || 'free';
}
```

### Webhook Event Reference

| Event Type | Endpoint | Purpose | Retry Pattern |
|-----------|----------|---------|---------------|
| `AppInstalled` | `/webhook/app-installed` | Create user, grant trial | ~1min, ~10min, ~1hr |
| `AppRemoved` | `/webhook/app-removed` | Mark inactive | ~1min, ~10min, ~1hr |
| `PaidPlanPurchased` | `/webhook/plan-purchased` | Grant subscription | ~1min, ~10min, ~1hr |
| `PaidPlanChanged` | `/webhook/plan-updated` | Upgrade/downgrade | ~1min, ~10min, ~1hr |
| `PaidPlanAutoRenewalCancelled` | `/webhook/plan-cancelled` | Set cancel flag | ~1min, ~10min, ~1hr |

**Critical Billing Rules:**
- All webhook handlers MUST be idempotent (same webhook can arrive multiple times)
- Always return 200 immediately, then process asynchronously if needed
- Map ALL plan ID variants (see above)
- Keep user access until `currentPeriodEnd` even after cancellation
- Log every webhook for debugging billing issues
- The `payment-processing-universal` skill provides additional patterns for webhook security and subscription lifecycle management

---

## Wix Blocks (Custom UI Components)

Wix Blocks allows you to create custom, reusable UI components (widgets) that site owners can drag and drop onto their pages. These are distinct from dashboard pages.

### When to Use Blocks

- Site-facing widgets (not dashboard UI)
- Embeddable components for Wix Editor
- Custom elements that site owners configure
- Public-facing content displays

### Block Architecture

```
┌───────────────────────────────────────────────┐
│               WIX BLOCKS                       │
├───────────────────────────────────────────────┤
│                                                │
│  ┌──────────────────────┐  ┌────────────────┐ │
│  │ Widget (Frontend)     │  │ Settings Panel │ │
│  │                       │  │                │ │
│  │ - React component     │  │ - Configuration│ │
│  │ - Rendered on site    │  │   UI           │ │
│  │ - Uses Wix SDK        │  │ - Persisted    │ │
│  │ - Responsive layout   │  │   by Wix       │ │
│  └──────────────────────┘  └────────────────┘ │
│                                                │
│  ┌──────────────────────┐                      │
│  │ Backend (Velo)        │                      │
│  │                       │                      │
│  │ - Server-side logic   │                      │
│  │ - API calls           │                      │
│  │ - Data processing     │                      │
│  └──────────────────────┘                      │
│                                                │
└───────────────────────────────────────────────┘
```

### Creating a Widget

```tsx
// blocks/my-widget/widget.tsx
import { useState, useEffect } from 'react';

interface WidgetProps {
  // Props come from the settings panel
  title: string;
  showBorder: boolean;
  theme: 'light' | 'dark';
}

export default function MyWidget({ title, showBorder, theme }: WidgetProps) {
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    // Fetch data from your backend or Wix Data
    loadWidgetData();
  }, []);

  async function loadWidgetData() {
    // Use Wix SDK or fetch from external API
    try {
      const response = await fetch('/api/widget-data');
      const result = await response.json();
      setData(result.items);
    } catch (error) {
      console.error('Widget data load failed:', error);
    }
  }

  return (
    <div
      className={`widget ${theme}`}
      style={{
        border: showBorder ? '1px solid #ccc' : 'none',
        padding: '16px',
        borderRadius: '8px',
      }}
    >
      <h3>{title}</h3>
      <ul>
        {data.map((item, index) => (
          <li key={index}>{item.name}</li>
        ))}
      </ul>
    </div>
  );
}
```

### Settings Panel

```tsx
// blocks/my-widget/settings.tsx
import {
  Box,
  FormField,
  Input,
  ToggleSwitch,
  Dropdown,
} from '@wix/design-system';

interface SettingsProps {
  title: string;
  showBorder: boolean;
  theme: 'light' | 'dark';
  onChange: (key: string, value: any) => void;
}

export default function WidgetSettings({
  title,
  showBorder,
  theme,
  onChange,
}: SettingsProps) {
  return (
    <Box direction="vertical" gap="16px" padding="16px">
      <FormField label="Widget Title">
        <Input
          value={title}
          onChange={(e) => onChange('title', e.target.value)}
        />
      </FormField>

      <FormField label="Show Border">
        <ToggleSwitch
          checked={showBorder}
          onChange={() => onChange('showBorder', !showBorder)}
        />
      </FormField>

      <FormField label="Theme">
        <Dropdown
          selectedId={theme}
          options={[
            { id: 'light', value: 'Light' },
            { id: 'dark', value: 'Dark' },
          ]}
          onSelect={(option) => onChange('theme', option.id)}
        />
      </FormField>
    </Box>
  );
}
```

### Block Best Practices

1. **Responsive Design**: Blocks must adapt to the container width set by the site owner.
2. **Minimal Dependencies**: Keep block bundles small -- they load on every page view.
3. **Error Boundaries**: Always wrap blocks in error boundaries so a widget crash does not break the entire page.
4. **Loading States**: Show skeleton loaders while data fetches, not blank space.
5. **Settings Defaults**: Always provide sensible defaults for all configurable properties.

---

## Deployment & Publishing

### Wix Native App Deployment

```bash
# Development
wix dev          # Local dev server, linked to a Wix site

# Preview (test before publishing)
wix preview      # Creates a temporary preview version

# Production
wix publish      # Publishes to your Wix site

# Build only (for CI/CD)
wix build        # Outputs build artifacts
```

### External Dashboard Deployment

#### Docker Compose Production Stack

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Reverse Proxy with Auto-HTTPS
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
      - ./frontend/dist:/srv/frontend
    depends_on:
      - api
    networks:
      - web

  # Backend API
  api:
    build:
      context: ./backend
      dockerfile: Dockerfile
    restart: unless-stopped
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@db:5432/myapp
      - REDIS_URL=redis://redis:6379
      - WIX_APP_SECRET=${WIX_APP_SECRET}
      - WIX_APP_ID=${WIX_APP_ID}
      - PORT=3000
      - HOST=0.0.0.0
    depends_on:
      - db
      - redis
    networks:
      - web
      - internal
    deploy:
      resources:
        limits:
          memory: 512M

  # Background Workers
  worker:
    build:
      context: ./backend
      dockerfile: Dockerfile
    command: npm run worker
    restart: unless-stopped
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@db:5432/myapp
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    networks:
      - internal
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 512M

  # PostgreSQL
  db:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=myapp
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - internal
    deploy:
      resources:
        limits:
          memory: 1G

  # Redis for Job Queue
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    networks:
      - internal
    deploy:
      resources:
        limits:
          memory: 256M

volumes:
  postgres_data:
  redis_data:
  caddy_data:
  caddy_config:

networks:
  web:
    driver: bridge
  internal:
    driver: bridge
```

#### Caddyfile (Reverse Proxy with Auto-HTTPS)

```
{
    email admin@yourdomain.com
}

your-app.yourdomain.com {
    # API routes
    handle /api/* {
        reverse_proxy api:3000
    }

    # Webhook routes (no auth, verified by signature)
    handle /webhook/* {
        reverse_proxy api:3000
    }

    # Frontend (React SPA)
    handle {
        root * /srv/frontend
        try_files {path} /index.html
        file_server
    }

    # Security headers
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        Referrer-Policy strict-origin-when-cross-origin
    }

    encode gzip
}
```

#### Backend Dockerfile

```dockerfile
# Multi-stage build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

# Production image
FROM node:20-alpine
WORKDIR /app
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001

COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./

USER nodejs
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

#### Background Worker Process

```typescript
// workers/publishWorker.ts
import 'dotenv/config';
import { createPublishWorker } from '../services/jobService';

const worker = createPublishWorker();

worker.on('completed', (job) => {
  console.log(`Job ${job.id} completed`);
});

worker.on('failed', (job, err) => {
  console.error(`Job ${job?.id} failed:`, err.message);
});

worker.on('error', (err) => {
  console.error('Worker error:', err);
});

console.log('Worker started');

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing worker...');
  await worker.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, closing worker...');
  await worker.close();
  process.exit(0);
});
```

#### Deployment Commands

```bash
# Initial server setup
ssh root@your-server-ip

# Install Docker
curl -fsSL https://get.docker.com | sh
apt install docker-compose-plugin

# Clone and configure
git clone https://github.com/your-repo/your-app.git
cd your-app
cp .env.example .env
nano .env  # Add secrets

# Build frontend
cd frontend && npm install && npm run build && cd ..

# Deploy
docker compose up -d --build

# Run migrations
docker compose exec api npx prisma migrate deploy

# View logs
docker compose logs -f

# Restart after code changes
git pull && docker compose up -d --build
```

### Memory Allocation Guide (4GB VPS)

```
┌──────────────────────────────────┐
│  Memory Distribution (4GB)       │
├──────────────────────────────────┤
│  PostgreSQL:     1.0 GB          │
│  Redis:          256 MB          │
│  API Server:     512 MB          │
│  Worker 1:       512 MB          │
│  Worker 2:       512 MB          │
│  Caddy:          128 MB          │
│  System/Buffer:  1.1 GB          │
├──────────────────────────────────┤
│  Total:          4.0 GB          │
└──────────────────────────────────┘
```

### Scaling Path

| Daily Requests | Server | Cost/Month |
|---------------|--------|------------|
| 1-5k | CPX21 (4GB) | ~$8 |
| 5-15k | CPX31 (8GB) | ~$15 |
| 15-50k | CPX41 (16GB) | ~$29 |
| 50k+ | AX41 Dedicated | ~$43 |

```bash
# Scale workers
docker compose up -d --scale worker=4

# Increase Redis memory
# Edit docker-compose.yml: --maxmemory 512mb
```

### Wix Dev Center Configuration

After deployment, configure your app in the Wix Dev Center:

1. **App URL**: `https://your-app.yourdomain.com/wix-dashboard`
2. **OAuth Redirect URL**: `https://your-app.yourdomain.com/oauth/callback`
3. **Webhook URL**: `https://your-app.yourdomain.com/api/v1/wix/webhook`
4. **Dashboard Page**: Register as "Full Page" component
5. **Paid Plans**: Define pricing tiers and plan IDs

---

## Environment Variables

### Frontend (Vite)

```bash
# .env (frontend)

# API URL (backend)
VITE_API_URL=http://localhost:3000

# Wix App ID (from Wix Dev Center)
VITE_WIX_APP_ID=your-wix-app-id-here
```

### Backend

```bash
# .env (backend)

# Server
NODE_ENV=development
PORT=3000
HOST=0.0.0.0
LOG_LEVEL=info

# Frontend URL (for CORS)
FRONTEND_URL=http://localhost:5173

# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/myapp

# Redis (for BullMQ job queue)
REDIS_URL=redis://localhost:6379

# Wix App (from Wix Dev Center)
WIX_APP_ID=your-wix-app-id
WIX_APP_SECRET=your-wix-app-secret

# External APIs (app-specific)
# AYRSHARE_API_KEY=your-key
# OPENAI_API_KEY=your-key
```

### Docker Compose / Production

```bash
# .env (root - used by docker-compose.yml)

# Database
DB_PASSWORD=your_secure_password_here

# Wix App
WIX_APP_ID=your_wix_app_id
WIX_APP_SECRET=your_wix_app_secret

# Optional
NODE_ENV=production
LOG_LEVEL=info
```

**Security Rules:**
- NEVER commit `.env` files -- add to `.gitignore`
- Use Wix Secrets Manager for API keys in Wix Native apps
- Rotate `WIX_APP_SECRET` periodically
- Use strong, unique `DB_PASSWORD` values
- Store production secrets in server environment, not in files

---

## Integrates With

This skill works alongside other components in the Streamlined Development system:

### Direct Dependencies

| Component | Type | How It Integrates |
|-----------|------|-------------------|
| **`unified-api-client`** | module | Provides the base HTTP client class used by both Wix Velo backend (`api-client.ts`) and external dashboard API services. Handles retry logic, auth header injection (`Authorization: WixInstance <token>` or `Bearer <jwt>`), and response normalization. |
| **`auth-universal`** | skill | Provides reusable OAuth 2.0 patterns that apply to Wix authentication. Specifically: HMAC-SHA256 token verification (same pattern as Wix instance tokens), JWT management, session lifecycle, and MFA support for admin panels. |
| **`payment-processing-universal`** | skill | Provides webhook security patterns (signature verification), subscription lifecycle management (plan purchase, upgrade, downgrade, cancellation), idempotency key patterns, and credit/billing system design. The Wix Paid Plans integration follows the same adapter pattern. |

### Related Skills

| Component | Type | Relationship |
|-----------|------|-------------|
| **`background-jobs-universal`** | skill | BullMQ job queue setup, Redis connection management, worker process patterns, and progress tracking used by the external dashboard's async operations. |
| **`deployment-patterns`** | skill | Docker Compose production stacks, Caddy reverse proxy configuration, and VPS deployment scripts used by the external dashboard architecture. |
| **`database-patterns`** | skill | Prisma schema design, migration strategies, and PostgreSQL optimization used by the external dashboard backend. |
| **`api-patterns`** | skill | RESTful API design, route organization, middleware patterns, and error handling used by Fastify backend routes. |

### TypeScript Type Definitions

Core types shared across Wix apps (generalized from production):

```typescript
// Wix Instance Token
interface WixInstanceData {
  instanceId: string;
  signDate: string;
  uid?: string;
  permissions?: string;
  demoMode?: boolean;
  siteOwnerId?: string;
  siteMemberId?: string;
  expirationDate?: string;
  loginAccountId?: string;
}

// User with billing
interface WixAppUser {
  userId: string;
  email?: string;
  plan: 'free' | 'starter' | 'pro' | 'agency';
  credits: number;
  creditsUsed: number;
  billingSource: 'wix' | 'stripe' | 'none';
  isTrial: boolean;
  trialCreditsRemaining: number;
  currentPeriodEnd: string | null;
  cancelAtPeriodEnd: boolean;
}

// API response wrapper
interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

// Job polling state
type JobStatus = 'queued' | 'processing' | 'optimizing' | 'publishing' | 'completed' | 'failed';

interface JobState {
  jobId: string;
  status: JobStatus;
  progressPercent: number;
  currentStep: string;
  result?: any;
  error?: string;
}

// BI event tracking
interface WixBiEvent {
  src: string;       // App ID
  evid: number;      // Event counter
  eventName: string;
  timestamp: number;
  params?: Record<string, string | number | boolean>;
}
```

### Lessons Applied

These production-tested lessons are embedded throughout this skill:

1. **Wix Plan ID Mapping**: Always normalize plan IDs -- Wix sends `starter`, `starter-plan`, `starter-monthly`, `starter-yearly` for the same plan tier.
2. **Auth Mismatch**: Use `WixInstance` auth header format (not `Bearer`) for all Wix-embedded API calls.
3. **Delete Must Remove DB Records**: When deleting items, clean up both external storage and database records.
4. **Progress Updates**: For operations longer than 30 seconds, show progress updates every 5-10 seconds via job polling.
5. **Preview Modal**: In-app preview of results is always better than opening external links.
6. **Webhook Idempotency**: The same webhook may arrive 2-3 times. Always check if the action was already performed before executing.
7. **X-Frame-Options**: Set `SAMEORIGIN` in production headers so Wix can embed your app in its dashboard iframe.
8. **CORS Configuration**: Your backend must allow requests from `*.wix.com` origins when embedded in the Wix dashboard.
9. **Instance Token Expiry**: Wix instance tokens have an expiration. Re-fetch from the URL parameter if API calls start failing with 401.
10. **Graceful Worker Shutdown**: Always handle SIGTERM/SIGINT in worker processes for clean Docker container stops.
