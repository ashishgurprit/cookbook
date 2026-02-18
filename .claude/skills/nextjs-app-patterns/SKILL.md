---
name: nextjs-app-patterns
description: "Next.js App Router production patterns and architecture. Use when building: (1) Next.js 14/15/16 applications with App Router, (2) Server Component and Client Component architecture, (3) Data fetching with Server Actions and Route Handlers, (4) Streaming and Suspense patterns, (5) ISR/SSG/SSR rendering strategies, (6) Parallel and intercepting routes, (7) Middleware for auth/redirects/geolocation, (8) Metadata API and SEO optimization, (9) Next.js caching layers, (10) next/image optimization, (11) MDX content integration. Triggers on 'Next.js', 'App Router', 'Server Components', 'Server Actions', 'next/image', 'generateMetadata', 'generateStaticParams', 'ISR', 'Route Handlers', 'Next.js middleware', 'Next.js caching', or 'parallel routes'."
license: Proprietary
---

# Next.js App Router Production Patterns

Production-grade patterns for Next.js App Router (v14-16). Next.js 16 shipped October 2025 with PPR stable, Cache Components, Turbopack as default bundler, and React 19 Compiler v1.0 support. This skill covers Next.js-SPECIFIC architecture, rendering strategies, data fetching, caching, and deployment patterns. For general frontend patterns (React hooks, testing, performance), see the `elite-frontend-developer` skill.

## Core Philosophy

Every decision flows from one question: **"Where does this code need to run?"**

- **Server-first**: Default to Server Components. Only add `"use client"` when you need browser APIs, event handlers, or React state.
- **Streaming over blocking**: Use Suspense boundaries to stream UI progressively.
- **Colocation**: Keep data fetching close to where data is consumed.
- **Convention over configuration**: File-system conventions replace manual routing boilerplate.

---

## Quick Start

```bash
npx create-next-app@latest my-app --typescript --tailwind --eslint --app --src-dir --import-alias "@/*"
```

```
src/app/
  layout.tsx        # Root layout (required)
  page.tsx          # Home (/)
  globals.css
  blog/
    page.tsx        # /blog
    [slug]/page.tsx # /blog/:slug
  api/
    contact/route.ts  # POST /api/contact
src/components/     # Shared components
src/lib/            # Utilities, configs
src/content/        # MDX/content files
next.config.ts
```

---

# 1. App Router Architecture

## File Conventions

| File | Purpose | Component Type |
|------|---------|----------------|
| `layout.tsx` | Shared wrapper (persists across navigations) | Server |
| `page.tsx` | Route UI (required to make route accessible) | Server |
| `loading.tsx` | Loading UI (auto-wraps page in Suspense) | Server |
| `error.tsx` | Error boundary for segment | **Client** (required) |
| `not-found.tsx` | 404 UI for segment | Server |
| `route.ts` | API endpoint (GET, POST, PUT, DELETE) | Server only |
| `template.tsx` | Like layout but re-mounts on navigation | Server |
| `default.tsx` | Fallback for parallel routes | Server |

## Root Layout

```typescript
// src/app/layout.tsx
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: { default: "My Site", template: "%s | My Site" },
  description: "Production Next.js application",
  metadataBase: new URL("https://example.com"),
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <Header />
        <main>{children}</main>
        <Footer />
      </body>
    </html>
  );
}
```

## Nested Layouts, Loading, Error, Not-Found

```typescript
// src/app/dashboard/layout.tsx — wraps ALL /dashboard/* routes
export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex">
      <Sidebar />
      <div className="flex-1 p-6">{children}</div>
    </div>
  );
}

// src/app/dashboard/loading.tsx — auto Suspense fallback
export default function Loading() {
  return <div className="animate-pulse"><div className="h-8 bg-gray-200 rounded w-1/3" /></div>;
}

// src/app/dashboard/error.tsx — MUST be "use client"
"use client";
export default function Error({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <div className="text-center p-8">
      <h2>Something went wrong</h2>
      <button onClick={reset}>Try again</button>
    </div>
  );
}

// Trigger not-found programmatically
import { notFound } from "next/navigation";
export default async function BlogPost({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const post = await getPost(slug);
  if (!post) notFound();
  return <article>{/* ... */}</article>;
}
```

## Route Groups

Organize without affecting URLs using `(groupName)`:

```
src/app/
  (marketing)/layout.tsx    # Marketing layout
  (marketing)/page.tsx      # / (home)
  (marketing)/about/page.tsx
  (app)/layout.tsx          # App layout (sidebar)
  (app)/dashboard/page.tsx
  (auth)/layout.tsx         # Auth layout (centered)
  (auth)/login/page.tsx
```

---

# 2. Server Components vs Client Components

## Decision Framework

```
Does this component need...
  Browser APIs (window, document, localStorage)?     → "use client"
  Event handlers (onClick, onChange, onSubmit)?       → "use client"
  React hooks (useState, useEffect, useReducer)?     → "use client"
  Third-party client libraries (framer-motion, etc)? → "use client"
  None of the above?                                 → Server Component (default)
```

## The Boundary Pattern: Push "use client" Down

```typescript
// page.tsx — Server Component fetches data
export default async function ProductsPage() {
  const products = await getProducts(); // Server-side
  return <ProductFilters products={products} />; // Pass to client
}

// components/ProductFilters.tsx — Client Component handles interaction
"use client";
import { useState } from "react";

export default function ProductFilters({ products }: { products: Product[] }) {
  const [category, setCategory] = useState("all");
  const filtered = category === "all" ? products : products.filter((p) => p.category === category);
  return (
    <>
      <select value={category} onChange={(e) => setCategory(e.target.value)}>
        <option value="all">All</option>
        <option value="electronics">Electronics</option>
      </select>
      <div className="grid grid-cols-3 gap-4">
        {filtered.map((p) => <div key={p.id}>{p.name}</div>)}
      </div>
    </>
  );
}
```

## Composition: Server Components as Children of Client Components

```typescript
// Drawer.tsx — Client Component
"use client";
export default function Drawer({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button onClick={() => setOpen(true)}>Open</button>
      {open && <aside>{children}</aside>}
    </>
  );
}

// page.tsx — Server Component passes server-rendered content
import Drawer from "@/components/Drawer";
import ServerContent from "@/components/ServerContent";

export default function Page() {
  return <Drawer><ServerContent /></Drawer>;
}
```

| Requirement | Server | Client |
|---|---|---|
| Fetch data (DB, API, filesystem) | Yes | Via useEffect/Server Action |
| Keep secrets (API keys) | Yes | No |
| Reduce JS bundle | Yes | No |
| useState / useEffect / onClick | No | Yes |
| Browser APIs | No | Yes |

---

# 3. Data Fetching Patterns

## Server Component Fetch (Default)

```typescript
async function getPosts(): Promise<Post[]> {
  const res = await fetch("https://api.example.com/posts", {
    next: { revalidate: 3600 }, // ISR: revalidate hourly
  });
  if (!res.ok) throw new Error("Failed to fetch posts");
  return res.json();
}

export default async function BlogPage() {
  const posts = await getPosts();
  return <div className="grid grid-cols-3 gap-6">{posts.map((p) => <BlogCard key={p.id} post={p} />)}</div>;
}
```

### Parallel Fetching

```typescript
// GOOD: Parallel
const [user, orders, notifications] = await Promise.all([getUser(), getOrders(), getNotifications()]);

// BAD: Sequential waterfall
const user = await getUser();
const orders = await getOrders(); // waits for user
```

## Route Handlers (API Routes)

```typescript
// src/app/api/contact/route.ts
import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    if (!body.email || !body.message) {
      return NextResponse.json({ error: "Email and message required" }, { status: 400 });
    }
    await sendEmail({ to: "admin@example.com", body: body.message, replyTo: body.email });
    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// Dynamic segment: src/app/api/posts/[id]/route.ts
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const post = await getPostById(id);
  if (!post) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json(post);
}
```

### Streaming Response

```typescript
// src/app/api/stream/route.ts
export async function GET() {
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      for (let i = 0; i < 10; i++) {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ count: i })}\n\n`));
        await new Promise((r) => setTimeout(r, 1000));
      }
      controller.close();
    },
  });
  return new Response(stream, {
    headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" },
  });
}
```

## Server Actions (Form Mutations)

```typescript
// src/app/actions.ts
"use server";
import { revalidatePath } from "next/cache";
import { z } from "zod";

const ContactSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  message: z.string().min(10),
});

export type ContactFormState = {
  errors?: { name?: string[]; email?: string[]; message?: string[] };
  message?: string;
  success?: boolean;
};

export async function submitContact(
  prevState: ContactFormState,
  formData: FormData
): Promise<ContactFormState> {
  const validated = ContactSchema.safeParse({
    name: formData.get("name"),
    email: formData.get("email"),
    message: formData.get("message"),
  });

  if (!validated.success) {
    return { errors: validated.error.flatten().fieldErrors, message: "Validation failed" };
  }

  await saveContact(validated.data);
  revalidatePath("/contact");
  return { success: true, message: "Sent!" };
}
```

### Client Component with Server Action

```typescript
"use client";
import { useActionState } from "react";
import { submitContact, type ContactFormState } from "@/app/actions";

export default function ContactForm() {
  const [state, formAction, isPending] = useActionState(submitContact, {} as ContactFormState);

  return (
    <form action={formAction}>
      <input name="name" required />
      {state.errors?.name && <p className="text-red-600">{state.errors.name[0]}</p>}
      <input name="email" type="email" required />
      <textarea name="message" required />
      <button disabled={isPending}>{isPending ? "Sending..." : "Send"}</button>
      {state.success && <p className="text-green-600">{state.message}</p>}
    </form>
  );
}
```

### Data Fetching Decision Matrix

| Pattern | Use When | Example |
|---|---|---|
| Server Component fetch | Display data on page load | Blog listing, product pages |
| Route Handler (GET/POST) | External clients need API | Webhooks, mobile API |
| Server Action | User-initiated mutations | Form submissions, CRUD |
| Client-side fetch | Real-time updates, polling | Chat, live dashboards |

---

# 4. Streaming and Suspense

## Manual Suspense Boundaries

```typescript
import { Suspense } from "react";

export default function DashboardPage() {
  return (
    <div className="grid grid-cols-12 gap-6">
      <Suspense fallback={<ProfileSkeleton />}>
        <UserProfile />    {/* ~100ms — renders first */}
      </Suspense>
      <Suspense fallback={<OrdersSkeleton />}>
        <RecentOrders />   {/* ~500ms — streams when ready */}
      </Suspense>
      <Suspense fallback={<AnalyticsSkeleton />}>
        <Analytics />      {/* ~2000ms — streams last */}
      </Suspense>
    </div>
  );
}

// Each async Server Component fetches independently
async function Analytics() {
  const data = await getAnalytics(); // Slow fetch
  return <AnalyticsChart data={data} />;
}
```

## Skeleton Pattern

```typescript
export function CardSkeleton() {
  return (
    <div className="animate-pulse rounded-lg border p-4">
      <div className="h-48 bg-gray-200 rounded mb-4" />
      <div className="h-4 bg-gray-200 rounded w-3/4 mb-2" />
      <div className="h-4 bg-gray-200 rounded w-1/2" />
    </div>
  );
}
```

---

# 5. ISR vs SSG vs SSR Decision Matrix

## Static Site Generation (SSG)

```typescript
// Generate pages at build time
export async function generateStaticParams() {
  const slugs = await getAllPostSlugs();
  return slugs.map((slug) => ({ slug }));
}

export default async function BlogPost({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const post = await getPostBySlug(slug);
  if (!post) notFound();
  return <article>{/* ... */}</article>;
}
```

## Incremental Static Regeneration (ISR)

```typescript
// Time-based: fetch-level
const res = await fetch(url, { next: { revalidate: 3600 } });

// Segment-level
export const revalidate = 3600;

// On-demand: webhook/admin trigger
import { revalidatePath, revalidateTag } from "next/cache";

export async function POST(request: NextRequest) {
  const { path, tag, secret } = await request.json();
  if (secret !== process.env.REVALIDATION_SECRET) {
    return NextResponse.json({ error: "Invalid" }, { status: 401 });
  }
  if (tag) revalidateTag(tag);
  else if (path) revalidatePath(path);
  return NextResponse.json({ revalidated: true });
}
```

## Server-Side Rendering (SSR)

```typescript
export const dynamic = "force-dynamic"; // Force SSR

// Or: using cookies/headers auto-opts into dynamic
import { cookies } from "next/headers";
export default async function DashboardPage() {
  const cookieStore = await cookies();
  const session = cookieStore.get("session")?.value;
  const user = await getUserBySession(session);
  return <Dashboard user={user} />;
}
```

## Decision Matrix

| Factor | SSG | ISR | SSR |
|---|---|---|---|
| Response time | Instant (CDN) | Instant + bg revalidation | Server compute |
| Data freshness | Build time only | Configurable | Real-time |
| Personalization | No | No | Yes |
| Use cases | Docs, marketing, blog | E-commerce, news | Dashboards, auth pages |
| Cost | Lowest | Low | Higher |

## Route Segment Config

```typescript
export const dynamic = "auto" | "force-dynamic" | "error" | "force-static";
export const revalidate = false | 0 | number; // seconds
export const runtime = "nodejs" | "edge";
export const preferredRegion = "auto" | "iad1" | "syd1" | string[];
export const maxDuration = 60; // seconds
```

---

# 6. Parallel Routes and Intercepting Routes

## Parallel Routes

Render multiple pages simultaneously in the same layout using `@slotName` folders.

```
src/app/dashboard/
  layout.tsx          # Receives @analytics, @team as props
  page.tsx
  @analytics/page.tsx # Independent loading/error
  @team/page.tsx
```

```typescript
export default function DashboardLayout({
  children, analytics, team,
}: {
  children: React.ReactNode; analytics: React.ReactNode; team: React.ReactNode;
}) {
  return (
    <div>{children}
      <div className="grid grid-cols-2 gap-6">{analytics}{team}</div>
    </div>
  );
}
```

## Intercepting Routes

Show a modal when navigating via link, full page when navigating directly.

Convention: `(.)` same level, `(..)` one up, `(...)` root.

```
src/app/
  feed/
    page.tsx                    # Photo grid
    @modal/(.)photo/[id]/page.tsx  # Modal view (intercepted)
    @modal/default.tsx          # No modal default
    layout.tsx                  # Layout with modal slot
  photo/[id]/page.tsx           # Full page (direct navigation)
```

```typescript
// feed/layout.tsx
export default function FeedLayout({ children, modal }: { children: React.ReactNode; modal: React.ReactNode }) {
  return <>{children}{modal}</>;
}

// feed/@modal/(.)photo/[id]/page.tsx — Modal
export default async function PhotoModal({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const photo = await getPhoto(id);
  return <Modal><img src={photo.url} alt={photo.alt} /></Modal>;
}

// feed/@modal/default.tsx
export default function Default() { return null; }
```

---

# 7. Middleware Patterns

Middleware runs at the edge before every matched request. File: `src/middleware.ts`.

```typescript
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Auth guard
  const session = request.cookies.get("session")?.value;
  if (pathname.startsWith("/dashboard") && !session) {
    const login = new URL("/login", request.url);
    login.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(login);
  }

  // Geo redirect
  const country = request.geo?.country || "US";
  if (pathname === "/" && country === "AU") {
    return NextResponse.rewrite(new URL("/au", request.url));
  }

  // Security headers
  const response = NextResponse.next();
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api).*)"],
};
```

### JWT Auth Middleware

```typescript
import { jwtVerify } from "jose";

const PUBLIC_PATHS = ["/", "/login", "/register", "/blog"];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const token = request.cookies.get("auth-token")?.value;
  const isPublic = PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith("/blog/"));

  if (token) {
    try {
      await jwtVerify(token, new TextEncoder().encode(process.env.JWT_SECRET!));
      if (["/login", "/register"].includes(pathname)) {
        return NextResponse.redirect(new URL("/dashboard", request.url));
      }
    } catch {
      const res = NextResponse.redirect(new URL("/login", request.url));
      res.cookies.delete("auth-token");
      return res;
    }
  } else if (!isPublic) {
    const login = new URL("/login", request.url);
    login.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(login);
  }

  return NextResponse.next();
}
```

| Use Case | Pattern |
|---|---|
| Auth | Check session cookie, redirect to login |
| Redirects | URL rewrites, locale redirects |
| A/B Testing | Set cookie, rewrite to variant |
| Geolocation | `request.geo`, rewrite to localized page |
| Security Headers | Add CSP, X-Frame-Options |

> **See also**: `auth-universal` skill for comprehensive auth middleware patterns.

---

# 8. Metadata API and SEO

## Static Metadata

```typescript
export const metadata: Metadata = {
  title: { default: "My Site", template: "%s | My Site" },
  description: "Description",
  metadataBase: new URL("https://example.com"),
  openGraph: {
    type: "website", locale: "en_US", siteName: "My Site",
    images: [{ url: "/og-image.jpg", width: 1200, height: 630 }],
  },
  twitter: { card: "summary_large_image", creator: "@handle" },
  robots: { index: true, follow: true },
};
```

## Dynamic Metadata

```typescript
export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const { slug } = await params;
  const post = await getPostBySlug(slug);
  if (!post) return { title: "Not Found" };

  return {
    title: post.title,
    description: post.excerpt,
    openGraph: {
      title: post.title, type: "article", publishedTime: post.publishedAt,
      images: post.image ? [{ url: post.image, width: 1200, height: 630 }] : [],
    },
    alternates: { canonical: `https://example.com/blog/${slug}` },
  };
}
```

## generateStaticParams

```typescript
export async function generateStaticParams() {
  const posts = await getAllPosts();
  return posts.map((post) => ({ slug: post.slug }));
}

// Nested: /blog/[category]/[slug]
export async function generateStaticParams() {
  const posts = await getAllPosts();
  return posts.map((post) => ({ category: post.category, slug: post.slug }));
}
```

## Structured Data (JSON-LD)

```typescript
const articleSchema = {
  "@context": "https://schema.org", "@type": "Article",
  headline: post.title, description: post.excerpt,
  datePublished: post.publishedAt, dateModified: post.updatedAt,
  author: { "@type": "Person", name: post.author },
  mainEntityOfPage: { "@type": "WebPage", "@id": `https://example.com/blog/${slug}` },
};

return (
  <>
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(articleSchema) }} />
    <article>{/* ... */}</article>
  </>
);
```

## Sitemap and Robots

```typescript
// src/app/sitemap.ts
export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const posts = await getAllPosts();
  return [
    { url: "https://example.com", lastModified: new Date(), priority: 1.0 },
    { url: "https://example.com/blog", lastModified: new Date(), priority: 0.9 },
    ...posts.map((p) => ({
      url: `https://example.com/blog/${p.slug}`,
      lastModified: p.updatedAt || p.publishedAt, priority: 0.7,
    })),
  ];
}

// src/app/robots.ts
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", allow: "/", disallow: ["/admin/", "/api/"] }],
    sitemap: "https://example.com/sitemap.xml",
  };
}
```

> **See also**: `seo-geo-aeo` skill for comprehensive SEO strategy and geo-targeted patterns.

---

# 9. Caching Behavior

## The Four Caches

| Cache | What | Where | Opt Out |
|---|---|---|---|
| **Request Memoization** | Deduplicates identical fetch calls in single render | Server | `AbortController` |
| **Data Cache** | Persists fetch results across requests | Server | `cache: "no-store"` |
| **Full Route Cache** | Pre-rendered HTML + RSC payload | Server | `dynamic = "force-dynamic"` |
| **Router Cache** | Client-side visited route cache | Client | `router.refresh()` |

## Data Cache

```typescript
// Cached indefinitely (static pages default)
await fetch(url);

// ISR: revalidate hourly
await fetch(url, { next: { revalidate: 3600 } });

// No cache (SSR)
await fetch(url, { cache: "no-store" });

// Tag-based revalidation
await fetch(url, { next: { tags: ["posts"] } });
// Later: revalidateTag("posts");
```

## Caching Non-Fetch Data

```typescript
import { unstable_cache } from "next/cache";

const getCachedUser = unstable_cache(
  async (userId: string) => db.user.findUnique({ where: { id: userId } }),
  ["user"],
  { tags: ["user"], revalidate: 3600 }
);

// Request-level deduplication
import { cache } from "react";
export const getUser = cache(async (id: string) => {
  const res = await fetch(`/api/users/${id}`);
  return res.json();
});
```

## Revalidation

```typescript
"use server";
import { revalidatePath, revalidateTag } from "next/cache";

export async function updatePost(id: string, data: PostData) {
  await db.post.update({ where: { id }, data });
  revalidatePath("/blog");
  revalidateTag("posts");
}
```

## Cache Decision Flowchart

```
Same for every user?
  YES → Stale OK for minutes/hours?
    YES → ISR (revalidate: N)
    NO  → SSR or short revalidation
  NO → Personalized (cookies/headers)?
    YES → SSR (auto-dynamic)
```

---

# 10. Image Optimization (next/image)

```typescript
import Image from "next/image";
import heroImage from "@/public/hero.jpg";

// Local image: auto-sized, blur placeholder
<Image src={heroImage} alt="Hero" priority placeholder="blur" className="w-full h-auto" />

// Remote image: explicit dimensions
<Image src="https://cdn.example.com/photo.jpg" alt="Product" width={800} height={600} />

// Fill mode: container-relative (parent needs position: relative)
<div className="relative w-full h-64 md:h-96 rounded-lg overflow-hidden">
  <Image
    src={post.image} alt={post.title} fill
    className="object-cover"
    sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
    priority
  />
</div>
```

### next.config.ts Image Config

```typescript
images: {
  remotePatterns: [{ protocol: "https", hostname: "cdn.example.com" }],
  formats: ["image/avif", "image/webp"],
  deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
},
```

### Checklist

| Rule | Why |
|---|---|
| Always `alt` text | Accessibility |
| `priority` for LCP image | Above-fold preload |
| `fill` + `sizes` for responsive | Avoids downloading oversized images |
| `width`/`height` for fixed images | Prevents CLS |
| `placeholder="blur"` for local images | Perceived performance |
| Configure `remotePatterns` | Security whitelist |

---

# 11. MDX/Content Integration

## Setup

```bash
npm install @next/mdx @mdx-js/loader @mdx-js/react next-mdx-remote gray-matter
```

```typescript
// next.config.ts
pageExtensions: ["js", "jsx", "md", "mdx", "ts", "tsx"],
```

## Local MDX with Frontmatter

```typescript
// src/lib/blog.ts
import fs from "fs";
import path from "path";
import matter from "gray-matter";

const POSTS_DIR = path.join(process.cwd(), "src/content/posts");

export function getAllPosts(): Post[] {
  return fs.readdirSync(POSTS_DIR)
    .filter((f) => f.endsWith(".mdx"))
    .map((filename) => {
      const { data, content } = matter(fs.readFileSync(path.join(POSTS_DIR, filename), "utf8"));
      return { slug: filename.replace(".mdx", ""), ...data, content } as Post;
    })
    .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
}

export function getPostBySlug(slug: string): Post | null {
  try {
    const { data, content } = matter(fs.readFileSync(path.join(POSTS_DIR, `${slug}.mdx`), "utf8"));
    return { slug, ...data, content } as Post;
  } catch { return null; }
}
```

## Rendering with next-mdx-remote

```typescript
import { MDXRemote } from "next-mdx-remote/rsc";
import { mdxComponents } from "@/components/mdx-components";

export default async function BlogPost({ params }: Props) {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) notFound();

  return (
    <article className="prose max-w-none">
      <MDXRemote source={post.content} components={mdxComponents} />
    </article>
  );
}
```

## Custom MDX Components

```typescript
// src/components/mdx-components.tsx
import Image from "next/image";
import Link from "next/link";

export const mdxComponents = {
  a: ({ href, children, ...props }: React.AnchorHTMLAttributes<HTMLAnchorElement>) => {
    if (href?.startsWith("http")) {
      return <a href={href} target="_blank" rel="noopener noreferrer" {...props}>{children}</a>;
    }
    return <Link href={href || "#"}>{children}</Link>;
  },
  img: ({ src, alt }: React.ImgHTMLAttributes<HTMLImageElement>) => (
    <Image src={src || ""} alt={alt || ""} width={800} height={450} className="rounded-lg my-4" />
  ),
  Callout: ({ type = "info", children }: { type?: "info" | "warning" | "error"; children: React.ReactNode }) => {
    const styles = { info: "bg-blue-50 border-blue-500", warning: "bg-yellow-50 border-yellow-500", error: "bg-red-50 border-red-500" };
    return <div className={`border-l-4 p-4 my-4 rounded ${styles[type]}`}>{children}</div>;
  },
};
```

---

# Production Configuration

## next.config.ts Template

```typescript
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone", // Docker/Railway
  images: {
    remotePatterns: [{ protocol: "https", hostname: "cdn.example.com" }],
    formats: ["image/avif", "image/webp"],
  },
  pageExtensions: ["js", "jsx", "md", "mdx", "ts", "tsx"],
  async redirects() {
    return [{ source: "/old-blog/:slug", destination: "/blog/:slug", permanent: true }];
  },
  async headers() {
    return [{
      source: "/(.*)",
      headers: [
        { key: "X-Frame-Options", value: "DENY" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
      ],
    }];
  },
};
export default nextConfig;
```

## Font Optimization (next/font)

```typescript
import { Inter } from "next/font/google";
import localFont from "next/font/local";

const inter = Inter({ subsets: ["latin"], display: "swap", variable: "--font-inter" });
const custom = localFont({
  src: [{ path: "../fonts/Custom-Regular.woff2", weight: "400" }, { path: "../fonts/Custom-Bold.woff2", weight: "700" }],
  variable: "--font-custom",
});

// Apply in layout
<html className={`${inter.variable} ${custom.variable}`}>
```

## Google Analytics with Consent

```typescript
import Script from "next/script";
const GA_ID = process.env.NEXT_PUBLIC_GA_ID;

// In layout <head>
{GA_ID && (
  <>
    <Script src={`https://www.googletagmanager.com/gtag/js?id=${GA_ID}`} strategy="afterInteractive" />
    <Script id="ga" strategy="afterInteractive">{`
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('consent', 'default', { 'analytics_storage': 'denied' });
      gtag('js', new Date());
      gtag('config', '${GA_ID}', { 'anonymize_ip': true });
    `}</Script>
  </>
)}
```

---

# Common Anti-Patterns

| Anti-Pattern | Fix |
|---|---|
| `"use client"` on page.tsx with useEffect fetch | Keep page as Server Component, push interactivity to child Client Components |
| Client-side fetch for static data | Use Server Component fetch |
| Missing error.tsx boundaries | Add error.tsx at each meaningful route segment |
| Dynamic pages without generateStaticParams | Pre-render known routes at build time |
| `<Image fill>` without `sizes` | Always provide `sizes` to avoid downloading oversized images |
| Sequential awaits in Server Components | Use `Promise.all()` for parallel fetching |
| Putting secrets in Client Components | Keep API keys in Server Components or Server Actions |

---

# Integrates With

| Skill/Module | Relationship |
|---|---|
| **`elite-frontend-developer`** skill | General React, testing, performance, a11y. This skill adds Next.js layers on top. |
| **`auth-universal`** skill | Auth middleware patterns. Combine with Section 7 for Next.js auth guards. |
| **`seo-geo-aeo`** skill | SEO strategy. Combine with Section 8 for Next.js Metadata API. |
| **`supabase-database-setup`** module | Supabase `nextjs-client.ts`. Use with Section 3 for server-side Supabase queries. |
| **`astro-blog-seo`** module | Contrast: Astro = zero JS content sites. Next.js = interactive apps with content. |
| **`caching-universal`** skill | General caching. Section 9 covers Next.js-specific caching layers. |
| **`deployment-patterns`** / **`railway-deployment`** skills | Use `output: "standalone"` for Railway/Docker. |

---

# Version Compatibility

| Feature | Next.js 14 | Next.js 15 | Next.js 16 (Oct 2025) |
|---|---|---|---|
| App Router | Stable | Stable | Stable |
| Server Actions | Stable | Stable | Stable |
| `params` as Promise | No (direct) | Yes (await) | Yes (await) |
| PPR (Partial Prerendering) | Experimental | Experimental | **Stable** |
| Cache Components | N/A | N/A | **Stable** |
| `useActionState` | `useFormState` | `useActionState` | `useActionState` |
| Turbopack | Alpha | Beta | **Default bundler** |
| React version | React 18 | React 19 | React 19.2+ (Compiler v1.0) |
| Node.js minimum | 18.17 | 18.18 | 20+ (target 24 LTS) |
| ESLint | eslintrc | eslintrc or flat | **Flat config only (ESLint 10)** |

**Migration note** (v14 to v15+): `params` and `searchParams` became Promises:

```typescript
// v14: export default function Page({ params }: { params: { slug: string } })
// v15+: export default async function Page({ params }: { params: Promise<{ slug: string }> })
//         const { slug } = await params;
```

**Next.js 16 highlights** (Oct 2025):
- **PPR (Partial Prerendering)**: Stable. Combine static shells with dynamic holes. No config needed.
- **Cache Components**: New primitive for granular caching at component level. Replaces complex `unstable_cache` patterns.
- **Turbopack**: Now the default bundler. Webpack still available via `--webpack` flag.
- **React 19 Compiler**: Auto-memoization. Remove manual `useMemo`/`useCallback` when using Compiler.
- **ESLint 10**: Flat config only. Use `eslint.config.js` (no `.eslintrc`).
- **Node.js**: Target Node.js 24 LTS. Node.js 20 EOL April 2026.

---

**Remember**: Start with everything on the server. Only add `"use client"` when you have a concrete reason. This gives you the smallest JS bundle and fastest initial page load.
