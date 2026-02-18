# Headless CMS Universal - Production Guide

> Multi-provider headless CMS integration for content-driven applications with Git-based and API-based workflows

**Version**: 1.0.0
**Last Updated**: 2026-02-16
**Architecture**: Multi-provider (Decap + Sanity + Contentful + Strapi + DatoCMS)
**Stack**: TypeScript / React / Next.js / Astro

---

## Table of Contents

1. [Overview](#overview)
2. [Decision Matrix](#decision-matrix)
3. [Decap CMS (Git-Based)](#decap-cms-git-based)
4. [Sanity Integration](#sanity-integration)
5. [Contentful Integration](#contentful-integration)
6. [Strapi Integration](#strapi-integration)
7. [DatoCMS Integration](#datocms-integration)
8. [Common Patterns](#common-patterns)
9. [Integrates With](#integrates-with)

---

## Overview

**What**: Universal headless CMS integration patterns covering Git-based (Decap) and API-based (Sanity, Contentful, Strapi, DatoCMS) systems with TypeScript, preview workflows, and production deployment.

**Why**: Wrong CMS choice costs 40-80 hours of rework. Standardized integration patterns prevent repeated mistakes across projects.

**How**: Decision matrix for selection, per-CMS integration code, common abstractions for preview/webhooks/media.

---

## Decision Matrix

### Quick Selection Guide

| Factor | Decap CMS | Sanity | Contentful | Strapi | DatoCMS |
|--------|-----------|--------|------------|--------|---------|
| **Cost (small/scale)** | Free / Free | Free (3 users) / $99/mo | Free (5 users) / $489/mo | Free (self-host) / Server cost | Free (1 user) / $99/mo |
| **Content storage** | Git (your repo) | Sanity Cloud | Contentful Cloud | Your database | DatoCMS Cloud |
| **Real-time collab** | No | Yes | Limited | No | Yes |
| **API type** | None (static files) | GROQ / GraphQL | REST / GraphQL | REST / GraphQL | GraphQL |
| **Self-hostable** | Yes | No | No | Yes | No |
| **Editor/Dev experience** | Basic / Simple | Excellent / Excellent | Good / Good | Good / Good | Good / Excellent |
| **Media handling** | Git LFS / manual | Built-in CDN | Built-in CDN | Local / S3 | Built-in CDN (Imgix) |
| **Localization** | Manual | Built-in | Built-in | Plugin | Built-in |
| **Ideal team size** | 1-3 | 1-50 | 5-100 | 1-20 | 1-30 |

### When to Choose Each

**Decap CMS** -- Solo/small team, content in Git (MDX/Markdown), zero cost, simple blog or docs, full content ownership.

**Sanity** -- Real-time collaboration, complex content relationships, custom editing (Portable Text), large teams, GROQ flexibility.

**Contentful** -- Enterprise SLAs/compliance, large editorial teams with RBAC, multi-channel delivery, GraphQL-first.

**Strapi** -- Full infrastructure control, self-hosting mandatory (data sovereignty), custom backend logic, no per-seat licensing.

**DatoCMS** -- Image-heavy content, strong validation, real-time previews, modular content blocks, excellent TypeScript codegen.

### Cost at Scale (50 editors, 10K items)

| CMS | Monthly | Notes |
|-----|---------|-------|
| Decap | $0 | Git storage only |
| Sanity | $949 | Business plan |
| Contentful | $2,499 | Enterprise (est.) |
| Strapi | $200-500 | Server + DB hosting |
| DatoCMS | $499 | Business plan |

---

## Decap CMS (Git-Based)

> Formerly Netlify CMS. Open-source CMS storing content directly in your repository as Markdown/MDX files.

### Architecture

```
Editor (Browser /admin/) ──> Git Provider (GitHub/GitLab) ──> Static Site (Next.js/Astro)
     commits content files directly to repo          builds from Git content at deploy
```

### admin/config.yml Setup

Production-ready config (derived from ashganda-nextjs implementation):

```yaml
# public/admin/config.yml
backend:
  name: github
  repo: your-org/your-repo
  branch: main
  base_url: https://your-site.com
  auth_endpoint: /api/auth

local_backend: true  # Enable local dev proxy

media_folder: "public/images"
public_folder: "/images"
site_url: https://your-site.com
display_url: https://your-site.com

collections:
  - name: "blog"
    label: "Blog Posts"
    folder: "src/content/posts"
    create: true
    slug: "{{slug}}"
    extension: "mdx"
    format: "frontmatter"
    identifier_field: "title"
    summary: "{{title}} - {{date}}"
    fields:
      - { label: "Title", name: "title", widget: "string" }
      - { label: "Description", name: "description", widget: "text" }
      - { label: "Publish Date", name: "date", widget: "datetime", format: "YYYY-MM-DD" }
      - { label: "Author", name: "author", widget: "string", default: "Author Name" }
      - { label: "Tags", name: "tags", widget: "list", required: false }
      - { label: "Featured Image", name: "image", widget: "image", required: false }
      - { label: "Slug", name: "slug", widget: "string", hint: "URL-friendly identifier" }
      - { label: "Keywords", name: "keywords", widget: "list", required: false }
      - { label: "OG Title", name: "ogTitle", widget: "string", required: false }
      - { label: "OG Description", name: "ogDescription", widget: "text", required: false }
      - { label: "OG Image", name: "ogImage", widget: "image", required: false }
      - { label: "Canonical URL", name: "canonical", widget: "string", required: false }
      - { label: "Body", name: "body", widget: "markdown" }
```

### admin/index.html

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="robots" content="noindex" />
  <title>Content Manager</title>
</head>
<body>
  <script src="https://unpkg.com/decap-cms@^3.3.3/dist/decap-cms.js"></script>
  <!-- Optional: Image paste & drop (see decap-image-paste module) -->
  <script src="/admin/decap-image-paste.min.js"
    data-repo="your-org/your-repo" data-branch="main"
    data-media-folder="public/images/blog" data-public-folder="/images/blog">
  </script>
</body>
</html>
```

### Collection Types

**Folder collections** (multiple items): Blog posts, docs -- one file per item in a directory.

**File collections** (singletons): Settings, navigation -- specific files.

```yaml
collections:
  - name: "settings"
    label: "Site Settings"
    files:
      - name: "general"
        label: "General Settings"
        file: "src/content/settings/general.json"
        fields:
          - { label: "Site Title", name: "siteTitle", widget: "string" }
          - { label: "Logo", name: "logo", widget: "image" }
          - label: "Social Links"
            name: "social"
            widget: "object"
            fields:
              - { label: "Twitter", name: "twitter", widget: "string", required: false }
              - { label: "GitHub", name: "github", widget: "string", required: false }
```

### Widget Types Reference

| Widget | Use Case | Key Options |
|--------|----------|-------------|
| `string` | Short text, titles | `default`, `pattern` (regex) |
| `text` | Long text (no formatting) | `default` |
| `markdown` | Rich text body | hint |
| `number` | Numeric values | `min`, `max`, `step`, `value_type` |
| `boolean` | Toggles | `default` |
| `datetime` | Dates/times | `format`, `date_format`, `time_format` |
| `select` | Dropdowns | `options`, `multiple` |
| `list` | Arrays | `field` (single type), `fields` (objects) |
| `object` | Nested objects | `fields`, `collapsed` |
| `relation` | Cross-references | `collection`, `search_fields`, `value_field` |
| `image` / `file` | Uploads | `media_folder`, `allow_multiple` |
| `color` | Color picker | `allowInput`, `enableAlpha` |
| `code` | Code blocks | `default_language`, `allow_language_selection` |

### Git Gateway vs GitHub Backend

| Feature | Git Gateway | GitHub Backend |
|---------|------------|----------------|
| **Auth** | Netlify Identity | GitHub OAuth (self-managed) |
| **Hosting** | Netlify only | Any host (Vercel, Railway, etc.) |
| **Rate limits** | Higher (Netlify proxy) | GitHub API (5K/hr) |

**Git Gateway**: `backend: { name: git-gateway, branch: main }`

**GitHub Backend** -- requires custom OAuth endpoint:

```typescript
// src/app/api/auth/route.ts
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get('code');

  if (!code) {
    const clientId = process.env.GITHUB_CLIENT_ID;
    const redirectUri = `${request.nextUrl.origin}/api/auth`;
    return NextResponse.redirect(
      `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=repo,user`
    );
  }

  const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
    }),
  });

  const data = await tokenResponse.json();
  if (data.error) return NextResponse.json({ error: 'Auth failed' }, { status: 400 });

  // Return token via postMessage (Decap CMS protocol)
  const html = `<!DOCTYPE html><html><body><script>
    (function() {
      window.addEventListener("message", function(e) {
        window.opener.postMessage(
          'authorization:github:success:${JSON.stringify({ token: data.access_token, provider: 'github' })}',
          e.origin
        );
      }, false);
      window.opener.postMessage("authorizing:github", "*");
    })();
  </script></body></html>`;

  return new NextResponse(html, { headers: { 'Content-Type': 'text/html' } });
}
```

### Local Development Proxy

```bash
npm install decap-server --save-dev
# package.json: "dev:cms": "concurrently \"npm run dev\" \"npx decap-server\""
```

Set `local_backend: true` in config.yml. Proxy runs on `http://localhost:8081`, reads/writes files on disk. Disable for production.

### Reading Content in Next.js (MDX)

```typescript
// src/lib/blog.ts
import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';

const postsDirectory = path.join(process.cwd(), 'src/content/posts');

export interface PostMeta {
  slug: string; title: string; description: string; date: string;
  author: string; image?: string; tags?: string[];
  keywords?: string[]; ogTitle?: string; ogDescription?: string;
  ogImage?: string; canonical?: string;
}

export interface Post extends PostMeta { content: string; }

export function getAllPosts(): PostMeta[] {
  if (!fs.existsSync(postsDirectory)) return [];
  return fs.readdirSync(postsDirectory)
    .filter((f) => f.endsWith('.mdx') || f.endsWith('.md'))
    .map((fileName) => {
      const slug = fileName.replace(/\.(mdx|md)$/, '');
      const { data } = matter(fs.readFileSync(path.join(postsDirectory, fileName), 'utf8'));
      return { slug, title: data.title || slug, description: data.description || '',
        date: data.date || new Date().toISOString(), author: data.author || 'Author',
        image: data.image, tags: data.tags || [], keywords: data.keywords,
        ogTitle: data.ogTitle, ogDescription: data.ogDescription,
        ogImage: data.ogImage, canonical: data.canonical } as PostMeta;
    })
    .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
}

export function getPostBySlug(slug: string): Post | null {
  const mdxPath = path.join(postsDirectory, `${slug}.mdx`);
  const mdPath = path.join(postsDirectory, `${slug}.md`);
  const fullPath = fs.existsSync(mdxPath) ? mdxPath : fs.existsSync(mdPath) ? mdPath : null;
  if (!fullPath) return null;
  const { data, content } = matter(fs.readFileSync(fullPath, 'utf8'));
  return { slug, content, title: data.title || slug, description: data.description || '',
    date: data.date || new Date().toISOString(), author: data.author || 'Author',
    image: data.image, tags: data.tags || [], keywords: data.keywords,
    ogTitle: data.ogTitle, ogDescription: data.ogDescription,
    ogImage: data.ogImage, canonical: data.canonical };
}
```

### Rendering MDX in Next.js

```typescript
// src/app/blog/[slug]/page.tsx
import { MDXRemote } from 'next-mdx-remote/rsc';
import { getPostBySlug, getPostSlugs } from '@/lib/blog';
import { mdxComponents } from '@/components/mdx-components';
import { notFound } from 'next/navigation';
import { Metadata } from 'next';

export async function generateStaticParams() {
  return getPostSlugs().map((slug) => ({ slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) return { title: 'Not Found' };
  return {
    title: post.title, description: post.description,
    openGraph: { title: post.ogTitle || post.title, type: 'article', publishedTime: post.date,
      images: post.ogImage ? [post.ogImage] : post.image ? [post.image] : [] },
    alternates: { canonical: post.canonical || `/blog/${slug}` },
  };
}

export default async function BlogPost({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) notFound();
  return (
    <article>
      <h1>{post.title}</h1>
      <div className="prose max-w-none">
        <MDXRemote source={post.content} components={mdxComponents} />
      </div>
    </article>
  );
}
```

---

## Sanity Integration

> Real-time structured content platform with GROQ query language.

### Setup

```bash
npm create sanity@latest -- --project your-project-id --dataset production
npm install next-sanity @sanity/image-url @sanity/client
```

### Schema Definitions

```typescript
// sanity/schemas/post.ts
import { defineField, defineType } from 'sanity';

export const postType = defineType({
  name: 'post', title: 'Blog Post', type: 'document',
  fields: [
    defineField({ name: 'title', type: 'string', validation: (Rule) => Rule.required().max(100) }),
    defineField({ name: 'slug', type: 'slug', options: { source: 'title', maxLength: 96 },
      validation: (Rule) => Rule.required() }),
    defineField({ name: 'author', type: 'reference', to: [{ type: 'author' }] }),
    defineField({ name: 'mainImage', type: 'image', options: { hotspot: true },
      fields: [defineField({ name: 'alt', type: 'string', validation: (Rule) => Rule.required() })] }),
    defineField({ name: 'categories', type: 'array', of: [{ type: 'reference', to: [{ type: 'category' }] }] }),
    defineField({ name: 'publishedAt', type: 'datetime' }),
    defineField({ name: 'excerpt', type: 'text', rows: 3, validation: (Rule) => Rule.max(200) }),
    defineField({ name: 'body', type: 'blockContent' }),
    defineField({ name: 'seo', type: 'object', fields: [
      defineField({ name: 'metaTitle', type: 'string' }),
      defineField({ name: 'metaDescription', type: 'text', rows: 3 }),
      defineField({ name: 'ogImage', type: 'image' }),
    ]}),
  ],
  preview: {
    select: { title: 'title', author: 'author.name', media: 'mainImage' },
    prepare({ title, author, media }) {
      return { title, subtitle: author ? `by ${author}` : '', media };
    },
  },
});
```

### GROQ Queries

```typescript
// src/lib/sanity/queries.ts
import { groq } from 'next-sanity';

export const postsQuery = groq`
  *[_type == "post" && defined(slug.current)] | order(publishedAt desc) {
    _id, title, slug, publishedAt, excerpt,
    mainImage { asset -> { _id, url, metadata { dimensions, lqip } }, alt },
    "author": author -> { name, image },
    "categories": categories[] -> { title, slug }
  }
`;

export const postBySlugQuery = groq`
  *[_type == "post" && slug.current == $slug][0] {
    _id, title, slug, publishedAt, excerpt, body,
    mainImage { asset -> { _id, url, metadata { dimensions, lqip } }, alt },
    "author": author -> { name, image, bio },
    "categories": categories[] -> { title, slug },
    seo { metaTitle, metaDescription, ogImage { asset -> { url } } },
    "relatedPosts": *[_type == "post" && _id != ^._id &&
      count(categories[@._ref in ^.^.categories[]._ref]) > 0
    ] | order(publishedAt desc) [0...3] { title, slug, mainImage, publishedAt }
  }
`;
```

### Client Setup

```typescript
// src/lib/sanity/client.ts
import { createClient } from 'next-sanity';
import imageUrlBuilder from '@sanity/image-url';

const config = {
  projectId: process.env.NEXT_PUBLIC_SANITY_PROJECT_ID!,
  dataset: process.env.NEXT_PUBLIC_SANITY_DATASET || 'production',
  apiVersion: '2024-01-01',
  useCdn: process.env.NODE_ENV === 'production',
};

export const client = createClient(config);

export const previewClient = createClient({
  ...config, useCdn: false,
  token: process.env.SANITY_API_READ_TOKEN,
  perspective: 'previewDrafts',
});

export function getClient(preview = false) {
  return preview ? previewClient : client;
}

const builder = imageUrlBuilder(client);
export function urlForImage(source: any) { return builder.image(source); }
```

### Real-Time Preview with next-sanity

```typescript
// src/app/api/draft/route.ts
import { draftMode } from 'next/headers';
import { redirect } from 'next/navigation';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  if (searchParams.get('secret') !== process.env.SANITY_PREVIEW_SECRET) {
    return new Response('Invalid token', { status: 401 });
  }
  (await draftMode()).enable();
  redirect(searchParams.get('slug') ? `/blog/${searchParams.get('slug')}` : '/');
}
```

```typescript
// Page with LiveQuery preview support
import { draftMode } from 'next/headers';
import { LiveQuery } from 'next-sanity/preview';
import { PortableText } from '@portabletext/react';

export default async function PostPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const { isEnabled: preview } = await draftMode();
  const post = await getClient(preview).fetch(postBySlugQuery, { slug });

  if (preview) {
    return (
      <LiveQuery enabled={preview} query={postBySlugQuery} params={{ slug }} initialData={post}>
        {(data) => <PostContent post={data} />}
      </LiveQuery>
    );
  }
  return <PostContent post={post} />;
}
```

---

## Contentful Integration

> Enterprise-grade headless CMS with REST and GraphQL APIs.

### Setup

```bash
npm install contentful @contentful/rich-text-react-renderer @contentful/rich-text-types
```

### Client

```typescript
// src/lib/contentful/client.ts
import { createClient } from 'contentful';

export const contentfulClient = createClient({
  space: process.env.CONTENTFUL_SPACE_ID!,
  accessToken: process.env.CONTENTFUL_ACCESS_TOKEN!,
});

export const previewClient = createClient({
  space: process.env.CONTENTFUL_SPACE_ID!,
  accessToken: process.env.CONTENTFUL_PREVIEW_TOKEN!,
  host: 'preview.contentful.com',
});

export function getClient(preview = false) { return preview ? previewClient : contentfulClient; }
```

### GraphQL Queries

```typescript
const ENDPOINT = `https://graphql.contentful.com/content/v1/spaces/${process.env.CONTENTFUL_SPACE_ID}`;

async function fetchGraphQL(query: string, preview = false) {
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json',
      Authorization: `Bearer ${preview ? process.env.CONTENTFUL_PREVIEW_TOKEN : process.env.CONTENTFUL_ACCESS_TOKEN}` },
    body: JSON.stringify({ query }),
    next: { revalidate: preview ? 0 : 3600 },
  });
  const json = await res.json();
  if (json.errors) throw new Error(`Contentful Error: ${JSON.stringify(json.errors)}`);
  return json.data;
}

export async function getPostBySlugGraphQL(slug: string, preview = false) {
  const data = await fetchGraphQL(`query {
    blogPostCollection(where: { slug: "${slug}" }, preview: ${preview}, limit: 1) {
      items {
        title slug excerpt publishDate
        body { json links {
          assets { block { sys { id } url width height description } }
        }}
        featuredImage { url width height description }
        author { name avatar { url } }
        seoTitle seoDescription ogImage { url }
      }
    }
  }`, preview);
  return data.blogPostCollection.items[0] || null;
}
```

### Rich Text Rendering

```typescript
// src/components/contentful/RichText.tsx
import { documentToReactComponents, Options } from '@contentful/rich-text-react-renderer';
import { BLOCKS, INLINES, MARKS } from '@contentful/rich-text-types';
import Image from 'next/image';

export function RichText({ content, links }: { content: any; links?: any }) {
  const assetMap = new Map<string, any>();
  links?.assets?.block?.forEach((a: any) => assetMap.set(a.sys.id, a));

  const options: Options = {
    renderNode: {
      [BLOCKS.EMBEDDED_ASSET]: (node) => {
        const asset = assetMap.get(node.data.target.sys.id);
        if (!asset) return null;
        return (
          <figure className="my-8">
            <Image src={`https:${asset.url}`} alt={asset.description || ''}
              width={asset.width} height={asset.height} className="rounded-lg" />
          </figure>
        );
      },
      [INLINES.HYPERLINK]: (node, children) => (
        <a href={node.data.uri} target="_blank" rel="noopener noreferrer">{children}</a>
      ),
    },
  };

  return <>{documentToReactComponents(content, options)}</>;
}
```

---

## Strapi Integration

> Open-source, self-hosted headless CMS with REST and GraphQL APIs.

### Setup

```bash
npx create-strapi-app@latest my-cms --quickstart
```

### Client

```typescript
// src/lib/strapi/client.ts
const STRAPI_URL = process.env.STRAPI_URL || 'http://localhost:1337';

export async function strapiQuery<T>(endpoint: string, options: {
  populate?: string[]; filters?: Record<string, any>;
  sort?: string[]; pagination?: { page: number; pageSize: number };
  publicationState?: 'live' | 'preview';
} = {}): Promise<{ data: T; meta: any }> {
  const params = new URLSearchParams();

  options.populate?.forEach((p, i) => params.set(`populate[${i}]`, p));
  options.sort?.forEach((s, i) => params.set(`sort[${i}]`, s));
  if (options.pagination) {
    params.set('pagination[page]', String(options.pagination.page));
    params.set('pagination[pageSize]', String(options.pagination.pageSize));
  }
  if (options.publicationState) params.set('publicationState', options.publicationState);
  if (options.filters) {
    const flatten = (obj: any, prefix = 'filters') => {
      for (const [k, v] of Object.entries(obj)) {
        if (typeof v === 'object' && !Array.isArray(v)) flatten(v, `${prefix}[${k}]`);
        else params.set(`${prefix}[${k}]`, String(v));
      }
    };
    flatten(options.filters);
  }

  const res = await fetch(`${STRAPI_URL}/api/${endpoint}?${params}`, {
    headers: { Authorization: `Bearer ${process.env.STRAPI_API_TOKEN}` },
    next: { revalidate: 60 },
  });
  if (!res.ok) throw new Error(`Strapi error: ${res.status}`);
  return res.json();
}

export async function getAllPosts(preview = false) {
  return strapiQuery('posts', {
    populate: ['featuredImage', 'author', 'categories', 'seo'],
    sort: ['publishDate:desc'],
    publicationState: preview ? 'preview' : 'live',
  });
}

export async function getPostBySlug(slug: string, preview = false) {
  const result = await strapiQuery('posts', {
    filters: { slug: { $eq: slug } },
    populate: ['featuredImage', 'author', 'categories', 'seo'],
    publicationState: preview ? 'preview' : 'live',
  });
  return (result.data as any[])[0] || null;
}
```

---

## DatoCMS Integration

> Developer-friendly CMS with GraphQL API, real-time previews, and Imgix-powered images.

### Client

```typescript
// src/lib/datocms/client.ts
export async function datocmsQuery<T = any>(query: string, options: {
  preview?: boolean; variables?: Record<string, any>;
} = {}): Promise<T> {
  const { preview = false, variables = {} } = options;
  const url = preview ? 'https://graphql.datocms.com/preview' : 'https://graphql.datocms.com';

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json',
      Authorization: `Bearer ${process.env.DATOCMS_API_TOKEN}` },
    body: JSON.stringify({ query, variables }),
    next: { revalidate: preview ? 0 : 3600 },
  });
  const json = await res.json();
  if (json.errors) throw new Error(`DatoCMS error: ${JSON.stringify(json.errors)}`);
  return json.data;
}
```

### Queries with Responsive Images

```typescript
export const ALL_POSTS_QUERY = `
  query AllPosts($first: IntType = 20, $skip: IntType = 0) {
    allPosts(first: $first, skip: $skip, orderBy: _publishedAt_DESC) {
      id title slug excerpt _publishedAt
      coverImage {
        responsiveImage(imgixParams: { fit: crop, w: 800, h: 450, auto: format }) {
          srcSet webpSrcSet sizes src width height alt base64
        }
      }
      author { name picture { url(imgixParams: { w: 48, h: 48, fit: crop }) } }
      categories { name slug }
    }
    _allPostsMeta { count }
  }
`;
```

### Rendering with react-datocms

```typescript
import { Image as DatoImage, StructuredText } from 'react-datocms';

// DatoImage handles responsive images with blur-up placeholder automatically
<DatoImage data={post.coverImage.responsiveImage} />

// StructuredText renders DatoCMS content blocks
<StructuredText data={post.content} renderBlock={({ record }) => {
  if (record.__typename === 'ImageBlockRecord') {
    return <DatoImage data={record.image.responsiveImage} />;
  }
  return null;
}} />
```

---

## Common Patterns

### Unified CMS Provider Abstraction

```typescript
// src/lib/cms/index.ts
export interface CMSPost {
  id: string; title: string; slug: string; excerpt: string;
  body: any; publishedAt: string;
  author: { name: string; avatar?: string };
  featuredImage?: { url: string; alt: string; width: number; height: number };
  categories: { name: string; slug: string }[];
  seo?: { title?: string; description?: string; ogImage?: string };
}

export interface CMSProvider {
  getAllPosts(preview?: boolean): Promise<CMSPost[]>;
  getPostBySlug(slug: string, preview?: boolean): Promise<CMSPost | null>;
}

export function getCMSProvider(): CMSProvider {
  switch (process.env.CMS_PROVIDER || 'decap') {
    case 'sanity': return new SanityProvider();
    case 'contentful': return new ContentfulProvider();
    case 'strapi': return new StrapiProvider();
    case 'datocms': return new DatoCMSProvider();
    default: return new DecapProvider();
  }
}
```

### Preview & Draft Mode (All Providers)

```typescript
// src/app/api/draft/route.ts -- universal draft mode endpoint
import { draftMode } from 'next/headers';
import { redirect } from 'next/navigation';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  if (searchParams.get('secret') !== process.env.CMS_PREVIEW_SECRET) {
    return new Response('Invalid preview token', { status: 401 });
  }
  (await draftMode()).enable();
  redirect(searchParams.get('slug') ? `/blog/${searchParams.get('slug')}` : '/');
}
```

```typescript
// src/components/PreviewBar.tsx -- visual indicator for draft mode
'use client';
import { useRouter } from 'next/navigation';

export function PreviewBar() {
  const router = useRouter();
  return (
    <div className="fixed bottom-0 left-0 right-0 bg-yellow-500 text-black text-center py-2 z-50">
      <strong>Preview Mode</strong> -- You are viewing draft content
      <button onClick={async () => { await fetch('/api/disable-draft'); router.refresh(); }}
        className="ml-4 px-3 py-1 bg-black text-white rounded text-sm">
        Exit Preview
      </button>
    </div>
  );
}
```

### Webhook-Triggered Rebuilds & ISR

```typescript
// src/app/api/revalidate/route.ts
import { revalidatePath, revalidateTag } from 'next/cache';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  if (request.headers.get('x-webhook-secret') !== process.env.REVALIDATION_SECRET) {
    return NextResponse.json({ error: 'Invalid secret' }, { status: 401 });
  }
  const body = await request.json();
  const slug = body.slug || body.fields?.slug?.['en-US'] || body.slugCurrent;

  if (slug) revalidatePath(`/blog/${slug}`);
  revalidatePath('/blog');
  revalidateTag('posts');

  return NextResponse.json({ revalidated: true, timestamp: Date.now() });
}
```

| CMS | Webhook Events | Trigger |
|-----|---------------|---------|
| Sanity | Document published/unpublished | Webhook to `/api/revalidate` |
| Contentful | Entry.publish, Entry.unpublish | Webhook to `/api/revalidate` |
| Strapi | entry.publish, entry.unpublish | Webhook to `/api/revalidate` |
| DatoCMS | record_published, record_unpublished | Webhook to `/api/revalidate` |
| Decap | N/A (Git push) | Deploy hook on Git push |

### Content Modeling Best Practices

1. **Separate content from presentation** -- Never store HTML/CSS in content fields. Use structured content and render in frontend.
2. **Use slugs as identifiers** -- Auto-generate URL-friendly slugs. Make immutable after publish.
3. **Reference, do not duplicate** -- Authors, categories as separate types, referenced from posts.
4. **Plan for localization early** -- Structure with i18n support even for single-language launch.
5. **Version your content model** -- API-based CMS migrations are like database migrations.

**Content Type Pattern**:
```
Post: title, slug, excerpt, body (rich text), featuredImage, author (ref), categories (ref[]),
      tags (string[]), publishDate, status (draft/published/archived), seo { metaTitle, metaDescription, ogImage }
Author: name, slug, bio, avatar, social { twitter, linkedin, github }
Category: name, slug, description, parent (self-ref for hierarchy)
```

**Frontmatter Validation (Git-based CMS)**:
```typescript
import { z } from 'zod';
export const postSchema = z.object({
  title: z.string().max(100), slug: z.string().regex(/^[a-z0-9-]+$/),
  description: z.string().max(200), date: z.string().datetime(),
  author: z.string().default('Author'), image: z.string().optional(),
  tags: z.array(z.string()).default([]), draft: z.boolean().default(false),
});
```

### Media Handling & Optimization

| CMS | Storage | Optimization | Recommendation |
|-----|---------|-------------|----------------|
| Decap | Git repo | `decap-image-paste` module | Use `image-optimizer` module + CDN |
| Sanity | Sanity CDN | `urlForImage().width(800).format('webp')` | Built-in, use image-url builder |
| Contentful | Contentful CDN | `?w=800&fm=webp&q=80` URL params | Built-in Images API |
| Strapi | Local / S3 | Plugin-based | S3 + CloudFront + `image-optimizer` |
| DatoCMS | Imgix CDN | `responsiveImage` GraphQL field | Built-in, automatic |

**Next.js remote patterns config**:
```typescript
// next.config.ts
const nextConfig = { images: { remotePatterns: [
  { protocol: 'https', hostname: 'cdn.sanity.io' },
  { protocol: 'https', hostname: 'images.ctfassets.net' },
  { protocol: 'https', hostname: 'www.datocms-assets.com' },
]}};
```

### Multi-Environment Content

```bash
# .env.development          # .env.production
CMS_PROVIDER=decap           CMS_PROVIDER=sanity
NEXT_PUBLIC_DRAFT_MODE=true  NEXT_PUBLIC_SANITY_DATASET=production
                             REVALIDATION_SECRET=webhook-secret-xxx
```

Sanity uses datasets (`production`, `staging`). Contentful uses environments (`master`, `staging`). Decap uses Git branches.

### Troubleshooting

**Decap "Not Authenticated"**: Verify `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET`, check OAuth callback URL matches `base_url + auth_endpoint`, ensure `local_backend: true` for local dev.

**Sanity CORS errors**: Run `sanity cors add https://your-site.com` and `sanity cors add http://localhost:3000 --credentials`.

**Contentful rate limiting (429)**: Enable CDN client, implement ISR caching, use GraphQL to reduce requests.

**Strapi images not loading**: Prepend `STRAPI_URL` to relative paths, add domain to `next.config.ts` `remotePatterns`.

**Build fails with missing content**: Return `[]` fallback for empty content, set `dynamicParams = true` for new slugs.

---

## Integrates With

| Module/Skill | Relationship | Usage |
|-------------|-------------|-------|
| **`decap-image-paste` module** | Direct integration | Enhanced image upload for Decap CMS (paste, drag-drop, auto-optimize) |
| **`wordpress-publisher` module** | Alternative approach | WordPress REST API publishing -- contrast with headless CMS approach |
| **`wordpress-patterns` skill** | Complementary | WordPress headless patterns -- use when WP is the CMS backend |
| **`nextjs-app-patterns` skill** | Frontend integration | Next.js App Router patterns for rendering CMS content |
| **`astro-blog-seo` module** | Astro integration | SEO components for Astro-based sites using headless CMS data |
| **`image-optimizer` module** | Media pipeline | Server-side WebP conversion and optimization for CMS media assets |
| **`seo-geo-aeo` skill** | SEO layer | Schema markup and technical SEO for CMS-driven pages |
| **`blog-content-writer` skill** | Content creation | Brand-specific writing templates for CMS workflows |

---

## References

- **Decap CMS**: https://decapcms.org/docs/
- **Sanity**: https://www.sanity.io/docs
- **Contentful**: https://www.contentful.com/developers/docs/
- **Strapi**: https://docs.strapi.io/
- **DatoCMS**: https://www.datocms.com/docs
- **next-sanity**: https://github.com/sanity-io/next-sanity
- **next-mdx-remote**: https://github.com/hashicorp/next-mdx-remote

---

## Version History

- **v1.0.0** (2026-02-16): Initial release
  - Decision matrix for 5 headless CMS providers
  - Decap CMS full integration (config, collections, widgets, OAuth, local proxy)
  - Sanity integration (schemas, GROQ, real-time preview)
  - Contentful integration (GraphQL, Rich Text rendering)
  - Strapi integration (REST client with TypeScript)
  - DatoCMS integration (GraphQL, responsive images)
  - Common patterns (preview/draft mode, ISR webhooks, content modeling)
  - Media handling, multi-environment content, troubleshooting
  - Derived from production ashganda-nextjs Decap CMS implementation
