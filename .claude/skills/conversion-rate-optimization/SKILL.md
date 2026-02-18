---
name: conversion-rate-optimization
description: "Production CRO (Conversion Rate Optimization) skill covering the full experimentation lifecycle: hypothesis, A/B testing, measurement, and iteration. Use when implementing: (1) A/B or multivariate testing (server-side and client-side), (2) Heatmap and session recording integration, (3) Funnel analysis and drop-off detection, (4) Landing page optimization and CTA testing, (5) Personalization and segment-based content, (6) Conversion tracking for Google Ads and Meta Ads. Triggers on 'conversion rate', 'A/B test', 'split test', 'funnel optimization', 'landing page optimization', 'heatmap', 'CRO', 'conversion tracking', or any experimentation request."
license: Proprietary
---

# Conversion Rate Optimization (CRO)

Production-grade CRO methodology and TypeScript/React implementation patterns for Next.js applications. Covers the full experimentation lifecycle: hypothesis, A/B testing, heatmaps, funnel analysis, landing pages, personalization, and ad conversion tracking.

## Core Philosophy

**"Run tests you expect to lose. If every test wins, your hypotheses are too conservative."**

- **Hypothesis-driven**: Every test starts with a falsifiable hypothesis
- **Statistically rigorous**: No peeking, no early stops, proper sample sizes
- **User-centered**: Optimize for user value, not dark patterns
- **Compounding**: 1% weekly improvement = 67% annual improvement
- **Full-funnel**: Measure downstream impact, not just click-through

## Quick Reference

| Discipline | Tools | Key Metric |
|---|---|---|
| **A/B Testing** | Feature flags, Optimizely, VWO | Statistical significance (p < 0.05) |
| **Heatmaps** | Hotjar, Microsoft Clarity | Click density, scroll depth |
| **Funnel Analysis** | GA4, Mixpanel, Amplitude | Step-to-step conversion rate |
| **Landing Pages** | Next.js, Tailwind, React | Bounce rate, CTA click-through |
| **Personalization** | Segment, feature flags | Lift per segment |
| **Ad Tracking** | Google Ads, Meta Pixel | ROAS, CPA, conversion value |

---

# Part 1: CRO Methodology

## Experimentation Cycle

```
RESEARCH (heatmaps, replays, surveys) → HYPOTHESIZE ("If [change], then [metric]
will [direction] because [reason]") → PRIORITIZE (ICE score) → DESIGN →
IMPLEMENT (feature flags + tracking) → TEST (proper sample size) →
ANALYZE (statistical significance) → DOCUMENT → Repeat
```

## Hypothesis & Prioritization

```typescript
// types/experiment.ts
interface ExperimentHypothesis {
  id: string;
  name: string;
  hypothesis: string;           // "If we [change], then [metric] will [direction] because [reason]"
  primaryMetric: string;
  secondaryMetrics: string[];
  guardrailMetrics: string[];   // Must NOT degrade
  minimumDetectableEffect: number;
  requiredSampleSize: number;
  iceScore: { impact: number; confidence: number; ease: number; total: number }; // 1-10 each
  status: 'draft' | 'approved' | 'running' | 'concluded';
  result?: 'winner' | 'loser' | 'inconclusive';
}

// ICE prioritization: sort by (impact + confidence + ease) / 3
function prioritize(ideas: { name: string; impact: number; confidence: number; ease: number }[]) {
  return ideas
    .map((i) => ({ ...i, ice: (i.impact + i.confidence + i.ease) / 3 }))
    .sort((a, b) => b.ice - a.ice);
}
```

## Statistical Significance

```typescript
// lib/cro/statistics.ts
function calculateSampleSize(baselineRate: number, minRelativeLift: number, power = 0.8, sig = 0.05): number {
  const zA = getZScore(1 - sig / 2), zB = getZScore(power);
  const p1 = baselineRate, p2 = p1 * (1 + minRelativeLift), pBar = (p1 + p2) / 2;
  return Math.ceil(
    (zA * Math.sqrt(2 * pBar * (1 - pBar)) + zB * Math.sqrt(p1 * (1 - p1) + p2 * (1 - p2))) ** 2
    / (p2 - p1) ** 2
  );
}

function testSignificance(cV: number, cC: number, vV: number, vC: number) {
  const p1 = cC / cV, p2 = vC / vV;
  const pPool = (cC + vC) / (cV + vV);
  const se = Math.sqrt(pPool * (1 - pPool) * (1 / cV + 1 / vV));
  const z = (p2 - p1) / se;
  const pValue = 2 * (1 - normalCDF(Math.abs(z)));
  const seDiff = Math.sqrt((p1 * (1 - p1)) / cV + (p2 * (1 - p2)) / vV);
  const moe = 1.96 * seDiff, diff = p2 - p1;
  return {
    controlRate: p1, variantRate: p2, relativeLift: diff / p1,
    zScore: z, pValue, significant: pValue < 0.05,
    confidenceInterval: [diff - moe, diff + moe] as [number, number],
  };
}

function getZScore(p: number): number {
  if (p < 0.5) return -getZScore(1 - p);
  const t = Math.sqrt(-2 * Math.log(1 - p));
  return t - (2.515517 + 0.802853 * t + 0.010328 * t * t) /
             (1 + 1.432788 * t + 0.189269 * t * t + 0.001308 * t ** 3);
}

function normalCDF(z: number): number {
  const s = z < 0 ? -1 : 1, x = Math.abs(z) / Math.sqrt(2);
  const t = 1 / (1 + 0.3275911 * x);
  const y = 1 - ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x);
  return 0.5 * (1 + s * y);
}
```

---

# Part 2: A/B Testing Implementation

## Server-Side (Next.js Middleware)

Eliminates flicker. Deterministic hashing ensures sticky assignment.

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';

interface ExperimentConfig {
  id: string;
  variants: { id: string; weight: number }[];
  paths: string[];
  active: boolean;
}

const EXPERIMENTS: ExperimentConfig[] = [
  { id: 'pricing-v2', variants: [{ id: 'control', weight: 50 }, { id: 'variant-a', weight: 50 }], paths: ['/pricing'], active: true },
];

export function middleware(req: NextRequest) {
  const res = NextResponse.next();
  for (const exp of EXPERIMENTS) {
    if (!exp.active || !exp.paths.some((p) => new RegExp(`^${p}$`).test(req.nextUrl.pathname))) continue;
    const cookie = `exp_${exp.id}`;
    const existing = req.cookies.get(cookie)?.value;
    if (existing) { res.headers.set(`x-exp-${exp.id}`, existing); continue; }

    const userId = req.cookies.get('user_id')?.value ?? crypto.randomUUID();
    const variant = assignVariant(userId, exp);
    res.cookies.set(cookie, variant, { maxAge: 30 * 86400, httpOnly: true, sameSite: 'lax', path: '/' });
    res.headers.set(`x-exp-${exp.id}`, variant);
  }
  return res;
}

function assignVariant(uid: string, exp: ExperimentConfig): string {
  const hash = Array.from(new TextEncoder().encode(`${exp.id}:${uid}`))
    .reduce((h, b) => ((h << 5) - h + b) | 0, 0);
  const bucket = Math.abs(hash) % 100;
  let cum = 0;
  for (const v of exp.variants) { cum += v.weight; if (bucket < cum) return v.id; }
  return exp.variants[0].id;
}
```

### Server Component + Tracking

```tsx
// app/pricing/page.tsx
import { cookies } from 'next/headers';
import { ExperimentTracker } from '@/components/ExperimentTracker';

export default async function PricingPage() {
  const variant = (await cookies()).get('exp_pricing-v2')?.value ?? 'control';
  return (
    <>
      <ExperimentTracker experimentId="pricing-v2" variantId={variant} />
      {variant === 'variant-a' ? <PricingVariantA /> : <PricingControl />}
    </>
  );
}

// components/ExperimentTracker.tsx
'use client';
import { useEffect } from 'react';
export function ExperimentTracker({ experimentId, variantId }: { experimentId: string; variantId: string }) {
  useEffect(() => {
    window.dataLayer?.push({ event: 'experiment_impression', experiment_id: experimentId, variant_id: variantId });
  }, [experimentId, variantId]);
  return null;
}
```

## Feature Flag-Based (Unleash / LaunchDarkly)

```typescript
// lib/cro/feature-flag-experiment.ts
import { UnleashClient } from 'unleash-proxy-client';

const unleash = new UnleashClient({
  url: process.env.NEXT_PUBLIC_UNLEASH_PROXY_URL!,
  clientKey: process.env.NEXT_PUBLIC_UNLEASH_CLIENT_KEY!,
  appName: 'web-app',
});

export function useExperimentVariant(flagName: string): string {
  const v = unleash.getVariant(flagName);
  return v.enabled ? v.name : 'control';
}
```

## Client-Side (VWO / Optimizely)

```typescript
// VWO
export function initVWO(accountId: string): void {
  const s = document.createElement('script');
  s.async = true;
  s.src = `https://dev.visualwebsiteoptimizer.com/j.php?a=${accountId}&u=${encodeURIComponent(document.URL)}&r=${Math.random()}`;
  document.head.appendChild(s);
}
export function trackVWOGoal(goalId: number, revenue?: number): void {
  (window as any).VWO = (window as any).VWO || [];
  (window as any).VWO.push(['track.goalConversion', goalId, revenue]);
}

// Optimizely Full Stack
import { createInstance } from '@optimizely/optimizely-sdk';
const client = createInstance({ sdkKey: process.env.NEXT_PUBLIC_OPTIMIZELY_SDK_KEY! });

export function getOptimizelyVariant(userId: string, flagKey: string, attrs?: Record<string, any>) {
  const ctx = client!.createUserContext(userId, attrs);
  return ctx?.decide(flagKey);
}
```

### Anti-Flicker Snippet

```tsx
// components/AntiFlicker.tsx — prevents FOUC with client-side testing
'use client';
import { useEffect } from 'react';
export function AntiFlicker({ maxMs = 2000 }: { maxMs?: number }) {
  useEffect(() => {
    document.documentElement.style.opacity = '0';
    const reveal = () => { document.documentElement.style.opacity = '1'; };
    window.addEventListener('ab_sdk_ready', reveal);
    const t = setTimeout(reveal, maxMs);
    return () => { clearTimeout(t); window.removeEventListener('ab_sdk_ready', reveal); reveal(); };
  }, [maxMs]);
  return null;
}
```

---

# Part 3: Heatmaps & Session Recording

## Microsoft Clarity (Free, Unlimited Traffic)

```typescript
// lib/cro/clarity.ts
export function initClarity(projectId: string): void {
  (window as any).clarity = (window as any).clarity || function(...a: any[]) { ((window as any).clarity.q = (window as any).clarity.q || []).push(a); };
  const s = document.createElement('script'); s.async = true;
  s.src = `https://www.clarity.ms/tag/${projectId}`;
  document.head.appendChild(s);
}
export const clarity = {
  tag: (key: string, value: string) => (window as any).clarity?.('set', key, value),
  identify: (userId: string) => (window as any).clarity?.('identify', userId),
  event: (name: string) => (window as any).clarity?.('event', name),
  tagExperiment: (expId: string, variant: string) => (window as any).clarity?.('set', `exp_${expId}`, variant),
};
```

## Hotjar

```typescript
// lib/cro/hotjar.ts
export function initHotjar(siteId: number): void {
  (window as any)._hjSettings = { hjid: siteId, hjsv: 6 };
  const s = document.createElement('script'); s.async = true;
  s.src = `https://static.hotjar.com/c/hotjar-${siteId}.js?sv=6`;
  document.head.appendChild(s);
}
export const hotjar = {
  event: (name: string) => (window as any).hj?.('event', name),
  identify: (userId: string, attrs: Record<string, any>) => (window as any).hj?.('identify', userId, attrs),
  tagExperiment: (expId: string, variant: string) => (window as any).hj?.('tagRecording', [`${expId}:${variant}`]),
  triggerSurvey: (id: number) => (window as any).hj?.('trigger', `survey-${id}`),
};
```

## Unified Heatmap Provider

```tsx
// lib/cro/heatmap-provider.tsx
'use client';
import { createContext, useContext, useEffect, ReactNode } from 'react';
import { initClarity, clarity } from './clarity';
import { initHotjar, hotjar } from './hotjar';

type Provider = 'clarity' | 'hotjar' | 'both';
interface Config { provider: Provider; clarityId?: string; hotjarId?: number; }

const Ctx = createContext<{ tagExp: (id: string, v: string) => void; identify: (uid: string, a?: Record<string, any>) => void } | null>(null);

export function HeatmapProvider({ config, children }: { config: Config; children: ReactNode }) {
  useEffect(() => {
    if ((config.provider !== 'hotjar') && config.clarityId) initClarity(config.clarityId);
    if ((config.provider !== 'clarity') && config.hotjarId) initHotjar(config.hotjarId);
  }, [config]);

  const tagExp = (id: string, v: string) => { clarity.tagExperiment(id, v); hotjar.tagExperiment(id, v); };
  const identify = (uid: string, a?: Record<string, any>) => { clarity.identify(uid); hotjar.identify(uid, a ?? {}); };

  return <Ctx.Provider value={{ tagExp, identify }}>{children}</Ctx.Provider>;
}
export const useHeatmap = () => { const c = useContext(Ctx); if (!c) throw new Error('Wrap in <HeatmapProvider>'); return c; };
```

---

# Part 4: Funnel Analysis

## Funnel Templates

```typescript
// lib/cro/funnel-tracker.ts
interface FunnelStep { id: string; name: string; order: number; }
interface FunnelConfig { id: string; name: string; steps: FunnelStep[]; thresholds?: { maxDropOff: number; minCompletion: number }; }

export const FUNNELS: Record<string, FunnelConfig> = {
  checkout: {
    id: 'checkout', name: 'E-Commerce Checkout',
    steps: [
      { id: 'cart_viewed', name: 'Cart', order: 1 },
      { id: 'checkout_started', name: 'Checkout', order: 2 },
      { id: 'shipping_entered', name: 'Shipping', order: 3 },
      { id: 'payment_entered', name: 'Payment', order: 4 },
      { id: 'order_confirmed', name: 'Confirmed', order: 5 },
    ],
    thresholds: { maxDropOff: 0.30, minCompletion: 0.02 },
  },
  onboarding: {
    id: 'onboarding', name: 'User Onboarding',
    steps: [
      { id: 'signup_started', name: 'Signup', order: 1 },
      { id: 'email_verified', name: 'Verified', order: 2 },
      { id: 'profile_completed', name: 'Profile', order: 3 },
      { id: 'first_action', name: 'First Action', order: 4 },
      { id: 'activation', name: 'Activated', order: 5 },
    ],
    thresholds: { maxDropOff: 0.50, minCompletion: 0.15 },
  },
  multiStepForm: {
    id: 'form', name: 'Multi-Step Form',
    steps: [
      { id: 'form_started', name: 'Opened', order: 1 },
      { id: 'step_1', name: 'Step 1', order: 2 },
      { id: 'step_2', name: 'Step 2', order: 3 },
      { id: 'step_3', name: 'Step 3', order: 4 },
      { id: 'submitted', name: 'Submitted', order: 5 },
    ],
    thresholds: { maxDropOff: 0.25, minCompletion: 0.30 },
  },
  leadGen: {
    id: 'lead-gen', name: 'Lead Generation',
    steps: [
      { id: 'landing_view', name: 'Landing', order: 1 },
      { id: 'cta_clicked', name: 'CTA Click', order: 2 },
      { id: 'form_started', name: 'Form', order: 3 },
      { id: 'form_submitted', name: 'Submit', order: 4 },
      { id: 'qualified', name: 'Qualified', order: 5 },
    ],
    thresholds: { maxDropOff: 0.60, minCompletion: 0.03 },
  },
};

export function trackFunnelStep(funnelId: string, stepId: string, meta?: Record<string, any>): void {
  window.dataLayer?.push({ event: 'funnel_step', funnel_id: funnelId, step_id: stepId, ...meta });
}
export function trackFunnelAbandonment(funnelId: string, lastStep: string, reason = 'unknown'): void {
  window.dataLayer?.push({ event: 'funnel_abandoned', funnel_id: funnelId, last_step_id: lastStep, reason });
}
```

## Multi-Step Form with Tracking

```tsx
// components/cro/MultiStepFormFunnel.tsx
'use client';
import { useState, useCallback, useEffect, ReactNode } from 'react';
import { trackFunnelStep, trackFunnelAbandonment } from '@/lib/cro/funnel-tracker';

interface Step { id: string; label: string; component: ReactNode; validate?: () => boolean; }

export function MultiStepFormFunnel({ funnelId, steps, onComplete }: { funnelId: string; steps: Step[]; onComplete: () => void }) {
  const [cur, setCur] = useState(0);

  useEffect(() => { trackFunnelStep(funnelId, 'form_started'); }, [funnelId]);
  useEffect(() => () => { if (cur < steps.length - 1) trackFunnelAbandonment(funnelId, steps[cur].id, 'page_exit'); }, [cur]);

  const next = useCallback(() => {
    if (steps[cur].validate && !steps[cur].validate!()) return;
    trackFunnelStep(funnelId, steps[cur].id, { step: cur + 1, total: steps.length });
    cur === steps.length - 1 ? onComplete() : setCur((p) => p + 1);
  }, [cur, funnelId, steps, onComplete]);

  return (
    <div className="max-w-2xl mx-auto">
      <div className="w-full bg-gray-200 rounded-full h-2 mb-8">
        <div className="bg-blue-600 h-2 rounded-full transition-all" style={{ width: `${((cur + 1) / steps.length) * 100}%` }} />
      </div>
      <div className="min-h-[300px]">{steps[cur].component}</div>
      <div className="flex justify-between mt-6">
        <button onClick={() => setCur((p) => Math.max(0, p - 1))} disabled={cur === 0} className="px-6 py-2 border rounded-lg disabled:opacity-50">Back</button>
        <button onClick={next} className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">{cur === steps.length - 1 ? 'Submit' : 'Continue'}</button>
      </div>
    </div>
  );
}
```

## Drop-Off Alerting (Server-Side)

```typescript
// lib/cro/funnel-alerting.ts
interface StepMetrics { stepId: string; visitors: number; completions: number; dropOff: number; }

function analyzeFunnel(funnelId: string, steps: StepMetrics[], thresholds: { maxDropOff: number; minCompletion: number }) {
  const alerts: { severity: 'warning' | 'critical'; message: string }[] = [];
  for (const s of steps) {
    if (s.dropOff > thresholds.maxDropOff)
      alerts.push({ severity: s.dropOff > thresholds.maxDropOff * 1.5 ? 'critical' : 'warning',
        message: `[${funnelId}] "${s.stepId}" drop-off ${(s.dropOff * 100).toFixed(1)}% exceeds ${(thresholds.maxDropOff * 100)}%` });
  }
  const overall = steps.length ? steps[steps.length - 1].completions / steps[0].visitors : 0;
  if (overall < thresholds.minCompletion)
    alerts.push({ severity: 'critical', message: `[${funnelId}] Completion ${(overall * 100).toFixed(2)}% below ${(thresholds.minCompletion * 100)}%` });
  return alerts;
}
// Dispatch alerts to #cro-alerts Slack channel for critical, #cro-monitoring for warnings
```

---

# Part 5: Landing Page Optimization

## Hero Section: Problem-Agitate-Solve (PAS)

```tsx
// components/cro/HeroPAS.tsx
export function HeroPAS({ problem, agitation, solution, ctaText, ctaHref, socialProof, heroImage }: {
  problem: string; agitation: string; solution: string; ctaText: string; ctaHref: string; socialProof?: string; heroImage?: string;
}) {
  return (
    <section className="bg-white">
      <div className="mx-auto max-w-7xl px-6 py-24 lg:flex lg:items-center lg:gap-x-10">
        <div className="max-w-2xl lg:flex-auto">
          <p className="text-lg font-medium text-red-600">{problem}</p>
          <h1 className="mt-4 text-5xl font-bold tracking-tight text-gray-900">{agitation}</h1>
          <p className="mt-6 text-xl text-gray-600">{solution}</p>
          <div className="mt-10">
            <a href={ctaHref} className="rounded-lg bg-blue-600 px-6 py-3.5 text-lg font-semibold text-white hover:bg-blue-500 transition-colors">{ctaText}</a>
          </div>
          {socialProof && <p className="mt-6 text-sm text-gray-500">{socialProof}</p>}
        </div>
        {heroImage && <img src={heroImage} alt="" className="mt-16 lg:mt-0 w-[22rem] max-w-full rounded-xl" loading="eager" fetchPriority="high" />}
      </div>
    </section>
  );
}
```

## Hero Section: Before-After-Bridge (BAB)

```tsx
// components/cro/HeroBAB.tsx
export function HeroBAB({ before, after, bridge, ctaText, ctaHref, metrics }: {
  before: string; after: string; bridge: string; ctaText: string; ctaHref: string; metrics?: { label: string; value: string }[];
}) {
  return (
    <section className="bg-gradient-to-b from-gray-50 to-white">
      <div className="max-w-4xl mx-auto px-6 py-24 text-center">
        <p className="text-lg text-gray-400 line-through decoration-red-400">{before}</p>
        <h1 className="mt-4 text-5xl font-bold text-gray-900">{after}</h1>
        <p className="mt-6 text-xl text-gray-600 max-w-2xl mx-auto">{bridge}</p>
        {metrics && <div className="mt-10 flex justify-center gap-12">{metrics.map((m) => (
          <div key={m.label}><div className="text-3xl font-bold text-blue-600">{m.value}</div><div className="text-sm text-gray-500">{m.label}</div></div>
        ))}</div>}
        <a href={ctaHref} className="mt-10 inline-flex items-center rounded-lg bg-blue-600 px-8 py-4 text-lg font-semibold text-white hover:bg-blue-500">{ctaText}</a>
      </div>
    </section>
  );
}
```

## Social Proof Components

```tsx
// components/cro/SocialProof.tsx
export function LogoBar({ logos, heading = 'Trusted by industry leaders' }: { logos: { name: string; src: string }[]; heading?: string }) {
  return (
    <div className="py-12"><p className="text-center text-sm font-semibold text-gray-500 uppercase">{heading}</p>
      <div className="mt-8 flex flex-wrap justify-center gap-x-12 gap-y-6">
        {logos.map((l) => <img key={l.name} src={l.src} alt={l.name} className="h-8 grayscale opacity-60 hover:grayscale-0 hover:opacity-100 transition-all" loading="lazy" />)}
      </div>
    </div>
  );
}

export function TestimonialCard({ quote, author, role, company, metric }: { quote: string; author: string; role: string; company: string; metric?: string }) {
  return (
    <div className="bg-white rounded-2xl p-8 shadow-sm border border-gray-100">
      {metric && <div className="mb-4 inline-block bg-green-50 text-green-700 text-sm font-semibold px-3 py-1 rounded-full">{metric}</div>}
      <blockquote className="text-gray-700 text-lg">&ldquo;{quote}&rdquo;</blockquote>
      <div className="mt-6"><div className="font-semibold">{author}</div><div className="text-sm text-gray-500">{role}, {company}</div></div>
    </div>
  );
}

export function StatsBar({ stats }: { stats: { value: string; label: string }[] }) {
  return (
    <div className="bg-blue-600 py-16"><div className="max-w-7xl mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-8">
      {stats.map((s) => <div key={s.label} className="text-center"><div className="text-4xl font-bold text-white">{s.value}</div><div className="mt-2 text-sm text-blue-100">{s.label}</div></div>)}
    </div></div>
  );
}
```

## CTA Optimization

```
CTA BEST PRACTICES:
- TEXT: Action verbs ("Start", "Get", "Try") + value ("Start Free Trial" > "Submit")
- COLOR: High contrast (WCAG AA 4.5:1), consistent primary color, avoid red for positive actions
- PLACEMENT: Above fold (always), after social proof, end of feature sections, sticky footer on mobile
- SIZE: Min 44x44px tap target, prominent but not overwhelming
- URGENCY: Use sparingly and honestly ("Free for 14 Days", not fake countdown timers)
```

## Above-the-Fold Checklist

```
REQUIRED above the fold:
1. H1 headline — clear value prop, under 10 words, addresses primary pain
2. Sub-headline — supports H1 with specifics, 1-2 sentences max
3. Primary CTA — single clear action, high-contrast button
4. Social proof — logos, user count, star rating, or "as seen in"
5. Hero visual — product screenshot optimized for LCP (preload, correct size)

AVOID above the fold:
- Multiple competing CTAs
- Auto-playing video (hurts CWV)
- Carousels/sliders (users do not interact)
- Generic stock photos
```

---

# Part 6: Core Web Vitals Impact on Conversion

```
- 100ms added load time = 1.11% conversion drop (Akamai)
- 2s pages convert 15% better than 4s pages (Google)
- 53% mobile users abandon sites > 3s load (Google)
- 1s mobile delay = up to 20% conversion loss (Google)
```

## CWV Monitoring for CRO

```typescript
// lib/cro/cwv-monitor.ts
import { onLCP, onCLS, onINP, onTTFB, Metric } from 'web-vitals';

const THRESHOLDS = { lcp: [2500, 4000], cls: [0.1, 0.25], inp: [200, 500], ttfb: [800, 1800] } as const;

export function initCWVMonitoring() {
  const send = (m: Metric) => {
    const key = m.name.toLowerCase() as keyof typeof THRESHOLDS;
    const [good, poor] = THRESHOLDS[key] ?? [0, 0];
    const rating = m.value <= good ? 'good' : m.value <= poor ? 'needs-improvement' : 'poor';
    window.dataLayer?.push({ event: 'web_vitals', name: m.name, value: Math.round(m.value), rating });
  };
  onLCP(send); onCLS(send); onINP(send); onTTFB(send);
}
```

## Performance Budget (Conversion Pages)

```typescript
export const BUDGETS = {
  landing: { js: '150KB', css: '30KB', total: '500KB', lcp: '2s', cls: 0.05, tti: '3s', thirdPartyJs: '50KB', maxFonts: 2, heroImage: '80KB webp' },
  checkout: { js: '100KB', lcp: '1.5s', cls: 0.02, tti: '2.5s', noThirdParty: true },
} as const;
```

---

# Part 7: Personalization Patterns

## Segment-Based Content

```typescript
// lib/cro/personalization.ts
type Condition =
  | { type: 'utm_source'; value: string }
  | { type: 'device'; value: 'mobile' | 'desktop' }
  | { type: 'returning'; value: boolean }
  | { type: 'page_count'; op: 'gt' | 'lt'; value: number }
  | { type: 'referrer'; pattern: string };

interface Segment { id: string; name: string; conditions: Condition[]; }

const SEGMENTS: Segment[] = [
  { id: 'google-ads', name: 'Google Ads', conditions: [{ type: 'utm_source', value: 'google' }] },
  { id: 'returning', name: 'Returning', conditions: [{ type: 'returning', value: true }] },
  { id: 'mobile', name: 'Mobile', conditions: [{ type: 'device', value: 'mobile' }] },
  { id: 'high-intent', name: 'High Intent', conditions: [{ type: 'page_count', op: 'gt', value: 3 }] },
];

export function resolveSegments(): Segment[] {
  const url = new URL(window.location.href);
  const mobile = /Mobi|Android/i.test(navigator.userAgent);
  const returning = document.cookie.includes('returning=true');
  const pages = parseInt(localStorage.getItem('page_count') ?? '1', 10);

  return SEGMENTS.filter((s) => s.conditions.every((c) => {
    switch (c.type) {
      case 'utm_source': return url.searchParams.get('utm_source') === c.value;
      case 'device': return c.value === 'mobile' ? mobile : !mobile;
      case 'returning': return returning === c.value;
      case 'page_count': return c.op === 'gt' ? pages > c.value : pages < c.value;
      case 'referrer': return document.referrer.includes(c.pattern);
    }
  }));
}
```

### Personalized Content Component

```tsx
// components/cro/PersonalizedContent.tsx
'use client';
import { useEffect, useState, ReactNode } from 'react';
import { resolveSegments } from '@/lib/cro/personalization';

export function PersonalizedContent({ variants, fallback, trackingId }: {
  variants: { segmentId: string; content: ReactNode }[];
  fallback: ReactNode;
  trackingId: string;
}) {
  const [content, setContent] = useState<ReactNode>(fallback);
  useEffect(() => {
    const ids = new Set(resolveSegments().map((s) => s.id));
    const match = variants.find((v) => ids.has(v.segmentId));
    if (match) setContent(match.content);
    window.dataLayer?.push({ event: 'personalization', id: trackingId, segment: match?.segmentId ?? 'fallback' });
  }, [variants, trackingId]);
  return <>{content}</>;
}
```

---

# Part 8: Analytics Event Taxonomy

```typescript
// lib/cro/event-taxonomy.ts — Naming: <object>_<action> in snake_case

export type CROEvent =
  | { name: 'page_viewed'; props: { page_url: string; referrer: string; utm_source?: string; utm_medium?: string; utm_campaign?: string } }
  | { name: 'page_scrolled'; props: { page_url: string; scroll_depth: 25 | 50 | 75 | 100 } }
  | { name: 'cta_clicked'; props: { cta_id: string; cta_text: string; position: string; destination: string } }
  | { name: 'form_started'; props: { form_id: string } }
  | { name: 'form_field_error'; props: { form_id: string; field: string; error: string } }
  | { name: 'form_submitted'; props: { form_id: string; time_ms: number } }
  | { name: 'form_abandoned'; props: { form_id: string; last_field: string; pct: number } }
  | { name: 'checkout_started'; props: { value: number; items: number; currency: string } }
  | { name: 'checkout_completed'; props: { transaction_id: string; value: number; currency: string } }
  | { name: 'experiment_viewed'; props: { experiment_id: string; variant_id: string } }
  | { name: 'experiment_converted'; props: { experiment_id: string; variant_id: string; type: string; value?: number } }
  | { name: 'funnel_step'; props: { funnel_id: string; step_id: string } }
  | { name: 'funnel_abandoned'; props: { funnel_id: string; last_step: string; reason?: string } }
  | { name: 'conversion_completed'; props: { type: string; value?: number; currency?: string; source?: string } };

export function trackCRO(event: CROEvent): void {
  window.dataLayer?.push({ event: event.name, ...event.props });
}
```

### Scroll Depth Tracking

```typescript
// lib/cro/scroll-tracking.ts
export function initScrollTracking(): () => void {
  const fired = new Set<number>();
  let ticking = false;
  const handler = () => {
    const pct = Math.round((window.scrollY / (document.documentElement.scrollHeight - window.innerHeight)) * 100);
    for (const t of [25, 50, 75, 100] as const)
      if (pct >= t && !fired.has(t)) { fired.add(t); window.dataLayer?.push({ event: 'page_scrolled', scroll_depth: t, page_url: location.pathname }); }
  };
  const throttled = () => { if (!ticking) { requestAnimationFrame(() => { handler(); ticking = false; }); ticking = true; } };
  window.addEventListener('scroll', throttled, { passive: true });
  return () => window.removeEventListener('scroll', throttled);
}
```

---

# Part 9: Google Ads / Meta Ads Conversion Tracking

## Google Ads

```typescript
// lib/cro/google-ads.ts
export function trackGoogleConversion(label: string, value?: number, currency = 'USD', txnId?: string): void {
  window.gtag?.('event', 'conversion', { send_to: label, value, currency, transaction_id: txnId });
}

export function setGoogleEnhancedConversions(data: { email?: string; phone?: string; firstName?: string; lastName?: string }): void {
  window.gtag?.('set', 'user_data', { email: data.email, phone_number: data.phone, address: { first_name: data.firstName, last_name: data.lastName } });
}
```

### Next.js Script Setup

```tsx
// app/layout.tsx
import Script from 'next/script';
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en"><head>
      <Script src={`https://www.googletagmanager.com/gtag/js?id=${process.env.NEXT_PUBLIC_GA_ID}`} strategy="afterInteractive" />
      <Script id="gtag-init" strategy="afterInteractive">{`
        window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}
        gtag('js',new Date());gtag('config','${process.env.NEXT_PUBLIC_GA_ID}');gtag('config','${process.env.NEXT_PUBLIC_GADS_ID}');
      `}</Script>
    </head><body>{children}</body></html>
  );
}
```

## Meta Pixel (Client-Side)

```typescript
// lib/cro/meta-pixel.ts
export function initMetaPixel(pixelId: string): void {
  if ((window as any).fbq) return;
  const n = ((window as any).fbq = function(...a: any[]) { n.callMethod ? n.callMethod.apply(n, a) : n.queue.push(a); }) as any;
  n.push = n; n.loaded = true; n.version = '2.0'; n.queue = [];
  const s = document.createElement('script'); s.async = true; s.src = 'https://connect.facebook.net/en_US/fbevents.js'; document.head.appendChild(s);
  (window as any).fbq('init', pixelId);
  (window as any).fbq('track', 'PageView');
}

export const MetaEvents = {
  addToCart: (v: number, c: string, id: string) => (window as any).fbq?.('track', 'AddToCart', { value: v, currency: c, content_ids: [id] }),
  checkout: (v: number, c: string, n: number) => (window as any).fbq?.('track', 'InitiateCheckout', { value: v, currency: c, num_items: n }),
  purchase: (v: number, c: string, ids: string[], orderId?: string) => (window as any).fbq?.('track', 'Purchase', { value: v, currency: c, content_ids: ids, order_id: orderId }),
  lead: (v?: number) => (window as any).fbq?.('track', 'Lead', { value: v }),
  signup: (v?: number) => (window as any).fbq?.('track', 'CompleteRegistration', { value: v }),
};
```

## Meta Conversions API (Server-Side)

Improves attribution accuracy by 15-30% vs pixel-only.

```typescript
// lib/cro/meta-capi.ts (Next.js API route / server action)
export async function sendMetaCAPI(pixelId: string, token: string, event: {
  name: string; time: number; email?: string; phone?: string; fbp?: string; fbc?: string;
  ip?: string; ua?: string; url: string; value?: number; currency?: string; orderId?: string;
}): Promise<void> {
  const hash = async (s: string) => Array.from(new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s.toLowerCase().trim()))
  )).map((b) => b.toString(16).padStart(2, '0')).join('');

  await fetch(`https://graph.facebook.com/v18.0/${pixelId}/events`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: [{ event_name: event.name, event_time: event.time, action_source: 'website', event_source_url: event.url,
        user_data: { em: event.email ? await hash(event.email) : undefined, ph: event.phone ? await hash(event.phone.replace(/\D/g, '')) : undefined,
          fbp: event.fbp, fbc: event.fbc, client_ip_address: event.ip, client_user_agent: event.ua },
        custom_data: event.value ? { value: event.value, currency: event.currency, order_id: event.orderId } : undefined }],
      access_token: token,
    }),
  });
}
```

## Unified Conversion Tracker

```typescript
// lib/cro/conversion-tracker.ts
import { trackGoogleConversion } from './google-ads';
import { MetaEvents } from './meta-pixel';

export class ConversionTracker {
  constructor(private cfg: { gadsLabel?: string; meta?: boolean; ga4?: boolean }) {}

  purchase(p: { txnId: string; value: number; currency: string; items: { id: string; name: string; price: number; qty: number }[] }) {
    if (this.cfg.gadsLabel) trackGoogleConversion(this.cfg.gadsLabel, p.value, p.currency, p.txnId);
    if (this.cfg.meta) MetaEvents.purchase(p.value, p.currency, p.items.map((i) => i.id), p.txnId);
    if (this.cfg.ga4) window.dataLayer?.push({ event: 'purchase', ecommerce: { transaction_id: p.txnId, value: p.value, currency: p.currency,
      items: p.items.map((i) => ({ item_id: i.id, item_name: i.name, price: i.price, quantity: i.qty })) } });
  }

  lead(value?: number, source?: string) {
    if (this.cfg.gadsLabel) trackGoogleConversion(this.cfg.gadsLabel, value);
    if (this.cfg.meta) MetaEvents.lead(value);
    window.dataLayer?.push({ event: 'generate_lead', value, source });
  }

  signup(method: string, value?: number) {
    if (this.cfg.meta) MetaEvents.signup(value);
    window.dataLayer?.push({ event: 'sign_up', method });
  }
}
```

---

## CRO Checklist

```
FOUNDATION:
[ ] Event taxonomy defined     [ ] CWV monitoring active     [ ] Heatmap tool installed
[ ] Funnel tracking live       [ ] Baseline conversion rates documented

A/B TESTING:
[ ] Server-side infra ready    [ ] Sample size calculator     [ ] Anti-flicker (client-side)
[ ] Experiment events firing   [ ] Guardrail metrics defined

LANDING PAGES:
[ ] Hero: PAS or BAB           [ ] Social proof above fold    [ ] Single primary CTA/viewport
[ ] Perf budget < 150KB JS     [ ] Mobile sticky CTA

CONVERSION TRACKING:
[ ] Google Ads tag verified    [ ] Meta Pixel + standard events  [ ] Meta CAPI (server-side)
[ ] Enhanced conversions on    [ ] Deduplication via txn IDs

ONGOING:
[ ] Weekly experiment review   [ ] Monthly funnel report      [ ] Quarterly ICE prioritization
[ ] 2hr/week session replays   [ ] Performance regression alerts
```

---

## Integrates With

| Skill / Module | Integration Point |
|---|---|
| **`analytics-universal`** | Event tracking infrastructure, Segment/Mixpanel, user identification |
| **`google-analytics-search-console`** | GA4 conversion reports, BigQuery export, Search Console CTR data |
| **`mobile-remote-config`** | Feature flags for experiment assignment, remote config for personalization |
| **`seo-geo-aeo`** | Core Web Vitals optimization, page speed impact on organic conversions |
| **`web-copywriter-fortune100`** | Headline/CTA copy variants, PAS/BAB frameworks, persuasion techniques |
| **`performance`** | Bundle optimization, image compression, caching for conversion pages |
