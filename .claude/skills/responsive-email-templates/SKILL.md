---
name: responsive-email-templates
description: "Production-ready email template development system using MJML and React Email. Use when: (1) Building HTML email templates, (2) Setting up MJML or React Email pipelines, (3) Ensuring cross-client compatibility (Outlook, Gmail, Apple Mail, Yahoo), (4) Adding dark mode support to emails, (5) Creating responsive email layouts, (6) Building template variable/personalization systems, (7) Testing emails across clients. Triggers on 'email template', 'MJML', 'React Email', 'email HTML', 'email dark mode', 'email responsive', 'newsletter template', 'transactional email template', 'email design'."
license: Proprietary
---

# Responsive Email Templates

> **Production-ready email template development with MJML and React Email**
>
> Cross-client compatible templates with dark mode, responsive layouts, and a tested template library for every use case.

---

## Overview

**What**: Framework-driven email template system covering transactional, marketing, and notification emails
**Why**: Email rendering is fragmented across 90+ clients; hand-coded HTML tables are brittle and unmaintainable
**How**: MJML for markup abstraction + React Email for component architecture + systematic testing

**Scope boundary**: This skill covers template **design and development**. For sending infrastructure (providers, queues, deliverability), see the `email-universal` skill.

| Template Type | Framework | Complexity | Typical Sections |
|---|---|---|---|
| Welcome/Onboarding | MJML or React Email | Medium | Hero, value props, CTA |
| Order Confirmation | React Email | High | Order table, shipping, totals |
| Password Reset | MJML | Low | Message, button, security note |
| Marketing Newsletter | MJML | High | Multi-section, images, CTAs |
| Weekly Digest | React Email | High | Data tables, charts, summaries |
| Shipping Notification | MJML | Medium | Tracking, timeline, details |
| Receipt | React Email | Medium | Line items, totals, payment info |
| Verification Code | MJML | Low | Code display, expiry notice |

---

## Framework Setup

### MJML

MJML compiles custom XML into battle-tested responsive HTML tables.

```bash
npm install mjml mjml-cli --save-dev
mkdir -p emails/{templates,partials,compiled,assets}
npx mjml emails/templates/welcome.mjml -o emails/compiled/welcome.html
npx mjml --watch emails/templates/*.mjml -o emails/compiled/  # dev mode
```

**MJML Base Template:**

```xml
<mjml>
  <mj-head>
    <mj-title>{{subject}}</mj-title>
    <mj-preview>{{preheader}}</mj-preview>
    <mj-attributes>
      <mj-all font-family="'Helvetica Neue', Helvetica, Arial, sans-serif" />
      <mj-text font-size="16px" line-height="1.6" color="#333333" />
      <mj-button background-color="#4F46E5" color="#ffffff" border-radius="6px"
                  font-size="16px" font-weight="600" inner-padding="14px 32px" />
    </mj-attributes>
    <mj-style>
      :root { color-scheme: light dark; supported-color-schemes: light dark; }
      @media (prefers-color-scheme: dark) {
        .dark-bg { background-color: #1a1a2e !important; }
        .dark-text { color: #e0e0e0 !important; }
        .dark-card { background-color: #252540 !important; }
        .dark-button { background-color: #6366F1 !important; }
      }
    </mj-style>
    <mj-style>
      @media only screen and (max-width: 480px) {
        .mobile-full-width table { width: 100% !important; }
        .mobile-hidden { display: none !important; mso-hide: all !important; }
      }
    </mj-style>
  </mj-head>
  <mj-body background-color="#f4f4f7" css-class="dark-bg" width="600px">
    <mj-section padding="24px 24px 0">
      <mj-column>
        <mj-image src="{{logoUrl}}" alt="{{companyName}}" width="140px" align="left" />
      </mj-column>
    </mj-section>
    <mj-include path="./partials/content.mjml" />
    <mj-section padding="24px" background-color="#f9fafb" css-class="dark-card">
      <mj-column>
        <mj-text font-size="12px" color="#9CA3AF" align="center">
          {{companyName}} | {{companyAddress}}<br/>
          <a href="{{unsubscribeUrl}}" style="color:#9CA3AF;text-decoration:underline;">Unsubscribe</a>
        </mj-text>
      </mj-column>
    </mj-section>
  </mj-body>
</mjml>
```

### React Email

```bash
npm install @react-email/components react-email --save-dev
npx react-email dev --dir emails/react --port 3030  # live preview
```

**Base Layout Component:**

```tsx
// emails/react/components/Layout.tsx
import { Html, Head, Body, Container, Section, Text, Link, Img, Hr, Preview, Font } from '@react-email/components';

interface LayoutProps {
  previewText: string; children: React.ReactNode;
  companyName: string; logoUrl: string; unsubscribeUrl: string; companyAddress: string;
}

export function Layout({ previewText, children, companyName, logoUrl, unsubscribeUrl, companyAddress }: LayoutProps) {
  return (
    <Html lang="en" dir="ltr">
      <Head>
        <meta name="color-scheme" content="light dark" />
        <meta name="supported-color-schemes" content="light dark" />
        <Font fontFamily="Inter" fallbackFontFamily="Helvetica"
          webFont={{ url: 'https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuLyfAZ9hiA.woff2', format: 'woff2' }}
          fontWeight={400} fontStyle="normal" />
      </Head>
      <Preview>{previewText}</Preview>
      <Body style={{ backgroundColor: '#f4f4f7', fontFamily: "'Inter','Helvetica Neue',Helvetica,Arial,sans-serif", margin: 0 }}>
        <Container style={{ maxWidth: '600px', margin: '0 auto', backgroundColor: '#fff' }}>
          <Section style={{ padding: '24px 32px' }}>
            <Img src={logoUrl} alt={companyName} width="140" height="auto" />
          </Section>
          <Section style={{ padding: '0 32px 32px' }}>{children}</Section>
          <Section style={{ padding: '24px 32px', backgroundColor: '#f9fafb' }}>
            <Hr style={{ borderColor: '#e5e7eb', margin: '0 0 16px 0' }} />
            <Text style={{ fontSize: '12px', color: '#9ca3af', textAlign: 'center', margin: 0 }}>
              {companyName} | {companyAddress}<br />
              <Link href={unsubscribeUrl} style={{ color: '#9ca3af', textDecoration: 'underline' }}>Unsubscribe</Link>
            </Text>
          </Section>
        </Container>
      </Body>
    </Html>
  );
}
```

**Rendering to HTML:**

```tsx
import { render } from '@react-email/render';
import { WelcomeEmail } from '../emails/react/WelcomeEmail';

const html = await render(<WelcomeEmail {...props} />, { pretty: false });
const text = await render(<WelcomeEmail {...props} />, { plainText: true });
```

---

## Template Library

### 1. Welcome / Onboarding (MJML)

```xml
<mj-section background-color="#4F46E5" padding="40px 32px" border-radius="8px 8px 0 0">
  <mj-column>
    <mj-text color="#ffffff" font-size="28px" font-weight="700" line-height="1.3">
      Welcome to {{companyName}}, {{firstName}}!
    </mj-text>
    <mj-text color="#c7d2fe" font-size="16px">
      Your account is ready. Here's everything you need to get started.
    </mj-text>
  </mj-column>
</mj-section>
<!-- Numbered steps: use mj-column width="48px" for number + mj-column width="90%" for text -->
<mj-section background-color="#ffffff" padding="24px 32px 40px" css-class="dark-card">
  <mj-column>
    <mj-button href="{{dashboardUrl}}">Go to Dashboard</mj-button>
  </mj-column>
</mj-section>
```

### 2. Order Confirmation (React Email)

```tsx
// Key structure: confirmation header, item rows with image/name/qty/price,
// totals section (subtotal/shipping/tax/total), shipping address, tracking CTA
export function OrderConfirmation({ customerName, orderNumber, items, total, shippingAddress, trackingUrl }: Props) {
  return (
    <Layout previewText={`Order #${orderNumber} confirmed`} {...layoutProps}>
      <Section style={{ textAlign: 'center', padding: '16px 0' }}>
        <Heading as="h1">Order Confirmed</Heading>
        <Text>Hi {customerName}, thanks for your order!</Text>
        <Text style={{ fontSize: '14px', color: '#9CA3AF' }}>Order #{orderNumber}</Text>
      </Section>
      <Hr />
      {items.map((item, i) => (
        <Row key={i} style={{ marginBottom: '12px' }}>
          {item.imageUrl && <Column style={{ width: '64px' }}><Img src={item.imageUrl} alt={item.name} width="56" /></Column>}
          <Column><Text style={{ fontWeight: 600 }}>{item.name}</Text><Text>Qty: {item.quantity}</Text></Column>
          <Column style={{ width: '80px', textAlign: 'right' }}><Text>${(item.price * item.quantity / 100).toFixed(2)}</Text></Column>
        </Row>
      ))}
      <Hr />
      {/* Subtotal/shipping/tax rows, then bold total */}
      {trackingUrl && <Button href={trackingUrl}>Track Your Order</Button>}
    </Layout>
  );
}
```

### 3. Password Reset (MJML)

```xml
<mj-section background-color="#ffffff" padding="40px 32px" border-radius="8px" css-class="dark-card">
  <mj-column>
    <mj-text align="center" font-size="48px">&#128274;</mj-text>
    <mj-text font-size="22px" font-weight="700" align="center" css-class="dark-text">
      Reset your password
    </mj-text>
    <mj-text color="#6B7280" align="center" css-class="dark-text-secondary">
      Click the button below to choose a new password.
    </mj-text>
    <mj-button href="{{resetUrl}}" align="center">Reset Password</mj-button>
    <mj-text font-size="13px" color="#9CA3AF" align="center">
      This link expires in {{expiryMinutes}} minutes.
      If you did not request this, ignore this email.
    </mj-text>
    <mj-divider />
    <mj-text font-size="12px" color="#9CA3AF">
      Can't click? Copy this URL: <a href="{{resetUrl}}" style="color:#4F46E5;word-break:break-all;">{{resetUrl}}</a>
    </mj-text>
  </mj-column>
</mj-section>
```

### 4. Verification Code (MJML)

```xml
<mj-text font-size="22px" font-weight="700" align="center">Your verification code</mj-text>
<mj-text align="center">
  <span style="font-family:'Courier New',monospace; font-size:36px; font-weight:700;
               letter-spacing:8px; color:#4F46E5; background-color:#EEF2FF;
               padding:16px 24px; border-radius:8px; display:inline-block;">
    {{verificationCode}}
  </span>
</mj-text>
<mj-text font-size="13px" color="#9CA3AF" align="center">Expires in {{expiryMinutes}} minutes.</mj-text>
```

### 5. Marketing Newsletter (MJML)

```xml
<!-- Hero image full-width -->
<mj-section background-color="#ffffff" padding="0" css-class="dark-card">
  <mj-column padding="0">
    <mj-image src="{{heroImageUrl}}" alt="{{heroImageAlt}}" fluid-on-mobile="true" />
  </mj-column>
</mj-section>
<mj-section background-color="#ffffff" padding="24px 32px" css-class="dark-card">
  <mj-column>
    <mj-text font-size="12px" color="#4F46E5" font-weight="600" text-transform="uppercase">{{heroCategory}}</mj-text>
    <mj-text font-size="24px" font-weight="700" css-class="dark-text">{{heroTitle}}</mj-text>
    <mj-text color="#6B7280" css-class="dark-text-secondary">{{heroExcerpt}}</mj-text>
    <mj-button href="{{heroUrl}}" align="left">Read More</mj-button>
  </mj-column>
</mj-section>
<!-- Two-column article grid: use two mj-column width="50%" with image + category + title + excerpt -->
<!-- CTA banner: mj-section bg #4F46E5 with white text + inverted button -->
```

### 6. Weekly Digest (React Email)

```tsx
// Structure: greeting, 3-column metrics row (label/value/change%),
// highlights list (category/title/description/timestamp cards),
// action items checklist, "View Full Dashboard" CTA
// Metrics use colored change indicators: green (#10B981) up, red (#EF4444) down
```

### 7. Shipping Notification (MJML)

```xml
<!-- Package icon, "Your order is on its way!", order/carrier info -->
<!-- Tracking card: bg #EEF2FF with tracking number, carrier, est. delivery -->
<!-- Timeline: filled circle (&#9679; #4F46E5) for active, empty (&#9675; #D1D5DB) for pending -->
<!-- Steps: Shipped (active) -> In Transit (pending) -> Delivered (pending) -->
<mj-button href="{{trackingUrl}}" align="center">Track Package</mj-button>
```

---

## Email Client Compatibility Matrix

| Client | Engine | CSS Support | Dark Mode | Key Limitations |
|---|---|---|---|---|
| **Outlook 2016-2021** | Word | Very limited | Partial | No `<div>` layout, no border-radius, must use tables + VML |
| **Outlook 365 Web** | Browser | Good | Yes | Modern rendering |
| **Outlook Mac** | WebKit | Good | Yes | Much better than Windows |
| **Gmail Web** | Browser | Moderate | Yes | Strips `<style>` in some views; inline styles required |
| **Gmail Mobile** | Browser | Moderate | Yes | Limited `@media` support |
| **Apple Mail** | WebKit | Excellent | Yes | Best engine, full CSS, `prefers-color-scheme` |
| **Apple Mail iOS** | WebKit | Excellent | Yes | Full support |
| **Yahoo Mail** | Browser | Moderate | No | Strips some CSS |
| **Samsung Mail** | Browser | Moderate | Partial | Aggressive CSS stripping |
| **Thunderbird** | Gecko | Good | Yes | Solid rendering |

### Compatibility Rules

```
ALWAYS:                                    NEVER:
- Tables for layout (Outlook needs it)    - <div> for layout (breaks Outlook)
- Inline critical styles (Gmail)          - CSS float/flexbox/grid
- Both HTML + plain-text versions         - Shorthand CSS (margin: 10px 20px)
- Width on images (Outlook)               - background-image without VML fallback
- Alt text on all images                  - JavaScript (stripped by all)
- Padding on <td>, not margin             - <video>, <audio>, form elements
- role="presentation" on layout tables    - position: absolute/relative
- border attribute, not CSS border        - Base64 embedded images
```

### Outlook VML Button (Rounded Corners)

```html
<!--[if mso]>
<v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word"
  href="{{url}}" style="height:48px;v-text-anchor:middle;width:200px;" arcsize="12%"
  strokecolor="#4F46E5" fillcolor="#4F46E5">
  <w:anchorlock/><center style="color:#fff;font-family:Arial;font-size:16px;font-weight:bold;">Click Here</center>
</v:roundrect><![endif]-->
<!--[if !mso]><!--><a href="{{url}}" style="background-color:#4F46E5;color:#fff;border-radius:6px;
  padding:14px 32px;text-decoration:none;display:inline-block;font-weight:600;">Click Here</a><!--<![endif]-->
```

---

## Dark Mode Support

### Client Tiers

```
Tier 1 (Full):    Apple Mail, Outlook Mac, Outlook 365 Web — honors @media (prefers-color-scheme: dark)
Tier 2 (Partial): Gmail, Outlook Windows — auto-inverts colors (may look wrong)
Tier 3 (None):    Yahoo Mail, older clients — always light mode
```

### Implementation

```html
<head>
  <meta name="color-scheme" content="light dark" />
  <meta name="supported-color-schemes" content="light dark" />
  <style>
    :root { color-scheme: light dark; supported-color-schemes: light dark; }
    @media (prefers-color-scheme: dark) {
      .body-bg { background-color: #1a1a2e !important; }
      .card-bg { background-color: #252540 !important; }
      .text-primary { color: #e0e0e0 !important; }
      .text-secondary { color: #a0a0a0 !important; }
      .link-primary { color: #818CF8 !important; }
      .btn-primary { background-color: #6366F1 !important; }
      .border-light { border-color: #3a3a5c !important; }
      .dark-img-swap { display: block !important; max-height: none !important; }
      .light-img-swap { display: none !important; max-height: 0 !important; overflow: hidden !important; }
    }
  </style>
</head>
```

### Image Swapping for Dark Mode

```html
<!--[if !mso]><!--><img src="logo-dark-text.png" alt="Logo" class="light-img-swap" style="display:block;" /><!--<![endif]-->
<!--[if !mso]><!--><img src="logo-light-text.png" alt="Logo" class="dark-img-swap" style="display:none;max-height:0;overflow:hidden;" /><!--<![endif]-->
<!--[if mso]><img src="logo-dark-text.png" alt="Logo" width="140" /><![endif]-->
```

### Dark Mode Checklist

```
[ ] Body/card backgrounds change        [ ] Logo visible (swap or add bg)
[ ] Text WCAG AA: 4.5:1 contrast       [ ] Images with transparency OK
[ ] Links distinguishable               [ ] Dividers/borders visible but subtle
[ ] Buttons have contrast               [ ] Gmail auto-dark doesn't break combos
```

---

## Responsive Design Patterns

### Fluid Layout (No Media Queries)

Works everywhere including Gmail mobile:

```html
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
  <tr><td align="center" style="padding:16px;">
    <!--[if mso]><table width="600" cellpadding="0" cellspacing="0"><tr><td><![endif]-->
    <div style="max-width:600px;margin:0 auto;"><!-- content --></div>
    <!--[if mso]></td></tr></table><![endif]-->
  </td></tr>
</table>
```

### Stackable Columns (Raw HTML)

```html
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
  <!--[if mso]><td valign="top" width="280"><![endif]-->
  <div style="display:inline-block;width:100%;max-width:280px;vertical-align:top;">
    <table role="presentation" width="100%"><tr><td style="padding:0 12px 16px;">
      <!-- Column 1 -->
    </td></tr></table>
  </div>
  <!--[if mso]></td><td valign="top" width="280"><![endif]-->
  <div style="display:inline-block;width:100%;max-width:280px;vertical-align:top;">
    <table role="presentation" width="100%"><tr><td style="padding:0 12px 16px;">
      <!-- Column 2 -->
    </td></tr></table>
  </div>
  <!--[if mso]></td><![endif]-->
</tr></table>
```

### MJML Responsive (Automatic)

```xml
<!-- Auto-stacks below 480px -->
<mj-section>
  <mj-column width="50%"><mj-text>Stacks on top</mj-text></mj-column>
  <mj-column width="50%"><mj-text>Stacks below</mj-text></mj-column>
</mj-section>

<!-- Three-column feature grid -->
<mj-section>
  <mj-column width="33.33%">
    <mj-image src="{{icon1}}" width="48px" align="center" />
    <mj-text align="center" font-weight="600">Feature 1</mj-text>
  </mj-column>
  <!-- repeat for columns 2, 3 -->
</mj-section>
```

### Mobile Utility Classes

```css
@media only screen and (max-width: 480px) {
  .mobile-hidden { display: none !important; mso-hide: all !important; }
  .mobile-only { display: block !important; max-height: none !important; }
  .mobile-full-width img { width: 100% !important; height: auto !important; }
  .mobile-text-center { text-align: center !important; }
  .mobile-button a { display: block !important; padding: 16px !important; font-size: 18px !important; }
  .mobile-stack { display: block !important; width: 100% !important; }
}
```

---

## Typography in Email

### Web-Safe Font Stacks

```css
/* Sans-serif (default) */   'Helvetica Neue', Helvetica, Arial, sans-serif
/* Modern (with web font) */ 'Inter', 'Helvetica Neue', Helvetica, Arial, sans-serif
/* System native */          -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif
/* Serif (editorial) */      Georgia, 'Times New Roman', Times, serif
/* Monospace (codes) */      'Courier New', Courier, monospace
```

### Web Fonts

Work in Apple Mail, iOS Mail, Thunderbird. Ignored by Outlook and Gmail.

```html
<style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');</style>
<!-- OR -->
<style>@font-face { font-family:'Inter'; font-weight:400;
  src: url('https://fonts.gstatic.com/s/inter/v13/...woff2') format('woff2'); }</style>
```

### Type Scale

```
H1:        24-28px  700  line-height 1.3       Min font size: 13px (iOS auto-scales smaller)
H2:        18-20px  600  line-height 1.4       Max line width: 600px (45-75 chars)
Body:      15-16px  400  line-height 1.6
Small:     13-14px  400  line-height 1.5
Caption:   11-12px  400  line-height 1.4
Button:    16px     600
```

---

## Image Handling

### Retina (@2x)

```html
<!-- Serve 280x160 source, display at 140x80 -->
<img src="hero@2x.jpg" alt="Hero" width="140" height="80"
     style="width:140px;height:auto;display:block;border:0;" />
```

### Styled Alt Text Fallback

```html
<img src="banner.jpg" alt="Summer Sale: 30% off all products"
     width="600" height="200"
     style="display:block;width:100%;height:auto;border:0;
            font-family:Arial;font-size:16px;font-weight:bold;color:#4F46E5;
            background-color:#EEF2FF;text-align:center;padding:40px 20px;" />
```

### Background Images (Outlook VML)

```html
<!--[if mso]><v:rect xmlns:v="urn:schemas-microsoft-com:vml" fill="true" stroke="false"
  style="width:600px;height:300px;"><v:fill type="frame" src="https://example.com/bg.jpg" />
  <v:textbox inset="0,0,0,0" style="mso-fit-shape-to-text:true"><![endif]-->
<div style="background-image:url('https://example.com/bg.jpg');background-size:cover;
            background-color:#4F46E5;max-width:600px;padding:60px 40px;">
  <h1 style="color:#fff;font-size:28px;margin:0;">Headline</h1>
</div>
<!--[if mso]></v:textbox></v:rect><![endif]-->
```

### Image Checklist

```
Format: JPEG (photos, 70-80%), PNG (transparency), GIF (animation <1MB). Avoid WebP/AVIF.
Size:   Hero 1200x600 source -> 600x300 display. Logo 280px -> 140px. Total HTML <100KB.
Host:   CDN with HTTPS (Gmail blocks HTTP). Long cache headers. Versioned filenames.
        Never embed base64. Always provide descriptive alt text.
```

---

## Template Variable Systems

### Variable Replacement Engine

```typescript
interface TemplateVars { [key: string]: string | number | boolean | undefined; }

export function renderTemplate(html: string, vars: TemplateVars): string {
  return html.replace(/\{\{(\w+)\}\}/g, (match, key) => {
    const val = vars[key];
    if (val === undefined) { console.warn(`Missing: "${key}"`); return match; }
    return escapeHtml(String(val));
  });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]!));
}
```

### Conditional Blocks

```typescript
// Syntax: {{#if variable}}content{{else}}fallback{{/if}}
export function processConditionals(html: string, vars: Record<string, unknown>): string {
  html = html.replace(/\{\{#if (\w+)\}\}([\s\S]*?)\{\{else\}\}([\s\S]*?)\{\{\/if\}\}/g,
    (_, key, ifTrue, ifFalse) => vars[key] ? ifTrue : ifFalse);
  html = html.replace(/\{\{#if (\w+)\}\}([\s\S]*?)\{\{\/if\}\}/g,
    (_, key, content) => vars[key] ? content : '');
  return html;
}
```

### Loop Blocks

```typescript
// Syntax: {{#each items}}...{{this.field}}...{{/each}}
export function processLoops(html: string, vars: Record<string, unknown>): string {
  return html.replace(/\{\{#each (\w+)\}\}([\s\S]*?)\{\{\/each\}\}/g, (_, key, tpl) => {
    const items = vars[key]; if (!Array.isArray(items)) return '';
    return items.map((item, i) => {
      let r = tpl.replace(/\{\{this\.(\w+)\}\}/g, (_: string, f: string) => escapeHtml(String(item[f] ?? '')));
      r = r.replace(/\{\{@index\}\}/g, String(i));
      return r;
    }).join('');
  });
}
```

### Personalization Rules

```
DO:  Provide fallbacks ("Hi {{firstName|there}}"), personalize subject lines (2-3x open rate),
     use preheader strategically (40-90 chars), localize dates/currencies, segment by user attributes.
DON'T: Include sensitive data (SSN, passwords), over-personalize ("we saw you at 3:42am"),
       render user content without escaping (XSS), assume variable availability.
```

---

## Testing Workflow

### Automated Tests

```typescript
import { render } from '@react-email/render';
import { JSDOM } from 'jsdom';

describe('Email compliance', () => {
  it('has unsubscribe link (CAN-SPAM)', async () => {
    const html = await render(<WelcomeEmail {...props} />);
    const doc = new JSDOM(html).window.document;
    expect(doc.querySelector('a[href*="unsubscribe"]')).toBeTruthy();
  });
  it('has alt text on all images', async () => {
    const html = await render(<WelcomeEmail {...props} />);
    const imgs = new JSDOM(html).window.document.querySelectorAll('img');
    imgs.forEach(img => expect(img.getAttribute('alt')).toBeTruthy());
  });
  it('HTML under 100KB', async () => {
    const html = await render(<WelcomeEmail {...props} />);
    expect(Buffer.byteLength(html) / 1024).toBeLessThan(100);
  });
  it('has color-scheme meta for dark mode', async () => {
    const html = await render(<WelcomeEmail {...props} />);
    expect(html).toContain('color-scheme');
  });
  it('generates valid plain text', async () => {
    const text = await render(<WelcomeEmail {...props} />, { plainText: true });
    expect(text).not.toContain('<');
  });
});
```

### Manual Testing Matrix

```
[ ] Browser render (Chrome, Firefox, Safari)
[ ] Litmus or Email on Acid cross-client test
[ ] Real clients: Apple Mail macOS/iOS (light+dark), Gmail web/Android/iOS,
    Outlook 2019/2021 Windows, Outlook 365 web, Outlook Mac, Yahoo web
[ ] Plain text version        [ ] All links work (with UTM params)
[ ] Images load + disabled    [ ] Subject + preheader display
[ ] Unsubscribe link works    [ ] No raw {{variable}} visible
[ ] Responsive stacks <480px  [ ] Dark mode readable
[ ] HTML <100KB               [ ] Spam score (Mail Tester, GlockApps)
```

### CI/CD

```yaml
# .github/workflows/email-templates.yml
name: Email Templates
on:
  push: { paths: ['emails/**'] }
  pull_request: { paths: ['emails/**'] }
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm ci
      - run: npm run email:build
      - run: npm test -- --testPathPattern=email
      - name: Check HTML size
        run: |
          for f in emails/compiled/*.html; do
            size=$(wc -c < "$f")
            [ "$size" -gt 102400 ] && echo "ERROR: $f is ${size}B (>100KB)" && exit 1
            echo "OK: $f (${size}B)"
          done
```

---

## Integrates With

| Skill | Relationship |
|---|---|
| `email-universal` | **Sending infrastructure** -- delivery layer (SendGrid, SES, SMTP), queuing, retries. This skill builds the HTML that gets handed to that pipeline. |
| `notification-universal` | **Trigger layer** -- defines when notification emails fire. Templates from this skill are rendered and passed to the notification system. |
| `graphic-designer` | **Visual design** -- brand identity, layout composition, visual hierarchy, color theory for email templates. |
| `visual-design-consultant` | **Color/typography** -- palette selection, font pairings, WCAG contrast ratios in light and dark mode. |
| `translation-pipeline` | **Multilingual templates** -- extracting translatable strings, locale files, locale-aware formatting with the variable system. |
