# Typography Guide

Comprehensive typography reference for professional design systems.

## Font Pairing Principles

### The Classic Rule
Pair a **display/heading font** with a **body font** that:
- Contrasts in style (serif + sans-serif, or decorative + neutral)
- Shares similar proportions (x-height, letter width)
- Complements in mood and era

### Pairing Categories

| Category | Heading | Body | Mood |
|----------|---------|------|------|
| Modern Corporate | Outfit | Source Sans 3 | Professional, clean |
| Tech Startup | Space Grotesk | Inter | Innovative, precise |
| Editorial | Playfair Display | Lora | Sophisticated, readable |
| Healthcare | IBM Plex Sans | Open Sans | Trustworthy, clear |
| Creative Agency | Syne | DM Sans | Bold, contemporary |
| Luxury Brand | Cormorant | Crimson Pro | Elegant, refined |
| Friendly SaaS | Plus Jakarta Sans | Nunito | Approachable, modern |
| E-commerce | Montserrat | Noto Sans | Versatile, commercial |
| Education | Merriweather | Source Serif Pro | Academic, readable |
| Playful Brand | Fredoka | Quicksand | Fun, approachable |

## Google Fonts Recommendations

### Sans-Serif (Modern)
```
Inter           - The new Helvetica, excellent for UI
Plus Jakarta Sans - Geometric, friendly, versatile
DM Sans         - Open, slightly quirky, great for tech
Source Sans 3   - Adobe's workhorse, highly legible
Nunito Sans     - Rounded, friendly, good for apps
Outfit          - Variable, geometric, professional
Space Grotesk   - Distinctive, technical, modern
IBM Plex Sans   - Neutral, corporate, accessible
Karla           - Quirky, characterful, readable
```

### Serif (Classic)
```
Lora            - Contemporary serif, excellent for body
Source Serif Pro - Matches Source Sans, editorial
Crimson Pro     - Old-style, elegant, book-like
Merriweather    - Screen-optimised, highly readable
Playfair Display - High contrast, luxury headings
Cormorant       - Classical, refined, display use
EB Garamond     - Timeless, academic, sophisticated
```

### Display (Headings Only)
```
Syne            - Bold geometric, contemporary
Fraunces        - Soft serif, characterful
Clash Display   - Ultra-modern, geometric
Cabinet Grotesk - Clean, architectural
Satoshi         - Minimal, versatile
```

## Type Scale (Modular)

### Base: 16px, Ratio: 1.25 (Major Third)
```
--text-xs:    0.64rem   (10.24px)  - Fine print
--text-sm:    0.8rem    (12.8px)   - Caption
--text-base:  1rem      (16px)     - Body
--text-lg:    1.25rem   (20px)     - Lead paragraph
--text-xl:    1.563rem  (25px)     - H4
--text-2xl:   1.953rem  (31.25px)  - H3
--text-3xl:   2.441rem  (39px)     - H2
--text-4xl:   3.052rem  (48.8px)   - H1
--text-5xl:   3.815rem  (61px)     - Display
--text-6xl:   4.768rem  (76.3px)   - Hero
```

### Alternative Ratios
| Ratio | Name | Use Case |
|-------|------|----------|
| 1.067 | Minor Second | Compact UI, data-dense |
| 1.125 | Major Second | Apps, dashboards |
| 1.200 | Minor Third | General websites |
| 1.250 | Major Third | Marketing sites |
| 1.333 | Perfect Fourth | Editorial, magazines |
| 1.414 | Augmented Fourth | Bold statements |
| 1.618 | Golden Ratio | Luxury, artistic |

### Calculate Scale
```javascript
function generateTypeScale(base = 16, ratio = 1.25, steps = 10) {
  const scale = {};
  const names = ['xs', 'sm', 'base', 'lg', 'xl', '2xl', '3xl', '4xl', '5xl', '6xl'];
  
  for (let i = 0; i < steps; i++) {
    const size = base * Math.pow(ratio, i - 2);
    scale[names[i]] = `${(size / 16).toFixed(3)}rem`;
  }
  
  return scale;
}
```

## Line Height Guidelines

| Text Size | Line Height | Use |
|-----------|-------------|-----|
| < 14px | 1.6 - 1.8 | Small text needs more leading |
| 14-18px | 1.5 - 1.6 | Body copy sweet spot |
| 18-24px | 1.4 - 1.5 | Large body, lead paragraphs |
| 24-36px | 1.2 - 1.4 | Subheadings |
| > 36px | 1.0 - 1.2 | Headlines, display |

### Responsive Line Height
```css
/* Fluid line-height that adjusts with viewport */
--line-height-body: clamp(1.5, 1.4 + 0.25vw, 1.7);
--line-height-heading: clamp(1.1, 1 + 0.2vw, 1.3);
```

## Letter Spacing (Tracking)

| Element | Spacing | Notes |
|---------|---------|-------|
| Body text | 0 to -0.01em | Slight tightening for modern feel |
| Headings | -0.02 to -0.04em | Tighter for impact |
| All caps | 0.05 to 0.15em | Must be loose for readability |
| Display (large) | -0.03 to -0.05em | Optical compensation |
| Monospace | 0 | Never adjust |

```css
.heading { letter-spacing: -0.025em; }
.body { letter-spacing: -0.011em; }
.caps { letter-spacing: 0.1em; text-transform: uppercase; }
```

## Font Weights

### Standard Weight Scale
```
100 - Thin        (display only)
200 - Extra Light (display only)
300 - Light       (headings, decorative)
400 - Regular     (body default)
500 - Medium      (emphasis, UI)
600 - Semi Bold   (subheadings)
700 - Bold        (headings, strong emphasis)
800 - Extra Bold  (impact headings)
900 - Black       (display, logos)
```

### Usage Recommendations
- **Body**: 400 (regular), 600 for emphasis
- **Headings**: 600-700 (semi-bold to bold)
- **Display**: 700-900 (bold to black)
- **UI Elements**: 500-600 (medium to semi-bold)

## Responsive Typography

### Fluid Type Scale
```css
/* Base size: 16px at 320px, 18px at 1200px */
:root {
  --text-base: clamp(1rem, 0.9rem + 0.5vw, 1.125rem);
  --text-lg: clamp(1.25rem, 1.1rem + 0.75vw, 1.5rem);
  --text-xl: clamp(1.5rem, 1.25rem + 1.25vw, 2rem);
  --text-2xl: clamp(1.875rem, 1.5rem + 1.875vw, 2.5rem);
  --text-3xl: clamp(2.25rem, 1.75rem + 2.5vw, 3.5rem);
}
```

### Breakpoint Adjustments
```css
/* Mobile-first approach */
body { font-size: 16px; }

@media (min-width: 640px) { body { font-size: 17px; } }
@media (min-width: 1024px) { body { font-size: 18px; } }
@media (min-width: 1440px) { body { font-size: 19px; } }
```

## Paragraph Styling

### Optimal Line Length
- **Minimum**: 45 characters (too narrow = choppy)
- **Optimal**: 65-75 characters
- **Maximum**: 90 characters (too wide = loses place)

```css
.prose {
  max-width: 65ch; /* Character-based width */
}
```

### Paragraph Spacing
```css
p + p {
  margin-top: 1.5em; /* Or use margin-bottom on all p */
}

/* First paragraph after heading - less space */
h2 + p, h3 + p {
  margin-top: 0.75em;
}
```

## CSS Typography System

### Complete System
```css
:root {
  /* Font Families */
  --font-heading: 'Plus Jakarta Sans', sans-serif;
  --font-body: 'Source Sans 3', sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
  
  /* Font Sizes */
  --text-xs: 0.75rem;
  --text-sm: 0.875rem;
  --text-base: 1rem;
  --text-lg: 1.125rem;
  --text-xl: 1.25rem;
  --text-2xl: 1.5rem;
  --text-3xl: 1.875rem;
  --text-4xl: 2.25rem;
  --text-5xl: 3rem;
  
  /* Line Heights */
  --leading-tight: 1.25;
  --leading-snug: 1.375;
  --leading-normal: 1.5;
  --leading-relaxed: 1.625;
  --leading-loose: 2;
  
  /* Letter Spacing */
  --tracking-tighter: -0.05em;
  --tracking-tight: -0.025em;
  --tracking-normal: 0;
  --tracking-wide: 0.025em;
  --tracking-wider: 0.05em;
  --tracking-widest: 0.1em;
  
  /* Font Weights */
  --font-light: 300;
  --font-normal: 400;
  --font-medium: 500;
  --font-semibold: 600;
  --font-bold: 700;
}

/* Apply to elements */
body {
  font-family: var(--font-body);
  font-size: var(--text-base);
  line-height: var(--leading-normal);
  font-weight: var(--font-normal);
}

h1, h2, h3, h4, h5, h6 {
  font-family: var(--font-heading);
  font-weight: var(--font-bold);
  line-height: var(--leading-tight);
  letter-spacing: var(--tracking-tight);
}
```

## Font Loading

### Google Fonts Import
```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Source+Sans+3:wght@400;600&display=swap" rel="stylesheet">
```

### Font Display Strategy
```css
@font-face {
  font-family: 'Plus Jakarta Sans';
  font-display: swap; /* Show fallback immediately, swap when loaded */
}
```

## Accessibility

### Minimum Sizes
- Body text: 16px minimum
- Secondary text: 14px minimum
- Never below 12px for any readable content

### Contrast Requirements
- Normal text (< 18px): 4.5:1 minimum
- Large text (≥ 18px or ≥ 14px bold): 3:1 minimum

### Dyslexia-Friendly Options
- Use sans-serif fonts
- Avoid full justification
- Line height minimum 1.5
- Paragraph spacing minimum 2x font size
- Letter spacing minimum 0.12em
