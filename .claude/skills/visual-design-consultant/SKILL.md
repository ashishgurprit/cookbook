---
name: visual-design-consultant
description: "Expert visual design consultant for crafting beautiful, professional designs based on user colour preferences. Use when creating: (1) UI/UX designs for apps and websites, (2) Brand logos and identity systems, (3) Colour palettes and design tokens, (4) Component libraries and style guides, (5) Marketing assets and visual materials. Triggers on requests for 'design system', 'colour palette', 'brand identity', 'logo design', 'UI design', 'beautiful interface', or any visual design consultation."
license: Proprietary
---

# Visual Design Consultant

Transform user colour preferences into comprehensive, professional design systems with beautiful aesthetics.

## Quick Reference

| Input | Output |
|-------|--------|
| Single colour + project type | Complete design system |
| Mood/industry keywords | Curated palette + typography |
| Existing brand colours | Extended palette + components |
| "Make it beautiful" | Bold aesthetic direction + implementation |

## Core Workflow

```
INPUT → ANALYSE → GENERATE → VALIDATE → OUTPUT
  │        │          │          │         │
  │        │          │          │         └─ Design tokens, components, assets
  │        │          │          └─ WCAG contrast, harmony check
  │        │          └─ Palette, typography, spacing, components
  │        └─ Colour theory, audience, project type
  └─ User preferences, mood, industry
```

### Step 1: Gather Design Intent

Extract from user input:
- **Primary colour**: Hex, RGB, or colour name
- **Project type**: App, website, dashboard, branding, marketing
- **Audience**: Corporate, playful, luxury, clinical, creative
- **Mood keywords**: Calm, energetic, professional, warm, modern

If missing, infer intelligently or ask ONE clarifying question.

### Step 2: Generate Colour Palette

Use colour theory algorithms from `references/colour-theory.md`:

```
PRIMARY → Apply harmony type → SECONDARY
    │                              │
    ├── Complementary (bold)       │
    ├── Analogous (harmonious)     │
    ├── Triadic (vibrant)          │
    └── Split-comp (balanced)      │
                                   ↓
                            Generate scales:
                            • 50-950 for each colour
                            • Semantic colours (success, error, warning)
                            • Neutral grey scale (warm/cool tinted)
```

### Step 3: Select Typography

Match fonts to audience and mood:

| Audience | Heading Font | Body Font |
|----------|--------------|-----------|
| Corporate | Outfit, Plus Jakarta Sans | Source Sans 3, Nunito Sans |
| Creative | Space Grotesk, Syne | DM Sans, Karla |
| Luxury | Cormorant, Playfair Display | Lora, Crimson Pro |
| Clinical | Inter, IBM Plex Sans | Open Sans, Noto Sans |
| Playful | Fredoka, Quicksand | Nunito, Comfortaa |

### Step 4: Define Spacing System

Use 4px base unit with modular scale:
```
spacing: [4, 8, 12, 16, 24, 32, 48, 64, 96, 128]
         xs  sm  md  base lg  xl  2xl 3xl 4xl 5xl
```

### Step 5: Generate Component Styles

Create styles for core components:
- Buttons (primary, secondary, ghost, destructive)
- Cards (elevated, outlined, filled)
- Inputs (default, focus, error, disabled)
- Typography scale (display, h1-h6, body, caption)

### Step 6: Validate Accessibility

Check all colour combinations against WCAG 2.1:
- **AA minimum**: 4.5:1 for normal text, 3:1 for large text
- **AAA optimal**: 7:1 for normal text, 4.5:1 for large text

Auto-adjust colours that fail contrast requirements.

## Output Formats

### Design Tokens (JSON/CSS)
```json
{
  "colors": {
    "primary": { "50": "#eff6ff", "500": "#3b82f6", "900": "#1e3a8a" },
    "secondary": { ... },
    "neutral": { ... }
  },
  "typography": { ... },
  "spacing": { ... },
  "borderRadius": { ... }
}
```

### Tailwind Config
Generate tailwind.config.js with custom theme.

### CSS Variables
Generate :root variables for vanilla CSS projects.

### React Components
Generate styled component library with design tokens applied.

### SVG Assets
Generate logos, icons, and illustrations using the palette.

## Logo & Brand Asset Generation

When creating logos:
1. Understand brand personality from colour choices
2. Generate SVG-based designs (scalable, editable)
3. Create variations: full colour, mono, reversed, favicon
4. Export multiple formats: SVG, PNG (various sizes)

See `references/logo-patterns.md` for shape psychology and composition rules.

## Aesthetic Directions

Match aesthetic to user intent:

| Keywords | Aesthetic | Characteristics |
|----------|-----------|-----------------|
| clean, modern | Minimalist | Generous whitespace, subtle shadows, mono accents |
| bold, energetic | Maximalist | Vibrant colours, dynamic shapes, strong contrast |
| elegant, premium | Luxury | Gold/dark accents, serif fonts, refined details |
| friendly, approachable | Playful | Rounded corners, soft colours, bouncy animations |
| trustworthy, professional | Corporate | Blue-dominant, structured grid, clear hierarchy |
| innovative, tech | Futuristic | Gradients, glass morphism, neon accents |

## Critical Design Principles

1. **Intentionality over decoration**: Every element serves a purpose
2. **Consistency builds trust**: Use tokens everywhere, no magic numbers
3. **Accessibility is non-negotiable**: If it fails WCAG, fix it
4. **Context drives choices**: A medical app ≠ a gaming website
5. **Restraint shows mastery**: 2-3 colours used well > rainbow chaos

## File References

- `references/colour-theory.md` - Harmony algorithms, psychology, accessibility
- `references/typography-guide.md` - Font pairing rules, scale calculations
- `references/logo-patterns.md` - Logo composition, shape meanings, export specs
- `references/component-patterns.md` - UI component best practices
- `scripts/generate-palette.js` - Colour palette generation script
- `scripts/contrast-checker.js` - WCAG contrast validation
- `assets/` - Font files, icon sets, templates
