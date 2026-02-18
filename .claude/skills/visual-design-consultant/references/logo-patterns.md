# Logo & Brand Asset Patterns

Comprehensive guide for creating professional logos and brand assets.

## Logo Design Principles

### The 5-Second Rule
A logo must communicate brand essence in 5 seconds or less:
1. Instantly recognisable silhouette
2. Works at any size (favicon to billboard)
3. Memorable after brief viewing
4. Unique within its industry

### Logo Types

| Type | Description | Best For |
|------|-------------|----------|
| Wordmark | Styled company name | Unique names, personal brands |
| Lettermark | Initials/monogram | Long names, corporate |
| Symbol | Icon/mark only | Established brands |
| Combination | Icon + wordmark | New brands, versatility |
| Emblem | Text inside symbol | Traditional, badges |
| Abstract | Geometric/artistic | Tech, creative industries |

## Shape Psychology

### Geometric Meanings

```
CIRCLE      → Unity, community, wholeness, infinity
             Trust, protection, completeness
             
SQUARE      → Stability, reliability, balance
             Professional, trustworthy, solid
             
TRIANGLE    → Power, direction, dynamic energy
             △ Up: Growth, aspiration, progress
             ▽ Down: Stability, grounding
             
RECTANGLE   → Security, structure, reliability
             Traditional, dependable
             
HEXAGON     → Balance, nature, efficiency
             Tech, science, connection
             
SPIRAL      → Growth, evolution, creativity
             Journey, transformation
```

### Line Characteristics

| Style | Conveys |
|-------|---------|
| Straight | Precision, order, efficiency |
| Curved | Creativity, movement, approachability |
| Diagonal | Dynamic, action, progress |
| Thick | Strength, boldness, confidence |
| Thin | Elegance, sophistication, lightness |
| Broken | Modern, abstract, tech |

## Logo Composition Rules

### Golden Ratio Grid
```
┌─────────────────────────────────────────┐
│                                         │
│    ┌─────────────┐  ┌───────┐           │
│    │             │  │       │           │
│    │     1.618   │  │   1   │           │
│    │             │  │       │           │
│    │             │  └───────┘           │
│    │             │                      │
│    └─────────────┘                      │
│                                         │
│    Use ratio 1:1.618 for proportions    │
│                                         │
└─────────────────────────────────────────┘
```

### Balance Types

**Symmetrical**: Formal, stable, traditional
```
    ┌─┐      ┌─┐
    │ │      │ │
 ───┴─┴──────┴─┴───
```

**Asymmetrical**: Dynamic, modern, interesting
```
    ┌───┐
    │   │  ┌─┐
 ───┴───┴──┴─┴───
```

### Safe Zone / Clear Space
```
┌─────────────────────────────┐
│                             │
│    ┌─────────────────┐      │
│    │                 │      │
│    │      LOGO       │      │
│    │                 │      │
│    └─────────────────┘      │
│                             │
│  ←──── X ────→              │
│                             │
└─────────────────────────────┘

X = height of logo's defining element
Clear space = 0.5X to 1X on all sides
```

## SVG Logo Structure

### Basic SVG Template
```xml
<svg 
  xmlns="http://www.w3.org/2000/svg" 
  viewBox="0 0 100 100"
  width="100" 
  height="100"
>
  <title>Brand Name Logo</title>
  <desc>Description for accessibility</desc>
  
  <!-- Logo elements -->
  <g id="logo-mark">
    <!-- Symbol/icon -->
  </g>
  
  <g id="logo-text">
    <!-- Wordmark if combination -->
  </g>
</svg>
```

### Optimised SVG Practices
- Use `viewBox` for scalability
- Group related elements with `<g>`
- Use CSS classes for colour variants
- Include `<title>` and `<desc>` for accessibility
- Minimise path complexity
- Use whole numbers in paths where possible

## Logo Colour Variants

### Required Versions
1. **Full Colour**: Primary brand colours
2. **Reversed**: For dark backgrounds
3. **Mono Dark**: Single dark colour
4. **Mono Light**: Single light colour (for dark backgrounds)
5. **Favicon**: Simplified, square, recognisable at 16x16

### CSS Variables for Variants
```css
.logo {
  --logo-primary: #3B82F6;
  --logo-secondary: #1E3A8A;
  --logo-text: #1F2937;
}

.logo--reversed {
  --logo-primary: #60A5FA;
  --logo-secondary: #93C5FD;
  --logo-text: #FFFFFF;
}

.logo--mono {
  --logo-primary: currentColor;
  --logo-secondary: currentColor;
  --logo-text: currentColor;
}
```

## Logo Export Specifications

### File Formats

| Format | Use Case | Settings |
|--------|----------|----------|
| SVG | Web, scalable | Optimised, minified |
| PNG | Digital, transparency | 2x/3x for retina |
| JPG | Print, solid bg | CMYK for print |
| PDF | Print, vector | Embedded fonts |
| ICO | Favicon | Multi-resolution |
| WEBP | Web optimised | 90% quality |

### Size Recommendations

| Use | Minimum | Recommended |
|-----|---------|-------------|
| Favicon | 16x16 | 32x32 + 16x16 |
| Social Avatar | 400x400 | 800x800 |
| Web Header | 120px height | 200px height |
| Email Signature | 100px width | 200px width |
| Print (business card) | 300dpi | 600dpi |

### Export Sizes Checklist
```
□ favicon-16.png (16x16)
□ favicon-32.png (32x32)
□ favicon-180.png (180x180 - Apple touch)
□ favicon-192.png (192x192 - Android)
□ favicon-512.png (512x512 - PWA)
□ logo.svg (vector)
□ logo@1x.png (standard)
□ logo@2x.png (retina)
□ logo@3x.png (super retina)
□ logo-reversed.svg
□ logo-mono.svg
□ og-image.png (1200x630 - social)
```

## Logo Generation Patterns

### Abstract Mark from Initials
```javascript
// Create geometric abstraction from letter shapes
function abstractFromInitials(initials, style) {
  const shapes = [];
  
  for (const letter of initials) {
    // Simplify letter to basic geometric forms
    const geometry = letterToGeometry(letter);
    shapes.push(geometry);
  }
  
  // Combine and style
  return combineShapes(shapes, style);
}
```

### Wordmark Generation
```javascript
// Create custom typography treatment
function generateWordmark(text, options) {
  const { 
    font, 
    weight = 600,
    letterSpacing = -0.02,
    ligatures = true 
  } = options;
  
  return {
    text,
    style: {
      fontFamily: font,
      fontWeight: weight,
      letterSpacing: `${letterSpacing}em`,
      fontFeatureSettings: ligatures ? '"liga" 1' : '"liga" 0'
    }
  };
}
```

### Icon + Text Combination
```
Horizontal:     [ICON]  BRANDNAME
Vertical:         [ICON]
                BRANDNAME
Stacked:        [ICON] BRAND
                       NAME
```

## Brand Asset Guidelines

### Business Card
```
┌─────────────────────────────┐
│ [LOGO]                      │
│                             │
│ Name                        │
│ Title                       │
│                             │
│ email@company.com           │
│ +61 XXX XXX XXX             │
│ company.com                 │
└─────────────────────────────┘

Standard: 85mm x 55mm (AU/UK)
US: 3.5" x 2"
```

### Social Media Sizes

| Platform | Profile | Cover/Banner |
|----------|---------|--------------|
| LinkedIn | 400x400 | 1584x396 |
| Twitter/X | 400x400 | 1500x500 |
| Facebook | 180x180 | 820x312 |
| Instagram | 320x320 | N/A |
| YouTube | 800x800 | 2560x1440 |

### Email Signature
```html
<table style="font-family: sans-serif; font-size: 14px;">
  <tr>
    <td style="padding-right: 15px; border-right: 2px solid #3B82F6;">
      <img src="logo.png" width="100" alt="Company">
    </td>
    <td style="padding-left: 15px;">
      <strong>Name</strong><br>
      Title<br>
      <a href="mailto:email@company.com">email@company.com</a>
    </td>
  </tr>
</table>
```

## Common Logo Mistakes to Avoid

1. **Too complex**: Won't work at small sizes
2. **Too trendy**: Will date quickly
3. **Generic symbols**: Light bulbs, globes, swooshes
4. **Poor spacing**: Letters too close/far
5. **Too many colours**: Stick to 2-3 maximum
6. **Relies on effects**: Gradients, shadows that don't translate
7. **Not scalable**: Looks different at different sizes
8. **No clear space**: Logo gets crowded

## Logo Testing Checklist

```
□ Recognisable at 16x16 favicon size
□ Clear at 200px width
□ Works in single colour
□ Works reversed on dark background
□ Distinct from competitors
□ No unintended negative space meanings
□ Passes 5-second recognition test
□ Text readable when scaled down
□ Works in black and white print
□ Vector version available
```
