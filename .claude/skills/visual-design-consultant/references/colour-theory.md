# Colour Theory Reference

Comprehensive colour theory guide for generating professional palettes from user preferences.

## Colour Space Conversions

### HEX to HSL
```javascript
function hexToHsl(hex) {
  const r = parseInt(hex.slice(1, 3), 16) / 255;
  const g = parseInt(hex.slice(3, 5), 16) / 255;
  const b = parseInt(hex.slice(5, 7), 16) / 255;
  
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  let h, s, l = (max + min) / 2;
  
  if (max === min) {
    h = s = 0;
  } else {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r: h = ((g - b) / d + (g < b ? 6 : 0)) / 6; break;
      case g: h = ((b - r) / d + 2) / 6; break;
      case b: h = ((r - g) / d + 4) / 6; break;
    }
  }
  return { h: h * 360, s: s * 100, l: l * 100 };
}
```

### HSL to HEX
```javascript
function hslToHex(h, s, l) {
  s /= 100; l /= 100;
  const a = s * Math.min(l, 1 - l);
  const f = n => {
    const k = (n + h / 30) % 12;
    const colour = l - a * Math.max(Math.min(k - 3, 9 - k, 1), -1);
    return Math.round(255 * colour).toString(16).padStart(2, '0');
  };
  return `#${f(0)}${f(8)}${f(4)}`;
}
```

## Colour Harmony Algorithms

### Rotate Hue
```javascript
function rotateHue(hsl, degrees) {
  return { ...hsl, h: (hsl.h + degrees + 360) % 360 };
}
```

### Harmony Types

| Type | Rotation | Use Case |
|------|----------|----------|
| Complementary | 180° | High contrast, call-to-action |
| Analogous | ±30° | Harmonious, cohesive |
| Triadic | 120°, 240° | Vibrant, balanced |
| Split-complementary | 150°, 210° | Contrast without tension |
| Tetradic | 90°, 180°, 270° | Rich, complex palettes |

### Generate Harmony
```javascript
function generateHarmony(baseHex, type) {
  const base = hexToHsl(baseHex);
  
  switch(type) {
    case 'complementary':
      return [baseHex, hslToHex(rotateHue(base, 180))];
    
    case 'analogous':
      return [
        hslToHex(rotateHue(base, -30)),
        baseHex,
        hslToHex(rotateHue(base, 30))
      ];
    
    case 'triadic':
      return [
        baseHex,
        hslToHex(rotateHue(base, 120)),
        hslToHex(rotateHue(base, 240))
      ];
    
    case 'split-complementary':
      return [
        baseHex,
        hslToHex(rotateHue(base, 150)),
        hslToHex(rotateHue(base, 210))
      ];
  }
}
```

## Colour Scale Generation

### Generate 11-Step Scale (50-950)
```javascript
function generateScale(baseHex) {
  const base = hexToHsl(baseHex);
  const steps = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
  const scale = {};
  
  steps.forEach(step => {
    // Map step to lightness: 50 → ~97%, 500 → base, 950 → ~5%
    let l;
    if (step <= 500) {
      l = base.l + (97 - base.l) * (500 - step) / 450;
    } else {
      l = base.l - (base.l - 5) * (step - 500) / 450;
    }
    
    // Adjust saturation: slightly increase for mid-tones
    let s = base.s;
    if (step >= 300 && step <= 700) {
      s = Math.min(100, base.s * 1.1);
    }
    
    scale[step] = hslToHex(base.h, s, l);
  });
  
  return scale;
}
```

## Neutral Scale with Tint

### Warm vs Cool Neutrals
```javascript
function generateNeutrals(primaryHex, temperature = 'warm') {
  const primary = hexToHsl(primaryHex);
  const tintHue = temperature === 'warm' ? 30 : 220;
  const tintAmount = 3; // Very subtle
  
  const steps = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
  const neutrals = {};
  
  steps.forEach(step => {
    const l = 100 - (step / 10);
    neutrals[step] = hslToHex(tintHue, tintAmount, l);
  });
  
  return neutrals;
}
```

## Semantic Colours

### Default Semantic Palette
```javascript
const semanticDefaults = {
  success: { base: '#10B981', name: 'Emerald' },
  warning: { base: '#F59E0B', name: 'Amber' },
  error:   { base: '#EF4444', name: 'Red' },
  info:    { base: '#3B82F6', name: 'Blue' }
};
```

### Adjust Semantic for Palette Harmony
```javascript
function harmoniseSemanticColour(semanticHex, primaryHex) {
  const semantic = hexToHsl(semanticHex);
  const primary = hexToHsl(primaryHex);
  
  // Subtly shift saturation to match primary's intensity
  const adjustedS = (semantic.s * 0.7) + (primary.s * 0.3);
  
  return hslToHex(semantic.h, adjustedS, semantic.l);
}
```

## Colour Psychology

### Colour Associations by Industry

| Colour | Positive | Negative | Best For |
|--------|----------|----------|----------|
| Blue | Trust, calm, professional | Cold, distant | Finance, healthcare, tech |
| Green | Growth, nature, health | Envy, inexperience | Environment, wellness, finance |
| Red | Energy, passion, urgency | Danger, aggression | Food, entertainment, sales |
| Orange | Friendly, confident, creative | Cheap, immature | Youth brands, food, sports |
| Purple | Luxury, creative, spiritual | Artificial, decadent | Beauty, luxury, creative |
| Yellow | Optimism, clarity, warmth | Caution, cowardice | Children, food, energy |
| Pink | Playful, romantic, nurturing | Immature, weak | Beauty, fashion, sweets |
| Black | Elegant, powerful, sophisticated | Death, evil | Luxury, fashion, tech |
| White | Pure, clean, simple | Sterile, empty | Healthcare, tech, minimal |

### Mood to Colour Mapping
```javascript
const moodToColour = {
  calm:        { hue: 200, saturation: 30 },  // Soft blue
  energetic:   { hue: 15,  saturation: 90 },  // Vibrant orange
  professional:{ hue: 220, saturation: 60 },  // Strong blue
  warm:        { hue: 25,  saturation: 70 },  // Warm orange
  cool:        { hue: 190, saturation: 50 },  // Teal
  natural:     { hue: 140, saturation: 40 },  // Soft green
  luxurious:   { hue: 280, saturation: 45 },  // Purple
  playful:     { hue: 330, saturation: 80 },  // Pink
  minimalist:  { hue: 0,   saturation: 0 },   // Grey
  bold:        { hue: 0,   saturation: 85 }   // Red
};
```

## WCAG Contrast Checking

### Calculate Relative Luminance
```javascript
function getLuminance(hex) {
  const rgb = [
    parseInt(hex.slice(1, 3), 16),
    parseInt(hex.slice(3, 5), 16),
    parseInt(hex.slice(5, 7), 16)
  ].map(c => {
    c /= 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
}
```

### Calculate Contrast Ratio
```javascript
function getContrastRatio(hex1, hex2) {
  const l1 = getLuminance(hex1);
  const l2 = getLuminance(hex2);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}
```

### WCAG Requirements
| Level | Normal Text | Large Text | UI Components |
|-------|-------------|------------|---------------|
| AA | 4.5:1 | 3:1 | 3:1 |
| AAA | 7:1 | 4.5:1 | 4.5:1 |

### Auto-Adjust for Contrast
```javascript
function ensureContrast(foreground, background, targetRatio = 4.5) {
  let fg = hexToHsl(foreground);
  const ratio = getContrastRatio(foreground, background);
  
  if (ratio >= targetRatio) return foreground;
  
  const bgLuminance = getLuminance(background);
  const direction = bgLuminance > 0.5 ? -1 : 1; // Darken or lighten
  
  while (getContrastRatio(hslToHex(fg.h, fg.s, fg.l), background) < targetRatio) {
    fg.l += direction * 5;
    if (fg.l <= 0 || fg.l >= 100) break;
  }
  
  return hslToHex(fg.h, fg.s, Math.max(0, Math.min(100, fg.l)));
}
```

## Palette Generation Algorithm

### Complete Palette from Single Colour
```javascript
function generateCompletePalette(primaryHex, options = {}) {
  const {
    harmonyType = 'split-complementary',
    temperature = 'warm',
    includeSemantics = true
  } = options;
  
  const palette = {
    primary: generateScale(primaryHex),
    neutral: generateNeutrals(primaryHex, temperature)
  };
  
  // Generate secondary from harmony
  const harmony = generateHarmony(primaryHex, harmonyType);
  if (harmony[1]) {
    palette.secondary = generateScale(harmony[1]);
  }
  if (harmony[2]) {
    palette.accent = generateScale(harmony[2]);
  }
  
  // Add semantic colours
  if (includeSemantics) {
    palette.success = generateScale(harmoniseSemanticColour('#10B981', primaryHex));
    palette.warning = generateScale(harmoniseSemanticColour('#F59E0B', primaryHex));
    palette.error = generateScale(harmoniseSemanticColour('#EF4444', primaryHex));
    palette.info = generateScale(harmoniseSemanticColour('#3B82F6', primaryHex));
  }
  
  return palette;
}
```

## Named Colour Parsing

### Common Colour Names to Hex
```javascript
const namedColours = {
  // Basic
  red: '#EF4444', blue: '#3B82F6', green: '#22C55E',
  yellow: '#EAB308', orange: '#F97316', purple: '#A855F7',
  pink: '#EC4899', cyan: '#06B6D4', teal: '#14B8A6',
  
  // Extended
  coral: '#FF7F50', salmon: '#FA8072', crimson: '#DC143C',
  navy: '#1E3A5F', royal: '#4169E1', sky: '#0EA5E9',
  forest: '#228B22', lime: '#84CC16', mint: '#98FF98',
  gold: '#FFD700', amber: '#FFBF00', honey: '#EB9605',
  plum: '#8E4585', violet: '#8B5CF6', lavender: '#E6E6FA',
  rose: '#FF007F', blush: '#DE5D83', burgundy: '#800020',
  slate: '#64748B', charcoal: '#36454F', graphite: '#383838'
};
```

## Output Format Templates

### CSS Custom Properties
```css
:root {
  /* Primary */
  --color-primary-50: #eff6ff;
  --color-primary-500: #3b82f6;
  --color-primary-900: #1e3a8a;
  
  /* Semantic */
  --color-success: #10b981;
  --color-warning: #f59e0b;
  --color-error: #ef4444;
}
```

### Tailwind Config
```javascript
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#eff6ff',
          // ... full scale
        }
      }
    }
  }
}
```

### Design Tokens (JSON)
```json
{
  "color": {
    "primary": {
      "50": { "value": "#eff6ff" },
      "500": { "value": "#3b82f6" }
    }
  }
}
```
