#!/usr/bin/env node

/**
 * Visual Design Consultant - Palette Generator
 * Generates complete colour palettes from user preferences
 * 
 * Usage:
 *   node generate-palette.js --primary "#3B82F6"
 *   node generate-palette.js --primary "blue" --harmony triadic
 *   node generate-palette.js --mood "calm professional"
 */

const fs = require('fs');

// ============================================
// Colour Conversions
// ============================================

function hexToHsl(hex) {
  hex = hex.replace('#', '');
  const r = parseInt(hex.slice(0, 2), 16) / 255;
  const g = parseInt(hex.slice(2, 4), 16) / 255;
  const b = parseInt(hex.slice(4, 6), 16) / 255;
  
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
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

function hslToHex(h, s, l) {
  s /= 100;
  l /= 100;
  
  const a = s * Math.min(l, 1 - l);
  const f = n => {
    const k = (n + h / 30) % 12;
    const colour = l - a * Math.max(Math.min(k - 3, 9 - k, 1), -1);
    return Math.round(255 * colour).toString(16).padStart(2, '0');
  };
  
  return `#${f(0)}${f(8)}${f(4)}`;
}

function hexToRgb(hex) {
  hex = hex.replace('#', '');
  return {
    r: parseInt(hex.slice(0, 2), 16),
    g: parseInt(hex.slice(2, 4), 16),
    b: parseInt(hex.slice(4, 6), 16)
  };
}

// ============================================
// Named Colours
// ============================================

const namedColours = {
  red: '#EF4444', blue: '#3B82F6', green: '#22C55E',
  yellow: '#EAB308', orange: '#F97316', purple: '#A855F7',
  pink: '#EC4899', cyan: '#06B6D4', teal: '#14B8A6',
  indigo: '#6366F1', violet: '#8B5CF6', rose: '#F43F5E',
  coral: '#FF7F50', salmon: '#FA8072', crimson: '#DC143C',
  navy: '#1E3A5F', royal: '#4169E1', sky: '#0EA5E9',
  forest: '#228B22', lime: '#84CC16', mint: '#98FF98',
  gold: '#FFD700', amber: '#FFBF00', honey: '#EB9605',
  plum: '#8E4585', lavender: '#E6E6FA',
  blush: '#DE5D83', burgundy: '#800020',
  slate: '#64748B', charcoal: '#36454F', graphite: '#383838'
};

// ============================================
// Mood to Colour
// ============================================

const moodKeywords = {
  calm: { hue: 200, saturation: 35, lightness: 50 },
  energetic: { hue: 15, saturation: 85, lightness: 55 },
  professional: { hue: 220, saturation: 65, lightness: 45 },
  warm: { hue: 25, saturation: 75, lightness: 50 },
  cool: { hue: 190, saturation: 55, lightness: 45 },
  natural: { hue: 140, saturation: 45, lightness: 45 },
  luxurious: { hue: 280, saturation: 50, lightness: 35 },
  playful: { hue: 330, saturation: 75, lightness: 55 },
  minimalist: { hue: 220, saturation: 10, lightness: 45 },
  bold: { hue: 0, saturation: 80, lightness: 50 },
  trustworthy: { hue: 210, saturation: 70, lightness: 45 },
  creative: { hue: 280, saturation: 65, lightness: 55 },
  elegant: { hue: 0, saturation: 0, lightness: 20 },
  fresh: { hue: 160, saturation: 60, lightness: 50 },
  earthy: { hue: 30, saturation: 40, lightness: 40 }
};

function moodToColour(moodString) {
  const words = moodString.toLowerCase().split(/\s+/);
  let h = 0, s = 0, l = 0, count = 0;
  
  for (const word of words) {
    if (moodKeywords[word]) {
      h += moodKeywords[word].hue;
      s += moodKeywords[word].saturation;
      l += moodKeywords[word].lightness;
      count++;
    }
  }
  
  if (count === 0) {
    // Default to professional blue
    return '#3B82F6';
  }
  
  return hslToHex(h / count, s / count, l / count);
}

// ============================================
// Colour Harmony
// ============================================

function rotateHue(hsl, degrees) {
  return { ...hsl, h: (hsl.h + degrees + 360) % 360 };
}

function generateHarmony(baseHex, type = 'split-complementary') {
  const base = hexToHsl(baseHex);
  
  switch (type) {
    case 'complementary':
      return {
        primary: baseHex,
        secondary: hslToHex(rotateHue(base, 180).h, base.s, base.l)
      };
    
    case 'analogous':
      return {
        primary: baseHex,
        secondary: hslToHex(rotateHue(base, 30).h, base.s, base.l),
        accent: hslToHex(rotateHue(base, -30).h, base.s, base.l)
      };
    
    case 'triadic':
      return {
        primary: baseHex,
        secondary: hslToHex(rotateHue(base, 120).h, base.s, base.l),
        accent: hslToHex(rotateHue(base, 240).h, base.s, base.l)
      };
    
    case 'split-complementary':
    default:
      return {
        primary: baseHex,
        secondary: hslToHex(rotateHue(base, 150).h, base.s, base.l),
        accent: hslToHex(rotateHue(base, 210).h, base.s, base.l)
      };
  }
}

// ============================================
// Scale Generation
// ============================================

function generateScale(baseHex) {
  const base = hexToHsl(baseHex);
  const steps = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
  const scale = {};
  
  for (const step of steps) {
    let l, s;
    
    if (step <= 500) {
      // Lighter shades
      l = base.l + (97 - base.l) * (500 - step) / 450;
      s = Math.max(0, base.s - (500 - step) * 0.05);
    } else {
      // Darker shades
      l = base.l - (base.l - 5) * (step - 500) / 450;
      s = Math.min(100, base.s + (step - 500) * 0.02);
    }
    
    scale[step] = hslToHex(base.h, s, l);
  }
  
  return scale;
}

function generateNeutrals(primaryHex, temperature = 'warm') {
  const primary = hexToHsl(primaryHex);
  const tintHue = temperature === 'warm' ? 
    (primary.h > 180 ? 30 : primary.h * 0.3 + 20) : 
    220;
  
  const steps = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
  const neutrals = {};
  
  for (const step of steps) {
    const l = 100 - (step / 10);
    const s = Math.max(0, 5 - step * 0.005);
    neutrals[step] = hslToHex(tintHue, s, l);
  }
  
  return neutrals;
}

// ============================================
// Semantic Colours
// ============================================

function generateSemanticColours(primaryHex) {
  const primary = hexToHsl(primaryHex);
  
  const semantics = {
    success: { h: 160, s: 70, l: 40 },
    warning: { h: 40, s: 95, l: 50 },
    error: { h: 0, s: 85, l: 55 },
    info: { h: 210, s: 80, l: 50 }
  };
  
  const result = {};
  
  for (const [name, colour] of Object.entries(semantics)) {
    // Slightly adjust saturation to match primary's intensity
    const adjustedS = (colour.s * 0.8) + (primary.s * 0.2);
    const baseHex = hslToHex(colour.h, adjustedS, colour.l);
    result[name] = generateScale(baseHex);
  }
  
  return result;
}

// ============================================
// Contrast Checking
// ============================================

function getLuminance(hex) {
  const rgb = hexToRgb(hex);
  const [r, g, b] = [rgb.r, rgb.g, rgb.b].map(c => {
    c /= 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function getContrastRatio(hex1, hex2) {
  const l1 = getLuminance(hex1);
  const l2 = getLuminance(hex2);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

function validateContrast(palette) {
  const issues = [];
  
  // Check primary on white
  const primaryOnWhite = getContrastRatio(palette.primary[500], '#FFFFFF');
  if (primaryOnWhite < 4.5) {
    issues.push(`Primary 500 on white: ${primaryOnWhite.toFixed(2)} (needs 4.5)`);
  }
  
  // Check primary on neutral background
  const primaryOnNeutral = getContrastRatio(palette.primary[500], palette.neutral[50]);
  if (primaryOnNeutral < 4.5) {
    issues.push(`Primary 500 on neutral-50: ${primaryOnNeutral.toFixed(2)} (needs 4.5)`);
  }
  
  return issues;
}

// ============================================
// Output Formatters
// ============================================

function toCSS(palette) {
  let css = ':root {\n';
  
  for (const [colorName, scale] of Object.entries(palette)) {
    for (const [step, hex] of Object.entries(scale)) {
      css += `  --color-${colorName}-${step}: ${hex};\n`;
    }
    css += '\n';
  }
  
  css += '}\n';
  return css;
}

function toTailwind(palette) {
  const config = {
    theme: {
      extend: {
        colors: {}
      }
    }
  };
  
  for (const [colorName, scale] of Object.entries(palette)) {
    config.theme.extend.colors[colorName] = scale;
  }
  
  return `module.exports = ${JSON.stringify(config, null, 2)}`;
}

function toJSON(palette) {
  return JSON.stringify(palette, null, 2);
}

// ============================================
// Main Generation Function
// ============================================

function generatePalette(options = {}) {
  let {
    primary,
    mood,
    harmony = 'split-complementary',
    temperature = 'warm',
    format = 'json'
  } = options;
  
  // Resolve primary colour
  if (mood && !primary) {
    primary = moodToColour(mood);
  } else if (primary && !primary.startsWith('#')) {
    primary = namedColours[primary.toLowerCase()] || '#3B82F6';
  } else if (!primary) {
    primary = '#3B82F6';
  }
  
  // Generate harmony
  const harmonyColours = generateHarmony(primary, harmony);
  
  // Build complete palette
  const palette = {
    primary: generateScale(harmonyColours.primary),
    secondary: generateScale(harmonyColours.secondary),
    neutral: generateNeutrals(primary, temperature)
  };
  
  if (harmonyColours.accent) {
    palette.accent = generateScale(harmonyColours.accent);
  }
  
  // Add semantic colours
  const semantics = generateSemanticColours(primary);
  Object.assign(palette, semantics);
  
  // Validate
  const issues = validateContrast(palette);
  
  // Format output
  let output;
  switch (format) {
    case 'css':
      output = toCSS(palette);
      break;
    case 'tailwind':
      output = toTailwind(palette);
      break;
    case 'json':
    default:
      output = toJSON(palette);
  }
  
  return {
    palette,
    output,
    issues,
    meta: {
      primary,
      harmony,
      temperature
    }
  };
}

// ============================================
// CLI Interface
// ============================================

function parseArgs(args) {
  const options = {};
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '--primary' && args[i + 1]) {
      options.primary = args[++i];
    } else if (arg === '--mood' && args[i + 1]) {
      options.mood = args[++i];
    } else if (arg === '--harmony' && args[i + 1]) {
      options.harmony = args[++i];
    } else if (arg === '--temperature' && args[i + 1]) {
      options.temperature = args[++i];
    } else if (arg === '--format' && args[i + 1]) {
      options.format = args[++i];
    } else if (arg === '--output' && args[i + 1]) {
      options.outputFile = args[++i];
    } else if (arg === '--help') {
      console.log(`
Visual Design Consultant - Palette Generator

Usage:
  node generate-palette.js [options]

Options:
  --primary <colour>    Base colour (hex or name)
  --mood <keywords>     Mood keywords (e.g., "calm professional")
  --harmony <type>      Harmony type: complementary, analogous, triadic, split-complementary
  --temperature <temp>  warm or cool
  --format <format>     Output format: json, css, tailwind
  --output <file>       Output file path

Examples:
  node generate-palette.js --primary "#3B82F6"
  node generate-palette.js --primary blue --harmony triadic
  node generate-palette.js --mood "calm professional" --format css
      `);
      process.exit(0);
    }
  }
  
  return options;
}

// Run if called directly
if (require.main === module) {
  const options = parseArgs(process.argv.slice(2));
  const result = generatePalette(options);
  
  console.log(result.output);
  
  if (result.issues.length > 0) {
    console.error('\n⚠️  Contrast Issues:');
    result.issues.forEach(issue => console.error(`   - ${issue}`));
  }
  
  if (options.outputFile) {
    fs.writeFileSync(options.outputFile, result.output);
    console.log(`\n✓ Written to ${options.outputFile}`);
  }
}

module.exports = { generatePalette, hexToHsl, hslToHex, getContrastRatio };
