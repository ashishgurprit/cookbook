#!/usr/bin/env node

/**
 * Visual Design Consultant - WCAG Contrast Checker
 * Validates colour combinations for accessibility compliance
 * 
 * Usage:
 *   node contrast-checker.js --fg "#FFFFFF" --bg "#3B82F6"
 *   node contrast-checker.js --palette palette.json
 */

const fs = require('fs');

// ============================================
// Colour Conversion
// ============================================

function hexToRgb(hex) {
  hex = hex.replace('#', '');
  return {
    r: parseInt(hex.slice(0, 2), 16),
    g: parseInt(hex.slice(2, 4), 16),
    b: parseInt(hex.slice(4, 6), 16)
  };
}

function hexToHsl(hex) {
  const { r, g, b } = hexToRgb(hex);
  const rNorm = r / 255;
  const gNorm = g / 255;
  const bNorm = b / 255;
  
  const max = Math.max(rNorm, gNorm, bNorm);
  const min = Math.min(rNorm, gNorm, bNorm);
  let h, s, l = (max + min) / 2;
  
  if (max === min) {
    h = s = 0;
  } else {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case rNorm: h = ((gNorm - bNorm) / d + (gNorm < bNorm ? 6 : 0)) / 6; break;
      case gNorm: h = ((bNorm - rNorm) / d + 2) / 6; break;
      case bNorm: h = ((rNorm - gNorm) / d + 4) / 6; break;
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

// ============================================
// Luminance & Contrast
// ============================================

function getRelativeLuminance(hex) {
  const { r, g, b } = hexToRgb(hex);
  
  const [rSrgb, gSrgb, bSrgb] = [r, g, b].map(c => {
    c /= 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  
  return 0.2126 * rSrgb + 0.7152 * gSrgb + 0.0722 * bSrgb;
}

function getContrastRatio(hex1, hex2) {
  const l1 = getRelativeLuminance(hex1);
  const l2 = getRelativeLuminance(hex2);
  
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  
  return (lighter + 0.05) / (darker + 0.05);
}

// ============================================
// WCAG Level Assessment
// ============================================

const WCAG_LEVELS = {
  'AAA-normal': 7.0,
  'AAA-large': 4.5,
  'AA-normal': 4.5,
  'AA-large': 3.0,
  'AA-ui': 3.0
};

function assessContrast(ratio) {
  const results = {
    ratio: ratio.toFixed(2),
    passes: {},
    fails: {}
  };
  
  for (const [level, threshold] of Object.entries(WCAG_LEVELS)) {
    if (ratio >= threshold) {
      results.passes[level] = true;
    } else {
      results.fails[level] = threshold;
    }
  }
  
  return results;
}

function getPassLevel(ratio) {
  if (ratio >= 7.0) return '✓ AAA';
  if (ratio >= 4.5) return '✓ AA';
  if (ratio >= 3.0) return '◐ AA-large only';
  return '✗ Fails';
}

// ============================================
// Auto-Adjust for Contrast
// ============================================

function adjustForContrast(foreground, background, targetRatio = 4.5) {
  const currentRatio = getContrastRatio(foreground, background);
  
  if (currentRatio >= targetRatio) {
    return { colour: foreground, ratio: currentRatio, adjusted: false };
  }
  
  const fgHsl = hexToHsl(foreground);
  const bgLuminance = getRelativeLuminance(background);
  
  const direction = bgLuminance > 0.5 ? -5 : 5;
  
  let adjusted = { ...fgHsl };
  let iterations = 0;
  const maxIterations = 20;
  
  while (iterations < maxIterations) {
    adjusted.l += direction;
    adjusted.l = Math.max(0, Math.min(100, adjusted.l));
    
    const newHex = hslToHex(adjusted.h, adjusted.s, adjusted.l);
    const newRatio = getContrastRatio(newHex, background);
    
    if (newRatio >= targetRatio) {
      return { colour: newHex, ratio: newRatio, adjusted: true };
    }
    
    iterations++;
  }
  
  return {
    colour: hslToHex(adjusted.h, adjusted.s, adjusted.l),
    ratio: getContrastRatio(hslToHex(adjusted.h, adjusted.s, adjusted.l), background),
    adjusted: true,
    warning: 'Could not reach target contrast'
  };
}

// ============================================
// Output
// ============================================

function formatSingleCheck(fg, bg) {
  const ratio = getContrastRatio(fg, bg);
  const level = getPassLevel(ratio);
  
  console.log('\n┌─────────────────────────────────────────┐');
  console.log('│          WCAG Contrast Check            │');
  console.log('├─────────────────────────────────────────┤');
  console.log(`│  Foreground: ${fg.padEnd(25)}│`);
  console.log(`│  Background: ${bg.padEnd(25)}│`);
  console.log('├─────────────────────────────────────────┤');
  console.log(`│  Ratio: ${ratio.toFixed(2)}:1`.padEnd(42) + '│');
  console.log(`│  Level: ${level}`.padEnd(42) + '│');
  console.log('└─────────────────────────────────────────┘');
  
  if (ratio < 4.5) {
    const adjusted = adjustForContrast(fg, bg);
    console.log('\n💡 Suggestion:');
    console.log(`   Adjust foreground to ${adjusted.colour} for ${adjusted.ratio.toFixed(2)}:1 ratio`);
  }
}

// CLI
if (require.main === module) {
  const args = process.argv.slice(2);
  let fg, bg;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--fg' && args[i + 1]) fg = args[++i];
    if (args[i] === '--bg' && args[i + 1]) bg = args[++i];
  }
  
  if (fg && bg) {
    formatSingleCheck(fg, bg);
  } else {
    console.log('Usage: node contrast-checker.js --fg "#FFF" --bg "#000"');
  }
}

module.exports = { getContrastRatio, adjustForContrast, assessContrast };
