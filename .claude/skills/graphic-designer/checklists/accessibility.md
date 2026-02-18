# Accessibility Checklist for Graphic Design

## Core Principle

**Accessibility is not optional.** Designing for everyone—including people with disabilities—is ethical, legal, and expands your audience. Accessible design is often better design for everyone.

---

## Color & Contrast (WCAG 2.1)

### Contrast Ratios

**WCAG AA (Minimum Standard):**
- [ ] **Normal text** (< 18pt): 4.5:1 contrast ratio
- [ ] **Large text** (≥ 18pt or bold ≥ 14pt): 3:1 contrast ratio
- [ ] **UI components** (icons, buttons, form borders): 3:1

**WCAG AAA (Enhanced):**
- [ ] **Normal text**: 7:1 contrast ratio
- [ ] **Large text**: 4.5:1 contrast ratio

**Tools:**
- WebAIM Contrast Checker: https://webaim.org/resources/contrastchecker/
- Stark (Figma plugin): https://www.getstark.co/
- Color Oracle (desktop app): https://colororacle.org/

### Color Blindness

**8% of men, 0.5% of women have color blindness**

**Types:**
- **Deuteranopia** (most common): Red-green confusion
- **Protanopia**: Red-green (different wavelengths than deuteranopia)
- **Tritanopia**: Blue-yellow confusion
- **Achromatopsia** (rare): Complete color blindness (monochrome vision)

**Design Rules:**
- [ ] **Never use color alone** to convey meaning
  - ✅ Use color + icon (green checkmark, red X)
  - ✅ Use color + pattern (striped, dotted, solid)
  - ✅ Use color + text label
  - ❌ Green = success, Red = error (text-only, no label)

- [ ] **Avoid problematic combinations:**
  - ❌ Red text on green background (or vice versa)
  - ❌ Blue text on purple background
  - ❌ Light green on white (low contrast for deuteranopes)

- [ ] **Use colorblind-safe palettes:**
  - ✅ Blue + Orange (instead of blue + red)
  - ✅ Purple + Yellow
  - ✅ High contrast (dark + light, not similar hues)

**Testing:**
- [ ] Simulate colorblindness:
  - Stark plugin (Figma/Sketch)
  - Color Oracle (desktop)
  - Coblis (web): https://www.color-blindness.com/coblis-color-blindness-simulator/

---

## Typography

### Readability

**Font Size:**
- [ ] **Body text**: Minimum 16px (1rem) for web, 10pt for print
- [ ] **Small text** (captions): Minimum 12px web, 8pt print
- [ ] **Interactive elements** (buttons, links): Minimum 16px (easier to tap)

**Line Height (Leading):**
- [ ] **Body text**: 1.4-1.6× font size (e.g., 16px text = 24px line height)
- [ ] **Headings**: 1.2-1.3× font size (tighter for display)
- [ ] **Small text**: 1.5-1.7× (more leading helps legibility)

**Line Length (Measure):**
- [ ] **Optimal**: 45-75 characters per line
- [ ] **Ideal**: 66 characters per line
- [ ] **Too long**: > 90 characters (causes eye strain, hard to track)
- [ ] **Too short**: < 40 characters (choppy reading)

**Font Choice:**
- [ ] **Avoid decorative fonts** for body text (hard to read)
- [ ] **Humanist sans** or **serif** for long-form reading (higher x-height = more legible)
- [ ] **Clear letterforms**: Distinct I/l/1, O/0, rn/m
- [ ] **OpenType features**: Use ligatures (fi, fl), proper numbers (lining/oldstyle)

**Letter Spacing:**
- [ ] **Body text**: Default (0) or slight positive (+0-10)
- [ ] **All caps**: +50 to +100 tracking (improves legibility)
- [ ] **Avoid negative tracking** for text < 18pt (reduces legibility)

**Alignment:**
- [ ] **Left-aligned** for body text (easiest to read for LTR languages)
- [ ] **Avoid justified** if possible (creates uneven spacing, "rivers" in text)
- [ ] **Never center-align** paragraphs (hard to scan)

### Dyslexia Considerations

**10% of population has dyslexia**

- [ ] **Use dyslexia-friendly fonts** (optional, but helpful):
  - OpenDyslexic (free, designed specifically for dyslexia)
  - Comic Sans (often mocked, but actually helpful for some)
  - Verdana, Tahoma (high x-height, clear letterforms)

- [ ] **Avoid italics** for long passages (harder to read)
- [ ] **Generous line height** (1.5-2× for dyslexic readers)
- [ ] **Avoid all caps** (harder to distinguish word shapes)
- [ ] **Use bold for emphasis**, not underline (underline = link confusion)

---

## Images & Graphics

### Alt Text (Web & Digital)

**Purpose:** Screen readers describe images to blind/low-vision users

- [ ] **Every image needs alt text** (or marked as decorative)
- [ ] **Descriptive, concise**: "Woman typing on laptop in coffee shop"
  - ❌ "Image123.jpg"
  - ❌ "Photo of a woman"
  - ✅ "Woman typing on laptop in coffee shop"

- [ ] **Context matters**: Alt text should match content purpose
  - If image is informational: Describe what's conveyed
  - If image is decorative: Use empty alt (`alt=""`) so screen readers skip

- [ ] **Text in images**: Include text in alt description
  - Example: Infographic → "Chart showing 60% increase in sales from Q1 to Q2"

### Graphs & Data Visualizations

- [ ] **Provide data table alternative** (raw data for screen readers)
- [ ] **Describe key insights** in alt text (not just "bar chart")
  - ✅ "Bar chart showing North region leads with $180K, followed by East ($150K), South ($120K), West ($80K)"

- [ ] **Use patterns + color** (not just color to differentiate)
  - Striped, dotted, solid patterns in addition to colors

- [ ] **Direct labels** (label data points directly, not just legend)
  - Easier for everyone, not just accessibility

### Decorative vs Informational

**Decorative (Skip for Screen Readers):**
- Background patterns
- Divider lines (purely visual)
- Stock photos (not adding information)
→ Use `alt=""` (empty alt) in HTML

**Informational (Requires Alt Text):**
- Product photos
- Diagrams, charts, infographics
- Logos (when conveying brand identity)
→ Provide descriptive alt text

---

## Interactive Elements (Web/Digital)

### Buttons & Links

**Size & Spacing:**
- [ ] **Minimum touch target**: 44×44px (Apple), 48×48px (Google)
- [ ] **Spacing between targets**: 8px minimum (prevents mis-taps)

**Visual Indicators:**
- [ ] **Hover state**: Visual change (color, underline, shadow)
- [ ] **Focus state**: Clear outline for keyboard users (don't remove `:focus` outline!)
- [ ] **Active state**: Pressed/clicked feedback
- [ ] **Disabled state**: Visually distinct (grayed out, lower opacity)

**Label Clarity:**
- [ ] **Descriptive text**: "Download Report" not just "Click Here"
- [ ] **Icon + text**: Icons alone can be ambiguous (use text label or aria-label)

### Forms

**Labels:**
- [ ] **Every input has a label** (visible text, not just placeholder)
- [ ] **Labels above inputs** (easier to scan than left-aligned)
- [ ] **Placeholder text ≠ label** (placeholders disappear on input, hard for memory)

**Error Messages:**
- [ ] **Clear, specific**: "Email format invalid" not "Error"
- [ ] **Color + icon + text**: Red color + error icon + text (not just red)
- [ ] **Positioned near input**: Error message adjacent to field, not just top of form

**Required Fields:**
- [ ] **Marked clearly**: Asterisk (*) + text "Required" (not just asterisk alone)
- [ ] **Consistent marking**: All required fields use same indicator

---

## Motion & Animation

### Vestibular Disorders

**People with vestibular disorders can experience nausea, dizziness, migraines from motion**

- [ ] **Respect `prefers-reduced-motion`** (CSS media query)
  ```css
  @media (prefers-reduced-motion: reduce) {
    * {
      animation-duration: 0.01ms !important;
      transition-duration: 0.01ms !important;
    }
  }
  ```

- [ ] **Avoid parallax scrolling** (or make optional/subtle)
- [ ] **Limit auto-playing animations** (especially looping, rapid movement)
- [ ] **Provide pause/stop controls** for animations

### Animation Best Practices

- [ ] **Subtle, purposeful**: Animation should guide, not distract
- [ ] **Short duration**: 200-300ms for UI feedback (longer = feels slow)
- [ ] **Ease timing**: Use ease-out (feels responsive) over linear
- [ ] **Avoid flashing**: No more than 3 flashes per second (seizure risk)

---

## Document Accessibility (PDF, Print)

### PDF Accessibility

- [ ] **Tagged PDF**: Use proper heading structure (H1, H2, H3)
- [ ] **Alt text for images**: Same as web (descriptive or empty if decorative)
- [ ] **Reading order**: Logical flow for screen readers
- [ ] **Searchable text**: Not scanned images (use OCR if needed)
- [ ] **Form fields labeled**: Fillable PDFs need labels for each field

**Tools:**
- Adobe Acrobat Pro (Accessibility Checker)
- PAC 2024 (free PDF accessibility checker): https://pac.pdf-ua.org/

### Print Accessibility

**Large Print:**
- [ ] **Minimum 16pt body text** (18pt ideal for large print)
- [ ] **High contrast**: Black on white (or very dark on very light)
- [ ] **Sans serif fonts**: Clearer at large sizes (Arial, Verdana)

**Braille:**
- [ ] **Contracted Braille** for long documents (Grade 2)
- [ ] **Uncontracted** for proper names, technical terms
- [ ] Work with certified Braille transcription services

---

## Cognitive Accessibility

### Simplicity & Clarity

- [ ] **Clear hierarchy**: Obvious headings, subheadings, body text distinction
- [ ] **Consistent layout**: Don't change navigation/structure mid-document
- [ ] **Chunked content**: Break long content into sections (use headings, lists)
- [ ] **Avoid jargon**: Plain language when possible (or define terms)

### Instructions & Guidance

- [ ] **Visual cues**: Icons, arrows, highlighting to guide users
- [ ] **Progressive disclosure**: Don't overwhelm with all info at once
- [ ] **Error prevention**: Clear labels, examples, help text before errors occur

---

## Testing Checklist

### Automated Testing (Good Starting Point)

- [ ] **Contrast checker**: WebAIM, Stark, Chrome DevTools
- [ ] **Color blindness simulator**: Stark, Color Oracle, Coblis
- [ ] **Accessibility audits**: Lighthouse (Chrome), axe DevTools

### Manual Testing (Essential)

- [ ] **Keyboard navigation**: Tab through site (no mouse), can you access everything?
- [ ] **Screen reader**: Test with NVDA (Windows, free), JAWS (Windows), VoiceOver (Mac/iOS)
- [ ] **Zoom to 200%**: Text still readable? Layout not broken?
- [ ] **Grayscale**: Remove all color (does meaning still make sense?)

### User Testing (Best Practice)

- [ ] **Test with real users**: People with disabilities, various assistive tech
- [ ] **Diverse testers**: Different ages, abilities, tech familiarity
- [ ] **Observe, don't lead**: Watch how they interact, where they struggle

---

## Legal Standards (Varies by Region)

**United States:**
- **ADA** (Americans with Disabilities Act): Applies to public spaces, including websites
- **Section 508**: Federal websites must be accessible
- **WCAG 2.1 Level AA**: Common legal standard

**European Union:**
- **EN 301 549**: Accessibility requirements (harmonized with WCAG 2.1)
- **European Accessibility Act**: Applies to digital products/services

**Canada:**
- **AODA** (Accessibility for Ontarians with Disabilities Act)
- **WCAG 2.0 Level AA**: Legal requirement for Ontario

**Australia:**
- **DDA** (Disability Discrimination Act)
- **WCAG 2.1 Level AA**: Recommended standard

**UK:**
- **Equality Act 2010**: Websites must be accessible
- **WCAG 2.1 Level AA**: Public sector requirement

---

## Resources

**Guidelines:**
- WCAG 2.1 (Web Content Accessibility Guidelines): https://www.w3.org/WAI/WCAG21/quickref/
- WebAIM (practical resources): https://webaim.org/
- A11Y Project (community-driven): https://www.a11yproject.com/

**Tools:**
- Stark (Figma/Sketch plugin): https://www.getstark.co/
- Color Oracle (colorblind simulator): https://colororacle.org/
- WAVE (web accessibility checker): https://wave.webaim.org/
- axe DevTools (browser extension): https://www.deque.com/axe/

**Testing:**
- NVDA (free screen reader, Windows): https://www.nvaccess.org/
- VoiceOver (built-in, Mac/iOS): System Preferences > Accessibility
- JAWS (screen reader, Windows, paid): https://www.freedomscientific.com/

**Learning:**
- *Inclusive Design Patterns* by Heydon Pickering
- *Accessibility for Everyone* by Laura Kalbag
- WebAIM training: https://webaim.org/training/
- Deque University: https://dequeuniversity.com/

---

**Remember:** Accessibility is not a checkbox. It's an ongoing commitment to inclusive design that benefits everyone—from people with disabilities to elderly users to anyone in challenging circumstances (bright sunlight, noisy environments, temporary injuries).
