# Print Production Specifications

## Critical Principle

**Digital ≠ Print.** What looks perfect on screen may be unprintable. Always proof and understand production constraints before finalizing designs.

## Color Modes

### RGB (Red, Green, Blue)
**Use:** Screen display (web, apps, presentations, video)
**Range:** 0-255 per channel (16.7 million colors)
**Device:** Additive color (light emission)

```
RGB(255, 0, 0) = Red
RGB(0, 255, 0) = Green
RGB(0, 0, 255) = Blue
RGB(255, 255, 255) = White (all light)
RGB(0, 0, 0) = Black (no light)
```

### CMYK (Cyan, Magenta, Yellow, Black/Key)
**Use:** Print (offset, digital)
**Range:** 0-100% per channel
**Device:** Subtractive color (ink on paper)

```
CMYK(0, 100, 100, 0) = Red
CMYK(100, 0, 100, 0) = Green
CMYK(100, 100, 0, 0) = Blue
CMYK(0, 0, 0, 0) = White (no ink, paper shows)
CMYK(0, 0, 0, 100) = Black
```

**RGB to CMYK Conversion Issues:**
- **RGB has wider gamut** (can display colors CMYK can't print)
- **Vibrant blues, greens, oranges** often shift when converted
- **Always soft-proof** (View > Proof Setup > CMYK in Photoshop/Illustrator)

### Pantone/Spot Colors
**Use:** Brand colors that must be exact (logos, corporate identity)
**Format:** Pantone Matching System (PMS)
**Advantage:** Consistent color regardless of printer

```
Examples:
Coca-Cola Red: PMS 484
Tiffany Blue: PMS 1837
Starbucks Green: PMS 3425
```

**When to Use:**
- Brand identity materials (business cards, packaging)
- 1-3 color print jobs (cheaper than full CMYK)
- Metallic, fluorescent, or neon colors (can't be achieved with CMYK)
- Critical color matching (pharmaceutical labels, safety signage)

**Cost:** Adds expense (each spot color = additional print pass)

---

## Resolution & Image Quality

### Print Resolution (DPI/PPI)

**Standard:** 300 DPI (dots per inch) at final print size
**Minimum:** 250 DPI (acceptable but not ideal)
**Low Quality:** <200 DPI (pixelated, avoid)

```
Example:
8×10" photo print at 300 DPI = 2400×3000 pixels

Calculation:
Width (inches) × DPI = Pixel Width
8 × 300 = 2400px
10 × 300 = 3000px
```

**Exceptions:**
- **Large format** (billboards, banners): 100-150 DPI (viewed from distance)
- **Fine art prints:** 360-600 DPI (museum quality)
- **Newspapers:** 150-200 DPI (lower quality paper)

### Vector vs Raster

**Vector (Scalable):**
- Formats: AI, EPS, PDF, SVG
- Use: Logos, icons, illustrations, type
- Resolution: Infinite (math-based, not pixels)
- File size: Small

**Raster (Pixel-Based):**
- Formats: TIFF, PSD, JPG, PNG
- Use: Photographs, complex gradients, textured images
- Resolution: Fixed (scales poorly)
- File size: Large

**Rule:** Use vector whenever possible. Rasterize only for final output if required.

---

## Bleed, Trim, Safe Area

### Anatomy of a Print Document

```
┌─────────────────────────────────┐
│ ← 3mm Bleed (extends beyond)    │
│  ┌───────────────────────────┐  │ ← Trim Line (cut edge)
│  │  5mm Safe Area (margins)  │  │
│  │  ┌─────────────────────┐  │  │ ← Safe Area (no critical content)
│  │  │                     │  │  │
│  │  │   Live Content      │  │  │
│  │  │   Area              │  │  │
│  │  │                     │  │  │
│  │  └─────────────────────┘  │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

### Bleed
**Definition:** Area extending beyond trim line (typically 3mm/0.125")
**Purpose:** Prevents white edges if cutting is slightly off
**Rule:** Extend all background images/colors to bleed edge

**Without Bleed (WRONG):**
```
┌─────────────┐
│             │ ← If cut is off, white edge shows
│   Content   │
│             │
└─────────────┘
```

**With Bleed (CORRECT):**
```
┌───────────────┐
│               │ ← Image extends beyond cut
│   Content     │
│               │
└───────────────┘
```

### Safe Area
**Definition:** Margin inside trim line where critical content must stay
**Standard:** 5mm (0.2") from trim
**Rule:** No text, logos, or important elements in danger zone

**Why:** Cutting can be off by 1-2mm, binding consumes edge space

---

## File Formats by Use Case

| Format | Use Case | Notes |
|--------|----------|-------|
| **PDF/X-1a** | Print-ready final files | Industry standard, embeds fonts, flattens transparency |
| **EPS** | Vector graphics | Legacy format, use PDF for modern workflows |
| **TIFF** | High-res images | Lossless, large files, supports CMYK + spot colors |
| **AI** | Adobe Illustrator working files | Keep layers, editability |
| **INDD** | Adobe InDesign working files | Multi-page layouts, keep live text |
| **PSD** | Adobe Photoshop working files | Keep layers, adjustments |
| **JPG** | Low-res proofs, email previews | Lossy compression, NOT for final print |
| **PNG** | Transparent graphics (web) | Not ideal for print (RGB, no CMYK support) |

### Exporting Print-Ready PDFs

**Adobe Illustrator/InDesign Settings:**
1. **Preset:** PDF/X-1a:2001 or PDF/X-4 (modern)
2. **Compatibility:** Acrobat 5.0+ (X-1a) or 7.0+ (X-4)
3. **Color:** Convert to CMYK (unless spot colors specified)
4. **Fonts:** Embed all fonts (subset OK if <100% used)
5. **Compression:** Maximum quality for images (300 DPI preserved)
6. **Marks & Bleeds:**
   - Include bleed (3mm/0.125")
   - Add crop marks (outside bleed)
   - Add color bars (if required by printer)
7. **Transparency:** Flatten (X-1a) or preserve (X-4, if printer supports)

**Checklist Before Export:**
- [ ] All images 300 DPI at 100% size
- [ ] All fonts embedded or outlined
- [ ] CMYK color mode (or spot colors documented)
- [ ] Bleed 3mm on all sides
- [ ] No content in safe area margins
- [ ] Black set to 100% K (not rich black C:40 M:40 Y:40 K:100)
- [ ] Transparency flattened or documented
- [ ] Document size = trim size + bleed

---

## Paper & Substrates

### Paper Weight (US System)

**Text Weight** (lighter, flexible)
- 60 lb / 90 gsm: Cheap flyers, newspapers
- 70 lb / 104 gsm: Standard office paper
- 80 lb / 118 gsm: Quality brochures, magazines
- 100 lb / 148 gsm: Premium brochures

**Cover Weight** (heavier, stiff)
- 80 lb / 216 gsm: Postcards, invitations
- 100 lb / 271 gsm: Business cards, covers
- 130 lb / 350 gsm: Premium business cards, box packaging

**Note:** US "lb" and metric "gsm" (grams per square meter) are different systems. Always specify both if possible.

### Paper Finish

| Finish | Description | Best For | Avoid For |
|--------|-------------|----------|-----------|
| **Gloss** | Shiny, reflective | Vibrant images, magazines, product brochures | Text-heavy (glare), fine art |
| **Matte** | Non-reflective, smooth | Photography books, elegant feel, text | When vibrance is critical |
| **Satin** | Slight sheen (between gloss/matte) | Versatile, less glare than gloss | Budget projects (costs more) |
| **Uncoated** | Natural, textured | Letterpress, writing notes, artisanal | Photo-heavy (ink absorbs, less vibrant) |

### Special Finishes

**Spot UV:** Glossy coating on specific areas (logos, accents)
- Effect: Contrast between matte + gloss
- Cost: Moderate premium
- Use: Business cards, packaging, premium brochures

**Embossing/Debossing:** Raised or recessed impression
- Effect: Tactile, premium
- Cost: Expensive (requires custom die)
- Use: Luxury branding, invitations, book covers

**Foil Stamping:** Metallic or colored foil applied with heat
- Options: Gold, silver, copper, holographic
- Cost: Expensive (custom die + foil)
- Use: Logos, luxury packaging, awards

**Die Cutting:** Custom shapes (not just rectangles)
- Cost: Expensive (custom die)
- Use: Unique business cards, packaging, POS displays

---

## Binding Methods

### Saddle Stitch
**Description:** Stapled along spine (2-3 staples)
**Page Count:** 8-64 pages (must be divisible by 4)
**Use:** Magazines, small catalogs, pamphlets
**Pros:** Cheap, lays flat when open
**Cons:** Limited page count, not very durable

### Perfect Binding
**Description:** Pages glued to spine (like paperback books)
**Page Count:** 40+ pages (minimum for spine strength)
**Use:** Books, thick catalogs, manuals
**Pros:** Professional, durable, spine can be printed
**Cons:** Doesn't lay flat, can crack over time

### Spiral/Coil Binding
**Description:** Plastic or metal coil through punched holes
**Use:** Notebooks, manuals, cookbooks
**Pros:** Lays completely flat, 360° rotation
**Cons:** Looks informal, can snag

### Case Binding (Hardcover)
**Description:** Sewn signatures glued to hard cover
**Use:** Premium books, yearbooks, art portfolios
**Pros:** Most durable, premium feel
**Cons:** Expensive, heavyweight

---

## Printing Methods

### Offset Printing (Traditional)
**Process:** Ink transferred from plate → rubber blanket → paper
**Best For:** High volume (500+ copies), highest quality
**Pros:** Excellent quality, consistent color, cost-effective at scale
**Cons:** Expensive setup (plates), slow turnaround, minimum quantities

**When to Use:**
- Large print runs (1,000+ ideal)
- Critical color matching (spot colors)
- High-quality publications (magazines, books, packaging)

### Digital Printing
**Process:** Toner or inkjet applied directly to paper (like large photocopier)
**Best For:** Low volume (1-500 copies), quick turnaround
**Pros:** No setup cost, fast, variable data (personalization)
**Cons:** Slightly lower quality than offset, color can vary between batches

**When to Use:**
- Short runs (business cards, proofs, posters)
- Quick turnaround (same-day or next-day)
- Variable data (personalized direct mail)

### Large Format (Wide Format)
**Process:** Inkjet on large rolls (banners, posters, signage)
**Sizes:** Up to 10ft+ wide
**Pros:** Huge sizes, vibrant colors
**Cons:** Lower resolution acceptable (viewed from distance)

**When to Use:**
- Banners, posters, trade show graphics
- Outdoor signage, vehicle wraps
- Retail displays, wall murals

### Screen Printing
**Process:** Ink pushed through mesh stencil
**Best For:** T-shirts, posters, textiles, flat surfaces
**Pros:** Vibrant colors, works on many materials, durable
**Cons:** Setup cost (screens), limited detail, not for photos

**When to Use:**
- Apparel (T-shirts, hoodies)
- Posters (limited colors, bold graphics)
- Specialty items (tote bags, signage)

---

## Common Print Sizes

### US Standard Sizes

| Name | Dimensions | Use |
|------|------------|-----|
| Letter | 8.5×11" | Documents, flyers |
| Legal | 8.5×14" | Legal documents |
| Tabloid (Ledger) | 11×17" | Posters, menus |
| Business Card | 3.5×2" | Business cards |

### International (ISO A Series)

| Name | mm | inches | Use |
|------|-----|--------|-----|
| A0 | 841×1189 | 33.1×46.8 | Posters, architectural plans |
| A1 | 594×841 | 23.4×33.1 | Large posters |
| A2 | 420×594 | 16.5×23.4 | Medium posters |
| A3 | 297×420 | 11.7×16.5 | Small posters, tabloid |
| A4 | 210×297 | 8.3×11.7 | Standard documents (like US Letter) |
| A5 | 148×210 | 5.8×8.3 | Booklets, notepads |
| A6 | 105×148 | 4.1×5.8 | Postcards, flyers |

**Key Property:** Each size is ½ the area of the previous (A4 → A5 = cut in half)

---

## Pre-Flight Checklist

Before sending files to printer:

**Color:**
- [ ] CMYK mode (unless RGB requested)
- [ ] Spot colors defined (if used)
- [ ] Soft-proofed on screen (View > Proof Colors)
- [ ] Rich black defined: C:40 M:40 Y:40 K:100 (not 0/0/0/100)

**Fonts:**
- [ ] All fonts embedded OR outlined
- [ ] No missing fonts warning
- [ ] Small text >6pt (or printer minimum)

**Images:**
- [ ] 300 DPI at 100% size (minimum)
- [ ] All images linked or embedded
- [ ] No missing links warning
- [ ] RGB images converted to CMYK

**Layout:**
- [ ] Bleed: 3mm (0.125") on all edges
- [ ] Safe area: 5mm from trim
- [ ] No critical content in margins
- [ ] Document size = trim + bleed

**File:**
- [ ] PDF/X-1a or PDF/X-4 format
- [ ] File name: project-name_print-ready.pdf
- [ ] Transparency flattened (or noted if preserved)
- [ ] Crop marks included (if requested)

**Proofing:**
- [ ] Print proof on laser printer (check layout)
- [ ] Soft-proof on calibrated monitor (check color)
- [ ] Request hard proof from printer (expensive but safest)

---

## Troubleshooting Common Issues

### Rich Black vs Pure Black

**Pure Black (WRONG for large areas):**
```
CMYK: 0/0/0/100 (K-only black)
Problem: Looks washed out, shows printer registration errors
```

**Rich Black (CORRECT for large backgrounds):**
```
CMYK: 40/40/40/100 (warm rich black)
OR: 60/40/40/100 (cool rich black)
Result: Deep, saturated black
```

**Text Black (CORRECT for small text):**
```
CMYK: 0/0/0/100 (K-only)
Why: Prevents registration issues (if CMYK, slight misalignment = blurry)
```

### Registration Marks

**Problem:** CMYK plates slightly misaligned (up to 0.5mm off)

**Solution:**
- Overprint black text (text knocks out background, then K prints on top)
- Avoid thin strokes in multiple colors
- Trap: Overlap colors slightly to prevent gaps

### Ink Coverage (TAC/UCR)

**Total Area Coverage (TAC):** Sum of all CMYK percentages
**Max TAC:** 280-320% (varies by printer, paper)

**Example:**
```
C:100 M:100 Y:100 K:100 = 400% TAC (TOO MUCH, will smudge/not dry)
C:60 M:40 Y:40 K:100 = 240% TAC (Safe)
```

**Solution:** Use "UCR" (Under Color Removal) in Photoshop when converting to CMYK

---

## Resources

**Color Management:**
- Pantone Color Bridge (CMYK equivalents)
- Adobe Color (color palette generator)
- X-Rite ColorMunki (monitor calibration)

**Learning:**
- *Print Design & Graphic Communication* by Michael Barnard
- *Print Production Essentials* by GATFPress
- PrintWiki.org (comprehensive print glossary)

**Printers (Get Quotes):**
- **Local:** Support local print shops, easier communication
- **Online:** Moo, Vistaprint, PrintNinja (for standard products)
- **Trade Printers:** PrintingForLess, PrintPlace (B2B, cheaper but less hand-holding)

---

**Golden Rule:** Talk to your printer BEFORE designing. Every printer has different requirements, and a 10-minute conversation can save hours of rework.
