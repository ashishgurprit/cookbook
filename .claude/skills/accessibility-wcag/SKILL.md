---
name: accessibility-wcag
description: "WCAG 2.2 AA accessibility compliance for web and mobile applications. Use when building: (1) Accessible React/TypeScript components, (2) WCAG-compliant forms and navigation, (3) Screen reader-friendly interfaces, (4) Keyboard-navigable UIs, (5) React Native accessible mobile apps, (6) Automated accessibility testing pipelines. Triggers on 'accessibility', 'a11y', 'WCAG', 'screen reader', 'keyboard navigation', 'ARIA', 'alt text', 'focus management', 'color contrast', 'assistive technology', or accessible component patterns."
license: Proprietary
---

# Accessibility & WCAG 2.2 AA Compliance

Build inclusive, accessible web and mobile applications that meet WCAG 2.2 AA standards. This skill codifies accessibility patterns from the W3C WAI, Deque Systems, the A11Y Project, and React accessibility best practices.

## Core Philosophy

**"Accessibility is not a feature. It is a prerequisite."**

Accessible development means:
- **Perceivable**: All users can perceive content (text alternatives, captions, contrast)
- **Operable**: All users can interact (keyboard, timing, seizures, navigation)
- **Understandable**: All users can comprehend (readable, predictable, input assistance)
- **Robust**: Content works with current and future assistive technologies

## Quick Reference: WCAG 2.2 AA Principles

| Principle | Key Criteria | Common Failures |
|-----------|-------------|-----------------|
| **Perceivable** | Alt text, contrast, resize, captions | Missing alt, low contrast, fixed font sizes |
| **Operable** | Keyboard, timing, navigation, input | Mouse-only interactions, no skip links |
| **Understandable** | Readable, predictable, error help | No error messages, unexpected context changes |
| **Robust** | Valid HTML, name/role/value, status | Invalid ARIA, missing form labels |

---

# Part 1: WCAG 2.2 AA Compliance Checklist

## Level A (Minimum — Must Pass)

### 1.1 Text Alternatives
- [ ] **1.1.1 Non-text Content**: All images, icons, and media have text alternatives
- [ ] Decorative images use `alt=""` or `role="presentation"`
- [ ] Complex images (charts, diagrams) have long descriptions

### 1.2 Time-based Media
- [ ] **1.2.1 Audio-only/Video-only**: Transcripts or audio descriptions provided
- [ ] **1.2.2 Captions (Prerecorded)**: Synchronized captions for all video
- [ ] **1.2.3 Audio Description**: Audio description for prerecorded video

### 1.3 Adaptable
- [ ] **1.3.1 Info and Relationships**: Semantic HTML conveys structure (headings, lists, tables, landmarks)
- [ ] **1.3.2 Meaningful Sequence**: Reading order matches visual order
- [ ] **1.3.3 Sensory Characteristics**: Instructions don't rely solely on shape, size, position, or color

### 1.4 Distinguishable
- [ ] **1.4.1 Use of Color**: Color is not the only means of conveying information
- [ ] **1.4.2 Audio Control**: Auto-playing audio can be paused or stopped

### 2.1 Keyboard Accessible
- [ ] **2.1.1 Keyboard**: All functionality available via keyboard
- [ ] **2.1.2 No Keyboard Trap**: Focus can always be moved away from any component
- [ ] **2.1.4 Character Key Shortcuts**: Single character shortcuts can be remapped or disabled (WCAG 2.1+)

### 2.2 Enough Time
- [ ] **2.2.1 Timing Adjustable**: Time limits can be extended
- [ ] **2.2.2 Pause, Stop, Hide**: Moving/blinking content can be controlled

### 2.3 Seizures and Physical Reactions
- [ ] **2.3.1 Three Flashes**: No content flashes more than 3 times per second

### 2.4 Navigable
- [ ] **2.4.1 Bypass Blocks**: Skip navigation link present
- [ ] **2.4.2 Page Titled**: Descriptive page titles
- [ ] **2.4.3 Focus Order**: Logical tab order
- [ ] **2.4.4 Link Purpose (In Context)**: Link text is descriptive

### 2.5 Input Modalities
- [ ] **2.5.1 Pointer Gestures**: Multi-point gestures have single-pointer alternatives
- [ ] **2.5.2 Pointer Cancellation**: Down-event doesn't trigger action (use click/up events)
- [ ] **2.5.4 Motion Actuation**: Motion-triggered actions have UI alternatives

### 3.1 Readable
- [ ] **3.1.1 Language of Page**: `lang` attribute on `<html>`

### 3.2 Predictable
- [ ] **3.2.1 On Focus**: No unexpected context change on focus
- [ ] **3.2.2 On Input**: No unexpected context change on input (without warning)

### 3.3 Input Assistance
- [ ] **3.3.1 Error Identification**: Errors described in text
- [ ] **3.3.2 Labels or Instructions**: Form inputs have labels

### 4.1 Compatible
- [ ] **4.1.2 Name, Role, Value**: Custom components expose correct name/role/value

## Level AA (Standard — Required for Compliance)

### 1.3 Adaptable (AA additions)
- [ ] **1.3.4 Orientation**: Content not restricted to single orientation
- [ ] **1.3.5 Identify Input Purpose**: Input fields use `autocomplete` attributes

### 1.4 Distinguishable (AA additions)
- [ ] **1.4.3 Contrast (Minimum)**: Text has 4.5:1 ratio; large text has 3:1
- [ ] **1.4.4 Resize Text**: Text resizable to 200% without loss
- [ ] **1.4.5 Images of Text**: Real text used instead of images of text
- [ ] **1.4.10 Reflow**: Content reflows at 320px width (no horizontal scroll)
- [ ] **1.4.11 Non-text Contrast**: UI components and graphics have 3:1 contrast
- [ ] **1.4.12 Text Spacing**: Content adapts to custom text spacing
- [ ] **1.4.13 Content on Hover or Focus**: Dismissible, hoverable, persistent

### 2.4 Navigable (AA additions)
- [ ] **2.4.5 Multiple Ways**: More than one way to locate pages (nav, search, sitemap)
- [ ] **2.4.6 Headings and Labels**: Descriptive headings and labels
- [ ] **2.4.7 Focus Visible**: Keyboard focus indicator is visible
- [ ] **2.4.11 Focus Not Obscured (Minimum)**: Focused element is at least partially visible (WCAG 2.2)

### 2.5 Input Modalities (AA additions)
- [ ] **2.5.7 Dragging Movements**: Drag operations have non-dragging alternatives (WCAG 2.2)
- [ ] **2.5.8 Target Size (Minimum)**: Touch targets are at least 24x24px (WCAG 2.2)

### 3.1 Readable (AA additions)
- [ ] **3.1.2 Language of Parts**: Language changes marked with `lang` attribute

### 3.2 Predictable (AA additions)
- [ ] **3.2.3 Consistent Navigation**: Navigation order is consistent
- [ ] **3.2.4 Consistent Identification**: Same functionality uses same labels

### 3.3 Input Assistance (AA additions)
- [ ] **3.3.2 Labels or Instructions**: Sufficient labels and instructions
- [ ] **3.3.3 Error Suggestion**: Error corrections suggested when known
- [ ] **3.3.4 Error Prevention (Legal/Financial)**: Submissions are reversible, verified, or confirmed
- [ ] **3.3.7 Redundant Entry**: Previously entered info is auto-populated or selectable (WCAG 2.2)
- [ ] **3.3.8 Accessible Authentication (Minimum)**: No cognitive function test for login (WCAG 2.2)

---

# Part 2: Semantic HTML Patterns

## Landmarks

Landmarks provide structural navigation for screen readers. Every page should have these:

```html
<!-- Correct landmark structure -->
<body>
  <header role="banner">
    <nav aria-label="Main navigation">
      <ul>
        <li><a href="/">Home</a></li>
        <li><a href="/about">About</a></li>
        <li><a href="/contact">Contact</a></li>
      </ul>
    </nav>
  </header>

  <main id="main-content">
    <h1>Page Title</h1>
    <!-- Primary content -->

    <section aria-labelledby="featured-heading">
      <h2 id="featured-heading">Featured Items</h2>
      <!-- Section content -->
    </section>

    <aside aria-label="Related articles">
      <!-- Complementary content -->
    </aside>
  </main>

  <footer role="contentinfo">
    <nav aria-label="Footer navigation">
      <!-- Secondary navigation -->
    </nav>
  </footer>
</body>
```

### Landmark Rules

| HTML Element | Implicit Role | When to Use |
|-------------|---------------|-------------|
| `<header>` (top-level) | `banner` | Site-wide header (once per page) |
| `<nav>` | `navigation` | Navigation blocks (label each one) |
| `<main>` | `main` | Primary content (once per page) |
| `<aside>` | `complementary` | Related but independent content |
| `<footer>` (top-level) | `contentinfo` | Site-wide footer (once per page) |
| `<section>` | `region` (if labeled) | Thematic grouping (must have accessible name) |
| `<form>` | `form` (if labeled) | Form regions |

## Heading Hierarchy

```tsx
// ✅ CORRECT: Logical heading hierarchy
function ProductPage() {
  return (
    <main>
      <h1>Running Shoes</h1>                    {/* Page title */}

      <section aria-labelledby="mens-heading">
        <h2 id="mens-heading">Men's Shoes</h2>  {/* Section */}

        <article>
          <h3>Trail Runner Pro</h3>              {/* Subsection */}
          <h4>Specifications</h4>                {/* Sub-subsection */}
          <h4>Reviews</h4>
        </article>
      </section>

      <section aria-labelledby="womens-heading">
        <h2 id="womens-heading">Women's Shoes</h2>
      </section>
    </main>
  );
}

// ❌ WRONG: Skipping heading levels
function BadPage() {
  return (
    <main>
      <h1>Products</h1>
      <h3>Category</h3>    {/* Skipped h2! */}
      <h5>Subcategory</h5>  {/* Skipped h4! */}
    </main>
  );
}
```

## Accessible Tables

```tsx
function DataTable({ data }: { data: SalesData[] }) {
  return (
    <table>
      <caption>Quarterly Sales Report, 2024</caption>
      <thead>
        <tr>
          <th scope="col">Quarter</th>
          <th scope="col">Revenue</th>
          <th scope="col">Growth</th>
        </tr>
      </thead>
      <tbody>
        {data.map((row) => (
          <tr key={row.quarter}>
            <th scope="row">{row.quarter}</th>
            <td>{formatCurrency(row.revenue)}</td>
            <td>
              <span
                aria-label={`${row.growth > 0 ? 'Increased' : 'Decreased'} by ${Math.abs(row.growth)}%`}
              >
                {row.growth > 0 ? '+' : ''}{row.growth}%
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
```

## Accessible Lists

```tsx
// ✅ Use semantic lists for related items
function FeatureList({ features }: { features: Feature[] }) {
  return (
    <section aria-labelledby="features-heading">
      <h2 id="features-heading">Key Features</h2>
      <ul>
        {features.map((feature) => (
          <li key={feature.id}>
            <strong>{feature.name}:</strong> {feature.description}
          </li>
        ))}
      </ul>
    </section>
  );
}

// ✅ Use <dl> for key-value pairs
function ProductSpecs({ specs }: { specs: Record<string, string> }) {
  return (
    <dl>
      {Object.entries(specs).map(([key, value]) => (
        <div key={key}>
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
```

---

# Part 3: ARIA Roles, States, and Properties

## The First Rule of ARIA

**"No ARIA is better than bad ARIA."** — W3C WAI

Use native HTML elements whenever possible. ARIA is a last resort for custom widgets.

```tsx
// ❌ BAD: Using ARIA when native HTML works
<div role="button" tabIndex={0} onClick={handleClick} onKeyDown={handleKeyDown}>
  Submit
</div>

// ✅ GOOD: Use native HTML
<button onClick={handleClick}>Submit</button>

// ❌ BAD: Redundant ARIA
<nav role="navigation">      {/* <nav> already has navigation role */}
<button role="button">Click</button>  {/* <button> already has button role */}

// ✅ GOOD: No redundant roles
<nav aria-label="Primary">
<button>Click</button>
```

## When ARIA IS Needed

### Custom Widgets

```tsx
// Accordion pattern — no native HTML equivalent
function Accordion({ items }: { items: AccordionItem[] }) {
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  return (
    <div>
      {items.map((item, index) => {
        const isOpen = openIndex === index;
        const headingId = `accordion-heading-${index}`;
        const panelId = `accordion-panel-${index}`;

        return (
          <div key={item.id}>
            <h3>
              <button
                id={headingId}
                aria-expanded={isOpen}
                aria-controls={panelId}
                onClick={() => setOpenIndex(isOpen ? null : index)}
              >
                {item.title}
                <span aria-hidden="true">{isOpen ? '−' : '+'}</span>
              </button>
            </h3>
            <div
              id={panelId}
              role="region"
              aria-labelledby={headingId}
              hidden={!isOpen}
            >
              {item.content}
            </div>
          </div>
        );
      })}
    </div>
  );
}
```

### Tabs Pattern

```tsx
function Tabs({ tabs }: { tabs: TabData[] }) {
  const [activeIndex, setActiveIndex] = useState(0);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const handleKeyDown = (e: React.KeyboardEvent, index: number) => {
    let newIndex = index;

    switch (e.key) {
      case 'ArrowRight':
        newIndex = (index + 1) % tabs.length;
        break;
      case 'ArrowLeft':
        newIndex = (index - 1 + tabs.length) % tabs.length;
        break;
      case 'Home':
        newIndex = 0;
        break;
      case 'End':
        newIndex = tabs.length - 1;
        break;
      default:
        return;
    }

    e.preventDefault();
    setActiveIndex(newIndex);
    tabRefs.current[newIndex]?.focus();
  };

  return (
    <div>
      <div role="tablist" aria-label="Content tabs">
        {tabs.map((tab, index) => (
          <button
            key={tab.id}
            ref={(el) => { tabRefs.current[index] = el; }}
            role="tab"
            id={`tab-${tab.id}`}
            aria-selected={activeIndex === index}
            aria-controls={`panel-${tab.id}`}
            tabIndex={activeIndex === index ? 0 : -1}
            onClick={() => setActiveIndex(index)}
            onKeyDown={(e) => handleKeyDown(e, index)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {tabs.map((tab, index) => (
        <div
          key={tab.id}
          role="tabpanel"
          id={`panel-${tab.id}`}
          aria-labelledby={`tab-${tab.id}`}
          hidden={activeIndex !== index}
          tabIndex={0}
        >
          {tab.content}
        </div>
      ))}
    </div>
  );
}
```

### Live Regions (Dynamic Content Updates)

```tsx
// Announce dynamic updates to screen readers
function SearchResults({ results, isLoading }: SearchResultsProps) {
  return (
    <div>
      {/* Polite: Announced after current speech finishes */}
      <div aria-live="polite" aria-atomic="true" className="sr-only">
        {isLoading
          ? 'Loading search results...'
          : `${results.length} results found`
        }
      </div>

      {/* Assertive: Interrupts current speech — use sparingly */}
      <div aria-live="assertive" aria-atomic="true" className="sr-only">
        {/* Only for critical alerts like errors */}
      </div>

      <ul aria-label="Search results">
        {results.map((result) => (
          <li key={result.id}>{result.title}</li>
        ))}
      </ul>
    </div>
  );
}

// Toast/notification system with aria-live
function ToastContainer({ toasts }: { toasts: Toast[] }) {
  return (
    <div
      aria-live="polite"
      aria-relevant="additions"
      className="toast-container"
    >
      {toasts.map((toast) => (
        <div
          key={toast.id}
          role={toast.type === 'error' ? 'alert' : 'status'}
          className={`toast toast--${toast.type}`}
        >
          <p>{toast.message}</p>
          <button
            onClick={() => dismissToast(toast.id)}
            aria-label={`Dismiss: ${toast.message}`}
          >
            Close
          </button>
        </div>
      ))}
    </div>
  );
}
```

## ARIA States and Properties Reference

| Attribute | Purpose | Example |
|-----------|---------|---------|
| `aria-expanded` | Toggle open/closed state | Accordions, dropdowns, menus |
| `aria-selected` | Selected item in set | Tabs, listboxes |
| `aria-checked` | Checked state | Custom checkboxes, switches |
| `aria-disabled` | Disabled state | Prefer native `disabled` attribute |
| `aria-hidden="true"` | Hide from assistive technology | Decorative icons, duplicated content |
| `aria-label` | Accessible name (no visible label) | Icon buttons, unlabeled inputs |
| `aria-labelledby` | Reference visible label element | Sections, dialogs, regions |
| `aria-describedby` | Additional description | Error messages, help text |
| `aria-controls` | Element this controls | Tabs, accordions, comboboxes |
| `aria-live` | Dynamic content region | Search results, notifications |
| `aria-atomic` | Announce entire region or changes | Status messages |
| `aria-current` | Current item in set | Current page, date, step |
| `aria-invalid` | Invalid form input | Form validation |
| `aria-required` | Required field | Prefer native `required` attribute |
| `aria-busy` | Region is updating | Loading states |
| `aria-errormessage` | Points to error message element | Form field errors |

## Common ARIA Anti-Patterns

```tsx
// ❌ NEVER: role="presentation" or aria-hidden on focusable elements
<button aria-hidden="true">Click me</button>
<a href="/page" role="presentation">Link</a>

// ❌ NEVER: Conflicting roles
<input type="checkbox" role="switch" />  // Use one or the other

// ❌ NEVER: aria-label on non-interactive <div> or <span>
<div aria-label="Important text">...</div>  // Screen readers may ignore this

// ❌ NEVER: Changing roles dynamically
<div role={isButton ? 'button' : 'link'}>  // Confuses assistive tech

// ✅ ALWAYS: Keep ARIA states in sync with visual state
<button
  aria-expanded={isOpen}  // Must match visual open/closed state
  aria-controls="menu"
>
  Menu
</button>
```

---

# Part 4: Keyboard Navigation

## Focus Management Fundamentals

### Tab Order

```tsx
// ✅ Natural tab order follows DOM order — arrange elements logically
<form>
  <label htmlFor="name">Name</label>
  <input id="name" type="text" />          {/* Tab stop 1 */}

  <label htmlFor="email">Email</label>
  <input id="email" type="email" />        {/* Tab stop 2 */}

  <button type="submit">Submit</button>     {/* Tab stop 3 */}
</form>

// ❌ AVOID: Positive tabindex values — they override natural order
<input tabIndex={3} />  // Don't do this
<input tabIndex={1} />  // Creates confusing order
<input tabIndex={2} />  // Maintenance nightmare

// ✅ ONLY use tabIndex={0} (add to tab order) or tabIndex={-1} (programmatic focus)
<div tabIndex={0}>Focusable div (only when no native element works)</div>
<div tabIndex={-1} ref={errorRef}>Error region (focused via JavaScript)</div>
```

### Skip Links

```tsx
// Skip link — must be the first focusable element
function SkipLink() {
  return (
    <a
      href="#main-content"
      className="skip-link"
    >
      Skip to main content
    </a>
  );
}

// CSS for skip link
// .skip-link {
//   position: absolute;
//   top: -40px;
//   left: 0;
//   background: #000;
//   color: #fff;
//   padding: 8px 16px;
//   z-index: 100;
//   transition: top 0.2s;
// }
// .skip-link:focus {
//   top: 0;
// }

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <SkipLink />
      <header>
        <nav aria-label="Main navigation">{/* ... */}</nav>
      </header>
      <main id="main-content" tabIndex={-1}>
        {children}
      </main>
    </>
  );
}
```

### Focus Trap for Modals

```tsx
import { useEffect, useRef, useCallback } from 'react';

function useFocusTrap(isActive: boolean) {
  const containerRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  const getFocusableElements = useCallback(() => {
    if (!containerRef.current) return [];
    const selector = [
      'a[href]',
      'button:not([disabled])',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      '[tabindex]:not([tabindex="-1"])',
    ].join(', ');
    return Array.from(
      containerRef.current.querySelectorAll<HTMLElement>(selector)
    );
  }, []);

  useEffect(() => {
    if (!isActive) return;

    // Store previous focus to restore later
    previousFocusRef.current = document.activeElement as HTMLElement;

    // Focus the first focusable element in the trap
    const focusableElements = getFocusableElements();
    if (focusableElements.length > 0) {
      focusableElements[0].focus();
    }

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;

      const focusable = getFocusableElements();
      if (focusable.length === 0) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];

      if (e.shiftKey) {
        // Shift+Tab: wrap from first to last
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        // Tab: wrap from last to first
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      // Restore focus when trap deactivates
      previousFocusRef.current?.focus();
    };
  }, [isActive, getFocusableElements]);

  return containerRef;
}

// Usage in a modal
function Modal({ isOpen, onClose, title, children }: ModalProps) {
  const focusTrapRef = useFocusTrap(isOpen);

  useEffect(() => {
    if (!isOpen) return;
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={focusTrapRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        <h2 id="modal-title">{title}</h2>
        {children}
        <button onClick={onClose} aria-label="Close dialog">
          Close
        </button>
      </div>
    </div>
  );
}
```

### Route Change Focus Management (SPA)

```tsx
import { useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';

function useFocusOnRouteChange() {
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);
  const isFirstRender = useRef(true);

  useEffect(() => {
    // Don't steal focus on initial page load
    if (isFirstRender.current) {
      isFirstRender.current = false;
      return;
    }

    // Focus the main content area on route change
    if (mainRef.current) {
      mainRef.current.focus();
    }

    // Update document title
    document.title = getPageTitle(location.pathname);
  }, [location.pathname]);

  return mainRef;
}

function App() {
  const mainRef = useFocusOnRouteChange();

  return (
    <>
      <SkipLink />
      <Header />
      <main ref={mainRef} id="main-content" tabIndex={-1}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/about" element={<About />} />
        </Routes>
      </main>
      <Footer />
    </>
  );
}
```

### Keyboard Interaction Patterns

| Widget | Key | Action |
|--------|-----|--------|
| **Button** | `Enter`, `Space` | Activate |
| **Link** | `Enter` | Follow link |
| **Checkbox** | `Space` | Toggle |
| **Radio** | `Arrow keys` | Move selection |
| **Tab list** | `Arrow Left/Right` | Switch tab |
| **Menu** | `Arrow Up/Down` | Navigate items |
| **Menu** | `Escape` | Close menu |
| **Dialog** | `Escape` | Close dialog |
| **Combobox** | `Arrow Down` | Open/navigate options |
| **Tree** | `Arrow Right` | Expand node |
| **Tree** | `Arrow Left` | Collapse node |

---

# Part 5: Screen Reader Testing Workflow

## Testing Checklist

Before release, every page must pass:

1. [ ] All content is announced in logical order
2. [ ] All interactive elements are identifiable (role + name)
3. [ ] Form fields have associated labels
4. [ ] Error messages are announced
5. [ ] Dynamic content updates are announced via aria-live
6. [ ] Navigation landmarks are present and labeled
7. [ ] Heading structure is logical and complete
8. [ ] Images have appropriate alt text
9. [ ] Links and buttons have descriptive text

## VoiceOver (macOS/iOS)

### Keyboard Shortcuts (macOS)

| Shortcut | Action |
|----------|--------|
| `Cmd + F5` | Toggle VoiceOver on/off |
| `VO + Right Arrow` | Move to next element |
| `VO + Left Arrow` | Move to previous element |
| `VO + Space` | Activate element |
| `VO + U` | Open rotor (landmark/heading navigator) |
| `VO + Cmd + H` | Next heading |
| `VO + Cmd + J` | Next form control |
| `VO + Cmd + L` | Next link |
| `VO + Cmd + T` | Next table |

(`VO` = Control + Option)

### VoiceOver Testing Script

```
1. Enable VoiceOver (Cmd + F5)
2. Navigate to page
3. Open Rotor (VO + U):
   - Check Landmarks: banner, navigation, main, contentinfo
   - Check Headings: h1 -> h2 -> h3 in order
   - Check Links: all descriptive (no "click here")
   - Check Form Controls: all labeled
4. Tab through all interactive elements:
   - Every element announces role + name
   - Focus indicator is visible
5. Test forms:
   - Labels read on focus
   - Required fields announced
   - Errors announced on submit
6. Test dynamic content:
   - Notifications/toasts announced
   - Search results count announced
   - Loading states announced
```

## NVDA (Windows — Free)

### Key Shortcuts

| Shortcut | Action |
|----------|--------|
| `Insert + Space` | Toggle browse/focus mode |
| `H` | Next heading |
| `D` | Next landmark |
| `F` | Next form field |
| `K` | Next link |
| `T` | Next table |
| `Insert + F7` | Elements list (links, headings, landmarks) |
| `Insert + F5` | Elements list (form fields) |

### NVDA Testing Script

```
1. Install NVDA (free: nvaccess.org)
2. Open browser, navigate to page
3. Enter browse mode (Insert + Space if in focus mode)
4. Navigate headings (H key) — verify hierarchy
5. Navigate landmarks (D key) — verify completeness
6. Navigate form fields (F key) — verify labels
7. Tab through interactive elements — verify announcements
8. Test forms: submit with errors, verify error announcement
9. Test dynamic content: verify aria-live announcements
```

## JAWS (Windows — Commercial)

### Key Differences from NVDA

| Feature | JAWS | NVDA |
|---------|------|------|
| Cost | Commercial ($1000+/yr) | Free |
| Virtual cursor key | `Insert` | `Insert` |
| Mode toggle | `Insert + Z` | `Insert + Space` |
| Verbosity | Very detailed | Moderate |

### Cross-Screen-Reader Compatibility Issues

```tsx
// These patterns work consistently across all screen readers:

// 1. visually-hidden text (prefer over aria-label for complex text)
const srOnlyStyles: React.CSSProperties = {
  position: 'absolute',
  width: '1px',
  height: '1px',
  padding: 0,
  margin: '-1px',
  overflow: 'hidden',
  clip: 'rect(0, 0, 0, 0)',
  whiteSpace: 'nowrap',
  border: 0,
};

function VisuallyHidden({ children }: { children: React.ReactNode }) {
  return <span style={srOnlyStyles}>{children}</span>;
}

// Usage
<button>
  <TrashIcon aria-hidden="true" />
  <VisuallyHidden>Delete item: {itemName}</VisuallyHidden>
</button>

// 2. aria-live region — placed BEFORE dynamic content, always in DOM
// ✅ GOOD: Region exists on mount, content changes
function LiveAnnouncer() {
  const [message, setMessage] = useState('');

  return (
    <div
      aria-live="polite"
      aria-atomic="true"
      style={srOnlyStyles}
    >
      {message}
    </div>
  );
}

// ❌ BAD: Conditionally rendering the live region
{showMessage && <div aria-live="polite">{message}</div>}
// Screen readers may not detect it if the region didn't exist before
```

---

# Part 6: Color Contrast

## WCAG 2.2 AA Contrast Requirements

| Content Type | Minimum Ratio | Example |
|-------------|---------------|---------|
| Normal text (< 18pt / 14pt bold) | **4.5:1** | Body copy, labels, links |
| Large text (>= 18pt / 14pt bold) | **3:1** | Headings, large UI text |
| UI components & graphics | **3:1** | Borders, icons, focus rings |
| Disabled elements | No requirement | Grayed-out buttons |
| Logos/decoration | No requirement | Brand logos |

### What Counts as "Large Text"?

- Regular weight: 24px (18pt) or larger
- Bold weight (700+): 18.66px (14pt) or larger

## Contrast Checking Tools

### In-Browser

```bash
# Chrome DevTools
# 1. Right-click element -> Inspect
# 2. Click color swatch in Styles panel
# 3. See "Contrast ratio" section — shows AA/AAA pass/fail

# Firefox Accessibility Inspector
# 1. DevTools -> Accessibility tab
# 2. Enable "Check for issues" -> "Contrast"
# 3. Highlights all failing elements
```

### Automated CLI Tools

```bash
# Using pa11y for contrast checks
npx pa11y --reporter=cli https://your-site.com

# Using axe-core via CLI
npx @axe-core/cli https://your-site.com --rules color-contrast

# Lighthouse accessibility audit
npx lighthouse https://your-site.com --only-categories=accessibility --output=json
```

### Programmatic Contrast Checking

```typescript
// Utility to calculate contrast ratio
function getLuminance(r: number, g: number, b: number): number {
  const [rs, gs, bs] = [r, g, b].map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
}

function getContrastRatio(
  fg: [number, number, number],
  bg: [number, number, number]
): number {
  const l1 = getLuminance(...fg);
  const l2 = getLuminance(...bg);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

function meetsWCAG(
  fg: [number, number, number],
  bg: [number, number, number],
  level: 'AA' | 'AAA' = 'AA',
  isLargeText: boolean = false
): boolean {
  const ratio = getContrastRatio(fg, bg);
  if (level === 'AA') {
    return isLargeText ? ratio >= 3 : ratio >= 4.5;
  }
  return isLargeText ? ratio >= 4.5 : ratio >= 7;
}

// Usage
const white: [number, number, number] = [255, 255, 255];
const brandBlue: [number, number, number] = [0, 102, 204];
console.log(getContrastRatio(white, brandBlue)); // 4.68 — passes AA for normal text
```

## Accessible Color Palette Design

```tsx
// Design tokens with contrast-safe pairs
const colorTokens = {
  // Each token documents its contrast ratio against its typical background
  text: {
    primary: '#1a1a2e',      // 15.4:1 on white — passes AAA
    secondary: '#4a4a6a',    // 7.2:1 on white — passes AAA
    tertiary: '#6b6b8a',     // 4.6:1 on white — passes AA only
    inverse: '#ffffff',      // Use on dark backgrounds
    error: '#c41e3a',        // 5.9:1 on white — passes AA
    success: '#0d6e3f',      // 5.6:1 on white — passes AA
    link: '#0052a3',         // 7.1:1 on white — passes AAA
  },
  background: {
    primary: '#ffffff',
    secondary: '#f5f5f7',
    tertiary: '#e8e8ed',
  },
  border: {
    default: '#6b6b8a',      // 4.6:1 on white — passes 3:1 for non-text
    focus: '#0052a3',        // High contrast focus ring
  },
} as const;

// Focus ring that always meets 3:1 contrast
const focusRingStyles = `
  outline: 3px solid ${colorTokens.border.focus};
  outline-offset: 2px;
`;

// Never rely on color alone — pair with icons or text
function StatusBadge({ status }: { status: 'success' | 'warning' | 'error' }) {
  const config = {
    success: { color: '#0d6e3f', bg: '#e6f4ed', icon: '✓', label: 'Success' },
    warning: { color: '#7a5900', bg: '#fef3cd', icon: '⚠', label: 'Warning' },
    error:   { color: '#c41e3a', bg: '#fde8ec', icon: '✕', label: 'Error' },
  };

  const { color, bg, icon, label } = config[status];

  return (
    <span
      style={{ color, backgroundColor: bg, padding: '2px 8px', borderRadius: '4px' }}
      role="status"
    >
      <span aria-hidden="true">{icon} </span>
      {label}
    </span>
  );
}
```

---

# Part 7: Form Accessibility

## Labels and Inputs

```tsx
import { useId } from 'react';

// ✅ Pattern 1: Explicit label association with useId
function TextInput({ label, required, error, helpText, ...props }: TextInputProps) {
  const id = useId();
  const errorId = `${id}-error`;
  const helpId = `${id}-help`;

  return (
    <div>
      <label htmlFor={id}>
        {label}
        {required && <span aria-hidden="true"> *</span>}
        {required && <span className="sr-only"> (required)</span>}
      </label>

      {helpText && (
        <p id={helpId} className="help-text">
          {helpText}
        </p>
      )}

      <input
        id={id}
        aria-required={required}
        aria-invalid={!!error}
        aria-describedby={[
          error ? errorId : null,
          helpText ? helpId : null,
        ].filter(Boolean).join(' ') || undefined}
        aria-errormessage={error ? errorId : undefined}
        {...props}
      />

      {error && (
        <p id={errorId} role="alert" className="error-text">
          {error}
        </p>
      )}
    </div>
  );
}

// ✅ Pattern 2: Grouped fields with fieldset/legend
function AddressForm() {
  return (
    <fieldset>
      <legend>Shipping Address</legend>

      <TextInput label="Street Address" name="street" required autoComplete="street-address" />
      <TextInput label="City" name="city" required autoComplete="address-level2" />
      <TextInput label="State" name="state" required autoComplete="address-level1" />
      <TextInput label="ZIP Code" name="zip" required autoComplete="postal-code" />
      <TextInput label="Country" name="country" required autoComplete="country-name" />
    </fieldset>
  );
}
```

## Autocomplete Attributes

```tsx
// WCAG 1.3.5 requires autocomplete on common input types
const autocompleteMap: Record<string, string> = {
  'full-name': 'name',
  'first-name': 'given-name',
  'last-name': 'family-name',
  'email': 'email',
  'phone': 'tel',
  'street': 'street-address',
  'city': 'address-level2',
  'state': 'address-level1',
  'zip': 'postal-code',
  'country': 'country-name',
  'cc-number': 'cc-number',
  'cc-name': 'cc-name',
  'cc-exp': 'cc-exp',
  'cc-csc': 'cc-csc',
  'username': 'username',
  'new-password': 'new-password',
  'current-password': 'current-password',
  'birthday': 'bday',
};
```

## Error Handling

```tsx
// Accessible form with comprehensive error handling
function RegistrationForm() {
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitted, setSubmitted] = useState(false);
  const errorSummaryRef = useRef<HTMLDivElement>(null);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const newErrors = validateForm(formData);

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      // Focus the error summary for screen readers
      errorSummaryRef.current?.focus();
      return;
    }

    // Submit form...
    setSubmitted(true);
  };

  return (
    <form onSubmit={handleSubmit} noValidate>
      {/* Error summary — appears at the top, focused on validation failure */}
      {Object.keys(errors).length > 0 && (
        <div
          ref={errorSummaryRef}
          role="alert"
          tabIndex={-1}
          className="error-summary"
        >
          <h2>There are {Object.keys(errors).length} errors in this form</h2>
          <ul>
            {Object.entries(errors).map(([field, message]) => (
              <li key={field}>
                <a href={`#${field}`}>{message}</a>
              </li>
            ))}
          </ul>
        </div>
      )}

      <TextInput
        label="Email"
        name="email"
        type="email"
        required
        autoComplete="email"
        error={errors.email}
      />

      <TextInput
        label="Password"
        name="password"
        type="password"
        required
        autoComplete="new-password"
        error={errors.password}
        helpText="Must be at least 8 characters with one uppercase, one number"
      />

      <button type="submit">Create Account</button>

      {/* Success confirmation */}
      {submitted && (
        <div role="status" aria-live="polite">
          Account created successfully. Redirecting...
        </div>
      )}
    </form>
  );
}
```

## Radio and Checkbox Groups

```tsx
function RadioGroup({
  legend,
  name,
  options,
  value,
  onChange,
  error,
  required,
}: RadioGroupProps) {
  const groupId = useId();
  const errorId = `${groupId}-error`;

  return (
    <fieldset
      aria-required={required}
      aria-invalid={!!error}
      aria-errormessage={error ? errorId : undefined}
    >
      <legend>
        {legend}
        {required && <span aria-hidden="true"> *</span>}
      </legend>

      {options.map((option) => {
        const optionId = `${groupId}-${option.value}`;
        return (
          <div key={option.value}>
            <input
              type="radio"
              id={optionId}
              name={name}
              value={option.value}
              checked={value === option.value}
              onChange={(e) => onChange(e.target.value)}
            />
            <label htmlFor={optionId}>
              {option.label}
              {option.description && (
                <span className="option-description">{option.description}</span>
              )}
            </label>
          </div>
        );
      })}

      {error && (
        <p id={errorId} role="alert" className="error-text">
          {error}
        </p>
      )}
    </fieldset>
  );
}
```

## Accessible Combobox (Autocomplete/Select)

```tsx
function Combobox({ label, options, value, onChange }: ComboboxProps) {
  const id = useId();
  const listboxId = `${id}-listbox`;
  const [isOpen, setIsOpen] = useState(false);
  const [filter, setFilter] = useState('');
  const [activeIndex, setActiveIndex] = useState(-1);
  const inputRef = useRef<HTMLInputElement>(null);

  const filteredOptions = options.filter((opt) =>
    opt.label.toLowerCase().includes(filter.toLowerCase())
  );

  const handleKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setIsOpen(true);
        setActiveIndex((prev) => Math.min(prev + 1, filteredOptions.length - 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setActiveIndex((prev) => Math.max(prev - 1, 0));
        break;
      case 'Enter':
        e.preventDefault();
        if (activeIndex >= 0 && filteredOptions[activeIndex]) {
          onChange(filteredOptions[activeIndex].value);
          setFilter(filteredOptions[activeIndex].label);
          setIsOpen(false);
        }
        break;
      case 'Escape':
        setIsOpen(false);
        inputRef.current?.focus();
        break;
    }
  };

  return (
    <div>
      <label htmlFor={id}>{label}</label>
      <input
        ref={inputRef}
        id={id}
        role="combobox"
        aria-expanded={isOpen}
        aria-controls={listboxId}
        aria-autocomplete="list"
        aria-activedescendant={
          activeIndex >= 0 ? `${id}-option-${activeIndex}` : undefined
        }
        value={filter}
        onChange={(e) => {
          setFilter(e.target.value);
          setIsOpen(true);
          setActiveIndex(-1);
        }}
        onKeyDown={handleKeyDown}
        onFocus={() => setIsOpen(true)}
        onBlur={() => setTimeout(() => setIsOpen(false), 200)}
      />

      {isOpen && filteredOptions.length > 0 && (
        <ul id={listboxId} role="listbox" aria-label={label}>
          {filteredOptions.map((option, index) => (
            <li
              key={option.value}
              id={`${id}-option-${index}`}
              role="option"
              aria-selected={index === activeIndex}
              onClick={() => {
                onChange(option.value);
                setFilter(option.label);
                setIsOpen(false);
              }}
            >
              {option.label}
            </li>
          ))}
        </ul>
      )}

      {isOpen && filteredOptions.length === 0 && (
        <div role="status" aria-live="polite">
          No matching options found
        </div>
      )}
    </div>
  );
}
```

---

# Part 8: Image Accessibility

## Alt Text Decision Tree

```
Is the image purely decorative?
├── YES → alt="" (empty string, NOT missing alt)
│
└── NO → Does the image contain text?
    ├── YES → alt text = the text in the image
    │
    └── NO → Is it a functional image (link, button)?
        ├── YES → alt text = the action it performs
        │         Example: alt="Search" for a search icon button
        │
        └── NO → Is it informational?
            ├── YES → alt text = the information it conveys
            │         Example: alt="Bar chart showing Q4 revenue of $2.3M, up 15% from Q3"
            │
            └── Is it a complex image (chart, diagram, map)?
                ├── YES → Short alt + long description
                │         Use aria-describedby pointing to a detailed text description
                │
                └── NO → Describe what the image shows concisely
                          Example: alt="Golden retriever playing fetch in a park"
```

## Implementation Patterns

```tsx
// 1. Decorative image — ignored by screen readers
<img src="/hero-bg.jpg" alt="" role="presentation" />

// 2. Informative image — describes content
<img
  src="/team-photo.jpg"
  alt="Our engineering team of 12 people at the 2024 company retreat"
/>

// 3. Functional image — describes action
<a href="/search">
  <img src="/search-icon.svg" alt="Search" />
</a>

// Better: Use a button with accessible name
<button aria-label="Search">
  <SearchIcon aria-hidden="true" />
</button>

// 4. Complex image — short alt + long description
<figure>
  <img
    src="/quarterly-revenue-chart.png"
    alt="Quarterly revenue chart showing upward trend"
    aria-describedby="chart-description"
  />
  <figcaption id="chart-description">
    Revenue by quarter: Q1 $1.2M, Q2 $1.5M, Q3 $2.0M, Q4 $2.3M.
    Year-over-year growth of 42%. Q4 showed the strongest performance
    driven by holiday sales.
  </figcaption>
</figure>

// 5. SVG accessibility
<svg role="img" aria-labelledby="svg-title svg-desc">
  <title id="svg-title">Monthly Active Users</title>
  <desc id="svg-desc">
    Line graph showing monthly active users growing from 10,000 in
    January to 45,000 in December 2024.
  </desc>
  {/* SVG paths */}
</svg>

// 6. Decorative SVG icon alongside text
<button>
  <svg aria-hidden="true" focusable="false">
    {/* icon paths */}
  </svg>
  Save Document
</button>

// 7. Icon-only button (no visible text)
<button aria-label="Close dialog">
  <svg aria-hidden="true" focusable="false">
    {/* X icon paths */}
  </svg>
</button>
```

## Common Alt Text Mistakes

```tsx
// ❌ BAD: Filename as alt text
<img src="/IMG_2847.jpg" alt="IMG_2847.jpg" />

// ❌ BAD: "Image of..." prefix (screen readers already announce "image")
<img src="/dog.jpg" alt="Image of a dog" />

// ✅ GOOD: Concise, descriptive
<img src="/dog.jpg" alt="Golden retriever playing fetch" />

// ❌ BAD: Alt text too long (> 125 characters)
<img alt="This is a photograph of our company's main office building which is located at 123 Main Street in downtown San Francisco and was built in 2019 by the famous architect..." />

// ✅ GOOD: Concise, with long description for complex images
<img
  alt="Company headquarters in San Francisco"
  aria-describedby="building-details"
/>

// ❌ BAD: Missing alt attribute entirely (screen reader reads filename)
<img src="/photo.jpg" />

// ❌ BAD: Redundant alt text when caption exists
<figure>
  <img alt="Team photo at retreat" />
  <figcaption>Team photo at retreat</figcaption>  {/* Duplicated! */}
</figure>

// ✅ GOOD: Alt and caption complement each other
<figure>
  <img alt="Twelve team members standing on a mountain overlook" />
  <figcaption>Annual retreat, Blue Ridge Mountains, October 2024</figcaption>
</figure>
```

---

# Part 9: Automated Accessibility Testing

## axe-core Integration

### Jest + React Testing Library

```bash
npm install --save-dev @axe-core/react jest-axe @testing-library/react
```

```typescript
// setupTests.ts
import 'jest-axe/extend-expect';

// Component test with a11y
import { render } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';

expect.extend(toHaveNoViolations);

describe('Button', () => {
  it('should have no accessibility violations', async () => {
    const { container } = render(
      <Button onClick={() => {}}>Click me</Button>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('should have no violations when disabled', async () => {
    const { container } = render(
      <Button onClick={() => {}} disabled>
        Click me
      </Button>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});

// Form test with a11y
describe('LoginForm', () => {
  it('should have no accessibility violations', async () => {
    const { container } = render(<LoginForm onSubmit={() => {}} />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('should have no violations with errors displayed', async () => {
    const { container, getByRole } = render(
      <LoginForm onSubmit={() => {}} />
    );
    // Trigger validation
    fireEvent.click(getByRole('button', { name: /submit/i }));
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
```

### Vitest Integration

```typescript
// vitest.setup.ts
import 'vitest-axe/extend-expect';
import { configDefaults } from 'vitest/config';

// a11y test helper
import { axe } from 'vitest-axe';
import { render } from '@testing-library/react';

export async function expectNoA11yViolations(ui: React.ReactElement) {
  const { container } = render(ui);
  const results = await axe(container);
  expect(results).toHaveNoViolations();
  return results;
}

// Usage in tests
import { expectNoA11yViolations } from '../vitest.setup';

test('Card has no a11y violations', async () => {
  await expectNoA11yViolations(
    <Card title="Test" description="Description" />
  );
});
```

## Playwright Accessibility Testing

```typescript
// playwright.config.ts
import { defineConfig } from '@playwright/test';

export default defineConfig({
  use: {
    // Enable accessibility testing
  },
  projects: [
    {
      name: 'accessibility',
      testMatch: /.*\.a11y\.spec\.ts/,
    },
  ],
});

// tests/homepage.a11y.spec.ts
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Homepage accessibility', () => {
  test('should not have any automatically detectable violations', async ({
    page,
  }) => {
    await page.goto('/');

    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag22aa'])
      .analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('should not have violations on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/');

    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze();

    expect(results.violations).toEqual([]);
  });

  test('should not have violations after user interaction', async ({
    page,
  }) => {
    await page.goto('/');

    // Open a modal
    await page.getByRole('button', { name: 'Open settings' }).click();
    await page.waitForSelector('[role="dialog"]');

    // Scan only the modal
    const results = await new AxeBuilder({ page })
      .include('[role="dialog"]')
      .analyze();

    expect(results.violations).toEqual([]);
  });

  test('should have correct focus management in modal', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Open settings' }).click();

    // Focus should be inside the modal
    const focusedElement = await page.evaluate(() =>
      document.activeElement?.closest('[role="dialog"]') !== null
    );
    expect(focusedElement).toBe(true);

    // Escape should close the modal
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).not.toBeVisible();

    // Focus should return to the trigger button
    const focusedAfterClose = await page.evaluate(() =>
      document.activeElement?.textContent
    );
    expect(focusedAfterClose).toContain('Open settings');
  });
});
```

## pa11y CI Integration

```bash
npm install --save-dev pa11y pa11y-ci
```

```json
// .pa11yci.json
{
  "defaults": {
    "standard": "WCAG2AA",
    "timeout": 30000,
    "wait": 1000,
    "chromeLaunchConfig": {
      "args": ["--no-sandbox"]
    },
    "runners": ["axe", "htmlcs"]
  },
  "urls": [
    "http://localhost:3000/",
    "http://localhost:3000/login",
    "http://localhost:3000/dashboard",
    {
      "url": "http://localhost:3000/settings",
      "actions": [
        "click element #tab-profile",
        "wait for element #profile-form to be visible"
      ]
    }
  ]
}
```

```yaml
# GitHub Actions workflow
name: Accessibility Tests
on: [push, pull_request]

jobs:
  a11y:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - run: npm ci
      - run: npm run build

      - name: Start server
        run: npm run preview &
        env:
          PORT: 3000

      - name: Wait for server
        run: npx wait-on http://localhost:3000

      - name: Run pa11y-ci
        run: npx pa11y-ci

      - name: Run Lighthouse a11y audit
        uses: treosh/lighthouse-ci-action@v11
        with:
          urls: |
            http://localhost:3000/
            http://localhost:3000/login
          configPath: .lighthouserc.json
```

## Lighthouse Accessibility Configuration

```json
// .lighthouserc.json
{
  "ci": {
    "assert": {
      "assertions": {
        "categories:accessibility": ["error", { "minScore": 0.95 }],
        "color-contrast": "error",
        "image-alt": "error",
        "label": "error",
        "link-name": "error",
        "button-name": "error",
        "document-title": "error",
        "html-has-lang": "error",
        "meta-viewport": "error"
      }
    }
  }
}
```

## ESLint Accessibility Plugin

```bash
npm install --save-dev eslint-plugin-jsx-a11y
```

```javascript
// eslint.config.js (flat config)
import jsxA11y from 'eslint-plugin-jsx-a11y';

export default [
  {
    plugins: {
      'jsx-a11y': jsxA11y,
    },
    rules: {
      // Error-level rules
      'jsx-a11y/alt-text': 'error',
      'jsx-a11y/anchor-has-content': 'error',
      'jsx-a11y/anchor-is-valid': 'error',
      'jsx-a11y/aria-props': 'error',
      'jsx-a11y/aria-proptypes': 'error',
      'jsx-a11y/aria-role': 'error',
      'jsx-a11y/aria-unsupported-elements': 'error',
      'jsx-a11y/click-events-have-key-events': 'error',
      'jsx-a11y/heading-has-content': 'error',
      'jsx-a11y/html-has-lang': 'error',
      'jsx-a11y/img-redundant-alt': 'error',
      'jsx-a11y/interactive-supports-focus': 'error',
      'jsx-a11y/label-has-associated-control': 'error',
      'jsx-a11y/no-access-key': 'error',
      'jsx-a11y/no-autofocus': 'warn',
      'jsx-a11y/no-distracting-elements': 'error',
      'jsx-a11y/no-interactive-element-to-noninteractive-role': 'error',
      'jsx-a11y/no-noninteractive-element-interactions': 'warn',
      'jsx-a11y/no-noninteractive-element-to-interactive-role': 'error',
      'jsx-a11y/no-noninteractive-tabindex': 'warn',
      'jsx-a11y/no-redundant-roles': 'error',
      'jsx-a11y/no-static-element-interactions': 'warn',
      'jsx-a11y/role-has-required-aria-props': 'error',
      'jsx-a11y/role-supports-aria-props': 'error',
      'jsx-a11y/scope': 'error',
      'jsx-a11y/tabindex-no-positive': 'error',
    },
  },
];
```

---

# Part 10: React Component Patterns for Accessibility

## forwardRef for Accessible Composition

```tsx
import { forwardRef, useId, type ComponentPropsWithRef } from 'react';

// Accessible input component with forwarded ref
interface InputProps extends Omit<ComponentPropsWithRef<'input'>, 'id'> {
  label: string;
  error?: string;
  helpText?: string;
}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, helpText, required, className, ...props }, ref) => {
    const id = useId();
    const errorId = `${id}-error`;
    const helpId = `${id}-help`;

    return (
      <div className={className}>
        <label htmlFor={id}>
          {label}
          {required && <span aria-hidden="true"> *</span>}
        </label>

        <input
          ref={ref}
          id={id}
          aria-required={required}
          aria-invalid={error ? true : undefined}
          aria-describedby={
            [error && errorId, helpText && helpId].filter(Boolean).join(' ') ||
            undefined
          }
          {...props}
        />

        {helpText && (
          <p id={helpId} className="text-sm text-gray-500">
            {helpText}
          </p>
        )}
        {error && (
          <p id={errorId} role="alert" className="text-sm text-red-600">
            {error}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
```

## useId for Stable Accessible IDs

```tsx
import { useId } from 'react';

// useId generates unique IDs stable across server and client rendering
function PasswordField() {
  const id = useId();

  return (
    <div>
      <label htmlFor={id}>Password</label>
      <input
        id={id}
        type="password"
        aria-describedby={`${id}-requirements`}
        autoComplete="new-password"
      />
      <ul id={`${id}-requirements`} aria-label="Password requirements">
        <li>At least 8 characters</li>
        <li>One uppercase letter</li>
        <li>One number</li>
      </ul>
    </div>
  );
}
```

## Accessible Loading States

```tsx
function DataLoader<T>({
  isLoading,
  error,
  data,
  children,
  loadingLabel = 'Loading...',
}: DataLoaderProps<T>) {
  if (error) {
    return (
      <div role="alert">
        <h2>Something went wrong</h2>
        <p>{error.message}</p>
        <button onClick={() => window.location.reload()}>Try again</button>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div role="status" aria-live="polite">
        <Spinner aria-hidden="true" />
        <span className="sr-only">{loadingLabel}</span>
      </div>
    );
  }

  if (!data) return null;

  return <>{children(data)}</>;
}

// Usage
<DataLoader
  isLoading={isLoading}
  error={error}
  data={users}
  loadingLabel="Loading users..."
>
  {(users) => <UserList users={users} />}
</DataLoader>
```

## Accessible Disclosure (Show/Hide)

```tsx
function Disclosure({
  label,
  children,
  defaultOpen = false,
}: DisclosureProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const contentId = useId();

  return (
    <div>
      <button
        aria-expanded={isOpen}
        aria-controls={contentId}
        onClick={() => setIsOpen(!isOpen)}
      >
        <span
          aria-hidden="true"
          style={{
            display: 'inline-block',
            transform: isOpen ? 'rotate(90deg)' : 'rotate(0deg)',
            transition: 'transform 0.2s',
          }}
        >
          &#9654;
        </span>
        {label}
      </button>

      <div id={contentId} hidden={!isOpen}>
        {children}
      </div>
    </div>
  );
}
```

## Accessible Data Table with Sorting

```tsx
type SortDirection = 'ascending' | 'descending' | 'none';

interface Column<T> {
  key: keyof T;
  header: string;
  sortable?: boolean;
  render?: (value: T[keyof T], row: T) => React.ReactNode;
}

function AccessibleTable<T extends { id: string }>({
  data,
  columns,
  caption,
}: {
  data: T[];
  columns: Column<T>[];
  caption: string;
}) {
  const [sortColumn, setSortColumn] = useState<keyof T | null>(null);
  const [sortDirection, setSortDirection] = useState<SortDirection>('none');
  const liveRegionId = useId();

  const handleSort = (key: keyof T) => {
    let newDirection: SortDirection = 'ascending';
    if (sortColumn === key) {
      newDirection = sortDirection === 'ascending' ? 'descending' : 'ascending';
    }
    setSortColumn(key);
    setSortDirection(newDirection);
  };

  const sortedData = useMemo(() => {
    if (!sortColumn || sortDirection === 'none') return data;
    return [...data].sort((a, b) => {
      const aVal = a[sortColumn];
      const bVal = b[sortColumn];
      const cmp = aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
      return sortDirection === 'ascending' ? cmp : -cmp;
    });
  }, [data, sortColumn, sortDirection]);

  return (
    <>
      <div id={liveRegionId} aria-live="polite" className="sr-only">
        {sortColumn &&
          `Table sorted by ${String(sortColumn)}, ${sortDirection}`}
      </div>

      <table aria-describedby={liveRegionId}>
        <caption>{caption}</caption>
        <thead>
          <tr>
            {columns.map((col) => (
              <th
                key={String(col.key)}
                scope="col"
                aria-sort={
                  sortColumn === col.key ? sortDirection : undefined
                }
              >
                {col.sortable ? (
                  <button
                    onClick={() => handleSort(col.key)}
                    aria-label={`Sort by ${col.header}`}
                  >
                    {col.header}
                    <span aria-hidden="true">
                      {sortColumn === col.key
                        ? sortDirection === 'ascending'
                          ? ' ▲'
                          : ' ▼'
                        : ' ⇅'}
                    </span>
                  </button>
                ) : (
                  col.header
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sortedData.map((row) => (
            <tr key={row.id}>
              {columns.map((col) => (
                <td key={String(col.key)}>
                  {col.render
                    ? col.render(row[col.key], row)
                    : String(row[col.key])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
```

---

# Part 11: React Native Accessibility

## Core Accessibility Props

```tsx
import { View, Text, TouchableOpacity, Image, Switch } from 'react-native';

// Basic accessible button
function AccessibleButton({ onPress, label, hint }: AccessibleButtonProps) {
  return (
    <TouchableOpacity
      onPress={onPress}
      accessibilityRole="button"
      accessibilityLabel={label}
      accessibilityHint={hint}
    >
      <Text>{label}</Text>
    </TouchableOpacity>
  );
}

// Image with accessibility
function ProfileImage({ uri, userName }: ProfileImageProps) {
  return (
    <Image
      source={{ uri }}
      accessibilityLabel={`Profile photo of ${userName}`}
      accessibilityRole="image"
    />
  );
}

// Decorative image — hidden from screen readers
function DecorativeImage({ uri }: { uri: string }) {
  return (
    <Image
      source={{ uri }}
      accessibilityElementsHidden={true}  // iOS
      importantForAccessibility="no-hide-descendants"  // Android
    />
  );
}
```

## accessibilityState

```tsx
// Toggle with accessibility state
function ToggleSetting({ label, value, onToggle }: ToggleProps) {
  return (
    <View
      accessibilityRole="switch"
      accessibilityLabel={label}
      accessibilityState={{ checked: value }}
    >
      <Text>{label}</Text>
      <Switch
        value={value}
        onValueChange={onToggle}
        accessibilityLabel={label}
      />
    </View>
  );
}

// Button with disabled state
function SubmitButton({ onPress, isLoading, isDisabled }: SubmitButtonProps) {
  return (
    <TouchableOpacity
      onPress={onPress}
      disabled={isDisabled || isLoading}
      accessibilityRole="button"
      accessibilityLabel={isLoading ? 'Submitting...' : 'Submit form'}
      accessibilityState={{
        disabled: isDisabled || isLoading,
        busy: isLoading,
      }}
    >
      <Text>{isLoading ? 'Submitting...' : 'Submit'}</Text>
    </TouchableOpacity>
  );
}

// Selected item in a list
function SelectableItem({ item, isSelected, onSelect }: SelectableItemProps) {
  return (
    <TouchableOpacity
      onPress={() => onSelect(item.id)}
      accessibilityRole="radio"
      accessibilityLabel={item.name}
      accessibilityState={{ selected: isSelected }}
      accessibilityHint={
        isSelected ? 'Currently selected' : 'Double-tap to select'
      }
    >
      <View style={[styles.item, isSelected && styles.selected]}>
        <Text>{item.name}</Text>
        {isSelected && <CheckIcon accessibilityElementsHidden />}
      </View>
    </TouchableOpacity>
  );
}
```

## Grouping and Live Regions

```tsx
import { AccessibilityInfo, Platform } from 'react-native';

// Group related elements for a single swipe gesture
function ProductCard({ product }: { product: Product }) {
  return (
    <View
      accessible={true}  // Groups children into one accessible element
      accessibilityLabel={
        `${product.name}, $${product.price}, ${product.rating} stars, ` +
        `${product.inStock ? 'In stock' : 'Out of stock'}`
      }
      accessibilityRole="button"
      accessibilityHint="Double-tap to view product details"
    >
      <Image source={{ uri: product.image }} />
      <Text>{product.name}</Text>
      <Text>${product.price}</Text>
      <StarRating rating={product.rating} />
    </View>
  );
}

// Live region for dynamic content
function CartBadge({ count }: { count: number }) {
  return (
    <View
      accessibilityLiveRegion="polite"
      accessibilityLabel={`Cart: ${count} items`}
      accessibilityRole="text"
    >
      <Text>{count}</Text>
    </View>
  );
}

// Announce dynamic changes programmatically
function useAccessibilityAnnounce() {
  return useCallback((message: string) => {
    if (Platform.OS === 'ios') {
      AccessibilityInfo.announceForAccessibility(message);
    } else {
      // Android: Use accessibilityLiveRegion on a component instead
      AccessibilityInfo.announceForAccessibility(message);
    }
  }, []);
}

// Usage
function AddToCartButton({ product }: { product: Product }) {
  const announce = useAccessibilityAnnounce();

  const handleAddToCart = () => {
    addToCart(product);
    announce(`${product.name} added to cart`);
  };

  return (
    <TouchableOpacity
      onPress={handleAddToCart}
      accessibilityRole="button"
      accessibilityLabel={`Add ${product.name} to cart`}
    >
      <Text>Add to Cart</Text>
    </TouchableOpacity>
  );
}
```

## React Native Forms

```tsx
import { TextInput, View, Text } from 'react-native';

function AccessibleFormField({
  label,
  error,
  required,
  helpText,
  value,
  onChangeText,
  keyboardType,
  autoComplete,
}: AccessibleFormFieldProps) {
  return (
    <View>
      <Text
        accessibilityRole="text"
        nativeID={`label-${label}`}
      >
        {label}{required ? ' (required)' : ''}
      </Text>

      {helpText && (
        <Text
          nativeID={`help-${label}`}
          accessibilityRole="text"
          style={styles.helpText}
        >
          {helpText}
        </Text>
      )}

      <TextInput
        value={value}
        onChangeText={onChangeText}
        accessibilityLabel={label}
        accessibilityLabelledBy={`label-${label}`}
        accessibilityDescribedBy={
          error ? `error-${label}` : helpText ? `help-${label}` : undefined
        }
        accessibilityState={{
          disabled: false,
        }}
        accessibilityHint={required ? 'Required field' : undefined}
        keyboardType={keyboardType}
        autoComplete={autoComplete}
        style={[styles.input, error && styles.inputError]}
      />

      {error && (
        <Text
          nativeID={`error-${label}`}
          accessibilityRole="alert"
          accessibilityLiveRegion="assertive"
          style={styles.errorText}
        >
          {error}
        </Text>
      )}
    </View>
  );
}
```

## React Native Accessibility Testing

```tsx
import { render, screen } from '@testing-library/react-native';

describe('AccessibleButton', () => {
  it('has correct accessibility role', () => {
    render(<AccessibleButton label="Submit" onPress={() => {}} />);
    const button = screen.getByRole('button', { name: 'Submit' });
    expect(button).toBeTruthy();
  });

  it('announces disabled state', () => {
    render(
      <SubmitButton onPress={() => {}} isLoading={false} isDisabled={true} />
    );
    const button = screen.getByRole('button');
    expect(button.props.accessibilityState).toEqual(
      expect.objectContaining({ disabled: true })
    );
  });

  it('announces loading state', () => {
    render(
      <SubmitButton onPress={() => {}} isLoading={true} isDisabled={false} />
    );
    const button = screen.getByRole('button');
    expect(button.props.accessibilityState).toEqual(
      expect.objectContaining({ busy: true })
    );
  });
});
```

### React Native Accessibility Checklist

- [ ] All `TouchableOpacity`/`Pressable` have `accessibilityRole` and `accessibilityLabel`
- [ ] Images have `accessibilityLabel` (informative) or `accessibilityElementsHidden` (decorative)
- [ ] Groups of related elements use `accessible={true}` to combine
- [ ] Dynamic content uses `accessibilityLiveRegion` or `announceForAccessibility`
- [ ] Disabled/loading states use `accessibilityState`
- [ ] Touch targets are at least 44x44 points (iOS) / 48x48dp (Android)
- [ ] Custom gestures have accessible alternatives
- [ ] Forms have proper labels, errors, and hints
- [ ] Navigation provides `accessibilityRole="header"` for screen titles
- [ ] Lists use FlatList (which provides VoiceOver list navigation)

---

# Part 12: Common WCAG Failures and Quick Fixes

## Top 10 Most Common Failures

### 1. Missing Form Labels

```tsx
// ❌ FAIL: Input without label
<input type="text" placeholder="Email" />

// ✅ FIX: Add explicit label
<label htmlFor="email">Email</label>
<input id="email" type="text" placeholder="e.g., user@example.com" />

// ✅ FIX (alternative): aria-label for visually hidden label
<input type="text" aria-label="Email address" placeholder="Email" />
```

### 2. Low Color Contrast

```css
/* ❌ FAIL: 2.5:1 ratio — fails AA */
.text-gray { color: #999999; } /* on white background */

/* ✅ FIX: 4.6:1 ratio — passes AA */
.text-gray { color: #6b6b6b; } /* on white background */

/* ❌ FAIL: Placeholder text too light */
input::placeholder { color: #cccccc; } /* 1.6:1 ratio */

/* ✅ FIX: Placeholder meets 4.5:1 */
input::placeholder { color: #767676; } /* 4.5:1 ratio */
```

### 3. Missing Alt Text

```tsx
// ❌ FAIL: No alt attribute
<img src="/hero.jpg" />

// ✅ FIX: Descriptive alt for informative images
<img src="/hero.jpg" alt="Developer working at a standing desk" />

// ✅ FIX: Empty alt for decorative images
<img src="/divider.svg" alt="" />
```

### 4. Empty Links and Buttons

```tsx
// ❌ FAIL: Link with only an icon, no accessible name
<a href="/settings"><GearIcon /></a>

// ✅ FIX: Add aria-label
<a href="/settings" aria-label="Settings">
  <GearIcon aria-hidden="true" />
</a>

// ❌ FAIL: Button with no text content
<button onClick={handleClose}><XIcon /></button>

// ✅ FIX: Add accessible name
<button onClick={handleClose} aria-label="Close">
  <XIcon aria-hidden="true" />
</button>
```

### 5. Missing Document Language

```html
<!-- ❌ FAIL: No lang attribute -->
<html>

<!-- ✅ FIX: Add lang attribute -->
<html lang="en">

<!-- ✅ FIX: Mark language changes inline -->
<p>The French phrase <span lang="fr">joie de vivre</span> means joy of living.</p>
```

### 6. Missing Page Title

```tsx
// ❌ FAIL: Generic title
<title>Page</title>

// ✅ FIX: Descriptive, unique title
<title>Shopping Cart (3 items) — StoreName</title>

// React Helmet or Next.js Head
<Head>
  <title>{`${pageTitle} — ${siteName}`}</title>
</Head>
```

### 7. Keyboard Trap

```tsx
// ❌ FAIL: Custom dropdown traps keyboard focus
function BadDropdown() {
  return (
    <div onKeyDown={(e) => {
      // Only handles up/down, no Escape to exit!
      if (e.key === 'ArrowDown') selectNext();
      if (e.key === 'ArrowUp') selectPrev();
    }}>
      {/* options */}
    </div>
  );
}

// ✅ FIX: Allow Escape and Tab to exit
function GoodDropdown() {
  return (
    <div onKeyDown={(e) => {
      if (e.key === 'ArrowDown') selectNext();
      if (e.key === 'ArrowUp') selectPrev();
      if (e.key === 'Escape') {
        closeDropdown();
        triggerRef.current?.focus(); // Return focus to trigger
      }
      // Tab naturally moves focus out — don't prevent it
    }}>
      {/* options */}
    </div>
  );
}
```

### 8. Auto-Playing Media

```tsx
// ❌ FAIL: Auto-playing video with sound
<video autoPlay src="/promo.mp4" />

// ✅ FIX: Muted autoplay or no autoplay
<video autoPlay muted src="/promo.mp4">
  <track kind="captions" src="/promo-captions.vtt" srcLang="en" label="English" />
</video>

// ✅ BETTER: Let user initiate playback
<video controls src="/promo.mp4">
  <track kind="captions" src="/promo-captions.vtt" srcLang="en" label="English" />
</video>
```

### 9. Focus Not Visible

```css
/* ❌ FAIL: Removing focus outline completely */
*:focus { outline: none; }
button:focus { outline: 0; }

/* ✅ FIX: Custom focus style that meets 3:1 contrast */
:focus-visible {
  outline: 3px solid #0052a3;
  outline-offset: 2px;
}

/* Hide focus ring for mouse users, show for keyboard */
:focus:not(:focus-visible) {
  outline: none;
}
```

### 10. Non-Descriptive Link Text

```tsx
// ❌ FAIL: Vague link text
<a href="/report">Click here</a>
<a href="/report">Read more</a>
<a href="/report">Learn more</a>

// ✅ FIX: Descriptive link text
<a href="/report">View the Q4 sales report</a>

// ✅ FIX: When space is limited, use aria-label
<a href="/report" aria-label="Read the Q4 sales report">
  Read more
</a>

// ✅ FIX: Or use visually hidden text
<a href="/report">
  Read more<span className="sr-only"> about the Q4 sales report</span>
</a>
```

## Accessibility Quick Audit Checklist

Run this 5-minute check before every PR:

```
[ ] 1. Tab through the page — can you reach and operate everything?
[ ] 2. Focus visible — can you always see where focus is?
[ ] 3. Screen reader — does content make sense when read aloud?
[ ] 4. Zoom to 200% — does layout still work?
[ ] 5. Check headings — logical h1 > h2 > h3 hierarchy?
[ ] 6. Check images — all have alt text (or alt="")?
[ ] 7. Check forms — all inputs have labels?
[ ] 8. Check errors — are they announced to screen readers?
[ ] 9. Check contrast — run browser contrast checker?
[ ] 10. Run axe — no critical or serious violations?
```

---

# CSS Utilities for Accessibility

```css
/* Visually hidden but accessible to screen readers */
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

/* Show element when focused (for skip links) */
.sr-only-focusable:focus,
.sr-only-focusable:active {
  position: static;
  width: auto;
  height: auto;
  padding: inherit;
  margin: inherit;
  overflow: visible;
  clip: auto;
  white-space: normal;
}

/* Respect user motion preferences */
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}

/* High contrast mode support */
@media (forced-colors: active) {
  .custom-checkbox {
    border: 2px solid ButtonText;
  }
  .custom-focus-ring {
    outline: 2px solid Highlight;
  }
}

/* Touch target sizing (WCAG 2.2 — 2.5.8) */
.touch-target {
  min-width: 44px;
  min-height: 44px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

/* Focus ring that works on all backgrounds */
.focus-ring:focus-visible {
  outline: 3px solid #0052a3;
  outline-offset: 2px;
  box-shadow: 0 0 0 6px rgba(0, 82, 163, 0.25);
}
```

---

# Integrates With

| Skill / Module | Integration Point |
|---|---|
| **`elite-frontend-developer`** | React component patterns — forwardRef, useId, composition patterns for accessible components |
| **`testing-strategies`** | Accessibility testing layer — axe-core and jest-axe as part of the unit/integration test pyramid |
| **`e2e-testing`** | Automated a11y in E2E — @axe-core/playwright scans during Playwright E2E test runs |
| **`design-system`** | Accessible design tokens — contrast-safe color palettes, focus ring tokens, touch target sizing |
| **`mobile-form-validation`** | Accessible mobile forms — React Native form fields with accessibilityLabel, error announcements, and autocomplete |

### Integration Examples

**With `elite-frontend-developer`**: Use the React component patterns from this skill (forwardRef Input, useId, VisuallyHidden) as the foundation for all components built following the elite frontend developer patterns. Every component from that skill should pass `jest-axe` checks.

**With `testing-strategies`**: Add accessibility testing as a required layer in the test pyramid. Unit tests include `jest-axe`/`vitest-axe` checks. Integration tests verify focus management across component compositions. E2E tests run full-page axe scans.

**With `e2e-testing`**: Extend Playwright/Puppeteer E2E tests with `@axe-core/playwright` or `@axe-core/puppeteer` scans. Run WCAG 2.2 AA checks on every page visited during E2E flows. Fail CI on critical a11y violations.

**With `design-system`**: Design tokens must include contrast-validated color pairs, standardized focus ring styles, and minimum touch target sizes. The color contrast utilities from this skill validate that all token pairs meet WCAG AA requirements.

**With `mobile-form-validation`**: React Native form components must use `accessibilityLabel`, `accessibilityState`, `accessibilityHint`, and `accessibilityLiveRegion` for error announcements. Touch targets must be 44x44pt (iOS) / 48x48dp (Android).
