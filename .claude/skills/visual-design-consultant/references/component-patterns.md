# UI Component Patterns

Design system component patterns for beautiful, consistent interfaces.

## Button Styles

### Variant Hierarchy
```
PRIMARY     → Main action (submit, save, confirm)
SECONDARY   → Alternative action (cancel, back)
GHOST       → Tertiary action (learn more, details)
DESTRUCTIVE → Dangerous action (delete, remove)
OUTLINE     → Neutral emphasis
LINK        → Inline text action
```

### Button States
```css
.btn {
  /* Base */
  --btn-bg: var(--color-primary-500);
  --btn-text: white;
  --btn-border: transparent;
  
  /* Hover: Slightly darker */
  --btn-hover-bg: var(--color-primary-600);
  
  /* Active: Even darker */
  --btn-active-bg: var(--color-primary-700);
  
  /* Focus: Ring */
  --btn-focus-ring: 0 0 0 3px var(--color-primary-200);
  
  /* Disabled: Reduced opacity */
  --btn-disabled-opacity: 0.5;
}
```

### Size Scale
| Size | Padding | Font Size | Height |
|------|---------|-----------|--------|
| xs | 8px 12px | 12px | 28px |
| sm | 8px 16px | 14px | 32px |
| md | 10px 20px | 14px | 40px |
| lg | 12px 24px | 16px | 48px |
| xl | 16px 32px | 18px | 56px |

### Button CSS
```css
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  
  padding: 10px 20px;
  font-size: 14px;
  font-weight: 500;
  line-height: 1;
  
  border-radius: 8px;
  border: 1px solid transparent;
  
  cursor: pointer;
  transition: all 150ms ease;
}

.btn-primary {
  background: var(--color-primary-500);
  color: white;
}

.btn-primary:hover {
  background: var(--color-primary-600);
}

.btn-secondary {
  background: var(--color-neutral-100);
  color: var(--color-neutral-900);
}

.btn-ghost {
  background: transparent;
  color: var(--color-primary-500);
}

.btn-destructive {
  background: var(--color-error-500);
  color: white;
}
```

## Card Patterns

### Card Variants
```
ELEVATED    → Shadow, hover lift
OUTLINED    → Border, no shadow
FILLED      → Background colour, subtle
INTERACTIVE → Clickable, cursor pointer
```

### Card Structure
```html
<article class="card">
  <header class="card-header">
    <img class="card-image" />
    <span class="card-badge">New</span>
  </header>
  
  <div class="card-body">
    <h3 class="card-title">Title</h3>
    <p class="card-description">Description text...</p>
  </div>
  
  <footer class="card-footer">
    <button class="btn btn-primary">Action</button>
  </footer>
</article>
```

### Card CSS
```css
.card {
  background: white;
  border-radius: 12px;
  overflow: hidden;
  
  /* Elevated variant */
  box-shadow: 
    0 1px 3px rgba(0,0,0,0.1),
    0 1px 2px rgba(0,0,0,0.06);
}

.card:hover {
  box-shadow: 
    0 10px 15px rgba(0,0,0,0.1),
    0 4px 6px rgba(0,0,0,0.05);
  transform: translateY(-2px);
}

.card-body {
  padding: 20px;
}

.card-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 8px;
}

.card-description {
  color: var(--color-neutral-600);
  font-size: 14px;
  line-height: 1.5;
}
```

## Input Components

### Input States
```
DEFAULT     → Ready for input
FOCUS       → Active, ring highlight
FILLED      → Has value
ERROR       → Validation failed
DISABLED    → Not interactive
READONLY    → View only
```

### Input Structure
```html
<div class="form-field">
  <label class="form-label" for="email">
    Email address
    <span class="required">*</span>
  </label>
  
  <div class="input-wrapper">
    <span class="input-icon">📧</span>
    <input 
      type="email" 
      id="email" 
      class="input" 
      placeholder="you@example.com"
    />
  </div>
  
  <span class="form-hint">We'll never share your email.</span>
  <span class="form-error">Please enter a valid email.</span>
</div>
```

### Input CSS
```css
.input {
  width: 100%;
  padding: 10px 14px;
  
  font-size: 14px;
  line-height: 1.5;
  
  border: 1px solid var(--color-neutral-300);
  border-radius: 8px;
  
  background: white;
  
  transition: all 150ms ease;
}

.input:focus {
  outline: none;
  border-color: var(--color-primary-500);
  box-shadow: 0 0 0 3px var(--color-primary-100);
}

.input:disabled {
  background: var(--color-neutral-50);
  cursor: not-allowed;
  opacity: 0.6;
}

.input.error {
  border-color: var(--color-error-500);
}

.input.error:focus {
  box-shadow: 0 0 0 3px var(--color-error-100);
}

.form-label {
  display: block;
  font-size: 14px;
  font-weight: 500;
  margin-bottom: 6px;
  color: var(--color-neutral-700);
}

.form-hint {
  display: block;
  font-size: 12px;
  color: var(--color-neutral-500);
  margin-top: 6px;
}

.form-error {
  display: none;
  font-size: 12px;
  color: var(--color-error-500);
  margin-top: 6px;
}

.form-field.has-error .form-error {
  display: block;
}
```

## Modal / Dialog

### Modal Structure
```html
<div class="modal-overlay">
  <div class="modal" role="dialog" aria-modal="true">
    <header class="modal-header">
      <h2 class="modal-title">Title</h2>
      <button class="modal-close" aria-label="Close">×</button>
    </header>
    
    <div class="modal-body">
      <!-- Content -->
    </div>
    
    <footer class="modal-footer">
      <button class="btn btn-secondary">Cancel</button>
      <button class="btn btn-primary">Confirm</button>
    </footer>
  </div>
</div>
```

### Modal Sizes
| Size | Width | Use Case |
|------|-------|----------|
| sm | 400px | Confirmation, simple forms |
| md | 560px | Standard forms, content |
| lg | 720px | Complex forms, data tables |
| xl | 900px | Dashboards, rich content |
| full | 100% - margins | Full-screen experience |

### Modal CSS
```css
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  z-index: 1000;
}

.modal {
  background: white;
  border-radius: 16px;
  width: 100%;
  max-width: 560px;
  max-height: calc(100vh - 40px);
  overflow: hidden;
  display: flex;
  flex-direction: column;
  
  box-shadow: 
    0 25px 50px rgba(0, 0, 0, 0.25);
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 20px 24px;
  border-bottom: 1px solid var(--color-neutral-200);
}

.modal-body {
  padding: 24px;
  overflow-y: auto;
}

.modal-footer {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  padding: 16px 24px;
  border-top: 1px solid var(--color-neutral-200);
  background: var(--color-neutral-50);
}
```

## Navigation Patterns

### Navbar
```html
<nav class="navbar">
  <a href="/" class="navbar-brand">
    <img src="logo.svg" alt="Brand" />
  </a>
  
  <ul class="navbar-menu">
    <li><a href="/features" class="navbar-link">Features</a></li>
    <li><a href="/pricing" class="navbar-link">Pricing</a></li>
    <li><a href="/about" class="navbar-link">About</a></li>
  </ul>
  
  <div class="navbar-actions">
    <button class="btn btn-ghost">Sign In</button>
    <button class="btn btn-primary">Get Started</button>
  </div>
</nav>
```

### Sidebar
```html
<aside class="sidebar">
  <div class="sidebar-header">
    <img src="logo.svg" alt="Brand" />
  </div>
  
  <nav class="sidebar-nav">
    <a href="/dashboard" class="sidebar-link active">
      <span class="sidebar-icon">🏠</span>
      <span class="sidebar-label">Dashboard</span>
    </a>
    <a href="/analytics" class="sidebar-link">
      <span class="sidebar-icon">📊</span>
      <span class="sidebar-label">Analytics</span>
    </a>
  </nav>
  
  <div class="sidebar-footer">
    <a href="/settings" class="sidebar-link">
      <span class="sidebar-icon">⚙️</span>
      <span class="sidebar-label">Settings</span>
    </a>
  </div>
</aside>
```

## Badge / Tag

### Badge Variants
```css
.badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  font-size: 12px;
  font-weight: 500;
  border-radius: 9999px;
}

.badge-primary {
  background: var(--color-primary-100);
  color: var(--color-primary-700);
}

.badge-success {
  background: var(--color-success-100);
  color: var(--color-success-700);
}

.badge-warning {
  background: var(--color-warning-100);
  color: var(--color-warning-700);
}

.badge-error {
  background: var(--color-error-100);
  color: var(--color-error-700);
}
```

## Alert / Notification

### Alert Structure
```html
<div class="alert alert-success" role="alert">
  <span class="alert-icon">✓</span>
  <div class="alert-content">
    <h4 class="alert-title">Success!</h4>
    <p class="alert-message">Your changes have been saved.</p>
  </div>
  <button class="alert-close" aria-label="Dismiss">×</button>
</div>
```

### Alert CSS
```css
.alert {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 16px;
  border-radius: 8px;
  border-left: 4px solid;
}

.alert-success {
  background: var(--color-success-50);
  border-color: var(--color-success-500);
  color: var(--color-success-800);
}

.alert-warning {
  background: var(--color-warning-50);
  border-color: var(--color-warning-500);
  color: var(--color-warning-800);
}

.alert-error {
  background: var(--color-error-50);
  border-color: var(--color-error-500);
  color: var(--color-error-800);
}

.alert-info {
  background: var(--color-info-50);
  border-color: var(--color-info-500);
  color: var(--color-info-800);
}
```

## Spacing System

### 4px Base Scale
```css
:root {
  --space-0: 0;
  --space-1: 4px;   /* 0.25rem */
  --space-2: 8px;   /* 0.5rem */
  --space-3: 12px;  /* 0.75rem */
  --space-4: 16px;  /* 1rem */
  --space-5: 20px;  /* 1.25rem */
  --space-6: 24px;  /* 1.5rem */
  --space-8: 32px;  /* 2rem */
  --space-10: 40px; /* 2.5rem */
  --space-12: 48px; /* 3rem */
  --space-16: 64px; /* 4rem */
  --space-20: 80px; /* 5rem */
  --space-24: 96px; /* 6rem */
}
```

### Usage Guidelines
| Element | Padding | Margin |
|---------|---------|--------|
| Button | 8-12px vertical, 16-24px horizontal | - |
| Card | 16-24px | 16px between cards |
| Section | 48-96px vertical | - |
| Form field | - | 16-24px bottom |
| Paragraph | - | 16px bottom |

## Border Radius

### Consistent Scale
```css
:root {
  --radius-none: 0;
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 12px;
  --radius-xl: 16px;
  --radius-2xl: 24px;
  --radius-full: 9999px;
}
```

### Component Mapping
| Component | Radius |
|-----------|--------|
| Button | md (8px) |
| Card | lg (12px) |
| Input | md (8px) |
| Badge | full (pill) |
| Modal | xl (16px) |
| Avatar | full (circle) |

## Shadow System

### Elevation Levels
```css
:root {
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
  
  --shadow-md: 
    0 4px 6px rgba(0, 0, 0, 0.07),
    0 2px 4px rgba(0, 0, 0, 0.06);
  
  --shadow-lg: 
    0 10px 15px rgba(0, 0, 0, 0.1),
    0 4px 6px rgba(0, 0, 0, 0.05);
  
  --shadow-xl: 
    0 20px 25px rgba(0, 0, 0, 0.1),
    0 10px 10px rgba(0, 0, 0, 0.04);
  
  --shadow-2xl: 
    0 25px 50px rgba(0, 0, 0, 0.25);
}
```

### Usage
| Component | Shadow |
|-----------|--------|
| Dropdown | lg |
| Card | md (hover: lg) |
| Modal | 2xl |
| Tooltip | lg |
| Button | none (hover: sm) |
