# Color System

## Design Tokens
Always use CSS variables or theme tokens. Never hardcode hex values.

## Color Palette

### Primary
```css
--color-primary-50: #eff6ff;
--color-primary-100: #dbeafe;
--color-primary-200: #bfdbfe;
--color-primary-300: #93c5fd;
--color-primary-400: #60a5fa;
--color-primary-500: #3b82f6;  /* Default */
--color-primary-600: #2563eb;
--color-primary-700: #1d4ed8;
--color-primary-800: #1e40af;
--color-primary-900: #1e3a8a;
```

### Neutral (Gray)
```css
--color-neutral-50: #fafafa;
--color-neutral-100: #f4f4f5;
--color-neutral-200: #e4e4e7;
--color-neutral-300: #d4d4d8;
--color-neutral-400: #a1a1aa;
--color-neutral-500: #71717a;
--color-neutral-600: #52525b;
--color-neutral-700: #3f3f46;
--color-neutral-800: #27272a;
--color-neutral-900: #18181b;
```

### Semantic Colors
```css
/* Success */
--color-success: #22c55e;
--color-success-light: #dcfce7;
--color-success-dark: #16a34a;

/* Warning */
--color-warning: #f59e0b;
--color-warning-light: #fef3c7;
--color-warning-dark: #d97706;

/* Error */
--color-error: #ef4444;
--color-error-light: #fee2e2;
--color-error-dark: #dc2626;

/* Info */
--color-info: #3b82f6;
--color-info-light: #dbeafe;
--color-info-dark: #2563eb;
```

### Background & Surface
```css
/* Light Mode */
--color-background: #ffffff;
--color-surface: #f4f4f5;
--color-surface-elevated: #ffffff;

/* Dark Mode */
--color-background-dark: #18181b;
--color-surface-dark: #27272a;
--color-surface-elevated-dark: #3f3f46;
```

### Text Colors
```css
/* Light Mode */
--color-text-primary: #18181b;
--color-text-secondary: #52525b;
--color-text-tertiary: #a1a1aa;
--color-text-inverse: #ffffff;

/* Dark Mode */
--color-text-primary-dark: #fafafa;
--color-text-secondary-dark: #a1a1aa;
--color-text-tertiary-dark: #71717a;
```

## Usage Guidelines

### Do
- Use semantic color names (error, success) for state
- Use neutral palette for text and backgrounds
- Ensure 4.5:1 contrast ratio for text
- Use opacity for hover/active states

### Don't
- Hardcode hex values in components
- Mix light and dark mode colors
- Use color alone to convey meaning
- Create new colors without adding to system
