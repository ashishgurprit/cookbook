# Design System Skill

> Auto-discovered when UI/UX tasks detected.

## When to Apply

Activates on: "component", "styling", "CSS", "theme", "color", "typography", "responsive", "layout", "UI", "UX"

## Core Principles

1. **Consistency** - Use defined tokens, never hardcode values
2. **Accessibility** - WCAG 2.1 AA compliance minimum
3. **Responsiveness** - Mobile-first approach
4. **Performance** - Minimize CSS bundle size

## Quick Reference

### Colors
See `colors.md` for full palette.

### Typography
See `typography.md` for font stack and scales.

### Components
See `components.md` for component patterns.

## Usage

When building UI, always:
1. Check if a component already exists
2. Use design tokens for all values
3. Follow the component patterns
4. Test across breakpoints
5. Verify accessibility

## Visual Feedback Loop

If using Playwright MCP:
1. Implement component
2. Screenshot rendered output
3. Validate against requirements
4. Iterate until visual match

## Common Patterns

| Task | Pattern |
|------|---------|
| Spacing | Use `--space-*` tokens |
| Colors | Use semantic names (`--color-error`, not `red`) |
| Typography | Use scale (`--text-lg`, not `18px`) |
| Responsive | Mobile-first with `min-width` breakpoints |
| States | hover → focus → active → disabled |
