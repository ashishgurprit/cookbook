# Code Review Checklist

## Elite Frontend Code Review Standards

Use this checklist for all pull requests to ensure production-quality code.

---

## Section 1: Code Quality

### Readability

- [ ] **Clear variable/function names** (self-documenting)
- [ ] **No magic numbers** (use named constants)
- [ ] **Functions are single-purpose** (do one thing well)
- [ ] **No commented-out code** (delete or commit separately)
- [ ] **Consistent formatting** (Prettier/ESLint enforced)
- [ ] **Comments explain "why," not "what"** (code should explain "what")

**Examples**:
```javascript
// ❌ BAD: Magic number
setTimeout(fn, 300);

// ✅ GOOD: Named constant
const DEBOUNCE_DELAY_MS = 300;
setTimeout(fn, DEBOUNCE_DELAY_MS);

// ❌ BAD: Unclear name
const d = new Date();

// ✅ GOOD: Clear name
const currentDate = new Date();
```

---

### Component Structure

- [ ] **Components are small** (< 200 lines)
- [ ] **Single Responsibility Principle** (one reason to change)
- [ ] **Props are destructured** (clear what's being used)
- [ ] **PropTypes or TypeScript** (type safety)
- [ ] **Default props defined** (prevents undefined errors)
- [ ] **No prop drilling** (use Context or state management if needed)

**Examples**:
```javascript
// ✅ GOOD: Small, focused component
function UserAvatar({ user, size = 'medium' }) {
  return (
    <img
      src={user.avatar}
      alt={`${user.name}'s avatar`}
      className={`avatar avatar-${size}`}
    />
  );
}

// ❌ BAD: God component (200+ lines, does everything)
```

---

### Hooks Best Practices

- [ ] **All hooks at top level** (not in conditions/loops)
- [ ] **useEffect has cleanup** (removes listeners, cancels requests)
- [ ] **useEffect dependencies are correct** (eslint-plugin-react-hooks)
- [ ] **Custom hooks extracted** (reusable logic)
- [ ] **useMemo/useCallback used appropriately** (not prematurely)

**Examples**:
```javascript
// ✅ GOOD: Proper useEffect with cleanup
useEffect(() => {
  const controller = new AbortController();

  fetch('/api/data', { signal: controller.signal })
    .then(res => res.json())
    .then(data => setData(data));

  return () => controller.abort(); // Cleanup
}, []);

// ❌ BAD: Missing cleanup
useEffect(() => {
  setInterval(() => console.log('tick'), 1000);
}, []); // Memory leak!
```

---

## Section 2: Performance

### Bundle Size

- [ ] **No unnecessary dependencies** (check bundle size)
- [ ] **Tree-shaking friendly imports** (`import { x } from 'lib'`)
- [ ] **Large libraries loaded on-demand** (lazy imports)
- [ ] **Bundle analyzed** (webpack-bundle-analyzer, rollup-plugin-visualizer)
- [ ] **Polyfills only for needed browsers**

**Check**:
```bash
# Check bundle size
npm run build
ls -lh dist/

# Analyze bundle
npx vite-bundle-visualizer
```

---

### Rendering Performance

- [ ] **No inline function definitions** (in render or JSX)
- [ ] **React.memo used appropriately** (expensive components)
- [ ] **useMemo for expensive calculations**
- [ ] **useCallback for stable callbacks**
- [ ] **Keys are stable** (not array index unless static)
- [ ] **Virtualization for long lists** (react-window, @tanstack/react-virtual)

**Examples**:
```javascript
// ❌ BAD: Inline function (new function every render)
<button onClick={() => handleClick(id)}>Click</button>

// ✅ GOOD: Stable callback
const handleClick = useCallback(() => {
  doSomething(id);
}, [id]);

<button onClick={handleClick}>Click</button>
```

---

### Network Optimization

- [ ] **API calls are debounced/throttled** (when appropriate)
- [ ] **Parallel requests use Promise.all**
- [ ] **Caching strategy implemented** (React Query, SWR, or manual)
- [ ] **Optimistic updates** (for better UX)
- [ ] **Error retry logic** (exponential backoff)

---

## Section 3: Testing

### Coverage

- [ ] **New code has tests** (unit + integration)
- [ ] **Tests pass** (`npm test`)
- [ ] **Coverage > 70%** (for critical paths)
- [ ] **Edge cases tested** (empty states, errors, loading)
- [ ] **Tests are maintainable** (not brittle)

---

### Test Quality

- [ ] **Tests user behavior** (not implementation details)
- [ ] **Uses Testing Library queries** (getByRole, getByLabelText)
- [ ] **Async properly handled** (findBy, waitFor)
- [ ] **Mocks are minimal** (prefer integration tests)
- [ ] **Tests are readable** (clear arrange/act/assert)

**Examples**:
```javascript
// ✅ GOOD: Tests behavior
test('user can submit form', async () => {
  render(<LoginForm />);

  await user.type(screen.getByLabelText(/email/i), 'user@test.com');
  await user.click(screen.getByRole('button', { name: /submit/i }));

  expect(await screen.findByText(/success/i)).toBeInTheDocument();
});

// ❌ BAD: Tests implementation
test('state updates on input change', () => {
  const wrapper = shallow(<LoginForm />);
  wrapper.setState({ email: 'test' });
  expect(wrapper.state('email')).toBe('test');
});
```

---

## Section 4: Accessibility

### Semantic HTML

- [ ] **Semantic elements used** (header, nav, main, article, footer)
- [ ] **Buttons are `<button>`** (not `<div>` with onClick)
- [ ] **Links are `<a>`** (not `<span>` with onClick)
- [ ] **Forms use `<form>`** (not div)
- [ ] **Heading hierarchy correct** (h1 → h2 → h3, no skips)

---

### ARIA & Keyboard

- [ ] **ARIA only when necessary** (native HTML first)
- [ ] **Interactive elements are keyboard accessible** (Tab, Enter, Space)
- [ ] **Focus states visible** (not `outline: none` without replacement)
- [ ] **Focus trapped in modals** (can't tab outside)
- [ ] **Screen reader tested** (at least spot check)

---

### Color & Contrast

- [ ] **Color contrast ≥ 4.5:1** (normal text)
- [ ] **Color contrast ≥ 3:1** (large text, UI components)
- [ ] **Information not conveyed by color alone** (use icons, text)
- [ ] **Focus indicators visible** (keyboard navigation)

**Tools**:
- Chrome DevTools Lighthouse
- axe DevTools
- WebAIM Contrast Checker

---

## Section 5: Security

### Input Validation

- [ ] **User input sanitized** (XSS prevention)
- [ ] **No `dangerouslySetInnerHTML`** (unless absolutely necessary + sanitized)
- [ ] **Form validation on client AND server**
- [ ] **SQL injection prevented** (parameterized queries on backend)

---

### Authentication & Authorization

- [ ] **Auth tokens stored securely** (httpOnly cookies, not localStorage)
- [ ] **Sensitive data not logged**
- [ ] **CORS configured correctly**
- [ ] **API keys not in frontend code**
- [ ] **Environment variables for secrets**

---

### Dependencies

- [ ] **No known vulnerabilities** (`npm audit`)
- [ ] **Dependencies up to date** (within reason)
- [ ] **Lockfile committed** (package-lock.json, yarn.lock)

---

## Section 6: Error Handling

### User-Facing Errors

- [ ] **Error boundaries implemented** (prevent white screen)
- [ ] **User-friendly error messages** ("Something went wrong" > stack trace)
- [ ] **Retry mechanisms** (for transient errors)
- [ ] **Loading states** (skeletons, spinners)
- [ ] **Empty states** (no data messaging)

**Examples**:
```javascript
// ✅ GOOD: Error boundary
class ErrorBoundary extends React.Component {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, info) {
    logErrorToService(error, info);
  }

  render() {
    if (this.state.hasError) {
      return <ErrorFallback />;
    }

    return this.props.children;
  }
}
```

---

### Developer Experience

- [ ] **Errors logged** (Sentry, LogRocket, etc.)
- [ ] **Source maps available** (for production debugging)
- [ ] **Console errors/warnings fixed**
- [ ] **TypeScript errors resolved** (if using TS)

---

## Section 7: Documentation

### Code Documentation

- [ ] **Complex logic commented** (why, not what)
- [ ] **README updated** (if public API changed)
- [ ] **Props documented** (JSDoc or TypeScript)
- [ ] **Breaking changes noted** (in PR description)

---

### Component Documentation

- [ ] **Storybook stories** (if using Storybook)
- [ ] **Usage examples** (in comments or docs)
- [ ] **Edge cases documented** (gotchas, limitations)

---

## Section 8: Git & PR Quality

### Commits

- [ ] **Atomic commits** (one logical change per commit)
- [ ] **Clear commit messages** (imperative mood: "Add feature" not "Added")
- [ ] **No merge commits** (rebase before merge)
- [ ] **No sensitive data** (passwords, API keys)

---

### Pull Request

- [ ] **PR title is descriptive**
- [ ] **PR description explains "why"** (not just "what")
- [ ] **Screenshots/videos** (for UI changes)
- [ ] **Breaking changes highlighted**
- [ ] **Self-reviewed** (read your own diff before requesting review)
- [ ] **Passing CI/CD** (tests, linting, build)

---

## Section 9: Mobile & Responsive

### Responsive Design

- [ ] **Works on mobile** (tested in DevTools or real device)
- [ ] **Touch targets ≥ 44x44px** (accessible tap size)
- [ ] **No horizontal scroll** (viewport meta tag set)
- [ ] **Breakpoints tested** (mobile, tablet, desktop)
- [ ] **Images responsive** (`srcset`, `sizes`)

---

### Performance on Mobile

- [ ] **Load time < 3s on 3G** (Lighthouse mobile)
- [ ] **No layout shift** (CLS < 0.1)
- [ ] **Interactive quickly** (INP < 200ms)
- [ ] **Images optimized** (WebP/AVIF, lazy loading)

---

## Section 10: Build & Deployment

### Build Configuration

- [ ] **Environment variables configured** (.env.example provided)
- [ ] **Build runs without warnings**
- [ ] **Production build tested locally**
- [ ] **Source maps generated** (for debugging)

---

### Deployment Readiness

- [ ] **Environment-specific config** (dev/staging/prod)
- [ ] **Error tracking configured** (Sentry, etc.)
- [ ] **Analytics configured** (Google Analytics, Plausible, etc.)
- [ ] **Performance monitoring** (Web Vitals, Lighthouse CI)
- [ ] **Feature flags** (if applicable)

---

## Quick Review Checklist (Essential)

For quick reviews, check at minimum:

- [ ] Tests pass and cover new code
- [ ] No console errors/warnings
- [ ] Accessibility basics (semantic HTML, keyboard nav)
- [ ] Performance (no obvious bottlenecks)
- [ ] Security (no exposed secrets, input validation)
- [ ] Works on mobile
- [ ] PR description is clear

---

## Red Flags (Require Discussion)

🚩 **Large PR** (>500 lines): Break into smaller PRs
🚩 **Disabled linting rules**: Why? Fix the issue instead
🚩 **TODO comments**: Create ticket or remove
🚩 **Skipped tests**: `.skip()` should be temporary with reason
🚩 **Hardcoded values**: Use config/env vars
🚩 **Copy-pasted code**: Extract to shared function/component
🚩 **`any` type (TypeScript)**: Defeats purpose of TypeScript

---

**Remember**: Code review is about **collaboration**, not **criticism**. Ask questions, suggest alternatives, and be respectful. The goal is to improve code quality and share knowledge.
