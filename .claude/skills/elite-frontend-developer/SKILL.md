---
name: elite-frontend-developer
description: "Elite frontend developer trained in best practices from industry leaders (Dan Abramov, Kent C. Dodds, Addy Osmani, Sarah Drasner, Wes Bos, Brad Frost). Use when building: (1) Modern React/Vue/Svelte applications, (2) Performance-optimized frontends, (3) Production-grade component architecture, (4) Accessible and tested web apps, (5) Optimized build configurations. Triggers on 'frontend development', 'React patterns', 'performance optimization', 'modern JavaScript', 'component architecture', 'frontend best practices', or elite developer techniques."
license: Proprietary
---

# Elite Frontend Developer

Master modern frontend development using proven patterns from the world's top developers. This skill codifies knowledge from React core team, Chrome DevRel, Testing JavaScript creators, and open-source leaders.

## Core Philosophy

**"The best code is no code at all. The second best is simple, readable code that solves the problem."** — Adapted from industry wisdom

Elite frontend development is:
- **User-centered**: Performance and accessibility are features, not nice-to-haves
- **Test-driven**: Confidence through comprehensive testing
- **Component-based**: Composition over inheritance
- **Performance-conscious**: Every kilobyte matters
- **Accessible by default**: WCAG 2.2 AA minimum
- **Maintainable**: Code is read more than written

## Quick Reference: Developer Wisdom

| Developer | Specialty | Key Principle |
|-----------|-----------|---------------|
| **Dan Abramov** | React patterns | "Don't stop the data flow" |
| **Kent C. Dodds** | Testing | "The more your tests resemble how users interact, the more confidence they give" |
| **Addy Osmani** | Performance | "Fast matters. Performance is a feature." |
| **Sarah Drasner** | Vue & Animation | "Code like an artist, think like an engineer" |
| **Wes Bos** | Modern JS | "Learn the fundamentals deeply, frameworks come and go" |
| **Brad Frost** | Design Systems | "Create systems, not pages" |

---

# Part 1: Modern JavaScript (ES2025+)

## Async Patterns (The Right Way)

### Promise Patterns

```javascript
// ✅ GOOD: Parallel execution
const [users, posts, comments] = await Promise.all([
  fetchUsers(),
  fetchPosts(),
  fetchComments()
]);

// ❌ BAD: Sequential (slower)
const users = await fetchUsers();
const posts = await fetchPosts();
const comments = await fetchComments();

// ✅ GOOD: Race condition (fastest wins)
const fastestData = await Promise.race([
  fetchFromCDN(),
  fetchFromOrigin(),
  fetchFromCache()
]);

// ✅ GOOD: AllSettled (don't fail on one error)
const results = await Promise.allSettled([
  fetchUsers(),
  fetchPosts(),
  fetchComments()
]);

results.forEach(result => {
  if (result.status === 'fulfilled') {
    console.log('Success:', result.value);
  } else {
    console.error('Failed:', result.reason);
  }
});
```

### Async Iteration

```javascript
// ✅ GOOD: Process stream of data
async function* fetchPages(url) {
  let page = 1;
  while (true) {
    const response = await fetch(`${url}?page=${page}`);
    const data = await response.json();

    if (data.length === 0) break;

    yield data;
    page++;
  }
}

// Usage
for await (const page of fetchPages('/api/users')) {
  console.log('Processing page:', page);
}
```

---

## Modern Array Methods

```javascript
// ✅ GOOD: Declarative transformations
const activeAdults = users
  .filter(user => user.age >= 18)
  .filter(user => user.isActive)
  .map(user => ({
    id: user.id,
    name: user.name,
    email: user.email
  }));

// ✅ GOOD: Find single item
const admin = users.find(user => user.role === 'admin');

// ✅ GOOD: Check existence
const hasAdmin = users.some(user => user.role === 'admin');

// ✅ GOOD: Reduce for aggregation
const totalRevenue = orders.reduce((sum, order) => sum + order.total, 0);

// ✅ GOOD: Group by property (ES2024)
const usersByRole = Object.groupBy(users, user => user.role);
// { admin: [...], user: [...], guest: [...] }
```

---

## Immutability Patterns

```javascript
// ✅ GOOD: Immutable updates
const updatedUser = {
  ...user,
  name: 'New Name',
  settings: {
    ...user.settings,
    theme: 'dark'
  }
};

// ✅ GOOD: Immutable array updates
const addedItem = [...items, newItem];
const removedItem = items.filter(item => item.id !== removeId);
const updatedItem = items.map(item =>
  item.id === updateId ? { ...item, ...updates } : item
);

// ❌ BAD: Mutation
user.name = 'New Name'; // Breaks React, Vue reactivity
items.push(newItem); // Unpredictable
```

---

## Error Handling Patterns

```javascript
// ✅ GOOD: Explicit error handling
async function fetchUser(id) {
  try {
    const response = await fetch(`/api/users/${id}`);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    // Log for debugging
    console.error('Failed to fetch user:', error);

    // Rethrow or return safe value
    throw new Error(`Failed to load user ${id}`);
  }
}

// ✅ GOOD: Custom error types
class APIError extends Error {
  constructor(message, status, response) {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.response = response;
  }
}

async function apiRequest(url) {
  const response = await fetch(url);

  if (!response.ok) {
    throw new APIError(
      'API request failed',
      response.status,
      await response.json()
    );
  }

  return response.json();
}
```

---

# Part 2: React Patterns (Dan Abramov + Community)

## Component Composition

### Compound Components Pattern

```javascript
// ✅ GOOD: Flexible API, shared state
function Select({ children, value, onChange }) {
  return (
    <SelectContext.Provider value={{ value, onChange }}>
      <div className="select">{children}</div>
    </SelectContext.Provider>
  );
}

function Option({ value, children }) {
  const { value: selectedValue, onChange } = useSelectContext();
  const isSelected = value === selectedValue;

  return (
    <button
      className={`option ${isSelected ? 'selected' : ''}`}
      onClick={() => onChange(value)}
    >
      {children}
    </button>
  );
}

// Usage (flexible, composable)
<Select value={value} onChange={setValue}>
  <Select.Option value="react">React</Select.Option>
  <Select.Option value="vue">Vue</Select.Option>
  <Select.Option value="svelte">Svelte</Select.Option>
</Select>
```

---

## Custom Hooks (Extract Logic)

```javascript
// ✅ GOOD: Reusable fetch hook
function useFetch(url) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchData() {
      try {
        setLoading(true);
        setError(null);

        const response = await fetch(url);
        const json = await response.json();

        if (!cancelled) {
          setData(json);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    fetchData();

    return () => {
      cancelled = true;
    };
  }, [url]);

  return { data, loading, error };
}

// Usage
function UserProfile({ userId }) {
  const { data: user, loading, error } = useFetch(`/api/users/${userId}`);

  if (loading) return <Loading />;
  if (error) return <Error message={error.message} />;

  return <div>{user.name}</div>;
}
```

---

## useEffect Best Practices

```javascript
// ❌ BAD: Missing dependency
useEffect(() => {
  fetchUser(userId); // userId not in deps
}, []); // Will use stale userId

// ✅ GOOD: All dependencies included
useEffect(() => {
  fetchUser(userId);
}, [userId]);

// ❌ BAD: Object/array dependency (always changes)
useEffect(() => {
  doSomething(config);
}, [config]); // New object every render

// ✅ GOOD: Destructure or use primitive values
useEffect(() => {
  doSomething(config);
}, [config.apiKey, config.endpoint]); // Stable primitives

// ✅ GOOD: Cleanup side effects
useEffect(() => {
  const timer = setInterval(() => {
    console.log('Tick');
  }, 1000);

  return () => clearInterval(timer); // Cleanup
}, []);

// ✅ GOOD: Cancel async operations
useEffect(() => {
  let cancelled = false;

  async function loadData() {
    const data = await fetchData();
    if (!cancelled) {
      setData(data);
    }
  }

  loadData();

  return () => {
    cancelled = true;
  };
}, []);
```

---

## State Management Patterns

### Local State (useState, useReducer)

```javascript
// ✅ GOOD: Simple state
const [count, setCount] = useState(0);

// ✅ GOOD: Complex state with useReducer
function reducer(state, action) {
  switch (action.type) {
    case 'increment':
      return { count: state.count + 1 };
    case 'decrement':
      return { count: state.count - 1 };
    case 'reset':
      return { count: 0 };
    default:
      throw new Error(`Unknown action: ${action.type}`);
  }
}

function Counter() {
  const [state, dispatch] = useReducer(reducer, { count: 0 });

  return (
    <div>
      <p>Count: {state.count}</p>
      <button onClick={() => dispatch({ type: 'increment' })}>+</button>
      <button onClick={() => dispatch({ type: 'decrement' })}>-</button>
      <button onClick={() => dispatch({ type: 'reset' })}>Reset</button>
    </div>
  );
}
```

### Context (Avoid Prop Drilling)

```javascript
// ✅ GOOD: Split contexts to avoid unnecessary re-renders
const ThemeContext = createContext();
const UserContext = createContext();

// ❌ BAD: One giant context (everything re-renders)
const AppContext = createContext(); // { theme, user, settings, ... }

// ✅ GOOD: Custom provider with optimization
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState('light');

  // Memoize value to prevent re-renders
  const value = useMemo(
    () => ({ theme, setTheme }),
    [theme]
  );

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

// ✅ GOOD: Custom hook for consumption
function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider');
  }
  return context;
}
```

### External State (Zustand - Recommended)

```javascript
// ✅ GOOD: Simple, performant global state
import create from 'zustand';

const useStore = create((set) => ({
  count: 0,
  increment: () => set((state) => ({ count: state.count + 1 })),
  decrement: () => set((state) => ({ count: state.count - 1 })),
  reset: () => set({ count: 0 })
}));

// Usage (only re-renders when count changes)
function Counter() {
  const count = useStore((state) => state.count);
  const increment = useStore((state) => state.increment);

  return (
    <div>
      <p>{count}</p>
      <button onClick={increment}>+</button>
    </div>
  );
}
```

---

## Performance Optimization

### React.memo (Prevent Unnecessary Re-renders)

```javascript
// ✅ GOOD: Memoize expensive component
const ExpensiveList = React.memo(function ExpensiveList({ items }) {
  return (
    <ul>
      {items.map(item => (
        <li key={item.id}>{item.name}</li>
      ))}
    </ul>
  );
});

// ❌ BAD: Memo with unstable props
function Parent() {
  return (
    <ExpensiveList items={[1, 2, 3]} /> // New array every render
  );
}

// ✅ GOOD: Stable props
function Parent() {
  const items = useMemo(() => [1, 2, 3], []); // Stable reference
  return <ExpensiveList items={items} />;
}
```

> **React 19 Compiler (v1.0, Oct 2025)**: The React Compiler auto-memoizes components and values. When using the Compiler, manual `React.memo`, `useMemo`, and `useCallback` are no longer needed for performance. The patterns below remain valid for projects not yet using the Compiler.

### useMemo & useCallback

```javascript
// ✅ GOOD: Memoize expensive calculations
function ProductList({ products, searchTerm }) {
  const filteredProducts = useMemo(() => {
    return products.filter(product =>
      product.name.toLowerCase().includes(searchTerm.toLowerCase())
    );
  }, [products, searchTerm]); // Only recalculate when these change

  return <ul>{filteredProducts.map(...)}</ul>;
}

// ✅ GOOD: Stable callback references
function Parent() {
  const [count, setCount] = useState(0);

  // Stable callback (doesn't change on every render)
  const handleClick = useCallback(() => {
    setCount(c => c + 1); // Use functional update
  }, []); // No dependencies needed

  return <Child onClick={handleClick} />;
}
```

---

## Code Splitting & Lazy Loading

```javascript
// ✅ GOOD: Route-based code splitting
import { lazy, Suspense } from 'react';

const Dashboard = lazy(() => import('./Dashboard'));
const Settings = lazy(() => import('./Settings'));
const Profile = lazy(() => import('./Profile'));

function App() {
  return (
    <Suspense fallback={<Loading />}>
      <Routes>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/profile" element={<Profile />} />
      </Routes>
    </Suspense>
  );
}

// ✅ GOOD: Component-level lazy loading
const HeavyChart = lazy(() => import('./HeavyChart'));

function Analytics() {
  const [showChart, setShowChart] = useState(false);

  return (
    <div>
      <button onClick={() => setShowChart(true)}>
        Show Chart
      </button>

      {showChart && (
        <Suspense fallback={<ChartSkeleton />}>
          <HeavyChart />
        </Suspense>
      )}
    </div>
  );
}
```

---

# Part 3: Performance Optimization (Addy Osmani)

## Core Web Vitals (2026 Standards)

### LCP (Largest Contentful Paint)
**Target**: < 2.5 seconds

```javascript
// ✅ GOOD: Preload critical resources
<link rel="preload" href="/hero-image.jpg" as="image" />
<link rel="preload" href="/critical.css" as="style" />

// ✅ GOOD: Priority hints (2026+)
<img src="/hero.jpg" fetchpriority="high" />
<script src="/analytics.js" fetchpriority="low" />

// ✅ GOOD: Image optimization
<picture>
  <source srcset="/hero.avif" type="image/avif" />
  <source srcset="/hero.webp" type="image/webp" />
  <img
    src="/hero.jpg"
    alt="Hero"
    loading="eager"
    fetchpriority="high"
    width="1200"
    height="600"
  />
</picture>
```

### FID (First Input Delay) → INP (Interaction to Next Paint)
**Target**: < 200ms

```javascript
// ✅ GOOD: Debounce expensive operations
import { debounce } from 'lodash-es';

const debouncedSearch = debounce((query) => {
  searchAPI(query);
}, 300);

// ✅ GOOD: Use requestIdleCallback for non-critical work
function processAnalytics(data) {
  if ('requestIdleCallback' in window) {
    requestIdleCallback(() => {
      sendToAnalytics(data);
    });
  } else {
    setTimeout(() => sendToAnalytics(data), 0);
  }
}

// ✅ GOOD: Code splitting for faster TTI
const HeavyComponent = lazy(() => import('./HeavyComponent'));
```

### CLS (Cumulative Layout Shift)
**Target**: < 0.1

```css
/* ✅ GOOD: Reserve space for images */
img {
  aspect-ratio: 16 / 9;
  width: 100%;
  height: auto;
}

/* ✅ GOOD: Reserve space for ads/embeds */
.ad-container {
  min-height: 250px;
}

/* ❌ BAD: Inject content without space */
.banner {
  /* No height = layout shift when loaded */
}
```

---

## Bundle Optimization

### Tree Shaking

```javascript
// ❌ BAD: Imports everything
import _ from 'lodash';
_.debounce(fn, 300);

// ✅ GOOD: Import only what you need
import debounce from 'lodash-es/debounce';
debounce(fn, 300);

// ✅ GOOD: Named imports (better for tree-shaking)
import { debounce } from 'lodash-es';
```

### Dynamic Imports

```javascript
// ✅ GOOD: Load heavy libraries on-demand
async function showChart(data) {
  const Chart = await import('chart.js');
  return new Chart(data);
}

// ✅ GOOD: Conditional loading
if (isFeatureEnabled) {
  const { feature } = await import('./feature');
  feature.init();
}
```

---

## Image Optimization

```javascript
// ✅ GOOD: Responsive images with modern formats
<picture>
  <source
    srcset="
      /image-400.avif 400w,
      /image-800.avif 800w,
      /image-1200.avif 1200w
    "
    type="image/avif"
    sizes="(max-width: 600px) 400px, (max-width: 1200px) 800px, 1200px"
  />
  <source
    srcset="
      /image-400.webp 400w,
      /image-800.webp 800w,
      /image-1200.webp 1200w
    "
    type="image/webp"
    sizes="(max-width: 600px) 400px, (max-width: 1200px) 800px, 1200px"
  />
  <img
    src="/image-800.jpg"
    alt="Description"
    loading="lazy"
    decoding="async"
    width="800"
    height="600"
  />
</picture>

// ✅ GOOD: Lazy load images below fold
<img src="/image.jpg" loading="lazy" alt="..." />

// ✅ GOOD: Native lazy loading with IntersectionObserver fallback
function LazyImage({ src, alt }) {
  const [imageSrc, setImageSrc] = useState(null);
  const imgRef = useRef();

  useEffect(() => {
    if ('loading' in HTMLImageElement.prototype) {
      setImageSrc(src);
      return;
    }

    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setImageSrc(src);
        observer.disconnect();
      }
    });

    if (imgRef.current) {
      observer.observe(imgRef.current);
    }

    return () => observer.disconnect();
  }, [src]);

  return <img ref={imgRef} src={imageSrc} alt={alt} />;
}
```

---

# Part 4: Testing (Kent C. Dodds)

## The Testing Trophy

```
     E2E
    /   \
   /     \
  / Integ \
 /   Tests \
/___________\
 Unit Tests
```

**Priority**: Integration > E2E > Unit

**Why**: Integration tests give the most confidence for the cost.

---

## Testing Library Best Practices

```javascript
// ✅ GOOD: Test user behavior, not implementation
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

test('user can submit login form', async () => {
  const user = userEvent.setup();
  const handleSubmit = jest.fn();

  render(<LoginForm onSubmit={handleSubmit} />);

  // Query by role (accessible)
  await user.type(
    screen.getByRole('textbox', { name: /email/i }),
    'user@example.com'
  );

  await user.type(
    screen.getByLabelText(/password/i),
    'password123'
  );

  await user.click(
    screen.getByRole('button', { name: /log in/i })
  );

  expect(handleSubmit).toHaveBeenCalledWith({
    email: 'user@example.com',
    password: 'password123'
  });
});

// ❌ BAD: Testing implementation details
test('form state updates on input change', () => {
  const { rerender } = render(<LoginForm />);
  // Testing internal state = brittle
});
```

---

## Query Priority (Most → Least Accessible)

```javascript
// 1. ✅ BEST: getByRole (most accessible)
screen.getByRole('button', { name: /submit/i });

// 2. ✅ GOOD: getByLabelText (forms)
screen.getByLabelText(/email/i);

// 3. ✅ GOOD: getByPlaceholderText (if no label)
screen.getByPlaceholderText(/enter email/i);

// 4. ✅ GOOD: getByText (visible text)
screen.getByText(/hello world/i);

// 5. ⚠️ OK: getByAltText (images)
screen.getByAltText(/product photo/i);

// 6. ⚠️ OK: getByTitle
screen.getByTitle(/close/i);

// 7. ❌ LAST RESORT: getByTestId
screen.getByTestId('submit-button'); // Use only when no other option
```

---

## Async Testing

```javascript
// ✅ GOOD: Wait for elements to appear
test('shows success message after submission', async () => {
  render(<Form />);

  await user.click(screen.getByRole('button', { name: /submit/i }));

  // Wait for async operation
  expect(await screen.findByText(/success/i)).toBeInTheDocument();
});

// ✅ GOOD: Wait for element to disappear
test('hides loading spinner after data loads', async () => {
  render(<DataLoader />);

  expect(screen.getByText(/loading/i)).toBeInTheDocument();

  await waitForElementToBeRemoved(() => screen.queryByText(/loading/i));

  expect(screen.getByText(/data loaded/i)).toBeInTheDocument();
});
```

---

## Mocking Best Practices

```javascript
// ✅ GOOD: Mock network requests (MSW v2)
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

const server = setupServer(
  http.get('/api/user', () => {
    return HttpResponse.json({ name: 'John Doe' });
  })
);

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

test('displays user name', async () => {
  render(<UserProfile />);

  expect(await screen.findByText('John Doe')).toBeInTheDocument();
});

// ✅ GOOD: Override mock per test
test('handles error state', async () => {
  server.use(
    rest.get('/api/user', (req, res, ctx) => {
      return res(ctx.status(500));
    })
  );

  render(<UserProfile />);

  expect(await screen.findByText(/error/i)).toBeInTheDocument();
});
```

---

# Part 5: Accessibility (WCAG 2.1 AA+)

## Semantic HTML

```javascript
// ✅ GOOD: Semantic elements
<header>
  <nav>
    <ul>
      <li><a href="/">Home</a></li>
      <li><a href="/about">About</a></li>
    </ul>
  </nav>
</header>

<main>
  <article>
    <h1>Article Title</h1>
    <p>Content...</p>
  </article>
</main>

<footer>
  <p>&copy; 2026 Company</p>
</footer>

// ❌ BAD: Div soup
<div class="header">
  <div class="nav">
    <div class="link">Home</div>
  </div>
</div>
```

---

## ARIA When Necessary

```javascript
// ✅ GOOD: Button (native semantics)
<button onClick={handleClick}>Submit</button>

// ❌ BAD: Div as button (requires ARIA)
<div role="button" tabIndex={0} onClick={handleClick}>
  Submit
</div>

// ✅ GOOD: ARIA when needed (custom widgets)
<div
  role="tablist"
  aria-label="Product tabs"
>
  <button
    role="tab"
    aria-selected={selectedTab === 'overview'}
    aria-controls="overview-panel"
    id="overview-tab"
  >
    Overview
  </button>
</div>

<div
  role="tabpanel"
  id="overview-panel"
  aria-labelledby="overview-tab"
  hidden={selectedTab !== 'overview'}
>
  Content...
</div>
```

---

## Keyboard Navigation

```javascript
// ✅ GOOD: Full keyboard support
function Dialog({ isOpen, onClose, children }) {
  const dialogRef = useRef();

  useEffect(() => {
    if (!isOpen) return;

    // Focus first focusable element
    const firstFocusable = dialogRef.current.querySelector(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    firstFocusable?.focus();

    // Trap focus inside dialog
    function handleKeyDown(e) {
      if (e.key === 'Escape') {
        onClose();
      }

      if (e.key === 'Tab') {
        const focusableElements = dialogRef.current.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );

        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        if (e.shiftKey && document.activeElement === firstElement) {
          e.preventDefault();
          lastElement.focus();
        } else if (!e.shiftKey && document.activeElement === lastElement) {
          e.preventDefault();
          firstElement.focus();
        }
      }
    }

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      ref={dialogRef}
      role="dialog"
      aria-modal="true"
      aria-labelledby="dialog-title"
    >
      {children}
    </div>
  );
}
```

---

## Color Contrast

```css
/* ✅ GOOD: WCAG AA contrast (4.5:1 minimum) */
.text {
  color: #333;
  background: #fff;
  /* Contrast ratio: 12.6:1 ✓ */
}

.button-primary {
  color: #fff;
  background: #0066cc;
  /* Contrast ratio: 7.4:1 ✓ */
}

/* ❌ BAD: Insufficient contrast */
.text-light {
  color: #aaa;
  background: #fff;
  /* Contrast ratio: 2.3:1 ✗ (fails AA) */
}
```

**Tools**:
- Chrome DevTools (Lighthouse)
- WebAIM Contrast Checker
- axe DevTools

---

# Part 6: Build Optimization

## Vite Configuration (Recommended 2026)

```javascript
// vite.config.js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { visualizer } from 'rollup-plugin-visualizer';

export default defineConfig({
  plugins: [
    react(),
    visualizer({ open: true }) // Bundle analyzer
  ],

  build: {
    // Target modern browsers only
    target: 'esnext',

    // Enable minification
    minify: 'esbuild',

    // Generate sourcemaps for production debugging
    sourcemap: true,

    rollupOptions: {
      output: {
        // Manual chunk splitting
        manualChunks: {
          'vendor': ['react', 'react-dom'],
          'ui': ['@headlessui/react', 'framer-motion'],
          'utils': ['date-fns', 'lodash-es']
        }
      }
    },

    // Chunk size warnings
    chunkSizeWarningLimit: 500
  },

  // Optimize dependencies
  optimizeDeps: {
    include: ['react', 'react-dom']
  }
});
```

---

## File References

- `references/react-patterns.md` - Dan Abramov's recommended patterns
- `references/performance-optimization.md` - Addy Osmani's PRPL + Core Web Vitals
- `references/testing-strategies.md` - Kent C. Dodds' Testing Trophy
- `references/modern-javascript.md` - ES2024+ patterns
- `references/accessibility-wcag.md` - WCAG 2.1 AA+ compliance
- `references/build-optimization.md` - Vite, Webpack, esbuild
- `patterns/component-composition.md` - Compound components, render props
- `patterns/state-management.md` - Local, Context, External, Server state
- `patterns/api-integration.md` - Fetch patterns, error handling
- `patterns/form-handling.md` - Form validation, submission
- `anti-patterns/react-anti-patterns.md` - Common React mistakes
- `anti-patterns/performance-anti-patterns.md` - Performance pitfalls
- `anti-patterns/code-quality-anti-patterns.md` - Code smells
- `checklists/code-review.md` - Code review checklist
- `checklists/pre-deployment.md` - Pre-deployment checklist
- `checklists/performance-audit.md` - Performance audit checklist
- `examples/production-react-app.md` - Complete app structure
- `examples/performance-optimization-before-after.md` - Case studies
- `examples/testing-examples.md` - Real-world test examples

---

**Remember**: "Premature optimization is the root of all evil. But knowing what to optimize and when is the mark of an elite developer." — Adapted from Donald Knuth

Focus on:
1. **Correctness** first (does it work?)
2. **Maintainability** second (can others understand it?)
3. **Performance** third (but measure, don't guess)

---

# Research Update: February 2026

Key ecosystem changes to be aware of:

| Technology | Version | Key Change |
|-----------|---------|------------|
| React | 19.2.4 | Compiler v1.0 (auto-memoization). `forwardRef` removed — use `ref` as prop. Actions for forms. `use()` hook. |
| Next.js | 16.1.6 | PPR stable. Cache Components. Turbopack default. See `nextjs-app-patterns` skill. |
| Tailwind CSS | 4.1.18 | Complete rewrite. CSS-first config (`@import "tailwindcss"`). `@theme` replaces config file. 10x faster builds. |
| Vite | 7.3.1 | ESM-only. Rolldown integration. Requires Node.js 20+. |
| ESLint | 10.0.0 | Flat config only (`.eslintrc` removed). Requires Node.js 20.19+. |
| TypeScript | 5.9.3 | Incremental improvements. Keep updated for best IDE support. |
| Node.js | 24 LTS | Active LTS. Node.js 20 EOL April 2026. Target 24 for new projects. |
