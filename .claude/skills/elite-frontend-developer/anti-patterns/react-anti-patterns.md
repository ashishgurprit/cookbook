# React Anti-Patterns: What NOT to Do

Common mistakes that even experienced developers make. Learn from others' mistakes.

---

## 1. useEffect Abuse

### Anti-Pattern: Using useEffect for Derived State

```javascript
// ❌ BAD: Unnecessary useEffect
function SearchResults({ query }) {
  const [results, setResults] = useState([]);

  useEffect(() => {
    const filtered = items.filter(item =>
      item.name.includes(query)
    );
    setResults(filtered);
  }, [query, items]);

  return <div>{results.map(...)}</div>;
}

// ✅ GOOD: Calculate during render
function SearchResults({ query }) {
  const results = items.filter(item =>
    item.name.includes(query)
  );

  return <div>{results.map(...)}</div>;
}

// ✅ BETTER: Memoize if expensive
function SearchResults({ query }) {
  const results = useMemo(() =>
    items.filter(item => item.name.includes(query)),
    [query, items]
  );

  return <div>{results.map(...)}</div>;
}
```

**Why it's bad**: useEffect runs *after* render, causing double render. Calculate directly instead.

---

### Anti-Pattern: useEffect with Fetch on Every Render

```javascript
// ❌ BAD: Fetches on every render
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);

  useEffect(() => {
    fetch(`/api/users/${userId}`)
      .then(res => res.json())
      .then(setUser);
  }); // No dependency array = runs every render!

  return <div>{user?.name}</div>;
}

// ✅ GOOD: Dependency array prevents infinite loop
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);

  useEffect(() => {
    let cancelled = false;

    fetch(`/api/users/${userId}`)
      .then(res => res.json())
      .then(data => {
        if (!cancelled) setUser(data);
      });

    return () => {
      cancelled = true;
    };
  }, [userId]); // Only fetch when userId changes

  return <div>{user?.name}</div>;
}

// ✅ BETTER: Use a data fetching library
import { useQuery } from '@tanstack/react-query';

function UserProfile({ userId }) {
  const { data: user } = useQuery({
    queryKey: ['user', userId],
    queryFn: () => fetch(`/api/users/${userId}`).then(r => r.json())
  });

  return <div>{user?.name}</div>;
}
```

---

## 2. Prop Drilling

### Anti-Pattern: Passing Props Through Many Layers

```javascript
// ❌ BAD: Prop drilling nightmare
function App() {
  const [user, setUser] = useState(null);
  return <Dashboard user={user} setUser={setUser} />;
}

function Dashboard({ user, setUser }) {
  return <Sidebar user={user} setUser={setUser} />;
}

function Sidebar({ user, setUser }) {
  return <UserMenu user={user} setUser={setUser} />;
}

function UserMenu({ user, setUser }) {
  return <UserAvatar user={user} />; // Finally used here!
}

// ✅ GOOD: Context for deeply nested state
const UserContext = createContext();

function App() {
  const [user, setUser] = useState(null);

  return (
    <UserContext.Provider value={{ user, setUser }}>
      <Dashboard />
    </UserContext.Provider>
  );
}

function Dashboard() {
  return <Sidebar />; // No props!
}

function Sidebar() {
  return <UserMenu />;
}

function UserMenu() {
  const { user } = useContext(UserContext); // Get directly
  return <UserAvatar user={user} />;
}
```

**When prop drilling is okay**: 1-2 levels deep. Context/state management for deeper.

---

## 3. Inline Functions in JSX

### Anti-Pattern: Creating New Functions Every Render

```javascript
// ❌ BAD: New function every render
function TodoList({ todos }) {
  return (
    <ul>
      {todos.map(todo => (
        <TodoItem
          key={todo.id}
          todo={todo}
          onDelete={() => deleteTodo(todo.id)} // New function every render!
        />
      ))}
    </ul>
  );
}

// ✅ GOOD: Stable callback with useCallback
function TodoList({ todos }) {
  const handleDelete = useCallback((id) => {
    deleteTodo(id);
  }, []);

  return (
    <ul>
      {todos.map(todo => (
        <TodoItem
          key={todo.id}
          todo={todo}
          onDelete={handleDelete}
        />
      ))}
    </ul>
  );
}

// ✅ ALSO GOOD: Pass ID, not callback
function TodoList({ todos }) {
  return (
    <ul>
      {todos.map(todo => (
        <TodoItem
          key={todo.id}
          todo={todo}
          onDelete={deleteTodo}
        />
      ))}
    </ul>
  );
}

function TodoItem({ todo, onDelete }) {
  return (
    <li>
      {todo.text}
      <button onClick={() => onDelete(todo.id)}>Delete</button>
    </li>
  );
}
```

---

## 4. Key Prop Mistakes

### Anti-Pattern: Using Array Index as Key

```javascript
// ❌ BAD: Array index as key
{items.map((item, index) => (
  <div key={index}>{item.name}</div>
))}

// Why it's bad:
// 1. Deleting items causes wrong elements to re-render
// 2. List reordering breaks component state
// 3. Performance issues

// ✅ GOOD: Stable unique ID
{items.map(item => (
  <div key={item.id}>{item.name}</div>
))}

// ✅ ACCEPTABLE: Index IF list is static (never changes)
const STATIC_ITEMS = ['Home', 'About', 'Contact'];

{STATIC_ITEMS.map((item, index) => (
  <NavLink key={index}>{item}</NavLink>
))}
```

---

### Anti-Pattern: Using Random/Generated Keys

```javascript
// ❌ BAD: Random key (new on every render)
{items.map(item => (
  <div key={Math.random()}>{item.name}</div>
))}

// ❌ BAD: Generated key from Date.now()
{items.map(item => (
  <div key={Date.now()}>{item.name}</div>
))}

// ✅ GOOD: Use item's stable unique identifier
{items.map(item => (
  <div key={item.id}>{item.name}</div>
))}
```

---

## 5. State Management Anti-Patterns

### Anti-Pattern: Too Much Local State

```javascript
// ❌ BAD: Duplicating server state locally
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    fetch(`/api/users/${userId}`)
      .then(res => res.json())
      .then(data => {
        setUser(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err);
        setLoading(false);
      });
  }, [userId]);

  // Now managing: data, loading, error, refetch, cache, etc.
  // This is what libraries like React Query do!
}

// ✅ GOOD: Let library handle server state
import { useQuery } from '@tanstack/react-query';

function UserProfile({ userId }) {
  const { data: user, isLoading, error } = useQuery({
    queryKey: ['user', userId],
    queryFn: () => fetch(`/api/users/${userId}`).then(r => r.json())
  });

  // Loading, error, caching, refetching all handled!
}
```

---

### Anti-Pattern: Storing Derived State

```javascript
// ❌ BAD: Storing derived state
function ShoppingCart({ items }) {
  const [total, setTotal] = useState(0);

  useEffect(() => {
    setTotal(items.reduce((sum, item) => sum + item.price, 0));
  }, [items]);

  return <div>Total: ${total}</div>;
}

// ✅ GOOD: Calculate during render
function ShoppingCart({ items }) {
  const total = items.reduce((sum, item) => sum + item.price, 0);

  return <div>Total: ${total}</div>;
}

// ✅ BETTER: Memoize if expensive
function ShoppingCart({ items }) {
  const total = useMemo(
    () => items.reduce((sum, item) => sum + item.price, 0),
    [items]
  );

  return <div>Total: ${total}</div>;
}
```

---

## 6. Context Anti-Patterns

### Anti-Pattern: One Giant Context

```javascript
// ❌ BAD: Everything in one context
const AppContext = createContext();

function AppProvider({ children }) {
  const [user, setUser] = useState(null);
  const [theme, setTheme] = useState('light');
  const [settings, setSettings] = useState({});
  const [notifications, setNotifications] = useState([]);

  // Problem: Any state change re-renders EVERYTHING
  const value = { user, setUser, theme, setTheme, settings, notifications };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

// ✅ GOOD: Split contexts by concern
const UserContext = createContext();
const ThemeContext = createContext();
const SettingsContext = createContext();

function Providers({ children }) {
  return (
    <UserProvider>
      <ThemeProvider>
        <SettingsProvider>
          {children}
        </SettingsProvider>
      </ThemeProvider>
    </UserProvider>
  );
}

// Now components only re-render when their context changes
```

---

### Anti-Pattern: Not Memoizing Context Value

```javascript
// ❌ BAD: New object every render
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState('light');

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}
// Every render creates new { theme, setTheme } object
// All consumers re-render unnecessarily!

// ✅ GOOD: Memoize context value
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState('light');

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
```

---

## 7. Component Structure Anti-Patterns

### Anti-Pattern: God Components

```javascript
// ❌ BAD: 500-line component that does everything
function Dashboard() {
  const [users, setUsers] = useState([]);
  const [posts, setPosts] = useState([]);
  const [comments, setComments] = useState([]);
  const [loading, setLoading] = useState(false);
  // ... 50 more state variables

  useEffect(() => { /* fetch users */ }, []);
  useEffect(() => { /* fetch posts */ }, []);
  useEffect(() => { /* fetch comments */ }, []);
  // ... 20 more useEffects

  function handleUserClick() { /* ... */ }
  function handlePostClick() { /* ... */ }
  function handleCommentClick() { /* ... */ }
  // ... 30 more functions

  return (
    <div>
      {/* 400 lines of JSX */}
    </div>
  );
}

// ✅ GOOD: Split into focused components
function Dashboard() {
  return (
    <div>
      <UsersList />
      <PostsFeed />
      <CommentsSection />
    </div>
  );
}

function UsersList() {
  const { data: users, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: fetchUsers
  });

  if (isLoading) return <Loading />;

  return (
    <ul>
      {users.map(user => (
        <UserCard key={user.id} user={user} />
      ))}
    </ul>
  );
}
```

---

## 8. Performance Anti-Patterns

### Anti-Pattern: Premature Optimization

```javascript
// ❌ BAD: Over-optimizing simple components
const Button = React.memo(function Button({ onClick, children }) {
  // This button doesn't need memo - it's too simple!
  return <button onClick={onClick}>{children}</button>;
});

const Label = React.memo(function Label({ text }) {
  // Simple presentational component - memo is overkill
  return <span>{text}</span>;
});

// ✅ GOOD: Only optimize when needed
function Button({ onClick, children }) {
  return <button onClick={onClick}>{children}</button>;
}

// ✅ GOOD: Memo for expensive components
const ExpensiveChart = React.memo(function ExpensiveChart({ data }) {
  // Expensive rendering (charts, maps, complex calculations)
  return <ComplexVisualization data={data} />;
});
```

**Rule**: Measure first, optimize second. Don't memo everything.

---

### Anti-Pattern: Blocking the Main Thread

```javascript
// ❌ BAD: Synchronous heavy computation
function SearchResults({ query }) {
  const results = items.filter(item => {
    // Imagine this processes 100,000 items
    return expensiveMatch(item, query);
  });

  return <div>{results.map(...)}</div>;
}
// UI freezes during filtering!

// ✅ GOOD: Use Web Worker for heavy computation
function SearchResults({ query }) {
  const [results, setResults] = useState([]);

  useEffect(() => {
    const worker = new Worker('search-worker.js');

    worker.postMessage({ items, query });

    worker.onmessage = (e) => {
      setResults(e.data);
    };

    return () => worker.terminate();
  }, [query]);

  return <div>{results.map(...)}</div>;
}

// ✅ ALSO GOOD: Virtualize large lists
import { FixedSizeList } from 'react-window';

function SearchResults({ results }) {
  return (
    <FixedSizeList
      height={600}
      itemCount={results.length}
      itemSize={50}
      width="100%"
    >
      {({ index, style }) => (
        <div style={style}>{results[index].name}</div>
      )}
    </FixedSizeList>
  );
}
```

---

## 9. TypeScript Anti-Patterns

### Anti-Pattern: Using `any`

```typescript
// ❌ BAD: Defeats purpose of TypeScript
function processData(data: any) {
  return data.value.toUpperCase(); // No type safety!
}

// ✅ GOOD: Proper typing
interface Data {
  value: string;
}

function processData(data: Data) {
  return data.value.toUpperCase(); // Type-safe!
}

// ✅ ALSO GOOD: Generic when type varies
function processData<T extends { value: string }>(data: T) {
  return data.value.toUpperCase();
}
```

---

### Anti-Pattern: Type Assertions Without Validation

```typescript
// ❌ BAD: Unsafe type assertion
const data = await response.json() as User;
// What if API returns different shape?

// ✅ GOOD: Runtime validation (Zod, Yup, etc.)
import { z } from 'zod';

const UserSchema = z.object({
  id: z.number(),
  name: z.string(),
  email: z.string().email()
});

const data = UserSchema.parse(await response.json());
// Throws if invalid, guarantees type at runtime
```

---

## 10. Accessibility Anti-Patterns

### Anti-Pattern: Div as Button

```javascript
// ❌ BAD: Not keyboard accessible
<div onClick={handleClick}>Click me</div>

// ✅ GOOD: Use button element
<button onClick={handleClick}>Click me</button>

// ✅ ACCEPTABLE: If absolutely must use div (rare)
<div
  role="button"
  tabIndex={0}
  onClick={handleClick}
  onKeyDown={(e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      handleClick();
    }
  }}
>
  Click me
</div>
```

---

### Anti-Pattern: Missing Alt Text

```javascript
// ❌ BAD: No alt text
<img src="/product.jpg" />

// ✅ GOOD: Descriptive alt text
<img src="/product.jpg" alt="Blue running shoes with white sole" />

// ✅ GOOD: Empty alt for decorative images
<img src="/decoration.jpg" alt="" />
```

---

## Summary: Quick Anti-Pattern Checklist

Avoid these common mistakes:

- [ ] Using useEffect for derived state (calculate during render)
- [ ] Prop drilling (use Context or state management)
- [ ] Inline functions in render (use useCallback)
- [ ] Array index as key (use stable unique IDs)
- [ ] One giant context (split by concern)
- [ ] Not memoizing context values (use useMemo)
- [ ] God components (break into smaller components)
- [ ] Premature optimization (measure first)
- [ ] TypeScript `any` (use proper types)
- [ ] Div as button (use semantic HTML)

---

**Remember**: "The best code is no code. The second best is simple, working code. Premature optimization is the root of all evil." — Adapted from Donald Knuth

Focus on:
1. **Correctness** first
2. **Readability** second
3. **Performance** third (but only where it matters)
