# Canva Engineering Practices

> Best practices from Canva's engineering culture.
> Sources: Canva Engineering Blog, Tech Talks

## Core Principles

### 1. Design-First Development

Always start with design, not code:

```
┌─────────────────────────────────────────────────────────────┐
│                 DESIGN-FIRST FLOW                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   User Need → Design Exploration → Prototype → Validate     │
│                                         ↓                   │
│                                    Build Only               │
│                                  After Validation           │
│                                                             │
│   "The best code is code you never had to write"           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Questions before coding:**
- What problem are we solving?
- Who are we solving it for?
- How will we know it's solved?
- Is there a simpler solution?

### 2. Component-Driven Development

Build reusable, composable components:

```typescript
// Canva's component principles

// 1. Single Responsibility
// BAD
const UserCard = ({ user, onEdit, onDelete, onShare }) => {...}

// GOOD
const UserAvatar = ({ src, name }) => {...}
const UserInfo = ({ name, email }) => {...}
const ActionMenu = ({ actions }) => {...}

// 2. Composition over Configuration
// BAD - prop explosion
<Button primary large disabled loading icon="save" />

// GOOD - composable
<Button variant="primary" size="large">
  <LoadingSpinner />
  <Icon name="save" />
  Save
</Button>

// 3. Sensible Defaults
const Button = ({
  variant = 'secondary',
  size = 'medium',
  type = 'button',
  ...props
}) => {...}
```

### 3. Performance at Scale

Canva serves billions of designs:

**Image Optimization**
```typescript
// Lazy loading with intersection observer
const LazyImage = ({ src, alt }) => {
  const [isVisible, ref] = useIntersectionObserver();

  return (
    <div ref={ref}>
      {isVisible ? (
        <img src={src} alt={alt} loading="lazy" />
      ) : (
        <Placeholder />
      )}
    </div>
  );
};

// Responsive images
<picture>
  <source srcset="image-400.webp 400w, image-800.webp 800w" type="image/webp" />
  <source srcset="image-400.jpg 400w, image-800.jpg 800w" type="image/jpeg" />
  <img src="image-400.jpg" alt="..." loading="lazy" />
</picture>
```

**Bundle Optimization**
```typescript
// Code splitting by route
const Editor = lazy(() => import('./Editor'));
const Dashboard = lazy(() => import('./Dashboard'));

// Feature-based splitting
const AdvancedTools = lazy(() =>
  import(/* webpackChunkName: "advanced-tools" */ './AdvancedTools')
);
```

**Render Performance**
```typescript
// Virtualization for large lists
import { FixedSizeList } from 'react-window';

const DesignList = ({ designs }) => (
  <FixedSizeList
    height={600}
    itemCount={designs.length}
    itemSize={200}
  >
    {({ index, style }) => (
      <DesignCard design={designs[index]} style={style} />
    )}
  </FixedSizeList>
);

// Memoization
const ExpensiveComponent = memo(({ data }) => {
  const processed = useMemo(() => heavyComputation(data), [data]);
  return <div>{processed}</div>;
});
```

### 4. Internationalization (i18n)

Canva supports 100+ languages:

```typescript
// 1. Never hardcode strings
// BAD
<button>Save</button>

// GOOD
<button>{t('actions.save')}</button>

// 2. Handle pluralization
t('items.count', { count: items.length })
// en: "1 item" / "5 items"
// ru: "1 элемент" / "2 элемента" / "5 элементов"

// 3. Handle RTL languages
const styles = {
  marginLeft: isRTL ? 0 : spacing,
  marginRight: isRTL ? spacing : 0,
  // Better: use logical properties
  marginInlineStart: spacing,
};

// 4. Format dates/numbers locally
new Intl.DateTimeFormat(locale).format(date)
new Intl.NumberFormat(locale, { style: 'currency', currency }).format(amount)
```

### 5. Accessibility (a11y)

Design for everyone:

```typescript
// 1. Semantic HTML
// BAD
<div onClick={handleClick}>Click me</div>

// GOOD
<button onClick={handleClick}>Click me</button>

// 2. ARIA when needed
<div
  role="tabpanel"
  aria-labelledby="tab-1"
  aria-hidden={!isActive}
>

// 3. Keyboard navigation
const handleKeyDown = (e) => {
  switch (e.key) {
    case 'ArrowRight': focusNext(); break;
    case 'ArrowLeft': focusPrev(); break;
    case 'Enter':
    case ' ': select(); break;
    case 'Escape': close(); break;
  }
};

// 4. Focus management
const Modal = ({ isOpen, onClose, children }) => {
  const firstFocusRef = useRef();

  useEffect(() => {
    if (isOpen) firstFocusRef.current?.focus();
  }, [isOpen]);

  return (
    <FocusTrap>
      <div role="dialog" aria-modal="true">
        <button ref={firstFocusRef} onClick={onClose}>
          Close
        </button>
        {children}
      </div>
    </FocusTrap>
  );
};

// 5. Color contrast
// Minimum 4.5:1 for normal text
// Minimum 3:1 for large text
// Don't convey info by color alone
```

### 6. Collaboration Features

Building for real-time collaboration:

```typescript
// Optimistic updates
const updateDesign = async (change) => {
  // 1. Apply immediately (optimistic)
  dispatch({ type: 'APPLY_CHANGE', change });

  try {
    // 2. Sync to server
    await api.saveChange(change);
  } catch (error) {
    // 3. Rollback on failure
    dispatch({ type: 'ROLLBACK_CHANGE', change });
    showError('Failed to save');
  }
};

// Conflict resolution (Last Write Wins with Transform)
const resolveConflict = (localChange, remoteChange) => {
  if (remoteChange.timestamp > localChange.timestamp) {
    return transform(localChange, remoteChange);
  }
  return localChange;
};

// Presence indicators
const Cursors = ({ collaborators }) => (
  <>
    {collaborators.map(user => (
      <Cursor
        key={user.id}
        position={user.cursor}
        color={user.color}
        name={user.name}
      />
    ))}
  </>
);
```

### 7. Feature Flags

Safe rollouts:

```typescript
// Feature flag usage
const NewEditor = () => {
  const { isEnabled } = useFeatureFlag('new-editor-v2');

  if (!isEnabled) {
    return <OldEditor />;
  }

  return <EditorV2 />;
};

// Gradual rollout
const flagConfig = {
  'new-editor-v2': {
    enabled: true,
    rolloutPercentage: 10, // 10% of users
    allowlist: ['beta-testers'],
    blocklist: ['enterprise-critical'],
  }
};

// Kill switch
if (await checkKillSwitch('new-editor-v2')) {
  return <FallbackUI />;
}
```

### 8. Observability

Monitor everything:

```typescript
// Structured logging
logger.info('design.saved', {
  designId: design.id,
  userId: user.id,
  duration: endTime - startTime,
  size: design.elements.length,
});

// Performance metrics
performance.mark('render-start');
// ... render ...
performance.mark('render-end');
performance.measure('render-time', 'render-start', 'render-end');

// Error tracking with context
Sentry.withScope(scope => {
  scope.setUser({ id: user.id });
  scope.setTag('feature', 'editor');
  scope.setContext('design', { id: design.id, type: design.type });
  Sentry.captureException(error);
});
```

## Quick Reference

| Practice | Key Principle |
|----------|---------------|
| Design-First | Validate before building |
| Components | Composable, single-purpose |
| Performance | Lazy load, virtualize, memoize |
| i18n | No hardcoded strings |
| a11y | Semantic HTML, keyboard nav |
| Collaboration | Optimistic updates |
| Feature Flags | Gradual, safe rollouts |
| Observability | Log everything |
