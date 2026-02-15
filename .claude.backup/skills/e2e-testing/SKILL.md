# E2E Testing Skill

**Purpose:** Comprehensive end-to-end testing framework using Puppeteer for frontend, middleware, and backend testing.

**When to use:** When you need to validate complete user workflows, API integrations, or full-stack functionality across the entire application stack.

---

## Overview

This skill provides Puppeteer-based E2E testing templates and utilities for testing at three critical layers:

1. **Frontend E2E**: User interface interactions, forms, navigation, accessibility
2. **Middleware E2E**: API endpoints, authentication, session management, data transformation
3. **Backend E2E**: Complete workflows, data persistence, third-party integrations

### Test Pyramid Position

E2E tests sit at the top of the test pyramid:
- **Volume**: 10% of total tests
- **Speed**: Slowest (seconds to minutes)
- **Scope**: Widest (entire stack)
- **Cost**: Highest (complex setup, maintenance)

---

## Quick Start

### Installation

```bash
# Install dependencies
npm install --save-dev puppeteer jest-puppeteer

# Or with specific Puppeteer version
npm install --save-dev puppeteer@21.6.1 jest-puppeteer
```

### Configuration

Create `jest-puppeteer.config.js`:
```javascript
module.exports = {
  launch: {
    headless: true,
    slowMo: 50,
    defaultViewport: {
      width: 1920,
      height: 1080
    },
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage'
    ]
  },
  browserContext: 'default',
  exitOnPageError: false
};
```

Update `jest.config.js`:
```javascript
module.exports = {
  preset: 'jest-puppeteer',
  testMatch: ['**/e2e/**/*.test.js'],
  testTimeout: 30000,
  setupFilesAfterEnv: ['<rootDir>/e2e/setup.js']
};
```

---

## Usage

### Generate Test from Template

```bash
# Frontend E2E test
cp .claude/skills/e2e-testing/templates/frontend-e2e.template.js \
   tests/e2e/login-flow.test.js

# Middleware E2E test
cp .claude/skills/e2e-testing/templates/middleware-e2e.template.js \
   tests/e2e/api-auth.test.js

# Backend E2E test
cp .claude/skills/e2e-testing/templates/backend-e2e.template.js \
   tests/e2e/user-registration.test.js
```

### Run Tests

```bash
# Run all E2E tests
npm run test:e2e

# Run with headed browser (see what's happening)
npm run test:e2e:headed

# Run specific test file
npm test tests/e2e/login-flow.test.js

# Run with debugging
PWDEBUG=1 npm test tests/e2e/login-flow.test.js
```

---

## Templates

### 1. Frontend E2E Template

**File**: `templates/frontend-e2e.template.js`

**Use for:**
- User login/logout flows
- Form submissions and validation
- Navigation and routing
- UI state changes
- Accessibility testing
- Responsive design testing

**Example:**
```javascript
describe('Login Flow', () => {
  test('should login successfully with valid credentials', async () => {
    await page.goto('http://localhost:3000/login');

    await page.type('#email', 'user@example.com');
    await page.type('#password', 'SecurePass123!');
    await page.click('button[type="submit"]');

    await page.waitForNavigation();
    expect(page.url()).toBe('http://localhost:3000/dashboard');
  });
});
```

### 2. Middleware E2E Template

**File**: `templates/middleware-e2e.template.js`

**Use for:**
- API endpoint testing
- Authentication flows
- Session management
- Rate limiting
- CORS validation
- Error handling

**Example:**
```javascript
describe('API Authentication Middleware', () => {
  test('should reject request without auth token', async () => {
    const response = await page.evaluate(async () => {
      const res = await fetch('http://localhost:3000/api/protected', {
        method: 'GET'
      });
      return { status: res.status, body: await res.json() };
    });

    expect(response.status).toBe(401);
    expect(response.body.error).toBe('Unauthorized');
  });
});
```

### 3. Backend E2E Template

**File**: `templates/backend-e2e.template.js`

**Use for:**
- Complete user workflows
- Multi-step processes
- Data persistence validation
- Third-party integrations
- Email/SMS verification
- Payment processing

**Example:**
```javascript
describe('User Registration Workflow', () => {
  test('should complete full registration flow', async () => {
    // 1. Register
    await page.goto('http://localhost:3000/register');
    await fillRegistrationForm(page);
    await page.click('button[type="submit"]');

    // 2. Verify email sent (check test inbox)
    const verificationLink = await getVerificationEmail();
    await page.goto(verificationLink);

    // 3. Verify account created in database
    const user = await db.findUserByEmail('newuser@example.com');
    expect(user.verified).toBe(true);

    // 4. Login with new account
    await loginAsUser(page, 'newuser@example.com', 'password123');
    expect(page.url()).toContain('/dashboard');
  });
});
```

---

## Best Practices

### 1. Test Organization

```
tests/
└── e2e/
    ├── setup.js                    # Global setup
    ├── teardown.js                 # Global teardown
    ├── helpers/                    # Reusable helpers
    │   ├── auth.js
    │   ├── database.js
    │   └── navigation.js
    ├── fixtures/                   # Test data
    │   └── users.json
    └── tests/
        ├── frontend/               # UI tests
        │   ├── login.test.js
        │   └── checkout.test.js
        ├── middleware/             # API tests
        │   ├── auth.test.js
        │   └── rate-limit.test.js
        └── backend/                # Full-stack tests
            ├── registration.test.js
            └── payment.test.js
```

### 2. Selectors Strategy

**Prefer data attributes:**
```javascript
// Good - stable, semantic
await page.click('[data-testid="login-button"]');

// Okay - if unique and stable
await page.click('#login-button');

// Avoid - brittle, implementation-dependent
await page.click('.btn.btn-primary.mt-4');
```

### 3. Waiting Strategy

```javascript
// ✅ Wait for navigation
await page.click('a[href="/dashboard"]');
await page.waitForNavigation();

// ✅ Wait for element
await page.waitForSelector('[data-testid="dashboard-content"]');

// ✅ Wait for network idle
await page.goto(url, { waitUntil: 'networkidle2' });

// ✅ Wait for specific condition
await page.waitForFunction(() => {
  return document.querySelector('.spinner') === null;
});

// ❌ Avoid arbitrary waits
await page.waitForTimeout(3000); // Flaky!
```

### 4. Error Handling

```javascript
test('should handle network errors gracefully', async () => {
  // Simulate network failure
  await page.setOfflineMode(true);

  await page.click('[data-testid="submit-button"]');

  // Should show error message
  const errorMessage = await page.waitForSelector('.error-message');
  expect(await errorMessage.textContent()).toContain('Network error');

  // Restore connection
  await page.setOfflineMode(false);
});
```

### 5. Test Data Management

```javascript
// ✅ Create fresh data for each test
beforeEach(async () => {
  await db.seed.testUsers();
});

afterEach(async () => {
  await db.clean.testUsers();
});

// ✅ Use factories
const user = await createTestUser({
  email: 'test@example.com',
  role: 'admin'
});

// ❌ Avoid shared state between tests
let globalUser; // Don't do this!
```

---

## Common Patterns

### Authentication Helper

```javascript
// e2e/helpers/auth.js
export async function loginAsUser(page, email, password) {
  await page.goto('http://localhost:3000/login');
  await page.type('[data-testid="email-input"]', email);
  await page.type('[data-testid="password-input"]', password);
  await page.click('[data-testid="login-button"]');
  await page.waitForNavigation();
}

export async function getAuthToken(page) {
  return page.evaluate(() => localStorage.getItem('authToken'));
}
```

### Form Filling Helper

```javascript
// e2e/helpers/forms.js
export async function fillForm(page, formData) {
  for (const [fieldName, value] of Object.entries(formData)) {
    const selector = `[name="${fieldName}"]`;
    await page.waitForSelector(selector);
    await page.type(selector, value);
  }
}

// Usage
await fillForm(page, {
  firstName: 'John',
  lastName: 'Doe',
  email: 'john@example.com'
});
```

### Screenshot on Failure

```javascript
// e2e/setup.js
afterEach(async () => {
  if (global.testResult?.status === 'failed') {
    const testName = expect.getState().currentTestName;
    const screenshotPath = `screenshots/${testName}.png`;
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.log(`Screenshot saved: ${screenshotPath}`);
  }
});
```

### API Mocking

```javascript
test('should display products from API', async () => {
  // Intercept API call and return mock data
  await page.setRequestInterception(true);

  page.on('request', request => {
    if (request.url().includes('/api/products')) {
      request.respond({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 1, name: 'Product 1', price: 29.99 },
          { id: 2, name: 'Product 2', price: 39.99 }
        ])
      });
    } else {
      request.continue();
    }
  });

  await page.goto('http://localhost:3000/products');

  const products = await page.$$('[data-testid="product-card"]');
  expect(products).toHaveLength(2);
});
```

---

## Performance Optimization

### 1. Parallel Execution

```javascript
// jest.config.js
module.exports = {
  maxWorkers: 4, // Run 4 tests in parallel
  // or
  maxWorkers: '50%' // Use 50% of CPU cores
};
```

### 2. Reuse Browser Context

```javascript
// e2e/setup.js
let browser;
let context;

beforeAll(async () => {
  browser = await puppeteer.launch();
  context = await browser.createIncognitoBrowserContext();
});

beforeEach(async () => {
  page = await context.newPage();
});

afterEach(async () => {
  await page.close();
});

afterAll(async () => {
  await context.close();
  await browser.close();
});
```

### 3. Resource Blocking

```javascript
// Block unnecessary resources to speed up tests
await page.setRequestInterception(true);

page.on('request', request => {
  const blockedResources = ['image', 'stylesheet', 'font'];
  if (blockedResources.includes(request.resourceType())) {
    request.abort();
  } else {
    request.continue();
  }
});
```

---

## Debugging

### 1. Headed Mode

```bash
# See the browser while tests run
HEADLESS=false npm test
```

### 2. Slow Motion

```javascript
// jest-puppeteer.config.js
module.exports = {
  launch: {
    headless: false,
    slowMo: 100 // Slow down by 100ms per action
  }
};
```

### 3. DevTools

```javascript
// Pause execution and open DevTools
await page.evaluate(() => {
  debugger;
});
```

### 4. Console Logs

```javascript
// Capture browser console logs
page.on('console', msg => console.log('BROWSER LOG:', msg.text()));
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  e2e:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Start application
        run: npm start &

      - name: Wait for app
        run: npx wait-on http://localhost:3000

      - name: Run E2E tests
        run: npm run test:e2e

      - name: Upload screenshots
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: screenshots
          path: screenshots/
```

---

## Scripts

### Test Runner

**File**: `scripts/run-e2e-tests.sh`

```bash
#!/bin/bash
# Comprehensive E2E test runner with environment setup
./scripts/run-e2e-tests.sh --env=staging --headed
```

---

## Examples

See `examples/` directory for complete working examples:

- `examples/frontend-login.test.js` - Complete login flow test
- `examples/middleware-api-auth.test.js` - API authentication test
- `examples/backend-checkout.test.js` - Full checkout workflow
- `examples/accessibility.test.js` - Accessibility testing
- `examples/visual-regression.test.js` - Visual regression testing

---

## Troubleshooting

### Issue: Tests timeout

**Solution:**
```javascript
// Increase timeout for slow operations
test('slow operation', async () => {
  // ... test code
}, 60000); // 60 second timeout

// Or globally in jest.config.js
module.exports = {
  testTimeout: 60000
};
```

### Issue: Element not found

**Solution:**
```javascript
// Wait for element before interacting
await page.waitForSelector('[data-testid="button"]', {
  visible: true,
  timeout: 5000
});
await page.click('[data-testid="button"]');
```

### Issue: Tests fail in CI but pass locally

**Solution:**
```javascript
// Ensure consistent viewport
await page.setViewport({
  width: 1920,
  height: 1080
});

// Wait for network idle
await page.goto(url, { waitUntil: 'networkidle2' });

// Add explicit waits
await page.waitForSelector('[data-testid="content"]');
```

---

## Related Skills

- `/testing-strategies` - Overall testing strategy and test pyramid
- `/code-review` - Review E2E test code quality
- `/deployment-patterns` - Run E2E tests as part of deployment smoke tests

---

## Resources

- [Puppeteer Documentation](https://pptr.dev/)
- [Jest-Puppeteer](https://github.com/smooth-code/jest-puppeteer)
- [Puppeteer Recorder](https://chrome.google.com/webstore/detail/puppeteer-recorder) - Chrome extension to record interactions

---

**Remember:** E2E tests are expensive. Use them for critical user journeys only. Cover edge cases with unit and integration tests.
