# E2E Testing Examples

This directory contains complete working examples of E2E tests using Puppeteer.

## Files

### Configuration

- **jest-puppeteer.config.js** - Jest-Puppeteer configuration
  - Browser launch settings
  - Viewport configuration
  - Server startup options

- **setup.js** - Global test setup and teardown
  - Custom Jest matchers
  - Screenshot capture on failure
  - Helper functions

### Example Tests

- **login-flow.test.js** - Complete login/logout flow example
  - Successful login with valid credentials
  - Form validation errors
  - Failed login attempts and account lockout
  - Password reset flow
  - Logout and session management
  - Accessibility testing
  - Security checks

## Quick Start

### 1. Copy Configuration Files

```bash
# Copy to your project root
cp jest-puppeteer.config.js /path/to/your/project/

# Copy to your test directory
cp setup.js /path/to/your/project/tests/e2e/
```

### 2. Update package.json

```json
{
  "scripts": {
    "test:e2e": "jest tests/e2e",
    "test:e2e:headed": "HEADLESS=false jest tests/e2e",
    "test:e2e:debug": "PWDEBUG=1 jest tests/e2e"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "jest-puppeteer": "^9.0.0",
    "puppeteer": "^21.0.0"
  }
}
```

### 3. Update jest.config.js

```javascript
module.exports = {
  preset: 'jest-puppeteer',
  testMatch: ['**/tests/e2e/**/*.test.js'],
  testTimeout: 30000,
  setupFilesAfterEnv: ['<rootDir>/tests/e2e/setup.js']
};
```

### 4. Run Tests

```bash
# Run all E2E tests
npm run test:e2e

# Run with visible browser
npm run test:e2e:headed

# Run specific test
npm test tests/e2e/login-flow.test.js

# Run with debugging
npm run test:e2e:debug
```

## Example Test Structure

```javascript
describe('Feature Name', () => {
  let testPage;

  beforeEach(async () => {
    testPage = await browser.newPage();
    await testPage.goto('http://localhost:3000');
  });

  afterEach(async () => {
    await testPage.close();
  });

  test('should do something', async () => {
    // Arrange
    await testPage.type('#input', 'value');

    // Act
    await testPage.click('#submit');

    // Assert
    const result = await testPage.$eval('#result', el => el.textContent);
    expect(result).toBe('expected');
  });
});
```

## Best Practices Demonstrated

### 1. Data Attributes for Selectors

```javascript
// ✅ Good - stable, semantic
await page.click('[data-testid="login-button"]');

// ❌ Avoid - brittle
await page.click('.btn.btn-primary.mt-4');
```

### 2. Explicit Waits

```javascript
// ✅ Wait for specific condition
await page.waitForSelector('[data-testid="success"]', { visible: true });

// ❌ Avoid arbitrary timeouts
await page.waitForTimeout(3000);
```

### 3. Screenshot on Failure

```javascript
afterEach(async () => {
  if (global.testResult?.status === 'failed') {
    await page.screenshot({ path: `screenshots/${testName}.png` });
  }
});
```

### 4. Page Object Pattern

```javascript
// Helper function
async function loginUser(page, email, password) {
  await page.type('[data-testid="email"]', email);
  await page.type('[data-testid="password"]', password);
  await page.click('[data-testid="login"]');
  await page.waitForNavigation();
}

// Use in test
await loginUser(testPage, 'user@example.com', 'password');
```

### 5. Accessibility Testing

```javascript
test('should be keyboard navigable', async () => {
  await page.keyboard.press('Tab');
  let focused = await page.evaluate(() =>
    document.activeElement.getAttribute('data-testid')
  );
  expect(focused).toBe('email-input');
});
```

## Common Patterns

### API Mocking

```javascript
await page.setRequestInterception(true);
page.on('request', request => {
  if (request.url().includes('/api/data')) {
    request.respond({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: 'mocked' })
    });
  } else {
    request.continue();
  }
});
```

### Form Filling

```javascript
async function fillForm(page, formData) {
  for (const [field, value] of Object.entries(formData)) {
    await page.type(`[name="${field}"]`, value);
  }
}

await fillForm(page, {
  email: 'user@example.com',
  password: 'password123'
});
```

### Authentication Helper

```javascript
async function authenticateUser(page) {
  const token = await page.evaluate(async () => {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: 'user@example.com',
        password: 'password123'
      })
    });
    const data = await response.json();
    return data.token;
  });

  await page.evaluate((token) => {
    localStorage.setItem('authToken', token);
  }, token);
}
```

### Waiting for Network Idle

```javascript
await page.goto(url, { waitUntil: 'networkidle2' });
```

### Checking Element Visibility

```javascript
const isVisible = await page.$eval(
  '[data-testid="element"]',
  el => window.getComputedStyle(el).display !== 'none'
);
```

## Debugging Tips

### 1. Run in Headed Mode

```bash
HEADLESS=false npm run test:e2e
```

### 2. Slow Down Execution

```bash
SLOW_MO=100 npm run test:e2e
```

### 3. Use Debugger

```javascript
await page.evaluate(() => {
  debugger; // Opens Chrome DevTools
});
```

### 4. Capture Screenshots at Any Point

```javascript
await page.screenshot({ path: 'debug.png', fullPage: true });
```

### 5. Console Logs

```javascript
page.on('console', msg => console.log('BROWSER:', msg.text()));
```

## Environment Variables

```bash
# Browser mode
HEADLESS=false              # Show browser window

# Debugging
PWDEBUG=1                   # Enable Playwright debug mode
SLOW_MO=100                 # Slow down by 100ms per action
VERBOSE=true                # Show detailed logs

# Environment
BASE_URL=http://localhost:3000
NODE_ENV=test

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=test_db
```

## Troubleshooting

### Tests are flaky

- Use explicit waits instead of `waitForTimeout`
- Wait for `networkidle2` instead of `load`
- Use `waitForSelector` with `visible: true`

### Element not found

```javascript
// Add explicit wait
await page.waitForSelector('[data-testid="element"]', {
  visible: true,
  timeout: 5000
});
```

### Tests timeout

```javascript
// Increase timeout for slow operations
test('slow test', async () => {
  // test code
}, 60000); // 60 second timeout
```

### Can't click on element

```javascript
// Wait for element to be clickable
await page.waitForSelector('[data-testid="button"]', { visible: true });
await page.click('[data-testid="button"]');
```

## Additional Resources

- [Puppeteer Documentation](https://pptr.dev/)
- [Jest-Puppeteer](https://github.com/smooth-code/jest-puppeteer)
- [Testing Best Practices](https://kentcdodds.com/blog/common-mistakes-with-react-testing-library)

## Next Steps

1. Copy configuration files to your project
2. Adapt the login-flow example to your application
3. Create page object helpers for common operations
4. Add more test scenarios based on critical user journeys
5. Integrate E2E tests into your CI/CD pipeline
