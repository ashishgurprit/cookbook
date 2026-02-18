/**
 * Playwright E2E Test Template
 *
 * Purpose: Test complete user workflows in a real browser
 * Framework: Playwright
 *
 * Usage:
 *   1. Copy this template
 *   2. Replace {FeatureName}, selectors, etc.
 *   3. Configure test environment
 *   4. Run: npx playwright test
 *
 * Installation:
 *   npm install -D @playwright/test
 *   npx playwright install
 */

// ============================================================================
// IMPORTS
// ============================================================================

import { test, expect, Page } from '@playwright/test';

// ============================================================================
// TEST CONFIGURATION
// ============================================================================

test.describe('{FeatureName} E2E Tests', () => {
  let page: Page;

  // ──────────────────────────────────────────────────────────────────────
  // Setup & Teardown
  // ──────────────────────────────────────────────────────────────────────

  test.beforeEach(async ({ page: testPage, context }) => {
    page = testPage;

    // Set viewport
    await page.setViewportSize({ width: 1280, height: 720 });

    // Setup authentication (if needed)
    await context.addCookies([{
      name: 'session',
      value: 'test-session-token',
      domain: 'localhost',
      path: '/'
    }]);

    // Navigate to starting page
    await page.goto('http://localhost:3000');
  });

  test.afterEach(async () => {
    // Cleanup: Clear local storage, cookies, etc.
    await page.evaluate(() => localStorage.clear());
  });

  // ──────────────────────────────────────────────────────────────────────
  // Happy Path - Complete User Flow
  // ──────────────────────────────────────────────────────────────────────

  test('should complete {featureName} workflow successfully', async () => {
    // Step 1: Navigate to feature
    await page.click('[data-testid="nav-{feature}"]');
    await expect(page).toHaveURL(/.*\/{feature}/);

    // Step 2: Fill out form
    await page.fill('[data-testid="input-name"]', 'Test Name');
    await page.fill('[data-testid="input-email"]', 'test@example.com');
    await page.selectOption('[data-testid="select-category"]', 'option1');

    // Step 3: Submit
    await page.click('[data-testid="btn-submit"]');

    // Step 4: Verify success
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Success');

    // Step 5: Verify data appears in list
    await expect(page.locator('[data-testid="item-list"]')).toContainText('Test Name');
  });

  // ──────────────────────────────────────────────────────────────────────
  // Authentication Flow
  // ──────────────────────────────────────────────────────────────────────

  test('should login successfully with valid credentials', async () => {
    // Navigate to login page
    await page.goto('http://localhost:3000/login');

    // Fill login form
    await page.fill('[data-testid="input-email"]', 'user@example.com');
    await page.fill('[data-testid="input-password"]', 'Password123!');

    // Submit
    await page.click('[data-testid="btn-login"]');

    // Wait for redirect
    await page.waitForURL('**/dashboard');

    // Verify logged in
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();
    await expect(page.locator('[data-testid="user-menu"]')).toContainText('user@example.com');
  });

  test('should show error for invalid credentials', async () => {
    await page.goto('http://localhost:3000/login');

    await page.fill('[data-testid="input-email"]', 'invalid@example.com');
    await page.fill('[data-testid="input-password"]', 'WrongPassword');

    await page.click('[data-testid="btn-login"]');

    // Should show error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid credentials');

    // Should stay on login page
    await expect(page).toHaveURL(/.*\/login/);
  });

  test('should logout successfully', async () => {
    // Assume already logged in
    await page.goto('http://localhost:3000/dashboard');

    // Click user menu
    await page.click('[data-testid="user-menu"]');

    // Click logout
    await page.click('[data-testid="btn-logout"]');

    // Should redirect to login
    await page.waitForURL('**/login');

    // Verify not authenticated
    await expect(page.locator('[data-testid="user-menu"]')).not.toBeVisible();
  });

  // ──────────────────────────────────────────────────────────────────────
  // Form Validation
  // ──────────────────────────────────────────────────────────────────────

  test('should validate required fields', async () => {
    await page.goto('http://localhost:3000/{feature}/new');

    // Try to submit empty form
    await page.click('[data-testid="btn-submit"]');

    // Should show validation errors
    await expect(page.locator('[data-testid="error-name"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-email"]')).toBeVisible();
  });

  test('should validate email format', async () => {
    await page.goto('http://localhost:3000/{feature}/new');

    await page.fill('[data-testid="input-email"]', 'invalid-email');
    await page.click('[data-testid="btn-submit"]');

    await expect(page.locator('[data-testid="error-email"]')).toContainText('valid email');
  });

  // ──────────────────────────────────────────────────────────────────────
  // CRUD Operations
  // ──────────────────────────────────────────────────────────────────────

  test('should create, read, update, and delete item', async () => {
    // CREATE
    await page.goto('http://localhost:3000/{resource}/new');
    await page.fill('[data-testid="input-name"]', 'Test Item');
    await page.click('[data-testid="btn-save"]');

    // Wait for redirect to detail page
    await page.waitForURL(/.*\/{resource}\/\d+/);

    // READ
    await expect(page.locator('h1')).toContainText('Test Item');

    // UPDATE
    await page.click('[data-testid="btn-edit"]');
    await page.fill('[data-testid="input-name"]', 'Updated Item');
    await page.click('[data-testid="btn-save"]');

    await expect(page.locator('h1')).toContainText('Updated Item');

    // DELETE
    await page.click('[data-testid="btn-delete"]');

    // Confirm deletion
    await page.click('[data-testid="btn-confirm-delete"]');

    // Should redirect to list page
    await page.waitForURL(/.*\/{resource}$/);

    // Item should not be in list
    await expect(page.locator('[data-testid="item-list"]')).not.toContainText('Updated Item');
  });

  // ──────────────────────────────────────────────────────────────────────
  // Navigation
  // ──────────────────────────────────────────────────────────────────────

  test('should navigate between pages using menu', async () => {
    await page.goto('http://localhost:3000/dashboard');

    // Navigate to different sections
    await page.click('[data-testid="nav-dashboard"]');
    await expect(page).toHaveURL(/.*\/dashboard/);

    await page.click('[data-testid="nav-settings"]');
    await expect(page).toHaveURL(/.*\/settings/);

    await page.click('[data-testid="nav-profile"]');
    await expect(page).toHaveURL(/.*\/profile/);
  });

  test('should handle browser back/forward buttons', async () => {
    await page.goto('http://localhost:3000/page1');
    await page.goto('http://localhost:3000/page2');

    // Go back
    await page.goBack();
    await expect(page).toHaveURL(/.*\/page1/);

    // Go forward
    await page.goForward();
    await expect(page).toHaveURL(/.*\/page2/);
  });

  // ──────────────────────────────────────────────────────────────────────
  // Search and Filtering
  // ──────────────────────────────────────────────────────────────────────

  test('should search and filter results', async () => {
    await page.goto('http://localhost:3000/{resource}');

    // Enter search term
    await page.fill('[data-testid="input-search"]', 'specific item');
    await page.press('[data-testid="input-search"]', 'Enter');

    // Wait for results
    await page.waitForSelector('[data-testid="search-results"]');

    // Verify filtered results
    const results = page.locator('[data-testid="result-item"]');
    await expect(results).toHaveCount(1);
    await expect(results.first()).toContainText('specific item');
  });

  test('should apply filters', async () => {
    await page.goto('http://localhost:3000/{resource}');

    // Apply category filter
    await page.selectOption('[data-testid="filter-category"]', 'Category A');

    // Apply status filter
    await page.click('[data-testid="filter-active"]');

    // Verify URL params
    await expect(page).toHaveURL(/.*category=Category%20A.*active=true/);

    // Verify filtered results
    const items = page.locator('[data-testid="result-item"]');
    const count = await items.count();
    expect(count).toBeGreaterThan(0);
  });

  // ──────────────────────────────────────────────────────────────────────
  // File Upload
  // ──────────────────────────────────────────────────────────────────────

  test('should upload file successfully', async () => {
    await page.goto('http://localhost:3000/upload');

    // Set file input
    const fileInput = page.locator('[data-testid="input-file"]');
    await fileInput.setInputFiles('./test-fixtures/sample.pdf');

    // Submit
    await page.click('[data-testid="btn-upload"]');

    // Wait for upload completion
    await expect(page.locator('[data-testid="upload-success"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-name"]')).toContainText('sample.pdf');
  });

  // ──────────────────────────────────────────────────────────────────────
  // Accessibility Tests
  // ──────────────────────────────────────────────────────────────────────

  test('should be keyboard navigable', async () => {
    await page.goto('http://localhost:3000/form');

    // Tab through form fields
    await page.keyboard.press('Tab');
    await expect(page.locator('[data-testid="input-name"]')).toBeFocused();

    await page.keyboard.press('Tab');
    await expect(page.locator('[data-testid="input-email"]')).toBeFocused();

    await page.keyboard.press('Tab');
    await expect(page.locator('[data-testid="btn-submit"]')).toBeFocused();

    // Submit with Enter key
    await page.keyboard.press('Enter');
  });

  test('should have proper ARIA labels', async () => {
    await page.goto('http://localhost:3000/form');

    // Verify ARIA labels
    const nameInput = page.locator('[data-testid="input-name"]');
    await expect(nameInput).toHaveAttribute('aria-label', 'Name');

    const submitButton = page.locator('[data-testid="btn-submit"]');
    await expect(submitButton).toHaveAttribute('aria-label', 'Submit form');
  });

  // ──────────────────────────────────────────────────────────────────────
  // Responsive Design
  // ──────────────────────────────────────────────────────────────────────

  test('should work on mobile viewport', async () => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    await page.goto('http://localhost:3000');

    // Mobile menu should be visible
    await expect(page.locator('[data-testid="mobile-menu-button"]')).toBeVisible();

    // Click to expand menu
    await page.click('[data-testid="mobile-menu-button"]');

    // Menu should expand
    await expect(page.locator('[data-testid="mobile-nav"]')).toBeVisible();
  });

  // ──────────────────────────────────────────────────────────────────────
  // Error Handling
  // ──────────────────────────────────────────────────────────────────────

  test('should handle network errors gracefully', async () => {
    // Simulate offline
    await page.context().setOffline(true);

    await page.goto('http://localhost:3000/{resource}/new');
    await page.fill('[data-testid="input-name"]', 'Test');
    await page.click('[data-testid="btn-submit"]');

    // Should show network error
    await expect(page.locator('[data-testid="error-network"]')).toBeVisible();

    // Go back online
    await page.context().setOffline(false);

    // Retry should work
    await page.click('[data-testid="btn-retry"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
  });

  // ──────────────────────────────────────────────────────────────────────
  // Performance
  // ──────────────────────────────────────────────────────────────────────

  test('should load page within performance budget', async () => {
    const startTime = Date.now();

    await page.goto('http://localhost:3000');
    await page.waitForLoadState('networkidle');

    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(3000); // 3 seconds
  });

  // ──────────────────────────────────────────────────────────────────────
  // Visual Regression (requires @playwright/test with screenshots)
  // ──────────────────────────────────────────────────────────────────────

  test('should match visual snapshot', async () => {
    await page.goto('http://localhost:3000/{page}');

    // Take screenshot and compare with baseline
    await expect(page).toHaveScreenshot('page-{name}.png');
  });
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function login(page: Page, email: string, password: string) {
  await page.goto('http://localhost:3000/login');
  await page.fill('[data-testid="input-email"]', email);
  await page.fill('[data-testid="input-password"]', password);
  await page.click('[data-testid="btn-login"]');
  await page.waitForURL('**/dashboard');
}

async function createTestData(page: Page, data: any) {
  // Helper to seed test data via API or UI
}

// ============================================================================
// PLAYWRIGHT CONFIGURATION (playwright.config.ts)
// ============================================================================

/*
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    {
      name: 'Mobile Chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'Mobile Safari',
      use: { ...devices['iPhone 12'] },
    },
  ],
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
  },
});
*/

// ============================================================================
// RUN COMMANDS
// ============================================================================

/*
# Run all tests
npx playwright test

# Run specific test file
npx playwright test {filename}

# Run in headed mode (see browser)
npx playwright test --headed

# Run in debug mode
npx playwright test --debug

# Run specific browser
npx playwright test --project=chromium

# Run mobile tests
npx playwright test --project="Mobile Chrome"

# Generate test code
npx playwright codegen http://localhost:3000

# Show test report
npx playwright show-report

# Update snapshots
npx playwright test --update-snapshots
*/
