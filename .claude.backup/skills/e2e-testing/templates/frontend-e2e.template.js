/**
 * Frontend E2E Test Template
 * ===========================
 *
 * Purpose: Test user-facing UI interactions, forms, navigation, and visual behavior
 *
 * Use this template for:
 * - Login/logout flows
 * - Form submissions and validation
 * - Navigation and routing
 * - UI state changes
 * - Accessibility testing
 * - Responsive design
 *
 * Usage:
 * 1. Copy this template to your test directory
 * 2. Replace {FEATURE_NAME}, {URL}, {SELECTOR} placeholders
 * 3. Implement test scenarios specific to your feature
 * 4. Run with: npm test path/to/test.js
 */

describe('{FEATURE_NAME} - Frontend E2E', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  let testPage;

  // ============================================================================
  // SETUP & TEARDOWN
  // ============================================================================

  beforeAll(async () => {
    // Setup runs once before all tests
    await jestPuppeteer.resetBrowser();
  });

  beforeEach(async () => {
    // Setup runs before each test
    testPage = await browser.newPage();

    // Set viewport for consistent testing
    await testPage.setViewport({
      width: 1920,
      height: 1080
    });

    // Capture console logs from browser
    testPage.on('console', msg => {
      console.log('BROWSER LOG:', msg.text());
    });

    // Capture page errors
    testPage.on('pageerror', error => {
      console.error('PAGE ERROR:', error.message);
    });

    // Navigate to the page under test
    await testPage.goto(`${BASE_URL}/{ROUTE}`, {
      waitUntil: 'networkidle2',
      timeout: 30000
    });
  });

  afterEach(async () => {
    // Take screenshot on failure
    if (global.testResult?.status === 'failed') {
      const testName = expect.getState().currentTestName;
      const screenshotPath = `screenshots/${testName.replace(/\s+/g, '-')}.png`;
      await testPage.screenshot({
        path: screenshotPath,
        fullPage: true
      });
      console.log(`📸 Screenshot saved: ${screenshotPath}`);
    }

    await testPage.close();
  });

  afterAll(async () => {
    // Cleanup runs once after all tests
  });

  // ============================================================================
  // HAPPY PATH TESTS
  // ============================================================================

  describe('Happy Path', () => {
    test('should load the page successfully', async () => {
      // Verify page title
      const title = await testPage.title();
      expect(title).toContain('{EXPECTED_TITLE}');

      // Verify main content is visible
      await testPage.waitForSelector('[data-testid="{MAIN_CONTENT_TESTID}"]', {
        visible: true,
        timeout: 5000
      });

      // Verify no error messages
      const errorElements = await testPage.$$('[data-testid="error-message"]');
      expect(errorElements).toHaveLength(0);
    });

    test('should navigate to {TARGET_PAGE} when clicking {ELEMENT}', async () => {
      // Click navigation element
      await testPage.click('[data-testid="{NAVIGATION_TESTID}"]');

      // Wait for navigation to complete
      await testPage.waitForNavigation({ waitUntil: 'networkidle2' });

      // Verify URL changed
      const currentUrl = testPage.url();
      expect(currentUrl).toContain('{EXPECTED_URL_FRAGMENT}');

      // Verify target page loaded
      await testPage.waitForSelector('[data-testid="{TARGET_CONTENT_TESTID}"]');
    });

    test('should submit form with valid data successfully', async () => {
      // Fill form fields
      await testPage.type('[data-testid="input-field-1"]', '{VALID_VALUE_1}');
      await testPage.type('[data-testid="input-field-2"]', '{VALID_VALUE_2}');

      // Optional: Select from dropdown
      await testPage.select('[data-testid="select-field"]', '{OPTION_VALUE}');

      // Optional: Check checkbox
      await testPage.click('[data-testid="checkbox-field"]');

      // Submit form
      await testPage.click('[data-testid="submit-button"]');

      // Wait for success message or navigation
      await testPage.waitForSelector('[data-testid="success-message"]', {
        visible: true,
        timeout: 10000
      });

      // Verify success message content
      const successText = await testPage.$eval(
        '[data-testid="success-message"]',
        el => el.textContent
      );
      expect(successText).toContain('{EXPECTED_SUCCESS_MESSAGE}');
    });

    test('should display correct content after user interaction', async () => {
      // Perform interaction (e.g., click button)
      await testPage.click('[data-testid="{TRIGGER_BUTTON}"]');

      // Wait for dynamic content to appear
      await testPage.waitForSelector('[data-testid="{DYNAMIC_CONTENT}"]', {
        visible: true
      });

      // Verify content
      const contentText = await testPage.$eval(
        '[data-testid="{DYNAMIC_CONTENT}"]',
        el => el.textContent
      );
      expect(contentText).toContain('{EXPECTED_CONTENT}');
    });
  });

  // ============================================================================
  // VALIDATION TESTS
  // ============================================================================

  describe('Form Validation', () => {
    test('should show validation error for empty required field', async () => {
      // Leave required field empty
      await testPage.type('[data-testid="optional-field"]', 'some value');

      // Attempt to submit
      await testPage.click('[data-testid="submit-button"]');

      // Verify validation error appears
      await testPage.waitForSelector('[data-testid="validation-error"]', {
        visible: true
      });

      const errorText = await testPage.$eval(
        '[data-testid="validation-error"]',
        el => el.textContent
      );
      expect(errorText).toContain('{EXPECTED_ERROR_MESSAGE}');
    });

    test('should show validation error for invalid email format', async () => {
      await testPage.type('[data-testid="email-input"]', 'invalid-email');
      await testPage.click('[data-testid="submit-button"]');

      await testPage.waitForSelector('[data-testid="email-error"]');
      const errorText = await testPage.$eval(
        '[data-testid="email-error"]',
        el => el.textContent
      );
      expect(errorText).toMatch(/invalid.*email/i);
    });

    test('should disable submit button while form is invalid', async () => {
      const isDisabled = await testPage.$eval(
        '[data-testid="submit-button"]',
        el => el.disabled
      );
      expect(isDisabled).toBe(true);
    });

    test('should enable submit button when form becomes valid', async () => {
      // Fill all required fields with valid data
      await testPage.type('[data-testid="field-1"]', '{VALID_VALUE_1}');
      await testPage.type('[data-testid="field-2"]', '{VALID_VALUE_2}');

      // Wait a bit for validation to process
      await testPage.waitForTimeout(500);

      const isDisabled = await testPage.$eval(
        '[data-testid="submit-button"]',
        el => el.disabled
      );
      expect(isDisabled).toBe(false);
    });
  });

  // ============================================================================
  // ERROR HANDLING TESTS
  // ============================================================================

  describe('Error Handling', () => {
    test('should display error message when server returns error', async () => {
      // Mock API to return error
      await testPage.setRequestInterception(true);
      testPage.once('request', request => {
        if (request.url().includes('{API_ENDPOINT}')) {
          request.respond({
            status: 500,
            contentType: 'application/json',
            body: JSON.stringify({ error: '{SERVER_ERROR_MESSAGE}' })
          });
        } else {
          request.continue();
        }
      });

      // Trigger action that calls API
      await testPage.click('[data-testid="submit-button"]');

      // Verify error message displayed
      await testPage.waitForSelector('[data-testid="error-message"]', {
        visible: true
      });

      const errorText = await testPage.$eval(
        '[data-testid="error-message"]',
        el => el.textContent
      );
      expect(errorText).toContain('{EXPECTED_ERROR_TEXT}');
    });

    test('should handle network failure gracefully', async () => {
      // Simulate offline mode
      await testPage.setOfflineMode(true);

      // Trigger action
      await testPage.click('[data-testid="submit-button"]');

      // Should show network error message
      await testPage.waitForSelector('[data-testid="network-error"]', {
        visible: true,
        timeout: 5000
      });

      // Restore connection
      await testPage.setOfflineMode(false);
    });

    test('should allow retry after error', async () => {
      // Trigger error
      await testPage.click('[data-testid="action-that-fails"]');
      await testPage.waitForSelector('[data-testid="error-message"]');

      // Click retry button
      await testPage.click('[data-testid="retry-button"]');

      // Should attempt action again
      await testPage.waitForFunction(
        () => !document.querySelector('[data-testid="error-message"]')
      );
    });
  });

  // ============================================================================
  // ACCESSIBILITY TESTS
  // ============================================================================

  describe('Accessibility', () => {
    test('should be keyboard navigable', async () => {
      // Tab through interactive elements
      await testPage.keyboard.press('Tab');
      let focusedElement = await testPage.evaluate(() => document.activeElement.getAttribute('data-testid'));
      expect(focusedElement).toBe('{FIRST_INTERACTIVE_ELEMENT}');

      await testPage.keyboard.press('Tab');
      focusedElement = await testPage.evaluate(() => document.activeElement.getAttribute('data-testid'));
      expect(focusedElement).toBe('{SECOND_INTERACTIVE_ELEMENT}');

      // Press Enter on focused button
      await testPage.keyboard.press('Enter');
      // Verify action triggered
    });

    test('should have proper ARIA labels', async () => {
      const ariaLabel = await testPage.$eval(
        '[data-testid="{ELEMENT_TESTID}"]',
        el => el.getAttribute('aria-label')
      );
      expect(ariaLabel).toBeTruthy();
      expect(ariaLabel).toContain('{EXPECTED_LABEL}');
    });

    test('should have sufficient color contrast', async () => {
      // Get computed styles
      const textColor = await testPage.$eval(
        '[data-testid="{TEXT_ELEMENT}"]',
        el => window.getComputedStyle(el).color
      );
      const bgColor = await testPage.$eval(
        '[data-testid="{TEXT_ELEMENT}"]',
        el => window.getComputedStyle(el).backgroundColor
      );

      // Note: Full contrast calculation would require additional utilities
      expect(textColor).toBeTruthy();
      expect(bgColor).toBeTruthy();
    });

    test('should announce dynamic content to screen readers', async () => {
      const liveRegion = await testPage.$('[aria-live="polite"]');
      expect(liveRegion).toBeTruthy();
    });
  });

  // ============================================================================
  // RESPONSIVE DESIGN TESTS
  // ============================================================================

  describe('Responsive Design', () => {
    test('should display mobile menu on mobile viewport', async () => {
      // Set mobile viewport
      await testPage.setViewport({
        width: 375,
        height: 667
      });

      await testPage.reload({ waitUntil: 'networkidle2' });

      // Desktop menu should be hidden
      const desktopMenu = await testPage.$('[data-testid="desktop-menu"]');
      const isDesktopVisible = await desktopMenu?.isIntersectingViewport();
      expect(isDesktopVisible).toBe(false);

      // Mobile menu button should be visible
      const mobileMenuButton = await testPage.$('[data-testid="mobile-menu-button"]');
      const isMobileVisible = await mobileMenuButton?.isIntersectingViewport();
      expect(isMobileVisible).toBe(true);
    });

    test('should stack elements vertically on mobile', async () => {
      await testPage.setViewport({ width: 375, height: 667 });
      await testPage.reload({ waitUntil: 'networkidle2' });

      const element1 = await testPage.$('[data-testid="element-1"]');
      const element2 = await testPage.$('[data-testid="element-2"]');

      const box1 = await element1?.boundingBox();
      const box2 = await element2?.boundingBox();

      // Element 2 should be below element 1
      expect(box2.y).toBeGreaterThan(box1.y + box1.height);
    });

    test('should display elements side-by-side on desktop', async () => {
      await testPage.setViewport({ width: 1920, height: 1080 });
      await testPage.reload({ waitUntil: 'networkidle2' });

      const element1 = await testPage.$('[data-testid="element-1"]');
      const element2 = await testPage.$('[data-testid="element-2"]');

      const box1 = await element1?.boundingBox();
      const box2 = await element2?.boundingBox();

      // Element 2 should be to the right of element 1
      expect(box2.x).toBeGreaterThan(box1.x + box1.width);
    });
  });

  // ============================================================================
  // INTERACTION TESTS
  // ============================================================================

  describe('User Interactions', () => {
    test('should update UI state when toggling checkbox', async () => {
      const checkbox = await testPage.$('[data-testid="toggle-checkbox"]');

      // Check current state
      let isChecked = await testPage.$eval(
        '[data-testid="toggle-checkbox"]',
        el => el.checked
      );
      expect(isChecked).toBe(false);

      // Click checkbox
      await checkbox.click();

      // Verify state changed
      isChecked = await testPage.$eval(
        '[data-testid="toggle-checkbox"]',
        el => el.checked
      );
      expect(isChecked).toBe(true);

      // Verify dependent UI updated
      const dependentElement = await testPage.$('[data-testid="dependent-content"]');
      expect(dependentElement).toBeTruthy();
    });

    test('should open modal when clicking trigger button', async () => {
      await testPage.click('[data-testid="open-modal-button"]');

      await testPage.waitForSelector('[data-testid="modal"]', {
        visible: true
      });

      const modalTitle = await testPage.$eval(
        '[data-testid="modal-title"]',
        el => el.textContent
      );
      expect(modalTitle).toContain('{EXPECTED_MODAL_TITLE}');
    });

    test('should close modal when clicking close button', async () => {
      // Open modal
      await testPage.click('[data-testid="open-modal-button"]');
      await testPage.waitForSelector('[data-testid="modal"]', { visible: true });

      // Close modal
      await testPage.click('[data-testid="close-modal-button"]');

      // Verify modal is hidden
      await testPage.waitForFunction(
        () => {
          const modal = document.querySelector('[data-testid="modal"]');
          return !modal || window.getComputedStyle(modal).display === 'none';
        },
        { timeout: 5000 }
      );
    });

    test('should filter results when typing in search box', async () => {
      await testPage.type('[data-testid="search-input"]', '{SEARCH_TERM}');

      // Wait for results to update
      await testPage.waitForTimeout(500); // Debounce delay

      const results = await testPage.$$('[data-testid="search-result"]');
      expect(results.length).toBeGreaterThan(0);

      // Verify all results match search term
      for (const result of results) {
        const text = await result.evaluate(el => el.textContent);
        expect(text.toLowerCase()).toContain('{SEARCH_TERM}'.toLowerCase());
      }
    });
  });

  // ============================================================================
  // LOADING STATES
  // ============================================================================

  describe('Loading States', () => {
    test('should show loading spinner while data is fetching', async () => {
      // Slow down network to capture loading state
      const client = await testPage.target().createCDPSession();
      await client.send('Network.enable');
      await client.send('Network.emulateNetworkConditions', {
        offline: false,
        downloadThroughput: 500 * 1024 / 8,
        uploadThroughput: 500 * 1024 / 8,
        latency: 2000
      });

      await testPage.click('[data-testid="load-data-button"]');

      // Loading spinner should appear
      const spinner = await testPage.waitForSelector('[data-testid="loading-spinner"]', {
        visible: true
      });
      expect(spinner).toBeTruthy();

      // Wait for data to load
      await testPage.waitForSelector('[data-testid="data-content"]', {
        visible: true,
        timeout: 15000
      });

      // Spinner should disappear
      const spinnerVisible = await testPage.$eval(
        '[data-testid="loading-spinner"]',
        el => window.getComputedStyle(el).display !== 'none'
      );
      expect(spinnerVisible).toBe(false);
    });

    test('should disable buttons while action is in progress', async () => {
      await testPage.click('[data-testid="async-action-button"]');

      // Button should be disabled immediately
      const isDisabled = await testPage.$eval(
        '[data-testid="async-action-button"]',
        el => el.disabled
      );
      expect(isDisabled).toBe(true);

      // Wait for action to complete
      await testPage.waitForFunction(
        () => !document.querySelector('[data-testid="async-action-button"]').disabled,
        { timeout: 10000 }
      );
    });
  });

  // ============================================================================
  // HELPER FUNCTIONS
  // ============================================================================

  /**
   * Helper: Wait for element and get its text content
   */
  async function getTextContent(selector) {
    await testPage.waitForSelector(selector, { visible: true });
    return testPage.$eval(selector, el => el.textContent);
  }

  /**
   * Helper: Fill form with data object
   */
  async function fillForm(formData) {
    for (const [fieldName, value] of Object.entries(formData)) {
      const selector = `[name="${fieldName}"]`;
      await testPage.type(selector, value);
    }
  }

  /**
   * Helper: Wait for URL to change
   */
  async function waitForUrlChange(expectedFragment) {
    await testPage.waitForFunction(
      (fragment) => window.location.href.includes(fragment),
      {},
      expectedFragment
    );
  }
});
