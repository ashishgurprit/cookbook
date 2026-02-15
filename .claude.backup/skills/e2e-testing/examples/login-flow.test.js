/**
 * Example: Complete Login Flow E2E Test
 * ======================================
 *
 * This example demonstrates a complete frontend E2E test covering:
 * - Page navigation
 * - Form filling
 * - Validation
 * - Error handling
 * - Success flow
 */

describe('Login Flow - Complete Example', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  let testPage;

  beforeEach(async () => {
    testPage = await browser.newPage();

    await testPage.setViewport({
      width: 1920,
      height: 1080
    });

    // Capture console logs
    testPage.on('console', msg => {
      if (process.env.VERBOSE === 'true') {
        console.log('BROWSER:', msg.text());
      }
    });

    // Capture errors
    testPage.on('pageerror', error => {
      console.error('PAGE ERROR:', error.message);
    });
  });

  afterEach(async () => {
    // Screenshot on failure
    if (global.testResult?.status === 'failed') {
      const testName = expect.getState().currentTestName;
      const filename = testName.replace(/\s+/g, '-').toLowerCase();
      await testPage.screenshot({
        path: `screenshots/${filename}.png`,
        fullPage: true
      });
    }

    await testPage.close();
  });

  describe('Successful Login', () => {
    test('should login with valid credentials', async () => {
      // Navigate to login page
      await testPage.goto(`${BASE_URL}/login`, {
        waitUntil: 'networkidle2'
      });

      // Verify we're on login page
      const title = await testPage.title();
      expect(title).toContain('Login');

      // Fill in credentials
      await testPage.type('[data-testid="email-input"]', 'user@example.com');
      await testPage.type('[data-testid="password-input"]', 'SecurePass123!');

      // Submit form
      await testPage.click('[data-testid="login-button"]');

      // Wait for navigation to dashboard
      await testPage.waitForNavigation({
        waitUntil: 'networkidle2',
        timeout: 10000
      });

      // Verify redirect to dashboard
      const currentUrl = testPage.url();
      expect(currentUrl).toContain('/dashboard');

      // Verify user is logged in (check for logout button or user menu)
      await testPage.waitForSelector('[data-testid="user-menu"]', {
        visible: true
      });

      const userMenuVisible = await testPage.$eval(
        '[data-testid="user-menu"]',
        el => el.offsetParent !== null
      );
      expect(userMenuVisible).toBe(true);
    });

    test('should persist login across page refresh', async () => {
      // Login first
      await testPage.goto(`${BASE_URL}/login`);
      await testPage.type('[data-testid="email-input"]', 'user@example.com');
      await testPage.type('[data-testid="password-input"]', 'SecurePass123!');
      await testPage.click('[data-testid="login-button"]');
      await testPage.waitForNavigation();

      // Verify on dashboard
      expect(testPage.url()).toContain('/dashboard');

      // Refresh page
      await testPage.reload({ waitUntil: 'networkidle2' });

      // Should still be logged in (not redirected to login)
      expect(testPage.url()).toContain('/dashboard');

      // User menu should still be visible
      const userMenu = await testPage.$('[data-testid="user-menu"]');
      expect(userMenu).toBeTruthy();
    });

    test('should remember me checkbox keep session longer', async () => {
      await testPage.goto(`${BASE_URL}/login`);

      // Check "Remember Me"
      await testPage.click('[data-testid="remember-me-checkbox"]');

      // Login
      await testPage.type('[data-testid="email-input"]', 'user@example.com');
      await testPage.type('[data-testid="password-input"]', 'SecurePass123!');
      await testPage.click('[data-testid="login-button"]');
      await testPage.waitForNavigation();

      // Check cookie expiration
      const cookies = await testPage.cookies();
      const sessionCookie = cookies.find(c => c.name === 'sessionId' || c.name === 'authToken');

      expect(sessionCookie).toBeTruthy();

      // Cookie should have long expiration (e.g., 30 days)
      const expirationDate = new Date(sessionCookie.expires * 1000);
      const now = new Date();
      const daysDiff = (expirationDate - now) / (1000 * 60 * 60 * 24);

      expect(daysDiff).toBeGreaterThan(7); // At least 7 days
    });
  });

  describe('Failed Login Attempts', () => {
    test('should show error for invalid email format', async () => {
      await testPage.goto(`${BASE_URL}/login`);

      // Enter invalid email
      await testPage.type('[data-testid="email-input"]', 'not-an-email');
      await testPage.type('[data-testid="password-input"]', 'password123');

      // Try to submit
      await testPage.click('[data-testid="login-button"]');

      // Should show validation error
      await testPage.waitForSelector('[data-testid="email-error"]', {
        visible: true
      });

      const errorText = await testPage.$eval(
        '[data-testid="email-error"]',
        el => el.textContent
      );
      expect(errorText).toMatch(/valid email|invalid email/i);

      // Should not navigate away
      expect(testPage.url()).toContain('/login');
    });

    test('should show error for empty password', async () => {
      await testPage.goto(`${BASE_URL}/login`);

      await testPage.type('[data-testid="email-input"]', 'user@example.com');
      // Leave password empty

      await testPage.click('[data-testid="login-button"]');

      // Should show validation error
      await testPage.waitForSelector('[data-testid="password-error"]', {
        visible: true
      });

      const errorText = await testPage.$eval(
        '[data-testid="password-error"]',
        el => el.textContent
      );
      expect(errorText).toMatch(/required|cannot be empty/i);
    });

    test('should show error for incorrect credentials', async () => {
      await testPage.goto(`${BASE_URL}/login`);

      await testPage.type('[data-testid="email-input"]', 'user@example.com');
      await testPage.type('[data-testid="password-input"]', 'WrongPassword123!');

      await testPage.click('[data-testid="login-button"]');

      // Should show authentication error
      await testPage.waitForSelector('[data-testid="auth-error"]', {
        visible: true,
        timeout: 10000
      });

      const errorText = await testPage.$eval(
        '[data-testid="auth-error"]',
        el => el.textContent
      );
      expect(errorText).toMatch(/invalid credentials|incorrect password/i);

      // Should remain on login page
      expect(testPage.url()).toContain('/login');
    });

    test('should lock account after multiple failed attempts', async () => {
      await testPage.goto(`${BASE_URL}/login`);

      // Attempt to login 5 times with wrong password
      for (let i = 0; i < 5; i++) {
        await testPage.type('[data-testid="email-input"]', 'user@example.com');
        await testPage.type('[data-testid="password-input"]', 'WrongPassword!');
        await testPage.click('[data-testid="login-button"]');

        await testPage.waitForTimeout(1000); // Wait between attempts

        // Clear fields for next attempt
        await testPage.evaluate(() => {
          document.querySelector('[data-testid="email-input"]').value = '';
          document.querySelector('[data-testid="password-input"]').value = '';
        });
      }

      // Sixth attempt should show account locked message
      await testPage.type('[data-testid="email-input"]', 'user@example.com');
      await testPage.type('[data-testid="password-input"]', 'WrongPassword!');
      await testPage.click('[data-testid="login-button"]');

      await testPage.waitForSelector('[data-testid="account-locked-error"]', {
        visible: true
      });

      const errorText = await testPage.$eval(
        '[data-testid="account-locked-error"]',
        el => el.textContent
      );
      expect(errorText).toMatch(/account locked|too many attempts/i);
    });
  });

  describe('Logout Flow', () => {
    beforeEach(async () => {
      // Login first
      await testPage.goto(`${BASE_URL}/login`);
      await testPage.type('[data-testid="email-input"]', 'user@example.com');
      await testPage.type('[data-testid="password-input"]', 'SecurePass123!');
      await testPage.click('[data-testid="login-button"]');
      await testPage.waitForNavigation();
    });

    test('should logout successfully', async () => {
      // Click user menu
      await testPage.click('[data-testid="user-menu"]');

      // Click logout
      await testPage.waitForSelector('[data-testid="logout-button"]', {
        visible: true
      });
      await testPage.click('[data-testid="logout-button"]');

      // Should redirect to login or home page
      await testPage.waitForNavigation();
      const currentUrl = testPage.url();
      expect(currentUrl).toMatch(/login|home|\/$/);

      // Should not be able to access protected pages
      await testPage.goto(`${BASE_URL}/dashboard`);

      // Should redirect to login
      await testPage.waitForNavigation();
      expect(testPage.url()).toContain('/login');
    });

    test('should clear session data on logout', async () => {
      // Logout
      await testPage.click('[data-testid="user-menu"]');
      await testPage.click('[data-testid="logout-button"]');
      await testPage.waitForNavigation();

      // Check localStorage cleared
      const localStorageKeys = await testPage.evaluate(() => {
        return Object.keys(localStorage);
      });
      expect(localStorageKeys).not.toContain('authToken');
      expect(localStorageKeys).not.toContain('user');

      // Check cookies cleared
      const cookies = await testPage.cookies();
      const authCookie = cookies.find(c =>
        c.name === 'sessionId' || c.name === 'authToken'
      );
      expect(authCookie).toBeFalsy();
    });
  });

  describe('Password Reset Flow', () => {
    test('should request password reset', async () => {
      await testPage.goto(`${BASE_URL}/login`);

      // Click "Forgot Password" link
      await testPage.click('[data-testid="forgot-password-link"]');

      // Should navigate to password reset page
      await testPage.waitForNavigation();
      expect(testPage.url()).toContain('/forgot-password');

      // Enter email
      await testPage.type('[data-testid="reset-email-input"]', 'user@example.com');
      await testPage.click('[data-testid="send-reset-button"]');

      // Should show success message
      await testPage.waitForSelector('[data-testid="reset-email-sent"]', {
        visible: true
      });

      const successText = await testPage.$eval(
        '[data-testid="reset-email-sent"]',
        el => el.textContent
      );
      expect(successText).toMatch(/email sent|check your email/i);
    });

    test('should show error for non-existent email', async () => {
      await testPage.goto(`${BASE_URL}/forgot-password`);

      await testPage.type('[data-testid="reset-email-input"]', 'nonexistent@example.com');
      await testPage.click('[data-testid="send-reset-button"]');

      // Should show error (or success for security - depends on your implementation)
      await testPage.waitForSelector('[data-testid="reset-error"], [data-testid="reset-email-sent"]', {
        visible: true
      });
    });
  });

  describe('Accessibility', () => {
    test('should be keyboard navigable', async () => {
      await testPage.goto(`${BASE_URL}/login`);

      // Tab to email field
      await testPage.keyboard.press('Tab');
      let focused = await testPage.evaluate(() => document.activeElement.getAttribute('data-testid'));
      expect(focused).toBe('email-input');

      // Type email
      await testPage.keyboard.type('user@example.com');

      // Tab to password field
      await testPage.keyboard.press('Tab');
      focused = await testPage.evaluate(() => document.activeElement.getAttribute('data-testid'));
      expect(focused).toBe('password-input');

      // Type password
      await testPage.keyboard.type('SecurePass123!');

      // Tab to submit button
      await testPage.keyboard.press('Tab');
      focused = await testPage.evaluate(() => document.activeElement.getAttribute('data-testid'));
      expect(focused).toBe('login-button');

      // Press Enter to submit
      await testPage.keyboard.press('Enter');

      // Should submit and navigate
      await testPage.waitForNavigation({ timeout: 10000 });
      expect(testPage.url()).toContain('/dashboard');
    });

    test('should have proper ARIA labels', async () => {
      await testPage.goto(`${BASE_URL}/login`);

      // Check email input
      const emailLabel = await testPage.$eval(
        '[data-testid="email-input"]',
        el => el.getAttribute('aria-label') || el.labels?.[0]?.textContent
      );
      expect(emailLabel).toBeTruthy();
      expect(emailLabel).toMatch(/email/i);

      // Check password input
      const passwordLabel = await testPage.$eval(
        '[data-testid="password-input"]',
        el => el.getAttribute('aria-label') || el.labels?.[0]?.textContent
      );
      expect(passwordLabel).toBeTruthy();
      expect(passwordLabel).toMatch(/password/i);

      // Check submit button
      const buttonLabel = await testPage.$eval(
        '[data-testid="login-button"]',
        el => el.getAttribute('aria-label') || el.textContent
      );
      expect(buttonLabel).toBeTruthy();
    });
  });

  describe('Security', () => {
    test('should use HTTPS in production', async () => {
      if (process.env.NODE_ENV === 'production') {
        const url = testPage.url();
        expect(url).toMatch(/^https:\/\//);
      }
    });

    test('should set secure cookie flags', async () => {
      await testPage.goto(`${BASE_URL}/login`);
      await testPage.type('[data-testid="email-input"]', 'user@example.com');
      await testPage.type('[data-testid="password-input"]', 'SecurePass123!');
      await testPage.click('[data-testid="login-button"]');
      await testPage.waitForNavigation();

      const cookies = await testPage.cookies();
      const sessionCookie = cookies.find(c => c.name === 'sessionId' || c.name === 'authToken');

      if (sessionCookie) {
        expect(sessionCookie.httpOnly).toBe(true);

        if (process.env.NODE_ENV === 'production') {
          expect(sessionCookie.secure).toBe(true);
        }
      }
    });

    test('should not expose sensitive data in client storage', async () => {
      await testPage.goto(`${BASE_URL}/login`);
      await testPage.type('[data-testid="email-input"]', 'user@example.com');
      await testPage.type('[data-testid="password-input"]', 'SecurePass123!');
      await testPage.click('[data-testid="login-button"]');
      await testPage.waitForNavigation();

      // Check localStorage doesn't contain password
      const localStorageData = await testPage.evaluate(() => {
        return JSON.stringify(localStorage);
      });
      expect(localStorageData).not.toMatch(/SecurePass123!/);
      expect(localStorageData.toLowerCase()).not.toContain('password');
    });
  });
});
