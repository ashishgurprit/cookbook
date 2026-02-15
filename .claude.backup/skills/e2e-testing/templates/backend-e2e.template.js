/**
 * Backend E2E Test Template
 * ==========================
 *
 * Purpose: Test complete workflows spanning frontend, middleware, backend, and database
 *
 * Use this template for:
 * - Complete user workflows (registration → verification → login)
 * - Multi-step business processes (checkout → payment → fulfillment)
 * - Data persistence validation
 * - Third-party integrations (payment gateways, email services)
 * - Cross-service communication
 * - End-to-end data flow
 *
 * Usage:
 * 1. Copy this template to your test directory
 * 2. Replace {WORKFLOW_NAME}, {DATABASE_CONNECTION} placeholders
 * 3. Implement complete workflow tests
 * 4. Run with: npm test path/to/test.js
 */

const { Client } = require('pg'); // Or your DB client: mysql, mongodb, etc.

describe('{WORKFLOW_NAME} - Backend E2E', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_BASE = `${BASE_URL}/api`;
  let testPage;
  let dbClient;
  let testData = {};

  // ============================================================================
  // SETUP & TEARDOWN
  // ============================================================================

  beforeAll(async () => {
    // Setup database connection
    dbClient = new Client({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 5432,
      database: process.env.DB_NAME || 'test_db',
      user: process.env.DB_USER || 'test_user',
      password: process.env.DB_PASSWORD || 'test_password'
    });

    await dbClient.connect();
    await jestPuppeteer.resetBrowser();
  });

  beforeEach(async () => {
    testPage = await browser.newPage();

    // Set viewport
    await testPage.setViewport({
      width: 1920,
      height: 1080
    });

    // Setup request interception for monitoring
    await testPage.setRequestInterception(true);

    const requests = [];
    testPage.on('request', request => {
      requests.push({
        url: request.url(),
        method: request.method(),
        timestamp: Date.now()
      });
      request.continue();
    });

    testData.requests = requests;

    // Seed test data
    await seedTestData();
  });

  afterEach(async () => {
    // Clean up test data
    await cleanTestData();

    await testPage.close();
  });

  afterAll(async () => {
    await dbClient.end();
  });

  // ============================================================================
  // DATABASE HELPER FUNCTIONS
  // ============================================================================

  async function seedTestData() {
    // Insert test users
    await dbClient.query(`
      INSERT INTO users (id, email, password_hash, verified, created_at)
      VALUES
        ('test-user-1', 'user1@example.com', '$2b$10$hashedpassword', true, NOW()),
        ('test-user-2', 'user2@example.com', '$2b$10$hashedpassword', true, NOW())
      ON CONFLICT (id) DO NOTHING;
    `);

    // Insert test products
    await dbClient.query(`
      INSERT INTO products (id, name, price, stock, created_at)
      VALUES
        ('prod-1', 'Test Product 1', 29.99, 100, NOW()),
        ('prod-2', 'Test Product 2', 49.99, 50, NOW())
      ON CONFLICT (id) DO NOTHING;
    `);
  }

  async function cleanTestData() {
    // Delete in reverse dependency order
    await dbClient.query("DELETE FROM order_items WHERE order_id LIKE 'test-%'");
    await dbClient.query("DELETE FROM orders WHERE id LIKE 'test-%'");
    await dbClient.query("DELETE FROM users WHERE id LIKE 'test-%'");
    await dbClient.query("DELETE FROM products WHERE id LIKE 'prod-%'");
  }

  async function getUserByEmail(email) {
    const result = await dbClient.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    return result.rows[0];
  }

  async function getOrderById(orderId) {
    const result = await dbClient.query(
      'SELECT * FROM orders WHERE id = $1',
      [orderId]
    );
    return result.rows[0];
  }

  async function getOrderItems(orderId) {
    const result = await dbClient.query(
      'SELECT * FROM order_items WHERE order_id = $1',
      [orderId]
    );
    return result.rows;
  }

  // ============================================================================
  // PAGE OBJECT HELPERS
  // ============================================================================

  async function loginUser(email, password) {
    await testPage.goto(`${BASE_URL}/login`);
    await testPage.type('[data-testid="email-input"]', email);
    await testPage.type('[data-testid="password-input"]', password);
    await testPage.click('[data-testid="login-button"]');
    await testPage.waitForNavigation({ waitUntil: 'networkidle2' });
  }

  async function registerUser(userData) {
    await testPage.goto(`${BASE_URL}/register`);
    await testPage.type('[data-testid="email-input"]', userData.email);
    await testPage.type('[data-testid="password-input"]', userData.password);
    await testPage.type('[data-testid="confirm-password-input"]', userData.password);
    await testPage.type('[data-testid="name-input"]', userData.name);
    await testPage.click('[data-testid="register-button"]');
  }

  async function addToCart(productId, quantity = 1) {
    await testPage.goto(`${BASE_URL}/products/${productId}`);
    await testPage.waitForSelector('[data-testid="quantity-input"]');
    await testPage.evaluate((qty) => {
      document.querySelector('[data-testid="quantity-input"]').value = qty;
    }, quantity);
    await testPage.click('[data-testid="add-to-cart-button"]');
    await testPage.waitForSelector('[data-testid="cart-updated-notification"]');
  }

  async function proceedToCheckout() {
    await testPage.goto(`${BASE_URL}/cart`);
    await testPage.click('[data-testid="checkout-button"]');
    await testPage.waitForNavigation({ waitUntil: 'networkidle2' });
  }

  async function fillShippingInfo(shippingData) {
    await testPage.type('[data-testid="address-input"]', shippingData.address);
    await testPage.type('[data-testid="city-input"]', shippingData.city);
    await testPage.type('[data-testid="zip-input"]', shippingData.zip);
    await testPage.select('[data-testid="country-select"]', shippingData.country);
  }

  async function fillPaymentInfo(paymentData) {
    // Switch to payment iframe if using Stripe/PayPal
    const iframeElement = await testPage.$('iframe[name="payment-frame"]');
    if (iframeElement) {
      const frame = await iframeElement.contentFrame();
      await frame.type('[data-testid="card-number"]', paymentData.cardNumber);
      await frame.type('[data-testid="card-expiry"]', paymentData.expiry);
      await frame.type('[data-testid="card-cvc"]', paymentData.cvc);
    } else {
      await testPage.type('[data-testid="card-number"]', paymentData.cardNumber);
      await testPage.type('[data-testid="card-expiry"]', paymentData.expiry);
      await testPage.type('[data-testid="card-cvc"]', paymentData.cvc);
    }
  }

  // ============================================================================
  // COMPLETE WORKFLOW TESTS
  // ============================================================================

  describe('User Registration Workflow', () => {
    test('should complete full registration flow', async () => {
      const newUser = {
        email: `test-${Date.now()}@example.com`,
        password: 'SecurePass123!',
        name: 'Test User'
      };

      // Step 1: Register new user
      await registerUser(newUser);

      // Should show success message
      await testPage.waitForSelector('[data-testid="registration-success"]', {
        visible: true
      });

      // Step 2: Verify user created in database
      const user = await getUserByEmail(newUser.email);
      expect(user).toBeTruthy();
      expect(user.email).toBe(newUser.email);
      expect(user.verified).toBe(false); // Should be unverified initially

      // Step 3: Verify email sent (check test email service or database)
      const verificationToken = user.verification_token;
      expect(verificationToken).toBeTruthy();

      // Step 4: Verify email by visiting verification link
      await testPage.goto(`${BASE_URL}/verify-email?token=${verificationToken}`);

      await testPage.waitForSelector('[data-testid="verification-success"]', {
        visible: true
      });

      // Step 5: Verify user is now verified in database
      const verifiedUser = await getUserByEmail(newUser.email);
      expect(verifiedUser.verified).toBe(true);

      // Step 6: Login with new account
      await loginUser(newUser.email, newUser.password);

      // Should redirect to dashboard
      expect(testPage.url()).toContain('/dashboard');
    }, 60000);

    test('should handle duplicate email registration', async () => {
      const existingEmail = 'user1@example.com'; // From seed data

      await registerUser({
        email: existingEmail,
        password: 'password123',
        name: 'Duplicate User'
      });

      // Should show error message
      await testPage.waitForSelector('[data-testid="registration-error"]', {
        visible: true
      });

      const errorText = await testPage.$eval(
        '[data-testid="registration-error"]',
        el => el.textContent
      );
      expect(errorText).toMatch(/already exists|taken/i);
    });
  });

  describe('E-Commerce Checkout Workflow', () => {
    test('should complete full checkout process', async () => {
      const orderId = `test-order-${Date.now()}`;

      // Step 1: Login
      await loginUser('user1@example.com', 'password123');

      // Step 2: Add products to cart
      await addToCart('prod-1', 2);
      await addToCart('prod-2', 1);

      // Step 3: Proceed to checkout
      await proceedToCheckout();

      expect(testPage.url()).toContain('/checkout');

      // Step 4: Fill shipping information
      await fillShippingInfo({
        address: '123 Test St',
        city: 'Test City',
        zip: '12345',
        country: 'US'
      });

      await testPage.click('[data-testid="continue-to-payment"]');

      // Step 5: Fill payment information
      await fillPaymentInfo({
        cardNumber: '4242424242424242', // Test card
        expiry: '12/25',
        cvc: '123'
      });

      // Step 6: Place order
      await testPage.click('[data-testid="place-order-button"]');

      // Step 7: Wait for order confirmation
      await testPage.waitForSelector('[data-testid="order-confirmation"]', {
        visible: true,
        timeout: 15000
      });

      // Step 8: Verify order in database
      const orderIdFromPage = await testPage.$eval(
        '[data-testid="order-id"]',
        el => el.textContent
      );

      const order = await getOrderById(orderIdFromPage);
      expect(order).toBeTruthy();
      expect(order.user_id).toBe('test-user-1');
      expect(order.status).toBe('pending');

      // Step 9: Verify order items
      const orderItems = await getOrderItems(orderIdFromPage);
      expect(orderItems).toHaveLength(2);

      const prod1Item = orderItems.find(item => item.product_id === 'prod-1');
      expect(prod1Item.quantity).toBe(2);

      const prod2Item = orderItems.find(item => item.product_id === 'prod-2');
      expect(prod2Item.quantity).toBe(1);

      // Step 10: Verify total amount
      const expectedTotal = (29.99 * 2) + (49.99 * 1);
      expect(parseFloat(order.total_amount)).toBeCloseTo(expectedTotal, 2);

      // Step 11: Verify inventory updated
      const prod1 = await dbClient.query(
        'SELECT stock FROM products WHERE id = $1',
        ['prod-1']
      );
      expect(prod1.rows[0].stock).toBe(98); // 100 - 2

      const prod2 = await dbClient.query(
        'SELECT stock FROM products WHERE id = $1',
        ['prod-2']
      );
      expect(prod2.rows[0].stock).toBe(49); // 50 - 1
    }, 90000);

    test('should handle insufficient inventory', async () => {
      await loginUser('user1@example.com', 'password123');

      // Try to order more than available stock
      await testPage.goto(`${BASE_URL}/products/prod-1`);
      await testPage.evaluate(() => {
        document.querySelector('[data-testid="quantity-input"]').value = 1000;
      });
      await testPage.click('[data-testid="add-to-cart-button"]');

      // Should show error
      await testPage.waitForSelector('[data-testid="error-message"]', {
        visible: true
      });

      const errorText = await testPage.$eval(
        '[data-testid="error-message"]',
        el => el.textContent
      );
      expect(errorText).toMatch(/insufficient|out of stock/i);
    });

    test('should handle payment failure', async () => {
      await loginUser('user1@example.com', 'password123');
      await addToCart('prod-1', 1);
      await proceedToCheckout();

      await fillShippingInfo({
        address: '123 Test St',
        city: 'Test City',
        zip: '12345',
        country: 'US'
      });

      await testPage.click('[data-testid="continue-to-payment"]');

      // Use card number that triggers decline
      await fillPaymentInfo({
        cardNumber: '4000000000000002', // Decline card
        expiry: '12/25',
        cvc: '123'
      });

      await testPage.click('[data-testid="place-order-button"]');

      // Should show payment error
      await testPage.waitForSelector('[data-testid="payment-error"]', {
        visible: true
      });

      // Verify no order created
      const orders = await dbClient.query(
        "SELECT * FROM orders WHERE user_id = 'test-user-1' AND created_at > NOW() - INTERVAL '1 minute'"
      );
      expect(orders.rows).toHaveLength(0);
    });
  });

  // ============================================================================
  // DATA SYNCHRONIZATION TESTS
  // ============================================================================

  describe('Data Synchronization', () => {
    test('should sync data changes across multiple tabs', async () => {
      // Login in first tab
      await loginUser('user1@example.com', 'password123');

      // Add item to cart
      await addToCart('prod-1', 1);

      // Open second tab
      const secondPage = await browser.newPage();
      await secondPage.goto(`${BASE_URL}/login`);

      // Login with same user
      await secondPage.type('[data-testid="email-input"]', 'user1@example.com');
      await secondPage.type('[data-testid="password-input"]', 'password123');
      await secondPage.click('[data-testid="login-button"]');
      await secondPage.waitForNavigation();

      // Navigate to cart
      await secondPage.goto(`${BASE_URL}/cart`);

      // Should see the item added in first tab
      await secondPage.waitForSelector('[data-testid="cart-item"]');
      const cartItems = await secondPage.$$('[data-testid="cart-item"]');
      expect(cartItems).toHaveLength(1);

      await secondPage.close();
    });

    test('should handle concurrent updates correctly', async () => {
      // Two users try to purchase last item simultaneously
      const page1 = await browser.newPage();
      const page2 = await browser.newPage();

      // Update product to have only 1 in stock
      await dbClient.query(
        "UPDATE products SET stock = 1 WHERE id = 'prod-1'"
      );

      // User 1 adds to cart
      await page1.goto(`${BASE_URL}/login`);
      await page1.type('[data-testid="email-input"]', 'user1@example.com');
      await page1.type('[data-testid="password-input"]', 'password123');
      await page1.click('[data-testid="login-button"]');
      await page1.waitForNavigation();

      // User 2 adds to cart
      await page2.goto(`${BASE_URL}/login`);
      await page2.type('[data-testid="email-input"]', 'user2@example.com');
      await page2.type('[data-testid="password-input"]', 'password123');
      await page2.click('[data-testid="login-button"]');
      await page2.waitForNavigation();

      // Both try to add same item
      const addPromise1 = (async () => {
        await page1.goto(`${BASE_URL}/products/prod-1`);
        await page1.click('[data-testid="add-to-cart-button"]');
      })();

      const addPromise2 = (async () => {
        await page2.goto(`${BASE_URL}/products/prod-1`);
        await page2.click('[data-testid="add-to-cart-button"]');
      })();

      await Promise.all([addPromise1, addPromise2]);

      // One should succeed, one should fail
      const success1 = await page1.$('[data-testid="cart-updated-notification"]');
      const success2 = await page2.$('[data-testid="cart-updated-notification"]');
      const error1 = await page1.$('[data-testid="error-message"]');
      const error2 = await page2.$('[data-testid="error-message"]');

      const successCount = [success1, success2].filter(Boolean).length;
      const errorCount = [error1, error2].filter(Boolean).length;

      expect(successCount).toBe(1);
      expect(errorCount).toBe(1);

      await page1.close();
      await page2.close();
    }, 60000);
  });

  // ============================================================================
  // THIRD-PARTY INTEGRATION TESTS
  // ============================================================================

  describe('Third-Party Integrations', () => {
    test('should send email notification after order', async () => {
      // Mock email service or use test email provider
      const emailsSent = [];

      await testPage.on('request', request => {
        if (request.url().includes('api.sendgrid.com') ||
            request.url().includes('api.mailgun.net')) {
          emailsSent.push({
            to: request.postData()?.to,
            subject: request.postData()?.subject
          });
        }
      });

      await loginUser('user1@example.com', 'password123');
      await addToCart('prod-1', 1);
      await proceedToCheckout();

      // Complete checkout...
      await fillShippingInfo({
        address: '123 Test St',
        city: 'Test City',
        zip: '12345',
        country: 'US'
      });

      await testPage.click('[data-testid="continue-to-payment"]');
      await fillPaymentInfo({
        cardNumber: '4242424242424242',
        expiry: '12/25',
        cvc: '123'
      });

      await testPage.click('[data-testid="place-order-button"]');
      await testPage.waitForSelector('[data-testid="order-confirmation"]');

      // Verify email was sent (or queued)
      // In real test, check email queue table or mock service
      const emailJobs = await dbClient.query(
        "SELECT * FROM email_queue WHERE to_email = 'user1@example.com' AND created_at > NOW() - INTERVAL '1 minute'"
      );

      expect(emailJobs.rows.length).toBeGreaterThan(0);
      expect(emailJobs.rows[0].subject).toMatch(/order confirmation/i);
    });

    test('should process payment through payment gateway', async () => {
      // This would integrate with Stripe/PayPal test API
      // For demo purposes, we'll check the payment record

      await loginUser('user1@example.com', 'password123');
      await addToCart('prod-1', 1);
      await proceedToCheckout();

      await fillShippingInfo({
        address: '123 Test St',
        city: 'Test City',
        zip: '12345',
        country: 'US'
      });

      await testPage.click('[data-testid="continue-to-payment"]');
      await fillPaymentInfo({
        cardNumber: '4242424242424242',
        expiry: '12/25',
        cvc: '123'
      });

      await testPage.click('[data-testid="place-order-button"]');
      await testPage.waitForSelector('[data-testid="order-confirmation"]');

      const orderIdFromPage = await testPage.$eval(
        '[data-testid="order-id"]',
        el => el.textContent
      );

      // Verify payment record
      const payment = await dbClient.query(
        'SELECT * FROM payments WHERE order_id = $1',
        [orderIdFromPage]
      );

      expect(payment.rows).toHaveLength(1);
      expect(payment.rows[0].status).toBe('succeeded');
      expect(payment.rows[0].gateway).toBe('stripe'); // or your gateway
      expect(payment.rows[0].gateway_transaction_id).toBeTruthy();
    });
  });

  // ============================================================================
  // PERFORMANCE TESTS
  // ============================================================================

  describe('Performance', () => {
    test('should complete checkout within acceptable time', async () => {
      const startTime = Date.now();

      await loginUser('user1@example.com', 'password123');
      await addToCart('prod-1', 1);
      await proceedToCheckout();

      await fillShippingInfo({
        address: '123 Test St',
        city: 'Test City',
        zip: '12345',
        country: 'US'
      });

      await testPage.click('[data-testid="continue-to-payment"]');
      await fillPaymentInfo({
        cardNumber: '4242424242424242',
        expiry: '12/25',
        cvc: '123'
      });

      await testPage.click('[data-testid="place-order-button"]');
      await testPage.waitForSelector('[data-testid="order-confirmation"]');

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Checkout should complete within 30 seconds
      expect(duration).toBeLessThan(30000);
    }, 60000);
  });
});
