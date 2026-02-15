/**
 * Middleware E2E Test Template
 * =============================
 *
 * Purpose: Test API layer, authentication, session management, and middleware logic
 *
 * Use this template for:
 * - API endpoint testing
 * - Authentication and authorization
 * - Session management
 * - Rate limiting
 * - CORS validation
 * - Request/response transformations
 * - Error handling middleware
 *
 * Usage:
 * 1. Copy this template to your test directory
 * 2. Replace {API_ENDPOINT}, {AUTH_TOKEN}, placeholders
 * 3. Implement test scenarios for your middleware
 * 4. Run with: npm test path/to/test.js
 */

describe('{MIDDLEWARE_NAME} - Middleware E2E', () => {
  const BASE_URL = process.env.API_URL || 'http://localhost:3000';
  const API_BASE = `${BASE_URL}/api`;
  let testPage;
  let authToken;

  // ============================================================================
  // SETUP & TEARDOWN
  // ============================================================================

  beforeAll(async () => {
    await jestPuppeteer.resetBrowser();
  });

  beforeEach(async () => {
    testPage = await browser.newPage();

    // Set viewport (though less important for API testing)
    await testPage.setViewport({
      width: 1920,
      height: 1080
    });

    // Navigate to a blank page
    await testPage.goto(`${BASE_URL}/`, {
      waitUntil: 'networkidle2'
    });
  });

  afterEach(async () => {
    await testPage.close();
  });

  afterAll(async () => {
    // Cleanup test data if needed
  });

  // ============================================================================
  // HELPER FUNCTIONS FOR API TESTING
  // ============================================================================

  /**
   * Make API request from browser context
   */
  async function apiRequest(method, endpoint, options = {}) {
    return testPage.evaluate(async (method, endpoint, options) => {
      const response = await fetch(endpoint, {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        body: options.body ? JSON.stringify(options.body) : undefined
      });

      const contentType = response.headers.get('content-type');
      let data;

      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }

      return {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        data
      };
    }, method, endpoint, options);
  }

  /**
   * Login and get auth token
   */
  async function login(email, password) {
    const response = await apiRequest('POST', `${API_BASE}/auth/login`, {
      body: { email, password }
    });

    if (response.status === 200 && response.data.token) {
      return response.data.token;
    }

    throw new Error(`Login failed: ${response.statusText}`);
  }

  /**
   * Make authenticated API request
   */
  async function authenticatedRequest(method, endpoint, options = {}) {
    return apiRequest(method, endpoint, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${authToken}`
      }
    });
  }

  // ============================================================================
  // AUTHENTICATION TESTS
  // ============================================================================

  describe('Authentication Middleware', () => {
    test('should reject request without auth token', async () => {
      const response = await apiRequest('GET', `${API_BASE}/protected`);

      expect(response.status).toBe(401);
      expect(response.data.error).toMatch(/unauthorized|authentication/i);
    });

    test('should reject request with invalid auth token', async () => {
      const response = await apiRequest('GET', `${API_BASE}/protected`, {
        headers: {
          'Authorization': 'Bearer invalid-token-12345'
        }
      });

      expect(response.status).toBe(401);
      expect(response.data.error).toMatch(/invalid|token/i);
    });

    test('should reject request with expired auth token', async () => {
      const expiredToken = '{EXPIRED_TEST_TOKEN}';

      const response = await apiRequest('GET', `${API_BASE}/protected`, {
        headers: {
          'Authorization': `Bearer ${expiredToken}`
        }
      });

      expect(response.status).toBe(401);
      expect(response.data.error).toMatch(/expired/i);
    });

    test('should accept request with valid auth token', async () => {
      // Login to get valid token
      authToken = await login('test@example.com', 'password123');

      const response = await authenticatedRequest('GET', `${API_BASE}/protected`);

      expect(response.status).toBe(200);
      expect(response.data).toBeTruthy();
    });

    test('should include user info in request context after authentication', async () => {
      authToken = await login('test@example.com', 'password123');

      const response = await authenticatedRequest('GET', `${API_BASE}/me`);

      expect(response.status).toBe(200);
      expect(response.data.user.email).toBe('test@example.com');
    });

    test('should refresh token when near expiration', async () => {
      authToken = await login('test@example.com', 'password123');

      // Request refresh
      const response = await apiRequest('POST', `${API_BASE}/auth/refresh`, {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      });

      expect(response.status).toBe(200);
      expect(response.data.token).toBeTruthy();
      expect(response.data.token).not.toBe(authToken);
    });
  });

  // ============================================================================
  // AUTHORIZATION TESTS
  // ============================================================================

  describe('Authorization Middleware', () => {
    test('should allow admin to access admin-only endpoint', async () => {
      authToken = await login('admin@example.com', 'admin-password');

      const response = await authenticatedRequest('GET', `${API_BASE}/admin/users`);

      expect(response.status).toBe(200);
    });

    test('should reject non-admin from accessing admin-only endpoint', async () => {
      authToken = await login('user@example.com', 'user-password');

      const response = await authenticatedRequest('GET', `${API_BASE}/admin/users`);

      expect(response.status).toBe(403);
      expect(response.data.error).toMatch(/forbidden|permission/i);
    });

    test('should allow user to access their own resources', async () => {
      authToken = await login('user@example.com', 'user-password');

      const response = await authenticatedRequest('GET', `${API_BASE}/users/me/profile`);

      expect(response.status).toBe(200);
    });

    test('should reject user from accessing other users resources', async () => {
      authToken = await login('user@example.com', 'user-password');

      const response = await authenticatedRequest('GET', `${API_BASE}/users/other-user-id/profile`);

      expect(response.status).toBe(403);
    });
  });

  // ============================================================================
  // RATE LIMITING TESTS
  // ============================================================================

  describe('Rate Limiting Middleware', () => {
    test('should allow requests within rate limit', async () => {
      const requests = [];

      for (let i = 0; i < 5; i++) {
        requests.push(apiRequest('GET', `${API_BASE}/public-endpoint`));
      }

      const responses = await Promise.all(requests);

      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
    });

    test('should reject requests exceeding rate limit', async () => {
      const requests = [];
      const limit = 10; // Assuming rate limit is 10 requests per minute

      // Make more requests than the limit
      for (let i = 0; i < limit + 5; i++) {
        requests.push(apiRequest('GET', `${API_BASE}/public-endpoint`));
      }

      const responses = await Promise.all(requests);

      // Some requests should be rate limited
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });

    test('should include rate limit headers in response', async () => {
      const response = await apiRequest('GET', `${API_BASE}/public-endpoint`);

      expect(response.headers['x-ratelimit-limit']).toBeTruthy();
      expect(response.headers['x-ratelimit-remaining']).toBeTruthy();
      expect(response.headers['x-ratelimit-reset']).toBeTruthy();
    });

    test('should have different rate limits for authenticated users', async () => {
      // Unauthenticated request
      const unauthedResponse = await apiRequest('GET', `${API_BASE}/public-endpoint`);
      const unauthedLimit = parseInt(unauthedResponse.headers['x-ratelimit-limit']);

      // Authenticated request
      authToken = await login('user@example.com', 'user-password');
      const authedResponse = await authenticatedRequest('GET', `${API_BASE}/public-endpoint`);
      const authedLimit = parseInt(authedResponse.headers['x-ratelimit-limit']);

      // Authenticated users should have higher limit
      expect(authedLimit).toBeGreaterThan(unauthedLimit);
    });
  });

  // ============================================================================
  // CORS TESTS
  // ============================================================================

  describe('CORS Middleware', () => {
    test('should include CORS headers in preflight request', async () => {
      const response = await testPage.evaluate(async (apiBase) => {
        const res = await fetch(`${apiBase}/endpoint`, {
          method: 'OPTIONS',
          headers: {
            'Origin': 'https://example.com',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type'
          }
        });

        return {
          status: res.status,
          headers: Object.fromEntries(res.headers.entries())
        };
      }, API_BASE);

      expect(response.status).toBe(204);
      expect(response.headers['access-control-allow-origin']).toBeTruthy();
      expect(response.headers['access-control-allow-methods']).toContain('POST');
      expect(response.headers['access-control-allow-headers']).toContain('Content-Type');
    });

    test('should include CORS headers in actual request', async () => {
      const response = await apiRequest('GET', `${API_BASE}/public-endpoint`);

      expect(response.headers['access-control-allow-origin']).toBeTruthy();
    });

    test('should reject requests from unauthorized origins', async () => {
      const response = await testPage.evaluate(async (apiBase) => {
        const res = await fetch(`${apiBase}/endpoint`, {
          method: 'GET',
          headers: {
            'Origin': 'https://malicious-site.com'
          }
        });

        return {
          status: res.status,
          headers: Object.fromEntries(res.headers.entries())
        };
      }, API_BASE);

      // Either no CORS header or explicit rejection
      expect(
        !response.headers['access-control-allow-origin'] ||
        response.headers['access-control-allow-origin'] === 'null'
      ).toBe(true);
    });
  });

  // ============================================================================
  // REQUEST/RESPONSE TRANSFORMATION TESTS
  // ============================================================================

  describe('Request/Response Transformation Middleware', () => {
    test('should transform request data before reaching handler', async () => {
      const response = await apiRequest('POST', `${API_BASE}/transform-test`, {
        body: {
          firstName: 'john',
          lastName: 'doe'
        }
      });

      // Middleware should have transformed to camelCase or normalized
      expect(response.status).toBe(200);
      expect(response.data.processed).toBe(true);
    });

    test('should add metadata to response', async () => {
      const response = await apiRequest('GET', `${API_BASE}/public-endpoint`);

      expect(response.status).toBe(200);
      expect(response.data.meta).toBeTruthy();
      expect(response.data.meta.timestamp).toBeTruthy();
      expect(response.data.meta.version).toBeTruthy();
    });

    test('should sanitize sensitive data in response', async () => {
      authToken = await login('user@example.com', 'user-password');
      const response = await authenticatedRequest('GET', `${API_BASE}/users/me`);

      expect(response.status).toBe(200);
      expect(response.data.user).toBeTruthy();

      // Sensitive fields should be removed
      expect(response.data.user.password).toBeUndefined();
      expect(response.data.user.passwordHash).toBeUndefined();
      expect(response.data.user.ssn).toBeUndefined();
    });

    test('should compress large responses', async () => {
      const response = await testPage.evaluate(async (apiBase) => {
        const res = await fetch(`${apiBase}/large-data`, {
          headers: {
            'Accept-Encoding': 'gzip, deflate, br'
          }
        });

        return {
          status: res.status,
          headers: Object.fromEntries(res.headers.entries()),
          bodySize: (await res.text()).length
        };
      }, API_BASE);

      expect(response.status).toBe(200);
      expect(response.headers['content-encoding']).toMatch(/gzip|br|deflate/);
    });
  });

  // ============================================================================
  // ERROR HANDLING MIDDLEWARE TESTS
  // ============================================================================

  describe('Error Handling Middleware', () => {
    test('should return consistent error format', async () => {
      const response = await apiRequest('GET', `${API_BASE}/nonexistent-endpoint`);

      expect(response.status).toBe(404);
      expect(response.data).toHaveProperty('error');
      expect(response.data).toHaveProperty('message');
      expect(response.data).toHaveProperty('statusCode');
      expect(response.data.statusCode).toBe(404);
    });

    test('should handle validation errors properly', async () => {
      const response = await apiRequest('POST', `${API_BASE}/users`, {
        body: {
          // Missing required fields
          email: 'invalid-email'
        }
      });

      expect(response.status).toBe(400);
      expect(response.data.error).toBe('Validation Error');
      expect(response.data.details).toBeTruthy();
      expect(Array.isArray(response.data.details)).toBe(true);
    });

    test('should handle server errors gracefully', async () => {
      // Trigger endpoint that causes internal error
      const response = await apiRequest('GET', `${API_BASE}/trigger-error`);

      expect(response.status).toBe(500);
      expect(response.data.error).toBe('Internal Server Error');

      // Should not leak sensitive error details in production
      if (process.env.NODE_ENV === 'production') {
        expect(response.data.stack).toBeUndefined();
      }
    });

    test('should include request ID in error response for tracking', async () => {
      const response = await apiRequest('GET', `${API_BASE}/nonexistent`);

      expect(response.status).toBe(404);
      expect(response.data.requestId).toBeTruthy();
      expect(typeof response.data.requestId).toBe('string');
    });
  });

  // ============================================================================
  // SESSION MANAGEMENT TESTS
  // ============================================================================

  describe('Session Management Middleware', () => {
    test('should create session on login', async () => {
      const response = await apiRequest('POST', `${API_BASE}/auth/login`, {
        body: {
          email: 'user@example.com',
          password: 'password123'
        }
      });

      expect(response.status).toBe(200);
      expect(response.headers['set-cookie']).toBeTruthy();

      // Parse cookie
      const cookieHeader = response.headers['set-cookie'];
      expect(cookieHeader).toContain('sessionId=');
      expect(cookieHeader).toContain('HttpOnly');
      expect(cookieHeader).toContain('Secure');
    });

    test('should maintain session across requests', async () => {
      // Login to create session
      authToken = await login('user@example.com', 'password123');

      // Make multiple requests with same token
      const response1 = await authenticatedRequest('GET', `${API_BASE}/me`);
      const response2 = await authenticatedRequest('GET', `${API_BASE}/me`);

      expect(response1.status).toBe(200);
      expect(response2.status).toBe(200);
      expect(response1.data.user.id).toBe(response2.data.user.id);
    });

    test('should invalidate session on logout', async () => {
      authToken = await login('user@example.com', 'password123');

      // Logout
      const logoutResponse = await authenticatedRequest('POST', `${API_BASE}/auth/logout`);
      expect(logoutResponse.status).toBe(200);

      // Try to use same token
      const response = await authenticatedRequest('GET', `${API_BASE}/me`);
      expect(response.status).toBe(401);
    });

    test('should expire session after inactivity timeout', async () => {
      authToken = await login('user@example.com', 'password123');

      // Wait for session timeout (this test might need to be adjusted based on your timeout settings)
      // For testing, you might want to use a shorter timeout in test environment
      await new Promise(resolve => setTimeout(resolve, 31000)); // 31 seconds

      const response = await authenticatedRequest('GET', `${API_BASE}/me`);

      // Should be expired if timeout is 30 seconds
      expect(response.status).toBe(401);
      expect(response.data.error).toMatch(/expired|session/i);
    }, 60000); // Increase Jest timeout for this test
  });

  // ============================================================================
  // LOGGING MIDDLEWARE TESTS
  // ============================================================================

  describe('Logging Middleware', () => {
    test('should log request and response', async () => {
      const requestId = `test-${Date.now()}`;

      const response = await apiRequest('GET', `${API_BASE}/public-endpoint`, {
        headers: {
          'X-Request-ID': requestId
        }
      });

      expect(response.status).toBe(200);

      // In a real test, you'd verify logs were written
      // This might require access to log aggregation service or log files
    });

    test('should include request ID in logs', async () => {
      const response = await apiRequest('GET', `${API_BASE}/public-endpoint`);

      // Response should include request ID for correlation
      expect(response.headers['x-request-id']).toBeTruthy();
    });
  });

  // ============================================================================
  // SECURITY HEADERS MIDDLEWARE TESTS
  // ============================================================================

  describe('Security Headers Middleware', () => {
    test('should include security headers in response', async () => {
      const response = await apiRequest('GET', `${API_BASE}/public-endpoint`);

      expect(response.status).toBe(200);
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBeTruthy();
      expect(response.headers['x-xss-protection']).toBeTruthy();
      expect(response.headers['strict-transport-security']).toBeTruthy();
    });

    test('should include CSP header', async () => {
      const response = await apiRequest('GET', `${API_BASE}/public-endpoint`);

      expect(response.headers['content-security-policy']).toBeTruthy();
    });
  });

  // ============================================================================
  // CONTENT TYPE VALIDATION TESTS
  // ============================================================================

  describe('Content Type Validation Middleware', () => {
    test('should accept JSON content type', async () => {
      const response = await apiRequest('POST', `${API_BASE}/data`, {
        headers: {
          'Content-Type': 'application/json'
        },
        body: { name: 'test' }
      });

      expect(response.status).not.toBe(415); // Not Unsupported Media Type
    });

    test('should reject invalid content type for JSON endpoints', async () => {
      const response = await testPage.evaluate(async (apiBase) => {
        const res = await fetch(`${apiBase}/data`, {
          method: 'POST',
          headers: {
            'Content-Type': 'text/plain'
          },
          body: 'plain text data'
        });

        return {
          status: res.status,
          data: await res.json()
        };
      }, API_BASE);

      expect(response.status).toBe(415); // Unsupported Media Type
    });
  });
});
