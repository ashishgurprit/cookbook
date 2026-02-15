/**
 * Common Test Fixtures Library
 *
 * Purpose: Reusable test data generators for consistent testing
 * Usage: Import and use in any test file
 */

// ============================================================================
// USER FIXTURES
// ============================================================================

export const userFixtures = {
  /**
   * Valid user data
   */
  validUser: () => ({
    id: 1,
    email: 'user@example.com',
    username: 'testuser',
    firstName: 'John',
    lastName: 'Doe',
    password: 'Password123!',
    role: 'user',
    active: true,
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01'),
  }),

  /**
   * Admin user
   */
  adminUser: () => ({
    ...userFixtures.validUser(),
    id: 2,
    email: 'admin@example.com',
    username: 'admin',
    role: 'admin',
  }),

  /**
   * Inactive user
   */
  inactiveUser: () => ({
    ...userFixtures.validUser(),
    id: 3,
    email: 'inactive@example.com',
    active: false,
  }),

  /**
   * Multiple users
   */
  userList: (count = 5) => {
    return Array.from({ length: count }, (_, i) => ({
      ...userFixtures.validUser(),
      id: i + 1,
      email: `user${i + 1}@example.com`,
      username: `user${i + 1}`,
    }));
  },

  /**
   * User with custom overrides
   */
  customUser: (overrides = {}) => ({
    ...userFixtures.validUser(),
    ...overrides,
  }),
};

// ============================================================================
// API RESPONSE FIXTURES
// ============================================================================

export const apiFixtures = {
  /**
   * Success response
   */
  successResponse: (data = {}) => ({
    status: 'success',
    data,
    timestamp: new Date().toISOString(),
  }),

  /**
   * Error response
   */
  errorResponse: (message = 'An error occurred', code = 'ERROR') => ({
    status: 'error',
    error: {
      message,
      code,
    },
    timestamp: new Date().toISOString(),
  }),

  /**
   * Paginated response
   */
  paginatedResponse: (items = [], page = 1, limit = 10, total = items.length) => ({
    status: 'success',
    data: items.slice((page - 1) * limit, page * limit),
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit),
      hasNext: page < Math.ceil(total / limit),
      hasPrev: page > 1,
    },
  }),

  /**
   * Validation error response
   */
  validationError: (errors = []) => ({
    status: 'error',
    error: {
      message: 'Validation failed',
      code: 'VALIDATION_ERROR',
      errors,
    },
  }),
};

// ============================================================================
// DATABASE FIXTURES
// ============================================================================

export const dbFixtures = {
  /**
   * Product fixture
   */
  product: (overrides = {}) => ({
    id: 1,
    name: 'Test Product',
    description: 'A test product',
    price: 99.99,
    currency: 'USD',
    stock: 100,
    category: 'Electronics',
    active: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  }),

  /**
   * Order fixture
   */
  order: (overrides = {}) => ({
    id: 1,
    userId: 1,
    status: 'pending',
    total: 99.99,
    currency: 'USD',
    items: [
      {
        productId: 1,
        quantity: 1,
        price: 99.99,
      },
    ],
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  }),

  /**
   * Comment fixture
   */
  comment: (overrides = {}) => ({
    id: 1,
    userId: 1,
    postId: 1,
    content: 'This is a test comment',
    likes: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  }),
};

// ============================================================================
// FORM DATA FIXTURES
// ============================================================================

export const formFixtures = {
  /**
   * Login form data
   */
  loginForm: (overrides = {}) => ({
    email: 'user@example.com',
    password: 'Password123!',
    rememberMe: false,
    ...overrides,
  }),

  /**
   * Registration form data
   */
  registrationForm: (overrides = {}) => ({
    email: 'newuser@example.com',
    username: 'newuser',
    password: 'Password123!',
    confirmPassword: 'Password123!',
    firstName: 'John',
    lastName: 'Doe',
    acceptTerms: true,
    ...overrides,
  }),

  /**
   * Contact form data
   */
  contactForm: (overrides = {}) => ({
    name: 'John Doe',
    email: 'john@example.com',
    subject: 'Test Subject',
    message: 'This is a test message',
    ...overrides,
  }),
};

// ============================================================================
// EDGE CASE FIXTURES
// ============================================================================

export const edgeCaseFixtures = {
  /**
   * Empty values
   */
  emptyValues: {
    emptyString: '',
    emptyArray: [],
    emptyObject: {},
    nullValue: null,
    undefinedValue: undefined,
    zero: 0,
    false: false,
  },

  /**
   * Invalid email addresses
   */
  invalidEmails: [
    'notanemail',
    '@example.com',
    'user@',
    'user @example.com',
    'user@.com',
    '',
  ],

  /**
   * Invalid passwords
   */
  invalidPasswords: [
    '123',          // Too short
    'password',     // No numbers or special chars
    '12345678',     // No letters
    'Pass1',        // Too short
    '',             // Empty
  ],

  /**
   * Special characters
   */
  specialCharacters: {
    sql: "'; DROP TABLE users; --",
    xss: '<script>alert("XSS")</script>',
    unicode: '你好世界🎉',
    emoji: '🔥💯✨',
    longString: 'x'.repeat(10000),
    whitespace: '   ',
    newlines: 'line1\nline2\nline3',
    tabs: 'col1\tcol2\tcol3',
  },

  /**
   * Boundary values
   */
  boundaryValues: {
    maxInt: Number.MAX_SAFE_INTEGER,
    minInt: Number.MIN_SAFE_INTEGER,
    maxFloat: Number.MAX_VALUE,
    minFloat: Number.MIN_VALUE,
    infinity: Infinity,
    negativeInfinity: -Infinity,
    nan: NaN,
  },
};

// ============================================================================
// DATE FIXTURES
// ============================================================================

export const dateFixtures = {
  /**
   * Common date scenarios
   */
  today: () => new Date(),
  yesterday: () => new Date(Date.now() - 24 * 60 * 60 * 1000),
  tomorrow: () => new Date(Date.now() + 24 * 60 * 60 * 1000),
  oneWeekAgo: () => new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
  oneMonthAgo: () => new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
  oneYearAgo: () => new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),

  /**
   * Formatted dates
   */
  isoString: () => new Date().toISOString(),
  timestamp: () => Date.now(),
  unixTimestamp: () => Math.floor(Date.now() / 1000),

  /**
   * Date range
   */
  dateRange: (startDaysAgo = 7, endDaysAgo = 0) => ({
    start: new Date(Date.now() - startDaysAgo * 24 * 60 * 60 * 1000),
    end: new Date(Date.now() - endDaysAgo * 24 * 60 * 60 * 1000),
  }),
};

// ============================================================================
// FILE FIXTURES
// ============================================================================

export const fileFixtures = {
  /**
   * Mock file object
   */
  mockFile: (name = 'test.txt', size = 1024, type = 'text/plain') => {
    const content = 'x'.repeat(size);
    return new File([content], name, { type });
  },

  /**
   * Image file
   */
  imageFile: (name = 'test.png') => {
    return new File(['fake-image-content'], name, { type: 'image/png' });
  },

  /**
   * PDF file
   */
  pdfFile: (name = 'test.pdf') => {
    return new File(['fake-pdf-content'], name, { type: 'application/pdf' });
  },

  /**
   * Large file (for testing size limits)
   */
  largeFile: (sizeMB = 10) => {
    const size = sizeMB * 1024 * 1024;
    return fileFixtures.mockFile('large.bin', size, 'application/octet-stream');
  },
};

// ============================================================================
// ERROR FIXTURES
// ============================================================================

export const errorFixtures = {
  /**
   * Standard error
   */
  standardError: (message = 'Test error') => new Error(message),

  /**
   * Validation error
   */
  validationError: (field = 'email', message = 'Invalid email') => ({
    field,
    message,
    type: 'validation',
  }),

  /**
   * Network error
   */
  networkError: () => {
    const error = new Error('Network request failed');
    error.name = 'NetworkError';
    return error;
  },

  /**
   * Timeout error
   */
  timeoutError: () => {
    const error = new Error('Request timeout');
    error.name = 'TimeoutError';
    return error;
  },

  /**
   * Permission error
   */
  permissionError: () => {
    const error = new Error('Permission denied');
    error.name = 'PermissionError';
    return error;
  },
};

// ============================================================================
// MOCK FUNCTIONS
// ============================================================================

export const mockFunctions = {
  /**
   * Mock API call that succeeds
   */
  mockApiSuccess: (data = {}) => {
    return Promise.resolve(apiFixtures.successResponse(data));
  },

  /**
   * Mock API call that fails
   */
  mockApiError: (message = 'API Error') => {
    return Promise.reject(new Error(message));
  },

  /**
   * Mock delayed API call
   */
  mockApiDelayed: (data = {}, delayMs = 100) => {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(apiFixtures.successResponse(data));
      }, delayMs);
    });
  },

  /**
   * Mock async function
   */
  mockAsync: (returnValue, delayMs = 0) => {
    return jest.fn().mockImplementation(() => {
      return new Promise((resolve) => {
        setTimeout(() => resolve(returnValue), delayMs);
      });
    });
  },
};

// ============================================================================
// USAGE EXAMPLES
// ============================================================================

/*
// In your test file:

import { userFixtures, apiFixtures, edgeCaseFixtures } from './fixtures/common-fixtures';

test('should handle valid user', () => {
  const user = userFixtures.validUser();
  expect(user.email).toBe('user@example.com');
});

test('should create custom user', () => {
  const user = userFixtures.customUser({ email: 'custom@example.com' });
  expect(user.email).toBe('custom@example.com');
});

test('should handle SQL injection', () => {
  const malicious = edgeCaseFixtures.specialCharacters.sql;
  const result = sanitize(malicious);
  expect(result).not.toContain('DROP TABLE');
});

test('should return paginated response', () => {
  const users = userFixtures.userList(25);
  const response = apiFixtures.paginatedResponse(users, 1, 10);
  expect(response.data).toHaveLength(10);
  expect(response.pagination.total).toBe(25);
});
*/
