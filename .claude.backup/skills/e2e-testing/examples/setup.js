/**
 * Global Test Setup
 * ==================
 *
 * Copy this file to your tests/e2e/ directory as setup.js
 * Configure in jest.config.js: setupFilesAfterEnv: ['<rootDir>/tests/e2e/setup.js']
 */

// Extend Jest matchers
expect.extend({
  toBeWithinRange(received, floor, ceiling) {
    const pass = received >= floor && received <= ceiling;
    if (pass) {
      return {
        message: () => `expected ${received} not to be within range ${floor} - ${ceiling}`,
        pass: true
      };
    } else {
      return {
        message: () => `expected ${received} to be within range ${floor} - ${ceiling}`,
        pass: false
      };
    }
  }
});

// Set default timeout
jest.setTimeout(30000);

// Global setup
beforeAll(async () => {
  // Any global setup needed
  console.log('🚀 Starting E2E test suite');
});

// Global teardown
afterAll(async () => {
  console.log('✅ E2E test suite complete');
});

// Capture test results for screenshots
let testResult;

beforeEach(() => {
  testResult = { status: 'running' };
});

afterEach(function() {
  const { testPath, currentTestName } = this;
  if (this.currentTest?.state === 'failed') {
    testResult.status = 'failed';
  } else {
    testResult.status = 'passed';
  }

  // Make test result available globally
  global.testResult = testResult;
});

// Error handler for unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Console filter (optional - reduce noise)
const originalConsoleLog = console.log;
console.log = (...args) => {
  // Filter out verbose Puppeteer logs if needed
  const message = args.join(' ');
  if (message.includes('DevTools') || message.includes('ws://')) {
    return;
  }
  originalConsoleLog.apply(console, args);
};

// Helper functions available in all tests
global.waitFor = async (milliseconds) => {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
};

global.retryOperation = async (operation, maxRetries = 3, delay = 1000) => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await operation();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await global.waitFor(delay);
    }
  }
};
