/**
 * Jest-Puppeteer Configuration
 * =============================
 *
 * Copy this file to your project root as jest-puppeteer.config.js
 */

module.exports = {
  launch: {
    // Run headless by default, override with HEADLESS=false
    headless: process.env.HEADLESS !== 'false',

    // Slow down operations for debugging
    slowMo: process.env.SLOW_MO ? parseInt(process.env.SLOW_MO) : 0,

    // Default viewport
    defaultViewport: {
      width: 1920,
      height: 1080
    },

    // Browser arguments
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--disable-gpu',
      '--window-size=1920,1080'
    ],

    // Enable devtools in debug mode
    devtools: process.env.PWDEBUG === '1',

    // Increase timeout for CI environments
    timeout: 30000
  },

  // Browser context settings
  browserContext: 'default',

  // Exit on page errors (disable for debugging)
  exitOnPageError: false,

  // Server configuration (if you want jest-puppeteer to start your app)
  server: process.env.SKIP_SERVER ? undefined : {
    command: 'npm start',
    port: 3000,
    launchTimeout: 30000,
    debug: true
  }
};
