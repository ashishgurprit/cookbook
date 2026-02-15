/**
 * Rate Limiting - Express.js Implementation
 * ==========================================
 *
 * Production-ready token bucket rate limiting with Redis.
 *
 * Features:
 * - Token bucket algorithm (allows bursts)
 * - IP-based and user-based rate limiting
 * - Configurable per-endpoint limits
 * - Rate limit headers (X-RateLimit-*)
 * - Fail-open policy (availability > strict enforcement)
 * - Security logging (no sensitive data)
 * - OWASP compliant
 *
 * Usage:
 *     const { RateLimiter, rateLimitMiddleware } = require('./rate-limiting');
 *
 *     const rateLimiter = new RateLimiter(process.env.REDIS_URL);
 *     await rateLimiter.connect();
 *
 *     // Apply to all routes
 *     app.use(rateLimitMiddleware(rateLimiter));
 *
 *     // Or specific endpoint
 *     app.post('/api/login', rateLimit({ limit: 5, window: 60 }), (req, res) => {
 *       ...
 *     });
 */

const redis = require('redis');
const { promisify } = require('util');

// ============================================================================
// CONFIGURATION
// ============================================================================

// Startup validation
function validateEnvironment() {
  const required = ['REDIS_URL'];
  const missing = required.filter(v => !process.env[v]);

  if (missing.length > 0) {
    console.error(`❌ Missing required environment variables: ${missing.join(', ')}`);
    console.error('   Set REDIS_URL=redis://:password@host:6379/0');
    process.exit(1);
  }

  console.log('✅ Rate limiting configuration validated');
}

validateEnvironment();

// Default rate limits
const DEFAULT_RATE_LIMITS = {
  '/api/auth/login': { limit: 5, window: 60, strategy: 'ip' },
  '/api/auth/register': { limit: 5, window: 60, strategy: 'ip' },
  '/api/auth/reset-password': { limit: 5, window: 60, strategy: 'ip' },
  '/api/contact': { limit: 5, window: 3600, strategy: 'ip' },
  '/api/newsletter': { limit: 10, window: 3600, strategy: 'ip' },
};

// Paths to skip rate limiting
const SKIP_PATHS = ['/health', '/metrics'];

// ============================================================================
// RATE LIMITER CLASS
// ============================================================================

class RateLimiter {
  /**
   * Token Bucket Rate Limiter with Redis
   *
   * @param {string} redisUrl - Redis connection URL
   * @param {boolean} failOpen - Allow requests if Redis unavailable (default: true)
   */
  constructor(redisUrl, failOpen = true) {
    this.redisUrl = redisUrl;
    this.failOpen = failOpen;
    this.client = null;
  }

  /**
   * Connect to Redis
   */
  async connect() {
    try {
      this.client = redis.createClient({
        url: this.redisUrl,
        socket: {
          connectTimeout: 1000,
          timeout: 1000
        }
      });

      this.client.on('error', (err) => {
        console.error('Redis connection error:', err);
      });

      await this.client.connect();
      await this.client.ping();
      console.log('✅ Rate limiting Redis connected');
    } catch (err) {
      console.error('❌ Rate limiting Redis connection failed:', err.message);
      if (!this.failOpen) {
        throw err;
      }
    }
  }

  /**
   * Close Redis connection
   */
  async close() {
    if (this.client) {
      await this.client.quit();
    }
  }

  /**
   * Token Bucket Algorithm
   *
   * @param {string} key - Rate limit key (e.g., "ip:203.0.113.45:/api/login")
   * @param {number} maxRequests - Maximum requests allowed in window
   * @param {number} windowSeconds - Time window in seconds
   * @returns {Object} { allowed, limit, remaining, reset, retryAfter }
   */
  async checkRateLimit(key, maxRequests, windowSeconds) {
    const now = Date.now() / 1000;

    try {
      // Get bucket state from Redis
      const bucket = await this.client.hGetAll(`rate_limit:${key}`);

      let tokens, lastRefill;

      if (!bucket || !bucket.tokens) {
        // Initialize new bucket
        tokens = maxRequests - 1; // Consume 1 for this request
        lastRefill = now;
      } else {
        tokens = parseFloat(bucket.tokens);
        lastRefill = parseFloat(bucket.last_refill);

        // Refill tokens based on time elapsed
        const elapsed = now - lastRefill;
        const refillRate = maxRequests / windowSeconds;
        tokens = Math.min(maxRequests, tokens + (elapsed * refillRate));

        // Consume 1 token
        tokens -= 1;
      }

      // Check if allowed
      const allowed = tokens >= 0;

      if (allowed) {
        // Update bucket state in Redis
        await this.client.hSet(`rate_limit:${key}`, {
          tokens: tokens.toString(),
          last_refill: now.toString()
        });

        // Set TTL for auto-cleanup (2x window to handle refills)
        await this.client.expire(`rate_limit:${key}`, windowSeconds * 2);
      }

      // Calculate response values
      const remaining = Math.max(0, Math.floor(tokens));
      const reset = Math.floor(now + windowSeconds);
      const retryAfter = allowed ? 0 : windowSeconds;

      return {
        allowed,
        limit: maxRequests,
        remaining,
        reset,
        retryAfter
      };

    } catch (err) {
      console.error('Rate limit check failed:', err.message);

      if (this.failOpen) {
        // Fail-open: Allow request when Redis unavailable
        console.warn(`Rate limit fail-open triggered for key: ${key}`);
        return {
          allowed: true,
          limit: maxRequests,
          remaining: maxRequests,
          reset: Math.floor(now + windowSeconds),
          retryAfter: 0
        };
      } else {
        // Fail-closed: Block request when Redis unavailable
        return {
          allowed: false,
          limit: maxRequests,
          remaining: 0,
          reset: Math.floor(now + windowSeconds),
          retryAfter: windowSeconds
        };
      }
    }
  }

  /**
   * Get client IP address
   *
   * Handles X-Forwarded-For header from proxies/CDN.
   * Takes first IP in X-Forwarded-For (client IP).
   *
   * @param {Object} req - Express request object
   * @returns {string} Client IP address
   */
  getClientIp(req) {
    // Check X-Forwarded-For header (from proxy/CDN)
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
      // X-Forwarded-For: client, proxy1, proxy2
      // We want the client IP (first one)
      return forwardedFor.split(',')[0].trim();
    }

    // Fallback to direct connection IP
    return req.ip || req.connection.remoteAddress;
  }

  /**
   * Generate rate limit key based on strategy
   *
   * @param {Object} req - Express request object
   * @param {string} strategy - 'ip', 'user', or 'combined'
   * @param {string} userId - User ID (required for 'user' strategy)
   * @returns {string} Rate limit key
   */
  getRateLimitKey(req, strategy, userId = null) {
    const path = req.path;

    switch (strategy) {
      case 'ip':
        const ip = this.getClientIp(req);
        return `ip:${ip}:${path}`;

      case 'user':
        if (!userId) {
          throw new Error("userId required for 'user' strategy");
        }
        return `user:${userId}:${path}`;

      case 'combined':
        const clientIp = this.getClientIp(req);
        if (!userId) {
          return `ip:${clientIp}:${path}`;
        }
        return `combined:${userId}:${clientIp}:${path}`;

      default:
        throw new Error(`Invalid strategy: ${strategy}`);
    }
  }
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

/**
 * Express middleware for rate limiting
 *
 * @param {RateLimiter} rateLimiter - Rate limiter instance
 * @param {Object} rateLimits - Rate limit configuration (optional)
 * @returns {Function} Express middleware function
 */
function rateLimitMiddleware(rateLimiter, rateLimits = DEFAULT_RATE_LIMITS) {
  return async (req, res, next) => {
    // Skip rate limiting for certain paths
    if (SKIP_PATHS.some(skip => req.path.startsWith(skip))) {
      return next();
    }

    // Get rate limit configuration for this endpoint
    const config = rateLimits[req.path];

    if (!config) {
      // No rate limit configured, allow request
      return next();
    }

    // Get rate limit key
    const strategy = config.strategy || 'ip';
    const userId = req.user?.id || null; // Assumes auth middleware sets req.user

    const key = rateLimiter.getRateLimitKey(req, strategy, userId);

    // Check rate limit
    const result = await rateLimiter.checkRateLimit(
      key,
      config.limit,
      config.window
    );

    // Add rate limit headers
    res.set('X-RateLimit-Limit', result.limit.toString());
    res.set('X-RateLimit-Remaining', result.remaining.toString());
    res.set('X-RateLimit-Reset', result.reset.toString());

    if (!result.allowed) {
      // Rate limited - return 429
      console.warn(JSON.stringify({
        event: 'rate_limit.exceeded',
        ip: rateLimiter.getClientIp(req),
        endpoint: req.path,
        limit: result.limit
        // NO user data, NO request body
      }));

      res.set('Retry-After', result.retryAfter.toString());

      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: `Too many requests. Please try again in ${result.retryAfter} seconds.`,
        retryAfter: result.retryAfter
      });
    }

    // Allowed - continue to next middleware
    next();
  };
}

// ============================================================================
// ROUTE-LEVEL RATE LIMITING
// ============================================================================

/**
 * Rate limit decorator for specific routes
 *
 * Usage:
 *     app.post('/api/login', rateLimit({ limit: 5, window: 60 }), (req, res) => {
 *       ...
 *     });
 *
 * @param {Object} options - Rate limit options
 * @param {number} options.limit - Maximum requests
 * @param {number} options.window - Time window in seconds
 * @param {string} options.strategy - 'ip', 'user', or 'combined' (default: 'ip')
 * @returns {Function} Express middleware function
 */
function rateLimit(options) {
  const { limit, window, strategy = 'ip' } = options;

  return async (req, res, next) => {
    // Get rate limiter from app locals
    const rateLimiter = req.app.locals.rateLimiter;

    if (!rateLimiter) {
      console.error('Rate limiter not initialized in app.locals');
      return next();
    }

    // Get user ID if using 'user' strategy
    const userId = req.user?.id || null;

    // Get rate limit key
    const key = rateLimiter.getRateLimitKey(req, strategy, userId);

    // Check rate limit
    const result = await rateLimiter.checkRateLimit(key, limit, window);

    // Add headers
    res.set('X-RateLimit-Limit', result.limit.toString());
    res.set('X-RateLimit-Remaining', result.remaining.toString());
    res.set('X-RateLimit-Reset', result.reset.toString());

    if (!result.allowed) {
      res.set('Retry-After', result.retryAfter.toString());

      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: `Too many requests. Please try again in ${result.retryAfter} seconds.`,
        retryAfter: result.retryAfter
      });
    }

    next();
  };
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

/**
 * Check rate limiting health
 *
 * @param {RateLimiter} rateLimiter - Rate limiter instance
 * @returns {Object} Health status
 */
async function healthCheck(rateLimiter) {
  try {
    await rateLimiter.client.ping();
    return {
      rateLimiting: 'healthy',
      redis: 'connected'
    };
  } catch (err) {
    return {
      rateLimiting: 'degraded',
      redis: 'unavailable',
      error: err.message,
      failOpen: rateLimiter.failOpen
    };
  }
}

// ============================================================================
// EXAMPLE USAGE
// ============================================================================

/**
 * Example Express application
 *
 * // app.js
 *
 * const express = require('express');
 * const { RateLimiter, rateLimitMiddleware, rateLimit } = require('./rate-limiting');
 *
 * const app = express();
 *
 * // Initialize rate limiter
 * const rateLimiter = new RateLimiter(process.env.REDIS_URL);
 *
 * // Store in app.locals for route-level access
 * app.locals.rateLimiter = rateLimiter;
 *
 * // Apply middleware for automatic rate limiting
 * app.use(rateLimitMiddleware(rateLimiter));
 *
 * // Or use decorator for specific endpoints
 * app.post('/api/custom', rateLimit({ limit: 10, window: 60 }), (req, res) => {
 *   res.json({ message: 'Success' });
 * });
 *
 * // Startup
 * async function start() {
 *   await rateLimiter.connect();
 *   app.listen(3000, () => console.log('Server started on port 3000'));
 * }
 *
 * start();
 *
 * // Graceful shutdown
 * process.on('SIGINT', async () => {
 *   await rateLimiter.close();
 *   process.exit(0);
 * });
 */

// ============================================================================
// MONITORING
// ============================================================================

/**
 * Add Prometheus metrics
 *
 * const promClient = require('prom-client');
 *
 * const rateLimitExceeded = new promClient.Counter({
 *   name: 'rate_limit_exceeded_total',
 *   help: 'Total rate limit violations',
 *   labelNames: ['endpoint', 'strategy']
 * });
 *
 * const rateLimitLatency = new promClient.Histogram({
 *   name: 'rate_limit_check_duration_seconds',
 *   help: 'Time to check rate limit'
 * });
 *
 * // Usage in middleware
 * const start = Date.now();
 * const result = await rateLimiter.checkRateLimit(...);
 * rateLimitLatency.observe((Date.now() - start) / 1000);
 *
 * if (!result.allowed) {
 *   rateLimitExceeded.labels(req.path, strategy).inc();
 * }
 */

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  RateLimiter,
  rateLimitMiddleware,
  rateLimit,
  healthCheck
};
