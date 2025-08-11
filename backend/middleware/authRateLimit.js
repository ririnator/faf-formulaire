// Auth-specific rate limiting middleware
const rateLimit = require('express-rate-limit');
const { APP_CONSTANTS } = require('../constants');

// Stricter rate limiting for authentication endpoints
const createAuthRateLimit = (options = {}) => {
  const defaults = {
    windowMs: APP_CONSTANTS.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit to 5 attempts per window for auth
    message: 'Trop de tentatives, veuillez réessayer plus tard',
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false, // Count all requests
    keyGenerator: (req) => {
      // Use IP + user-agent for better tracking
      return `${req.ip}:${req.get('user-agent') || 'unknown'}`;
    },
    handler: (req, res) => {
      res.status(429).json({
        error: 'Trop de tentatives de connexion. Veuillez réessayer dans 15 minutes.',
        retryAfter: Math.round(options.windowMs / 1000)
      });
    }
  };

  return rateLimit({ ...defaults, ...options });
};

// Specific limiters for different auth operations
const authLimiters = {
  // Login: 5 attempts per 15 minutes
  login: createAuthRateLimit({
    max: 5,
    skipFailedRequests: false
  }),

  // Registration: 3 attempts per hour
  register: createAuthRateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3,
    message: 'Trop de tentatives d\'inscription'
  }),

  // Password reset: 3 attempts per hour
  passwordReset: createAuthRateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: 'Trop de demandes de réinitialisation'
  }),

  // Profile update: 10 attempts per hour
  profileUpdate: createAuthRateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    skipSuccessfulRequests: true // Only count failures
  })
};

module.exports = {
  createAuthRateLimit,
  authLimiters
};