// Enhanced Auth-specific rate limiting middleware with device fingerprinting
const rateLimit = require('express-rate-limit');
const { APP_CONSTANTS } = require('../constants');
const deviceFingerprinting = require('../utils/deviceFingerprinting');
const SecureLogger = require('../utils/secureLogger');

// Enhanced rate limiting with device fingerprinting
const createAuthRateLimit = (options = {}) => {
  const {
    enableFingerprinting = true,
    suspiciousBehaviorMultiplier = 0.5, // Reduce limits for suspicious devices
    trustScoreThreshold = 5, // Below this score, apply stricter limits
    fingerprintingOptions = {},
    ...rateLimitOptions
  } = options;

  const defaults = {
    windowMs: APP_CONSTANTS.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000, // 15 minutes
    max: 5, // Base limit
    message: 'Trop de tentatives, veuillez réessayer plus tard',
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    
    // Enhanced key generator with device fingerprinting
    keyGenerator: (req) => {
      if (!enableFingerprinting) {
        // Fallback to basic IP + User-Agent
        return `${req.ip}:${req.get('user-agent') || 'unknown'}`;
      }

      try {
        // Generate comprehensive device fingerprint
        return deviceFingerprinting.generateRateLimitKey(req, {
          includeUserAgent: true,
          includeLanguage: true,
          includeSecHeaders: true,
          ...fingerprintingOptions
        });
      } catch (error) {
        SecureLogger.logError('Fingerprinting failed in rate limiter', error);
        return `${req.ip}:${req.get('user-agent') || 'unknown'}`;
      }
    },

    // Dynamic limit based on device trust score
    max: (req) => {
      if (!enableFingerprinting) {
        return rateLimitOptions.max || defaults.max;
      }

      try {
        const analysis = deviceFingerprinting.analyzeSuspiciousPatterns(req);
        const baseLimit = rateLimitOptions.max || defaults.max;
        
        // Apply stricter limits for suspicious devices
        if (analysis.trustScore < trustScoreThreshold) {
          const adjustedLimit = Math.max(1, Math.floor(baseLimit * suspiciousBehaviorMultiplier));
          
          SecureLogger.logInfo('Applied stricter rate limit for suspicious device', {
            trustScore: analysis.trustScore,
            originalLimit: baseLimit,
            adjustedLimit,
            suspiciousIndicators: analysis.indicators.length,
            fingerprint: deviceFingerprinting.generateFingerprint(req).substring(0, 8)
          });
          
          return adjustedLimit;
        }

        return baseLimit;
      } catch (error) {
        SecureLogger.logError('Dynamic limit calculation failed', error);
        return rateLimitOptions.max || defaults.max;
      }
    },

    // Enhanced handler with fingerprint logging
    handler: (req, res) => {
      try {
        // Log rate limit violation with device fingerprint analysis
        if (enableFingerprinting) {
          const report = deviceFingerprinting.generateFingerprintReport(req);
          
          SecureLogger.logInfo('Rate limit exceeded with device analysis', {
            fingerprint: report.fingerprint.substring(0, 8),
            trustScore: report.analysis.trustScore,
            suspiciousIndicators: report.analysis.indicators,
            userAgent: report.characteristics.userAgentParsed,
            ip: req.ip,
            endpoint: req.path
          });
        } else {
          SecureLogger.logInfo('Rate limit exceeded (basic)', {
            ip: req.ip,
            userAgent: req.get('user-agent'),
            endpoint: req.path
          });
        }
      } catch (error) {
        SecureLogger.logError('Rate limit handler logging failed', error);
      }

      const windowMs = rateLimitOptions.windowMs || defaults.windowMs;
      res.status(429).json({
        error: 'Trop de tentatives de connexion. Veuillez réessayer plus tard.',
        retryAfter: Math.round(windowMs / 1000),
        message: 'Rate limit exceeded. Please try again later.'
      });
    }
  };

  return rateLimit({ ...defaults, ...rateLimitOptions });
};

// Enhanced specific limiters for different auth operations
const authLimiters = {
  // Login: Strict fingerprinting with dynamic limits based on trust
  login: createAuthRateLimit({
    max: 5, // Base limit, reduced for suspicious devices
    skipFailedRequests: false,
    enableFingerprinting: true,
    suspiciousBehaviorMultiplier: 0.4, // Very strict for login attempts
    trustScoreThreshold: 6, // Higher threshold for login security
    fingerprintingOptions: {
      includeUserAgent: true,
      includeLanguage: true,
      includeSecHeaders: true,
      includeTiming: false
    }
  }),

  // Registration: Medium security with longer window
  register: createAuthRateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // Base limit
    message: 'Trop de tentatives d\'inscription',
    enableFingerprinting: true,
    suspiciousBehaviorMultiplier: 0.5, // Allow some flexibility for new users
    trustScoreThreshold: 4, // Lower threshold for registration
    fingerprintingOptions: {
      includeUserAgent: true,
      includeLanguage: true,
      includeSecHeaders: false // Less strict for registration
    }
  }),

  // Password reset: Enhanced security for sensitive operation
  passwordReset: createAuthRateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: 'Trop de demandes de réinitialisation',
    enableFingerprinting: true,
    suspiciousBehaviorMultiplier: 0.3, // Very strict for password reset
    trustScoreThreshold: 7, // High security threshold
    fingerprintingOptions: {
      includeUserAgent: true,
      includeLanguage: true,
      includeSecHeaders: true,
      includeTiming: true // Include timing for extra security
    }
  }),

  // Profile update: Moderate fingerprinting for authenticated users
  profileUpdate: createAuthRateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    skipSuccessfulRequests: true, // Only count failures
    enableFingerprinting: true,
    suspiciousBehaviorMultiplier: 0.6, // More lenient for authenticated users
    trustScoreThreshold: 3, // Lower threshold for profile updates
    fingerprintingOptions: {
      includeUserAgent: true,
      includeLanguage: false, // Less strict for profile updates
      includeSecHeaders: false
    }
  }),

  // API endpoints: Enhanced protection for API access
  api: createAuthRateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // Higher limit for API usage
    enableFingerprinting: true,
    suspiciousBehaviorMultiplier: 0.3, // Strict for API abuse
    trustScoreThreshold: 5,
    fingerprintingOptions: {
      includeUserAgent: true,
      includeLanguage: false,
      includeSecHeaders: true,
      includeTiming: true // Prevent rapid API abuse
    }
  }),

  // Form submission: Balanced approach for public forms
  formSubmission: createAuthRateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // Limit form spam
    enableFingerprinting: true,
    suspiciousBehaviorMultiplier: 0.5, // Moderate restriction
    trustScoreThreshold: 4,
    fingerprintingOptions: {
      includeUserAgent: true,
      includeLanguage: true,
      includeSecHeaders: false // Don't be too strict for forms
    }
  })
};

// Utility functions for enhanced rate limiting
const rateLimitUtils = {
  /**
   * Get device fingerprint report for a request
   */
  getDeviceReport: (req) => {
    try {
      return deviceFingerprinting.generateFingerprintReport(req);
    } catch (error) {
      SecureLogger.logError('Failed to generate device report', error);
      return null;
    }
  },

  /**
   * Analyze request for suspicious patterns
   */
  analyzeSuspiciousPatterns: (req) => {
    try {
      return deviceFingerprinting.analyzeSuspiciousPatterns(req);
    } catch (error) {
      SecureLogger.logError('Failed to analyze suspicious patterns', error);
      return { suspiciousCount: 0, indicators: [], trustScore: 5 };
    }
  },

  /**
   * Get fingerprinting cache statistics
   */
  getFingerprintingStats: () => {
    try {
      return deviceFingerprinting.getCacheStats();
    } catch (error) {
      SecureLogger.logError('Failed to get fingerprinting stats', error);
      return { size: 0, timeout: 0, entries: [] };
    }
  },

  /**
   * Clean fingerprinting cache manually
   */
  cleanFingerprintingCache: () => {
    try {
      deviceFingerprinting.cleanupCache();
      return true;
    } catch (error) {
      SecureLogger.logError('Failed to clean fingerprinting cache', error);
      return false;
    }
  },

  /**
   * Create rate limiter with custom fingerprinting options
   */
  createCustomRateLimit: (options) => {
    return createAuthRateLimit(options);
  },

  /**
   * Test device fingerprinting without rate limiting
   */
  testFingerprinting: (req) => {
    try {
      const report = deviceFingerprinting.generateFingerprintReport(req);
      const key = deviceFingerprinting.generateRateLimitKey(req);
      
      return {
        success: true,
        fingerprint: report.fingerprint,
        rateLimitKey: key,
        analysis: report.analysis,
        userAgent: report.characteristics.userAgentParsed
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        fallback: `${req.ip}:${req.get('user-agent') || 'unknown'}`
      };
    }
  }
};

// Middleware for adding fingerprint info to request object
const addFingerprintInfo = (req, res, next) => {
  try {
    req.deviceFingerprint = rateLimitUtils.getDeviceReport(req);
    req.suspiciousAnalysis = rateLimitUtils.analyzeSuspiciousPatterns(req);
  } catch (error) {
    SecureLogger.logError('Failed to add fingerprint info to request', error);
  }
  next();
};

// Monitoring middleware for rate limiting statistics
const rateLimitMonitoring = (req, res, next) => {
  const startTime = Date.now();
  
  // Add response handler to log rate limit statistics
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - startTime;
    
    // Log if this was a rate-limited request
    if (res.statusCode === 429) {
      SecureLogger.logInfo('Rate limit triggered', {
        ip: req.ip,
        path: req.path,
        method: req.method,
        userAgent: req.get('user-agent'),
        duration,
        fingerprint: req.deviceFingerprint?.fingerprint?.substring(0, 8),
        trustScore: req.suspiciousAnalysis?.trustScore
      });
    }
    
    return originalSend.call(this, data);
  };
  
  next();
};

module.exports = {
  createAuthRateLimit,
  authLimiters,
  rateLimitUtils,
  addFingerprintInfo,
  rateLimitMonitoring,
  deviceFingerprinting // Export for direct access if needed
};