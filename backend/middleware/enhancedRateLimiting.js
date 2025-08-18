/**
 * Enhanced Rate Limiting System
 * Provides sophisticated rate limiting for public routes with anti-bypass protection
 */

const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

class EnhancedRateLimiter {
  constructor() {
    // Configuration for different route categories
    this.config = {
      // Public routes (most restrictive)
      public: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 10, // 10 requests per window
        skipSuccessfulRequests: false,
        standardHeaders: true,
        legacyHeaders: false
      },
      
      // Public token-based routes
      publicToken: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 20, // 20 requests per window (slightly higher for legitimate token use)
        skipSuccessfulRequests: false,
        standardHeaders: true,
        legacyHeaders: false
      },
      
      // Authentication routes
      auth: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 5, // 5 attempts per window
        skipSuccessfulRequests: true, // Don't count successful logins
        standardHeaders: true,
        legacyHeaders: false
      },
      
      // File uploads
      upload: {
        windowMs: 60 * 60 * 1000, // 1 hour
        max: 10, // 10 uploads per hour
        skipSuccessfulRequests: false,
        standardHeaders: true,
        legacyHeaders: false
      },
      
      // API endpoints (authenticated)
      api: {
        windowMs: 1 * 60 * 1000, // 1 minute
        max: 60, // 60 requests per minute
        skipSuccessfulRequests: false,
        standardHeaders: true,
        legacyHeaders: false
      }
    };
    
    // Tracking for advanced rate limiting
    this.requestFingerprints = new Map();
    this.suspiciousPatterns = new Map();
    this.MAX_FINGERPRINTS = 10000;
  }
  
  /**
   * Generate a unique fingerprint for the request
   * Helps identify bypass attempts using different IPs but same patterns
   */
  generateFingerprint(req) {
    const components = [
      req.get('user-agent') || 'unknown',
      req.get('accept-language') || 'unknown',
      req.get('accept-encoding') || 'unknown',
      req.get('accept') || 'unknown',
      req.get('dnt') || '0',
      req.get('connection') || 'unknown',
      // Add timing pattern (requests at exact intervals might be bots)
      Math.floor(Date.now() / 1000) % 60
    ];
    
    // Create hash of components
    const fingerprint = crypto
      .createHash('sha256')
      .update(components.join('|'))
      .digest('hex')
      .substring(0, 16);
    
    return fingerprint;
  }
  
  /**
   * Advanced key generator that combines multiple factors
   * Prevents simple IP-based bypass attempts
   */
  advancedKeyGenerator(req) {
    const factors = [];
    
    // 1. IP address (primary factor)
    factors.push(req.ip || req.connection.remoteAddress);
    
    // 2. User agent hash (detect same client with different IPs)
    const userAgent = req.get('user-agent') || 'unknown';
    const uaHash = crypto
      .createHash('md5')
      .update(userAgent)
      .digest('hex')
      .substring(0, 8);
    factors.push(uaHash);
    
    // 3. Token if present (rate limit per token)
    const token = req.params?.token || req.body?.token || req.query?.token;
    if (token && /^[a-f0-9]{64}$/i.test(token)) {
      factors.push(token.substring(0, 8));
    }
    
    // 4. Session ID if authenticated
    if (req.session?.userId) {
      factors.push(`user:${req.session.userId}`);
    }
    
    // 5. Request pattern (similar requests from different IPs)
    const pattern = `${req.method}:${req.path.replace(/[a-f0-9]{64}/i, 'TOKEN')}`;
    factors.push(pattern);
    
    return factors.join(':');
  }
  
  /**
   * Detect and block distributed attacks
   * Identifies coordinated requests from multiple IPs
   */
  detectDistributedAttack(req) {
    const fingerprint = this.generateFingerprint(req);
    const now = Date.now();
    
    // Memory management
    if (this.requestFingerprints.size > this.MAX_FINGERPRINTS) {
      // Clean old entries
      const cutoff = now - 30 * 60 * 1000; // 30 minutes
      for (const [key, data] of this.requestFingerprints.entries()) {
        if (data.lastSeen < cutoff) {
          this.requestFingerprints.delete(key);
        }
      }
    }
    
    // Track fingerprint
    if (!this.requestFingerprints.has(fingerprint)) {
      this.requestFingerprints.set(fingerprint, {
        ips: new Set([req.ip]),
        count: 1,
        firstSeen: now,
        lastSeen: now
      });
    } else {
      const data = this.requestFingerprints.get(fingerprint);
      data.ips.add(req.ip);
      data.count++;
      data.lastSeen = now;
      
      // Detect distributed attack pattern
      if (data.ips.size > 5 && data.count > 50) {
        // Same fingerprint from many IPs = likely distributed attack
        console.warn('Distributed attack detected', {
          fingerprint,
          ipCount: data.ips.size,
          requestCount: data.count,
          duration: now - data.firstSeen
        });
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Create rate limiter with enhanced protection
   */
  createLimiter(type = 'public', customConfig = {}) {
    const config = { ...this.config[type], ...customConfig };
    
    // Skip rate limiting in test environment if configured
    if (process.env.NODE_ENV === 'test' && process.env.DISABLE_RATE_LIMITING === 'true') {
      return (req, res, next) => next();
    }
    
    return rateLimit({
      ...config,
      
      // Use advanced key generator
      keyGenerator: (req) => this.advancedKeyGenerator(req),
      
      // Custom handler for rate limit exceeded
      handler: (req, res) => {
        // Check for distributed attack
        if (this.detectDistributedAttack(req)) {
          console.error('Distributed attack blocked', {
            ip: req.ip,
            userAgent: req.get('user-agent'),
            path: req.path
          });
        }
        
        res.status(429).json({
          success: false,
          error: 'Too many requests. Please try again later.',
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: Math.ceil(config.windowMs / 1000)
        });
      },
      
      // Skip function for exempting certain requests
      skip: (req) => {
        // Skip for whitelisted IPs (e.g., monitoring services)
        const whitelist = process.env.RATE_LIMIT_WHITELIST?.split(',') || [];
        if (whitelist.includes(req.ip)) {
          return true;
        }
        
        // Skip for health checks
        if (req.path === '/health' || req.path === '/api/health') {
          return true;
        }
        
        return false;
      },
      
      // Request validation before applying rate limit
      validate: {
        // Ensure valid IP
        trustProxy: true,
        xForwardedForHeader: true
      }
    });
  }
  
  /**
   * Sliding window rate limiter for more accurate limiting
   */
  createSlidingWindowLimiter(type = 'public', customConfig = {}) {
    const config = { ...this.config[type], ...customConfig };
    const requestLog = new Map();
    
    return (req, res, next) => {
      if (process.env.NODE_ENV === 'test' && process.env.DISABLE_RATE_LIMITING === 'true') {
        return next();
      }
      
      const key = this.advancedKeyGenerator(req);
      const now = Date.now();
      const windowStart = now - config.windowMs;
      
      // Get or create request log for this key
      if (!requestLog.has(key)) {
        requestLog.set(key, []);
      }
      
      const requests = requestLog.get(key);
      
      // Remove old requests outside the window
      const recentRequests = requests.filter(timestamp => timestamp > windowStart);
      
      // Check if limit exceeded
      if (recentRequests.length >= config.max) {
        // Calculate retry after
        const oldestRequest = Math.min(...recentRequests);
        const retryAfter = Math.ceil((oldestRequest + config.windowMs - now) / 1000);
        
        return res.status(429).json({
          success: false,
          error: 'Too many requests. Please try again later.',
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: retryAfter > 0 ? retryAfter : 1
        });
      }
      
      // Add current request
      recentRequests.push(now);
      requestLog.set(key, recentRequests);
      
      // Clean up old entries periodically
      if (requestLog.size > 1000) {
        for (const [k, timestamps] of requestLog.entries()) {
          const recent = timestamps.filter(t => t > windowStart);
          if (recent.length === 0) {
            requestLog.delete(k);
          } else {
            requestLog.set(k, recent);
          }
        }
      }
      
      // Set rate limit headers
      res.setHeader('X-RateLimit-Limit', config.max);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, config.max - recentRequests.length));
      res.setHeader('X-RateLimit-Reset', new Date(now + config.windowMs).toISOString());
      
      next();
    };
  }
  
  /**
   * Token bucket rate limiter for burst protection
   */
  createTokenBucketLimiter(capacity = 10, refillRate = 1) {
    const buckets = new Map();
    
    return (req, res, next) => {
      if (process.env.NODE_ENV === 'test' && process.env.DISABLE_RATE_LIMITING === 'true') {
        return next();
      }
      
      const key = this.advancedKeyGenerator(req);
      const now = Date.now();
      
      if (!buckets.has(key)) {
        buckets.set(key, {
          tokens: capacity,
          lastRefill: now
        });
      }
      
      const bucket = buckets.get(key);
      
      // Refill tokens based on time elapsed
      const timePassed = (now - bucket.lastRefill) / 1000; // in seconds
      const tokensToAdd = timePassed * refillRate;
      bucket.tokens = Math.min(capacity, bucket.tokens + tokensToAdd);
      bucket.lastRefill = now;
      
      // Check if request can proceed
      if (bucket.tokens < 1) {
        const retryAfter = Math.ceil((1 - bucket.tokens) / refillRate);
        
        return res.status(429).json({
          success: false,
          error: 'Rate limit exceeded. Please slow down.',
          code: 'TOKEN_BUCKET_EMPTY',
          retryAfter
        });
      }
      
      // Consume a token
      bucket.tokens--;
      
      // Set headers
      res.setHeader('X-RateLimit-Limit', capacity);
      res.setHeader('X-RateLimit-Remaining', Math.floor(bucket.tokens));
      
      next();
    };
  }
  
  /**
   * Composite rate limiter combining multiple strategies
   */
  createCompositeLimiter(limiters) {
    return (req, res, next) => {
      let currentIndex = 0;
      
      const processNext = (err) => {
        if (err) return next(err);
        if (currentIndex >= limiters.length) return next();
        
        const limiter = limiters[currentIndex++];
        limiter(req, res, processNext);
      };
      
      processNext();
    };
  }
  
  /**
   * Get pre-configured limiters for common use cases
   */
  getPublicRouteLimiter() {
    return this.createCompositeLimiter([
      this.createLimiter('public'),
      this.createSlidingWindowLimiter('public'),
      this.createTokenBucketLimiter(5, 0.5) // 5 burst, 0.5 per second refill
    ]);
  }
  
  getPublicTokenLimiter() {
    return this.createCompositeLimiter([
      this.createLimiter('publicToken'),
      this.createTokenBucketLimiter(10, 1) // 10 burst, 1 per second refill
    ]);
  }
  
  getAuthLimiter() {
    return this.createCompositeLimiter([
      this.createLimiter('auth'),
      this.createTokenBucketLimiter(3, 0.1) // 3 attempts, slow refill
    ]);
  }
  
  getUploadLimiter() {
    return this.createLimiter('upload');
  }
  
  getApiLimiter() {
    return this.createSlidingWindowLimiter('api');
  }
}

// Export singleton instance
module.exports = new EnhancedRateLimiter();