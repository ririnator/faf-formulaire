// middleware/security.js
const helmet = require('helmet');
const crypto = require('crypto');
const TokenGenerator = require('../utils/tokenGenerator');

/**
 * Enhanced Security Middleware with Nonce-based CSP
 * Replaces unsafe-inline with secure nonce approach
 */

function generateNonce() {
  return TokenGenerator.generateNonce();
}

/**
 * Set advanced security headers for enterprise-grade protection
 */
function setAdvancedSecurityHeaders(res, req, isProduction) {
  const clientIP = req.ip || req.connection?.remoteAddress || 'unknown';
  
  // Security headers for all requests
  const securityHeaders = {
    // Prevent clickjacking with strict frame options
    'X-Frame-Options': 'DENY',
    
    // Enhanced XSS protection
    'X-XSS-Protection': '1; mode=block',
    
    // Prevent MIME sniffing attacks
    'X-Content-Type-Options': 'nosniff',
    
    // Referrer policy for privacy
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    
    // Permissions policy (Feature Policy replacement)
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
    
    // Clear site data on logout (for admin routes)
    ...(req.path === '/logout' && {
      'Clear-Site-Data': '"cache", "cookies", "storage", "executionContexts"'
    }),
    
    // Enhanced cache control for sensitive pages
    ...(req.path.includes('/admin') && {
      'Cache-Control': 'no-store, no-cache, must-revalidate, private, max-age=0',
      'Pragma': 'no-cache',
      'Expires': '0'
    }),
    
    // Server information hiding
    'Server': 'FAF-Server',
    
    // Additional security headers for production
    ...(isProduction && {
      // Expect Certificate Transparency
      'Expect-CT': 'max-age=86400, enforce',
      
      // Network Error Logging
      'NEL': JSON.stringify({
        report_to: 'default',
        max_age: 86400,
        include_subdomains: true
      }),
      
      // Report-To header for security reporting
      'Report-To': JSON.stringify({
        group: 'default',
        max_age: 86400,
        endpoints: [{ url: '/api/security-reports' }],
        include_subdomains: true
      })
    }),
    
    // Development-specific headers
    ...(!isProduction && {
      'X-Development-Mode': 'true'
    })
  };
  
  // Apply all security headers
  Object.entries(securityHeaders).forEach(([header, value]) => {
    if (value !== undefined && value !== null) {
      res.setHeader(header, value);
    }
  });
  
  // Request tracing header for security monitoring
  const requestId = require('crypto').randomBytes(16).toString('hex');
  res.setHeader('X-Request-ID', requestId);
  
  // Rate limiting headers
  const rateLimitInfo = getRateLimitInfo(clientIP);
  if (rateLimitInfo) {
    res.setHeader('X-RateLimit-Limit', rateLimitInfo.limit);
    res.setHeader('X-RateLimit-Remaining', rateLimitInfo.remaining);
    res.setHeader('X-RateLimit-Reset', rateLimitInfo.reset);
  }
}

/**
 * Get rate limiting information for client
 */
function getRateLimitInfo(clientIP) {
  // This would integrate with your rate limiting system
  // For now, return basic info
  return {
    limit: 100,
    remaining: 95,
    reset: Date.now() + (15 * 60 * 1000) // 15 minutes
  };
}

function createSecurityMiddleware() {
  return (req, res, next) => {
    // Enhanced security headers configuration
    const isProduction = process.env.NODE_ENV === 'production';
    const clientIP = req.ip || req.connection?.remoteAddress || 'unknown';
    
    // Pages that need nonce-based CSP
    const noncePages = ['/auth-choice', '/register', '/login', '/admin-login', '/', '/form'];
    
    // Advanced CSP for all pages
    const nonce = generateNonce();
    res.locals.nonce = nonce;
    
    // Set advanced security headers before Helmet
    setAdvancedSecurityHeaders(res, req, isProduction);
    
    // Skip enhanced CSP for static files but maintain basic security
    if ((req.path.startsWith('/api/') || 
        req.path === '/admin' ||
        req.path.startsWith('/admin/') ||
        req.path.endsWith('.html') || 
        req.path.endsWith('.css') || 
        req.path.endsWith('.js') ||
        req.path.includes('/frontend/') ||
        req.path.startsWith('/css/') ||
        req.path.startsWith('/js/')) && 
        !noncePages.includes(req.path)) {
      
      // Apply enhanced Helmet security for static files
      helmet({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "cdn.tailwindcss.com"], // Removed unsafe-inline for security
            scriptSrc: ["'self'", "cdn.tailwindcss.com", "cdn.jsdelivr.net"],
            imgSrc: ["'self'", "res.cloudinary.com", "*.cloudinary.com", "data:", "blob:"],
            fontSrc: ["'self'", "fonts.googleapis.com", "fonts.gstatic.com"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            frameAncestors: ["'none'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'", "res.cloudinary.com"],
            childSrc: ["'none'"],
            workerSrc: ["'self'"],
            manifestSrc: ["'self'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
          },
          reportOnly: false
        },
        crossOriginEmbedderPolicy: false,
        crossOriginResourcePolicy: { policy: "cross-origin" },
        crossOriginOpenerPolicy: "same-origin-allow-popups"
      })(req, res, next);
      return;
    }
    
    // Enhanced CSP for dynamic pages with strict nonce-based policy
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", `'nonce-${nonce}'`, "cdn.tailwindcss.com"],
          scriptSrc: ["'self'", `'nonce-${nonce}'`, "cdn.tailwindcss.com", "cdn.jsdelivr.net"],
          imgSrc: ["'self'", "res.cloudinary.com", "*.cloudinary.com", "data:", "blob:"],
          fontSrc: ["'self'", "fonts.googleapis.com", "fonts.gstatic.com"],
          connectSrc: ["'self'"],
          frameSrc: ["'none'"],
          frameAncestors: ["'none'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'", "res.cloudinary.com"],
          childSrc: ["'none'"],
          workerSrc: ["'self'"],
          manifestSrc: ["'self'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          upgradeInsecureRequests: isProduction ? [] : null,
          blockAllMixedContent: isProduction ? [] : null,
          requireTrustedTypesFor: ["'script'"],
          trustedTypes: ["default"]
        },
        reportOnly: false
      },
      crossOriginEmbedderPolicy: false,
      crossOriginResourcePolicy: { policy: "cross-origin" },
      crossOriginOpenerPolicy: "same-origin-allow-popups",
      // Enhanced HSTS for production
      hsts: isProduction ? {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
      } : false
    })(req, res, next);
  };
}

/**
 * Enhanced Session Configuration with Advanced Security
 * Comprehensive handling of dev vs prod environments with additional security measures
 */
function getSessionConfig() {
  const isProduction = process.env.NODE_ENV === 'production';
  const isHttps = process.env.HTTPS === 'true' || isProduction;
  
  return {
    cookie: {
      maxAge: 1000 * 60 * 60, // 1 hour
      httpOnly: true,
      
      // Enhanced logic for different environments
      sameSite: isProduction ? 'none' : 'lax',
      
      // Only require secure in production OR when explicitly using HTTPS
      secure: isHttps,
      
      // Additional security in production
      ...(isProduction && {
        domain: process.env.COOKIE_DOMAIN || undefined,
        path: '/'
      }),
      
      // Enhanced cookie security attributes
      priority: 'high', // Chrome cookie priority
      partitioned: isProduction // CHIPS cookies for third-party contexts
    },
    
    // Advanced session security configuration
    genid: () => {
      // Generate cryptographically secure session IDs
      const crypto = require('crypto');
      return crypto.randomBytes(32).toString('hex');
    },
    
    // Enhanced session rolling for security
    rolling: true, // Extend session on activity
    
    // Strict uninitialized session handling
    saveUninitialized: false,
    
    // Enhanced session resave logic
    resave: false
  };
}

/**
 * Development-friendly session configuration
 * Handles edge cases for local development
 */
function createSessionOptions() {
  const MongoStore = require('connect-mongo');
  const mongoose = require('mongoose');
  const baseConfig = getSessionConfig();
  
  // In test environment, use the existing mongoose connection instead of MONGODB_URI
  const sessionConfig = {
    secret: process.env.SESSION_SECRET || 'test-secret-for-tests',
    resave: false,
    saveUninitialized: false,
    name: 'faf-session', // Custom session name for security
    ...baseConfig
  };
  
  // Only create MongoStore if not in test environment or if explicitly needed
  if (process.env.NODE_ENV === 'test') {
    // In tests, use memory store or connect to the test database
    if (mongoose.connection.readyState === 1) {
      // Use existing test connection
      sessionConfig.store = MongoStore.create({
        client: mongoose.connection.getClient(),
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60,
        autoRemove: 'native'
      });
    } else {
      // Fallback to memory store for tests
      const MemoryStore = require('express-session').MemoryStore;
      sessionConfig.store = new MemoryStore();
    }
  } else {
    // Production/development - use MONGODB_URI
    sessionConfig.store = MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: 'sessions',
      ttl: 14 * 24 * 60 * 60,
      autoRemove: 'native'
    });
  }
  
  return sessionConfig;
}

/**
 * Environment detection helper
 */
function getEnvironmentInfo() {
  const isProduction = process.env.NODE_ENV === 'production';
  const isHttpsExplicit = process.env.HTTPS === 'true';
  
  return {
    isProduction,
    isDevelopment: process.env.NODE_ENV === 'development' || !process.env.NODE_ENV,
    isHttps: isHttpsExplicit || isProduction,
    hasCustomDomain: !!process.env.COOKIE_DOMAIN
  };
}

module.exports = {
  createSecurityMiddleware,
  createSessionOptions,
  getSessionConfig,
  getEnvironmentInfo,
  generateNonce
};