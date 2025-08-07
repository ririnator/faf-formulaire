// middleware/security.js
const helmet = require('helmet');
const crypto = require('crypto');

/**
 * Enhanced Security Middleware with Nonce-based CSP
 * Replaces unsafe-inline with secure nonce approach
 */

function generateNonce() {
  return crypto.randomBytes(16).toString('base64');
}

function createSecurityMiddleware() {
  return (req, res, next) => {
    // Skip CSP completely for static content and HTML files
    // This allows CSS and JavaScript to load without nonce requirements
    if (req.path.startsWith('/api/') || 
        req.path === '/' || 
        req.path === '/admin' ||
        req.path.startsWith('/admin/') ||
        req.path.endsWith('.html') || 
        req.path.endsWith('.css') || 
        req.path.endsWith('.js') ||
        req.path.includes('/frontend/') ||
        req.path.startsWith('/css/') ||
        req.path.startsWith('/js/')) {
      
      // Apply basic Helmet security without CSP for static files
      helmet({
        contentSecurityPolicy: false, // Completely disable CSP for static content
        crossOriginEmbedderPolicy: false
      })(req, res, next);
      return;
    }
    
    // For other dynamic pages (if any), use nonce-based CSP
    const nonce = generateNonce();
    res.locals.nonce = nonce;
    
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", `'nonce-${nonce}'`, "cdn.tailwindcss.com"],
          scriptSrc: ["'self'", `'nonce-${nonce}'`, "cdn.tailwindcss.com", "cdn.jsdelivr.net"],
          imgSrc: ["'self'", "res.cloudinary.com", "*.cloudinary.com", "data:"],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"],
          frameSrc: ["'none'"],
          frameAncestors: ["'none'"]
        }
      },
      crossOriginEmbedderPolicy: false
    })(req, res, next);
  };
}

/**
 * Enhanced Session Configuration
 * Better handling of dev vs prod environments
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
      })
    }
  };
}

/**
 * Development-friendly session configuration
 * Handles edge cases for local development
 */
function createSessionOptions() {
  const MongoStore = require('connect-mongo');
  const baseConfig = getSessionConfig();
  
  return {
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: 'sessions',
      ttl: 14 * 24 * 60 * 60,    // 14 days
      autoRemove: 'native'
    }),
    name: 'faf-session', // Custom session name for security
    ...baseConfig
  };
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