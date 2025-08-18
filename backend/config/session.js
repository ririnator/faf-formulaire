const session = require('express-session');
const MongoStore = require('connect-mongo');
const SessionCleanupService = require('../services/sessionCleanupService');
const SecureLogger = require('../utils/secureLogger');
const crypto = require('crypto');

class SessionConfig {
  static cleanupService = null;
  static sessionTimeouts = new Map(); // Track session activity
  static renewalThreshold = 15 * 60 * 1000; // 15 minutes
  static _testSessionStoreWarningShown = false; // Track if we've shown the warning
  static _sessionStoreCache = null; // Cache for session store
  
  /**
   * Create session store configuration for tests with MongoDB fallback
   */
  static createTestSessionStore() {
    if (this._sessionStoreCache) {
      return this._sessionStoreCache;
    }
    
    const mongoose = require('mongoose');
    
    if (mongoose.connection.readyState === 1) {
      try {
        this._sessionStoreCache = MongoStore.create({
          client: mongoose.connection.getClient(),
          collectionName: 'test_sessions',
          ttl: 60 * 60,    // 1 hour for tests
          autoRemove: 'native',
          touchAfter: 0,   // Always update for tests
          createAutoRemoveIdx: true,
          autoRemoveInterval: 10, // Remove expired sessions every 10 minutes
          stringify: false // Use native MongoDB BSON instead of JSON
        });
        
        if (!this._testSessionStoreWarningShown) {
          console.log('✅ MongoDB session store initialized for tests');
          this._testSessionStoreWarningShown = true;
        }
        
        return this._sessionStoreCache;
      } catch (error) {
        // Fall back to memory store
        if (!this._testSessionStoreWarningShown) {
          console.warn('⚠️ Failed to create MongoDB session store for tests, using memory store:', error.message);
          this._testSessionStoreWarningShown = true;
        }
        return null;
      }
    }
    
    // MongoDB not ready - use memory store
    return null;
  }
  
  static getConfig() {
    // Use default secret for tests to avoid env requirement
    const secret = process.env.SESSION_SECRET || 'test-secret-key-for-testing-only';
    
    if (!secret) {
      throw new Error('SESSION_SECRET manquant dans les variables d\'environnement');
    }

    // Configure MongoDB store based on environment
    let storeConfig = {};
    
    if (process.env.NODE_ENV === 'test') {
      // For tests, use memory store to avoid MongoDB session conflicts
      // This is safer and eliminates session expiration issues during testing
      storeConfig = null; // Use default memory store for tests
    } else {
      // Production/development - use MONGODB_URI
      if (!process.env.MONGODB_URI) {
        throw new Error('MONGODB_URI manquant pour le store de sessions');
      }
      storeConfig = {
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60,    // 14 jours
        autoRemove: 'native',
        touchAfter: 24 * 3600      // Mise à jour max 1x/24h
      };
    }

    const config = {
      secret: secret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 1000 * 60 * 60,    // 1 heure
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        secure: process.env.NODE_ENV === 'production' || process.env.HTTPS === 'true',
        httpOnly: true,
        signed: true  // Enable signed cookies for tamper protection
      },
      genid: () => {
        // Generate cryptographically secure session IDs
        return crypto.randomBytes(32).toString('hex');
      },
      rolling: true,  // Reset expiration on each request
      unset: 'destroy',  // Delete session when unset
      name: 'faf.session'
    };

    // Add MongoDB store only if configuration available
    if (storeConfig) {
      if (storeConfig.store) {
        // Pre-created store (for tests)
        config.store = storeConfig.store;
      } else {
        // Create new store (for production/development)
        config.store = MongoStore.create(storeConfig);
      }
    }

    return config;
  }

  static middleware() {
    return session(this.getConfig());
  }

  /**
   * Initialize session cleanup service
   */
  static initializeCleanupService() {
    if (!this.cleanupService) {
      this.cleanupService = new SessionCleanupService();
      this.cleanupService.initialize();
    }
    return this.cleanupService;
  }

  /**
   * Get cleanup service instance
   */
  static getCleanupService() {
    return this.cleanupService;
  }

  /**
   * Session renewal middleware for active users
   */
  static sessionRenewal() {
    return (req, res, next) => {
      if (!req.session || !req.sessionID) {
        return next();
      }

      const now = Date.now();
      const sessionId = req.sessionID;
      const lastActivity = this.sessionTimeouts.get(sessionId) || 0;
      const timeSinceActivity = now - lastActivity;

      // Update activity timestamp
      this.sessionTimeouts.set(sessionId, now);

      // Auto-renew session if within renewal threshold and user is active
      if (timeSinceActivity > this.renewalThreshold && req.session.userId) {
        req.session.touch(); // Refresh session expiration
        SecureLogger.logInfo('Session renewed for active user', {
          sessionId: sessionId.substring(0, 8) + '...',
          userId: req.session.userId.toString().substring(0, 8) + '...',
          lastActivity: new Date(lastActivity).toISOString()
        });
      }

      next();
    };
  }

  /**
   * Session fixation protection
   */
  static regenerateSession() {
    return (req, res, next) => {
      if (req.session && req.session.regenerate) {
        const oldSessionData = { ...req.session };
        
        req.session.regenerate((err) => {
          if (err) {
            SecureLogger.logError('Session regeneration failed', err);
            return next();
          }
          
          // Restore session data after regeneration
          Object.assign(req.session, oldSessionData);
          
          SecureLogger.logInfo('Session regenerated', {
            newSessionId: req.sessionID.substring(0, 8) + '...',
            userId: req.session.userId ? req.session.userId.toString().substring(0, 8) + '...' : 'anonymous'
          });
          
          next();
        });
      } else {
        next();
      }
    };
  }

  /**
   * Idle timeout detection
   */
  static idleTimeoutCheck() {
    return (req, res, next) => {
      if (!req.session || !req.sessionID) {
        return next();
      }

      const now = Date.now();
      const sessionId = req.sessionID;
      const lastActivity = req.session.lastActivity || req.session.cookie.maxAge;
      const idleTime = now - lastActivity;
      const maxIdleTime = 30 * 60 * 1000; // 30 minutes

      if (idleTime > maxIdleTime && req.session.userId) {
        SecureLogger.logWarning('Session expired due to inactivity', {
          sessionId: sessionId.substring(0, 8) + '...',
          userId: req.session.userId.toString().substring(0, 8) + '...',
          idleTimeMinutes: Math.floor(idleTime / 60000)
        });
        
        req.session.destroy((err) => {
          if (err) {
            SecureLogger.logError('Failed to destroy idle session', err);
          }
          
          if (req.accepts('html')) {
            return res.redirect('/login?timeout=1');
          } else {
            return res.status(401).json({
              error: 'Session expired due to inactivity',
              code: 'SESSION_TIMEOUT'
            });
          }
        });
      } else {
        // Update last activity
        req.session.lastActivity = now;
        next();
      }
    };
  }

  /**
   * Session integrity validation
   */
  static validateSessionIntegrity() {
    return (req, res, next) => {
      if (!req.session) {
        return next();
      }

      // Check for session tampering indicators
      const suspiciousChanges = [];
      
      // Validate user agent consistency
      if (req.session.userAgent && req.session.userAgent !== req.get('User-Agent')) {
        suspiciousChanges.push('user_agent_changed');
      }
      
      // Validate IP consistency (with proxy tolerance)
      if (req.session.clientIP) {
        const currentIP = req.ip || req.connection.remoteAddress;
        const sessionIP = req.session.clientIP;
        
        // Allow IP changes within same subnet for dynamic IPs
        if (!this.isIPInSameSubnet(currentIP, sessionIP)) {
          suspiciousChanges.push('ip_changed');
        }
      }

      if (suspiciousChanges.length > 0) {
        SecureLogger.logWarning('Suspicious session changes detected', {
          sessionId: req.sessionID.substring(0, 8) + '...',
          changes: suspiciousChanges,
          currentIP: req.ip,
          sessionIP: req.session.clientIP,
          currentUA: req.get('User-Agent'),
          sessionUA: req.session.userAgent
        });
        
        // Destroy session if multiple suspicious changes
        if (suspiciousChanges.length > 1) {
          req.session.destroy();
          return res.status(401).json({
            error: 'Session security violation detected',
            code: 'SESSION_VIOLATION'
          });
        }
      }

      // Store current request info for future validation
      if (!req.session.userAgent) {
        req.session.userAgent = req.get('User-Agent');
      }
      if (!req.session.clientIP) {
        req.session.clientIP = req.ip || req.connection.remoteAddress;
      }

      next();
    };
  }

  /**
   * Check if two IPs are in the same subnet (for dynamic IP tolerance)
   */
  static isIPInSameSubnet(ip1, ip2) {
    if (!ip1 || !ip2) return false;
    
    // Simple IPv4 subnet check (first 3 octets)
    const parts1 = ip1.split('.');
    const parts2 = ip2.split('.');
    
    if (parts1.length === 4 && parts2.length === 4) {
      return parts1.slice(0, 3).join('.') === parts2.slice(0, 3).join('.');
    }
    
    return ip1 === ip2;
  }

  /**
   * Clean up session timeout tracking
   */
  static cleanupTimeouts() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    for (const [sessionId, timestamp] of this.sessionTimeouts.entries()) {
      if (now - timestamp > maxAge) {
        this.sessionTimeouts.delete(sessionId);
      }
    }
  }

  /**
   * Initialize session store for tests after MongoDB is ready
   */
  static initializeTestSessionStore() {
    if (process.env.NODE_ENV === 'test') {
      this._sessionStoreCache = null; // Reset cache
      return this.createTestSessionStore();
    }
    return null;
  }
  
  /**
   * Reset session store cache (for tests)
   */
  static resetSessionStoreCache() {
    this._sessionStoreCache = null;
    this._testSessionStoreWarningShown = false;
  }
  
  /**
   * Shutdown cleanup service
   */
  static shutdownCleanupService() {
    if (this.cleanupService) {
      this.cleanupService.shutdown();
      this.cleanupService = null;
    }
    
    // Clear timeout tracking
    this.sessionTimeouts.clear();
    
    // Clear session store cache
    this.resetSessionStoreCache();
  }
}

module.exports = SessionConfig;