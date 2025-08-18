// middleware/searchBlockingMiddleware.js

/**
 * Search Blocking Middleware
 * 
 * Integrates with SearchMonitoringService to block users who have been flagged for search abuse.
 * This provides an additional layer of protection beyond rate limiting.
 */

const searchMonitoringService = require('../services/searchMonitoringService');

/**
 * Middleware to check if user is blocked from searching
 */
function checkSearchBlocking(req, res, next) {
  try {
    // Only apply to GET requests with query parameters (search operations)
    if (req.method !== 'GET' || Object.keys(req.query).length === 0) {
      return next();
    }

    // Get user identifier (userId or IP)
    const userId = req.user?.id || req.session?.userId || req.currentUser?.id;
    const identifier = userId ? userId.toString() : req.ip;

    // Check if user/IP is blocked
    if (searchMonitoringService.isBlocked(identifier)) {
      console.warn('🚫 Blocked user attempted search:', {
        identifier,
        ip: req.ip,
        userId: userId ? userId.toString() : null,
        path: req.path,
        query: req.query,
        userAgent: req.get('user-agent'),
        timestamp: new Date().toISOString()
      });

      return res.status(429).json({
        success: false,
        error: 'Accès temporairement bloqué en raison d\'une activité de recherche suspecte.',
        code: 'SEARCH_TEMPORARILY_BLOCKED',
        retryAfter: 900, // 15 minutes
        contactSupport: true
      });
    }

    next();
  } catch (error) {
    console.error('❌ Error in search blocking middleware:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip,
      path: req.path,
      timestamp: new Date().toISOString()
    });
    
    // Don't block on middleware errors - let request proceed
    next();
  }
}

/**
 * Enhanced search blocking middleware with configurable options
 * @param {Object} options - Configuration options
 * @returns {Function} Configured middleware
 */
function createSearchBlockingMiddleware(options = {}) {
  const config = {
    checkAnonymousUsers: true,
    checkAuthenticatedUsers: true,
    logBlockedAttempts: true,
    customBlockedMessage: null,
    skipPaths: [],
    ...options
  };

  return (req, res, next) => {
    try {
      // Skip if path is in skip list
      if (config.skipPaths.some(path => req.path.includes(path))) {
        return next();
      }

      // Only apply to GET requests with query parameters (search operations)
      if (req.method !== 'GET' || Object.keys(req.query).length === 0) {
        return next();
      }

      const userId = req.user?.id || req.session?.userId || req.currentUser?.id;
      const isAuthenticated = !!userId;
      
      // Skip check based on configuration
      if (!isAuthenticated && !config.checkAnonymousUsers) {
        return next();
      }
      if (isAuthenticated && !config.checkAuthenticatedUsers) {
        return next();
      }

      const identifier = userId ? userId.toString() : req.ip;

      // Check if user/IP is blocked
      if (searchMonitoringService.isBlocked(identifier)) {
        if (config.logBlockedAttempts) {
          console.warn('🚫 Blocked user attempted search (enhanced):', {
            identifier,
            ip: req.ip,
            userId: userId ? userId.toString() : null,
            isAuthenticated,
            path: req.path,
            query: req.query,
            userAgent: req.get('user-agent'),
            timestamp: new Date().toISOString()
          });
        }

        const message = config.customBlockedMessage || 
          'Accès temporairement bloqué en raison d\'une activité de recherche suspecte.';

        return res.status(429).json({
          success: false,
          error: message,
          code: 'SEARCH_TEMPORARILY_BLOCKED',
          retryAfter: 900,
          contactSupport: true
        });
      }

      next();
    } catch (error) {
      console.error('❌ Error in enhanced search blocking middleware:', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        path: req.path,
        timestamp: new Date().toISOString()
      });
      
      // Don't block on middleware errors
      next();
    }
  };
}

/**
 * Middleware specifically for high-value endpoints that need extra protection
 */
function strictSearchBlockingMiddleware(req, res, next) {
  try {
    const userId = req.user?.id || req.session?.userId || req.currentUser?.id;
    const identifier = userId ? userId.toString() : req.ip;

    // Check blocking status
    if (searchMonitoringService.isBlocked(identifier)) {
      console.error('🔒 Strict blocking: High-value endpoint access blocked:', {
        identifier,
        ip: req.ip,
        path: req.path,
        query: req.query,
        userAgent: req.get('user-agent'),
        timestamp: new Date().toISOString()
      });

      return res.status(403).json({
        success: false,
        error: 'Accès refusé. Contactez le support technique.',
        code: 'STRICT_SEARCH_BLOCKED',
        contactSupport: true
      });
    }

    // Check for suspicious patterns even if not blocked
    const userProfile = searchMonitoringService.getUserSearchProfile(identifier);
    if (userProfile && userProfile.metrics.warnings.length >= 2) {
      console.warn('⚠️ Strict blocking: User with warnings accessing high-value endpoint:', {
        identifier,
        warningsCount: userProfile.metrics.warnings.length,
        recentWarnings: userProfile.metrics.warnings.slice(-2),
        path: req.path,
        timestamp: new Date().toISOString()
      });

      // Don't block but add extra monitoring
      req.highRiskUser = true;
    }

    next();
  } catch (error) {
    console.error('❌ Error in strict search blocking middleware:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip,
      path: req.path,
      timestamp: new Date().toISOString()
    });
    
    next();
  }
}

/**
 * Get search blocking status for a user (utility function)
 * @param {String} identifier - User identifier (userId or IP)
 * @returns {Object} Blocking status information
 */
function getSearchBlockingStatus(identifier) {
  try {
    const isBlocked = searchMonitoringService.isBlocked(identifier);
    const userProfile = searchMonitoringService.getUserSearchProfile(identifier);
    
    return {
      isBlocked,
      hasWarnings: userProfile ? userProfile.metrics.warnings.length > 0 : false,
      warningCount: userProfile ? userProfile.metrics.warnings.length : 0,
      lastActivity: userProfile ? userProfile.metrics.lastSearchTime : null,
      riskLevel: calculateRiskLevel(userProfile)
    };
  } catch (error) {
    console.error('Error getting search blocking status:', error);
    return {
      isBlocked: false,
      hasWarnings: false,
      warningCount: 0,
      lastActivity: null,
      riskLevel: 'unknown'
    };
  }
}

/**
 * Calculate risk level based on user profile
 * @param {Object} userProfile - User search profile
 * @returns {String} Risk level ('low', 'medium', 'high', 'critical')
 */
function calculateRiskLevel(userProfile) {
  if (!userProfile) return 'low';
  
  const { metrics } = userProfile;
  let riskScore = 0;
  
  // Warning-based scoring
  riskScore += metrics.warnings.length * 2;
  
  // Failed search ratio
  const failureRate = metrics.searchCount > 0 ? 
    (metrics.failedSearchCount / metrics.searchCount) : 0;
  if (failureRate > 0.3) riskScore += 3;
  
  // Suspicious query ratio
  const suspiciousRate = metrics.searchCount > 0 ? 
    (metrics.suspiciousQueryCount / metrics.searchCount) : 0;
  if (suspiciousRate > 0.1) riskScore += 4;
  
  // Complex search ratio
  const complexRate = metrics.searchCount > 0 ? 
    (metrics.complexSearchCount / metrics.searchCount) : 0;
  if (complexRate > 0.5) riskScore += 2;
  
  // Recent high activity
  const now = Date.now();
  const recentActivity = now - metrics.lastSearchTime < 5 * 60 * 1000; // 5 minutes
  if (recentActivity && metrics.searchCount > 20) riskScore += 2;
  
  // Determine risk level
  if (riskScore >= 10) return 'critical';
  if (riskScore >= 6) return 'high';
  if (riskScore >= 3) return 'medium';
  return 'low';
}

module.exports = {
  checkSearchBlocking,
  createSearchBlockingMiddleware,
  strictSearchBlockingMiddleware,
  getSearchBlockingStatus,
  calculateRiskLevel
};