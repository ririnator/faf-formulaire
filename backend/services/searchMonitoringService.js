// services/searchMonitoringService.js

/**
 * Search Monitoring Service
 * 
 * Tracks search patterns, detects abuse, and provides analytics for search behavior.
 * Integrates with the existing session monitoring infrastructure for comprehensive security.
 */

class SearchMonitoringService {
  constructor() {
    // In-memory storage for search patterns (in production, use Redis or database)
    this.searchPatterns = new Map(); // userId/IP -> search history
    this.abuseDetection = new Map(); // userId/IP -> abuse metrics
    this.blockedSearchers = new Set(); // Temporarily blocked IPs/users
    this.cleanupInterval = null; // Store interval reference for cleanup
    
    // Configuration
    this.config = {
      // Time windows for pattern analysis
      shortTermWindow: 5 * 60 * 1000,    // 5 minutes
      mediumTermWindow: 30 * 60 * 1000,  // 30 minutes
      longTermWindow: 60 * 60 * 1000,    // 1 hour
      
      // Abuse detection thresholds
      maxSearchesPerMinute: 10,
      maxComplexSearchesPerHour: 15,
      maxFailedSearchesPerHour: 20,
      suspiciousQueryPatterns: [
        /'.{100,}/, // Very long queries
        /script|javascript|eval|exec/i, // Injection attempts
        /union|select|drop|delete|insert/i, // SQL injection patterns
        /<[^>]*>/, // HTML/XML tags
        /\$\w+/, // MongoDB injection patterns
      ],
      
      // Temporary block duration
      blockDurationMs: 15 * 60 * 1000, // 15 minutes
      
      // Clean up intervals
      cleanupIntervalMs: 10 * 60 * 1000, // 10 minutes
      
      // Enable/disable cleanup interval (for testing)
      enableCleanupInterval: process.env.NODE_ENV !== 'test'
    };
    
    // Start cleanup interval only if enabled
    if (this.config.enableCleanupInterval) {
      this.startCleanupInterval();
    }
  }

  /**
   * Record a search event for monitoring
   * @param {Object} searchEvent - Search event data
   */
  recordSearchEvent(searchEvent) {
    const {
      userId,
      ip,
      query,
      path,
      complexity,
      responseTime,
      resultCount,
      success,
      userAgent
    } = searchEvent;

    const identifier = userId || ip;
    const timestamp = Date.now();
    
    // Initialize tracking if needed
    if (!this.searchPatterns.has(identifier)) {
      this.searchPatterns.set(identifier, []);
      this.abuseDetection.set(identifier, {
        searchCount: 0,
        complexSearchCount: 0,
        failedSearchCount: 0,
        suspiciousQueryCount: 0,
        lastSearchTime: 0,
        firstSearchTime: timestamp,
        blocked: false,
        warnings: []
      });
    }

    const history = this.searchPatterns.get(identifier);
    const metrics = this.abuseDetection.get(identifier);

    // Add to search history
    history.push({
      timestamp,
      query,
      path,
      complexity,
      responseTime,
      resultCount,
      success,
      userAgent,
      ip: userId ? ip : null // Store IP separately for authenticated users
    });

    // Update metrics
    metrics.searchCount++;
    metrics.lastSearchTime = timestamp;
    
    if (!success) {
      metrics.failedSearchCount++;
    }
    
    if (complexity && (complexity.level === 'high' || complexity.level === 'critical')) {
      metrics.complexSearchCount++;
    }
    
    // Check for suspicious patterns
    if (this.isSuspiciousQuery(query)) {
      metrics.suspiciousQueryCount++;
      this.logSecurityEvent('suspicious_query', {
        identifier,
        query: query.substring(0, 200), // Truncate for logging
        ip,
        userId,
        userAgent
      });
    }

    // Detect abuse patterns
    const abuseDetected = this.detectAbuse(identifier, metrics, history);
    if (abuseDetected) {
      this.handleAbuseDetection(identifier, abuseDetected, {
        ip,
        userId,
        userAgent,
        recentSearches: history.slice(-5) // Last 5 searches
      });
    }

    // Keep only recent history (last hour)
    const cutoffTime = timestamp - this.config.longTermWindow;
    const filteredHistory = history.filter(event => event.timestamp > cutoffTime);
    this.searchPatterns.set(identifier, filteredHistory);
  }

  /**
   * Check if a query contains suspicious patterns
   * @param {String} query - Search query to analyze
   * @returns {Boolean} True if suspicious
   */
  isSuspiciousQuery(query) {
    if (!query || typeof query !== 'string') return false;
    
    return this.config.suspiciousQueryPatterns.some(pattern => 
      pattern.test(query)
    );
  }

  /**
   * Detect abuse patterns in search behavior
   * @param {String} identifier - User identifier (userId or IP)
   * @param {Object} metrics - Current abuse metrics
   * @param {Array} history - Search history
   * @returns {Object|null} Abuse detection result
   */
  detectAbuse(identifier, metrics, history) {
    const now = Date.now();
    
    // Rate-based abuse detection
    const recentSearches = history.filter(
      event => now - event.timestamp < this.config.shortTermWindow
    );
    
    const searchRate = recentSearches.length / (this.config.shortTermWindow / 60000); // per minute
    
    if (searchRate > this.config.maxSearchesPerMinute) {
      return {
        type: 'high_search_rate',
        severity: 'high',
        details: {
          rate: searchRate,
          threshold: this.config.maxSearchesPerMinute,
          window: 'short_term'
        }
      };
    }

    // Complex search abuse
    const recentComplexSearches = history.filter(
      event => now - event.timestamp < this.config.longTermWindow &&
      event.complexity && 
      (event.complexity.level === 'high' || event.complexity.level === 'critical')
    );
    
    if (recentComplexSearches.length > this.config.maxComplexSearchesPerHour) {
      return {
        type: 'complex_search_abuse',
        severity: 'medium',
        details: {
          count: recentComplexSearches.length,
          threshold: this.config.maxComplexSearchesPerHour,
          window: 'long_term'
        }
      };
    }

    // Failed search spam
    const recentFailedSearches = history.filter(
      event => now - event.timestamp < this.config.longTermWindow &&
      !event.success
    );
    
    if (recentFailedSearches.length > this.config.maxFailedSearchesPerHour) {
      return {
        type: 'failed_search_spam',
        severity: 'medium',
        details: {
          count: recentFailedSearches.length,
          threshold: this.config.maxFailedSearchesPerHour,
          window: 'long_term'
        }
      };
    }

    // Suspicious query patterns
    if (metrics.suspiciousQueryCount > 3) {
      return {
        type: 'suspicious_queries',
        severity: 'high',
        details: {
          count: metrics.suspiciousQueryCount,
          threshold: 3
        }
      };
    }

    // Pattern-based detection (repeated identical searches)
    const uniqueQueries = new Set(recentSearches.map(s => s.query));
    if (recentSearches.length > 10 && uniqueQueries.size < 3) {
      return {
        type: 'repetitive_searches',
        severity: 'medium',
        details: {
          totalSearches: recentSearches.length,
          uniqueQueries: uniqueQueries.size
        }
      };
    }

    return null;
  }

  /**
   * Handle detected abuse
   * @param {String} identifier - User identifier
   * @param {Object} abuseInfo - Abuse detection details
   * @param {Object} context - Additional context
   */
  handleAbuseDetection(identifier, abuseInfo, context) {
    const metrics = this.abuseDetection.get(identifier);
    
    // Log the abuse detection
    this.logSecurityEvent('search_abuse_detected', {
      identifier,
      abuse: abuseInfo,
      context,
      metrics: {
        totalSearches: metrics.searchCount,
        failedSearches: metrics.failedSearchCount,
        suspiciousQueries: metrics.suspiciousQueryCount
      }
    });

    // Add warning to metrics
    metrics.warnings.push({
      timestamp: Date.now(),
      type: abuseInfo.type,
      severity: abuseInfo.severity,
      details: abuseInfo.details
    });

    // Implement progressive penalties
    if (abuseInfo.severity === 'high' || metrics.warnings.length >= 3) {
      this.temporaryBlock(identifier, abuseInfo);
    }
  }

  /**
   * Temporarily block a user/IP from searching
   * @param {String} identifier - User identifier
   * @param {Object} reason - Reason for blocking
   */
  temporaryBlock(identifier, reason) {
    this.blockedSearchers.add(identifier);
    
    // Set automatic unblock
    setTimeout(() => {
      this.blockedSearchers.delete(identifier);
      this.logSecurityEvent('search_block_lifted', {
        identifier,
        blockDuration: this.config.blockDurationMs
      });
    }, this.config.blockDurationMs);

    this.logSecurityEvent('search_user_blocked', {
      identifier,
      reason,
      duration: this.config.blockDurationMs
    });
  }

  /**
   * Check if a user/IP is currently blocked
   * @param {String} identifier - User identifier
   * @returns {Boolean} True if blocked
   */
  isBlocked(identifier) {
    return this.blockedSearchers.has(identifier);
  }

  /**
   * Get search statistics for monitoring dashboard
   * @param {String} timeWindow - Time window ('short', 'medium', 'long')
   * @returns {Object} Search statistics
   */
  getSearchStatistics(timeWindow = 'medium') {
    const now = Date.now();
    let windowMs;
    
    switch (timeWindow) {
      case 'short':
        windowMs = this.config.shortTermWindow;
        break;
      case 'long':
        windowMs = this.config.longTermWindow;
        break;
      default:
        windowMs = this.config.mediumTermWindow;
    }

    const cutoffTime = now - windowMs;
    let totalSearches = 0;
    let totalUsers = 0;
    let complexSearches = 0;
    let failedSearches = 0;
    let suspiciousSearches = 0;
    let blockedUsers = this.blockedSearchers.size;

    for (const [identifier, history] of this.searchPatterns.entries()) {
      const recentSearches = history.filter(event => event.timestamp > cutoffTime);
      
      if (recentSearches.length > 0) {
        totalUsers++;
        totalSearches += recentSearches.length;
        
        complexSearches += recentSearches.filter(s => 
          s.complexity && (s.complexity.level === 'high' || s.complexity.level === 'critical')
        ).length;
        
        failedSearches += recentSearches.filter(s => !s.success).length;
        
        suspiciousSearches += recentSearches.filter(s => 
          this.isSuspiciousQuery(s.query)
        ).length;
      }
    }

    return {
      timeWindow,
      windowMs,
      totalSearches,
      totalUsers,
      complexSearches,
      failedSearches,
      suspiciousSearches,
      blockedUsers,
      averageSearchesPerUser: totalUsers > 0 ? (totalSearches / totalUsers).toFixed(2) : 0,
      complexSearchRate: totalSearches > 0 ? ((complexSearches / totalSearches) * 100).toFixed(1) : 0,
      failureRate: totalSearches > 0 ? ((failedSearches / totalSearches) * 100).toFixed(1) : 0,
      timestamp: now
    };
  }

  /**
   * Log security events
   * @param {String} eventType - Type of security event
   * @param {Object} data - Event data
   */
  logSecurityEvent(eventType, data) {
    console.warn(`🔍 Search Security Event: ${eventType}`, {
      type: eventType,
      timestamp: new Date().toISOString(),
      ...data
    });
    
    // In production, integrate with your logging system or security monitoring
    // this.securityLogger.log(eventType, data);
  }

  /**
   * Start cleanup interval to remove old data
   */
  startCleanupInterval() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, this.config.cleanupIntervalMs);
  }

  /**
   * Stop cleanup interval (for testing)
   */
  stopCleanupInterval() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Cleanup old search data and metrics
   */
  cleanup() {
    const now = Date.now();
    const cutoffTime = now - this.config.longTermWindow;
    
    // Clean up search patterns
    for (const [identifier, history] of this.searchPatterns.entries()) {
      const filteredHistory = history.filter(event => event.timestamp > cutoffTime);
      
      if (filteredHistory.length === 0) {
        this.searchPatterns.delete(identifier);
        this.abuseDetection.delete(identifier);
      } else {
        this.searchPatterns.set(identifier, filteredHistory);
      }
    }

    // Clean up old warnings in abuse detection
    for (const [identifier, metrics] of this.abuseDetection.entries()) {
      metrics.warnings = metrics.warnings.filter(
        warning => now - warning.timestamp < this.config.longTermWindow
      );
    }

    console.log(`🧹 Search monitoring cleanup completed. Active patterns: ${this.searchPatterns.size}`);
  }

  /**
   * Get user search profile for analysis
   * @param {String} identifier - User identifier
   * @returns {Object|null} User search profile
   */
  getUserSearchProfile(identifier) {
    const history = this.searchPatterns.get(identifier);
    const metrics = this.abuseDetection.get(identifier);
    
    if (!history || !metrics) {
      return null;
    }

    const now = Date.now();
    const recentSearches = history.filter(
      event => now - event.timestamp < this.config.mediumTermWindow
    );

    return {
      identifier,
      metrics,
      recentActivity: {
        searchCount: recentSearches.length,
        uniqueQueries: new Set(recentSearches.map(s => s.query)).size,
        averageComplexity: this.calculateAverageComplexity(recentSearches),
        mostSearchedPaths: this.getMostSearchedPaths(recentSearches),
        isBlocked: this.isBlocked(identifier)
      },
      timeline: recentSearches.slice(-10) // Last 10 searches
    };
  }

  /**
   * Calculate average complexity of searches
   * @param {Array} searches - Array of search events
   * @returns {Number} Average complexity score
   */
  calculateAverageComplexity(searches) {
    const complexityScores = searches
      .filter(s => s.complexity && s.complexity.score)
      .map(s => s.complexity.score);
    
    if (complexityScores.length === 0) return 0;
    
    return (complexityScores.reduce((a, b) => a + b, 0) / complexityScores.length).toFixed(1);
  }

  /**
   * Get most frequently searched paths
   * @param {Array} searches - Array of search events
   * @returns {Array} Most searched paths with counts
   */
  getMostSearchedPaths(searches) {
    const pathCounts = {};
    
    searches.forEach(search => {
      pathCounts[search.path] = (pathCounts[search.path] || 0) + 1;
    });
    
    return Object.entries(pathCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([path, count]) => ({ path, count }));
  }
}

// Export singleton instance
module.exports = new SearchMonitoringService();