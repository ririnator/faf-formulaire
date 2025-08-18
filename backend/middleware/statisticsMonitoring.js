const fs = require('fs').promises;
const path = require('path');

/**
 * Statistics Endpoint Abuse Monitoring Middleware
 * 
 * This middleware provides specialized monitoring for statistics and analytics endpoints
 * to detect and prevent abuse of resource-intensive operations.
 * 
 * Features:
 * - Tracks usage patterns by endpoint and user
 * - Detects suspicious access patterns
 * - Monitors computational resource usage
 * - Provides alerts for potential DoS attacks via statistics
 * - Logs detailed statistics access patterns
 */

class StatisticsMonitor {
  constructor() {
    this.accessLog = new Map(); // IP -> access history
    this.userAccessLog = new Map(); // UserID -> access history
    this.endpointMetrics = new Map(); // Endpoint -> metrics
    this.suspiciousPatterns = new Set();
    this.alertThresholds = {
      maxRequestsPerMinute: 10,
      maxConcurrentRequests: 3,
      maxResponseTime: 30000, // 30 seconds
      suspiciousUserAgentPatterns: [
        /bot/i,
        /crawler/i,
        /scraper/i,
        /python/i,
        /curl/i,
        /wget/i,
        /postman/i
      ]
    };
    
    // Cleanup old entries every 10 minutes (disabled in test environment)
    if (process.env.NODE_ENV !== 'test') {
      setInterval(() => this.cleanupOldEntries(), 10 * 60 * 1000);
    }
  }

  /**
   * Creates tracking middleware for statistics endpoints
   */
  trackStatisticsAccess(endpointType = 'unknown') {
    return (req, res, next) => {
      const startTime = Date.now();
      const clientIP = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('user-agent') || 'unknown';
      const userId = req.user?.id || req.session?.userId || 'anonymous';
      const endpoint = `${req.method} ${req.path}`;
      
      // Track access attempt
      this.recordAccess({
        clientIP,
        userId,
        endpoint,
        endpointType,
        userAgent,
        timestamp: Date.now(),
        query: req.query,
        startTime
      });

      // Check for suspicious patterns before processing
      const suspiciousCheck = this.checkSuspiciousPatterns(clientIP, userId, userAgent, endpoint);
      if (suspiciousCheck.isSuspicious) {
        console.warn('🚨 Suspicious statistics access detected:', {
          clientIP,
          userId,
          endpoint,
          endpointType,
          reasons: suspiciousCheck.reasons,
          timestamp: new Date().toISOString()
        });
        
        // Log to security monitoring
        this.logSecurityEvent('suspicious_stats_access', {
          clientIP,
          userId,
          endpoint,
          endpointType,
          reasons: suspiciousCheck.reasons,
          userAgent
        });
      }

      // Override res.end to capture response time and status
      const originalEnd = res.end;
      res.end = (...args) => {
        const responseTime = Date.now() - startTime;
        const statusCode = res.statusCode;
        
        // Record completion
        this.recordCompletion({
          clientIP,
          userId,
          endpoint,
          endpointType,
          responseTime,
          statusCode,
          timestamp: Date.now()
        });

        // Check for performance alerts
        if (responseTime > this.alertThresholds.maxResponseTime) {
          this.logPerformanceAlert(endpoint, endpointType, responseTime, {
            clientIP,
            userId,
            statusCode
          });
        }

        originalEnd.apply(res, args);
      };

      next();
    };
  }

  /**
   * Records access attempt with detailed metrics
   */
  recordAccess(accessData) {
    const { clientIP, userId, endpoint, endpointType, timestamp } = accessData;
    
    // Track by IP
    if (!this.accessLog.has(clientIP)) {
      this.accessLog.set(clientIP, []);
    }
    this.accessLog.get(clientIP).push(accessData);

    // Track by user
    if (userId !== 'anonymous') {
      if (!this.userAccessLog.has(userId)) {
        this.userAccessLog.set(userId, []);
      }
      this.userAccessLog.get(userId).push(accessData);
    }

    // Track endpoint metrics
    if (!this.endpointMetrics.has(endpoint)) {
      this.endpointMetrics.set(endpoint, {
        type: endpointType,
        totalRequests: 0,
        averageResponseTime: 0,
        errorRate: 0,
        lastAccessed: timestamp,
        uniqueUsers: new Set(),
        uniqueIPs: new Set()
      });
    }
    
    const metrics = this.endpointMetrics.get(endpoint);
    metrics.totalRequests++;
    metrics.lastAccessed = timestamp;
    metrics.uniqueUsers.add(userId);
    metrics.uniqueIPs.add(clientIP);
  }

  /**
   * Records request completion with performance metrics
   */
  recordCompletion(completionData) {
    const { endpoint, responseTime, statusCode } = completionData;
    
    if (this.endpointMetrics.has(endpoint)) {
      const metrics = this.endpointMetrics.get(endpoint);
      
      // Update average response time
      const totalTime = metrics.averageResponseTime * (metrics.totalRequests - 1) + responseTime;
      metrics.averageResponseTime = totalTime / metrics.totalRequests;
      
      // Update error rate
      if (statusCode >= 400) {
        metrics.errorCount = (metrics.errorCount || 0) + 1;
        metrics.errorRate = metrics.errorCount / metrics.totalRequests;
      }
    }
  }

  /**
   * Checks for suspicious access patterns
   */
  checkSuspiciousPatterns(clientIP, userId, userAgent, endpoint) {
    const reasons = [];
    
    // Check request frequency by IP
    if (this.accessLog.has(clientIP)) {
      const ipHistory = this.accessLog.get(clientIP);
      const recentRequests = ipHistory.filter(
        access => Date.now() - access.timestamp < 60000 // Last minute
      );
      
      if (recentRequests.length > this.alertThresholds.maxRequestsPerMinute) {
        reasons.push(`High frequency: ${recentRequests.length} requests in last minute`);
      }
    }

    // Check for suspicious user agents
    for (const pattern of this.alertThresholds.suspiciousUserAgentPatterns) {
      if (pattern.test(userAgent)) {
        reasons.push(`Suspicious user agent: ${userAgent}`);
        break;
      }
    }

    // Check for rapid endpoint switching (potential scraping)
    if (userId !== 'anonymous' && this.userAccessLog.has(userId)) {
      const userHistory = this.userAccessLog.get(userId);
      const recentEndpoints = new Set(
        userHistory
          .filter(access => Date.now() - access.timestamp < 300000) // Last 5 minutes
          .map(access => access.endpoint)
      );
      
      if (recentEndpoints.size > 10) {
        reasons.push(`Rapid endpoint switching: ${recentEndpoints.size} different endpoints`);
      }
    }

    // Check concurrent requests
    const activeRequests = this.getActiveRequestCount(clientIP);
    if (activeRequests > this.alertThresholds.maxConcurrentRequests) {
      reasons.push(`High concurrent requests: ${activeRequests} active`);
    }

    return {
      isSuspicious: reasons.length > 0,
      reasons
    };
  }

  /**
   * Gets count of currently active requests for an IP
   */
  getActiveRequestCount(clientIP) {
    if (!this.accessLog.has(clientIP)) return 0;
    
    const now = Date.now();
    return this.accessLog.get(clientIP).filter(access => 
      access.startTime && !access.completedAt && (now - access.startTime < 60000)
    ).length;
  }

  /**
   * Logs security events to monitoring system
   */
  async logSecurityEvent(eventType, eventData) {
    const logEntry = {
      type: eventType,
      timestamp: new Date().toISOString(),
      severity: 'medium',
      data: eventData,
      source: 'statistics-monitoring'
    };

    try {
      // Log to console for immediate visibility
      console.warn(`🛡️ Statistics Security Event [${eventType}]:`, logEntry);
      
      // Optionally write to security log file
      if (process.env.NODE_ENV === 'production') {
        await this.writeToSecurityLog(logEntry);
      }
    } catch (error) {
      console.error('Failed to log security event:', error);
    }
  }

  /**
   * Logs performance alerts for slow statistics queries
   */
  async logPerformanceAlert(endpoint, endpointType, responseTime, context) {
    const alertData = {
      type: 'slow_statistics_query',
      endpoint,
      endpointType,
      responseTime,
      threshold: this.alertThresholds.maxResponseTime,
      context,
      timestamp: new Date().toISOString(),
      severity: responseTime > (this.alertThresholds.maxResponseTime * 2) ? 'high' : 'medium'
    };

    console.warn(`⚡ Statistics Performance Alert:`, alertData);
    
    if (process.env.NODE_ENV === 'production') {
      await this.writeToPerformanceLog(alertData);
    }
  }

  /**
   * Writes security events to dedicated log file
   */
  async writeToSecurityLog(logEntry) {
    try {
      const logDir = path.join(__dirname, '..', 'logs');
      await fs.mkdir(logDir, { recursive: true });
      
      const logFile = path.join(logDir, 'statistics-security.log');
      const logLine = JSON.stringify(logEntry) + '\n';
      
      await fs.appendFile(logFile, logLine);
    } catch (error) {
      console.error('Failed to write to security log:', error);
    }
  }

  /**
   * Writes performance alerts to dedicated log file
   */
  async writeToPerformanceLog(alertData) {
    try {
      const logDir = path.join(__dirname, '..', 'logs');
      await fs.mkdir(logDir, { recursive: true });
      
      const logFile = path.join(logDir, 'statistics-performance.log');
      const logLine = JSON.stringify(alertData) + '\n';
      
      await fs.appendFile(logFile, logLine);
    } catch (error) {
      console.error('Failed to write to performance log:', error);
    }
  }

  /**
   * Cleans up old entries to prevent memory leaks
   */
  cleanupOldEntries() {
    const cutoffTime = Date.now() - (24 * 60 * 60 * 1000); // 24 hours ago
    let totalCleaned = 0;

    // Cleanup IP access logs
    for (const [ip, history] of this.accessLog.entries()) {
      const filtered = history.filter(access => access.timestamp > cutoffTime);
      if (filtered.length === 0) {
        this.accessLog.delete(ip);
        totalCleaned++;
      } else if (filtered.length < history.length) {
        this.accessLog.set(ip, filtered);
        totalCleaned += history.length - filtered.length;
      }
    }

    // Cleanup user access logs
    for (const [userId, history] of this.userAccessLog.entries()) {
      const filtered = history.filter(access => access.timestamp > cutoffTime);
      if (filtered.length === 0) {
        this.userAccessLog.delete(userId);
        totalCleaned++;
      } else if (filtered.length < history.length) {
        this.userAccessLog.set(userId, filtered);
        totalCleaned += history.length - filtered.length;
      }
    }

    if (totalCleaned > 0) {
      console.log(`🧹 Statistics monitoring cleanup: removed ${totalCleaned} old entries`);
    }
  }

  /**
   * Gets current monitoring statistics
   */
  getMonitoringStats() {
    const now = Date.now();
    const lastHour = now - (60 * 60 * 1000);
    
    let totalRequests = 0;
    let recentRequests = 0;
    let uniqueIPs = new Set();
    let uniqueUsers = new Set();

    // Aggregate from all access logs
    for (const [ip, history] of this.accessLog.entries()) {
      uniqueIPs.add(ip);
      totalRequests += history.length;
      recentRequests += history.filter(access => access.timestamp > lastHour).length;
      
      history.forEach(access => {
        if (access.userId !== 'anonymous') {
          uniqueUsers.add(access.userId);
        }
      });
    }

    return {
      monitoring: {
        totalRequests,
        recentRequests,
        uniqueIPs: uniqueIPs.size,
        uniqueUsers: uniqueUsers.size,
        trackedEndpoints: this.endpointMetrics.size,
        suspiciousPatterns: this.suspiciousPatterns.size
      },
      endpoints: Array.from(this.endpointMetrics.entries()).map(([endpoint, metrics]) => ({
        endpoint,
        type: metrics.type,
        totalRequests: metrics.totalRequests,
        averageResponseTime: Math.round(metrics.averageResponseTime),
        errorRate: Math.round(metrics.errorRate * 100),
        uniqueUsers: metrics.uniqueUsers.size,
        uniqueIPs: metrics.uniqueIPs.size,
        lastAccessed: new Date(metrics.lastAccessed).toISOString()
      })),
      thresholds: this.alertThresholds
    };
  }

  /**
   * Updates monitoring configuration
   */
  updateConfig(newConfig) {
    this.alertThresholds = { ...this.alertThresholds, ...newConfig };
    console.log('📊 Statistics monitoring configuration updated:', this.alertThresholds);
  }

  /**
   * Resets all monitoring data
   */
  reset() {
    this.accessLog.clear();
    this.userAccessLog.clear();
    this.endpointMetrics.clear();
    this.suspiciousPatterns.clear();
    console.log('🔄 Statistics monitoring data reset');
  }
}

// Create global instance
const statisticsMonitor = new StatisticsMonitor();

// Middleware factory functions for different statistics endpoint types
const createStatsMiddleware = (endpointType) => {
  return statisticsMonitor.trackStatisticsAccess(endpointType);
};

module.exports = {
  statisticsMonitor,
  
  // Middleware for different types of statistics endpoints
  trackSimpleStats: createStatsMiddleware('simple_statistics'),
  trackAdminSummary: createStatsMiddleware('admin_summary'),
  trackHeavyAnalytics: createStatsMiddleware('heavy_analytics'),
  trackRealTimeMonitoring: createStatsMiddleware('realtime_monitoring'),
  trackComparison: createStatsMiddleware('comparison_analytics'),
  trackGlobalStats: createStatsMiddleware('global_statistics'),
  trackPerformanceStats: createStatsMiddleware('performance_statistics'),
  
  // General tracking middleware
  trackStatisticsAccess: (endpointType) => createStatsMiddleware(endpointType)
};