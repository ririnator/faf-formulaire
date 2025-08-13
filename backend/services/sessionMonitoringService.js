const mongoose = require('mongoose');
const SecureLogger = require('../utils/secureLogger');

class SessionMonitoringService {
  constructor() {
    this.config = {
      suspiciousLoginThreshold: 5, // Failed logins within time window
      timeWindow: 15 * 60 * 1000, // 15 minutes
      maxSessionsPerIP: 10, // Max concurrent sessions per IP
      maxSessionsPerUser: 5, // Max concurrent sessions per user
      unusualLocationThreshold: 100, // km for location changes
      sessionTimeoutThreshold: 24 * 60 * 60 * 1000, // 24 hours of inactivity
      enableRealTimeMonitoring: true
    };

    this.activeSessions = new Map(); // IP -> session count
    this.userSessions = new Map(); // userId -> session count  
    this.failedLogins = new Map(); // IP -> [{timestamp, attempts}]
    this.suspiciousIPs = new Set();
    this.sessionMetrics = {
      totalActiveSessions: 0,
      suspiciousActivities: 0,
      blockedAttempts: 0,
      lastReset: Date.now()
    };

    // Batch alert system for performance optimization
    this.alertQueue = [];
    this.alertBatchConfig = {
      batchSize: 10, // Maximum alerts per batch
      batchTimeout: 30000, // 30 seconds max wait
      enableBatching: true
    };
    this.batchTimer = null;

    this.monitoringInterval = null;
  }

  /**
   * Initialize session monitoring
   */
  initialize() {
    if (this.config.enableRealTimeMonitoring) {
      this.startRealTimeMonitoring();
      SecureLogger.logInfo('SessionMonitoringService: Real-time monitoring initialized');
    }

    // Clean up old data every hour
    setInterval(() => {
      this.cleanupOldData();
    }, 60 * 60 * 1000);
  }

  /**
   * Start real-time session monitoring
   */
  startRealTimeMonitoring() {
    this.monitoringInterval = setInterval(async () => {
      try {
        await this.checkActiveSessions();
        await this.detectAnomalousPatterns();
      } catch (error) {
        SecureLogger.logError('Session monitoring error', error);
      }
    }, 30 * 1000); // Check every 30 seconds
  }

  /**
   * Track session creation
   */
  trackSessionCreation(sessionId, req, userId = null) {
    const clientIP = this.getClientIP(req);
    const userAgent = (req.get && req.get('User-Agent')) || req.headers['user-agent'] || 'unknown';
    const timestamp = Date.now();

    // Update active sessions count
    const currentIPSessions = this.activeSessions.get(clientIP) || 0;
    this.activeSessions.set(clientIP, currentIPSessions + 1);

    if (userId) {
      const currentUserSessions = this.userSessions.get(userId) || 0;
      this.userSessions.set(userId, currentUserSessions + 1);
    }

    this.sessionMetrics.totalActiveSessions++;

    // Check for suspicious patterns
    const isSuspicious = this.detectSuspiciousSession(clientIP, userId, userAgent, req);
    
    if (isSuspicious) {
      this.handleSuspiciousActivity(sessionId, clientIP, userId, 'suspicious_session_creation', {
        userAgent,
        timestamp,
        sessionCount: currentIPSessions + 1
      });
    }

    SecureLogger.logInfo('Session created', {
      sessionId: sessionId.substring(0, 8) + '...',
      clientIP: this.maskIP(clientIP),
      userId: userId ? userId.toString().substring(0, 8) + '...' : 'anonymous',
      userAgent: userAgent.substring(0, 100),
      suspicious: isSuspicious
    });

    return isSuspicious;
  }

  /**
   * Track session destruction
   */
  trackSessionDestruction(sessionId, clientIP, userId = null) {
    // Update session counts
    const currentIPSessions = this.activeSessions.get(clientIP) || 0;
    if (currentIPSessions > 0) {
      this.activeSessions.set(clientIP, currentIPSessions - 1);
    }

    if (userId) {
      const currentUserSessions = this.userSessions.get(userId) || 0;
      if (currentUserSessions > 0) {
        this.userSessions.set(userId, currentUserSessions - 1);
      }
    }

    if (this.sessionMetrics.totalActiveSessions > 0) {
      this.sessionMetrics.totalActiveSessions--;
    }

    SecureLogger.logInfo('Session destroyed', {
      sessionId: sessionId.substring(0, 8) + '...',
      clientIP: this.maskIP(clientIP),
      userId: userId ? userId.toString().substring(0, 8) + '...' : 'anonymous'
    });
  }

  /**
   * Track failed login attempts
   */
  trackFailedLogin(clientIP, userAgent, attemptedCredentials = {}) {
    const timestamp = Date.now();
    const ipFailures = this.failedLogins.get(clientIP) || [];
    
    // Add new failure
    ipFailures.push({
      timestamp,
      userAgent: userAgent?.substring(0, 100),
      attemptedEmail: attemptedCredentials.email?.substring(0, 50) || 'unknown'
    });

    // Keep only recent failures (within time window)
    const recentFailures = ipFailures.filter(
      failure => timestamp - failure.timestamp < this.config.timeWindow
    );

    this.failedLogins.set(clientIP, recentFailures);

    // Check if IP should be marked as suspicious
    if (recentFailures.length >= this.config.suspiciousLoginThreshold) {
      this.suspiciousIPs.add(clientIP);
      
      this.handleSuspiciousActivity(null, clientIP, null, 'multiple_failed_logins', {
        attempts: recentFailures.length,
        timeWindow: this.config.timeWindow,
        recentAttempts: recentFailures.slice(-3)
      });

      SecureLogger.logWarning('IP marked as suspicious due to failed logins', {
        clientIP: this.maskIP(clientIP),
        attempts: recentFailures.length,
        timeWindow: `${this.config.timeWindow / 1000}s`
      });
    }

    return recentFailures.length;
  }

  /**
   * Check if IP is suspicious
   */
  isIPSuspicious(clientIP) {
    return this.suspiciousIPs.has(clientIP);
  }

  /**
   * Check if session creation should be blocked
   */
  shouldBlockSession(clientIP, userId = null) {
    // Block if IP is marked as suspicious
    if (this.isIPSuspicious(clientIP)) {
      return { blocked: true, reason: 'suspicious_ip' };
    }

    // Block if too many sessions from same IP
    const ipSessions = this.activeSessions.get(clientIP) || 0;
    if (ipSessions >= this.config.maxSessionsPerIP) {
      return { blocked: true, reason: 'too_many_ip_sessions', current: ipSessions };
    }

    // Block if user has too many sessions
    if (userId) {
      const userSessionCount = this.userSessions.get(userId) || 0;
      if (userSessionCount >= this.config.maxSessionsPerUser) {
        return { blocked: true, reason: 'too_many_user_sessions', current: userSessionCount };
      }
    }

    return { blocked: false };
  }

  /**
   * Detect suspicious session patterns
   */
  detectSuspiciousSession(clientIP, userId, userAgent, req) {
    // Check for rapid session creation - only flag if approaching the limit
    const ipSessions = this.activeSessions.get(clientIP) || 0;
    if (ipSessions >= this.config.maxSessionsPerIP - 1) {
      return true;
    }

    // Check for suspicious user agents
    if (this.isSuspiciousUserAgent(userAgent)) {
      return true;
    }

    // Check for known suspicious patterns
    const headers = req.headers;
    if (this.hasSuspiciousHeaders(headers)) {
      return true;
    }

    return false;
  }

  /**
   * Check active sessions for anomalies
   */
  async checkActiveSessions() {
    try {
      const db = mongoose.connection.db;
      const sessionsCollection = db.collection('sessions');
      
      // Get all active sessions
      const activeSessions = await sessionsCollection.find({
        expires: { $gt: new Date() }
      }).toArray();

      // Update our tracking
      const currentIPCount = new Map();
      const currentUserCount = new Map();

      for (const session of activeSessions) {
        try {
          const sessionData = JSON.parse(session.session);
          const clientIP = sessionData.clientIP;
          const userId = sessionData.userId;

          if (clientIP) {
            currentIPCount.set(clientIP, (currentIPCount.get(clientIP) || 0) + 1);
          }

          if (userId) {
            currentUserCount.set(userId, (currentUserCount.get(userId) || 0) + 1);
          }
        } catch (parseError) {
          // Skip malformed session data
          continue;
        }
      }

      // Update our maps
      this.activeSessions = currentIPCount;
      this.userSessions = currentUserCount;
      this.sessionMetrics.totalActiveSessions = activeSessions.length;

      // Log session statistics
      SecureLogger.logInfo('Session monitoring check completed', {
        totalActiveSessions: activeSessions.length,
        uniqueIPs: currentIPCount.size,
        uniqueUsers: currentUserCount.size,
        suspiciousIPs: this.suspiciousIPs.size
      });

    } catch (error) {
      SecureLogger.logError('Failed to check active sessions', error);
    }
  }

  /**
   * Detect anomalous patterns in session data
   */
  async detectAnomalousPatterns() {
    // Check for IPs with too many sessions
    for (const [ip, count] of this.activeSessions.entries()) {
      if (count > this.config.maxSessionsPerIP) {
        this.handleSuspiciousActivity(null, ip, null, 'excessive_sessions_per_ip', {
          sessionCount: count,
          threshold: this.config.maxSessionsPerIP
        });
      }
    }

    // Check for users with too many sessions
    for (const [userId, count] of this.userSessions.entries()) {
      if (count > this.config.maxSessionsPerUser) {
        this.handleSuspiciousActivity(null, null, userId, 'excessive_sessions_per_user', {
          sessionCount: count,
          threshold: this.config.maxSessionsPerUser
        });
      }
    }
  }

  /**
   * Batch alert processing for performance optimization
   */
  queueAlert(alertData) {
    if (!this.alertBatchConfig.enableBatching) {
      this.processSingleAlert(alertData);
      return;
    }

    this.alertQueue.push({
      ...alertData,
      queuedAt: Date.now()
    });

    // Process immediately if batch is full
    if (this.alertQueue.length >= this.alertBatchConfig.batchSize) {
      this.processBatchedAlerts();
      return;
    }

    // Set timer for batch timeout if not already set
    if (!this.batchTimer) {
      this.batchTimer = setTimeout(() => {
        this.processBatchedAlerts();
      }, this.alertBatchConfig.batchTimeout);
    }
  }

  /**
   * Process batched alerts efficiently
   */
  processBatchedAlerts() {
    if (this.alertQueue.length === 0) return;

    // Clear the timer
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }

    const batch = this.alertQueue.splice(0); // Take all alerts
    const now = Date.now();

    // Group alerts by type for efficient processing
    const groupedAlerts = batch.reduce((groups, alert) => {
      const key = `${alert.activityType}-${alert.clientIP}`;
      if (!groups[key]) {
        groups[key] = { ...alert, count: 1, firstSeen: alert.queuedAt, lastSeen: alert.queuedAt };
      } else {
        groups[key].count++;
        groups[key].lastSeen = alert.queuedAt;
        // Merge details if needed
        groups[key].details = { ...groups[key].details, ...alert.details };
      }
      return groups;
    }, {});

    // Process grouped alerts
    Object.values(groupedAlerts).forEach(groupedAlert => {
      const logData = {
        activityType: groupedAlert.activityType,
        sessionId: groupedAlert.sessionId,
        clientIP: groupedAlert.clientIP,
        userId: groupedAlert.userId,
        details: {
          ...groupedAlert.details,
          alertCount: groupedAlert.count,
          timeSpan: groupedAlert.lastSeen - groupedAlert.firstSeen,
          processedAt: now
        },
        timestamp: new Date().toISOString()
      };

      SecureLogger.logWarning(
        `Batch alert [${groupedAlert.count}x]: ${groupedAlert.activityType}`, 
        logData
      );
    });

    // Log batch processing stats
    if (batch.length > 1) {
      SecureLogger.logInfo(`Processed ${batch.length} alerts in batch (${Object.keys(groupedAlerts).length} unique)`);
    }
  }

  /**
   * Process single alert (fallback when batching disabled)
   */
  processSingleAlert(alertData) {
    SecureLogger.logWarning('Suspicious session activity detected: ' + alertData.activityType, alertData);
  }

  /**
   * Handle suspicious activity detection with optimized batch processing
   */
  handleSuspiciousActivity(sessionId, clientIP, userId, activityType, details) {
    this.sessionMetrics.suspiciousActivities++;

    const alertData = {
      activityType,
      sessionId: sessionId ? sessionId.substring(0, 8) + '...' : null,
      clientIP: clientIP ? this.maskIP(clientIP) : null,
      userId: userId ? userId.toString().substring(0, 8) + '...' : null,
      details,
      timestamp: new Date().toISOString()
    };

    // Queue alert for batch processing
    this.queueAlert(alertData);

    // Immediate action for critical alerts
    if (this.isCriticalActivity(activityType)) {
      this.handleCriticalAlert(alertData);
    }
  }

  /**
   * Determine if activity requires immediate attention
   */
  isCriticalActivity(activityType) {
    const criticalActivities = [
      'brute_force_detected',
      'session_hijacking_attempt',
      'privilege_escalation',
      'multiple_failed_logins'
    ];
    return criticalActivities.includes(activityType);
  }

  /**
   * Handle critical alerts that need immediate processing
   */
  handleCriticalAlert(alertData) {
    // Process critical alerts immediately, bypassing batch queue
    SecureLogger.logError('CRITICAL SECURITY ALERT: ' + alertData.activityType, alertData);
    
    // Additional immediate actions for critical alerts
    if (alertData.clientIP && alertData.activityType === 'brute_force_detected') {
      this.suspiciousIPs.add(alertData.clientIP.split('.').slice(0, 3).join('.') + '.xxx');
      this.sessionMetrics.blockedAttempts++;
    }
  }

  /**
   * Check for suspicious user agents
   */
  isSuspiciousUserAgent(userAgent) {
    if (!userAgent) return true;

    // Be more permissive - only flag clearly automated tools
    const suspiciousPatterns = [
      /^curl/i,
      /^wget/i,
      /^python-requests/i,
      /^java/i,
      /postman/i,
      /insomnia/i,
      /^bot\//i,  // Only flag explicit bot user agents, not partial matches
      /crawler/i,
      /spider/i
    ];

    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }

  /**
   * Check for suspicious request headers
   */
  hasSuspiciousHeaders(headers) {
    // Only check for explicitly suspicious headers, not missing ones
    // Missing headers are common with legitimate requests
    
    // Check for automated tools indicators
    const automation_headers = ['x-automated-tool', 'x-bot-request'];
    return automation_headers.some(header => headers[header]);
  }

  /**
   * Get client IP with proxy support
   */
  getClientIP(req) {
    return req.ip || 
           (req.connection && req.connection.remoteAddress) || 
           (req.socket && req.socket.remoteAddress) ||
           (req.connection && req.connection.socket && req.connection.socket.remoteAddress) ||
           '0.0.0.0';
  }

  /**
   * Mask IP for logging (privacy)
   */
  maskIP(ip) {
    if (!ip) return 'unknown';
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.xxx.xxx`;
    }
    return ip.substring(0, 8) + '...';
  }

  /**
   * Clean up old data
   */
  cleanupOldData() {
    const now = Date.now();
    
    // Clean up failed login attempts older than time window
    for (const [ip, failures] of this.failedLogins.entries()) {
      const recentFailures = failures.filter(
        failure => now - failure.timestamp < this.config.timeWindow
      );
      
      if (recentFailures.length === 0) {
        this.failedLogins.delete(ip);
        this.suspiciousIPs.delete(ip); // Remove from suspicious list if no recent failures
      } else {
        this.failedLogins.set(ip, recentFailures);
      }
    }

    // Process any remaining queued alerts before cleanup
    if (this.alertQueue.length > 0) {
      this.processBatchedAlerts();
    }

    SecureLogger.logInfo('Session monitoring data cleaned up', {
      suspiciousIPs: this.suspiciousIPs.size,
      trackedFailures: this.failedLogins.size,
      queuedAlerts: this.alertQueue.length
    });
  }

  /**
   * Get monitoring statistics with batch processing metrics
   */
  getMonitoringStats() {
    return {
      ...this.sessionMetrics,
      activeSessions: this.sessionMetrics.totalActiveSessions,
      uniqueIPs: this.activeSessions.size,
      uniqueUsers: this.userSessions.size,
      suspiciousIPs: this.suspiciousIPs.size,
      batchProcessing: {
        queuedAlerts: this.alertQueue.length,
        batchingEnabled: this.alertBatchConfig.enableBatching,
        batchSize: this.alertBatchConfig.batchSize,
        batchTimeout: this.alertBatchConfig.batchTimeout
      },
      trackedFailures: this.failedLogins.size
    };
  }

  /**
   * Reset suspicious IP (manual admin action)
   */
  resetSuspiciousIP(clientIP) {
    this.suspiciousIPs.delete(clientIP);
    this.failedLogins.delete(clientIP);
    
    SecureLogger.logInfo('Suspicious IP reset by admin', {
      clientIP: this.maskIP(clientIP)
    });
  }

  /**
   * Update monitoring configuration
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    SecureLogger.logInfo('Session monitoring configuration updated', this.config);
  }

  /**
   * Shutdown monitoring service
   */
  shutdown() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }
    
    SecureLogger.logInfo('SessionMonitoringService shutdown complete');
  }
}

module.exports = SessionMonitoringService;