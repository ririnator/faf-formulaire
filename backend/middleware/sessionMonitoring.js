const SessionMonitoringService = require('../services/sessionMonitoringService');

class SessionMonitoringMiddleware {
  constructor() {
    this.monitoringService = new SessionMonitoringService();
  }

  /**
   * Initialize monitoring service
   */
  initialize() {
    this.monitoringService.initialize();
  }

  /**
   * Middleware to track session creation
   */
  trackSessionCreation() {
    return (req, res, next) => {
      // Skip if no session
      if (!req.session || !req.sessionID) {
        return next();
      }

      try {
        const userId = req.session.userId || req.session.user?.id || null;
        const isSuspicious = this.monitoringService.trackSessionCreation(
          req.sessionID, 
          req, 
          userId
        );

        // Add monitoring data to session for future tracking
        req.session.clientIP = this.monitoringService.getClientIP(req);
        req.session.createdAt = Date.now();
        req.session.suspicious = isSuspicious;
        req.session.userAgent = req.get('User-Agent');
        req.session.lastActivity = Date.now();
        
        // Track API endpoint access patterns
        if (req.path.startsWith('/api/')) {
          this.trackAPIAccess(req, userId);
        }

      } catch (error) {
        console.error('Session tracking error:', error);
        
        // Alerte pour échecs critiques de monitoring
        if (this.isMonitoringCritical(error)) {
          this.sendCriticalAlert('SESSION_MONITORING_FAILURE', {
            error: error.message,
            ip: this.monitoringService.getClientIP(req),
            userAgent: req.get('User-Agent'),
            timestamp: Date.now()
          });
        }
        
        // Don't block request if tracking fails, but track failure
        this.trackMonitoringFailure(error);
      }

      next();
    };
  }

  /**
   * Middleware to track session destruction
   */
  trackSessionDestruction() {
    return (req, res, next) => {
      const originalDestroy = req.session?.destroy;
      
      if (originalDestroy && req.sessionID) {
        req.session.destroy = (callback) => {
          try {
            const clientIP = req.session.clientIP || this.monitoringService.getClientIP(req);
            const userId = req.session.userId || req.session.user?.id || null;
            
            this.monitoringService.trackSessionDestruction(req.sessionID, clientIP, userId);
          } catch (error) {
            console.error('Session destruction tracking error:', error);
          }
          
          return originalDestroy.call(req.session, callback);
        };
      }

      next();
    };
  }

  /**
   * Middleware to check for suspicious sessions and potentially block them
   */
  blockSuspiciousSessions() {
    return (req, res, next) => {
      // Bypass in test environment
      if (process.env.NODE_ENV === 'test' || process.env.DISABLE_RATE_LIMITING === 'true') {
        return next();
      }

      try {
        const clientIP = this.monitoringService.getClientIP(req);
        const userId = req.session?.userId || req.session?.user?.id || null;

        const blockCheck = this.monitoringService.shouldBlockSession(clientIP, userId);
        
        if (blockCheck.blocked) {
          // Destroy any existing session
          if (req.session?.destroy) {
            req.session.destroy();
          }

          return res.status(429).json({
            error: 'Session blocked due to suspicious activity',
            reason: blockCheck.reason,
            message: this.getBlockMessage(blockCheck.reason)
          });
        }

        // Mark request as passing security check
        req.sessionSecurityCheck = { passed: true, clientIP };
        
      } catch (error) {
        console.error('Session security check error:', error);
        // Allow request to continue if security check fails
      }

      next();
    };
  }

  /**
   * Middleware to track failed login attempts
   */
  trackFailedLogins() {
    return (req, res, next) => {
      // Store original res.json to intercept responses
      const originalJson = res.json;
      
      res.json = function(data) {
        // Check if this was a failed authentication
        if (res.statusCode === 401 || res.statusCode === 403 || 
            (data && (data.error === 'Invalid credentials' || data.error === 'Unauthorized'))) {
          
          try {
            const clientIP = req.sessionMonitoring?.getClientIP(req) || req.ip;
            const userAgent = req.get('User-Agent');
            const attemptedCredentials = {
              email: req.body?.email || req.body?.username
            };

            req.sessionMonitoring.trackFailedLogin(clientIP, userAgent, attemptedCredentials);
          } catch (error) {
            console.error('Failed login tracking error:', error);
          }
        }

        return originalJson.call(this, data);
      };

      // Attach monitoring service to request for easy access
      req.sessionMonitoring = this.monitoringService;
      
      next();
    };
  }

  /**
   * Get user-friendly block messages
   */
  getBlockMessage(reason) {
    const messages = {
      'suspicious_ip': 'Your IP address has been temporarily blocked due to suspicious activity. Please try again later.',
      'too_many_ip_sessions': 'Too many active sessions from your IP address. Please close some sessions and try again.',
      'too_many_user_sessions': 'You have too many active sessions. Please log out from other devices and try again.'
    };

    return messages[reason] || 'Session blocked due to security policy.';
  }

  /**
   * Admin endpoint middleware to get monitoring stats
   */
  getMonitoringStats() {
    return (req, res, next) => {
      try {
        const stats = this.monitoringService.getMonitoringStats();
        res.json({
          success: true,
          stats,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({
          error: 'Failed to retrieve monitoring stats',
          message: error.message
        });
      }
    };
  }

  /**
   * Admin endpoint to reset suspicious IP
   */
  resetSuspiciousIP() {
    return (req, res, next) => {
      try {
        const { ip } = req.body;
        if (!ip) {
          return res.status(400).json({ error: 'IP address is required' });
        }

        this.monitoringService.resetSuspiciousIP(ip);
        res.json({ 
          success: true, 
          message: `IP ${ip} has been reset` 
        });
      } catch (error) {
        res.status(500).json({
          error: 'Failed to reset suspicious IP',
          message: error.message
        });
      }
    };
  }

  /**
   * Track API endpoint access patterns for new routes
   */
  trackAPIAccess(req, userId) {
    const endpoint = this.normalizeEndpoint(req.path);
    const method = req.method;
    
    // Track access patterns for sensitive endpoints
    const sensitiveEndpoints = [
      '/api/contacts',
      '/api/handshakes', 
      '/api/invitations',
      '/api/submissions'
    ];
    
    if (sensitiveEndpoints.some(pattern => endpoint.startsWith(pattern))) {
      const accessKey = `${userId || 'anonymous'}:${endpoint}:${method}`;
      
      if (!this.apiAccessTracking) {
        this.apiAccessTracking = new Map();
      }
      
      const current = this.apiAccessTracking.get(accessKey) || { count: 0, firstAccess: Date.now() };
      current.count++;
      current.lastAccess = Date.now();
      
      this.apiAccessTracking.set(accessKey, current);
      
      // Alert on suspicious API access patterns
      if (current.count > 100) { // 100 requests to same endpoint
        console.warn('Suspicious API access pattern detected', {
          userId: userId ? userId.toString().substring(0, 8) + '...' : 'anonymous',
          endpoint,
          method,
          count: current.count,
          timeSpan: Date.now() - current.firstAccess
        });
      }
    }
  }
  
  /**
   * Normalize endpoint paths for tracking
   */
  normalizeEndpoint(path) {
    // Replace IDs with placeholder for pattern matching
    return path.replace(/\/[a-f0-9]{24}/g, '/:id')
               .replace(/\/[a-f0-9]{64}/g, '/:token')
               .replace(/\/\d{4}-\d{2}/g, '/:month');
  }
  
  /**
   * Enhanced session validation for new API routes
   */
  validateAPISession() {
    return (req, res, next) => {
      // Enhanced validation for API routes
      if (req.path.startsWith('/api/') && req.session) {
        // Check for session hijacking indicators
        const suspiciousIndicators = [];
        
        // User agent consistency check
        if (req.session.userAgent && req.session.userAgent !== req.get('User-Agent')) {
          suspiciousIndicators.push('user_agent_mismatch');
        }
        
        // Rapid endpoint switching detection
        if (req.session.lastEndpoint) {
          const timeSinceLastRequest = Date.now() - (req.session.lastRequestTime || 0);
          if (timeSinceLastRequest < 100 && req.session.lastEndpoint !== req.path) {
            suspiciousIndicators.push('rapid_endpoint_switching');
          }
        }
        
        req.session.lastEndpoint = req.path;
        req.session.lastRequestTime = Date.now();
        
        if (suspiciousIndicators.length > 0) {
          console.warn('API session validation concerns', {
            sessionId: req.sessionID.substring(0, 8) + '...',
            indicators: suspiciousIndicators,
            endpoint: req.path,
            method: req.method
          });
          
          // Track but don't block unless multiple indicators
          if (suspiciousIndicators.length > 1) {
            req.session.destroy();
            return res.status(401).json({
              error: 'Session security violation detected',
              code: 'SESSION_HIJACKING_SUSPECTED'
            });
          }
        }
      }
      
      next();
    };
  }
  
  /**
   * Get the monitoring service instance
   */
  getMonitoringService() {
    return this.monitoringService;
  }

  /**
   * Determine if monitoring error is critical
   */
  isMonitoringCritical(error) {
    const criticalErrors = [
      'ECONNREFUSED', // Base de données inaccessible
      'MongoNetworkError', // Erreur réseau MongoDB
      'Database not connected', // DB déconnectée
      'Out of memory' // Problème mémoire
    ];
    
    return criticalErrors.some(criticalError => 
      error.message.includes(criticalError) || error.name === criticalError
    );
  }

  /**
   * Send critical alert for monitoring failures
   */
  sendCriticalAlert(alertType, data) {
    const alert = {
      type: alertType,
      severity: 'CRITICAL',
      timestamp: new Date().toISOString(),
      data,
      hostname: require('os').hostname(),
      pid: process.pid
    };

    // Log immédiatement
    console.error('🚨 CRITICAL_MONITORING_ALERT:', JSON.stringify(alert));

    // TODO: En production, intégrer avec:
    // - Slack/Teams webhook
    // - PagerDuty
    // - Email alerts
    // - SMS notifications
    // - Monitoring dashboards (Grafana, DataDog)
    
    // Pour démonstration, on peut utiliser process.send() si disponible
    if (process.send) {
      process.send({ type: 'critical_alert', alert });
    }
    
    this.trackAlert(alert);
  }

  /**
   * Track monitoring failures for pattern analysis
   */
  trackMonitoringFailure(error) {
    if (!this.failureStats) {
      this.failureStats = {
        count: 0,
        lastFailure: null,
        errorTypes: new Map()
      };
    }

    this.failureStats.count++;
    this.failureStats.lastFailure = Date.now();
    
    const errorType = error.name || 'Unknown';
    const current = this.failureStats.errorTypes.get(errorType) || 0;
    this.failureStats.errorTypes.set(errorType, current + 1);

    // Alerte si trop d'échecs
    if (this.failureStats.count % 10 === 0) {
      this.sendCriticalAlert('MONITORING_FAILURE_PATTERN', {
        totalFailures: this.failureStats.count,
        errorTypes: Array.from(this.failureStats.errorTypes.entries()),
        timeWindow: '10 minutes'
      });
    }
  }

  /**
   * Track alerts for analysis
   */
  trackAlert(alert) {
    if (!this.alertHistory) {
      this.alertHistory = [];
    }
    
    this.alertHistory.push(alert);
    
    // Garder seulement les 100 dernières alertes
    if (this.alertHistory.length > 100) {
      this.alertHistory.shift();
    }
  }

  /**
   * Get monitoring health status
   */
  getMonitoringHealth() {
    return {
      status: this.failureStats ? 
        (this.failureStats.count > 50 ? 'CRITICAL' : 
         this.failureStats.count > 10 ? 'WARNING' : 'HEALTHY') : 'HEALTHY',
      failures: this.failureStats?.count || 0,
      lastFailure: this.failureStats?.lastFailure,
      alerts: this.alertHistory?.length || 0,
      uptime: process.uptime()
    };
  }

  /**
   * Clean up API access tracking
   */
  cleanupAPITracking() {
    if (this.apiAccessTracking) {
      const now = Date.now();
      const maxAge = 60 * 60 * 1000; // 1 hour
      
      for (const [key, data] of this.apiAccessTracking.entries()) {
        if (now - data.lastAccess > maxAge) {
          this.apiAccessTracking.delete(key);
        }
      }
    }
  }
  
  /**
   * Shutdown the monitoring service
   */
  shutdown() {
    this.monitoringService.shutdown();
    if (this.apiAccessTracking) {
      this.apiAccessTracking.clear();
    }
  }
}

// Create singleton instance
const sessionMonitoringMiddleware = new SessionMonitoringMiddleware();

module.exports = sessionMonitoringMiddleware;