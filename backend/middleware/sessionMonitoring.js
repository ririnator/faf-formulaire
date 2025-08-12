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

      } catch (error) {
        console.error('Session tracking error:', error);
        // Don't block request if tracking fails
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
   * Get the monitoring service instance
   */
  getMonitoringService() {
    return this.monitoringService;
  }

  /**
   * Shutdown the monitoring service
   */
  shutdown() {
    this.monitoringService.shutdown();
  }
}

// Create singleton instance
const sessionMonitoringMiddleware = new SessionMonitoringMiddleware();

module.exports = sessionMonitoringMiddleware;