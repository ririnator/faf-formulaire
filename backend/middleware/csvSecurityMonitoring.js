// middleware/csvSecurityMonitoring.js

/**
 * CSV Security Monitoring Middleware
 * Tracks and logs CSV-related security events for comprehensive monitoring
 */

const { logSecurityEvent } = require('./querySanitization');

class CSVSecurityMonitor {
  constructor() {
    this.csvEvents = new Map(); // Track CSV events per IP
    this.suspiciousIPs = new Set(); // Track IPs with suspicious CSV activity
    this.csvViolationThreshold = 3; // Max violations before IP blocking
    this.timeWindow = 60 * 60 * 1000; // 1 hour window for tracking
  }

  /**
   * Track CSV import security events
   */
  trackCSVImportEvent(req, eventType, details = {}) {
    const ip = req.ip;
    const userAgent = req.get('user-agent') || 'unknown';
    const userId = req.currentUser?.id || req.user?.id || req.session?.userId;

    const event = {
      type: 'csv_import',
      subType: eventType,
      ip,
      userAgent,
      userId,
      timestamp: new Date(),
      details: {
        ...details,
        path: req.path,
        method: req.method
      }
    };

    // Log security event
    logSecurityEvent('csv_security', event);

    // Track violations for IP-based blocking
    if (eventType === 'injection_attempt' || eventType === 'malicious_content') {
      this.trackViolation(ip, event);
    }

    // Special logging for console visibility
    switch (eventType) {
      case 'injection_attempt':
        console.warn('🚨 CSV Formula Injection Attempt Detected:', {
          ip,
          userAgent,
          userId,
          pattern: details.pattern,
          timestamp: event.timestamp
        });
        break;
      case 'malicious_content':
        console.warn('🚨 Malicious CSV Content Detected:', {
          ip,
          userAgent,
          userId,
          contentType: details.contentType,
          timestamp: event.timestamp
        });
        break;
      case 'size_violation':
        console.warn('📊 CSV Size Limit Exceeded:', {
          ip,
          userAgent,
          userId,
          actualSize: details.actualSize,
          maxSize: details.maxSize,
          timestamp: event.timestamp
        });
        break;
      case 'successful_import':
        console.log('✅ CSV Import Successful:', {
          ip,
          userId,
          recordCount: details.recordCount,
          timestamp: event.timestamp
        });
        break;
    }
  }

  /**
   * Track CSV export security events
   */
  trackCSVExportEvent(req, eventType, details = {}) {
    const ip = req.ip;
    const userAgent = req.get('user-agent') || 'unknown';
    const userId = req.currentUser?.id || req.user?.id || req.session?.userId;

    const event = {
      type: 'csv_export',
      subType: eventType,
      ip,
      userAgent,
      userId,
      timestamp: new Date(),
      details: {
        ...details,
        path: req.path,
        method: req.method
      }
    };

    // Log security event
    logSecurityEvent('csv_security', event);

    // Special logging for console visibility
    switch (eventType) {
      case 'successful_export':
        console.log('📥 CSV Export Successful:', {
          ip,
          userId,
          recordCount: details.recordCount,
          filters: details.filters,
          timestamp: event.timestamp
        });
        break;
      case 'unauthorized_export':
        console.warn('🚨 Unauthorized CSV Export Attempt:', {
          ip,
          userAgent,
          timestamp: event.timestamp
        });
        break;
    }
  }

  /**
   * Track CSV security violations for IP-based monitoring
   */
  trackViolation(ip, event) {
    const now = Date.now();
    
    if (!this.csvEvents.has(ip)) {
      this.csvEvents.set(ip, []);
    }

    const ipEvents = this.csvEvents.get(ip);
    
    // Remove events outside time window
    const validEvents = ipEvents.filter(e => (now - e.timestamp.getTime()) <= this.timeWindow);
    
    // Add current violation
    validEvents.push(event);
    this.csvEvents.set(ip, validEvents);

    // Check if IP exceeds violation threshold
    const violationCount = validEvents.filter(e => 
      e.subType === 'injection_attempt' || e.subType === 'malicious_content'
    ).length;

    if (violationCount >= this.csvViolationThreshold) {
      this.markIPAsSuspicious(ip, event);
    }
  }

  /**
   * Mark IP as suspicious for repeated CSV violations
   */
  markIPAsSuspicious(ip, triggeringEvent) {
    this.suspiciousIPs.add(ip);

    console.error('🚨 IP Marked as Suspicious due to CSV Violations:', {
      ip,
      violationCount: this.csvViolationThreshold,
      triggeringEvent: triggeringEvent.subType,
      userAgent: triggeringEvent.details.userAgent,
      timestamp: new Date()
    });

    // Log critical security event
    logSecurityEvent('csv_security_critical', {
      type: 'suspicious_ip_detected',
      ip,
      reason: 'repeated_csv_violations',
      violationCount: this.csvViolationThreshold,
      triggeringEvent,
      timestamp: new Date()
    });
  }

  /**
   * Check if IP is marked as suspicious
   */
  isIPSuspicious(ip) {
    return this.suspiciousIPs.has(ip);
  }

  /**
   * Middleware to block suspicious IPs from CSV operations
   */
  blockSuspiciousIPs() {
    return (req, res, next) => {
      const ip = req.ip;
      
      if (this.isIPSuspicious(ip)) {
        this.trackCSVImportEvent(req, 'blocked_suspicious_ip', {
          reason: 'repeated_csv_violations'
        });

        return res.status(403).json({
          success: false,
          error: 'Access denied due to suspicious activity',
          code: 'SUSPICIOUS_IP_BLOCKED'
        });
      }

      next();
    };
  }

  /**
   * Get CSV security statistics
   */
  getSecurityStats() {
    const now = Date.now();
    let totalViolations = 0;
    let activeViolations = 0;

    for (const [ip, events] of this.csvEvents.entries()) {
      const violations = events.filter(e => 
        e.subType === 'injection_attempt' || e.subType === 'malicious_content'
      );
      
      totalViolations += violations.length;
      
      const recentViolations = violations.filter(e => 
        (now - e.timestamp.getTime()) <= this.timeWindow
      );
      activeViolations += recentViolations.length;
    }

    return {
      suspiciousIPs: this.suspiciousIPs.size,
      totalViolations,
      activeViolations,
      monitoredIPs: this.csvEvents.size,
      timeWindow: this.timeWindow / 1000 / 60, // minutes
      violationThreshold: this.csvViolationThreshold
    };
  }

  /**
   * Clean up old events to prevent memory leaks
   */
  cleanupOldEvents() {
    const now = Date.now();
    
    for (const [ip, events] of this.csvEvents.entries()) {
      const validEvents = events.filter(e => 
        (now - e.timestamp.getTime()) <= this.timeWindow
      );
      
      if (validEvents.length === 0) {
        this.csvEvents.delete(ip);
      } else {
        this.csvEvents.set(ip, validEvents);
      }
    }
  }

  /**
   * Clear suspicious IP status (for testing or manual intervention)
   */
  clearSuspiciousIP(ip) {
    this.suspiciousIPs.delete(ip);
    this.csvEvents.delete(ip);
    
    console.log('✅ Cleared suspicious status for IP:', ip);
  }
}

// Create singleton instance
const csvSecurityMonitor = new CSVSecurityMonitor();

// Set up periodic cleanup (every 30 minutes) - disabled in test environment
if (process.env.NODE_ENV !== 'test') {
  setInterval(() => {
    csvSecurityMonitor.cleanupOldEvents();
  }, 30 * 60 * 1000);
}

module.exports = {
  csvSecurityMonitor,
  
  // Express middleware functions
  trackCSVImport: (eventType, details = {}) => (req, res, next) => {
    csvSecurityMonitor.trackCSVImportEvent(req, eventType, details);
    next();
  },
  
  trackCSVExport: (eventType, details = {}) => (req, res, next) => {
    csvSecurityMonitor.trackCSVExportEvent(req, eventType, details);
    next();
  },
  
  blockSuspiciousIPs: () => csvSecurityMonitor.blockSuspiciousIPs(),
  
  // Utility functions
  isIPSuspicious: (ip) => csvSecurityMonitor.isIPSuspicious(ip),
  getSecurityStats: () => csvSecurityMonitor.getSecurityStats(),
  clearSuspiciousIP: (ip) => csvSecurityMonitor.clearSuspiciousIP(ip)
};