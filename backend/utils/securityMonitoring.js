/**
 * Advanced Security Monitoring and Analytics
 * 
 * Provides comprehensive security event monitoring, pattern detection,
 * and threat intelligence for the FAF application.
 * 
 * Features:
 * - Real-time threat detection
 * - Attack pattern analysis
 * - Security metrics dashboard
 * - Automated incident response
 * - Threat intelligence correlation
 * 
 * @author FAF Security Team
 * @version 2.0.0
 */

const EventEmitter = require('events');

class SecurityMonitor extends EventEmitter {
  constructor(config = {}) {
    super();
    
    this.config = {
      maxEvents: config.maxEvents || 10000,
      alertThresholds: {
        suspiciousQueries: 5,
        timeWindow: 300000, // 5 minutes
        criticalEvents: 3,
        injectionAttempts: 10,
        rateLimitViolations: 20
      },
      enableRealTimeAnalysis: config.enableRealTimeAnalysis !== false,
      retentionPeriod: config.retentionPeriod || 7 * 24 * 60 * 60 * 1000, // 7 days
      ...config
    };
    
    this.events = [];
    this.attackPatterns = new Map();
    this.threatSources = new Map();
    this.activeIncidents = new Map();
    this.metrics = {
      totalEvents: 0,
      blockedAttacks: 0,
      criticalIncidents: 0,
      lastActivity: null,
      topAttackTypes: new Map(),
      topThreatSources: new Map()
    };
    
    // Start cleanup interval (disabled in test environment)
    if (process.env.NODE_ENV !== 'test') {
      this.cleanupInterval = setInterval(() => this.cleanup(), 60000); // Every minute
      
      // Initialize real-time analysis if enabled
      if (this.config.enableRealTimeAnalysis) {
        this.startRealTimeAnalysis();
      }
    }
  }

  /**
   * Record a security event
   * @param {Object} event - Security event data
   */
  recordEvent(event) {
    const enrichedEvent = {
      id: this.generateEventId(),
      timestamp: new Date(),
      ...event,
      severity: this.normalizeSeverity(event.severity),
      source: event.source || 'unknown',
      metadata: {
        ...event.metadata,
        sessionId: event.sessionId,
        userAgent: event.userAgent,
        ipAddress: event.ipAddress
      }
    };

    // Add to events array
    this.events.push(enrichedEvent);
    this.metrics.totalEvents++;
    this.metrics.lastActivity = enrichedEvent.timestamp;

    // Update attack pattern tracking
    this.updateAttackPatterns(enrichedEvent);
    
    // Update threat source tracking
    this.updateThreatSources(enrichedEvent);
    
    // Update metrics
    this.updateMetrics(enrichedEvent);

    // Perform real-time analysis
    if (this.config.enableRealTimeAnalysis) {
      this.analyzeEvent(enrichedEvent);
    }

    // Emit event for external listeners
    this.emit('securityEvent', enrichedEvent);

    // Cleanup old events if needed
    if (this.events.length > this.config.maxEvents) {
      this.events = this.events.slice(-this.config.maxEvents);
    }

    return enrichedEvent.id;
  }

  /**
   * Analyze an event for threats and patterns
   * @param {Object} event - Security event to analyze
   */
  analyzeEvent(event) {
    // Check for immediate threats
    if (event.severity === 'critical') {
      this.handleCriticalEvent(event);
    }

    // Pattern detection
    this.detectAttackPatterns(event);
    
    // Rate limiting analysis
    this.analyzeRatePatterns(event);
    
    // Correlation analysis
    this.correlateEvents(event);
  }

  /**
   * Handle critical security events
   * @param {Object} event - Critical event
   */
  handleCriticalEvent(event) {
    const incidentId = this.generateIncidentId();
    const incident = {
      id: incidentId,
      eventId: event.id,
      type: 'critical_security_event',
      severity: 'critical',
      timestamp: event.timestamp,
      source: event.source,
      description: `Critical security event: ${event.event}`,
      status: 'active',
      events: [event],
      response: {
        automated: true,
        actions: this.getAutomatedResponse(event)
      }
    };

    this.activeIncidents.set(incidentId, incident);
    this.metrics.criticalIncidents++;

    // Emit critical incident
    this.emit('criticalIncident', incident);

    // Log critical event
    console.error('🚨 CRITICAL SECURITY INCIDENT:', {
      incidentId,
      eventType: event.event,
      source: event.source,
      timestamp: event.timestamp
    });
  }

  /**
   * Detect attack patterns from events
   * @param {Object} event - Event to analyze
   */
  detectAttackPatterns(event) {
    const key = `${event.source}_${event.event}`;
    const pattern = this.attackPatterns.get(key) || {
      count: 0,
      firstSeen: event.timestamp,
      lastSeen: event.timestamp,
      events: []
    };

    pattern.count++;
    pattern.lastSeen = event.timestamp;
    pattern.events.push(event.id);

    // Keep only recent events in pattern
    if (pattern.events.length > 50) {
      pattern.events = pattern.events.slice(-50);
    }

    this.attackPatterns.set(key, pattern);

    // Check if pattern indicates coordinated attack
    const timeWindow = 5 * 60 * 1000; // 5 minutes
    const recentTime = Date.now() - timeWindow;
    const recentEvents = this.events.filter(e => 
      e.timestamp.getTime() > recentTime && 
      e.source === event.source &&
      e.event === event.event
    );

    if (recentEvents.length >= this.config.alertThresholds.suspiciousQueries) {
      this.createSecurityAlert('pattern_detected', {
        pattern: key,
        eventCount: recentEvents.length,
        timeWindow: timeWindow / 1000,
        severity: 'high'
      });
    }
  }

  /**
   * Analyze rate limiting patterns
   * @param {Object} event - Event to analyze
   */
  analyzeRatePatterns(event) {
    if (!event.metadata?.ipAddress) return;

    const ipKey = `rate_${event.metadata.ipAddress}`;
    const timeWindow = 60000; // 1 minute
    const recentTime = Date.now() - timeWindow;
    
    const recentEventsFromIP = this.events.filter(e => 
      e.timestamp.getTime() > recentTime && 
      e.metadata?.ipAddress === event.metadata.ipAddress
    );

    if (recentEventsFromIP.length >= this.config.alertThresholds.rateLimitViolations) {
      this.createSecurityAlert('rate_limit_violation', {
        ipAddress: event.metadata.ipAddress,
        eventCount: recentEventsFromIP.length,
        timeWindow: timeWindow / 1000,
        severity: 'medium'
      });
    }
  }

  /**
   * Correlate events to detect complex attacks
   * @param {Object} event - Event to correlate
   */
  correlateEvents(event) {
    // Look for injection attempts followed by authentication attempts
    if (event.event.includes('INJECTION')) {
      const recentTime = Date.now() - 300000; // 5 minutes
      const recentAuthEvents = this.events.filter(e => 
        e.timestamp.getTime() > recentTime &&
        e.event.includes('AUTH') &&
        e.metadata?.ipAddress === event.metadata?.ipAddress
      );

      if (recentAuthEvents.length > 0) {
        this.createSecurityAlert('injection_auth_correlation', {
          injectionEvent: event.event,
          authEvents: recentAuthEvents.length,
          ipAddress: event.metadata?.ipAddress,
          severity: 'high'
        });
      }
    }
  }

  /**
   * Create a security alert
   * @param {string} type - Alert type
   * @param {Object} data - Alert data
   */
  createSecurityAlert(type, data) {
    const alert = {
      id: this.generateAlertId(),
      type,
      timestamp: new Date(),
      severity: data.severity || 'medium',
      data,
      status: 'active'
    };

    this.emit('securityAlert', alert);
    
    console.warn('⚠️ SECURITY ALERT:', {
      type: alert.type,
      severity: alert.severity,
      data: alert.data
    });
  }

  /**
   * Update attack pattern tracking
   * @param {Object} event - Security event
   */
  updateAttackPatterns(event) {
    const attackType = this.categorizeAttack(event);
    if (attackType) {
      const current = this.metrics.topAttackTypes.get(attackType) || 0;
      this.metrics.topAttackTypes.set(attackType, current + 1);
    }
  }

  /**
   * Update threat source tracking
   * @param {Object} event - Security event
   */
  updateThreatSources(event) {
    if (event.metadata?.ipAddress) {
      const current = this.metrics.topThreatSources.get(event.metadata.ipAddress) || 0;
      this.metrics.topThreatSources.set(event.metadata.ipAddress, current + 1);
    }
  }

  /**
   * Update security metrics
   * @param {Object} event - Security event
   */
  updateMetrics(event) {
    if (event.severity === 'critical' || event.severity === 'high') {
      this.metrics.blockedAttacks++;
    }
  }

  /**
   * Categorize attack type from event
   * @param {Object} event - Security event
   * @returns {string} Attack category
   */
  categorizeAttack(event) {
    const eventType = event.event.toLowerCase();
    
    if (eventType.includes('injection')) return 'injection_attack';
    if (eventType.includes('operator')) return 'nosql_operator_attack';
    if (eventType.includes('regex')) return 'regex_attack';
    if (eventType.includes('auth')) return 'authentication_attack';
    if (eventType.includes('rate')) return 'rate_limit_violation';
    if (eventType.includes('field')) return 'field_access_attack';
    
    return 'unknown_attack';
  }

  /**
   * Get automated response actions for an event
   * @param {Object} event - Security event
   * @returns {Array} Array of response actions
   */
  getAutomatedResponse(event) {
    const actions = [];
    
    if (event.event.includes('INJECTION')) {
      actions.push('block_request');
      actions.push('log_detailed_info');
    }
    
    if (event.metadata?.ipAddress) {
      actions.push('monitor_ip_activity');
      
      // Check if IP should be temporarily blocked
      const recentEvents = this.getRecentEventsFromIP(event.metadata.ipAddress);
      if (recentEvents.length >= 10) {
        actions.push('temporary_ip_block');
      }
    }
    
    return actions;
  }

  /**
   * Get recent events from specific IP
   * @param {string} ipAddress - IP address to check
   * @returns {Array} Recent events from IP
   */
  getRecentEventsFromIP(ipAddress) {
    const recentTime = Date.now() - 300000; // 5 minutes
    return this.events.filter(e => 
      e.timestamp.getTime() > recentTime && 
      e.metadata?.ipAddress === ipAddress
    );
  }

  /**
   * Get security dashboard data
   * @returns {Object} Dashboard data
   */
  getDashboardData() {
    const now = Date.now();
    const last24h = now - (24 * 60 * 60 * 1000);
    const last1h = now - (60 * 60 * 1000);

    const recentEvents = this.events.filter(e => e.timestamp.getTime() > last24h);
    const hourlyEvents = this.events.filter(e => e.timestamp.getTime() > last1h);

    return {
      overview: {
        totalEvents: this.metrics.totalEvents,
        eventsLast24h: recentEvents.length,
        eventsLastHour: hourlyEvents.length,
        blockedAttacks: this.metrics.blockedAttacks,
        criticalIncidents: this.metrics.criticalIncidents,
        activeIncidents: this.activeIncidents.size,
        lastActivity: this.metrics.lastActivity
      },
      attackTypes: Array.from(this.metrics.topAttackTypes.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10),
      threatSources: Array.from(this.metrics.topThreatSources.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10),
      recentEvents: this.events
        .filter(e => e.timestamp.getTime() > last1h)
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, 50),
      severityBreakdown: this.getSeverityBreakdown(recentEvents),
      hourlyActivity: this.getHourlyActivity()
    };
  }

  /**
   * Get severity breakdown for events
   * @param {Array} events - Events to analyze
   * @returns {Object} Severity breakdown
   */
  getSeverityBreakdown(events) {
    const breakdown = { critical: 0, high: 0, medium: 0, low: 0 };
    
    events.forEach(event => {
      if (breakdown.hasOwnProperty(event.severity)) {
        breakdown[event.severity]++;
      }
    });
    
    return breakdown;
  }

  /**
   * Get hourly activity data
   * @returns {Array} Hourly activity data
   */
  getHourlyActivity() {
    const now = new Date();
    const hours = [];
    
    for (let i = 23; i >= 0; i--) {
      const hour = new Date(now);
      hour.setHours(hour.getHours() - i, 0, 0, 0);
      const nextHour = new Date(hour);
      nextHour.setHours(nextHour.getHours() + 1);
      
      const eventsInHour = this.events.filter(e => 
        e.timestamp >= hour && e.timestamp < nextHour
      ).length;
      
      hours.push({
        hour: hour.getHours(),
        events: eventsInHour,
        timestamp: hour
      });
    }
    
    return hours;
  }

  /**
   * Export security data for analysis
   * @param {Object} options - Export options
   * @returns {Object} Exported data
   */
  exportSecurityData(options = {}) {
    const {
      includeEvents = true,
      includePatterns = true,
      includeMetrics = true,
      includeIncidents = true,
      timeRange = null
    } = options;

    const data = {
      exportTimestamp: new Date(),
      config: this.config
    };

    if (includeEvents) {
      let events = this.events;
      if (timeRange) {
        const startTime = new Date(timeRange.start);
        const endTime = new Date(timeRange.end);
        events = events.filter(e => e.timestamp >= startTime && e.timestamp <= endTime);
      }
      data.events = events;
    }

    if (includePatterns) {
      data.attackPatterns = Array.from(this.attackPatterns.entries());
      data.threatSources = Array.from(this.threatSources.entries());
    }

    if (includeMetrics) {
      data.metrics = {
        ...this.metrics,
        topAttackTypes: Array.from(this.metrics.topAttackTypes.entries()),
        topThreatSources: Array.from(this.metrics.topThreatSources.entries())
      };
    }

    if (includeIncidents) {
      data.incidents = Array.from(this.activeIncidents.entries());
    }

    return data;
  }

  /**
   * Clean up old events and data
   */
  cleanup() {
    const cutoffTime = Date.now() - this.config.retentionPeriod;
    
    // Remove old events
    this.events = this.events.filter(e => e.timestamp.getTime() > cutoffTime);
    
    // Clean up old attack patterns
    for (const [key, pattern] of this.attackPatterns.entries()) {
      if (pattern.lastSeen.getTime() < cutoffTime) {
        this.attackPatterns.delete(key);
      }
    }
    
    // Clean up old incidents
    for (const [id, incident] of this.activeIncidents.entries()) {
      if (incident.timestamp.getTime() < cutoffTime) {
        this.activeIncidents.delete(id);
      }
    }
  }

  /**
   * Start real-time analysis
   */
  startRealTimeAnalysis() {
    // Real-time analysis is handled in analyzeEvent method
    console.log('🔍 Security monitoring: Real-time analysis enabled');
  }

  /**
   * Normalize severity levels
   * @param {string} severity - Raw severity
   * @returns {string} Normalized severity
   */
  normalizeSeverity(severity) {
    if (!severity) return 'low';
    
    const normalized = severity.toLowerCase();
    if (['critical', 'high', 'medium', 'low'].includes(normalized)) {
      return normalized;
    }
    
    return 'low';
  }

  /**
   * Generate unique event ID
   * @returns {string} Event ID
   */
  generateEventId() {
    return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Generate unique incident ID
   * @returns {string} Incident ID
   */
  generateIncidentId() {
    return `inc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Generate unique alert ID
   * @returns {string} Alert ID
   */
  generateAlertId() {
    return `alt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Shutdown monitoring
   */
  shutdown() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    this.removeAllListeners();
    console.log('🔍 Security monitoring: Shutdown completed');
  }
}

// Create global security monitor instance
const globalSecurityMonitor = new SecurityMonitor();

module.exports = {
  SecurityMonitor,
  globalSecurityMonitor
};