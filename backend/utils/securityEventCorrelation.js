// Security Event Correlation System for Enterprise Security
// Real-time correlation and analysis of security events

const crypto = require('crypto');
const SecureLogger = require('./secureLogger');

class SecurityEventCorrelationSystem {
  constructor() {
    this.config = {
      MAX_EVENTS_MEMORY: 10000,
      CORRELATION_WINDOW: 5 * 60 * 1000, // 5 minutes
      ALERT_THRESHOLD: 5,
      CLEANUP_INTERVAL: 60 * 1000, // 1 minute
      MAX_IP_EVENTS: 100
    };
    
    // Event storage
    this.events = new Map(); // eventId -> eventData
    this.ipEvents = new Map(); // ip -> eventIds[]
    this.patternMatches = new Map(); // pattern -> matches[]
    this.correlationRules = [];
    this.metrics = {
      eventsProcessed: 0,
      correlationsFound: 0,
      alertsGenerated: 0,
      falsePositives: 0
    };
    
    this.isInitialized = false;
    this.cleanupInterval = null;
  }
  
  async initialize() {
    try {
      console.log('🔍 Initializing Security Event Correlation System...');
      
      // Initialize correlation rules
      this.initializeCorrelationRules();
      
      // Start cleanup process
      this.startCleanupProcess();
      
      this.isInitialized = true;
      console.log('✅ Security Event Correlation System initialized');
      
    } catch (error) {
      console.error('❌ Failed to initialize correlation system:', error);
      throw error;
    }
  }
  
  /**
   * Log a security event for correlation analysis
   */
  async logSecurityEvent(eventType, eventData, context = {}) {
    try {
      const eventId = this.generateEventId();
      const timestamp = Date.now();
      
      const event = {
        id: eventId,
        type: eventType,
        timestamp,
        data: this.sanitizeEventData(eventData),
        context: this.sanitizeEventData(context),
        ip: eventData.ip || 'unknown',
        severity: this.calculateSeverity(eventType, eventData)
      };
      
      // Store event
      this.events.set(eventId, event);
      
      // Index by IP
      this.indexEventByIP(event);
      
      // Perform real-time correlation
      await this.performCorrelation(event);
      
      // Update metrics
      this.metrics.eventsProcessed++;
      
      // Cleanup if necessary
      this.ensureMemoryLimits();
      
    } catch (error) {
      console.error('Error logging security event:', error);
    }
  }
  
  /**
   * Perform real-time correlation analysis
   */
  async performCorrelation(newEvent) {
    const correlations = [];
    
    for (const rule of this.correlationRules) {
      try {
        const correlation = await this.applyCorrelationRule(rule, newEvent);
        if (correlation) {
          correlations.push(correlation);
          this.metrics.correlationsFound++;
          
          // Generate alert if threshold met
          if (correlation.score >= this.config.ALERT_THRESHOLD) {
            await this.generateAlert(correlation);
          }
        }
      } catch (error) {
        console.error('Error applying correlation rule:', error);
      }
    }
    
    return correlations;
  }
  
  /**
   * Apply a specific correlation rule
   */
  async applyCorrelationRule(rule, newEvent) {
    const timeWindow = Date.now() - this.config.CORRELATION_WINDOW;
    const relevantEvents = this.getEventsInTimeWindow(timeWindow);
    
    switch (rule.type) {
      case 'frequency_analysis':
        return this.analyzeFrequency(rule, newEvent, relevantEvents);
        
      case 'pattern_detection':
        return this.detectPatterns(rule, newEvent, relevantEvents);
        
      case 'anomaly_detection':
        return this.detectAnomalies(rule, newEvent, relevantEvents);
        
      case 'threat_escalation':
        return this.detectThreatEscalation(rule, newEvent, relevantEvents);
        
      default:
        return null;
    }
  }
  
  /**
   * Analyze event frequency for correlation
   */
  analyzeFrequency(rule, newEvent, relevantEvents) {
    const sameIPEvents = relevantEvents.filter(e => 
      e.ip === newEvent.ip && 
      rule.eventTypes.includes(e.type)
    );
    
    if (sameIPEvents.length >= rule.threshold) {
      return {
        type: 'frequency_correlation',
        rule: rule.name,
        score: Math.min(sameIPEvents.length / rule.threshold * 10, 10),
        confidence: this.calculateConfidence(sameIPEvents),
        events: sameIPEvents.map(e => e.id),
        description: `High frequency of ${rule.eventTypes.join(', ')} from ${this.maskIP(newEvent.ip)}`,
        recommendation: rule.recommendation || 'Monitor and consider rate limiting'
      };
    }
    
    return null;
  }
  
  /**
   * Detect attack patterns
   */
  detectPatterns(rule, newEvent, relevantEvents) {
    const patternEvents = relevantEvents.filter(e => 
      rule.pattern.test(e.type) || 
      (e.data.path && rule.pattern.test(e.data.path))
    );
    
    if (patternEvents.length >= rule.minOccurrences) {
      // Check for progression pattern
      const sorted = patternEvents.sort((a, b) => a.timestamp - b.timestamp);
      const timeSpan = sorted[sorted.length - 1].timestamp - sorted[0].timestamp;
      
      if (timeSpan <= rule.maxTimeSpan) {
        return {
          type: 'pattern_correlation',
          rule: rule.name,
          score: this.calculatePatternScore(patternEvents, rule),
          confidence: this.calculateConfidence(patternEvents),
          events: patternEvents.map(e => e.id),
          description: `Attack pattern detected: ${rule.description}`,
          timeSpan,
          recommendation: rule.recommendation || 'Block IP and investigate'
        };
      }
    }
    
    return null;
  }
  
  /**
   * Detect behavioral anomalies
   */
  detectAnomalies(rule, newEvent, relevantEvents) {
    const userEvents = relevantEvents.filter(e => 
      e.context.userId === newEvent.context.userId ||
      e.ip === newEvent.ip
    );
    
    if (userEvents.length < rule.minBaseline) {
      return null; // Not enough data for baseline
    }
    
    // Calculate baseline behavior
    const baseline = this.calculateBaseline(userEvents, rule.metric);
    const currentValue = this.extractMetric(newEvent, rule.metric);
    
    const deviation = Math.abs(currentValue - baseline.mean) / baseline.stddev;
    
    if (deviation > rule.deviationThreshold) {
      return {
        type: 'anomaly_correlation',
        rule: rule.name,
        score: Math.min(deviation * 2, 10),
        confidence: this.calculateConfidence([newEvent]),
        events: [newEvent.id],
        description: `Behavioral anomaly detected in ${rule.metric}`,
        baseline: baseline.mean,
        current: currentValue,
        deviation,
        recommendation: rule.recommendation || 'Monitor user behavior'
      };
    }
    
    return null;
  }
  
  /**
   * Detect threat escalation
   */
  detectThreatEscalation(rule, newEvent, relevantEvents) {
    const threatEvents = relevantEvents.filter(e => 
      e.data.threatScore && e.data.threatScore > 0
    );
    
    if (threatEvents.length < 2) return null;
    
    // Sort by timestamp and check for escalation
    const sorted = threatEvents.sort((a, b) => a.timestamp - b.timestamp);
    let escalationDetected = false;
    let escalationScore = 0;
    
    for (let i = 1; i < sorted.length; i++) {
      const prev = sorted[i - 1];
      const curr = sorted[i];
      
      if (curr.data.threatScore > prev.data.threatScore) {
        escalationScore += (curr.data.threatScore - prev.data.threatScore);
        escalationDetected = true;
      }
    }
    
    if (escalationDetected && escalationScore >= rule.escalationThreshold) {
      return {
        type: 'escalation_correlation',
        rule: rule.name,
        score: Math.min(escalationScore / 10, 10),
        confidence: this.calculateConfidence(threatEvents),
        events: threatEvents.map(e => e.id),
        description: 'Threat escalation pattern detected',
        escalationScore,
        initialThreat: sorted[0].data.threatScore,
        finalThreat: sorted[sorted.length - 1].data.threatScore,
        recommendation: rule.recommendation || 'Immediate investigation required'
      };
    }
    
    return null;
  }
  
  /**
   * Generate security alert
   */
  async generateAlert(correlation) {
    const alert = {
      id: this.generateEventId(),
      timestamp: Date.now(),
      type: 'SECURITY_CORRELATION_ALERT',
      severity: this.calculateAlertSeverity(correlation),
      correlation,
      status: 'active'
    };
    
    // Log alert
    console.warn('🚨 SECURITY CORRELATION ALERT:', {
      id: alert.id,
      type: correlation.type,
      score: correlation.score,
      description: correlation.description,
      eventsInvolved: correlation.events.length
    });
    
    // Store alert for dashboard
    this.storeAlert(alert);
    
    this.metrics.alertsGenerated++;
    
    return alert;
  }
  
  /**
   * Initialize correlation rules
   */
  initializeCorrelationRules() {
    this.correlationRules = [
      // High frequency login attempts
      {
        name: 'rapid_login_attempts',
        type: 'frequency_analysis',
        eventTypes: ['LOGIN_ATTEMPT', 'LOGIN_FAILURE'],
        threshold: 5,
        timeWindow: 60000, // 1 minute
        recommendation: 'Implement progressive delay and consider IP blocking'
      },
      
      // Attack pattern detection
      {
        name: 'sql_injection_pattern',
        type: 'pattern_detection',
        pattern: /sql|union|select|drop|delete/i,
        minOccurrences: 3,
        maxTimeSpan: 300000, // 5 minutes
        description: 'SQL injection attack pattern',
        recommendation: 'Block IP immediately and audit database access'
      },
      
      // XSS attack pattern
      {
        name: 'xss_attack_pattern',
        type: 'pattern_detection',
        pattern: /script|javascript|vbscript|onload|onerror/i,
        minOccurrences: 2,
        maxTimeSpan: 180000, // 3 minutes
        description: 'XSS attack pattern',
        recommendation: 'Block IP and review input validation'
      },
      
      // Behavioral anomaly - request size
      {
        name: 'unusual_request_size',
        type: 'anomaly_detection',
        metric: 'contentLength',
        minBaseline: 10,
        deviationThreshold: 3,
        recommendation: 'Monitor for potential payload injection'
      },
      
      // Threat escalation
      {
        name: 'threat_score_escalation',
        type: 'threat_escalation',
        escalationThreshold: 50,
        recommendation: 'Immediate security investigation required'
      }
    ];
  }
  
  /**
   * Helper methods
   */
  generateEventId() {
    return crypto.randomBytes(16).toString('hex');
  }
  
  sanitizeEventData(data) {
    if (!data || typeof data !== 'object') return data;
    
    const sanitized = {};
    for (const [key, value] of Object.entries(data)) {
      if (['password', 'token', 'sessionId'].includes(key)) {
        sanitized[key] = '[REDACTED]';
      } else if (key === 'ip') {
        sanitized[key] = this.maskIP(value);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }
  
  maskIP(ip) {
    if (!ip || ip === 'unknown') return 'unknown';
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.xxx.xxx`;
    }
    return ip.substring(0, 8) + '...';
  }
  
  calculateSeverity(eventType, eventData) {
    const severityMap = {
      'REQUEST_RECEIVED': 1,
      'LOGIN_ATTEMPT': 2,
      'LOGIN_FAILURE': 3,
      'ERROR_RESPONSE': 4,
      'THREAT_DETECTED': 6,
      'ATTACK_BLOCKED': 7,
      'CRITICAL_THREAT': 9
    };
    
    let baseSeverity = severityMap[eventType] || 1;
    
    // Adjust based on threat score
    if (eventData.threatScore) {
      baseSeverity += Math.floor(eventData.threatScore / 20);
    }
    
    return Math.min(baseSeverity, 10);
  }
  
  indexEventByIP(event) {
    const ip = event.ip;
    if (!this.ipEvents.has(ip)) {
      this.ipEvents.set(ip, []);
    }
    
    const events = this.ipEvents.get(ip);
    events.push(event.id);
    
    // Limit events per IP
    if (events.length > this.config.MAX_IP_EVENTS) {
      events.shift();
    }
  }
  
  getEventsInTimeWindow(windowStart) {
    const events = [];
    for (const event of this.events.values()) {
      if (event.timestamp >= windowStart) {
        events.push(event);
      }
    }
    return events;
  }
  
  calculateConfidence(events) {
    if (events.length === 0) return 0;
    if (events.length >= 5) return 95;
    if (events.length >= 3) return 80;
    if (events.length >= 2) return 65;
    return 45;
  }
  
  calculatePatternScore(events, rule) {
    const baseScore = events.length;
    const timeSpan = events[events.length - 1].timestamp - events[0].timestamp;
    const rapidityBonus = timeSpan < 60000 ? 2 : 1; // Bonus for rapid succession
    return Math.min(baseScore * rapidityBonus, 10);
  }
  
  calculateBaseline(events, metric) {
    const values = events.map(e => this.extractMetric(e, metric)).filter(v => v !== null);
    if (values.length === 0) return { mean: 0, stddev: 1 };
    
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
    const stddev = Math.sqrt(variance) || 1;
    
    return { mean, stddev };
  }
  
  extractMetric(event, metric) {
    switch (metric) {
      case 'contentLength':
        return parseInt(event.data.contentLength) || 0;
      case 'pathLength':
        return (event.data.path || '').length;
      case 'userAgentLength':
        return (event.data.userAgent || '').length;
      default:
        return 0;
    }
  }
  
  calculateAlertSeverity(correlation) {
    if (correlation.score >= 8) return 'critical';
    if (correlation.score >= 6) return 'high';
    if (correlation.score >= 4) return 'medium';
    return 'low';
  }
  
  storeAlert(alert) {
    // Store in memory for dashboard access
    if (!this.alerts) this.alerts = [];
    this.alerts.push(alert);
    
    // Keep only recent alerts
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    this.alerts = this.alerts.filter(a => a.timestamp > oneHourAgo);
  }
  
  ensureMemoryLimits() {
    if (this.events.size > this.config.MAX_EVENTS_MEMORY) {
      // Remove oldest events
      const events = Array.from(this.events.values()).sort((a, b) => a.timestamp - b.timestamp);
      const toRemove = events.slice(0, events.length - this.config.MAX_EVENTS_MEMORY);
      
      for (const event of toRemove) {
        this.events.delete(event.id);
        
        // Also clean up IP index
        const ipEvents = this.ipEvents.get(event.ip);
        if (ipEvents) {
          const index = ipEvents.indexOf(event.id);
          if (index > -1) ipEvents.splice(index, 1);
        }
      }
    }
  }
  
  startCleanupProcess() {
    this.cleanupInterval = setInterval(() => {
      this.performCleanup();
    }, this.config.CLEANUP_INTERVAL);
  }
  
  performCleanup() {
    const cutoff = Date.now() - this.config.CORRELATION_WINDOW;
    
    for (const [eventId, event] of this.events.entries()) {
      if (event.timestamp < cutoff) {
        this.events.delete(eventId);
      }
    }
    
    // Clean up IP index
    for (const [ip, eventIds] of this.ipEvents.entries()) {
      const validIds = eventIds.filter(id => this.events.has(id));
      if (validIds.length === 0) {
        this.ipEvents.delete(ip);
      } else {
        this.ipEvents.set(ip, validIds);
      }
    }
  }
  
  /**
   * Public API methods
   */
  getSecurityMetrics() {
    return {
      ...this.metrics,
      activeEvents: this.events.size,
      trackedIPs: this.ipEvents.size,
      recentAlerts: this.alerts ? this.alerts.length : 0
    };
  }
  
  getRecentEvents(limit = 20) {
    const events = Array.from(this.events.values())
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, limit);
    
    return events.map(event => ({
      id: event.id,
      type: event.type,
      timestamp: event.timestamp,
      severity: event.severity,
      ip: event.data.ip || 'unknown'
    }));
  }
  
  getRecentAlerts(limit = 10) {
    if (!this.alerts) return [];
    
    return this.alerts
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, limit)
      .map(alert => ({
        id: alert.id,
        timestamp: alert.timestamp,
        severity: alert.severity,
        type: alert.correlation.type,
        description: alert.correlation.description,
        score: alert.correlation.score
      }));
  }
  
  shutdown() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    console.log('🔍 Security Event Correlation System shutdown complete');
  }
}

module.exports = SecurityEventCorrelationSystem;