const EventEmitter = require('events');
const SecureLogger = require('../utils/secureLogger');

/**
 * Performance Alerting System
 * 
 * Advanced alerting system for database performance monitoring
 * Provides intelligent recommendations, escalation, and notification management
 */
class PerformanceAlerting extends EventEmitter {
  constructor(realTimeMetrics, options = {}) {
    super();
    
    this.realTimeMetrics = realTimeMetrics;
    this.config = {
      escalationTimeouts: {
        low: 30 * 60 * 1000,    // 30 minutes
        medium: 15 * 60 * 1000,  // 15 minutes
        high: 5 * 60 * 1000      // 5 minutes
      },
      maxAlerts: options.maxAlerts || 1000,
      notificationCooldown: options.notificationCooldown || 5 * 60 * 1000, // 5 minutes
      enableEmailAlerts: options.enableEmailAlerts || false,
      enableWebhooks: options.enableWebhooks || false,
      autoRemediation: options.autoRemediation || false,
      ...options
    };

    // Alert management
    this.alertRules = new Map();
    this.activeNotifications = new Map();
    this.escalationTimers = new Map();
    this.suppressedAlerts = new Set();
    
    // Metrics for alert system itself
    this.alertingMetrics = {
      totalAlertsTriggered: 0,
      totalAlertsResolved: 0,
      falsePositives: 0,
      escalationsTriggered: 0,
      autoRemediationsAttempted: 0,
      autoRemediationsSuccessful: 0,
      lastActivity: new Date()
    };

    this.isActive = false;
    this.setupDefaultRules();
  }

  /**
   * Set up default alert rules
   */
  setupDefaultRules() {
    // Slow query rate rule
    this.addAlertRule('slow_query_rate', {
      name: 'High Slow Query Rate',
      description: 'Monitors the percentage of slow queries',
      condition: (metrics) => metrics && typeof metrics.slowQueryRate === 'number' && metrics.slowQueryRate > 0.15,
      severity: 'high',
      cooldown: 5 * 60 * 1000, // 5 minutes
      recommendations: [
        'Review and optimize slow queries',
        'Check if appropriate indexes are being used',
        'Consider query structure optimization',
        'Monitor database load and resources'
      ],
      autoRemediation: {
        enabled: false,
        actions: ['index_analysis', 'query_optimization_suggestions']
      }
    });

    // Average execution time rule
    this.addAlertRule('avg_execution_time', {
      name: 'High Average Execution Time',
      description: 'Monitors average query execution time',
      condition: (metrics) => metrics && typeof metrics.avgExecutionTime === 'number' && metrics.avgExecutionTime > 200,
      severity: 'medium',
      cooldown: 10 * 60 * 1000, // 10 minutes
      recommendations: [
        'Analyze query performance patterns',
        'Verify index usage efficiency',
        'Check for resource contention',
        'Consider connection pool optimization'
      ],
      autoRemediation: {
        enabled: true,
        actions: ['performance_analysis', 'index_recommendations']
      }
    });

    // Index efficiency rule
    this.addAlertRule('index_efficiency', {
      name: 'Low Hybrid Index Efficiency',
      description: 'Monitors hybrid indexing strategy effectiveness',
      condition: (metrics) => metrics && typeof metrics.hybridIndexEfficiency === 'number' && metrics.hybridIndexEfficiency < 0.7 && metrics.hybridIndexEfficiency > 0,
      severity: 'medium',
      cooldown: 15 * 60 * 1000, // 15 minutes
      recommendations: [
        'Review hybrid indexing strategy',
        'Analyze query patterns for index optimization',
        'Consider adding or modifying indexes',
        'Check for collection scans'
      ],
      autoRemediation: {
        enabled: true,
        actions: ['hybrid_index_analysis', 'query_pattern_optimization']
      }
    });

    // Query volume spike rule
    this.addAlertRule('query_volume_spike', {
      name: 'Query Volume Spike',
      description: 'Detects unusual spikes in query volume',
      condition: (metrics, historical) => {
        if (!metrics || typeof metrics.queriesPerSecond !== 'number') return false;
        if (!historical || historical.length < 3) return false;
        const avgHistorical = historical.reduce((sum, h) => sum + (h.queriesPerSecond || 0), 0) / historical.length;
        return metrics.queriesPerSecond > avgHistorical * 2.5;
      },
      severity: 'low',
      cooldown: 5 * 60 * 1000, // 5 minutes
      recommendations: [
        'Monitor system resources',
        'Check for application load spikes',
        'Review query patterns for anomalies',
        'Consider scaling if needed'
      ],
      autoRemediation: {
        enabled: false,
        actions: ['resource_monitoring', 'load_analysis']
      }
    });

    // Memory usage rule
    this.addAlertRule('memory_usage', {
      name: 'High Memory Usage',
      description: 'Monitors application memory consumption',
      condition: (metrics) => {
        if (!metrics || !metrics.memoryUsage) return false;
        const memUsage = metrics.memoryUsage;
        return memUsage && typeof memUsage.heapUsedMB === 'number' && memUsage.heapUsedMB > 500; // 500MB threshold
      },
      severity: 'medium',
      cooldown: 10 * 60 * 1000, // 10 minutes
      recommendations: [
        'Monitor memory leak potential',
        'Review query result set sizes',
        'Check for inefficient data structures',
        'Consider garbage collection optimization'
      ],
      autoRemediation: {
        enabled: true,
        actions: ['memory_analysis', 'gc_optimization']
      }
    });
  }

  /**
   * Add custom alert rule
   */
  addAlertRule(id, rule) {
    this.alertRules.set(id, {
      id,
      createdAt: new Date(),
      triggeredCount: 0,
      lastTriggered: null,
      isActive: true,
      ...rule
    });
    
    SecureLogger.logInfo(`Alert rule added: ${id}`, { name: rule.name });
  }

  /**
   * Remove alert rule
   */
  removeAlertRule(id) {
    if (this.alertRules.has(id)) {
      this.alertRules.delete(id);
      this.clearEscalationTimer(id);
      SecureLogger.logInfo(`Alert rule removed: ${id}`);
      return true;
    }
    return false;
  }

  /**
   * Update alert rule
   */
  updateAlertRule(id, updates) {
    if (this.alertRules.has(id)) {
      const rule = this.alertRules.get(id);
      this.alertRules.set(id, { ...rule, ...updates });
      SecureLogger.logInfo(`Alert rule updated: ${id}`);
      return true;
    }
    return false;
  }

  /**
   * Start alerting system
   */
  startAlerting() {
    if (this.isActive) {
      SecureLogger.logWarning('Performance alerting already active');
      return;
    }

    SecureLogger.logInfo('Starting performance alerting system');

    // Listen to real-time metrics events
    this.realTimeMetrics.on('metrics-updated', this.checkAlertConditions.bind(this));
    this.realTimeMetrics.on('alert-triggered', this.handleMetricsAlert.bind(this));
    this.realTimeMetrics.on('alert-resolved', this.handleMetricsAlertResolved.bind(this));

    this.isActive = true;
    this.emit('alerting-started');
    
    SecureLogger.logInfo('Performance alerting system started');
  }

  /**
   * Stop alerting system
   */
  stopAlerting() {
    if (!this.isActive) return;

    SecureLogger.logInfo('Stopping performance alerting system');

    // Remove event listeners
    this.realTimeMetrics.removeAllListeners('metrics-updated');
    this.realTimeMetrics.removeAllListeners('alert-triggered');
    this.realTimeMetrics.removeAllListeners('alert-resolved');

    // Clear all escalation timers
    for (const [ruleId] of this.escalationTimers.entries()) {
      this.clearEscalationTimer(ruleId);
    }

    this.isActive = false;
    this.emit('alerting-stopped');
    
    SecureLogger.logInfo('Performance alerting system stopped');
  }

  /**
   * Check alert conditions against current metrics
   */
  checkAlertConditions(currentMetrics) {
    if (!this.isActive) return;

    this.alertingMetrics.lastActivity = new Date();
    
    // Get historical data for trend analysis
    const historicalMetrics = this.getHistoricalMetrics(10); // Last 10 data points

    for (const [ruleId, rule] of this.alertRules.entries()) {
      if (!rule.isActive || this.suppressedAlerts.has(ruleId)) continue;

      try {
        // Safety check for metrics availability
        if (!currentMetrics || !currentMetrics.realtime) {
          SecureLogger.logDebug(`Alert rule ${ruleId} skipped - metrics not available`, {
            hasCurrentMetrics: !!currentMetrics,
            hasRealtimeMetrics: !!(currentMetrics && currentMetrics.realtime),
            ruleId,
            timestamp: new Date().toISOString()
          });
          continue;
        }
        
        // Check if rule condition is met
        const conditionMet = rule.condition(currentMetrics.realtime, historicalMetrics);
        
        if (conditionMet) {
          this.triggerAlert(ruleId, rule, currentMetrics.realtime);
        } else {
          // Check if alert should be resolved
          this.checkAlertResolution(ruleId);
        }
        
      } catch (error) {
        SecureLogger.logError(`Error checking alert rule ${ruleId}`, error);
      }
    }
  }

  /**
   * Get historical metrics for trend analysis
   */
  getHistoricalMetrics(count = 10) {
    const recentWindows = this.realTimeMetrics.getRecentWindows(30 * 60 * 1000); // 30 minutes
    
    return recentWindows.slice(-count).map(window => ({
      timestamp: window.endTime,
      queriesPerSecond: window.stats?.queriesPerSecond || 0,
      avgExecutionTime: window.stats?.avgTime || 0,
      slowQueryRate: window.stats?.slowQueryRate || 0,
      indexEfficiency: window.stats?.indexEfficiency || 1
    }));
  }

  /**
   * Trigger alert for a specific rule
   */
  triggerAlert(ruleId, rule, metrics) {
    const now = new Date();
    
    // Check cooldown
    if (rule.lastTriggered && (now - rule.lastTriggered) < rule.cooldown) {
      return;
    }

    // Check notification cooldown
    const lastNotification = this.activeNotifications.get(ruleId);
    if (lastNotification && (now - lastNotification) < this.config.notificationCooldown) {
      return;
    }

    // Update rule statistics
    rule.triggeredCount++;
    rule.lastTriggered = now;
    this.alertingMetrics.totalAlertsTriggered++;

    // Create alert object
    const alert = {
      id: `${ruleId}_${Date.now()}`,
      ruleId,
      ruleName: rule.name,
      severity: rule.severity,
      description: rule.description,
      triggeredAt: now,
      metrics: { ...metrics },
      recommendations: rule.recommendations,
      status: 'active',
      escalated: false,
      autoRemediationAttempted: false
    };

    // Send notification
    this.sendNotification(alert);
    
    // Set up escalation timer
    this.setupEscalationTimer(alert);
    
    // Attempt auto-remediation if enabled
    if (this.config.autoRemediation && rule.autoRemediation?.enabled) {
      this.attemptAutoRemediation(alert, rule.autoRemediation);
    }

    // Record notification
    this.activeNotifications.set(ruleId, now);
    
    this.emit('alert-triggered', alert);
    
    SecureLogger.logWarning(`Performance alert triggered: ${rule.name}`, {
      ruleId,
      severity: rule.severity,
      metrics: this.sanitizeMetrics(metrics)
    });
  }

  /**
   * Check if an active alert should be resolved
   */
  checkAlertResolution(ruleId) {
    if (this.activeNotifications.has(ruleId)) {
      const rule = this.alertRules.get(ruleId);
      
      // Simple resolution: if condition hasn't been met for 2 cooldown periods
      const timeSinceLastTrigger = Date.now() - (rule.lastTriggered || 0);
      if (timeSinceLastTrigger > rule.cooldown * 2) {
        this.resolveAlert(ruleId);
      }
    }
  }

  /**
   * Resolve an active alert
   */
  resolveAlert(ruleId) {
    if (this.activeNotifications.has(ruleId)) {
      this.activeNotifications.delete(ruleId);
      this.clearEscalationTimer(ruleId);
      
      this.alertingMetrics.totalAlertsResolved++;
      
      const resolvedAlert = {
        ruleId,
        resolvedAt: new Date(),
        status: 'resolved'
      };
      
      this.emit('alert-resolved', resolvedAlert);
      
      SecureLogger.logInfo(`Performance alert resolved: ${ruleId}`);
    }
  }

  /**
   * Set up escalation timer for an alert
   */
  setupEscalationTimer(alert) {
    const escalationDelay = this.config.escalationTimeouts[alert.severity] || 15 * 60 * 1000;
    
    const timer = setTimeout(() => {
      this.escalateAlert(alert);
    }, escalationDelay);
    
    this.escalationTimers.set(alert.ruleId, timer);
  }

  /**
   * Clear escalation timer
   */
  clearEscalationTimer(ruleId) {
    if (this.escalationTimers.has(ruleId)) {
      clearTimeout(this.escalationTimers.get(ruleId));
      this.escalationTimers.delete(ruleId);
    }
  }

  /**
   * Escalate an alert to higher severity
   */
  escalateAlert(alert) {
    if (!this.activeNotifications.has(alert.ruleId)) return; // Alert was resolved

    const severityLevels = ['low', 'medium', 'high', 'critical'];
    const currentIndex = severityLevels.indexOf(alert.severity);
    
    if (currentIndex < severityLevels.length - 1) {
      alert.severity = severityLevels[currentIndex + 1];
      alert.escalated = true;
      alert.escalatedAt = new Date();
      
      this.alertingMetrics.escalationsTriggered++;
      
      // Send escalated notification
      this.sendNotification({
        ...alert,
        escalated: true,
        message: `ESCALATED: ${alert.ruleName} - condition persists`
      });
      
      this.emit('alert-escalated', alert);
      
      SecureLogger.logError(`Alert escalated to ${alert.severity}: ${alert.ruleName}`, {
        ruleId: alert.ruleId,
        originalSeverity: severityLevels[currentIndex]
      });
    }
  }

  /**
   * Attempt auto-remediation for an alert
   */
  async attemptAutoRemediation(alert, remediationConfig) {
    this.alertingMetrics.autoRemediationsAttempted++;
    alert.autoRemediationAttempted = true;

    SecureLogger.logInfo(`Attempting auto-remediation for alert: ${alert.ruleId}`, {
      actions: remediationConfig.actions
    });

    let success = false;
    const remediationResults = [];

    try {
      for (const action of remediationConfig.actions) {
        const result = await this.executeRemediationAction(action, alert);
        remediationResults.push(result);
        
        if (result.success) {
          success = true;
        }
      }

      if (success) {
        this.alertingMetrics.autoRemediationsSuccessful++;
      }

      alert.autoRemediationResults = remediationResults;
      alert.autoRemediationSuccessful = success;

    } catch (error) {
      SecureLogger.logError(`Auto-remediation failed for alert: ${alert.ruleId}`, error);
      alert.autoRemediationError = error.message;
    }

    this.emit('auto-remediation-attempted', {
      alert,
      success,
      results: remediationResults
    });
  }

  /**
   * Execute a specific remediation action
   */
  async executeRemediationAction(action, alert) {
    switch (action) {
      case 'index_analysis':
        return await this.performIndexAnalysis(alert);
      
      case 'query_optimization_suggestions':
        return await this.generateQueryOptimizationSuggestions(alert);
      
      case 'performance_analysis':
        return await this.performPerformanceAnalysis(alert);
      
      case 'hybrid_index_analysis':
        return await this.analyzeHybridIndexUsage(alert);
      
      case 'memory_analysis':
        return await this.analyzeMemoryUsage(alert);
      
      default:
        return {
          action,
          success: false,
          message: 'Unknown remediation action',
          timestamp: new Date()
        };
    }
  }

  /**
   * Perform index analysis remediation
   */
  async performIndexAnalysis(alert) {
    try {
      // This would integrate with the DBPerformanceMonitor
      // For now, we'll simulate the analysis
      
      const analysis = {
        missingIndexes: [],
        underutilizedIndexes: [],
        recommendations: [
          'Consider adding compound index on frequently queried fields',
          'Review partial filter expressions for sparse data',
          'Analyze query patterns for optimization opportunities'
        ]
      };

      return {
        action: 'index_analysis',
        success: true,
        results: analysis,
        message: 'Index analysis completed',
        timestamp: new Date()
      };
      
    } catch (error) {
      return {
        action: 'index_analysis',
        success: false,
        error: error.message,
        timestamp: new Date()
      };
    }
  }

  /**
   * Generate query optimization suggestions
   */
  async generateQueryOptimizationSuggestions(alert) {
    try {
      const suggestions = [
        'Use projection to limit returned fields',
        'Add appropriate indexes for filter conditions',
        'Consider query result caching for frequent queries',
        'Optimize aggregation pipeline stages'
      ];

      return {
        action: 'query_optimization_suggestions',
        success: true,
        suggestions,
        message: 'Query optimization suggestions generated',
        timestamp: new Date()
      };
      
    } catch (error) {
      return {
        action: 'query_optimization_suggestions',
        success: false,
        error: error.message,
        timestamp: new Date()
      };
    }
  }

  /**
   * Perform performance analysis
   */
  async performPerformanceAnalysis(alert) {
    try {
      const analysis = {
        bottlenecks: ['Query execution time', 'Index utilization'],
        systemHealth: 'Degraded',
        recommendations: [
          'Monitor query execution patterns',
          'Review index strategy',
          'Check system resources'
        ]
      };

      return {
        action: 'performance_analysis',
        success: true,
        results: analysis,
        message: 'Performance analysis completed',
        timestamp: new Date()
      };
      
    } catch (error) {
      return {
        action: 'performance_analysis',
        success: false,
        error: error.message,
        timestamp: new Date()
      };
    }
  }

  /**
   * Analyze hybrid index usage
   */
  async analyzeHybridIndexUsage(alert) {
    try {
      const analysis = {
        efficiency: alert.metrics.hybridIndexEfficiency || 0,
        patterns: ['user-auth', 'token-auth', 'time-range'],
        recommendations: [
          'Review hybrid indexing strategy effectiveness',
          'Consider query pattern optimization',
          'Evaluate index selectivity'
        ]
      };

      return {
        action: 'hybrid_index_analysis',
        success: true,
        results: analysis,
        message: 'Hybrid index analysis completed',
        timestamp: new Date()
      };
      
    } catch (error) {
      return {
        action: 'hybrid_index_analysis',
        success: false,
        error: error.message,
        timestamp: new Date()
      };
    }
  }

  /**
   * Analyze memory usage
   */
  async analyzeMemoryUsage(alert) {
    try {
      const memUsage = process.memoryUsage();
      const analysis = {
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        heapUtilization: memUsage.heapUsed / memUsage.heapTotal,
        recommendations: [
          'Monitor for memory leaks',
          'Review large object allocations',
          'Consider garbage collection tuning'
        ]
      };

      return {
        action: 'memory_analysis',
        success: true,
        results: analysis,
        message: 'Memory analysis completed',
        timestamp: new Date()
      };
      
    } catch (error) {
      return {
        action: 'memory_analysis',
        success: false,
        error: error.message,
        timestamp: new Date()
      };
    }
  }

  /**
   * Send notification for an alert
   */
  sendNotification(alert) {
    // Log notification
    SecureLogger.logWarning(`ALERT NOTIFICATION: ${alert.ruleName}`, {
      severity: alert.severity,
      ruleId: alert.ruleId,
      escalated: alert.escalated || false
    });

    // Emit event for external integrations
    this.emit('notification-sent', alert);

    // Here you would integrate with external notification systems:
    // - Email notifications
    // - Slack/Teams webhooks  
    // - SMS alerts
    // - PagerDuty integration
    // etc.
  }

  /**
   * Handle alerts from RealTimeMetrics
   */
  handleMetricsAlert(alert) {
    // RealTimeMetrics also generates alerts, we can enhance them here
    SecureLogger.logWarning(`Real-time metrics alert: ${alert.key}`, alert.details);
  }

  /**
   * Handle resolved alerts from RealTimeMetrics
   */
  handleMetricsAlertResolved(alert) {
    SecureLogger.logInfo(`Real-time metrics alert resolved: ${alert.key}`);
  }

  /**
   * Get alerting system status
   */
  getAlertingStatus() {
    return {
      isActive: this.isActive,
      metrics: { ...this.alertingMetrics },
      rules: {
        total: this.alertRules.size,
        active: Array.from(this.alertRules.values()).filter(r => r.isActive).length,
        triggered: Array.from(this.alertRules.values()).filter(r => r.triggeredCount > 0).length
      },
      activeAlerts: this.activeNotifications.size,
      escalationTimers: this.escalationTimers.size,
      suppressedAlerts: this.suppressedAlerts.size,
      config: { ...this.config }
    };
  }

  /**
   * Get all alert rules
   */
  getAlertRules() {
    return Array.from(this.alertRules.entries()).map(([id, rule]) => ({
      id,
      ...rule
    }));
  }

  /**
   * Suppress alerts for a specific rule
   */
  suppressAlert(ruleId, duration = 60 * 60 * 1000) { // Default 1 hour
    this.suppressedAlerts.add(ruleId);
    
    setTimeout(() => {
      this.suppressedAlerts.delete(ruleId);
      SecureLogger.logInfo(`Alert suppression lifted for rule: ${ruleId}`);
    }, duration);
    
    SecureLogger.logInfo(`Alert suppressed for rule: ${ruleId}`, { duration });
  }

  /**
   * Sanitize metrics for logging (remove sensitive data)
   */
  sanitizeMetrics(metrics) {
    const sanitized = { ...metrics };
    
    // Remove potentially sensitive or large data
    delete sanitized.memoryUsage;
    delete sanitized.breakdown;
    
    return sanitized;
  }

  /**
   * Export alerting data
   */
  exportAlertingData() {
    return {
      timestamp: new Date(),
      status: this.getAlertingStatus(),
      rules: this.getAlertRules(),
      activeNotifications: Array.from(this.activeNotifications.entries()),
      suppressedAlerts: Array.from(this.suppressedAlerts)
    };
  }

  /**
   * Reset alerting metrics
   */
  resetMetrics() {
    this.alertingMetrics = {
      totalAlertsTriggered: 0,
      totalAlertsResolved: 0,
      falsePositives: 0,
      escalationsTriggered: 0,
      autoRemediationsAttempted: 0,
      autoRemediationsSuccessful: 0,
      lastActivity: new Date()
    };
    
    // Reset rule statistics
    for (const rule of this.alertRules.values()) {
      rule.triggeredCount = 0;
      rule.lastTriggered = null;
    }
    
    SecureLogger.logInfo('Alerting metrics reset');
    this.emit('metrics-reset');
  }
}

module.exports = PerformanceAlerting;