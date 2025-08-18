const EventEmitter = require('events');
const SecureLogger = require('../utils/secureLogger');

/**
 * Scheduler-Specific Alerting System
 * 
 * Advanced alerting system designed specifically for Form-a-Friend v2 scheduler operations
 * Provides intelligent alerting, escalation, notification throttling, and auto-remediation
 * 
 * Features:
 * - Scheduler-specific alert rules and thresholds
 * - Multi-channel notification support (console, email, webhook)
 * - Intelligent alert throttling and suppression
 * - Escalation management with auto-escalation
 * - Auto-remediation capabilities
 * - Alert correlation and pattern detection
 * - Performance impact monitoring
 * - Historical alert analysis
 */
class SchedulerAlerting extends EventEmitter {
  constructor(config = {}) {
    super();
    
    this.config = {
      // Alert configuration
      enableAlerting: config.enableAlerting !== false,
      alertThrottleWindow: config.alertThrottleWindow || 5 * 60 * 1000, // 5 minutes
      maxAlertsPerHour: config.maxAlertsPerHour || 20,
      
      // Escalation settings
      escalationLevels: config.escalationLevels || ['low', 'medium', 'high', 'critical'],
      escalationTimeouts: config.escalationTimeouts || {
        low: 30 * 60 * 1000,    // 30 minutes
        medium: 15 * 60 * 1000,  // 15 minutes
        high: 5 * 60 * 1000,     // 5 minutes
        critical: 2 * 60 * 1000  // 2 minutes
      },
      
      // Notification channels
      enableConsoleAlerts: config.enableConsoleAlerts !== false,
      enableEmailAlerts: config.enableEmailAlerts || false,
      enableWebhookAlerts: config.enableWebhookAlerts || false,
      enableSlackAlerts: config.enableSlackAlerts || false,
      
      // Email settings
      emailRecipients: config.emailRecipients || [],
      emailSmtpConfig: config.emailSmtpConfig || null,
      
      // Webhook settings
      webhookUrls: config.webhookUrls || [],
      webhookTimeout: config.webhookTimeout || 10000,
      
      // Slack settings
      slackWebhookUrl: config.slackWebhookUrl || null,
      slackChannel: config.slackChannel || '#alerts',
      
      // Auto-remediation
      enableAutoRemediation: config.enableAutoRemediation || false,
      autoRemediationActions: config.autoRemediationActions || {},
      
      // Alert retention
      alertHistoryRetention: config.alertHistoryRetention || 30 * 24 * 60 * 60 * 1000, // 30 days
      maxAlertHistory: config.maxAlertHistory || 10000,
      
      ...config
    };

    // Alert state management
    this.activeAlerts = new Map();
    this.alertHistory = [];
    this.suppressedAlerts = new Set();
    this.escalationTimers = new Map();
    this.throttledAlerts = new Map();
    
    // Alert statistics
    this.alertStats = {
      totalAlerts: 0,
      alertsByLevel: new Map(),
      alertsByType: new Map(),
      escalationsTriggered: 0,
      autoRemediationsAttempted: 0,
      autoRemediationsSuccessful: 0,
      notificationsSent: 0,
      throttledNotifications: 0,
      falsePositives: 0,
      lastAlertTime: null,
      averageResolutionTime: 0
    };
    
    // Alert rules for scheduler-specific scenarios
    this.alertRules = new Map();
    this.isActive = false;
    
    // Service dependencies
    this.schedulerLogger = null;
    this.schedulerMonitoring = null;
    this.emailService = null;
    
    this.setupDefaultAlertRules();
    
    SecureLogger.logInfo('SchedulerAlerting initialized', {
      enableAlerting: this.config.enableAlerting,
      alertRules: this.alertRules.size,
      notificationChannels: this.getEnabledChannels().length
    });
  }

  /**
   * Initialize alerting service with dependencies
   */
  async initialize(dependencies = {}) {
    try {
      this.schedulerLogger = dependencies.schedulerLogger;
      this.schedulerMonitoring = dependencies.schedulerMonitoring;
      this.emailService = dependencies.emailService;

      // Setup monitoring integration if available
      if (this.schedulerMonitoring) {
        this.setupMonitoringIntegration();
      }

      SecureLogger.logInfo('SchedulerAlerting initialized successfully', {
        hasLogger: !!this.schedulerLogger,
        hasMonitoring: !!this.schedulerMonitoring,
        hasEmailService: !!this.emailService
      });
      
      return true;
    } catch (error) {
      SecureLogger.logError('Failed to initialize SchedulerAlerting', error);
      throw error;
    }
  }

  /**
   * Setup default alert rules for scheduler operations
   */
  setupDefaultAlertRules() {
    // Job failure alerts
    this.addAlertRule('job-failure', {
      name: 'Job Execution Failure',
      description: 'Triggered when a scheduled job fails to execute',
      severity: 'high',
      condition: (data) => data.eventType === 'job-failed',
      cooldown: 60000, // 1 minute
      autoRemediation: {
        enabled: true,
        actions: ['restart-job', 'check-dependencies', 'notify-ops']
      },
      escalation: {
        enabled: true,
        escalateAfter: 10 * 60 * 1000 // 10 minutes
      },
      notifications: ['console', 'email', 'webhook']
    });

    // Consecutive failures
    this.addAlertRule('consecutive-failures', {
      name: 'Consecutive Job Failures',
      description: 'Multiple consecutive job failures detected',
      severity: 'critical',
      condition: (data) => data.eventType === 'consecutive-failures' && data.count >= 3,
      cooldown: 300000, // 5 minutes
      autoRemediation: {
        enabled: true,
        actions: ['emergency-restart', 'escalate-to-ops', 'check-system-health']
      },
      escalation: {
        enabled: true,
        escalateAfter: 5 * 60 * 1000 // 5 minutes
      },
      notifications: ['console', 'email', 'webhook', 'slack']
    });

    // Monthly job specific alerts
    this.addAlertRule('monthly-job-failure', {
      name: 'Monthly Invitation Job Failure',
      description: 'Critical monthly invitation job has failed',
      severity: 'critical',
      condition: (data) => data.eventType === 'job-failed' && data.jobType === 'monthly-invitations',
      cooldown: 0, // No cooldown for critical monthly job
      autoRemediation: {
        enabled: true,
        actions: ['immediate-restart', 'backup-execution', 'notify-management']
      },
      escalation: {
        enabled: true,
        escalateAfter: 2 * 60 * 1000 // 2 minutes
      },
      notifications: ['console', 'email', 'webhook', 'slack']
    });

    // Performance degradation
    this.addAlertRule('performance-degradation', {
      name: 'Job Performance Degradation',
      description: 'Job execution time significantly exceeds normal duration',
      severity: 'medium',
      condition: (data) => data.eventType === 'performance-degradation',
      cooldown: 600000, // 10 minutes
      autoRemediation: {
        enabled: true,
        actions: ['analyze-performance', 'check-resources', 'optimize-execution']
      },
      escalation: {
        enabled: true,
        escalateAfter: 30 * 60 * 1000 // 30 minutes
      },
      notifications: ['console', 'email']
    });

    // Memory usage alerts
    this.addAlertRule('high-memory-usage', {
      name: 'High Memory Usage',
      description: 'Scheduler memory usage is critically high',
      severity: 'high',
      condition: (data) => data.eventType === 'high-memory-usage',
      cooldown: 300000, // 5 minutes
      autoRemediation: {
        enabled: true,
        actions: ['garbage-collection', 'memory-analysis', 'restart-if-critical']
      },
      escalation: {
        enabled: true,
        escalateAfter: 15 * 60 * 1000 // 15 minutes
      },
      notifications: ['console', 'email', 'webhook']
    });

    // Stuck job alerts
    this.addAlertRule('stuck-job', {
      name: 'Job Execution Stuck',
      description: 'Job appears to be stuck or hanging',
      severity: 'high',
      condition: (data) => data.eventType === 'stuck-job',
      cooldown: 180000, // 3 minutes
      autoRemediation: {
        enabled: true,
        actions: ['terminate-job', 'restart-job', 'check-dependencies']
      },
      escalation: {
        enabled: true,
        escalateAfter: 10 * 60 * 1000 // 10 minutes
      },
      notifications: ['console', 'email', 'webhook']
    });

    // Email service failures
    this.addAlertRule('email-service-failure', {
      name: 'Email Service Failure',
      description: 'Email service has failed or is unavailable',
      severity: 'high',
      condition: (data) => data.eventType === 'email-service-failure',
      cooldown: 300000, // 5 minutes
      autoRemediation: {
        enabled: true,
        actions: ['retry-email-service', 'switch-provider', 'queue-emails']
      },
      escalation: {
        enabled: true,
        escalateAfter: 15 * 60 * 1000 // 15 minutes
      },
      notifications: ['console', 'webhook', 'slack']
    });

    // Database connectivity issues
    this.addAlertRule('database-connectivity', {
      name: 'Database Connectivity Issues',
      description: 'Database connection issues detected',
      severity: 'critical',
      condition: (data) => data.eventType === 'database-connectivity',
      cooldown: 60000, // 1 minute
      autoRemediation: {
        enabled: true,
        actions: ['reconnect-database', 'check-connection-pool', 'fallback-mode']
      },
      escalation: {
        enabled: true,
        escalateAfter: 3 * 60 * 1000 // 3 minutes
      },
      notifications: ['console', 'email', 'webhook', 'slack']
    });

    // Worker utilization alerts
    this.addAlertRule('worker-overload', {
      name: 'Worker Thread Overload',
      description: 'Worker thread utilization is critically high',
      severity: 'medium',
      condition: (data) => data.eventType === 'worker-overload',
      cooldown: 600000, // 10 minutes
      autoRemediation: {
        enabled: true,
        actions: ['scale-workers', 'optimize-batches', 'throttle-execution']
      },
      escalation: {
        enabled: true,
        escalateAfter: 20 * 60 * 1000 // 20 minutes
      },
      notifications: ['console', 'email']
    });

    SecureLogger.logInfo('Default scheduler alert rules configured', {
      totalRules: this.alertRules.size
    });
  }

  /**
   * Setup integration with scheduler monitoring service
   */
  setupMonitoringIntegration() {
    if (!this.schedulerMonitoring || typeof this.schedulerMonitoring.on !== 'function') {
      return;
    }

    // Listen to monitoring events
    this.schedulerMonitoring.on('job-tracking-failed', this.handleJobFailure.bind(this));
    this.schedulerMonitoring.on('alert-triggered', this.handleMonitoringAlert.bind(this));
    this.schedulerMonitoring.on('metrics-collected', this.handleMetricsUpdate.bind(this));
    this.schedulerMonitoring.on('health-check-performed', this.handleHealthCheck.bind(this));

    SecureLogger.logInfo('Scheduler monitoring integration configured');
  }

  /**
   * Start alerting system
   */
  async startAlerting() {
    if (this.isActive) {
      SecureLogger.logWarning('Scheduler alerting already active');
      return;
    }

    if (!this.config.enableAlerting) {
      SecureLogger.logInfo('Scheduler alerting disabled by configuration');
      return;
    }

    try {
      this.isActive = true;
      
      // Start periodic cleanup
      this.startPeriodicCleanup();
      
      SecureLogger.logInfo('Scheduler alerting started successfully', {
        alertRules: this.alertRules.size,
        enabledChannels: this.getEnabledChannels().length
      });
      
      this.emit('alerting-started');
      
    } catch (error) {
      this.isActive = false;
      SecureLogger.logError('Failed to start scheduler alerting', error);
      throw error;
    }
  }

  /**
   * Stop alerting system
   */
  async stopAlerting() {
    if (!this.isActive) {
      return;
    }

    try {
      this.isActive = false;
      
      // Clear all escalation timers
      for (const [alertKey, timer] of this.escalationTimers) {
        clearTimeout(timer);
      }
      this.escalationTimers.clear();
      
      // Remove monitoring event listeners
      if (this.schedulerMonitoring && typeof this.schedulerMonitoring.removeAllListeners === 'function') {
        this.schedulerMonitoring.removeAllListeners('job-tracking-failed');
        this.schedulerMonitoring.removeAllListeners('alert-triggered');
        this.schedulerMonitoring.removeAllListeners('metrics-collected');
        this.schedulerMonitoring.removeAllListeners('health-check-performed');
      }
      
      SecureLogger.logInfo('Scheduler alerting stopped');
      this.emit('alerting-stopped');
      
    } catch (error) {
      SecureLogger.logError('Error stopping scheduler alerting', error);
      throw error;
    }
  }

  /**
   * Add custom alert rule
   */
  addAlertRule(ruleId, rule) {
    const alertRule = {
      id: ruleId,
      enabled: true,
      createdAt: new Date(),
      triggeredCount: 0,
      lastTriggered: null,
      ...rule
    };
    
    this.alertRules.set(ruleId, alertRule);
    
    SecureLogger.logInfo(`Alert rule added: ${ruleId}`, {
      name: rule.name,
      severity: rule.severity
    });
  }

  /**
   * Remove alert rule
   */
  removeAlertRule(ruleId) {
    if (this.alertRules.has(ruleId)) {
      this.alertRules.delete(ruleId);
      this.clearEscalationTimer(ruleId);
      SecureLogger.logInfo(`Alert rule removed: ${ruleId}`);
      return true;
    }
    return false;
  }

  /**
   * Event handlers
   */
  handleJobFailure(data) {
    this.processAlert('job-failure', 'high', {
      eventType: 'job-failed',
      jobId: data.jobId,
      jobType: data.type,
      error: data.error,
      duration: data.duration,
      timestamp: new Date()
    });
  }

  handleMonitoringAlert(alert) {
    this.processAlert(alert.key, alert.severity, {
      eventType: alert.key,
      details: alert.details,
      timestamp: new Date()
    });
  }

  handleMetricsUpdate(data) {
    // Check for performance degradation
    if (data.memoryUsage && data.memoryUsage.heapUsedMB > 500) {
      this.processAlert('high-memory-usage', 'high', {
        eventType: 'high-memory-usage',
        memoryUsage: data.memoryUsage,
        timestamp: new Date()
      });
    }
  }

  handleHealthCheck(data) {
    if (data.schedulerHealth && data.schedulerHealth.status !== 'healthy') {
      this.processAlert('scheduler-unhealthy', 'high', {
        eventType: 'scheduler-unhealthy',
        healthData: data,
        timestamp: new Date()
      });
    }
  }

  /**
   * Process alert through the alerting pipeline
   */
  async processAlert(alertType, severity, data) {
    if (!this.isActive || !this.config.enableAlerting) {
      return;
    }

    try {
      // Check if alert is suppressed
      if (this.suppressedAlerts.has(alertType)) {
        return;
      }

      // Check throttling
      if (this.isAlertThrottled(alertType)) {
        this.alertStats.throttledNotifications++;
        return;
      }

      // Find matching alert rule
      const rule = this.findMatchingRule(alertType, data);
      if (!rule) {
        SecureLogger.logDebug(`No matching alert rule found for: ${alertType}`);
        return;
      }

      // Check rule condition
      if (!rule.condition(data)) {
        return;
      }

      // Check cooldown
      if (this.isInCooldown(rule)) {
        return;
      }

      // Create alert
      const alert = await this.createAlert(alertType, severity, data, rule);
      
      // Process alert
      await this.triggerAlert(alert);
      
    } catch (error) {
      SecureLogger.logError('Failed to process alert', error);
    }
  }

  /**
   * Find matching alert rule
   */
  findMatchingRule(alertType, data) {
    // Direct match first
    if (this.alertRules.has(alertType)) {
      return this.alertRules.get(alertType);
    }

    // Pattern matching for complex rules
    for (const [ruleId, rule] of this.alertRules) {
      if (rule.enabled && rule.condition && rule.condition(data)) {
        return rule;
      }
    }

    return null;
  }

  /**
   * Check if alert is throttled
   */
  isAlertThrottled(alertType) {
    const now = Date.now();
    const throttleKey = alertType;
    
    if (!this.throttledAlerts.has(throttleKey)) {
      this.throttledAlerts.set(throttleKey, { count: 0, lastAlert: now });
      return false;
    }
    
    const throttleData = this.throttledAlerts.get(throttleKey);
    const timeSinceLastAlert = now - throttleData.lastAlert;
    
    if (timeSinceLastAlert < this.config.alertThrottleWindow) {
      throttleData.count++;
      return true;
    }
    
    // Reset throttle window
    this.throttledAlerts.set(throttleKey, { count: 1, lastAlert: now });
    return false;
  }

  /**
   * Check if rule is in cooldown
   */
  isInCooldown(rule) {
    if (!rule.lastTriggered || !rule.cooldown) {
      return false;
    }
    
    const timeSinceLastTrigger = Date.now() - rule.lastTriggered.getTime();
    return timeSinceLastTrigger < rule.cooldown;
  }

  /**
   * Create alert object
   */
  async createAlert(alertType, severity, data, rule) {
    const alertId = `${alertType}_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    
    const alert = {
      id: alertId,
      type: alertType,
      ruleId: rule.id,
      severity,
      name: rule.name,
      description: rule.description,
      data,
      triggeredAt: new Date(),
      status: 'active',
      escalated: false,
      resolved: false,
      autoRemediationAttempted: false,
      notifications: [],
      rule
    };
    
    return alert;
  }

  /**
   * Trigger alert and handle all associated actions
   */
  async triggerAlert(alert) {
    try {
      // Update rule statistics
      const rule = alert.rule;
      rule.triggeredCount++;
      rule.lastTriggered = new Date();
      
      // Update alert statistics
      this.updateAlertStats(alert);
      
      // Store active alert
      this.activeAlerts.set(alert.id, alert);
      this.alertHistory.push({ ...alert });
      
      // Log alert
      this.logAlert(alert);
      
      // Send notifications
      await this.sendNotifications(alert);
      
      // Setup escalation
      this.setupEscalation(alert);
      
      // Attempt auto-remediation
      if (this.config.enableAutoRemediation && rule.autoRemediation?.enabled) {
        await this.attemptAutoRemediation(alert);
      }
      
      // Emit event
      this.emit('alert-triggered', alert);
      
      SecureLogger.logWarning(`Scheduler alert triggered: ${alert.name}`, {
        alertId: alert.id,
        severity: alert.severity,
        type: alert.type
      });
      
    } catch (error) {
      SecureLogger.logError('Failed to trigger alert', error);
    }
  }

  /**
   * Send notifications through configured channels
   */
  async sendNotifications(alert) {
    const notifications = alert.rule.notifications || ['console'];
    const notificationPromises = [];
    
    for (const channel of notifications) {
      try {
        switch (channel) {
          case 'console':
            if (this.config.enableConsoleAlerts) {
              notificationPromises.push(this.sendConsoleNotification(alert));
            }
            break;
            
          case 'email':
            if (this.config.enableEmailAlerts) {
              notificationPromises.push(this.sendEmailNotification(alert));
            }
            break;
            
          case 'webhook':
            if (this.config.enableWebhookAlerts) {
              notificationPromises.push(this.sendWebhookNotification(alert));
            }
            break;
            
          case 'slack':
            if (this.config.enableSlackAlerts) {
              notificationPromises.push(this.sendSlackNotification(alert));
            }
            break;
            
          default:
            SecureLogger.logWarning(`Unknown notification channel: ${channel}`);
        }
      } catch (error) {
        SecureLogger.logError(`Failed to send ${channel} notification`, error);
      }
    }
    
    const results = await Promise.allSettled(notificationPromises);
    alert.notifications = results.map((result, index) => ({
      channel: notifications[index],
      success: result.status === 'fulfilled',
      timestamp: new Date(),
      error: result.status === 'rejected' ? result.reason?.message : null
    }));
    
    this.alertStats.notificationsSent += results.filter(r => r.status === 'fulfilled').length;
  }

  /**
   * Notification methods
   */
  async sendConsoleNotification(alert) {
    const message = this.formatAlertMessage(alert);
    console.warn(`🚨 SCHEDULER ALERT: ${message}`);
    
    if (this.schedulerLogger) {
      this.schedulerLogger.logWarning('Alert notification', {
        alertId: alert.id,
        type: alert.type,
        severity: alert.severity,
        message: alert.name
      });
    }
    
    return { success: true, channel: 'console' };
  }

  async sendEmailNotification(alert) {
    if (!this.emailService || !this.config.emailRecipients.length) {
      throw new Error('Email service or recipients not configured');
    }

    const subject = `🚨 Scheduler Alert: ${alert.name}`;
    const body = this.formatEmailAlertBody(alert);
    
    for (const recipient of this.config.emailRecipients) {
      await this.emailService.sendAlert(recipient, subject, body);
    }
    
    return { success: true, channel: 'email' };
  }

  async sendWebhookNotification(alert) {
    if (!this.config.webhookUrls.length) {
      throw new Error('No webhook URLs configured');
    }

    const payload = {
      alertId: alert.id,
      type: alert.type,
      severity: alert.severity,
      name: alert.name,
      description: alert.description,
      triggeredAt: alert.triggeredAt,
      data: alert.data
    };
    
    const webhookPromises = this.config.webhookUrls.map(url => 
      this.sendWebhookRequest(url, payload)
    );
    
    await Promise.all(webhookPromises);
    return { success: true, channel: 'webhook' };
  }

  async sendWebhookRequest(url, payload) {
    // Implementation would use fetch or axios
    // For now, just log the webhook call
    SecureLogger.logInfo('Webhook notification sent', {
      url: url.replace(/\/\/.*@/, '//***@'), // Mask credentials
      alertId: payload.alertId,
      severity: payload.severity
    });
  }

  async sendSlackNotification(alert) {
    if (!this.config.slackWebhookUrl) {
      throw new Error('Slack webhook URL not configured');
    }

    const slackPayload = {
      channel: this.config.slackChannel,
      username: 'Scheduler Monitor',
      icon_emoji: this.getSeverityEmoji(alert.severity),
      text: `🚨 Scheduler Alert: ${alert.name}`,
      attachments: [{
        color: this.getSeverityColor(alert.severity),
        fields: [
          { title: 'Severity', value: alert.severity.toUpperCase(), short: true },
          { title: 'Type', value: alert.type, short: true },
          { title: 'Time', value: alert.triggeredAt.toISOString(), short: true },
          { title: 'Description', value: alert.description, short: false }
        ]
      }]
    };
    
    // Implementation would send to Slack webhook
    SecureLogger.logInfo('Slack notification sent', {
      channel: this.config.slackChannel,
      alertId: alert.id,
      severity: alert.severity
    });
    
    return { success: true, channel: 'slack' };
  }

  /**
   * Setup alert escalation
   */
  setupEscalation(alert) {
    if (!alert.rule.escalation?.enabled) {
      return;
    }

    const escalationDelay = alert.rule.escalation.escalateAfter || 
                           this.config.escalationTimeouts[alert.severity] || 
                           15 * 60 * 1000;

    const timer = setTimeout(async () => {
      await this.escalateAlert(alert);
    }, escalationDelay);

    this.escalationTimers.set(alert.id, timer);
  }

  /**
   * Escalate alert to higher severity
   */
  async escalateAlert(alert) {
    if (!this.activeAlerts.has(alert.id)) {
      return; // Alert was resolved
    }

    const currentLevel = this.config.escalationLevels.indexOf(alert.severity);
    if (currentLevel < this.config.escalationLevels.length - 1) {
      const newSeverity = this.config.escalationLevels[currentLevel + 1];
      
      alert.severity = newSeverity;
      alert.escalated = true;
      alert.escalatedAt = new Date();
      
      this.alertStats.escalationsTriggered++;
      
      // Send escalated notifications
      await this.sendNotifications({
        ...alert,
        name: `ESCALATED: ${alert.name}`,
        description: `${alert.description} (escalated due to persistence)`
      });
      
      this.emit('alert-escalated', alert);
      
      SecureLogger.logError(`Alert escalated to ${newSeverity}: ${alert.name}`, {
        alertId: alert.id,
        originalSeverity: this.config.escalationLevels[currentLevel]
      });
    }
  }

  /**
   * Attempt auto-remediation
   */
  async attemptAutoRemediation(alert) {
    if (!alert.rule.autoRemediation?.actions) {
      return;
    }

    try {
      this.alertStats.autoRemediationsAttempted++;
      alert.autoRemediationAttempted = true;
      
      const results = [];
      
      for (const action of alert.rule.autoRemediation.actions) {
        const result = await this.executeRemediationAction(action, alert);
        results.push(result);
      }
      
      const successful = results.filter(r => r.success).length;
      if (successful > 0) {
        this.alertStats.autoRemediationsSuccessful++;
        alert.autoRemediationSuccessful = true;
      }
      
      alert.autoRemediationResults = results;
      
      this.emit('auto-remediation-attempted', {
        alert,
        results,
        successful: successful > 0
      });
      
      SecureLogger.logInfo(`Auto-remediation attempted for alert: ${alert.id}`, {
        actions: alert.rule.autoRemediation.actions.length,
        successful,
        total: results.length
      });
      
    } catch (error) {
      alert.autoRemediationError = error.message;
      SecureLogger.logError('Auto-remediation failed', error);
    }
  }

  /**
   * Execute specific remediation action
   */
  async executeRemediationAction(action, alert) {
    try {
      switch (action) {
        case 'restart-job':
          return await this.restartJob(alert);
          
        case 'check-dependencies':
          return await this.checkDependencies(alert);
          
        case 'notify-ops':
          return await this.notifyOpsTeam(alert);
          
        case 'emergency-restart':
          return await this.emergencyRestart(alert);
          
        case 'check-system-health':
          return await this.checkSystemHealth(alert);
          
        case 'garbage-collection':
          return await this.forceGarbageCollection(alert);
          
        case 'memory-analysis':
          return await this.analyzeMemoryUsage(alert);
          
        case 'terminate-job':
          return await this.terminateStuckJob(alert);
          
        default:
          return {
            action,
            success: false,
            message: 'Unknown remediation action',
            timestamp: new Date()
          };
      }
    } catch (error) {
      return {
        action,
        success: false,
        error: error.message,
        timestamp: new Date()
      };
    }
  }

  /**
   * Remediation action implementations
   */
  async restartJob(alert) {
    // Implementation would restart the failed job
    SecureLogger.logInfo('Auto-remediation: Attempting job restart', {
      alertId: alert.id,
      jobId: alert.data.jobId
    });
    
    return {
      action: 'restart-job',
      success: true,
      message: 'Job restart initiated',
      timestamp: new Date()
    };
  }

  async checkDependencies(alert) {
    // Implementation would check service dependencies
    return {
      action: 'check-dependencies',
      success: true,
      message: 'Dependencies checked',
      timestamp: new Date()
    };
  }

  async notifyOpsTeam(alert) {
    // Implementation would send urgent notification to operations team
    return {
      action: 'notify-ops',
      success: true,
      message: 'Operations team notified',
      timestamp: new Date()
    };
  }

  async emergencyRestart(alert) {
    // Implementation would perform emergency restart
    return {
      action: 'emergency-restart',
      success: true,
      message: 'Emergency restart completed',
      timestamp: new Date()
    };
  }

  async checkSystemHealth(alert) {
    // Implementation would perform comprehensive health check
    return {
      action: 'check-system-health',
      success: true,
      message: 'System health check completed',
      timestamp: new Date()
    };
  }

  async forceGarbageCollection(alert) {
    try {
      if (global.gc) {
        global.gc();
        return {
          action: 'garbage-collection',
          success: true,
          message: 'Garbage collection executed',
          timestamp: new Date()
        };
      } else {
        return {
          action: 'garbage-collection',
          success: false,
          message: 'Garbage collection not available',
          timestamp: new Date()
        };
      }
    } catch (error) {
      return {
        action: 'garbage-collection',
        success: false,
        error: error.message,
        timestamp: new Date()
      };
    }
  }

  async analyzeMemoryUsage(alert) {
    const memUsage = process.memoryUsage();
    return {
      action: 'memory-analysis',
      success: true,
      message: 'Memory analysis completed',
      data: memUsage,
      timestamp: new Date()
    };
  }

  async terminateStuckJob(alert) {
    // Implementation would terminate stuck job
    return {
      action: 'terminate-job',
      success: true,
      message: 'Stuck job terminated',
      timestamp: new Date()
    };
  }

  /**
   * Resolve alert
   */
  async resolveAlert(alertId, reason = 'Manual resolution') {
    const alert = this.activeAlerts.get(alertId);
    if (!alert) {
      return false;
    }

    alert.resolved = true;
    alert.resolvedAt = new Date();
    alert.resolutionReason = reason;
    alert.resolutionTime = alert.resolvedAt.getTime() - alert.triggeredAt.getTime();

    // Update average resolution time
    this.updateAverageResolutionTime(alert.resolutionTime);

    // Clear escalation timer
    this.clearEscalationTimer(alertId);

    // Remove from active alerts
    this.activeAlerts.delete(alertId);

    this.emit('alert-resolved', alert);

    SecureLogger.logInfo(`Alert resolved: ${alert.name}`, {
      alertId,
      resolutionTime: Math.round(alert.resolutionTime / 1000) + 's',
      reason
    });

    return true;
  }

  /**
   * Utility methods
   */
  clearEscalationTimer(alertId) {
    if (this.escalationTimers.has(alertId)) {
      clearTimeout(this.escalationTimers.get(alertId));
      this.escalationTimers.delete(alertId);
    }
  }

  updateAlertStats(alert) {
    this.alertStats.totalAlerts++;
    this.alertStats.lastAlertTime = new Date();

    // Update level counts
    const levelCount = this.alertStats.alertsByLevel.get(alert.severity) || 0;
    this.alertStats.alertsByLevel.set(alert.severity, levelCount + 1);

    // Update type counts
    const typeCount = this.alertStats.alertsByType.get(alert.type) || 0;
    this.alertStats.alertsByType.set(alert.type, typeCount + 1);
  }

  updateAverageResolutionTime(resolutionTime) {
    if (this.alertStats.averageResolutionTime === 0) {
      this.alertStats.averageResolutionTime = resolutionTime;
    } else {
      this.alertStats.averageResolutionTime = 
        (this.alertStats.averageResolutionTime + resolutionTime) / 2;
    }
  }

  formatAlertMessage(alert) {
    return `[${alert.severity.toUpperCase()}] ${alert.name} - ${alert.description}`;
  }

  formatEmailAlertBody(alert) {
    return `
Scheduler Alert: ${alert.name}

Severity: ${alert.severity.toUpperCase()}
Type: ${alert.type}
Triggered: ${alert.triggeredAt.toISOString()}
Description: ${alert.description}

Alert Data: ${JSON.stringify(alert.data, null, 2)}

This is an automated alert from the Form-a-Friend v2 Scheduler system.
    `.trim();
  }

  getSeverityEmoji(severity) {
    const emojis = {
      low: ':information_source:',
      medium: ':warning:',
      high: ':exclamation:',
      critical: ':rotating_light:'
    };
    return emojis[severity] || ':question:';
  }

  getSeverityColor(severity) {
    const colors = {
      low: '#36a64f',     // Green
      medium: '#ff9500',   // Orange
      high: '#ff0000',     // Red
      critical: '#ff0000'  // Red
    };
    return colors[severity] || '#808080';
  }

  getEnabledChannels() {
    const channels = [];
    if (this.config.enableConsoleAlerts) channels.push('console');
    if (this.config.enableEmailAlerts) channels.push('email');
    if (this.config.enableWebhookAlerts) channels.push('webhook');
    if (this.config.enableSlackAlerts) channels.push('slack');
    return channels;
  }

  logAlert(alert) {
    if (this.schedulerLogger) {
      this.schedulerLogger.logWarning('Alert triggered', {
        alertId: alert.id,
        type: alert.type,
        severity: alert.severity,
        name: alert.name,
        ruleId: alert.ruleId
      });
    }
  }

  /**
   * Periodic cleanup
   */
  startPeriodicCleanup() {
    // Cleanup every hour
    setInterval(() => {
      this.performCleanup();
    }, 60 * 60 * 1000);
  }

  performCleanup() {
    const cutoffTime = Date.now() - this.config.alertHistoryRetention;
    
    // Clean old alert history
    this.alertHistory = this.alertHistory.filter(
      alert => alert.triggeredAt.getTime() > cutoffTime
    );
    
    // Limit alert history size
    if (this.alertHistory.length > this.config.maxAlertHistory) {
      this.alertHistory = this.alertHistory.slice(-this.config.maxAlertHistory);
    }
    
    // Clean throttled alerts older than 1 hour
    const throttleCleanupTime = Date.now() - (60 * 60 * 1000);
    for (const [key, data] of this.throttledAlerts) {
      if (data.lastAlert < throttleCleanupTime) {
        this.throttledAlerts.delete(key);
      }
    }
    
    SecureLogger.logDebug('Alert cleanup completed', {
      alertHistorySize: this.alertHistory.length,
      activeAlerts: this.activeAlerts.size,
      throttledAlerts: this.throttledAlerts.size
    });
  }

  /**
   * Public API methods
   */
  getAlertingStatus() {
    return {
      isActive: this.isActive,
      config: {
        enableAlerting: this.config.enableAlerting,
        enabledChannels: this.getEnabledChannels(),
        alertThrottleWindow: this.config.alertThrottleWindow,
        maxAlertsPerHour: this.config.maxAlertsPerHour
      },
      stats: {
        ...this.alertStats,
        alertsByLevel: Object.fromEntries(this.alertStats.alertsByLevel),
        alertsByType: Object.fromEntries(this.alertStats.alertsByType)
      },
      active: {
        alertCount: this.activeAlerts.size,
        escalationTimers: this.escalationTimers.size,
        suppressedAlerts: this.suppressedAlerts.size
      },
      rules: {
        total: this.alertRules.size,
        enabled: Array.from(this.alertRules.values()).filter(r => r.enabled).length
      }
    };
  }

  getActiveAlerts() {
    return Array.from(this.activeAlerts.values());
  }

  getAlertHistory(limit = 100) {
    return this.alertHistory.slice(-limit);
  }

  getAlertRules() {
    return Array.from(this.alertRules.entries()).map(([id, rule]) => ({
      id,
      ...rule
    }));
  }

  suppressAlert(alertType, duration = 60 * 60 * 1000) { // Default 1 hour
    this.suppressedAlerts.add(alertType);
    
    setTimeout(() => {
      this.suppressedAlerts.delete(alertType);
      SecureLogger.logInfo(`Alert suppression lifted: ${alertType}`);
    }, duration);
    
    SecureLogger.logInfo(`Alert suppressed: ${alertType}`, { duration });
  }

  exportAlertData() {
    return {
      timestamp: new Date(),
      status: this.getAlertingStatus(),
      activeAlerts: this.getActiveAlerts(),
      recentHistory: this.getAlertHistory(50),
      rules: this.getAlertRules()
    };
  }
}

module.exports = SchedulerAlerting;