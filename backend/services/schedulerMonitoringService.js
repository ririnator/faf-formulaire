const EventEmitter = require('events');
const SecureLogger = require('../utils/secureLogger');

/**
 * Comprehensive Scheduler Monitoring Service
 * 
 * Real-time monitoring system for the Form-a-Friend v2 automation scheduler
 * Tracks job execution, performance metrics, error patterns, and system health
 * 
 * Features:
 * - Real-time job status tracking
 * - Performance metrics collection
 * - Error pattern analysis
 * - Memory and CPU usage monitoring
 * - Alert threshold management
 * - Detailed execution statistics
 * - Historical data retention
 */
class SchedulerMonitoringService extends EventEmitter {
  constructor(config = {}) {
    super();
    
    this.config = {
      // Data retention settings
      metricsRetentionHours: config.metricsRetentionHours || 72, // 3 days
      executionHistoryLimit: config.executionHistoryLimit || 1000,
      errorHistoryLimit: config.errorHistoryLimit || 500,
      
      // Alert thresholds
      alertThresholds: {
        jobFailureRate: config.alertThresholds?.jobFailureRate || 0.05, // 5%
        avgJobDuration: config.alertThresholds?.avgJobDuration || 3600000, // 1 hour
        memoryUsagePercent: config.alertThresholds?.memoryUsagePercent || 0.85, // 85%
        consecutiveFailures: config.alertThresholds?.consecutiveFailures || 3,
        stuckJobDuration: config.alertThresholds?.stuckJobDuration || 7200000, // 2 hours
        errorSpikeRate: config.alertThresholds?.errorSpikeRate || 10 // errors per hour
      },
      
      // Monitoring intervals
      metricsCollectionInterval: config.metricsCollectionInterval || 30000, // 30 seconds
      healthCheckInterval: config.healthCheckInterval || 60000, // 1 minute
      alertCheckInterval: config.alertCheckInterval || 120000, // 2 minutes
      
      // Performance tracking
      trackDetailedMetrics: config.trackDetailedMetrics !== false,
      enableErrorAnalysis: config.enableErrorAnalysis !== false,
      enablePerformanceProfiling: config.enablePerformanceProfiling !== false,
      
      ...config
    };

    // Real-time monitoring state
    this.isMonitoring = false;
    this.monitoringStartTime = null;
    this.schedulerService = null;
    this.realTimeMetrics = null;
    this.performanceAlerting = null;
    
    // Job tracking
    this.activeJobs = new Map();
    this.jobExecutionHistory = [];
    this.jobMetrics = {
      totalExecutions: 0,
      successfulExecutions: 0,
      failedExecutions: 0,
      totalExecutionTime: 0,
      avgExecutionTime: 0,
      lastExecution: null,
      consecutiveFailures: 0,
      longestJob: { duration: 0, jobId: null, type: null },
      fastestJob: { duration: Infinity, jobId: null, type: null }
    };
    
    // Performance metrics
    this.performanceMetrics = {
      memoryUsage: [],
      cpuUsage: [],
      systemHealth: [],
      workerUtilization: [],
      batchProcessingTimes: [],
      lastUpdated: null
    };
    
    // Error tracking and analysis
    this.errorTracking = {
      recentErrors: [],
      errorPatterns: new Map(),
      errorsByType: new Map(),
      errorsByJobType: new Map(),
      recoveryAttempts: new Map(),
      lastErrorSpike: null
    };
    
    // Alert state
    this.activeAlerts = new Map();
    this.alertHistory = [];
    this.suppressedAlerts = new Set();
    
    // Monitoring timers
    this.metricsTimer = null;
    this.healthCheckTimer = null;
    this.alertCheckTimer = null;
    this.cleanupTimer = null;

    SecureLogger.logInfo('SchedulerMonitoringService initialized', {
      metricsRetention: this.config.metricsRetentionHours + 'h',
      alertThresholds: Object.keys(this.config.alertThresholds).length,
      enabledFeatures: {
        detailedMetrics: this.config.trackDetailedMetrics,
        errorAnalysis: this.config.enableErrorAnalysis,
        performanceProfiling: this.config.enablePerformanceProfiling
      }
    });
  }

  /**
   * Initialize monitoring service with dependencies
   */
  async initialize(dependencies = {}) {
    try {
      this.schedulerService = dependencies.schedulerService;
      this.realTimeMetrics = dependencies.realTimeMetrics;
      this.performanceAlerting = dependencies.performanceAlerting;

      if (!this.schedulerService) {
        throw new Error('SchedulerService dependency required for monitoring');
      }

      // Setup scheduler event listeners
      this.setupSchedulerEventListeners();
      
      // Setup integration with existing monitoring services
      if (this.realTimeMetrics) {
        this.setupRealTimeMetricsIntegration();
      }
      
      if (this.performanceAlerting) {
        this.setupPerformanceAlertingIntegration();
      }

      SecureLogger.logInfo('SchedulerMonitoringService initialized successfully', {
        hasSchedulerService: !!this.schedulerService,
        hasRealTimeMetrics: !!this.realTimeMetrics,
        hasPerformanceAlerting: !!this.performanceAlerting
      });
      
      return true;
    } catch (error) {
      SecureLogger.logError('Failed to initialize SchedulerMonitoringService', error);
      throw error;
    }
  }

  /**
   * Start comprehensive monitoring
   */
  async startMonitoring() {
    if (this.isMonitoring) {
      SecureLogger.logWarning('Scheduler monitoring already active');
      return;
    }

    try {
      this.isMonitoring = true;
      this.monitoringStartTime = new Date();
      
      // Start periodic metrics collection
      this.startMetricsCollection();
      
      // Start health monitoring
      this.startHealthMonitoring();
      
      // Start alert checking
      this.startAlertMonitoring();
      
      // Start cleanup tasks
      this.startPeriodicCleanup();
      
      SecureLogger.logInfo('Scheduler monitoring started successfully', {
        metricsInterval: this.config.metricsCollectionInterval + 'ms',
        healthInterval: this.config.healthCheckInterval + 'ms',
        alertInterval: this.config.alertCheckInterval + 'ms'
      });
      
      this.emit('monitoring-started', {
        startTime: this.monitoringStartTime,
        config: this.getMonitoringConfig()
      });
      
    } catch (error) {
      this.isMonitoring = false;
      SecureLogger.logError('Failed to start scheduler monitoring', error);
      throw error;
    }
  }

  /**
   * Stop monitoring and cleanup resources
   */
  async stopMonitoring() {
    if (!this.isMonitoring) {
      return;
    }

    try {
      this.isMonitoring = false;
      
      // Clear all timers
      if (this.metricsTimer) {
        clearInterval(this.metricsTimer);
        this.metricsTimer = null;
      }
      
      if (this.healthCheckTimer) {
        clearInterval(this.healthCheckTimer);
        this.healthCheckTimer = null;
      }
      
      if (this.alertCheckTimer) {
        clearInterval(this.alertCheckTimer);
        this.alertCheckTimer = null;
      }
      
      if (this.cleanupTimer) {
        clearInterval(this.cleanupTimer);
        this.cleanupTimer = null;
      }
      
      // Remove scheduler event listeners
      this.removeSchedulerEventListeners();
      
      const monitoringDuration = Date.now() - this.monitoringStartTime.getTime();
      
      SecureLogger.logInfo('Scheduler monitoring stopped', {
        duration: Math.round(monitoringDuration / 1000) + 's',
        totalJobs: this.jobMetrics.totalExecutions,
        successRate: this.calculateSuccessRate() + '%'
      });
      
      this.emit('monitoring-stopped', {
        stopTime: new Date(),
        duration: monitoringDuration,
        finalMetrics: this.getBasicMetrics()
      });
      
    } catch (error) {
      SecureLogger.logError('Error stopping scheduler monitoring', error);
      throw error;
    }
  }

  /**
   * Setup event listeners for scheduler service
   */
  setupSchedulerEventListeners() {
    if (!this.schedulerService || typeof this.schedulerService.on !== 'function') {
      SecureLogger.logWarning('SchedulerService does not support event listeners');
      return;
    }

    // Job lifecycle events
    this.schedulerService.on('job-started', this.handleJobStarted.bind(this));
    this.schedulerService.on('job-progress', this.handleJobProgress.bind(this));
    this.schedulerService.on('job-completed', this.handleJobCompleted.bind(this));
    this.schedulerService.on('job-failed', this.handleJobFailed.bind(this));
    
    // Specific job type events
    this.schedulerService.on('monthly-job-completed', this.handleMonthlyJobCompleted.bind(this));
    this.schedulerService.on('reminder-job-completed', this.handleReminderJobCompleted.bind(this));
    this.schedulerService.on('cleanup-job-completed', this.handleCleanupJobCompleted.bind(this));
    
    // System events
    this.schedulerService.on('service-started', this.handleSchedulerServiceStarted.bind(this));
    this.schedulerService.on('service-stopped', this.handleSchedulerServiceStopped.bind(this));
    this.schedulerService.on('health-check-completed', this.handleHealthCheckCompleted.bind(this));
    this.schedulerService.on('health-check-failed', this.handleHealthCheckFailed.bind(this));
    
    // Alert events
    this.schedulerService.on('high-memory-usage', this.handleHighMemoryUsage.bind(this));
    this.schedulerService.on('alerts-triggered', this.handleSchedulerAlerts.bind(this));

    SecureLogger.logInfo('Scheduler event listeners configured');
  }

  /**
   * Remove scheduler event listeners
   */
  removeSchedulerEventListeners() {
    if (!this.schedulerService || typeof this.schedulerService.removeAllListeners !== 'function') {
      return;
    }

    this.schedulerService.removeAllListeners('job-started');
    this.schedulerService.removeAllListeners('job-progress');
    this.schedulerService.removeAllListeners('job-completed');
    this.schedulerService.removeAllListeners('job-failed');
    this.schedulerService.removeAllListeners('monthly-job-completed');
    this.schedulerService.removeAllListeners('reminder-job-completed');
    this.schedulerService.removeAllListeners('cleanup-job-completed');
    this.schedulerService.removeAllListeners('service-started');
    this.schedulerService.removeAllListeners('service-stopped');
    this.schedulerService.removeAllListeners('health-check-completed');
    this.schedulerService.removeAllListeners('health-check-failed');
    this.schedulerService.removeAllListeners('high-memory-usage');
    this.schedulerService.removeAllListeners('alerts-triggered');

    SecureLogger.logInfo('Scheduler event listeners removed');
  }

  /**
   * Setup integration with RealTimeMetrics service
   */
  setupRealTimeMetricsIntegration() {
    if (!this.realTimeMetrics || typeof this.realTimeMetrics.on !== 'function') {
      return;
    }

    this.realTimeMetrics.on('metrics-updated', this.handleRealTimeMetricsUpdate.bind(this));
    this.realTimeMetrics.on('alert-triggered', this.handleRealTimeMetricsAlert.bind(this));
    this.realTimeMetrics.on('alert-resolved', this.handleRealTimeMetricsAlertResolved.bind(this));

    SecureLogger.logInfo('RealTimeMetrics integration configured');
  }

  /**
   * Setup integration with PerformanceAlerting service
   */
  setupPerformanceAlertingIntegration() {
    if (!this.performanceAlerting || typeof this.performanceAlerting.on !== 'function') {
      return;
    }

    this.performanceAlerting.on('alert-triggered', this.handlePerformanceAlert.bind(this));
    this.performanceAlerting.on('alert-escalated', this.handlePerformanceAlertEscalated.bind(this));
    this.performanceAlerting.on('auto-remediation-attempted', this.handleAutoRemediationAttempted.bind(this));

    SecureLogger.logInfo('PerformanceAlerting integration configured');
  }

  /**
   * Handle job started event
   */
  handleJobStarted(data) {
    const { jobId, type } = data;
    const jobData = {
      jobId,
      type,
      startTime: new Date(),
      status: 'running',
      progress: 0,
      memoryAtStart: process.memoryUsage(),
      metrics: {
        itemsProcessed: 0,
        errorsEncountered: 0,
        batchesCompleted: 0
      }
    };

    this.activeJobs.set(jobId, jobData);
    
    SecureLogger.logInfo(`Monitoring job started: ${jobId}`, {
      type,
      activeJobs: this.activeJobs.size,
      memoryUsage: Math.round(jobData.memoryAtStart.heapUsed / 1024 / 1024) + 'MB'
    });

    this.emit('job-tracking-started', jobData);
  }

  /**
   * Handle job progress event
   */
  handleJobProgress(data) {
    const { jobId, progress } = data;
    const job = this.activeJobs.get(jobId);
    
    if (job) {
      job.progress = progress;
      job.lastProgressUpdate = new Date();
      
      // Check for stuck jobs
      this.checkForStuckJob(job);
      
      this.emit('job-progress-updated', { jobId, progress, type: job.type });
    }
  }

  /**
   * Handle job completed event
   */
  handleJobCompleted(data) {
    const { jobId, status, stats, duration } = data;
    const job = this.activeJobs.get(jobId);
    
    if (job) {
      job.endTime = new Date();
      job.duration = duration;
      job.status = status;
      job.stats = stats;
      job.memoryAtEnd = process.memoryUsage();
      
      // Update metrics
      this.updateJobMetrics(job, true);
      
      // Move to history
      this.addToExecutionHistory(job);
      this.activeJobs.delete(jobId);
      
      // Reset consecutive failures on success
      if (status === 'success') {
        this.jobMetrics.consecutiveFailures = 0;
      }
      
      SecureLogger.logInfo(`Job completed successfully: ${jobId}`, {
        type: job.type,
        duration: Math.round(duration / 1000) + 's',
        status,
        itemsProcessed: stats?.totalInvitations || stats?.totalSent || 0
      });
      
      this.emit('job-tracking-completed', { ...job, success: true });
    }
  }

  /**
   * Handle job failed event
   */
  handleJobFailed(data) {
    const { jobId, jobType, error, duration } = data;
    const job = this.activeJobs.get(jobId) || {
      jobId,
      type: jobType,
      startTime: new Date(Date.now() - duration),
      status: 'failed'
    };
    
    job.endTime = new Date();
    job.duration = duration;
    job.status = 'failed';
    job.error = error;
    job.memoryAtEnd = process.memoryUsage();
    
    // Update metrics
    this.updateJobMetrics(job, false);
    this.jobMetrics.consecutiveFailures++;
    
    // Track error
    this.trackError(error, job);
    
    // Move to history
    this.addToExecutionHistory(job);
    this.activeJobs.delete(jobId);
    
    SecureLogger.logError(`Job failed: ${jobId}`, {
      type: jobType,
      duration: Math.round(duration / 1000) + 's',
      error,
      consecutiveFailures: this.jobMetrics.consecutiveFailures
    });
    
    this.emit('job-tracking-failed', { ...job, success: false });
    
    // Check for failure alerts
    this.checkFailureAlerts();
  }

  /**
   * Handle specific job type completions
   */
  handleMonthlyJobCompleted(data) {
    const { jobId, stats } = data;
    this.recordJobTypeMetrics('monthly-invitations', stats);
  }

  handleReminderJobCompleted(data) {
    const { jobId, stats } = data;
    this.recordJobTypeMetrics('reminders', stats);
  }

  handleCleanupJobCompleted(data) {
    const { jobId, stats } = data;
    this.recordJobTypeMetrics('cleanup', stats);
  }

  /**
   * Handle scheduler service events
   */
  handleSchedulerServiceStarted(data) {
    SecureLogger.logInfo('Scheduler service started - monitoring active');
    this.emit('scheduler-service-started', data);
  }

  handleSchedulerServiceStopped(data) {
    SecureLogger.logInfo('Scheduler service stopped - monitoring paused');
    this.emit('scheduler-service-stopped', data);
  }

  handleHealthCheckCompleted(data) {
    this.recordHealthCheck(data, true);
  }

  handleHealthCheckFailed(data) {
    this.recordHealthCheck(data, false);
    this.trackError('Health check failed', { type: 'health-check' });
  }

  handleHighMemoryUsage(data) {
    this.triggerAlert('high-memory-usage', 'high', {
      message: 'High memory usage detected in scheduler',
      memoryUsage: data.memUsage,
      usagePercent: data.usagePercent,
      timestamp: new Date()
    });
  }

  handleSchedulerAlerts(data) {
    for (const alert of data.alerts) {
      this.handleSchedulerAlert(alert);
    }
  }

  /**
   * Handle alerts from scheduler
   */
  handleSchedulerAlert(alert) {
    this.triggerAlert(
      `scheduler-${alert.type}`,
      alert.severity,
      {
        message: alert.message,
        details: alert.details,
        value: alert.value,
        threshold: alert.threshold,
        timestamp: new Date()
      }
    );
  }

  /**
   * Handle RealTimeMetrics events
   */
  handleRealTimeMetricsUpdate(data) {
    if (this.config.trackDetailedMetrics) {
      this.recordRealTimeMetrics(data);
    }
  }

  handleRealTimeMetricsAlert(alert) {
    SecureLogger.logWarning('RealTimeMetrics alert received in scheduler monitoring', {
      alertKey: alert.key,
      severity: alert.severity
    });
  }

  handleRealTimeMetricsAlertResolved(alert) {
    SecureLogger.logInfo('RealTimeMetrics alert resolved', {
      alertKey: alert.key
    });
  }

  /**
   * Handle PerformanceAlerting events
   */
  handlePerformanceAlert(alert) {
    SecureLogger.logWarning('Performance alert received in scheduler monitoring', {
      ruleId: alert.ruleId,
      severity: alert.severity,
      ruleName: alert.ruleName
    });
  }

  handlePerformanceAlertEscalated(alert) {
    SecureLogger.logError('Performance alert escalated', {
      ruleId: alert.ruleId,
      severity: alert.severity,
      escalatedAt: alert.escalatedAt
    });
  }

  handleAutoRemediationAttempted(data) {
    SecureLogger.logInfo('Auto-remediation attempted', {
      alertId: data.alert.id,
      success: data.success,
      actionsCount: data.results.length
    });
  }

  /**
   * Start periodic metrics collection
   */
  startMetricsCollection() {
    this.metricsTimer = setInterval(() => {
      this.collectPerformanceMetrics();
    }, this.config.metricsCollectionInterval);
    
    SecureLogger.logInfo('Metrics collection started', {
      interval: this.config.metricsCollectionInterval + 'ms'
    });
  }

  /**
   * Start health monitoring
   */
  startHealthMonitoring() {
    this.healthCheckTimer = setInterval(() => {
      this.performHealthCheck();
    }, this.config.healthCheckInterval);
    
    SecureLogger.logInfo('Health monitoring started', {
      interval: this.config.healthCheckInterval + 'ms'
    });
  }

  /**
   * Start alert monitoring
   */
  startAlertMonitoring() {
    this.alertCheckTimer = setInterval(() => {
      this.checkAlertConditions();
    }, this.config.alertCheckInterval);
    
    SecureLogger.logInfo('Alert monitoring started', {
      interval: this.config.alertCheckInterval + 'ms'
    });
  }

  /**
   * Start periodic cleanup
   */
  startPeriodicCleanup() {
    // Cleanup every hour
    this.cleanupTimer = setInterval(() => {
      this.performCleanup();
    }, 60 * 60 * 1000);
    
    SecureLogger.logInfo('Periodic cleanup started');
  }

  /**
   * Collect performance metrics
   */
  collectPerformanceMetrics() {
    try {
      const now = new Date();
      const memUsage = process.memoryUsage();
      
      // Memory metrics
      this.performanceMetrics.memoryUsage.push({
        timestamp: now,
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        rss: memUsage.rss,
        external: memUsage.external,
        heapUsedMB: Math.round(memUsage.heapUsed / 1024 / 1024),
        heapUtilization: memUsage.heapUsed / memUsage.heapTotal
      });
      
      // Worker utilization if scheduler service available
      if (this.schedulerService && typeof this.schedulerService.getStatus === 'function') {
        const status = this.schedulerService.getStatus();
        this.performanceMetrics.workerUtilization.push({
          timestamp: now,
          activeWorkers: status.activeWorkers || 0,
          activeJobs: status.activeJobs || 0
        });
      }
      
      this.performanceMetrics.lastUpdated = now;
      
      // Emit metrics update
      this.emit('metrics-collected', {
        timestamp: now,
        memoryUsage: memUsage,
        activeJobs: this.activeJobs.size
      });
      
    } catch (error) {
      SecureLogger.logError('Failed to collect performance metrics', error);
    }
  }

  /**
   * Perform health check
   */
  performHealthCheck() {
    try {
      const healthData = {
        timestamp: new Date(),
        schedulerHealth: this.checkSchedulerHealth(),
        monitoringHealth: this.checkMonitoringHealth(),
        systemHealth: this.checkSystemHealth(),
        alertsHealth: this.checkAlertsHealth()
      };
      
      this.performanceMetrics.systemHealth.push(healthData);
      
      // Check for health-based alerts
      this.checkHealthAlerts(healthData);
      
      this.emit('health-check-performed', healthData);
      
    } catch (error) {
      SecureLogger.logError('Health check failed', error);
    }
  }

  /**
   * Check alert conditions
   */
  checkAlertConditions() {
    try {
      // Check job failure rate
      this.checkJobFailureRateAlert();
      
      // Check average job duration
      this.checkAverageJobDurationAlert();
      
      // Check memory usage
      this.checkMemoryUsageAlert();
      
      // Check consecutive failures
      this.checkConsecutiveFailuresAlert();
      
      // Check for stuck jobs
      this.checkStuckJobsAlert();
      
      // Check error spike
      this.checkErrorSpikeAlert();
      
    } catch (error) {
      SecureLogger.logError('Alert condition check failed', error);
    }
  }

  /**
   * Perform periodic cleanup
   */
  performCleanup() {
    try {
      const cutoffTime = Date.now() - (this.config.metricsRetentionHours * 60 * 60 * 1000);
      
      // Clean old performance metrics
      this.performanceMetrics.memoryUsage = this.performanceMetrics.memoryUsage.filter(
        metric => metric.timestamp.getTime() > cutoffTime
      );
      
      this.performanceMetrics.systemHealth = this.performanceMetrics.systemHealth.filter(
        health => health.timestamp.getTime() > cutoffTime
      );
      
      this.performanceMetrics.workerUtilization = this.performanceMetrics.workerUtilization.filter(
        util => util.timestamp.getTime() > cutoffTime
      );
      
      // Clean old execution history
      if (this.jobExecutionHistory.length > this.config.executionHistoryLimit) {
        this.jobExecutionHistory = this.jobExecutionHistory.slice(-this.config.executionHistoryLimit);
      }
      
      // Clean old errors
      this.errorTracking.recentErrors = this.errorTracking.recentErrors.filter(
        error => error.timestamp.getTime() > cutoffTime
      );
      
      if (this.errorTracking.recentErrors.length > this.config.errorHistoryLimit) {
        this.errorTracking.recentErrors = this.errorTracking.recentErrors.slice(-this.config.errorHistoryLimit);
      }
      
      // Clean old alerts
      this.alertHistory = this.alertHistory.filter(
        alert => alert.timestamp.getTime() > cutoffTime
      );
      
      SecureLogger.logInfo('Monitoring data cleanup completed', {
        memoryMetrics: this.performanceMetrics.memoryUsage.length,
        executionHistory: this.jobExecutionHistory.length,
        recentErrors: this.errorTracking.recentErrors.length,
        alertHistory: this.alertHistory.length
      });
      
    } catch (error) {
      SecureLogger.logError('Cleanup failed', error);
    }
  }

  /**
   * Update job metrics
   */
  updateJobMetrics(job, success) {
    this.jobMetrics.totalExecutions++;
    
    if (success) {
      this.jobMetrics.successfulExecutions++;
    } else {
      this.jobMetrics.failedExecutions++;
    }
    
    this.jobMetrics.totalExecutionTime += job.duration || 0;
    this.jobMetrics.avgExecutionTime = this.jobMetrics.totalExecutionTime / this.jobMetrics.totalExecutions;
    this.jobMetrics.lastExecution = job.endTime;
    
    // Track longest and fastest jobs
    if (job.duration) {
      if (job.duration > this.jobMetrics.longestJob.duration) {
        this.jobMetrics.longestJob = {
          duration: job.duration,
          jobId: job.jobId,
          type: job.type
        };
      }
      
      if (job.duration < this.jobMetrics.fastestJob.duration) {
        this.jobMetrics.fastestJob = {
          duration: job.duration,
          jobId: job.jobId,
          type: job.type
        };
      }
    }
  }

  /**
   * Add job to execution history
   */
  addToExecutionHistory(job) {
    const historyEntry = {
      jobId: job.jobId,
      type: job.type,
      startTime: job.startTime,
      endTime: job.endTime,
      duration: job.duration,
      status: job.status,
      progress: job.progress,
      error: job.error,
      stats: job.stats,
      memoryUsage: {
        start: job.memoryAtStart?.heapUsed || 0,
        end: job.memoryAtEnd?.heapUsed || 0,
        peak: Math.max(job.memoryAtStart?.heapUsed || 0, job.memoryAtEnd?.heapUsed || 0)
      }
    };
    
    this.jobExecutionHistory.push(historyEntry);
    
    // Maintain history limit
    if (this.jobExecutionHistory.length > this.config.executionHistoryLimit) {
      this.jobExecutionHistory = this.jobExecutionHistory.slice(-this.config.executionHistoryLimit);
    }
  }

  /**
   * Track error for analysis
   */
  trackError(error, job) {
    if (!this.config.enableErrorAnalysis) {
      return;
    }

    const errorEntry = {
      timestamp: new Date(),
      error: typeof error === 'string' ? error : error.message || 'Unknown error',
      jobId: job.jobId,
      jobType: job.type,
      stackTrace: error.stack,
      context: {
        duration: job.duration,
        progress: job.progress,
        memoryUsage: job.memoryAtEnd?.heapUsed || 0
      }
    };
    
    this.errorTracking.recentErrors.push(errorEntry);
    
    // Update error patterns
    const errorKey = this.extractErrorPattern(error);
    const patternCount = this.errorTracking.errorPatterns.get(errorKey) || 0;
    this.errorTracking.errorPatterns.set(errorKey, patternCount + 1);
    
    // Update errors by type
    const typeCount = this.errorTracking.errorsByType.get(errorKey) || 0;
    this.errorTracking.errorsByType.set(errorKey, typeCount + 1);
    
    // Update errors by job type
    const jobTypeCount = this.errorTracking.errorsByJobType.get(job.type) || 0;
    this.errorTracking.errorsByJobType.set(job.type, jobTypeCount + 1);
  }

  /**
   * Extract error pattern for classification
   */
  extractErrorPattern(error) {
    const message = typeof error === 'string' ? error : error.message || 'Unknown error';
    
    // Common error patterns
    if (message.includes('timeout')) return 'timeout';
    if (message.includes('connection')) return 'connection';
    if (message.includes('memory')) return 'memory';
    if (message.includes('worker')) return 'worker';
    if (message.includes('database')) return 'database';
    if (message.includes('email')) return 'email';
    if (message.includes('validation')) return 'validation';
    
    // Generic classification
    if (message.length < 50) return message.toLowerCase();
    return 'generic-error';
  }

  /**
   * Record job type specific metrics
   */
  recordJobTypeMetrics(jobType, stats) {
    // Implementation for job-type specific metrics tracking
    this.emit('job-type-metrics-recorded', { jobType, stats, timestamp: new Date() });
  }

  /**
   * Record health check results
   */
  recordHealthCheck(data, success) {
    const healthEntry = {
      timestamp: new Date(),
      success,
      data,
      systemHealth: success ? 'healthy' : 'unhealthy'
    };
    
    this.performanceMetrics.systemHealth.push(healthEntry);
  }

  /**
   * Record real-time metrics data
   */
  recordRealTimeMetrics(data) {
    // Integration with RealTimeMetrics service
    this.emit('realtime-metrics-integrated', { data, timestamp: new Date() });
  }

  /**
   * Check various health aspects
   */
  checkSchedulerHealth() {
    if (!this.schedulerService || typeof this.schedulerService.getStatus !== 'function') {
      return { status: 'unknown', reason: 'Scheduler service not available' };
    }
    
    const status = this.schedulerService.getStatus();
    return {
      status: status.isRunning ? 'healthy' : 'unhealthy',
      isRunning: status.isRunning,
      activeJobs: status.activeJobs,
      activeWorkers: status.activeWorkers,
      cronJobs: status.cronJobs?.length || 0
    };
  }

  checkMonitoringHealth() {
    return {
      status: this.isMonitoring ? 'healthy' : 'unhealthy',
      isMonitoring: this.isMonitoring,
      activeJobsTracked: this.activeJobs.size,
      metricsCollected: this.performanceMetrics.memoryUsage.length,
      errorsTracked: this.errorTracking.recentErrors.length,
      alertsActive: this.activeAlerts.size
    };
  }

  checkSystemHealth() {
    const memUsage = process.memoryUsage();
    const uptime = process.uptime();
    
    return {
      status: 'healthy',
      uptime: Math.round(uptime),
      memoryUsageMB: Math.round(memUsage.heapUsed / 1024 / 1024),
      memoryUtilization: memUsage.heapUsed / memUsage.heapTotal,
      nodeVersion: process.version,
      platform: process.platform
    };
  }

  checkAlertsHealth() {
    return {
      status: 'healthy',
      activeAlerts: this.activeAlerts.size,
      suppressedAlerts: this.suppressedAlerts.size,
      totalAlertHistory: this.alertHistory.length
    };
  }

  /**
   * Alert checking methods
   */
  checkJobFailureRateAlert() {
    const successRate = this.calculateSuccessRate() / 100;
    const failureRate = 1 - successRate;
    
    if (failureRate > this.config.alertThresholds.jobFailureRate && this.jobMetrics.totalExecutions >= 5) {
      this.triggerAlert('job-failure-rate', 'high', {
        message: `Job failure rate ${(failureRate * 100).toFixed(1)}% exceeds threshold ${(this.config.alertThresholds.jobFailureRate * 100).toFixed(1)}%`,
        failureRate,
        threshold: this.config.alertThresholds.jobFailureRate,
        totalJobs: this.jobMetrics.totalExecutions,
        failedJobs: this.jobMetrics.failedExecutions
      });
    } else {
      this.resolveAlert('job-failure-rate');
    }
  }

  checkAverageJobDurationAlert() {
    if (this.jobMetrics.avgExecutionTime > this.config.alertThresholds.avgJobDuration) {
      this.triggerAlert('avg-job-duration', 'medium', {
        message: `Average job duration ${Math.round(this.jobMetrics.avgExecutionTime / 1000)}s exceeds threshold ${Math.round(this.config.alertThresholds.avgJobDuration / 1000)}s`,
        avgDuration: this.jobMetrics.avgExecutionTime,
        threshold: this.config.alertThresholds.avgJobDuration,
        totalJobs: this.jobMetrics.totalExecutions
      });
    } else {
      this.resolveAlert('avg-job-duration');
    }
  }

  checkMemoryUsageAlert() {
    const memUsage = process.memoryUsage();
    const usagePercent = memUsage.heapUsed / memUsage.heapTotal;
    
    if (usagePercent > this.config.alertThresholds.memoryUsagePercent) {
      this.triggerAlert('memory-usage', 'high', {
        message: `Memory usage ${(usagePercent * 100).toFixed(1)}% exceeds threshold ${(this.config.alertThresholds.memoryUsagePercent * 100).toFixed(1)}%`,
        usagePercent,
        threshold: this.config.alertThresholds.memoryUsagePercent,
        heapUsedMB: Math.round(memUsage.heapUsed / 1024 / 1024),
        heapTotalMB: Math.round(memUsage.heapTotal / 1024 / 1024)
      });
    } else {
      this.resolveAlert('memory-usage');
    }
  }

  checkConsecutiveFailuresAlert() {
    if (this.jobMetrics.consecutiveFailures >= this.config.alertThresholds.consecutiveFailures) {
      this.triggerAlert('consecutive-failures', 'critical', {
        message: `${this.jobMetrics.consecutiveFailures} consecutive job failures detected`,
        consecutiveFailures: this.jobMetrics.consecutiveFailures,
        threshold: this.config.alertThresholds.consecutiveFailures,
        lastFailure: this.jobMetrics.lastExecution
      });
    } else {
      this.resolveAlert('consecutive-failures');
    }
  }

  checkStuckJobsAlert() {
    const now = Date.now();
    const stuckJobs = [];
    
    for (const [jobId, job] of this.activeJobs) {
      const runtime = now - job.startTime.getTime();
      if (runtime > this.config.alertThresholds.stuckJobDuration) {
        stuckJobs.push({ jobId, type: job.type, runtime, progress: job.progress });
      }
    }
    
    if (stuckJobs.length > 0) {
      this.triggerAlert('stuck-jobs', 'critical', {
        message: `${stuckJobs.length} stuck jobs detected`,
        stuckJobs,
        threshold: this.config.alertThresholds.stuckJobDuration
      });
    } else {
      this.resolveAlert('stuck-jobs');
    }
  }

  checkErrorSpikeAlert() {
    const hourAgo = Date.now() - (60 * 60 * 1000);
    const recentErrors = this.errorTracking.recentErrors.filter(
      error => error.timestamp.getTime() > hourAgo
    );
    
    if (recentErrors.length > this.config.alertThresholds.errorSpikeRate) {
      this.triggerAlert('error-spike', 'high', {
        message: `Error spike detected: ${recentErrors.length} errors in the last hour`,
        errorCount: recentErrors.length,
        threshold: this.config.alertThresholds.errorSpikeRate,
        timeframe: '1 hour'
      });
      
      this.errorTracking.lastErrorSpike = new Date();
    } else {
      this.resolveAlert('error-spike');
    }
  }

  checkForStuckJob(job) {
    const now = Date.now();
    const runtime = now - job.startTime.getTime();
    
    if (runtime > this.config.alertThresholds.stuckJobDuration) {
      this.triggerAlert(`stuck-job-${job.jobId}`, 'critical', {
        message: `Job ${job.jobId} appears to be stuck`,
        jobId: job.jobId,
        type: job.type,
        runtime,
        progress: job.progress,
        threshold: this.config.alertThresholds.stuckJobDuration
      });
    }
  }

  checkFailureAlerts() {
    // This is called after a job failure to check immediate alert conditions
    this.checkConsecutiveFailuresAlert();
    this.checkJobFailureRateAlert();
  }

  checkHealthAlerts(healthData) {
    // Check if any health aspect is unhealthy
    const unhealthyAspects = [];
    
    if (healthData.schedulerHealth.status !== 'healthy') {
      unhealthyAspects.push('scheduler');
    }
    
    if (healthData.monitoringHealth.status !== 'healthy') {
      unhealthyAspects.push('monitoring');
    }
    
    if (unhealthyAspects.length > 0) {
      this.triggerAlert('system-health', 'high', {
        message: `System health issues detected: ${unhealthyAspects.join(', ')}`,
        unhealthyAspects,
        healthData
      });
    } else {
      this.resolveAlert('system-health');
    }
  }

  /**
   * Alert management
   */
  triggerAlert(alertKey, severity, details) {
    if (this.suppressedAlerts.has(alertKey)) {
      return;
    }

    const now = new Date();
    
    if (this.activeAlerts.has(alertKey)) {
      // Update existing alert
      const alert = this.activeAlerts.get(alertKey);
      alert.count++;
      alert.lastTriggered = now;
      alert.details = details;
    } else {
      // Create new alert
      const alert = {
        key: alertKey,
        severity,
        details,
        firstTriggered: now,
        lastTriggered: now,
        count: 1,
        resolved: false
      };
      
      this.activeAlerts.set(alertKey, alert);
      this.alertHistory.push({ ...alert, timestamp: now });
      
      SecureLogger.logWarning(`Scheduler monitoring alert triggered: ${alertKey}`, {
        severity,
        message: details.message
      });
      
      this.emit('alert-triggered', alert);
    }
  }

  resolveAlert(alertKey) {
    if (this.activeAlerts.has(alertKey)) {
      const alert = this.activeAlerts.get(alertKey);
      alert.resolved = true;
      alert.resolvedAt = new Date();
      
      this.activeAlerts.delete(alertKey);
      
      SecureLogger.logInfo(`Scheduler monitoring alert resolved: ${alertKey}`);
      this.emit('alert-resolved', alert);
    }
  }

  /**
   * Utility methods
   */
  calculateSuccessRate() {
    if (this.jobMetrics.totalExecutions === 0) return 100;
    return Math.round((this.jobMetrics.successfulExecutions / this.jobMetrics.totalExecutions) * 100);
  }

  getMonitoringConfig() {
    return {
      alertThresholds: this.config.alertThresholds,
      retentionSettings: {
        metricsRetentionHours: this.config.metricsRetentionHours,
        executionHistoryLimit: this.config.executionHistoryLimit,
        errorHistoryLimit: this.config.errorHistoryLimit
      },
      intervals: {
        metricsCollection: this.config.metricsCollectionInterval,
        healthCheck: this.config.healthCheckInterval,
        alertCheck: this.config.alertCheckInterval
      },
      features: {
        trackDetailedMetrics: this.config.trackDetailedMetrics,
        enableErrorAnalysis: this.config.enableErrorAnalysis,
        enablePerformanceProfiling: this.config.enablePerformanceProfiling
      }
    };
  }

  /**
   * Public API methods
   */

  /**
   * Get current monitoring status
   */
  getMonitoringStatus() {
    return {
      isMonitoring: this.isMonitoring,
      startTime: this.monitoringStartTime,
      uptime: this.monitoringStartTime ? Date.now() - this.monitoringStartTime.getTime() : 0,
      activeJobs: this.activeJobs.size,
      totalJobsTracked: this.jobMetrics.totalExecutions,
      activeAlerts: this.activeAlerts.size,
      metricsCollected: this.performanceMetrics.memoryUsage.length,
      errorsTracked: this.errorTracking.recentErrors.length,
      config: this.getMonitoringConfig()
    };
  }

  /**
   * Get basic metrics
   */
  getBasicMetrics() {
    return {
      jobs: {
        total: this.jobMetrics.totalExecutions,
        successful: this.jobMetrics.successfulExecutions,
        failed: this.jobMetrics.failedExecutions,
        successRate: this.calculateSuccessRate(),
        consecutiveFailures: this.jobMetrics.consecutiveFailures,
        avgDuration: Math.round(this.jobMetrics.avgExecutionTime),
        lastExecution: this.jobMetrics.lastExecution
      },
      performance: {
        longestJob: this.jobMetrics.longestJob,
        fastestJob: this.jobMetrics.fastestJob.duration === Infinity ? null : this.jobMetrics.fastestJob,
        currentMemoryMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        activeJobs: this.activeJobs.size
      },
      errors: {
        recentCount: this.errorTracking.recentErrors.length,
        patterns: this.errorTracking.errorPatterns.size,
        lastErrorSpike: this.errorTracking.lastErrorSpike
      },
      alerts: {
        active: this.activeAlerts.size,
        total: this.alertHistory.length,
        suppressed: this.suppressedAlerts.size
      }
    };
  }

  /**
   * Get detailed metrics with full data
   */
  getDetailedMetrics() {
    return {
      ...this.getBasicMetrics(),
      activeJobs: Array.from(this.activeJobs.values()),
      recentExecutions: this.jobExecutionHistory.slice(-10),
      performanceMetrics: {
        memoryUsage: this.performanceMetrics.memoryUsage.slice(-20),
        workerUtilization: this.performanceMetrics.workerUtilization.slice(-20),
        systemHealth: this.performanceMetrics.systemHealth.slice(-10),
        lastUpdated: this.performanceMetrics.lastUpdated
      },
      errorAnalysis: {
        recentErrors: this.errorTracking.recentErrors.slice(-10),
        errorPatterns: Array.from(this.errorTracking.errorPatterns.entries()),
        errorsByType: Array.from(this.errorTracking.errorsByType.entries()),
        errorsByJobType: Array.from(this.errorTracking.errorsByJobType.entries())
      },
      activeAlerts: Array.from(this.activeAlerts.values()),
      recentAlerts: this.alertHistory.slice(-10)
    };
  }

  /**
   * Get execution history with filtering
   */
  getExecutionHistory(filters = {}) {
    let history = [...this.jobExecutionHistory];
    
    if (filters.type) {
      history = history.filter(job => job.type === filters.type);
    }
    
    if (filters.status) {
      history = history.filter(job => job.status === filters.status);
    }
    
    if (filters.since) {
      const sinceDate = new Date(filters.since);
      history = history.filter(job => job.startTime >= sinceDate);
    }
    
    if (filters.limit) {
      history = history.slice(-filters.limit);
    }
    
    return history;
  }

  /**
   * Get error analysis
   */
  getErrorAnalysis(timeframe = 24 * 60 * 60 * 1000) { // Default 24 hours
    const cutoff = Date.now() - timeframe;
    const recentErrors = this.errorTracking.recentErrors.filter(
      error => error.timestamp.getTime() > cutoff
    );
    
    const analysis = {
      timeframe,
      totalErrors: recentErrors.length,
      errorRate: this.jobMetrics.totalExecutions > 0 ? 
        (recentErrors.length / this.jobMetrics.totalExecutions) * 100 : 0,
      patterns: {},
      jobTypes: {},
      timeline: []
    };
    
    // Analyze patterns
    for (const error of recentErrors) {
      const pattern = this.extractErrorPattern(error.error);
      analysis.patterns[pattern] = (analysis.patterns[pattern] || 0) + 1;
      analysis.jobTypes[error.jobType] = (analysis.jobTypes[error.jobType] || 0) + 1;
    }
    
    // Create timeline (hourly buckets)
    const hours = Math.ceil(timeframe / (60 * 60 * 1000));
    for (let i = 0; i < hours; i++) {
      const hourStart = cutoff + (i * 60 * 60 * 1000);
      const hourEnd = hourStart + (60 * 60 * 1000);
      const hourErrors = recentErrors.filter(
        error => error.timestamp.getTime() >= hourStart && error.timestamp.getTime() < hourEnd
      );
      
      analysis.timeline.push({
        hour: new Date(hourStart).toISOString(),
        errorCount: hourErrors.length
      });
    }
    
    return analysis;
  }

  /**
   * Suppress alerts for a specific key
   */
  suppressAlert(alertKey, duration = 60 * 60 * 1000) { // Default 1 hour
    this.suppressedAlerts.add(alertKey);
    
    setTimeout(() => {
      this.suppressedAlerts.delete(alertKey);
      SecureLogger.logInfo(`Alert suppression lifted: ${alertKey}`);
    }, duration);
    
    SecureLogger.logInfo(`Alert suppressed: ${alertKey}`, { duration });
  }

  /**
   * Export monitoring data
   */
  exportMonitoringData() {
    return {
      timestamp: new Date(),
      status: this.getMonitoringStatus(),
      metrics: this.getDetailedMetrics(),
      config: this.getMonitoringConfig(),
      errorAnalysis: this.getErrorAnalysis()
    };
  }

  /**
   * Reset monitoring data (for testing)
   */
  resetMonitoringData() {
    this.jobMetrics = {
      totalExecutions: 0,
      successfulExecutions: 0,
      failedExecutions: 0,
      totalExecutionTime: 0,
      avgExecutionTime: 0,
      lastExecution: null,
      consecutiveFailures: 0,
      longestJob: { duration: 0, jobId: null, type: null },
      fastestJob: { duration: Infinity, jobId: null, type: null }
    };
    
    this.performanceMetrics = {
      memoryUsage: [],
      cpuUsage: [],
      systemHealth: [],
      workerUtilization: [],
      batchProcessingTimes: [],
      lastUpdated: null
    };
    
    this.errorTracking = {
      recentErrors: [],
      errorPatterns: new Map(),
      errorsByType: new Map(),
      errorsByJobType: new Map(),
      recoveryAttempts: new Map(),
      lastErrorSpike: null
    };
    
    this.activeAlerts.clear();
    this.alertHistory = [];
    this.jobExecutionHistory = [];
    
    SecureLogger.logInfo('Monitoring data reset');
    this.emit('monitoring-data-reset');
  }
}

module.exports = SchedulerMonitoringService;