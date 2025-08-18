const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');
const SecureLogger = require('../utils/secureLogger');

/**
 * Structured Logging System for Scheduler Operations
 * 
 * Advanced logging system specifically designed for Form-a-Friend v2 scheduler
 * Provides structured, searchable logs with rotation, retention, and security
 * 
 * Features:
 * - Structured JSON logging
 * - Log rotation and retention policies
 * - Context-aware logging with correlation IDs
 * - Performance metrics integration
 * - Security-compliant sanitization
 * - Multiple log levels and targets
 * - Real-time log streaming capability
 */
class SchedulerLogger {
  constructor(config = {}) {
    this.config = {
      // Log directories
      logDir: config.logDir || path.join(process.cwd(), 'logs', 'scheduler'),
      
      // Log levels
      logLevel: config.logLevel || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
      
      // File rotation settings
      maxSize: config.maxSize || '100m',
      maxFiles: config.maxFiles || '30d',
      datePattern: config.datePattern || 'YYYY-MM-DD',
      
      // Log formats
      enableConsoleOutput: config.enableConsoleOutput !== false,
      enableFileOutput: config.enableFileOutput !== false,
      enableJsonFormat: config.enableJsonFormat !== false,
      
      // Security settings
      enableSensitiveDataFiltering: config.enableSensitiveDataFiltering !== false,
      maxLogEntrySize: config.maxLogEntrySize || 10000, // 10KB limit per log entry
      
      // Performance settings
      enableAsyncLogging: config.enableAsyncLogging !== false,
      bufferSize: config.bufferSize || 1000,
      flushInterval: config.flushInterval || 1000, // 1 second
      
      ...config
    };

    this.loggers = new Map();
    this.contextStack = [];
    this.correlationId = null;
    this.isInitialized = false;
    
    // Log statistics
    this.stats = {
      totalLogs: 0,
      logsByLevel: new Map(),
      logsByCategory: new Map(),
      errorCount: 0,
      warningCount: 0,
      lastLogTime: null,
      avgLogSize: 0,
      totalLogSize: 0
    };
    
    // Initialize loggers
    this.initializeLoggers();
  }

  /**
   * Initialize winston loggers for different log categories
   */
  initializeLoggers() {
    try {
      // Ensure log directory exists
      this.ensureLogDirectory();
      
      // Create loggers for different categories
      this.createJobLogger();
      this.createPerformanceLogger();
      this.createErrorLogger();
      this.createAuditLogger();
      this.createMetricsLogger();
      
      this.isInitialized = true;
      
      SecureLogger.logInfo('SchedulerLogger initialized successfully', {
        logDir: this.config.logDir,
        logLevel: this.config.logLevel,
        loggersCreated: this.loggers.size
      });
      
    } catch (error) {
      SecureLogger.logError('Failed to initialize SchedulerLogger', error);
      throw error;
    }
  }

  /**
   * Ensure log directory exists
   */
  ensureLogDirectory() {
    try {
      if (!fs.existsSync(this.config.logDir)) {
        fs.mkdirSync(this.config.logDir, { recursive: true });
      }
    } catch (error) {
      throw new Error(`Failed to create log directory: ${error.message}`);
    }
  }

  /**
   * Create job execution logger
   */
  createJobLogger() {
    const transports = [];
    
    // File transport for job logs
    if (this.config.enableFileOutput) {
      transports.push(new DailyRotateFile({
        filename: path.join(this.config.logDir, 'jobs-%DATE%.log'),
        datePattern: this.config.datePattern,
        maxSize: this.config.maxSize,
        maxFiles: this.config.maxFiles,
        format: this.createJobLogFormat(),
        level: this.config.logLevel,
        handleExceptions: false,
        handleRejections: false
      }));
    }
    
    // Console transport for development
    if (this.config.enableConsoleOutput && process.env.NODE_ENV !== 'production') {
      transports.push(new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        )
      }));
    }
    
    const jobLogger = winston.createLogger({
      level: this.config.logLevel,
      transports,
      exitOnError: false,
      silent: false
    });
    
    this.loggers.set('jobs', jobLogger);
  }

  /**
   * Create performance metrics logger
   */
  createPerformanceLogger() {
    const transports = [];
    
    if (this.config.enableFileOutput) {
      transports.push(new DailyRotateFile({
        filename: path.join(this.config.logDir, 'performance-%DATE%.log'),
        datePattern: this.config.datePattern,
        maxSize: this.config.maxSize,
        maxFiles: this.config.maxFiles,
        format: this.createPerformanceLogFormat(),
        level: 'info'
      }));
    }
    
    const performanceLogger = winston.createLogger({
      level: 'info',
      transports,
      exitOnError: false
    });
    
    this.loggers.set('performance', performanceLogger);
  }

  /**
   * Create error logger
   */
  createErrorLogger() {
    const transports = [];
    
    if (this.config.enableFileOutput) {
      transports.push(new DailyRotateFile({
        filename: path.join(this.config.logDir, 'errors-%DATE%.log'),
        datePattern: this.config.datePattern,
        maxSize: this.config.maxSize,
        maxFiles: this.config.maxFiles,
        format: this.createErrorLogFormat(),
        level: 'error'
      }));
    }
    
    const errorLogger = winston.createLogger({
      level: 'error',
      transports,
      exitOnError: false
    });
    
    this.loggers.set('errors', errorLogger);
  }

  /**
   * Create audit logger
   */
  createAuditLogger() {
    const transports = [];
    
    if (this.config.enableFileOutput) {
      transports.push(new DailyRotateFile({
        filename: path.join(this.config.logDir, 'audit-%DATE%.log'),
        datePattern: this.config.datePattern,
        maxSize: this.config.maxSize,
        maxFiles: '90d', // Longer retention for audit logs
        format: this.createAuditLogFormat(),
        level: 'info'
      }));
    }
    
    const auditLogger = winston.createLogger({
      level: 'info',
      transports,
      exitOnError: false
    });
    
    this.loggers.set('audit', auditLogger);
  }

  /**
   * Create metrics logger
   */
  createMetricsLogger() {
    const transports = [];
    
    if (this.config.enableFileOutput) {
      transports.push(new DailyRotateFile({
        filename: path.join(this.config.logDir, 'metrics-%DATE%.log'),
        datePattern: this.config.datePattern,
        maxSize: this.config.maxSize,
        maxFiles: this.config.maxFiles,
        format: this.createMetricsLogFormat(),
        level: 'info'
      }));
    }
    
    const metricsLogger = winston.createLogger({
      level: 'info',
      transports,
      exitOnError: false
    });
    
    this.loggers.set('metrics', metricsLogger);
  }

  /**
   * Create log formats
   */
  createJobLogFormat() {
    return winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
      winston.format.errors({ stack: true }),
      winston.format.json(),
      winston.format.printf(info => {
        const logEntry = {
          timestamp: info.timestamp,
          level: info.level,
          category: 'job',
          message: info.message,
          correlationId: this.correlationId,
          context: this.getCurrentContext(),
          ...info
        };
        
        // Remove sensitive data and limit size
        return JSON.stringify(this.sanitizeLogEntry(logEntry));
      })
    );
  }

  createPerformanceLogFormat() {
    return winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
      winston.format.json(),
      winston.format.printf(info => {
        const logEntry = {
          timestamp: info.timestamp,
          level: info.level,
          category: 'performance',
          message: info.message,
          correlationId: this.correlationId,
          ...info
        };
        
        return JSON.stringify(this.sanitizeLogEntry(logEntry));
      })
    );
  }

  createErrorLogFormat() {
    return winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
      winston.format.errors({ stack: true }),
      winston.format.json(),
      winston.format.printf(info => {
        const logEntry = {
          timestamp: info.timestamp,
          level: info.level,
          category: 'error',
          message: info.message,
          correlationId: this.correlationId,
          context: this.getCurrentContext(),
          stack: info.stack,
          ...info
        };
        
        return JSON.stringify(this.sanitizeLogEntry(logEntry));
      })
    );
  }

  createAuditLogFormat() {
    return winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
      winston.format.json(),
      winston.format.printf(info => {
        const logEntry = {
          timestamp: info.timestamp,
          level: info.level,
          category: 'audit',
          message: info.message,
          correlationId: this.correlationId,
          userId: info.userId || 'system',
          action: info.action,
          resource: info.resource,
          ...info
        };
        
        return JSON.stringify(this.sanitizeLogEntry(logEntry));
      })
    );
  }

  createMetricsLogFormat() {
    return winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
      winston.format.json(),
      winston.format.printf(info => {
        const logEntry = {
          timestamp: info.timestamp,
          level: info.level,
          category: 'metrics',
          message: info.message,
          correlationId: this.correlationId,
          metricType: info.metricType,
          value: info.value,
          unit: info.unit,
          ...info
        };
        
        return JSON.stringify(this.sanitizeLogEntry(logEntry));
      })
    );
  }

  /**
   * Sanitize log entry for security and size limits
   */
  sanitizeLogEntry(logEntry) {
    if (!this.config.enableSensitiveDataFiltering) {
      return logEntry;
    }

    // Use existing SecureLogger sanitization
    const sanitized = SecureLogger.sanitizeForLogging(logEntry);
    
    // Limit log entry size
    const logString = JSON.stringify(sanitized);
    if (logString.length > this.config.maxLogEntrySize) {
      sanitized._truncated = true;
      sanitized._originalSize = logString.length;
      
      // Truncate large fields
      if (sanitized.stack && sanitized.stack.length > 2000) {
        sanitized.stack = sanitized.stack.substring(0, 2000) + '...[truncated]';
      }
      
      if (sanitized.data && JSON.stringify(sanitized.data).length > 1000) {
        sanitized.data = '[large object truncated]';
      }
    }
    
    return sanitized;
  }

  /**
   * Context management
   */
  pushContext(context) {
    this.contextStack.push({
      ...context,
      timestamp: new Date().toISOString()
    });
  }

  popContext() {
    return this.contextStack.pop();
  }

  getCurrentContext() {
    return this.contextStack.length > 0 ? this.contextStack[this.contextStack.length - 1] : null;
  }

  setCorrelationId(correlationId) {
    this.correlationId = correlationId;
  }

  generateCorrelationId() {
    this.correlationId = `sched_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    return this.correlationId;
  }

  /**
   * Job lifecycle logging methods
   */
  logJobStarted(jobId, jobType, context = {}) {
    this.pushContext({ jobId, jobType, phase: 'start' });
    
    const logger = this.loggers.get('jobs');
    if (logger) {
      logger.info('Job started', {
        jobId,
        jobType,
        startTime: new Date().toISOString(),
        memoryUsage: process.memoryUsage(),
        ...context
      });
    }
    
    this.updateStats('info', 'job-start');
    
    // Also log to audit logger
    this.logAudit('job_started', 'system', { jobId, jobType });
  }

  logJobProgress(jobId, progress, context = {}) {
    const logger = this.loggers.get('jobs');
    if (logger) {
      logger.info('Job progress update', {
        jobId,
        progress,
        timestamp: new Date().toISOString(),
        ...context
      });
    }
    
    this.updateStats('info', 'job-progress');
  }

  logJobCompleted(jobId, jobType, duration, stats = {}, context = {}) {
    const logger = this.loggers.get('jobs');
    if (logger) {
      logger.info('Job completed successfully', {
        jobId,
        jobType,
        duration,
        endTime: new Date().toISOString(),
        stats,
        memoryUsage: process.memoryUsage(),
        ...context
      });
    }
    
    this.updateStats('info', 'job-complete');
    this.popContext();
    
    // Log performance metrics
    this.logPerformance('job_duration', duration, 'ms', { jobId, jobType });
    
    // Audit log
    this.logAudit('job_completed', 'system', { jobId, jobType, duration });
  }

  logJobFailed(jobId, jobType, error, duration, context = {}) {
    const logger = this.loggers.get('jobs');
    const errorLogger = this.loggers.get('errors');
    
    const errorInfo = {
      jobId,
      jobType,
      error: error.message || error,
      stack: error.stack,
      duration,
      endTime: new Date().toISOString(),
      memoryUsage: process.memoryUsage(),
      ...context
    };
    
    if (logger) {
      logger.error('Job failed', errorInfo);
    }
    
    if (errorLogger) {
      errorLogger.error('Job execution error', errorInfo);
    }
    
    this.updateStats('error', 'job-error');
    this.popContext();
    
    // Audit log
    this.logAudit('job_failed', 'system', { jobId, jobType, error: error.message || error });
  }

  logJobRetry(jobId, jobType, attempt, error, context = {}) {
    const logger = this.loggers.get('jobs');
    if (logger) {
      logger.warn('Job retry attempt', {
        jobId,
        jobType,
        attempt,
        error: error.message || error,
        timestamp: new Date().toISOString(),
        ...context
      });
    }
    
    this.updateStats('warn', 'job-retry');
  }

  /**
   * Performance logging methods
   */
  logPerformance(metricName, value, unit = '', context = {}) {
    const logger = this.loggers.get('performance');
    if (logger) {
      logger.info('Performance metric', {
        metricType: metricName,
        value,
        unit,
        timestamp: new Date().toISOString(),
        ...context
      });
    }
    
    this.updateStats('info', 'performance');
  }

  logMemoryUsage(context = {}) {
    const memUsage = process.memoryUsage();
    this.logPerformance('memory_usage', {
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      rss: memUsage.rss,
      external: memUsage.external,
      heapUsedMB: Math.round(memUsage.heapUsed / 1024 / 1024),
      heapUtilization: memUsage.heapUsed / memUsage.heapTotal
    }, 'bytes', context);
  }

  logBatchProcessing(batchSize, processingTime, successCount, errorCount, context = {}) {
    const logger = this.loggers.get('performance');
    if (logger) {
      logger.info('Batch processing metrics', {
        batchSize,
        processingTime,
        successCount,
        errorCount,
        throughput: batchSize / (processingTime / 1000), // items per second
        errorRate: errorCount / batchSize,
        timestamp: new Date().toISOString(),
        ...context
      });
    }
    
    this.updateStats('info', 'batch-processing');
  }

  logWorkerUtilization(activeWorkers, maxWorkers, utilizationPercent, context = {}) {
    this.logPerformance('worker_utilization', {
      activeWorkers,
      maxWorkers,
      utilizationPercent,
      isHighUtilization: utilizationPercent > 0.8
    }, 'percent', context);
  }

  /**
   * Error logging methods
   */
  logError(message, error, context = {}) {
    const errorLogger = this.loggers.get('errors');
    if (errorLogger) {
      errorLogger.error(message, {
        error: error.message || error,
        stack: error.stack,
        timestamp: new Date().toISOString(),
        context: this.getCurrentContext(),
        ...context
      });
    }
    
    this.updateStats('error', 'general-error');
  }

  logCriticalError(message, error, context = {}) {
    const errorLogger = this.loggers.get('errors');
    if (errorLogger) {
      errorLogger.error(`CRITICAL: ${message}`, {
        severity: 'critical',
        error: error.message || error,
        stack: error.stack,
        timestamp: new Date().toISOString(),
        context: this.getCurrentContext(),
        ...context
      });
    }
    
    // Also use SecureLogger for immediate visibility
    SecureLogger.logError(`CRITICAL SCHEDULER ERROR: ${message}`, error);
    
    this.updateStats('error', 'critical-error');
  }

  logWarning(message, context = {}) {
    const logger = this.loggers.get('jobs');
    if (logger) {
      logger.warn(message, {
        timestamp: new Date().toISOString(),
        context: this.getCurrentContext(),
        ...context
      });
    }
    
    this.updateStats('warn', 'warning');
  }

  /**
   * Audit logging methods
   */
  logAudit(action, userId, details = {}) {
    const auditLogger = this.loggers.get('audit');
    if (auditLogger) {
      auditLogger.info('Audit event', {
        action,
        userId: userId || 'system',
        resource: 'scheduler',
        timestamp: new Date().toISOString(),
        correlationId: this.correlationId,
        ...details
      });
    }
    
    this.updateStats('info', 'audit');
  }

  logSecurityEvent(eventType, details = {}) {
    const auditLogger = this.loggers.get('audit');
    if (auditLogger) {
      auditLogger.warn('Security event', {
        eventType,
        severity: 'security',
        timestamp: new Date().toISOString(),
        correlationId: this.correlationId,
        ...details
      });
    }
    
    this.updateStats('warn', 'security');
  }

  /**
   * Metrics logging methods
   */
  logMetric(metricName, value, unit = '', tags = {}) {
    const metricsLogger = this.loggers.get('metrics');
    if (metricsLogger) {
      metricsLogger.info('Metric recorded', {
        metricType: metricName,
        value,
        unit,
        tags,
        timestamp: new Date().toISOString()
      });
    }
    
    this.updateStats('info', 'metric');
  }

  logHealthCheck(status, details = {}) {
    const logger = this.loggers.get('jobs');
    if (logger) {
      logger.info('Health check result', {
        healthStatus: status,
        timestamp: new Date().toISOString(),
        ...details
      });
    }
    
    this.updateStats('info', 'health-check');
  }

  /**
   * Statistics management
   */
  updateStats(level, category) {
    this.stats.totalLogs++;
    this.stats.lastLogTime = new Date();
    
    // Update level counts
    const levelCount = this.stats.logsByLevel.get(level) || 0;
    this.stats.logsByLevel.set(level, levelCount + 1);
    
    // Update category counts
    const categoryCount = this.stats.logsByCategory.get(category) || 0;
    this.stats.logsByCategory.set(category, categoryCount + 1);
    
    // Update specific counters
    if (level === 'error') {
      this.stats.errorCount++;
    } else if (level === 'warn') {
      this.stats.warningCount++;
    }
  }

  getStats() {
    return {
      ...this.stats,
      logsByLevel: Object.fromEntries(this.stats.logsByLevel),
      logsByCategory: Object.fromEntries(this.stats.logsByCategory),
      errorRate: this.stats.totalLogs > 0 ? (this.stats.errorCount / this.stats.totalLogs) * 100 : 0,
      warningRate: this.stats.totalLogs > 0 ? (this.stats.warningCount / this.stats.totalLogs) * 100 : 0
    };
  }

  /**
   * Utility methods
   */
  debug(message, context = {}) {
    const logger = this.loggers.get('jobs');
    if (logger) {
      logger.debug(message, {
        timestamp: new Date().toISOString(),
        context: this.getCurrentContext(),
        ...context
      });
    }
    
    this.updateStats('debug', 'debug');
  }

  info(message, context = {}) {
    const logger = this.loggers.get('jobs');
    if (logger) {
      logger.info(message, {
        timestamp: new Date().toISOString(),
        context: this.getCurrentContext(),
        ...context
      });
    }
    
    this.updateStats('info', 'info');
  }

  /**
   * Log management methods
   */
  async flushLogs() {
    const flushPromises = [];
    
    for (const [name, logger] of this.loggers) {
      if (logger && typeof logger.end === 'function') {
        flushPromises.push(new Promise((resolve) => {
          logger.end(() => resolve());
        }));
      }
    }
    
    await Promise.all(flushPromises);
    SecureLogger.logInfo('All scheduler logs flushed');
  }

  async rotateLogs() {
    // Force log rotation for all daily rotate transports
    for (const [name, logger] of this.loggers) {
      for (const transport of logger.transports) {
        if (transport instanceof DailyRotateFile) {
          transport.rotate();
        }
      }
    }
    
    SecureLogger.logInfo('Scheduler log rotation completed');
  }

  getLogFilePaths() {
    const paths = {};
    
    for (const [name, logger] of this.loggers) {
      paths[name] = [];
      for (const transport of logger.transports) {
        if (transport instanceof DailyRotateFile) {
          paths[name].push(transport.filename);
        }
      }
    }
    
    return paths;
  }

  /**
   * Cleanup and shutdown
   */
  async shutdown() {
    try {
      await this.flushLogs();
      
      // Close all loggers
      for (const [name, logger] of this.loggers) {
        if (logger && typeof logger.close === 'function') {
          logger.close();
        }
      }
      
      this.loggers.clear();
      this.isInitialized = false;
      
      SecureLogger.logInfo('SchedulerLogger shutdown completed');
      
    } catch (error) {
      SecureLogger.logError('Error during SchedulerLogger shutdown', error);
      throw error;
    }
  }
}

module.exports = SchedulerLogger;