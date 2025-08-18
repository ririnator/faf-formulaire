const express = require('express');
const router = express.Router();
const { requireAdminAccess } = require('../middleware/hybridAuth');
const rateLimiting = require('../middleware/rateLimiting');
const validation = require('../middleware/validation');
const SecureLogger = require('../utils/secureLogger');

/**
 * Scheduler Monitoring Dashboard API Routes
 * 
 * Comprehensive REST API for the Form-a-Friend v2 scheduler monitoring system
 * Provides real-time access to job metrics, performance data, alerts, and system health
 * 
 * Endpoints:
 * - GET /status - Current monitoring status and basic metrics
 * - GET /metrics - Detailed performance metrics
 * - GET /jobs - Job execution history and statistics
 * - GET /alerts - Alert management and history
 * - GET /health - System health and diagnostics
 * - POST /alerts/suppress - Suppress specific alerts
 * - POST /jobs/trigger - Manually trigger jobs (admin only)
 * - GET /logs - Access structured logs
 * - GET /export - Export monitoring data
 */

let schedulerMonitoring = null;
let schedulerAlerting = null;
let schedulerLogger = null;
let schedulerService = null;

/**
 * Initialize routes with service dependencies
 */
function initializeRoutes(services = {}) {
  schedulerMonitoring = services.schedulerMonitoring;
  schedulerAlerting = services.schedulerAlerting;
  schedulerLogger = services.schedulerLogger;
  schedulerService = services.schedulerService;
  
  SecureLogger.logInfo('Scheduler monitoring routes initialized', {
    hasMonitoring: !!schedulerMonitoring,
    hasAlerting: !!schedulerAlerting,
    hasLogger: !!schedulerLogger,
    hasScheduler: !!schedulerService
  });
}

/**
 * Middleware to check service availability
 */
function checkServiceAvailability(serviceName) {
  return (req, res, next) => {
    const services = {
      monitoring: schedulerMonitoring,
      alerting: schedulerAlerting,
      logger: schedulerLogger,
      scheduler: schedulerService
    };
    
    if (!services[serviceName]) {
      return res.status(503).json({
        success: false,
        error: `${serviceName} service not available`,
        timestamp: new Date().toISOString()
      });
    }
    
    next();
  };
}

/**
 * Error handler for monitoring routes
 */
function handleMonitoringError(error, req, res) {
  SecureLogger.logError('Scheduler monitoring API error', error);
  
  res.status(500).json({
    success: false,
    error: 'Internal monitoring error',
    message: error.message,
    timestamp: new Date().toISOString()
  });
}

// Apply rate limiting to all routes
router.use(rateLimiting.adminLimiter);

// Apply admin authentication to all routes
router.use(requireAdminAccess);

/**
 * GET /api/scheduler-monitoring/status
 * Get current monitoring status and basic metrics
 */
router.get('/status', 
  checkServiceAvailability('monitoring'),
  async (req, res) => {
    try {
      const status = schedulerMonitoring.getMonitoringStatus();
      const basicMetrics = schedulerMonitoring.getBasicMetrics();
      
      res.json({
        success: true,
        data: {
          status,
          metrics: basicMetrics,
          timestamp: new Date().toISOString()
        }
      });
      
    } catch (error) {
      handleMonitoringError(error, req, res);
    }
  }
);

/**
 * GET /api/scheduler-monitoring/metrics
 * Get detailed performance metrics
 */
router.get('/metrics', 
  checkServiceAvailability('monitoring'),
  async (req, res) => {
    try {
      const { timeframe, detailed } = req.query;
      
      let metrics;
      if (detailed === 'true') {
        metrics = schedulerMonitoring.getDetailedMetrics();
      } else {
        metrics = schedulerMonitoring.getBasicMetrics();
      }
      
      // Add timeframe filtering if requested
      if (timeframe) {
        const timeframeMs = parseTimeframe(timeframe);
        if (timeframeMs) {
          metrics = filterMetricsByTimeframe(metrics, timeframeMs);
        }
      }
      
      res.json({
        success: true,
        data: {
          metrics,
          timeframe: timeframe || 'all',
          timestamp: new Date().toISOString()
        }
      });
      
    } catch (error) {
      handleMonitoringError(error, req, res);
    }
  }
);

/**
 * GET /api/scheduler-monitoring/jobs
 * Get job execution history and statistics
 */
router.get('/jobs', 
  checkServiceAvailability('monitoring'),
  async (req, res) => {
    try {
      const { type, status, since, limit } = req.query;
      
      const filters = {};
      if (type) filters.type = type;
      if (status) filters.status = status;
      if (since) filters.since = since;
      if (limit) filters.limit = parseInt(limit, 10);
      
      const executionHistory = schedulerMonitoring.getExecutionHistory(filters);
      const jobMetrics = schedulerMonitoring.getBasicMetrics().jobs;
      
      res.json({
        success: true,
        data: {
          executionHistory,
          jobMetrics,
          filters,
          timestamp: new Date().toISOString()
        }
      });
      
    } catch (error) {
      handleMonitoringError(error, req, res);
    }
  }
);

/**
 * GET /api/scheduler-monitoring/alerts
 * Get alert information and history
 */
router.get('/alerts', 
  checkServiceAvailability('alerting'),
  async (req, res) => {
    try {
      const { active, limit, severity, type } = req.query;
      
      let alerts;
      if (active === 'true') {
        alerts = schedulerAlerting.getActiveAlerts();
      } else {
        const historyLimit = limit ? parseInt(limit, 10) : 100;
        alerts = schedulerAlerting.getAlertHistory(historyLimit);
      }
      
      // Filter by severity if requested
      if (severity) {
        alerts = alerts.filter(alert => alert.severity === severity);
      }
      
      // Filter by type if requested
      if (type) {
        alerts = alerts.filter(alert => alert.type === type);
      }
      
      const alertingStatus = schedulerAlerting.getAlertingStatus();
      
      res.json({
        success: true,
        data: {
          alerts,
          alertingStatus,
          filters: { active, limit, severity, type },
          timestamp: new Date().toISOString()
        }
      });
      
    } catch (error) {
      handleMonitoringError(error, req, res);
    }
  }
);

/**
 * GET /api/scheduler-monitoring/health
 * Get comprehensive system health information
 */
router.get('/health', 
  checkServiceAvailability('monitoring'),
  async (req, res) => {
    try {
      const healthData = {
        monitoring: schedulerMonitoring.checkMonitoringHealth(),
        scheduler: schedulerService ? schedulerService.getStatus() : { status: 'unavailable' },
        alerting: schedulerAlerting ? schedulerAlerting.getAlertingStatus() : { status: 'unavailable' },
        system: {
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          nodeVersion: process.version,
          platform: process.platform
        }
      };
      
      // Determine overall health status
      const overallStatus = determineOverallHealth(healthData);
      
      res.json({
        success: true,
        data: {
          health: healthData,
          overallStatus,
          timestamp: new Date().toISOString()
        }
      });
      
    } catch (error) {
      handleMonitoringError(error, req, res);
    }
  }
);

/**
 * GET /api/scheduler-monitoring/errors
 * Get error analysis and patterns
 */
router.get('/errors', 
  checkServiceAvailability('monitoring'),
  async (req, res) => {
    try {
      const { timeframe } = req.query;
      const timeframeMs = parseTimeframe(timeframe) || (24 * 60 * 60 * 1000); // Default 24 hours
      
      const errorAnalysis = schedulerMonitoring.getErrorAnalysis(timeframeMs);
      
      res.json({
        success: true,
        data: {
          errorAnalysis,
          timeframe: timeframe || '24h',
          timestamp: new Date().toISOString()
        }
      });
      
    } catch (error) {
      handleMonitoringError(error, req, res);
    }
  }
);

/**
 * POST /api/scheduler-monitoring/alerts/suppress
 * Suppress specific alert types
 */
router.post('/alerts/suppress',
  checkServiceAvailability('alerting'),
  async (req, res) => {
    try {
      const { alertType, duration } = req.body;
      const suppressDuration = duration || 60 * 60 * 1000; // Default 1 hour
      
      schedulerAlerting.suppressAlert(alertType, suppressDuration);
      
      SecureLogger.logAudit('alert_suppressed', req.user?.userId || 'admin', {
        alertType,
        duration: suppressDuration
      });
      
      res.json({
        success: true,
        data: {
          alertType,
          duration: suppressDuration,
          suppressedUntil: new Date(Date.now() + suppressDuration).toISOString()
        }
      });
      
    } catch (error) {
      handleMonitoringError(error, req, res);
    }
  }
);

/**
 * POST /api/scheduler-monitoring/jobs/trigger
 * Manually trigger scheduler jobs (admin only)
 */
router.post('/jobs/trigger',
  checkServiceAvailability('scheduler'),
  async (req, res) => {
    try {
      const { jobType, options } = req.body;
      
      if (!schedulerService.isRunning) {
        return res.status(400).json({
          success: false,
          error: 'Scheduler service is not running',
          timestamp: new Date().toISOString()
        });
      }
      
      // Log the manual job trigger
      SecureLogger.logAudit('manual_job_triggered', req.user?.userId || 'admin', {
        jobType,
        options: options || {}
      });
      
      // Trigger the job
      const result = await schedulerService.triggerJob(jobType, options);
      
      res.json({
        success: true,
        data: {
          jobType,
          triggeredAt: new Date().toISOString(),
          result
        }
      });
      
    } catch (error) {
      SecureLogger.logError('Manual job trigger failed', error);
      res.status(400).json({
        success: false,
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }
);

/**
 * GET /api/scheduler-monitoring/logs
 * Access structured logs (with pagination)
 */
router.get('/logs',
  checkServiceAvailability('logger'),
  async (req, res) => {
    try {
      const { category, level, limit, since } = req.query;
      
      // Get log file paths
      const logPaths = schedulerLogger.getLogFilePaths();
      const logStats = schedulerLogger.getStats();
      
      res.json({
        success: true,
        data: {
          logPaths,
          logStats,
          filters: { category, level, limit, since },
          note: 'Log content access requires file system access. Use log file paths to access actual log content.',
          timestamp: new Date().toISOString()
        }
      });
      
    } catch (error) {
      handleMonitoringError(error, req, res);
    }
  }
);

/**
 * GET /api/scheduler-monitoring/export
 * Export comprehensive monitoring data
 */
router.get('/export',
  checkServiceAvailability('monitoring'),
  async (req, res) => {
    try {
      const { format } = req.query;
      
      const exportData = {
        monitoring: schedulerMonitoring.exportMonitoringData(),
        alerting: schedulerAlerting ? schedulerAlerting.exportAlertData() : null,
        logging: schedulerLogger ? schedulerLogger.getStats() : null,
        scheduler: schedulerService ? schedulerService.getStatus() : null
      };
      
      if (format === 'csv') {
        // Convert to CSV format (simplified)
        const csv = convertToCSV(exportData);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=scheduler-monitoring-export.csv');
        res.send(csv);
      } else {
        // JSON format (default)
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=scheduler-monitoring-export.json');
        res.json(exportData);
      }
      
      SecureLogger.logAudit('monitoring_data_exported', req.user?.userId || 'admin', {
        format: format || 'json',
        dataSize: JSON.stringify(exportData).length
      });
      
    } catch (error) {
      handleMonitoringError(error, req, res);
    }
  }
);

/**
 * GET /api/scheduler-monitoring/dashboard
 * Get dashboard overview data
 */
router.get('/dashboard', async (req, res) => {
  try {
    const dashboardData = {
      overview: {
        isMonitoring: schedulerMonitoring ? schedulerMonitoring.getMonitoringStatus().isMonitoring : false,
        isAlerting: schedulerAlerting ? schedulerAlerting.getAlertingStatus().isActive : false,
        isSchedulerRunning: schedulerService ? schedulerService.getStatus().isRunning : false
      },
      metrics: schedulerMonitoring ? schedulerMonitoring.getBasicMetrics() : null,
      activeAlerts: schedulerAlerting ? schedulerAlerting.getActiveAlerts().length : 0,
      recentJobs: schedulerMonitoring ? schedulerMonitoring.getExecutionHistory({ limit: 10 }) : [],
      systemHealth: {
        memoryUsage: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        uptime: Math.round(process.uptime()),
        nodeVersion: process.version
      }
    };
    
    res.json({
      success: true,
      data: dashboardData,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    handleMonitoringError(error, req, res);
  }
});

/**
 * WebSocket endpoint for real-time monitoring (if WebSocket support is added)
 */
router.get('/websocket-info', (req, res) => {
  res.json({
    success: true,
    data: {
      message: 'WebSocket support not implemented yet',
      supportedEvents: [
        'job-started',
        'job-completed',
        'job-failed',
        'alert-triggered',
        'alert-resolved',
        'metrics-updated'
      ],
      note: 'Use polling with /status endpoint for real-time updates'
    }
  });
});

/**
 * Utility functions
 */
function parseTimeframe(timeframe) {
  if (!timeframe) return null;
  
  const timeframeMap = {
    '1h': 60 * 60 * 1000,
    '6h': 6 * 60 * 60 * 1000,
    '12h': 12 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000
  };
  
  return timeframeMap[timeframe] || null;
}

function filterMetricsByTimeframe(metrics, timeframeMs) {
  const cutoff = Date.now() - timeframeMs;
  
  // Filter time-based metrics
  if (metrics.performanceMetrics) {
    if (metrics.performanceMetrics.memoryUsage) {
      metrics.performanceMetrics.memoryUsage = metrics.performanceMetrics.memoryUsage.filter(
        m => m.timestamp && new Date(m.timestamp).getTime() > cutoff
      );
    }
    
    if (metrics.performanceMetrics.systemHealth) {
      metrics.performanceMetrics.systemHealth = metrics.performanceMetrics.systemHealth.filter(
        h => h.timestamp && new Date(h.timestamp).getTime() > cutoff
      );
    }
  }
  
  if (metrics.recentExecutions) {
    metrics.recentExecutions = metrics.recentExecutions.filter(
      job => job.startTime && new Date(job.startTime).getTime() > cutoff
    );
  }
  
  return metrics;
}

function determineOverallHealth(healthData) {
  const issues = [];
  
  if (healthData.monitoring?.status !== 'healthy') {
    issues.push('monitoring');
  }
  
  if (healthData.scheduler?.isRunning === false) {
    issues.push('scheduler');
  }
  
  if (healthData.alerting?.isActive === false) {
    issues.push('alerting');
  }
  
  const memoryUsageMB = healthData.system?.memoryUsage?.heapUsed ? 
    Math.round(healthData.system.memoryUsage.heapUsed / 1024 / 1024) : 0;
  
  if (memoryUsageMB > 512) {
    issues.push('memory');
  }
  
  if (issues.length === 0) {
    return { status: 'healthy', issues: [] };
  } else if (issues.length <= 1) {
    return { status: 'warning', issues };
  } else {
    return { status: 'critical', issues };
  }
}

function convertToCSV(data) {
  // Simplified CSV conversion for basic metrics
  const lines = ['Type,Metric,Value,Timestamp'];
  
  if (data.monitoring?.metrics?.jobs) {
    const jobs = data.monitoring.metrics.jobs;
    lines.push(`jobs,total,${jobs.total},${new Date().toISOString()}`);
    lines.push(`jobs,successful,${jobs.successful},${new Date().toISOString()}`);
    lines.push(`jobs,failed,${jobs.failed},${new Date().toISOString()}`);
    lines.push(`jobs,success_rate,${jobs.successRate},${new Date().toISOString()}`);
  }
  
  if (data.alerting?.stats) {
    const stats = data.alerting.stats;
    lines.push(`alerts,total,${stats.totalAlerts},${new Date().toISOString()}`);
    lines.push(`alerts,active,${stats.active?.alertCount || 0},${new Date().toISOString()}`);
  }
  
  return lines.join('\n');
}

// Export initialization function and router
module.exports = {
  router,
  initializeRoutes
};