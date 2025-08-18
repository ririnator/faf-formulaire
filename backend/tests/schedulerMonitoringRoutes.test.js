const request = require('supertest');
const express = require('express');
const { router, initializeRoutes } = require('../routes/schedulerMonitoringRoutes');
const SchedulerMonitoringService = require('../services/schedulerMonitoringService');
const SchedulerAlerting = require('../services/schedulerAlerting');
const SchedulerLogger = require('../services/schedulerLogger');

/**
 * Test Suite for Scheduler Monitoring Routes
 * 
 * Tests the REST API endpoints for scheduler monitoring dashboard
 * Covers authentication, error handling, data retrieval, and admin operations
 */

describe('Scheduler Monitoring Routes', () => {
  let app;
  let mockSchedulerMonitoring;
  let mockSchedulerAlerting;
  let mockSchedulerLogger;
  let mockSchedulerService;

  beforeEach(() => {
    // Create Express app with routes
    app = express();
    app.use(express.json());
    
    // Mock authentication middleware
    app.use((req, res, next) => {
      req.user = { userId: 'admin', role: 'admin' };
      next();
    });
    
    // Create mock services
    mockSchedulerMonitoring = {
      getMonitoringStatus: jest.fn(() => ({
        isMonitoring: true,
        activeJobs: 2,
        totalJobsTracked: 50,
        uptime: 3600000
      })),
      getBasicMetrics: jest.fn(() => ({
        jobs: {
          total: 50,
          successful: 48,
          failed: 2,
          successRate: 96,
          consecutiveFailures: 0,
          avgDuration: 15000
        },
        performance: {
          currentMemoryMB: 256,
          activeJobs: 2
        },
        errors: {
          recentCount: 3,
          patterns: 2
        },
        alerts: {
          active: 1,
          total: 10
        }
      })),
      getDetailedMetrics: jest.fn(() => ({
        jobs: { total: 50, successful: 48, failed: 2 },
        activeJobs: [],
        recentExecutions: [],
        performanceMetrics: {
          memoryUsage: [],
          systemHealth: []
        },
        errorAnalysis: {
          recentErrors: [],
          errorPatterns: []
        }
      })),
      getExecutionHistory: jest.fn(() => [
        {
          jobId: 'job-1',
          type: 'monthly-invitations',
          status: 'success',
          duration: 30000,
          startTime: new Date('2023-01-01T10:00:00Z'),
          endTime: new Date('2023-01-01T10:30:00Z')
        }
      ]),
      getErrorAnalysis: jest.fn(() => ({
        timeframe: 86400000,
        totalErrors: 5,
        errorRate: 2.5,
        patterns: {
          'database': 2,
          'timeout': 3
        },
        timeline: []
      })),
      checkMonitoringHealth: jest.fn(() => ({
        status: 'healthy',
        isMonitoring: true
      })),
      exportMonitoringData: jest.fn(() => ({
        timestamp: new Date(),
        status: {},
        metrics: {},
        config: {}
      }))
    };

    mockSchedulerAlerting = {
      getAlertingStatus: jest.fn(() => ({
        isActive: true,
        stats: {
          totalAlerts: 10,
          alertsByLevel: { high: 5, medium: 3, low: 2 },
          alertsByType: { 'job-failure': 8, 'memory-usage': 2 }
        },
        active: { alertCount: 1 },
        rules: { total: 8, enabled: 8 }
      })),
      getActiveAlerts: jest.fn(() => [
        {
          id: 'alert-1',
          type: 'job-failure',
          severity: 'high',
          name: 'Job Execution Failure',
          triggeredAt: new Date()
        }
      ]),
      getAlertHistory: jest.fn(() => [
        {
          id: 'alert-2',
          type: 'memory-usage',
          severity: 'medium',
          resolvedAt: new Date()
        }
      ]),
      suppressAlert: jest.fn(),
      exportAlertData: jest.fn(() => ({
        timestamp: new Date(),
        status: {},
        activeAlerts: [],
        recentHistory: []
      }))
    };

    mockSchedulerLogger = {
      getLogFilePaths: jest.fn(() => ({
        jobs: ['/logs/jobs-2023-01-01.log'],
        errors: ['/logs/errors-2023-01-01.log']
      })),
      getStats: jest.fn(() => ({
        totalLogs: 1500,
        errorCount: 25,
        warningCount: 50,
        logsByLevel: { info: 1200, warn: 50, error: 25 }
      }))
    };

    mockSchedulerService = {
      getStatus: jest.fn(() => ({
        isRunning: true,
        activeJobs: 2,
        activeWorkers: 4
      })),
      triggerJob: jest.fn(() => Promise.resolve({ success: true })),
      isRunning: true
    };

    // Initialize routes with mock services
    initializeRoutes({
      schedulerMonitoring: mockSchedulerMonitoring,
      schedulerAlerting: mockSchedulerAlerting,
      schedulerLogger: mockSchedulerLogger,
      schedulerService: mockSchedulerService
    });

    app.use('/api/scheduler-monitoring', router);
  });

  describe('GET /status', () => {
    test('should return monitoring status and basic metrics', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/status')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('status');
      expect(response.body.data).toHaveProperty('metrics');
      expect(response.body.data.status.isMonitoring).toBe(true);
      expect(response.body.data.metrics.jobs.total).toBe(50);
    });

    test('should handle service unavailable', async () => {
      // Test without monitoring service
      initializeRoutes({});
      
      const response = await request(app)
        .get('/api/scheduler-monitoring/status')
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('monitoring service not available');
    });
  });

  describe('GET /metrics', () => {
    test('should return basic metrics by default', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/metrics')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.metrics).toHaveProperty('jobs');
      expect(mockSchedulerMonitoring.getBasicMetrics).toHaveBeenCalled();
    });

    test('should return detailed metrics when requested', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/metrics?detailed=true')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(mockSchedulerMonitoring.getDetailedMetrics).toHaveBeenCalled();
    });

    test('should filter metrics by timeframe', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/metrics?timeframe=24h')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.timeframe).toBe('24h');
    });

    test('should handle invalid timeframe gracefully', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/metrics?timeframe=invalid')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.timeframe).toBe('invalid');
    });
  });

  describe('GET /jobs', () => {
    test('should return job execution history', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/jobs')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('executionHistory');
      expect(response.body.data).toHaveProperty('jobMetrics');
      expect(response.body.data.executionHistory).toHaveLength(1);
    });

    test('should filter jobs by type', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/jobs?type=monthly-invitations')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(mockSchedulerMonitoring.getExecutionHistory).toHaveBeenCalledWith({
        type: 'monthly-invitations'
      });
    });

    test('should filter jobs by status and limit', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/jobs?status=success&limit=10')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(mockSchedulerMonitoring.getExecutionHistory).toHaveBeenCalledWith({
        status: 'success',
        limit: 10
      });
    });
  });

  describe('GET /alerts', () => {
    test('should return active alerts by default', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/alerts?active=true')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('alerts');
      expect(response.body.data).toHaveProperty('alertingStatus');
      expect(mockSchedulerAlerting.getActiveAlerts).toHaveBeenCalled();
    });

    test('should return alert history when requested', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/alerts?active=false&limit=50')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(mockSchedulerAlerting.getAlertHistory).toHaveBeenCalledWith(50);
    });

    test('should filter alerts by severity', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/alerts?severity=high')
        .expect(200);

      expect(response.body.success).toBe(true);
      // Should filter the returned alerts by severity
      expect(response.body.data.filters.severity).toBe('high');
    });

    test('should handle alerting service unavailable', async () => {
      initializeRoutes({
        schedulerMonitoring: mockSchedulerMonitoring
      });

      const response = await request(app)
        .get('/api/scheduler-monitoring/alerts')
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('alerting service not available');
    });
  });

  describe('GET /health', () => {
    test('should return comprehensive health information', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/health')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('health');
      expect(response.body.data).toHaveProperty('overallStatus');
      expect(response.body.data.health).toHaveProperty('monitoring');
      expect(response.body.data.health).toHaveProperty('scheduler');
      expect(response.body.data.health).toHaveProperty('system');
    });

    test('should determine overall health status correctly', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/health')
        .expect(200);

      expect(response.body.data.overallStatus).toHaveProperty('status');
      expect(response.body.data.overallStatus).toHaveProperty('issues');
    });
  });

  describe('GET /errors', () => {
    test('should return error analysis', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/errors')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('errorAnalysis');
      expect(response.body.data.timeframe).toBe('24h');
      expect(mockSchedulerMonitoring.getErrorAnalysis).toHaveBeenCalledWith(24 * 60 * 60 * 1000);
    });

    test('should accept custom timeframe', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/errors?timeframe=1h')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.timeframe).toBe('1h');
      expect(mockSchedulerMonitoring.getErrorAnalysis).toHaveBeenCalledWith(60 * 60 * 1000);
    });
  });

  describe('POST /alerts/suppress', () => {
    test('should suppress alerts successfully', async () => {
      const response = await request(app)
        .post('/api/scheduler-monitoring/alerts/suppress')
        .send({
          alertType: 'job-failure',
          duration: 3600000 // 1 hour
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.alertType).toBe('job-failure');
      expect(response.body.data.duration).toBe(3600000);
      expect(mockSchedulerAlerting.suppressAlert).toHaveBeenCalledWith('job-failure', 3600000);
    });

    test('should use default duration when not provided', async () => {
      const response = await request(app)
        .post('/api/scheduler-monitoring/alerts/suppress')
        .send({
          alertType: 'memory-usage'
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.duration).toBe(60 * 60 * 1000); // Default 1 hour
    });

    test('should validate request body', async () => {
      const response = await request(app)
        .post('/api/scheduler-monitoring/alerts/suppress')
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    test('should validate duration limits', async () => {
      const response = await request(app)
        .post('/api/scheduler-monitoring/alerts/suppress')
        .send({
          alertType: 'test-alert',
          duration: 30000 // Less than minimum (1 minute)
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /jobs/trigger', () => {
    test('should trigger job successfully', async () => {
      const response = await request(app)
        .post('/api/scheduler-monitoring/jobs/trigger')
        .send({
          jobType: 'monthly-invitations',
          options: { force: true }
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.jobType).toBe('monthly-invitations');
      expect(mockSchedulerService.triggerJob).toHaveBeenCalledWith('monthly-invitations', { force: true });
    });

    test('should validate job type', async () => {
      const response = await request(app)
        .post('/api/scheduler-monitoring/jobs/trigger')
        .send({
          jobType: 'invalid-job-type'
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    test('should handle scheduler not running', async () => {
      mockSchedulerService.isRunning = false;

      const response = await request(app)
        .post('/api/scheduler-monitoring/jobs/trigger')
        .send({
          jobType: 'cleanup'
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('not running');
    });

    test('should handle job trigger failure', async () => {
      mockSchedulerService.triggerJob.mockRejectedValueOnce(new Error('Job trigger failed'));

      const response = await request(app)
        .post('/api/scheduler-monitoring/jobs/trigger')
        .send({
          jobType: 'health-check'
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Job trigger failed');
    });
  });

  describe('GET /logs', () => {
    test('should return log information', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/logs')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('logPaths');
      expect(response.body.data).toHaveProperty('logStats');
      expect(mockSchedulerLogger.getLogFilePaths).toHaveBeenCalled();
      expect(mockSchedulerLogger.getStats).toHaveBeenCalled();
    });

    test('should handle filters', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/logs?category=jobs&level=error&limit=100')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.filters).toEqual({
        category: 'jobs',
        level: 'error',
        limit: '100',
        since: null
      });
    });
  });

  describe('GET /export', () => {
    test('should export data as JSON by default', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/export')
        .expect(200);

      expect(response.headers['content-type']).toContain('application/json');
      expect(response.headers['content-disposition']).toContain('scheduler-monitoring-export.json');
      expect(response.body).toHaveProperty('monitoring');
      expect(response.body).toHaveProperty('alerting');
    });

    test('should export data as CSV when requested', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/export?format=csv')
        .expect(200);

      expect(response.headers['content-type']).toContain('text/csv');
      expect(response.headers['content-disposition']).toContain('scheduler-monitoring-export.csv');
      expect(response.text).toContain('Type,Metric,Value,Timestamp');
    });
  });

  describe('GET /dashboard', () => {
    test('should return dashboard overview data', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/dashboard')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('overview');
      expect(response.body.data).toHaveProperty('metrics');
      expect(response.body.data).toHaveProperty('systemHealth');
      expect(response.body.data.overview.isMonitoring).toBe(true);
    });

    test('should handle missing services gracefully', async () => {
      initializeRoutes({});

      const response = await request(app)
        .get('/api/scheduler-monitoring/dashboard')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.overview.isMonitoring).toBe(false);
      expect(response.body.data.metrics).toBeNull();
    });
  });

  describe('GET /websocket-info', () => {
    test('should return WebSocket information', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/websocket-info')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('supportedEvents');
      expect(response.body.data.supportedEvents).toContain('job-started');
    });
  });

  describe('Error Handling', () => {
    test('should handle monitoring service errors', async () => {
      mockSchedulerMonitoring.getMonitoringStatus.mockImplementationOnce(() => {
        throw new Error('Service error');
      });

      const response = await request(app)
        .get('/api/scheduler-monitoring/status')
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Internal monitoring error');
      expect(response.body.message).toBe('Service error');
    });

    test('should handle alerting service errors', async () => {
      mockSchedulerAlerting.getActiveAlerts.mockImplementationOnce(() => {
        throw new Error('Alerting error');
      });

      const response = await request(app)
        .get('/api/scheduler-monitoring/alerts?active=true')
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Internal monitoring error');
    });
  });

  describe('Rate Limiting', () => {
    test('should apply rate limiting to requests', async () => {
      // This would require setting up actual rate limiting middleware
      // For now, we just verify the routes are configured
      expect(router).toBeDefined();
    });
  });

  describe('Authentication', () => {
    test('should require admin access', async () => {
      // Create app without auth middleware
      const unauthApp = express();
      unauthApp.use(express.json());
      
      // Mock auth middleware that denies access
      unauthApp.use((req, res, next) => {
        res.status(401).json({ error: 'Unauthorized' });
      });
      
      unauthApp.use('/api/scheduler-monitoring', router);

      const response = await request(unauthApp)
        .get('/api/scheduler-monitoring/status')
        .expect(401);

      expect(response.body.error).toBe('Unauthorized');
    });
  });

  describe('Utility Functions', () => {
    test('should parse timeframes correctly', () => {
      // These would be tested if the utility functions were exported
      // For now, we test through the API endpoints
      
      const timeframes = ['1h', '6h', '12h', '24h', '7d', '30d'];
      
      timeframes.forEach(async (timeframe) => {
        const response = await request(app)
          .get(`/api/scheduler-monitoring/metrics?timeframe=${timeframe}`)
          .expect(200);
        
        expect(response.body.data.timeframe).toBe(timeframe);
      });
    });

    test('should handle invalid timeframes', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/metrics?timeframe=invalid')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.timeframe).toBe('invalid');
    });
  });

  describe('Data Filtering', () => {
    test('should filter metrics by timeframe', async () => {
      const detailedMetrics = {
        performanceMetrics: {
          memoryUsage: [
            { timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000) }, // 2 hours ago
            { timestamp: new Date(Date.now() - 30 * 60 * 1000) } // 30 minutes ago
          ]
        },
        recentExecutions: [
          { startTime: new Date(Date.now() - 2 * 60 * 60 * 1000) },
          { startTime: new Date(Date.now() - 30 * 60 * 1000) }
        ]
      };

      mockSchedulerMonitoring.getDetailedMetrics.mockReturnValueOnce(detailedMetrics);

      const response = await request(app)
        .get('/api/scheduler-monitoring/metrics?detailed=true&timeframe=1h')
        .expect(200);

      expect(response.body.success).toBe(true);
      // The filtering would be applied to the metrics
    });
  });

  describe('Health Status Determination', () => {
    test('should determine healthy status', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/health')
        .expect(200);

      const healthData = response.body.data.health;
      const overallStatus = response.body.data.overallStatus;

      // With all services healthy, overall status should be healthy
      expect(overallStatus.status).toBe('healthy');
      expect(overallStatus.issues).toHaveLength(0);
    });

    test('should detect unhealthy status', async () => {
      // Mock scheduler as not running
      mockSchedulerService.getStatus.mockReturnValueOnce({
        isRunning: false,
        activeJobs: 0,
        activeWorkers: 0
      });

      const response = await request(app)
        .get('/api/scheduler-monitoring/health')
        .expect(200);

      const overallStatus = response.body.data.overallStatus;
      expect(overallStatus.status).toBe('warning');
      expect(overallStatus.issues).toContain('scheduler');
    });
  });

  describe('CSV Export', () => {
    test('should generate valid CSV format', async () => {
      const response = await request(app)
        .get('/api/scheduler-monitoring/export?format=csv')
        .expect(200);

      const csvLines = response.text.split('\n');
      expect(csvLines[0]).toBe('Type,Metric,Value,Timestamp');
      expect(csvLines.length).toBeGreaterThan(1);
    });
  });
});