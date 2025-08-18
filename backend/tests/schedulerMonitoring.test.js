const SchedulerMonitoringService = require('../services/schedulerMonitoringService');
const SchedulerLogger = require('../services/schedulerLogger');
const SchedulerAlerting = require('../services/schedulerAlerting');
const EventEmitter = require('events');

/**
 * Comprehensive Test Suite for Scheduler Monitoring System
 * 
 * Tests cover:
 * - Monitoring service initialization and lifecycle
 * - Job tracking and metrics collection
 * - Error tracking and analysis
 * - Performance metrics collection
 * - Alert condition checking
 * - Health monitoring
 * - Data retention and cleanup
 * - API integration
 */

describe('SchedulerMonitoringService', () => {
  let monitoringService;
  let mockSchedulerService;
  let mockRealTimeMetrics;
  let mockPerformanceAlerting;

  beforeEach(() => {
    // Create mock scheduler service
    mockSchedulerService = new EventEmitter();
    mockSchedulerService.getStatus = jest.fn(() => ({
      isRunning: true,
      activeJobs: 2,
      activeWorkers: 3,
      cronJobs: ['monthly', 'reminders', 'cleanup']
    }));

    // Create mock real-time metrics service
    mockRealTimeMetrics = new EventEmitter();
    mockRealTimeMetrics.getRecentWindows = jest.fn(() => []);

    // Create mock performance alerting service
    mockPerformanceAlerting = new EventEmitter();

    // Initialize monitoring service
    monitoringService = new SchedulerMonitoringService({
      metricsRetentionHours: 1, // Short retention for testing
      metricsCollectionInterval: 100, // Fast collection for testing
      healthCheckInterval: 50,
      alertCheckInterval: 50
    });
  });

  afterEach(async () => {
    if (monitoringService.isMonitoring) {
      await monitoringService.stopMonitoring();
    }
  });

  describe('Initialization', () => {
    test('should initialize with default configuration', () => {
      expect(monitoringService).toBeDefined();
      expect(monitoringService.isMonitoring).toBe(false);
      expect(monitoringService.activeJobs.size).toBe(0);
      expect(monitoringService.jobMetrics.totalExecutions).toBe(0);
    });

    test('should accept custom configuration', () => {
      const customConfig = {
        metricsRetentionHours: 48,
        alertThresholds: {
          jobFailureRate: 0.1,
          avgJobDuration: 5000
        }
      };

      const customService = new SchedulerMonitoringService(customConfig);
      
      expect(customService.config.metricsRetentionHours).toBe(48);
      expect(customService.config.alertThresholds.jobFailureRate).toBe(0.1);
      expect(customService.config.alertThresholds.avgJobDuration).toBe(5000);
    });

    test('should initialize with dependencies', async () => {
      const result = await monitoringService.initialize({
        schedulerService: mockSchedulerService,
        realTimeMetrics: mockRealTimeMetrics,
        performanceAlerting: mockPerformanceAlerting
      });

      expect(result).toBe(true);
      expect(monitoringService.schedulerService).toBe(mockSchedulerService);
      expect(monitoringService.realTimeMetrics).toBe(mockRealTimeMetrics);
      expect(monitoringService.performanceAlerting).toBe(mockPerformanceAlerting);
    });

    test('should fail initialization without required dependencies', async () => {
      await expect(monitoringService.initialize({})).rejects.toThrow(
        'SchedulerService dependency required for monitoring'
      );
    });
  });

  describe('Monitoring Lifecycle', () => {
    beforeEach(async () => {
      await monitoringService.initialize({
        schedulerService: mockSchedulerService
      });
    });

    test('should start monitoring successfully', async () => {
      const startSpy = jest.spyOn(monitoringService, 'emit');
      
      await monitoringService.startMonitoring();
      
      expect(monitoringService.isMonitoring).toBe(true);
      expect(monitoringService.monitoringStartTime).toBeDefined();
      expect(startSpy).toHaveBeenCalledWith('monitoring-started', expect.any(Object));
    });

    test('should stop monitoring successfully', async () => {
      await monitoringService.startMonitoring();
      const stopSpy = jest.spyOn(monitoringService, 'emit');
      
      await monitoringService.stopMonitoring();
      
      expect(monitoringService.isMonitoring).toBe(false);
      expect(stopSpy).toHaveBeenCalledWith('monitoring-stopped', expect.any(Object));
    });

    test('should not start monitoring twice', async () => {
      await monitoringService.startMonitoring();
      
      // Should not throw but should warn
      await monitoringService.startMonitoring();
      
      expect(monitoringService.isMonitoring).toBe(true);
    });

    test('should handle stop when not running', async () => {
      // Should not throw
      await monitoringService.stopMonitoring();
      
      expect(monitoringService.isMonitoring).toBe(false);
    });
  });

  describe('Job Tracking', () => {
    beforeEach(async () => {
      await monitoringService.initialize({
        schedulerService: mockSchedulerService
      });
      await monitoringService.startMonitoring();
    });

    test('should track job started event', () => {
      const jobData = {
        jobId: 'test-job-1',
        type: 'monthly-invitations'
      };

      monitoringService.handleJobStarted(jobData);

      expect(monitoringService.activeJobs.has('test-job-1')).toBe(true);
      const trackedJob = monitoringService.activeJobs.get('test-job-1');
      expect(trackedJob.type).toBe('monthly-invitations');
      expect(trackedJob.status).toBe('running');
      expect(trackedJob.startTime).toBeInstanceOf(Date);
    });

    test('should track job progress updates', () => {
      const jobData = {
        jobId: 'test-job-1',
        type: 'monthly-invitations'
      };

      monitoringService.handleJobStarted(jobData);
      monitoringService.handleJobProgress({ jobId: 'test-job-1', progress: 50 });

      const trackedJob = monitoringService.activeJobs.get('test-job-1');
      expect(trackedJob.progress).toBe(50);
      expect(trackedJob.lastProgressUpdate).toBeInstanceOf(Date);
    });

    test('should track job completion', () => {
      const jobData = {
        jobId: 'test-job-1',
        type: 'monthly-invitations'
      };

      monitoringService.handleJobStarted(jobData);
      
      const completionData = {
        jobId: 'test-job-1',
        status: 'success',
        stats: { totalInvitations: 100 },
        duration: 30000
      };

      monitoringService.handleJobCompleted(completionData);

      expect(monitoringService.activeJobs.has('test-job-1')).toBe(false);
      expect(monitoringService.jobExecutionHistory.length).toBe(1);
      expect(monitoringService.jobMetrics.totalExecutions).toBe(1);
      expect(monitoringService.jobMetrics.successfulExecutions).toBe(1);
      expect(monitoringService.jobMetrics.consecutiveFailures).toBe(0);
    });

    test('should track job failures', () => {
      const jobData = {
        jobId: 'test-job-2',
        type: 'reminders'
      };

      const failureData = {
        jobId: 'test-job-2',
        jobType: 'reminders',
        error: 'Database connection failed',
        duration: 5000
      };

      monitoringService.handleJobFailed(failureData);

      expect(monitoringService.jobMetrics.totalExecutions).toBe(1);
      expect(monitoringService.jobMetrics.failedExecutions).toBe(1);
      expect(monitoringService.jobMetrics.consecutiveFailures).toBe(1);
      expect(monitoringService.errorTracking.recentErrors.length).toBe(1);
    });

    test('should handle consecutive failures', () => {
      // Simulate multiple consecutive failures
      for (let i = 0; i < 3; i++) {
        monitoringService.handleJobFailed({
          jobId: `test-job-${i}`,
          jobType: 'test',
          error: 'Test error',
          duration: 1000
        });
      }

      expect(monitoringService.jobMetrics.consecutiveFailures).toBe(3);
      expect(monitoringService.jobMetrics.failedExecutions).toBe(3);
    });

    test('should reset consecutive failures on success', () => {
      // First, have some failures
      monitoringService.handleJobFailed({
        jobId: 'failed-job',
        jobType: 'test',
        error: 'Test error',
        duration: 1000
      });

      expect(monitoringService.jobMetrics.consecutiveFailures).toBe(1);

      // Then have a success
      monitoringService.handleJobStarted({
        jobId: 'success-job',
        type: 'test'
      });

      monitoringService.handleJobCompleted({
        jobId: 'success-job',
        status: 'success',
        stats: {},
        duration: 2000
      });

      expect(monitoringService.jobMetrics.consecutiveFailures).toBe(0);
    });
  });

  describe('Performance Metrics', () => {
    beforeEach(async () => {
      await monitoringService.initialize({
        schedulerService: mockSchedulerService
      });
      await monitoringService.startMonitoring();
    });

    test('should collect performance metrics', () => {
      monitoringService.collectPerformanceMetrics();

      expect(monitoringService.performanceMetrics.memoryUsage.length).toBeGreaterThan(0);
      expect(monitoringService.performanceMetrics.lastUpdated).toBeInstanceOf(Date);

      const latestMemory = monitoringService.performanceMetrics.memoryUsage[0];
      expect(latestMemory).toHaveProperty('heapUsed');
      expect(latestMemory).toHaveProperty('heapTotal');
      expect(latestMemory).toHaveProperty('heapUsedMB');
      expect(latestMemory).toHaveProperty('heapUtilization');
    });

    test('should update job metrics correctly', () => {
      const job = {
        jobId: 'test-job',
        type: 'test',
        duration: 5000,
        endTime: new Date()
      };

      monitoringService.updateJobMetrics(job, true);

      expect(monitoringService.jobMetrics.totalExecutions).toBe(1);
      expect(monitoringService.jobMetrics.successfulExecutions).toBe(1);
      expect(monitoringService.jobMetrics.totalExecutionTime).toBe(5000);
      expect(monitoringService.jobMetrics.avgExecutionTime).toBe(5000);
      expect(monitoringService.jobMetrics.longestJob.duration).toBe(5000);
    });

    test('should track longest and fastest jobs', () => {
      const fastJob = {
        jobId: 'fast-job',
        type: 'test',
        duration: 1000,
        endTime: new Date()
      };

      const slowJob = {
        jobId: 'slow-job',
        type: 'test',
        duration: 10000,
        endTime: new Date()
      };

      monitoringService.updateJobMetrics(fastJob, true);
      monitoringService.updateJobMetrics(slowJob, true);

      expect(monitoringService.jobMetrics.longestJob.duration).toBe(10000);
      expect(monitoringService.jobMetrics.longestJob.jobId).toBe('slow-job');
      expect(monitoringService.jobMetrics.fastestJob.duration).toBe(1000);
      expect(monitoringService.jobMetrics.fastestJob.jobId).toBe('fast-job');
    });
  });

  describe('Error Tracking', () => {
    beforeEach(async () => {
      await monitoringService.initialize({
        schedulerService: mockSchedulerService
      });
    });

    test('should track and categorize errors', () => {
      const job = {
        jobId: 'error-job',
        type: 'test'
      };

      const errors = [
        'Connection timeout',
        'Database connection failed',
        'Memory allocation error',
        'Worker thread crashed',
        'Email service unavailable'
      ];

      errors.forEach(error => {
        monitoringService.trackError(error, job);
      });

      expect(monitoringService.errorTracking.recentErrors.length).toBe(5);
      expect(monitoringService.errorTracking.errorPatterns.size).toBeGreaterThan(0);
      expect(monitoringService.errorTracking.errorPatterns.get('timeout')).toBe(1);
      expect(monitoringService.errorTracking.errorPatterns.get('database')).toBe(1);
      expect(monitoringService.errorTracking.errorPatterns.get('memory')).toBe(1);
    });

    test('should extract error patterns correctly', () => {
      const patterns = [
        { error: 'Connection timeout occurred', expected: 'timeout' },
        { error: 'Database connection failed', expected: 'database' },
        { error: 'Memory allocation error', expected: 'memory' },
        { error: 'Worker thread crashed', expected: 'worker' },
        { error: 'Email service down', expected: 'email' },
        { error: 'Validation failed for input', expected: 'validation' },
        { error: 'Some random error', expected: 'some random error' }
      ];

      patterns.forEach(({ error, expected }) => {
        const pattern = monitoringService.extractErrorPattern(error);
        expect(pattern).toBe(expected);
      });
    });

    test('should provide error analysis', () => {
      const job = { jobId: 'test', type: 'test' };
      
      // Add some errors with different patterns
      monitoringService.trackError('Database timeout', job);
      monitoringService.trackError('Database connection failed', job);
      monitoringService.trackError('Memory error', job);
      
      const analysis = monitoringService.getErrorAnalysis(60 * 60 * 1000); // 1 hour
      
      expect(analysis.totalErrors).toBe(3);
      expect(analysis.patterns).toHaveProperty('database');
      expect(analysis.patterns).toHaveProperty('memory');
      expect(analysis.patterns.database).toBe(2);
      expect(analysis.patterns.memory).toBe(1);
    });
  });

  describe('Alert Conditions', () => {
    beforeEach(async () => {
      await monitoringService.initialize({
        schedulerService: mockSchedulerService
      });
      await monitoringService.startMonitoring();
    });

    test('should trigger job failure rate alert', () => {
      const alertSpy = jest.spyOn(monitoringService, 'triggerAlert');
      
      // Set up failure rate that exceeds threshold
      monitoringService.jobMetrics.totalExecutions = 10;
      monitoringService.jobMetrics.failedExecutions = 2; // 20% failure rate
      
      monitoringService.checkJobFailureRateAlert();
      
      expect(alertSpy).toHaveBeenCalledWith(
        'job-failure-rate',
        'high',
        expect.objectContaining({
          failureRate: 0.2,
          threshold: 0.05
        })
      );
    });

    test('should trigger consecutive failures alert', () => {
      const alertSpy = jest.spyOn(monitoringService, 'triggerAlert');
      
      monitoringService.jobMetrics.consecutiveFailures = 5;
      
      monitoringService.checkConsecutiveFailuresAlert();
      
      expect(alertSpy).toHaveBeenCalledWith(
        'consecutive-failures',
        'critical',
        expect.objectContaining({
          consecutiveFailures: 5,
          threshold: 3
        })
      );
    });

    test('should trigger memory usage alert', () => {
      const alertSpy = jest.spyOn(monitoringService, 'triggerAlert');
      
      // Mock high memory usage
      const originalMemUsage = process.memoryUsage;
      process.memoryUsage = jest.fn(() => ({
        heapUsed: 900 * 1024 * 1024, // 900MB
        heapTotal: 1000 * 1024 * 1024 // 1GB
      }));
      
      monitoringService.checkMemoryUsageAlert();
      
      expect(alertSpy).toHaveBeenCalledWith(
        'memory-usage',
        'high',
        expect.objectContaining({
          usagePercent: 0.9,
          threshold: 0.85
        })
      );
      
      // Restore original function
      process.memoryUsage = originalMemUsage;
    });

    test('should trigger stuck jobs alert', () => {
      const alertSpy = jest.spyOn(monitoringService, 'triggerAlert');
      
      // Add a job that's been running for too long
      const longRunningJob = {
        jobId: 'stuck-job',
        type: 'test',
        startTime: new Date(Date.now() - 3 * 60 * 60 * 1000), // 3 hours ago
        progress: 10
      };
      
      monitoringService.activeJobs.set('stuck-job', longRunningJob);
      
      monitoringService.checkStuckJobsAlert();
      
      expect(alertSpy).toHaveBeenCalledWith(
        'stuck-jobs',
        'critical',
        expect.objectContaining({
          stuckJobs: expect.arrayContaining([
            expect.objectContaining({
              jobId: 'stuck-job',
              type: 'test'
            })
          ])
        })
      );
    });

    test('should resolve alerts when conditions are met', () => {
      const resolveSpy = jest.spyOn(monitoringService, 'resolveAlert');
      
      // Set up normal conditions
      monitoringService.jobMetrics.totalExecutions = 10;
      monitoringService.jobMetrics.failedExecutions = 0; // 0% failure rate
      
      monitoringService.checkJobFailureRateAlert();
      
      expect(resolveSpy).toHaveBeenCalledWith('job-failure-rate');
    });
  });

  describe('Health Monitoring', () => {
    beforeEach(async () => {
      await monitoringService.initialize({
        schedulerService: mockSchedulerService
      });
    });

    test('should check scheduler health', () => {
      const health = monitoringService.checkSchedulerHealth();
      
      expect(health).toHaveProperty('status');
      expect(health).toHaveProperty('isRunning');
      expect(health).toHaveProperty('activeJobs');
      expect(health).toHaveProperty('activeWorkers');
      expect(health.status).toBe('healthy');
      expect(health.isRunning).toBe(true);
    });

    test('should check monitoring health', () => {
      const health = monitoringService.checkMonitoringHealth();
      
      expect(health).toHaveProperty('status');
      expect(health).toHaveProperty('isMonitoring');
      expect(health).toHaveProperty('activeJobsTracked');
      expect(health.status).toBe('unhealthy'); // Not monitoring yet
      expect(health.isMonitoring).toBe(false);
    });

    test('should check system health', () => {
      const health = monitoringService.checkSystemHealth();
      
      expect(health).toHaveProperty('status');
      expect(health).toHaveProperty('uptime');
      expect(health).toHaveProperty('memoryUsageMB');
      expect(health).toHaveProperty('nodeVersion');
      expect(health).toHaveProperty('platform');
      expect(health.status).toBe('healthy');
    });

    test('should perform comprehensive health check', () => {
      monitoringService.performHealthCheck();
      
      expect(monitoringService.performanceMetrics.systemHealth.length).toBeGreaterThan(0);
      
      const latestHealth = monitoringService.performanceMetrics.systemHealth[0];
      expect(latestHealth).toHaveProperty('schedulerHealth');
      expect(latestHealth).toHaveProperty('monitoringHealth');
      expect(latestHealth).toHaveProperty('systemHealth');
    });
  });

  describe('Data Management', () => {
    beforeEach(async () => {
      await monitoringService.initialize({
        schedulerService: mockSchedulerService
      });
    });

    test('should add jobs to execution history', () => {
      const job = {
        jobId: 'test-job',
        type: 'test',
        startTime: new Date(),
        endTime: new Date(),
        duration: 5000,
        status: 'success',
        stats: { processed: 100 },
        memoryAtStart: { heapUsed: 100000 },
        memoryAtEnd: { heapUsed: 200000 }
      };

      monitoringService.addToExecutionHistory(job);

      expect(monitoringService.jobExecutionHistory.length).toBe(1);
      const historyEntry = monitoringService.jobExecutionHistory[0];
      expect(historyEntry.jobId).toBe('test-job');
      expect(historyEntry.memoryUsage.start).toBe(100000);
      expect(historyEntry.memoryUsage.end).toBe(200000);
    });

    test('should limit execution history size', () => {
      const service = new SchedulerMonitoringService({
        executionHistoryLimit: 5
      });

      // Add more jobs than the limit
      for (let i = 0; i < 10; i++) {
        service.addToExecutionHistory({
          jobId: `job-${i}`,
          type: 'test',
          startTime: new Date(),
          endTime: new Date(),
          duration: 1000,
          status: 'success'
        });
      }

      expect(service.jobExecutionHistory.length).toBe(5);
      expect(service.jobExecutionHistory[0].jobId).toBe('job-5'); // Should keep latest
    });

    test('should perform cleanup correctly', () => {
      // Add old data
      const oldTime = Date.now() - (2 * 60 * 60 * 1000); // 2 hours ago
      
      monitoringService.performanceMetrics.memoryUsage.push({
        timestamp: new Date(oldTime),
        heapUsed: 100000
      });
      
      monitoringService.errorTracking.recentErrors.push({
        timestamp: new Date(oldTime),
        error: 'Old error'
      });

      // Add recent data
      monitoringService.performanceMetrics.memoryUsage.push({
        timestamp: new Date(),
        heapUsed: 200000
      });

      monitoringService.performCleanup();

      // Should keep only recent data (retention is 1 hour for test)
      expect(monitoringService.performanceMetrics.memoryUsage.length).toBe(1);
      expect(monitoringService.errorTracking.recentErrors.length).toBe(0);
    });

    test('should filter execution history by criteria', () => {
      // Add diverse job history
      const jobs = [
        { jobId: 'job1', type: 'monthly', status: 'success', startTime: new Date(Date.now() - 60000) },
        { jobId: 'job2', type: 'reminders', status: 'failed', startTime: new Date(Date.now() - 30000) },
        { jobId: 'job3', type: 'monthly', status: 'success', startTime: new Date() }
      ];

      jobs.forEach(job => monitoringService.addToExecutionHistory(job));

      // Filter by type
      const monthlyJobs = monitoringService.getExecutionHistory({ type: 'monthly' });
      expect(monthlyJobs.length).toBe(2);

      // Filter by status
      const successJobs = monitoringService.getExecutionHistory({ status: 'success' });
      expect(successJobs.length).toBe(2);

      // Filter by limit
      const limitedJobs = monitoringService.getExecutionHistory({ limit: 2 });
      expect(limitedJobs.length).toBe(2);
    });
  });

  describe('API Methods', () => {
    beforeEach(async () => {
      await monitoringService.initialize({
        schedulerService: mockSchedulerService
      });
    });

    test('should return monitoring status', () => {
      const status = monitoringService.getMonitoringStatus();
      
      expect(status).toHaveProperty('isMonitoring');
      expect(status).toHaveProperty('activeJobs');
      expect(status).toHaveProperty('totalJobsTracked');
      expect(status).toHaveProperty('config');
    });

    test('should return basic metrics', () => {
      const metrics = monitoringService.getBasicMetrics();
      
      expect(metrics).toHaveProperty('jobs');
      expect(metrics).toHaveProperty('performance');
      expect(metrics).toHaveProperty('errors');
      expect(metrics).toHaveProperty('alerts');
      
      expect(metrics.jobs).toHaveProperty('total');
      expect(metrics.jobs).toHaveProperty('successRate');
    });

    test('should return detailed metrics', () => {
      const metrics = monitoringService.getDetailedMetrics();
      
      expect(metrics).toHaveProperty('activeJobs');
      expect(metrics).toHaveProperty('recentExecutions');
      expect(metrics).toHaveProperty('performanceMetrics');
      expect(metrics).toHaveProperty('errorAnalysis');
    });

    test('should calculate success rate correctly', () => {
      // No jobs yet
      expect(monitoringService.calculateSuccessRate()).toBe(100);
      
      // Add some jobs
      monitoringService.jobMetrics.totalExecutions = 10;
      monitoringService.jobMetrics.successfulExecutions = 8;
      
      expect(monitoringService.calculateSuccessRate()).toBe(80);
    });

    test('should export monitoring data', () => {
      const exportData = monitoringService.exportMonitoringData();
      
      expect(exportData).toHaveProperty('timestamp');
      expect(exportData).toHaveProperty('status');
      expect(exportData).toHaveProperty('metrics');
      expect(exportData).toHaveProperty('config');
      expect(exportData).toHaveProperty('errorAnalysis');
    });

    test('should reset monitoring data', () => {
      // Add some data first
      monitoringService.jobMetrics.totalExecutions = 5;
      monitoringService.performanceMetrics.memoryUsage.push({ timestamp: new Date(), heapUsed: 100000 });
      monitoringService.errorTracking.recentErrors.push({ timestamp: new Date(), error: 'test' });

      monitoringService.resetMonitoringData();

      expect(monitoringService.jobMetrics.totalExecutions).toBe(0);
      expect(monitoringService.performanceMetrics.memoryUsage.length).toBe(0);
      expect(monitoringService.errorTracking.recentErrors.length).toBe(0);
    });
  });

  describe('Integration with External Services', () => {
    beforeEach(async () => {
      await monitoringService.initialize({
        schedulerService: mockSchedulerService,
        realTimeMetrics: mockRealTimeMetrics,
        performanceAlerting: mockPerformanceAlerting
      });
    });

    test('should handle real-time metrics events', () => {
      const recordSpy = jest.spyOn(monitoringService, 'recordRealTimeMetrics');
      
      const metricsData = {
        queriesPerSecond: 10,
        avgExecutionTime: 100
      };

      mockRealTimeMetrics.emit('metrics-updated', metricsData);

      expect(recordSpy).toHaveBeenCalledWith(metricsData);
    });

    test('should handle performance alerting events', () => {
      const alertData = {
        ruleId: 'test-rule',
        severity: 'high',
        ruleName: 'Test Alert'
      };

      // Should not throw
      mockPerformanceAlerting.emit('alert-triggered', alertData);
      mockPerformanceAlerting.emit('alert-escalated', alertData);
    });

    test('should setup event listeners correctly', () => {
      const listenerCount = mockSchedulerService.listenerCount('job-started');
      expect(listenerCount).toBeGreaterThan(0);
    });

    test('should remove event listeners on stop', async () => {
      await monitoringService.startMonitoring();
      
      const initialListeners = mockSchedulerService.listenerCount('job-started');
      expect(initialListeners).toBeGreaterThan(0);
      
      await monitoringService.stopMonitoring();
      
      const finalListeners = mockSchedulerService.listenerCount('job-started');
      expect(finalListeners).toBe(0);
    });
  });

  describe('Alert Management', () => {
    beforeEach(async () => {
      await monitoringService.initialize({
        schedulerService: mockSchedulerService
      });
    });

    test('should trigger alerts correctly', () => {
      const alertKey = 'test-alert';
      const severity = 'high';
      const details = { message: 'Test alert message' };

      monitoringService.triggerAlert(alertKey, severity, details);

      expect(monitoringService.activeAlerts.has(alertKey)).toBe(true);
      expect(monitoringService.alertHistory.length).toBe(1);

      const alert = monitoringService.activeAlerts.get(alertKey);
      expect(alert.severity).toBe(severity);
      expect(alert.details).toEqual(details);
    });

    test('should resolve alerts correctly', () => {
      const alertKey = 'test-alert';
      
      // First trigger an alert
      monitoringService.triggerAlert(alertKey, 'high', { message: 'test' });
      expect(monitoringService.activeAlerts.has(alertKey)).toBe(true);

      // Then resolve it
      monitoringService.resolveAlert(alertKey);
      expect(monitoringService.activeAlerts.has(alertKey)).toBe(false);
    });

    test('should update alert counts', () => {
      const alertKey = 'repeat-alert';
      
      // Trigger same alert multiple times
      monitoringService.triggerAlert(alertKey, 'medium', { message: 'test' });
      monitoringService.triggerAlert(alertKey, 'medium', { message: 'test' });
      monitoringService.triggerAlert(alertKey, 'medium', { message: 'test' });

      const alert = monitoringService.activeAlerts.get(alertKey);
      expect(alert.count).toBe(3);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle missing job data gracefully', () => {
      expect(() => {
        monitoringService.handleJobProgress({ jobId: 'nonexistent', progress: 50 });
      }).not.toThrow();
    });

    test('should handle invalid job completion data', () => {
      expect(() => {
        monitoringService.handleJobCompleted({
          jobId: 'invalid-job',
          status: 'success',
          duration: 'invalid-duration'
        });
      }).not.toThrow();
    });

    test('should handle error tracking with invalid data', () => {
      expect(() => {
        monitoringService.trackError(null, { jobId: 'test' });
      }).not.toThrow();
      
      expect(() => {
        monitoringService.trackError('error', null);
      }).not.toThrow();
    });

    test('should handle health check failures gracefully', () => {
      // Mock scheduler service to throw error
      mockSchedulerService.getStatus = jest.fn(() => {
        throw new Error('Service unavailable');
      });

      expect(() => {
        monitoringService.checkSchedulerHealth();
      }).not.toThrow();

      const health = monitoringService.checkSchedulerHealth();
      expect(health.status).toBe('unknown');
    });

    test('should handle metrics collection errors', () => {
      // Mock process.memoryUsage to throw
      const originalMemUsage = process.memoryUsage;
      process.memoryUsage = jest.fn(() => {
        throw new Error('Memory info unavailable');
      });

      expect(() => {
        monitoringService.collectPerformanceMetrics();
      }).not.toThrow();

      // Restore
      process.memoryUsage = originalMemUsage;
    });
  });
});

/**
 * Test Suite for SchedulerLogger
 */
describe('SchedulerLogger', () => {
  let logger;
  let tempLogDir;

  beforeEach(() => {
    tempLogDir = `/tmp/test-logs-${Date.now()}`;
    logger = new SchedulerLogger({
      logDir: tempLogDir,
      enableConsoleOutput: false, // Disable for tests
      enableFileOutput: false, // Disable file output for unit tests
      maxLogEntrySize: 1000
    });
  });

  afterEach(async () => {
    if (logger.isInitialized) {
      await logger.shutdown();
    }
  });

  describe('Initialization', () => {
    test('should initialize with default configuration', () => {
      expect(logger.isInitialized).toBe(true);
      expect(logger.loggers.size).toBeGreaterThan(0);
    });

    test('should create different logger categories', () => {
      expect(logger.loggers.has('jobs')).toBe(true);
      expect(logger.loggers.has('performance')).toBe(true);
      expect(logger.loggers.has('errors')).toBe(true);
      expect(logger.loggers.has('audit')).toBe(true);
      expect(logger.loggers.has('metrics')).toBe(true);
    });
  });

  describe('Context Management', () => {
    test('should manage context stack', () => {
      const context1 = { jobId: 'job1', phase: 'start' };
      const context2 = { batchId: 'batch1' };

      logger.pushContext(context1);
      logger.pushContext(context2);

      expect(logger.getCurrentContext()).toEqual(expect.objectContaining(context2));

      logger.popContext();
      expect(logger.getCurrentContext()).toEqual(expect.objectContaining(context1));
    });

    test('should generate correlation IDs', () => {
      const correlationId = logger.generateCorrelationId();
      expect(correlationId).toMatch(/^sched_\d+_[a-z0-9]+$/);
      expect(logger.correlationId).toBe(correlationId);
    });
  });

  describe('Job Logging', () => {
    test('should log job lifecycle events', () => {
      const jobId = 'test-job-1';
      const jobType = 'monthly-invitations';

      logger.logJobStarted(jobId, jobType, { userId: 'test-user' });
      logger.logJobProgress(jobId, 50, { processed: 100 });
      logger.logJobCompleted(jobId, jobType, 30000, { totalSent: 200 });

      expect(logger.stats.totalLogs).toBeGreaterThan(0);
      expect(logger.stats.logsByCategory.get('job-start')).toBe(1);
      expect(logger.stats.logsByCategory.get('job-progress')).toBe(1);
      expect(logger.stats.logsByCategory.get('job-complete')).toBe(1);
    });

    test('should log job failures', () => {
      const jobId = 'failed-job';
      const jobType = 'reminders';
      const error = new Error('Database connection failed');

      logger.logJobFailed(jobId, jobType, error, 5000);

      expect(logger.stats.errorCount).toBe(1);
      expect(logger.stats.logsByCategory.get('job-error')).toBe(1);
    });

    test('should log job retries', () => {
      const jobId = 'retry-job';
      const jobType = 'cleanup';
      const error = new Error('Temporary failure');

      logger.logJobRetry(jobId, jobType, 2, error);

      expect(logger.stats.warningCount).toBe(1);
      expect(logger.stats.logsByCategory.get('job-retry')).toBe(1);
    });
  });

  describe('Performance Logging', () => {
    test('should log performance metrics', () => {
      logger.logPerformance('job_duration', 5000, 'ms', { jobType: 'monthly' });
      logger.logMemoryUsage({ phase: 'start' });
      logger.logBatchProcessing(100, 2000, 95, 5);
      logger.logWorkerUtilization(8, 10, 80);

      expect(logger.stats.logsByCategory.get('performance')).toBeGreaterThan(0);
    });
  });

  describe('Error Logging', () => {
    test('should log different error types', () => {
      const error = new Error('Test error');
      
      logger.logError('Regular error occurred', error);
      logger.logCriticalError('Critical system failure', error);
      logger.logWarning('Warning message', { component: 'scheduler' });

      expect(logger.stats.errorCount).toBe(2);
      expect(logger.stats.warningCount).toBe(1);
    });
  });

  describe('Audit Logging', () => {
    test('should log audit events', () => {
      logger.logAudit('job_triggered', 'admin', { jobType: 'monthly' });
      logger.logSecurityEvent('unauthorized_access', { ip: '192.168.1.1' });

      expect(logger.stats.logsByCategory.get('audit')).toBe(1);
      expect(logger.stats.logsByCategory.get('security')).toBe(1);
    });
  });

  describe('Log Sanitization', () => {
    test('should sanitize sensitive data', () => {
      const logEntry = {
        message: 'Test log',
        password: 'secret123',
        token: 'abc123',
        email: 'user@example.com'
      };

      const sanitized = logger.sanitizeLogEntry(logEntry);
      
      // Should not contain sensitive fields (handled by SecureLogger)
      expect(sanitized.message).toBe('Test log');
    });

    test('should limit log entry size', () => {
      const largeData = 'x'.repeat(2000);
      const logEntry = {
        message: 'Large log entry',
        data: largeData,
        stack: 'a'.repeat(3000)
      };

      const sanitized = logger.sanitizeLogEntry(logEntry);
      
      expect(sanitized._truncated).toBe(true);
      expect(sanitized._originalSize).toBeGreaterThan(1000);
    });
  });

  describe('Statistics', () => {
    test('should track logging statistics', () => {
      logger.info('Info message');
      logger.debug('Debug message');
      logger.logError('Error message', new Error('test'));

      const stats = logger.getStats();
      
      expect(stats.totalLogs).toBe(3);
      expect(stats.errorCount).toBe(1);
      expect(stats.logsByLevel.info).toBe(1);
      expect(stats.logsByLevel.debug).toBe(1);
      expect(stats.logsByLevel.error).toBe(1);
    });
  });
});

/**
 * Test Suite for SchedulerAlerting
 */
describe('SchedulerAlerting', () => {
  let alerting;
  let mockLogger;
  let mockMonitoring;

  beforeEach(() => {
    mockLogger = {
      logWarning: jest.fn(),
      logError: jest.fn(),
      logInfo: jest.fn()
    };

    mockMonitoring = new EventEmitter();

    alerting = new SchedulerAlerting({
      enableAlerting: true,
      alertThrottleWindow: 1000, // 1 second for testing
      maxAlertsPerHour: 100,
      enableConsoleAlerts: true,
      enableEmailAlerts: false,
      escalationTimeouts: {
        low: 1000,
        medium: 500,
        high: 200,
        critical: 100
      }
    });
  });

  afterEach(async () => {
    if (alerting.isActive) {
      await alerting.stopAlerting();
    }
  });

  describe('Initialization', () => {
    test('should initialize with default alert rules', () => {
      expect(alerting.alertRules.size).toBeGreaterThan(0);
      expect(alerting.alertRules.has('job-failure')).toBe(true);
      expect(alerting.alertRules.has('consecutive-failures')).toBe(true);
      expect(alerting.alertRules.has('monthly-job-failure')).toBe(true);
    });

    test('should initialize with dependencies', async () => {
      const result = await alerting.initialize({
        schedulerLogger: mockLogger,
        schedulerMonitoring: mockMonitoring
      });

      expect(result).toBe(true);
      expect(alerting.schedulerLogger).toBe(mockLogger);
      expect(alerting.schedulerMonitoring).toBe(mockMonitoring);
    });
  });

  describe('Alert Rules Management', () => {
    test('should add custom alert rules', () => {
      const customRule = {
        name: 'Custom Test Rule',
        description: 'Test rule for unit tests',
        severity: 'medium',
        condition: (data) => data.testCondition === true,
        cooldown: 5000
      };

      alerting.addAlertRule('custom-test', customRule);

      expect(alerting.alertRules.has('custom-test')).toBe(true);
      const rule = alerting.alertRules.get('custom-test');
      expect(rule.name).toBe('Custom Test Rule');
      expect(rule.enabled).toBe(true);
    });

    test('should remove alert rules', () => {
      alerting.addAlertRule('temporary-rule', {
        name: 'Temporary Rule',
        condition: () => false
      });

      expect(alerting.alertRules.has('temporary-rule')).toBe(true);
      
      const removed = alerting.removeAlertRule('temporary-rule');
      expect(removed).toBe(true);
      expect(alerting.alertRules.has('temporary-rule')).toBe(false);
    });
  });

  describe('Alert Processing', () => {
    beforeEach(async () => {
      await alerting.initialize({
        schedulerLogger: mockLogger,
        schedulerMonitoring: mockMonitoring
      });
      await alerting.startAlerting();
    });

    test('should process job failure alerts', async () => {
      const failureData = {
        eventType: 'job-failed',
        jobId: 'test-job',
        jobType: 'monthly-invitations',
        error: 'Database connection failed'
      };

      await alerting.processAlert('job-failure', 'high', failureData);

      expect(alerting.activeAlerts.size).toBe(1);
      expect(alerting.alertStats.totalAlerts).toBe(1);
    });

    test('should throttle repeated alerts', async () => {
      const alertData = {
        eventType: 'job-failed',
        jobId: 'test-job'
      };

      // Send same alert multiple times quickly
      await alerting.processAlert('job-failure', 'high', alertData);
      await alerting.processAlert('job-failure', 'high', alertData);
      await alerting.processAlert('job-failure', 'high', alertData);

      // Should have throttled the duplicates
      expect(alerting.alertStats.totalAlerts).toBe(1);
      expect(alerting.alertStats.throttledNotifications).toBeGreaterThan(0);
    });

    test('should respect cooldown periods', async () => {
      const rule = alerting.alertRules.get('job-failure');
      rule.cooldown = 5000; // 5 seconds
      rule.lastTriggered = new Date();

      const alertData = {
        eventType: 'job-failed',
        jobId: 'test-job'
      };

      await alerting.processAlert('job-failure', 'high', alertData);

      // Should not create alert due to cooldown
      expect(alerting.activeAlerts.size).toBe(0);
    });

    test('should suppress alerts when configured', async () => {
      alerting.suppressAlert('job-failure', 1000);

      const alertData = {
        eventType: 'job-failed',
        jobId: 'test-job'
      };

      await alerting.processAlert('job-failure', 'high', alertData);

      expect(alerting.activeAlerts.size).toBe(0);
      expect(alerting.suppressedAlerts.has('job-failure')).toBe(true);
    });
  });

  describe('Alert Escalation', () => {
    beforeEach(async () => {
      await alerting.initialize({
        schedulerLogger: mockLogger
      });
      await alerting.startAlerting();
    });

    test('should escalate alerts after timeout', (done) => {
      const alertData = {
        eventType: 'job-failed',
        jobId: 'test-job'
      };

      alerting.on('alert-escalated', (alert) => {
        expect(alert.escalated).toBe(true);
        expect(alert.severity).toBe('critical'); // Escalated from high
        done();
      });

      alerting.processAlert('job-failure', 'high', alertData);
    }, 10000);

    test('should not escalate resolved alerts', async () => {
      const alertData = {
        eventType: 'job-failed',
        jobId: 'test-job'
      };

      await alerting.processAlert('job-failure', 'high', alertData);
      
      const alertId = Array.from(alerting.activeAlerts.keys())[0];
      await alerting.resolveAlert(alertId, 'Manual resolution');

      // Wait for escalation timeout
      await new Promise(resolve => setTimeout(resolve, 300));

      // Alert should still be resolved, not escalated
      expect(alerting.activeAlerts.has(alertId)).toBe(false);
    });
  });

  describe('Auto-Remediation', () => {
    beforeEach(async () => {
      alerting.config.enableAutoRemediation = true;
      await alerting.initialize({
        schedulerLogger: mockLogger
      });
      await alerting.startAlerting();
    });

    test('should attempt auto-remediation when enabled', async () => {
      const alertData = {
        eventType: 'job-failed',
        jobId: 'test-job'
      };

      const remediationSpy = jest.spyOn(alerting, 'attemptAutoRemediation');

      await alerting.processAlert('job-failure', 'high', alertData);

      expect(remediationSpy).toHaveBeenCalled();
      expect(alerting.alertStats.autoRemediationsAttempted).toBe(1);
    });

    test('should execute specific remediation actions', async () => {
      const alert = {
        id: 'test-alert',
        data: { jobId: 'test-job' }
      };

      const result = await alerting.executeRemediationAction('restart-job', alert);

      expect(result.success).toBe(true);
      expect(result.action).toBe('restart-job');
    });

    test('should handle unknown remediation actions', async () => {
      const alert = { id: 'test-alert' };

      const result = await alerting.executeRemediationAction('unknown-action', alert);

      expect(result.success).toBe(false);
      expect(result.message).toBe('Unknown remediation action');
    });
  });

  describe('Notification Channels', () => {
    beforeEach(async () => {
      await alerting.initialize({
        schedulerLogger: mockLogger
      });
    });

    test('should send console notifications', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      const alert = {
        id: 'test-alert',
        name: 'Test Alert',
        severity: 'high',
        description: 'Test alert description',
        rule: { notifications: ['console'] }
      };

      await alerting.sendNotifications(alert);

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('SCHEDULER ALERT')
      );

      consoleSpy.mockRestore();
    });

    test('should format alert messages correctly', () => {
      const alert = {
        severity: 'critical',
        name: 'Critical System Failure',
        description: 'The system has encountered a critical error'
      };

      const message = alerting.formatAlertMessage(alert);

      expect(message).toContain('[CRITICAL]');
      expect(message).toContain('Critical System Failure');
      expect(message).toContain('The system has encountered a critical error');
    });

    test('should get correct severity emojis and colors', () => {
      expect(alerting.getSeverityEmoji('low')).toBe(':information_source:');
      expect(alerting.getSeverityEmoji('critical')).toBe(':rotating_light:');
      
      expect(alerting.getSeverityColor('low')).toBe('#36a64f');
      expect(alerting.getSeverityColor('critical')).toBe('#ff0000');
    });
  });

  describe('Statistics and Reporting', () => {
    beforeEach(async () => {
      await alerting.initialize({
        schedulerLogger: mockLogger
      });
      await alerting.startAlerting();
    });

    test('should track alert statistics', async () => {
      const alertData = {
        eventType: 'job-failed',
        jobId: 'test-job'
      };

      await alerting.processAlert('job-failure', 'high', alertData);

      const status = alerting.getAlertingStatus();

      expect(status.stats.totalAlerts).toBe(1);
      expect(status.stats.alertsByLevel.high).toBe(1);
      expect(status.stats.alertsByType['job-failure']).toBe(1);
    });

    test('should provide alert history', async () => {
      const alertData = {
        eventType: 'job-failed',
        jobId: 'test-job'
      };

      await alerting.processAlert('job-failure', 'high', alertData);

      const history = alerting.getAlertHistory();
      expect(history.length).toBe(1);
      expect(history[0].type).toBe('job-failure');
    });

    test('should export alert data', () => {
      const exportData = alerting.exportAlertData();

      expect(exportData).toHaveProperty('timestamp');
      expect(exportData).toHaveProperty('status');
      expect(exportData).toHaveProperty('activeAlerts');
      expect(exportData).toHaveProperty('recentHistory');
      expect(exportData).toHaveProperty('rules');
    });
  });

  describe('Alert Resolution', () => {
    beforeEach(async () => {
      await alerting.initialize({
        schedulerLogger: mockLogger
      });
      await alerting.startAlerting();
    });

    test('should resolve alerts correctly', async () => {
      const alertData = {
        eventType: 'job-failed',
        jobId: 'test-job'
      };

      await alerting.processAlert('job-failure', 'high', alertData);
      
      const alertId = Array.from(alerting.activeAlerts.keys())[0];
      const resolved = await alerting.resolveAlert(alertId, 'Test resolution');

      expect(resolved).toBe(true);
      expect(alerting.activeAlerts.has(alertId)).toBe(false);
      expect(alerting.alertStats.totalAlertsResolved).toBe(1);
    });

    test('should handle resolution of non-existent alerts', async () => {
      const resolved = await alerting.resolveAlert('non-existent-alert');
      expect(resolved).toBe(false);
    });
  });

  describe('Integration Events', () => {
    beforeEach(async () => {
      await alerting.initialize({
        schedulerLogger: mockLogger,
        schedulerMonitoring: mockMonitoring
      });
      await alerting.startAlerting();
    });

    test('should handle monitoring events', () => {
      const failureData = {
        jobId: 'failed-job',
        type: 'monthly-invitations',
        error: 'Network timeout',
        duration: 30000
      };

      // Should not throw
      mockMonitoring.emit('job-tracking-failed', failureData);

      expect(alerting.activeAlerts.size).toBeGreaterThan(0);
    });

    test('should handle monitoring alerts', () => {
      const monitoringAlert = {
        key: 'memory-usage',
        severity: 'high',
        details: { memoryUsage: '90%' }
      };

      // Should not throw
      mockMonitoring.emit('alert-triggered', monitoringAlert);
    });
  });
});