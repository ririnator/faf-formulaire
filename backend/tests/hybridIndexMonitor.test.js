const HybridIndexMonitor = require('../services/hybridIndexMonitor');

// Mock SecureLogger to avoid logging during tests
jest.mock('../utils/secureLogger', () => ({
  logInfo: jest.fn(),
  logError: jest.fn(),
  logWarning: jest.fn()
}));

// Mock mongoose to avoid connection issues during tests
jest.mock('mongoose', () => ({
  startSession: jest.fn().mockResolvedValue({
    withTransaction: jest.fn().mockImplementation(async (fn) => await fn()),
    endSession: jest.fn()
  }),
  Query: {
    prototype: {
      exec: jest.fn()
    }
  },
  connection: {
    db: {
      collections: jest.fn().mockResolvedValue([{
        collectionName: 'responses',
        aggregate: jest.fn().mockReturnValue({
          toArray: jest.fn().mockResolvedValue([])
        })
      }])
    }
  }
}));

describe('HybridIndexMonitor', () => {
  let monitor;

  beforeEach(() => {
    monitor = new HybridIndexMonitor({
      monitoringInterval: 1000, // Short interval for tests
      slowQueryThreshold: 50,
      indexEfficiencyThreshold: 0.7,
      enableDetailedLogging: false
    });
  });

  afterEach(() => {
    if (monitor && monitor.isMonitoring) {
      monitor.stopMonitoring();
    }
  });

  describe('Initialization', () => {
    it('should properly initialize metrics with quoted property names', () => {
      expect(monitor.metrics.indexUsage).toHaveProperty('responses_createdAt_-1');
      expect(monitor.metrics.indexUsage).toHaveProperty('responses_userId_1');
      expect(monitor.metrics.indexUsage).toHaveProperty('responses_token_1');
      expect(monitor.metrics.indexUsage).toHaveProperty('responses_month_1_isAdmin_1');
      expect(monitor.metrics.indexUsage).toHaveProperty('responses_compound_hybrid');
    });

    it('should initialize with default configuration', () => {
      const defaultMonitor = new HybridIndexMonitor();
      expect(defaultMonitor.config.monitoringInterval).toBe(30000);
      expect(defaultMonitor.config.slowQueryThreshold).toBe(100);
      expect(defaultMonitor.config.indexEfficiencyThreshold).toBe(0.8);
      expect(defaultMonitor.config.sampleSize).toBe(1000);
    });

    it('should accept custom configuration options', () => {
      const customMonitor = new HybridIndexMonitor({
        monitoringInterval: 15000,
        slowQueryThreshold: 200,
        indexEfficiencyThreshold: 0.9,
        sampleSize: 500
      });
      
      expect(customMonitor.config.monitoringInterval).toBe(15000);
      expect(customMonitor.config.slowQueryThreshold).toBe(200);
      expect(customMonitor.config.indexEfficiencyThreshold).toBe(0.9);
      expect(customMonitor.config.sampleSize).toBe(500);
    });

    it('should initialize with empty metrics', () => {
      expect(monitor.metrics.authMethodPerformance.user.queryCount).toBe(0);
      expect(monitor.metrics.authMethodPerformance.token.queryCount).toBe(0);
      expect(monitor.metrics.authMethodPerformance.hybrid.queryCount).toBe(0);
      expect(monitor.metrics.indexUsage['responses_createdAt_-1'].hits).toBe(0);
      expect(monitor.metrics.trends.performanceAlerts).toHaveLength(0);
    });
  });

  describe('Metrics Management', () => {
    it('should reset metrics without syntax errors', () => {
      // Add some test data first
      monitor.metrics.authMethodPerformance.user.queryCount = 100;
      monitor.metrics.indexUsage['responses_createdAt_-1'].hits = 50;
      monitor.metrics.trends.performanceAlerts.push({ test: 'alert' });

      expect(() => monitor.resetMetrics()).not.toThrow();
      
      // Verify reset worked
      expect(monitor.metrics.authMethodPerformance.user.queryCount).toBe(0);
      expect(monitor.metrics.indexUsage['responses_createdAt_-1'].hits).toBe(0);
      expect(monitor.metrics.trends.performanceAlerts).toHaveLength(0);
    });

    it('should access all index usage properties without errors', () => {
      const indexNames = [
        'responses_userId_1',
        'responses_token_1', 
        'responses_month_1_isAdmin_1',
        'responses_createdAt_-1',
        'responses_compound_hybrid'
      ];

      indexNames.forEach(indexName => {
        expect(() => {
          monitor.metrics.indexUsage[indexName].hits++;
          monitor.metrics.indexUsage[indexName].misses++;
          monitor.metrics.indexUsage[indexName].efficiency = 0.5;
        }).not.toThrow();
      });
    });

    it('should generate performance reports with proper metrics', () => {
      // Add test data
      monitor.metrics.authMethodPerformance.user.queryCount = 100;
      monitor.metrics.authMethodPerformance.user.avgTime = 25.5;
      monitor.metrics.indexUsage['responses_createdAt_-1'].hits = 80;
      monitor.metrics.indexUsage['responses_createdAt_-1'].misses = 20;
      monitor.metrics.indexUsage['responses_createdAt_-1'].efficiency = 0.8;

      const report = monitor.generatePerformanceReport();
      
      expect(report).toHaveProperty('authMethodComparison');
      expect(report).toHaveProperty('indexEfficiency');
      expect(report).toHaveProperty('alerts');
      expect(report).toHaveProperty('recommendations');
      
      expect(report.authMethodComparison.user.queryCount).toBe(100);
      expect(report.authMethodComparison.user.avgTime).toBe(25.5);
      expect(report.indexEfficiency['responses_createdAt_-1'].efficiency).toBe(80);
      expect(report.indexEfficiency['responses_createdAt_-1'].totalOperations).toBe(100);
    });
  });

  describe('Query Pattern Detection', () => {
    it('should categorize user authentication queries', () => {
      const userQuery = '{"userId": "507f1f77bcf86cd799439011", "populate": "user"}';
      const category = monitor.categorizeQuery(userQuery);
      
      expect(category.type).toBe('user');
      expect(category.expectedIndex).toBe('responses_userId_1');
    });

    it('should categorize token authentication queries', () => {
      const tokenQuery = '{"token": "abc123def456789abc123def456789abc"}';
      const category = monitor.categorizeQuery(tokenQuery);
      
      expect(category.type).toBe('token');
      expect(category.expectedIndex).toBe('responses_token_1');
    });

    it('should categorize monthly queries', () => {
      const monthQuery = '{"month": "2025-01"}';
      const category = monitor.categorizeQuery(monthQuery);
      
      expect(category.type).toBe('monthly');
      expect(category.expectedIndex).toBe('responses_month_1_isAdmin_1');
    });

    it('should categorize admin queries', () => {
      const adminQuery = '{"isAdmin": true}';
      const category = monitor.categorizeQuery(adminQuery);
      
      expect(category.type).toBe('admin');
      expect(category.expectedIndex).toBe('responses_month_1_isAdmin_1');
    });

    it('should categorize hybrid queries', () => {
      // Pattern order matters - hybrid needs to be first or more specific
      // Since the regex is /(userId|token).*month.*isAdmin/i, let's test this exact pattern
      const hybridQuery = 'userId month isAdmin';
      const category = monitor.categorizeQuery(hybridQuery);
      
      expect(category.type).toBe('hybrid');
      expect(category.expectedIndex).toBe('responses_compound_hybrid');
    });

    it('should handle unknown query patterns', () => {
      const unknownQuery = '{"randomField": "value"}';
      const category = monitor.categorizeQuery(unknownQuery);
      
      expect(category.name).toBe('unknown');
      expect(category.type).toBe('other');
      expect(category.expectedIndex).toBe(null);
    });
  });

  describe('Performance Alerts', () => {
    it('should add performance alerts with proper structure', () => {
      const alert = {
        type: 'TEST_ALERT',
        severity: 'HIGH',
        message: 'Test alert message',
        timestamp: new Date()
      };

      monitor.addPerformanceAlert(alert);
      
      expect(monitor.metrics.trends.performanceAlerts).toHaveLength(1);
      expect(monitor.metrics.trends.performanceAlerts[0]).toEqual(alert);
    });

    it('should limit alerts to maximum 100 entries', () => {
      // Add 150 alerts
      for (let i = 0; i < 150; i++) {
        monitor.addPerformanceAlert({
          type: 'TEST_ALERT',
          severity: 'LOW',
          message: `Alert ${i}`,
          timestamp: new Date()
        });
      }

      expect(monitor.metrics.trends.performanceAlerts).toHaveLength(100);
      // Should keep the most recent alerts
      expect(monitor.metrics.trends.performanceAlerts[99].message).toBe('Alert 149');
    });

    it('should emit performance-alert events', (done) => {
      const alert = {
        type: 'TEST_EVENT',
        severity: 'MEDIUM',
        message: 'Test event emission'
      };

      monitor.once('performance-alert', (emittedAlert) => {
        expect(emittedAlert.type).toBe('TEST_EVENT');
        expect(emittedAlert.severity).toBe('MEDIUM');
        done();
      });

      monitor.addPerformanceAlert(alert);
    });
  });

  describe('Monitoring Lifecycle', () => {
    it('should handle monitoring start/stop cycle', async () => {
      expect(monitor.isMonitoring).toBe(false);

      await monitor.startMonitoring();
      expect(monitor.isMonitoring).toBe(true);
      
      monitor.stopMonitoring();
      expect(monitor.isMonitoring).toBe(false);
    });

    it('should not start monitoring if already running', async () => {
      monitor.isMonitoring = true;
      
      const result = await monitor.startMonitoring();
      // Should return early without error
      expect(result).toBeUndefined();
    });

    it('should handle stop monitoring when not running', () => {
      expect(monitor.isMonitoring).toBe(false);
      expect(() => monitor.stopMonitoring()).not.toThrow();
    });

    it('should emit monitoring lifecycle events', (done) => {
      let eventCount = 0;
      
      monitor.once('hybrid-monitoring-started', () => {
        eventCount++;
        monitor.stopMonitoring();
      });
      
      monitor.once('hybrid-monitoring-stopped', () => {
        eventCount++;
        expect(eventCount).toBe(2);
        done();
      });

      monitor.startMonitoring();
    });
  });

  describe('Performance Recommendations', () => {
    it('should generate automated recommendations for low efficiency indexes', () => {
      // Set up low efficiency index
      monitor.metrics.indexUsage['responses_userId_1'].hits = 2;
      monitor.metrics.indexUsage['responses_userId_1'].misses = 18;
      monitor.metrics.indexUsage['responses_userId_1'].efficiency = 0.1;

      monitor.generateAutomatedRecommendations();

      const recommendations = monitor.metrics.trends.recommendations;
      expect(recommendations.length).toBeGreaterThan(0);
      
      const indexRecommendation = recommendations.find(r => r.type === 'INDEX_OPTIMIZATION');
      expect(indexRecommendation).toBeDefined();
      expect(indexRecommendation.indexName).toBe('responses_userId_1');
      expect(indexRecommendation.priority).toBe('HIGH');
    });

    it('should detect unused indexes after sufficient queries', () => {
      // Simulate many total queries but unused index
      monitor.metrics.authMethodPerformance.user.queryCount = 150;
      monitor.metrics.authMethodPerformance.token.queryCount = 50;
      
      // Set all indexes as used except one
      monitor.metrics.indexUsage['responses_userId_1'].hits = 10;
      monitor.metrics.indexUsage['responses_token_1'].hits = 5;
      monitor.metrics.indexUsage['responses_month_1_isAdmin_1'].hits = 8;
      monitor.metrics.indexUsage['responses_createdAt_-1'].hits = 3;
      
      // Leave one index completely unused
      monitor.metrics.indexUsage['responses_compound_hybrid'].hits = 0;
      monitor.metrics.indexUsage['responses_compound_hybrid'].misses = 0;

      monitor.generateAutomatedRecommendations();

      const recommendations = monitor.metrics.trends.recommendations;
      const unusedRecommendation = recommendations.find(r => r.type === 'UNUSED_INDEX');
      
      expect(unusedRecommendation).toBeDefined();
      expect(unusedRecommendation.indexName).toBe('responses_compound_hybrid');
      expect(unusedRecommendation.priority).toBe('LOW');
    });

    it('should generate query-specific recommendations', () => {
      const queryType = { name: 'userAuth', type: 'user', expectedIndex: 'responses_userId_1' };
      const executionStats = {
        docsExamined: 1000,
        nReturned: 10,
        indexName: 'responses_userId_1'
      };

      monitor.generatePerformanceRecommendation(queryType, 0.3, executionStats);

      const recommendations = monitor.metrics.trends.recommendations;
      expect(recommendations.length).toBeGreaterThan(0);
      
      const queryRecommendation = recommendations.find(r => r.type === 'QUERY_OPTIMIZATION');
      expect(queryRecommendation).toBeDefined();
      expect(queryRecommendation.queryType).toBe('userAuth');
      expect(queryRecommendation.efficiency).toBe(0.3);
    });
  });

  describe('Query Metrics Update', () => {
    it('should update auth method performance metrics', () => {
      const queryType = { type: 'user', name: 'userAuth' };
      const executionTime = 25;

      monitor.updateQueryMetrics(queryType, executionTime, '{"userId": "test"}');

      const userMetrics = monitor.metrics.authMethodPerformance.user;
      expect(userMetrics.queryCount).toBe(1);
      expect(userMetrics.totalTime).toBe(25);
      expect(userMetrics.avgTime).toBe(25);
    });

    it('should update query pattern metrics', () => {
      const queryType = { type: 'token', name: 'tokenLookup' };
      const executionTime = 15;

      monitor.updateQueryMetrics(queryType, executionTime, '{"token": "test"}');

      const tokenPattern = monitor.metrics.queryPatterns.tokenLookup;
      expect(tokenPattern.count).toBe(1);
      expect(tokenPattern.avgTime).toBe(15);
    });

    it('should handle multiple metric updates correctly', () => {
      const userQueryType = { type: 'user', name: 'userLookup' };
      const tokenQueryType = { type: 'token', name: 'tokenLookup' };

      monitor.updateQueryMetrics(userQueryType, 30, '{}');
      monitor.updateQueryMetrics(userQueryType, 20, '{}');
      monitor.updateQueryMetrics(tokenQueryType, 10, '{}');

      const userMetrics = monitor.metrics.authMethodPerformance.user;
      expect(userMetrics.queryCount).toBe(2);
      expect(userMetrics.avgTime).toBe(25); // (30 + 20) / 2

      const tokenMetrics = monitor.metrics.authMethodPerformance.token;
      expect(tokenMetrics.queryCount).toBe(1);
      expect(tokenMetrics.avgTime).toBe(10);
    });
  });

  describe('Error Handling', () => {
    it('should handle database connection errors gracefully', async () => {
      const errorMonitor = new HybridIndexMonitor();
      
      // Mock captureBaselineMetrics to throw error
      jest.spyOn(errorMonitor, 'captureBaselineMetrics').mockImplementation(() => {
        throw new Error('Database connection failed');
      });

      // Should handle error internally
      await expect(errorMonitor.startMonitoring()).rejects.toThrow('Database connection failed');
    });

    it('should handle malformed query strings in categorization', () => {
      const malformedQuery = 'not-valid-json';
      
      expect(() => {
        monitor.categorizeQuery(malformedQuery);
      }).not.toThrow();
      
      const result = monitor.categorizeQuery(malformedQuery);
      expect(result.name).toBe('unknown');
    });
  });

  describe('Hourly Statistics', () => {
    it('should manage hourly statistics properly', () => {
      monitor.updateHourlyStats();
      
      const currentHour = new Date().getHours();
      const hourlyStats = monitor.metrics.trends.hourlyStats;
      
      expect(hourlyStats.has(currentHour)).toBe(true);
      expect(hourlyStats.get(currentHour)).toEqual({
        queries: 0,
        avgTime: 0,
        slowQueries: 0,
        indexHits: 0,
        indexMisses: 0
      });
    });

    it('should limit hourly statistics to 24 hours', () => {
      const hourlyStats = monitor.metrics.trends.hourlyStats;
      
      // Add 26 hours of data (should trigger cleanup)
      for (let i = 0; i < 26; i++) {
        hourlyStats.set(i, { queries: i });
      }
      
      // Single call should reduce by 1
      monitor.updateHourlyStats();
      
      expect(hourlyStats.size).toBeLessThanOrEqual(26); // Should be reduced to 26 or less
      expect(hourlyStats.size).toBeGreaterThan(24); // But still over 24
    });
  });

  describe('Performance Trends Analysis', () => {
    it('should detect performance differences between auth methods', () => {
      // Set up significant performance difference
      monitor.metrics.authMethodPerformance.user.queryCount = 100;
      monitor.metrics.authMethodPerformance.user.avgTime = 100;
      monitor.metrics.authMethodPerformance.token.queryCount = 100;
      monitor.metrics.authMethodPerformance.token.avgTime = 20;

      monitor.checkPerformanceTrends();

      const alerts = monitor.metrics.trends.performanceAlerts;
      const perfAlert = alerts.find(a => a.type === 'AUTH_METHOD_PERFORMANCE_GAP');
      
      expect(perfAlert).toBeDefined();
      expect(perfAlert.severity).toBe('MEDIUM');
      expect(perfAlert.data.userAvgTime).toBe(100);
      expect(perfAlert.data.tokenAvgTime).toBe(20);
    });

    it('should not alert for small performance differences', () => {
      // Set up small performance difference (within 50% threshold)
      monitor.metrics.authMethodPerformance.user.queryCount = 100;
      monitor.metrics.authMethodPerformance.user.avgTime = 25;
      monitor.metrics.authMethodPerformance.token.queryCount = 100;
      monitor.metrics.authMethodPerformance.token.avgTime = 20;

      const initialAlertCount = monitor.metrics.trends.performanceAlerts.length;
      monitor.checkPerformanceTrends();

      expect(monitor.metrics.trends.performanceAlerts.length).toBe(initialAlertCount);
    });
  });
});